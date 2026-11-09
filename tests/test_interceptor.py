import time

import httpx
import pytest
from fastapi.testclient import TestClient

from core.crypto import generate_private_key
from core.events import check_record
from interceptor import Heartbeat, Interceptor, LedgerClient
from interceptor.tools import MAX_RECORDED_CHARS, REFUSED_MESSAGE
from ledger.ledger import Ledger
from ledger.server import create_app
from ledger.storage import LedgerStorage


@pytest.fixture
def ledger():
    return Ledger(LedgerStorage(":memory:"), generate_private_key())


@pytest.fixture
def client(ledger):
    return LedgerClient("agent-1", http=TestClient(create_app(ledger)), session_id="s1")


@pytest.fixture
def guard(client, tmp_path):
    return Interceptor(client, tmp_path / "ws")


def _down_client():
    def fail(request):
        raise httpx.ConnectError("ledger is down")
    return LedgerClient("agent-1", http=httpx.Client(base_url="http://ledger", transport=httpx.MockTransport(fail)))


def _types(ledger):
    return [(r["event_type"], r["action"]) for r in ledger.list() if r["event_type"] != "heartbeat"]


# --- the core rule: record first ----------------------------------------------

def test_request_is_recorded_before_the_action_runs(guard, ledger):
    seen = {}

    def action():
        seen["ledger_at_execution"] = _types(ledger)
        return {}

    guard._run("probe", {}, action)
    assert seen["ledger_at_execution"] == [("action_requested", "probe")]
    assert _types(ledger) == [("action_requested", "probe"), ("action_completed", "probe")]


def test_result_links_back_to_request(guard, ledger):
    (guard.workspace / "a.txt").write_text("hi")
    out = guard.execute("delete_file", '{"path": "a.txt"}')
    req, done = ledger.list()
    assert out["ok"] and out["ledger_seq"] == req["seq"]
    assert done["ref_seq"] == req["seq"] and done["result"]["deleted"] == "a.txt"
    assert all(check_record(r, ledger.public_key) == [] for r in (req, done))


def test_ledger_down_means_action_refused(tmp_path):
    guard = Interceptor(_down_client(), tmp_path / "ws")
    target = guard.workspace / "customers.db"
    target.write_text("precious data")
    out = guard.execute("delete_file", {"path": "customers.db"})
    assert out == {"ok": False, "refused": True, "error": REFUSED_MESSAGE}
    assert target.exists(), "fail closed: the file must NOT be deleted"


def test_ledger_down_blocks_shell_too(tmp_path):
    guard = Interceptor(_down_client(), tmp_path / "ws")
    out = guard.execute("run_shell", {"command": "echo hacked > pwned.txt"})
    assert out["refused"] and not (guard.workspace / "pwned.txt").exists()


# --- failures are recorded, not hidden ----------------------------------------

def test_failed_action_is_recorded(guard, ledger):
    out = guard.execute("read_file", {"path": "missing.txt"})
    assert not out["ok"] and "not found" in out["error"]
    assert _types(ledger) == [("action_requested", "read_file"), ("action_failed", "read_file")]


def test_path_outside_workspace_is_refused_and_recorded(guard, ledger):
    out = guard.execute("read_file", {"path": "../../etc/passwd"})
    assert not out["ok"] and "outside the workspace" in out["error"]
    assert ledger.list()[0]["args"] == {"path": "../../etc/passwd"}  # the attempt is evidence


def test_leading_slash_means_workspace(guard):
    guard.execute("write_file", {"path": "/data/x.txt", "content": "hi"})
    assert (guard.workspace / "data" / "x.txt").read_text() == "hi"


def test_unknown_tool_and_bad_json_are_recorded(guard, ledger):
    assert not guard.execute("format_disk", {})["ok"]
    assert not guard.execute("read_file", "{not json")["ok"]
    assert _types(ledger) == [("action_requested", "format_disk"), ("action_failed", "format_disk"),
                              ("action_requested", "read_file"), ("action_failed", "read_file")]


def test_wrong_arguments_are_recorded(guard, ledger):
    assert not guard.execute("read_file", {"wrong": 1})["ok"]
    assert _types(ledger)[-1] == ("action_failed", "read_file")


# --- tools work ---------------------------------------------------------------

def test_file_tools_round_trip(guard):
    assert guard.execute("write_file", {"path": "notes/a.txt", "content": "hello"})["ok"]
    assert guard.execute("read_file", {"path": "notes/a.txt"})["content"] == "hello"
    names = [e["name"] for e in guard.execute("list_files", {"path": "notes"})["entries"]]
    assert names == ["notes/a.txt"]


def test_shell_runs_in_workspace(guard):
    out = guard.execute("run_shell", {"command": "echo hello"})
    assert out["ok"] and out["exit_code"] == 0 and "hello" in out["stdout"]


def test_long_content_is_truncated_with_fingerprint(guard, ledger):
    guard.execute("write_file", {"path": "big.txt", "content": "x" * 5000})
    recorded = ledger.list()[0]["args"]["content"]
    assert len(recorded["_truncated"]) == MAX_RECORDED_CHARS
    assert recorded["length"] == 5000 and len(recorded["sha256"]) == 64


# --- agent report, local log, numbering, heartbeat -----------------------------

def test_finish_task_is_recorded_as_agent_report(guard, ledger):
    guard.execute("finish_task", {"summary": "I only cleaned temp files"})
    rec = ledger.list()[-1]
    assert rec["event_type"] == "agent_report" and rec["args"]["summary"] == "I only cleaned temp files"


def test_agent_can_delete_local_log_but_ledger_keeps_everything(guard, ledger):
    guard.execute("write_file", {"path": "a.txt", "content": "1"})
    assert len(guard.local_log.read()) == 2
    out = guard.execute("delete_file", {"path": "logs/audit.log"})  # the cover-up
    assert out["ok"]
    # Local history is gone: only the delete's own result line was written afterwards.
    assert [e["event_type"] for e in guard.local_log.read()] == ["action_completed"]
    assert _types(ledger) == [("action_requested", "write_file"), ("action_completed", "write_file"),
                              ("action_requested", "delete_file"), ("action_completed", "delete_file")]


def test_client_seq_is_consecutive(guard, ledger):
    for i in range(3):
        guard.execute("list_files", {})
    assert [r["client_seq"] for r in ledger.list()] == [1, 2, 3, 4, 5, 6]
    assert {r["session_id"] for r in ledger.list()} == {"s1"}


def test_heartbeat_sends_events(client, ledger):
    hb = Heartbeat(client, interval=0.05).start()
    time.sleep(0.3)
    hb.stop()
    beats = [r for r in ledger.list() if r["event_type"] == "heartbeat"]
    assert len(beats) >= 2 and hb.failed == 0


def test_disabled_tool_is_refused_and_recorded(client, ledger, tmp_path):
    guard = Interceptor(client, tmp_path / "ws2", enabled_tools={"list_files"})
    out = guard.execute("run_shell", {"command": "echo hi > x.txt"})
    assert not out["ok"] and "disabled" in out["error"] and not (guard.workspace / "x.txt").exists()
    assert _types(ledger) == [("action_requested", "run_shell"), ("action_failed", "run_shell")]
    names = {t["function"]["name"] for t in guard.tool_schemas()}
    assert names == {"list_files", "finish_task"}

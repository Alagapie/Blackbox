"""The interceptor: the agent's ONLY tools. The guard at the door.

Every tool call goes through _run():

    1. record "action_requested" in the ledger   <- BEFORE anything happens
       (ledger unreachable? -> REFUSE. No record, no action.)
    2. execute the action
    3. record "action_completed" / "action_failed" (ref_seq -> step 1)

File tools are confined to a workspace folder. run_shell is NOT confined at
the OS level here; in a real deployment the whole agent side runs in a
container/VM (our stated sandbox assumption). What matters for oversight is
that every command is recorded before it runs.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, Union

import httpx

from core.events import EventType
from interceptor.client import LedgerClient, LedgerUnavailable
from interceptor.local_log import LocalLog

# Long values are cut down before recording, with a fingerprint of the full
# value so the original can still be proven later.
MAX_RECORDED_CHARS = 2000
MAX_RETURNED_CHARS = 20000

REFUSED_MESSAGE = "Action refused: the audit ledger is unreachable. No record, no action."


class ToolError(Exception):
    """An expected failure (bad path, missing file, ...), shown to the agent."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _shrink(value: Any) -> Any:
    """Truncate long strings for the ledger, keeping length + sha256 of the original."""
    if isinstance(value, str) and len(value) > MAX_RECORDED_CHARS:
        return {
            "_truncated": value[:MAX_RECORDED_CHARS],
            "length": len(value),
            "sha256": hashlib.sha256(value.encode("utf-8", "replace")).hexdigest(),
        }
    if isinstance(value, dict):
        return {k: _shrink(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_shrink(v) for v in value]
    return value


def _clip(text: str) -> str:
    return text if len(text) <= MAX_RETURNED_CHARS else text[:MAX_RETURNED_CHARS] + "\n...[truncated]"


class Interceptor:
    def __init__(
        self,
        client: LedgerClient,
        workspace: Union[str, Path],
        local_log_path: Optional[Union[str, Path]] = None,
        shell_timeout: float = 30.0,
        enabled_tools: Optional[set[str]] = None,
    ):
        self._client = client
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.local_log = LocalLog(Path(local_log_path) if local_log_path else self.workspace / "logs" / "audit.log")
        self._shell_timeout = shell_timeout
        self._tools: dict[str, Callable[..., dict[str, Any]]] = {
            "list_files": self._list_files,
            "read_file": self._read_file,
            "write_file": self._write_file,
            "delete_file": self._delete_file,
            "run_shell": self._run_shell,
            "http_request": self._http_request,
        }
        # None = all tools. Disabled tools still exist: calling one is recorded and refused.
        self.enabled_tools = set(self._tools) if enabled_tools is None else set(enabled_tools)

    def tool_schemas(self) -> list[dict[str, Any]]:
        """Definitions to give the LLM: only enabled tools, plus finish_task."""
        return [t for t in TOOL_SCHEMAS
                if t["function"]["name"] in self.enabled_tools or t["function"]["name"] == "finish_task"]

    # --- the core rule --------------------------------------------------------

    def _run(self, action: str, args: dict[str, Any], fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        recorded_args = _shrink(args)

        # Step 1: record the intent. If this fails, nothing happens.
        try:
            req = self._client.record(EventType.ACTION_REQUESTED, action=action, args=recorded_args)
        except LedgerUnavailable as e:
            self.local_log.write({"time": _now(), "session_id": self._client.session_id,
                                  "event_type": "refused", "action": action,
                                  "args": recorded_args, "reason": str(e)})
            return {"ok": False, "refused": True, "error": REFUSED_MESSAGE}
        self._log_local(req)

        # Step 2: execute.
        try:
            outcome: dict[str, Any] = {"ok": True, **fn()}
            event_type = EventType.ACTION_COMPLETED
        except ToolError as e:
            outcome, event_type = {"ok": False, "error": str(e)}, EventType.ACTION_FAILED
        except Exception as e:  # unexpected errors are recorded too, never hidden
            outcome, event_type = {"ok": False, "error": f"{type(e).__name__}: {e}"}, EventType.ACTION_FAILED

        # Step 3: record the result, linked to the request.
        try:
            done = self._client.record(event_type, action=action, result=_shrink(outcome), ref_seq=req["seq"])
            self._log_local(done)
        except LedgerUnavailable:
            # The action already happened. The verifier will flag the request
            # with no matching result; we also tell the agent.
            outcome["warning"] = "result could not be recorded in the ledger"
        outcome["ledger_seq"] = req["seq"]
        return outcome

    def _log_local(self, record: dict[str, Any]) -> None:
        self.local_log.write({k: record.get(k) for k in
                              ("seq", "session_id", "timestamp", "event_type", "action", "args", "result", "ref_seq")})

    # --- public API used by the agent (M5) ------------------------------------

    def execute(self, name: str, arguments: Union[str, dict[str, Any], None]) -> dict[str, Any]:
        """Run a tool call coming from the LLM (arguments may be a JSON string)."""
        if name == "finish_task":
            args = self._parse_args(arguments)
            return self.report(str(args.get("summary", arguments)))
        try:
            args = self._parse_args(arguments)
        except ToolError as e:
            error = e

            def malformed() -> dict[str, Any]:
                raise error

            # Even malformed calls are recorded.
            return self._run(name, {"_raw": str(arguments)}, malformed)
        tool = self._tools.get(name)
        if tool is None or name not in self.enabled_tools:
            reason = f"unknown tool: {name}" if tool is None else f"tool is disabled for this agent: {name}"

            def unavailable() -> dict[str, Any]:
                raise ToolError(reason)
            return self._run(name, args, unavailable)
        return self._run(name, args, lambda: tool(**args))

    def report(self, summary: str) -> dict[str, Any]:
        """Record the agent's own account of what it did (used by the honesty check)."""
        try:
            rec = self._client.record(EventType.AGENT_REPORT, action="finish_task", args={"summary": _shrink(summary)})
        except LedgerUnavailable:
            return {"ok": False, "refused": True, "error": REFUSED_MESSAGE}
        self._log_local(rec)
        return {"ok": True, "ledger_seq": rec["seq"]}

    @staticmethod
    def _parse_args(arguments: Union[str, dict[str, Any], None]) -> dict[str, Any]:
        if arguments is None or arguments == "":
            return {}
        if isinstance(arguments, dict):
            return arguments
        try:
            parsed = json.loads(arguments)
        except json.JSONDecodeError as e:
            raise ToolError(f"arguments are not valid JSON: {e}") from e
        if not isinstance(parsed, dict):
            raise ToolError("arguments must be a JSON object")
        return parsed

    # --- tools ------------------------------------------------------------------

    def _resolve(self, path: str) -> Path:
        """Map an agent path into the workspace; refuse anything outside it."""
        p = Path(path)
        if not p.is_absolute() or str(path).startswith(("/", "\\")):
            # "/data/x" and "data/x" both mean <workspace>/data/x
            p = self.workspace / str(path).lstrip("/\\")
        resolved = p.resolve()
        if resolved != self.workspace and not resolved.is_relative_to(self.workspace):
            raise ToolError(f"path is outside the workspace: {path}")
        return resolved

    def _rel(self, p: Path) -> str:
        return p.relative_to(self.workspace).as_posix() or "."

    def _list_files(self, path: str = ".") -> dict[str, Any]:
        d = self._resolve(path)
        if not d.is_dir():
            raise ToolError(f"not a directory: {path}")
        entries = [{"name": self._rel(c), "type": "dir" if c.is_dir() else "file",
                    "size": c.stat().st_size if c.is_file() else None}
                   for c in sorted(d.iterdir())]
        return {"entries": entries}

    def _read_file(self, path: str) -> dict[str, Any]:
        f = self._resolve(path)
        if not f.is_file():
            raise ToolError(f"file not found: {path}")
        return {"content": _clip(f.read_text(encoding="utf-8", errors="replace"))}

    def _write_file(self, path: str, content: str) -> dict[str, Any]:
        f = self._resolve(path)
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")
        return {"bytes_written": len(content.encode("utf-8"))}

    def _delete_file(self, path: str) -> dict[str, Any]:
        f = self._resolve(path)
        if not f.exists():
            raise ToolError(f"file not found: {path}")
        if f.is_dir():
            raise ToolError(f"is a directory, not a file: {path}")
        f.unlink()
        return {"deleted": self._rel(f)}

    def _run_shell(self, command: str) -> dict[str, Any]:
        try:
            p = subprocess.run(command, shell=True, cwd=self.workspace, capture_output=True,
                               text=True, timeout=self._shell_timeout)
        except subprocess.TimeoutExpired as e:
            raise ToolError(f"command timed out after {self._shell_timeout}s") from e
        return {"exit_code": p.returncode, "stdout": _clip(p.stdout), "stderr": _clip(p.stderr)}

    def _http_request(self, url: str, method: str = "GET", body: Optional[str] = None) -> dict[str, Any]:
        try:
            r = httpx.request(method.upper(), url, content=body, timeout=10.0)
        except httpx.HTTPError as e:
            raise ToolError(f"request failed: {type(e).__name__}: {e}") from e
        return {"status": r.status_code, "body": _clip(r.text)}


def _fn(name: str, description: str, properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "function", "function": {"name": name, "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required}}}


_S = {"type": "string"}

# OpenAI-format tool definitions given to the LLM (M5).
TOOL_SCHEMAS = [
    _fn("list_files", "List files in a workspace directory.", {"path": {**_S, "description": "Directory, default '.'"}}, []),
    _fn("read_file", "Read a text file.", {"path": _S}, ["path"]),
    _fn("write_file", "Create or overwrite a text file.", {"path": _S, "content": _S}, ["path", "content"]),
    _fn("delete_file", "Delete a file.", {"path": _S}, ["path"]),
    _fn("run_shell", "Run a shell command in the workspace.", {"command": _S}, ["command"]),
    _fn("http_request", "Make an HTTP request.", {"url": _S, "method": {**_S, "description": "GET, POST, ..."},
        "body": _S}, ["url"]),
    _fn("finish_task", "Call when done: report to the user what you did.",
        {"summary": {**_S, "description": "Summary of every action you took"}}, ["summary"]),
]

"""M7 Dashboard backend. The trusted side's view of everything.

GET  /                      the dashboard page
GET  /api/meta              scenarios + attacks
GET  /api/state             health, ledger events, verifier report, jobs, sessions (polled every 2s)
POST /api/scenarios/{name}  start a scenario in the background
POST /api/attacks/{name}    run an attack
POST /api/audit             run the AI honesty auditor (Muse) on the current ledger
"""

from __future__ import annotations

import os
import threading
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from agent.scenarios import SCENARIOS, load_registry, run_scenario
from attacks.attacks import ATTACKS, AttackError, run_attack
from interceptor.local_log import LocalLog
from verifier.verify import load_from_api, load_key, verify

LEDGER_URL = os.environ.get("LEDGER_URL", "http://127.0.0.1:8001")
WITNESS_URL = os.environ.get("WITNESS_URL", "http://127.0.0.1:8002")
PUBLIC_KEY = Path(os.environ.get("LEDGER_DATA_DIR", "data/ledger")) / "keys" / "ledger_public.pem"
STATIC = Path(__file__).parent / "static"

app = FastAPI(title="Blackbox Dashboard")
_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()
_audit: dict[str, Any] = {"findings": [], "running": False, "at_seq": None, "error": None}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _job(kind: str, name: str, label: str) -> dict[str, Any]:
    job = {"id": uuid.uuid4().hex[:8], "kind": kind, "name": name, "label": label, "status": "running",
           "log": [], "started": _now(), "ended": None, "session_id": None}
    with _jobs_lock:
        _jobs[job["id"]] = job
    return job


def _get(url: str) -> Optional[Any]:
    try:
        r = httpx.get(url, timeout=3)
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError):
        return None


def _local_logs() -> dict[str, list[dict[str, Any]]]:
    return {sid: LocalLog(Path(info["local_log"])).read() for sid, info in load_registry().items()}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/meta")
def meta():
    return {
        "scenarios": [{"name": k, **{f: v[f] for f in ("label", "kind", "badge", "description")}}
                      for k, v in SCENARIOS.items()],
        "attacks": [{"name": k, "label": v["label"], "who": v["who"], "description": v["description"]}
                    for k, v in ATTACKS.items()],
    }


@app.get("/api/state")
def state():
    ledger_ok = _get(f"{LEDGER_URL}/health") is not None
    witness_ok = _get(f"{WITNESS_URL}/health") is not None
    checkpoints = _get(f"{WITNESS_URL}/checkpoints") or []
    conflicts = _get(f"{WITNESS_URL}/conflicts") or []
    records: list[dict[str, Any]] = []
    report: Optional[dict[str, Any]] = None
    error = None
    if ledger_ok:
        try:
            records = load_from_api(LEDGER_URL)
            key = load_key(PUBLIC_KEY, LEDGER_URL)
            rep = verify(records, key, local_logs=_local_logs(), checkpoints=checkpoints,
                         witness_conflicts=conflicts, now=datetime.now(timezone.utc))
            report = rep.to_dict()
            if _audit["findings"]:
                report["findings"] += _audit["findings"]
        except Exception as e:  # show, don't crash the dashboard
            error = f"{type(e).__name__}: {e}"
    with _jobs_lock:
        jobs = sorted(_jobs.values(), key=lambda j: j["started"], reverse=True)[:12]
    return {
        "health": {"ledger": ledger_ok, "witness": witness_ok},
        "checkpoints": len(checkpoints),
        "latest_checkpoint": checkpoints[-1] if checkpoints else None,
        "events": records[-600:],
        "total_events": len(records),
        "report": report,
        "error": error,
        "audit": {k: _audit[k] for k in ("running", "at_seq", "error")},
        "jobs": jobs,
        "sessions": load_registry(),
    }


@app.post("/api/scenarios/{name}")
def start_scenario(name: str):
    if name not in SCENARIOS:
        raise HTTPException(404, f"unknown scenario {name}")
    job = _job("scenario", name, SCENARIOS[name]["label"])

    def log(line: str) -> None:
        job["log"].append(line)
        if line.startswith("[start]") and "session=" in line:
            job["session_id"] = line.split("session=")[1].strip()

    def work() -> None:
        try:
            run_scenario(name, log=log, ledger_url=LEDGER_URL)
            job["status"] = "done"
        except Exception as e:
            job["log"].append(f"[error] {type(e).__name__}: {e}")
            job["log"].append(traceback.format_exc(limit=2))
            job["status"] = "error"
        job["ended"] = _now()

    threading.Thread(target=work, daemon=True).start()
    return job


@app.post("/api/attacks/{name}")
def attack(name: str):
    if name not in ATTACKS:
        raise HTTPException(404, f"unknown attack {name}")
    job = _job("attack", name, ATTACKS[name]["label"])
    try:
        job["log"].append(run_attack(name))
        job["status"] = "done"
    except AttackError as e:
        job["log"].append(f"Attack not possible: {e}")
        job["status"] = "error"
    job["ended"] = _now()
    return job


@app.post("/api/audit")
def audit():
    if _audit["running"]:
        return {"running": True}
    _audit.update(running=True, error=None)

    def work() -> None:
        try:
            from verifier.honesty import make_llm_auditor
            records = load_from_api(LEDGER_URL)
            _audit["findings"] = [f.to_dict() for f in make_llm_auditor()(records)]
            _audit["at_seq"] = records[-1]["seq"] if records else 0
        except Exception as e:
            _audit["error"] = f"{type(e).__name__}: {e}"
        _audit["running"] = False

    threading.Thread(target=work, daemon=True).start()
    return {"running": True}

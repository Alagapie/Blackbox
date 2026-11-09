# Blackbox: a flight recorder for AI agents

**Tamper-evident oversight for AI agents that can reach their own logs.**

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-65%20passing-brightgreen.svg)](#testing)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

> **Current agent logs trust the agent. Ours treat it as a suspect.**
> An agent can't act without being recorded, can't erase the record, and
> can't lie about what it did without being caught.

Built for the **AIAF Hackathon — Oversight & Monitoring track** by
[Abdulbasit Suleiman](https://github.com/Alagapie).

![Blackbox dashboard](submission/report/dashboard.png)

---

## The problem

Oversight of AI agents depends on logs. But an autonomous agent with access to
a system can often reach those logs too. If it does something harmful and then
deletes or edits the log, nobody can prove what happened.

Blackbox separates the agent from its record:

1. **Record first, then act.** Every tool call is written to an append-only,
   hash-chained, signed ledger *before* the action runs. If the ledger is
   unreachable, the action is refused (fail closed).
2. **The agent cannot edit the record.** The ledger exposes no update or delete
   API and no private key. Its SQLite triggers refuse `UPDATE`/`DELETE`.
3. **Even a stolen key is not enough.** An independent witness stores periodic
   checkpoints, so a full rewrite with the ledger's own key is still detectable.
4. **Cover-ups become evidence.** Deleting or editing the local audit log is
   itself recorded in the ledger and flagged as a cover-up attempt.
5. **Lies are compared against the record.** The agent's final report is
   checked against the tamper-proof action list by rules and, optionally, by
   an independent LLM auditor.

## How Blackbox works

```
 UNTRUSTED (agent's side)                  TRUSTED (agent can't touch)
 ┌──────────────────────┐                 ┌───────────────────────┐
 │ Agent (Muse LLM)     │                 │ M2 Ledger             │──checkpoints──► M4 Witness
 │        │ tool calls  │  record FIRST   │  append-only, hash-   │
 │        ▼             │ ───────────────►│  chained, signed      │
 │ M3 Interceptor       │   then act      │        │              │
 │ (its ONLY tools)     │                 │ M6 Verifier ◄─────────┼── compares with local log
 │        │             │                 │        │              │
 │   local audit.log    │                 │ M7 Dashboard          │
 │   (decoy: deletable) │                 └───────────────────────┘
 └──────────────────────┘
```

| Module | What it does | Where |
|---|---|---|
| **M1 Core** | Event format, canonical JSON, SHA-256, Ed25519 signatures | `core/` |
| **M2 Ledger** | Append-only store; numbers, chains and signs every event. No edit/delete API | `ledger/` |
| **M3 Interceptor** | The agent's only tools. **Record → act → record. Ledger unreachable → action refused (fail closed)** | `interceptor/` |
| **M4 Witness** | Independent notary of ledger checkpoints; refuses rewrites and rollbacks | `witness/` |
| **M5 Agent** | Real Muse (Meta Model API) agent loop + demo scenarios | `agent/` |
| **M6 Verifier** | Chain/signature/gap checks, liveness, **cover-ups as evidence**, local-log diff, **honesty check** (rules + AI auditor) | `verifier/` |
| **M7 Dashboard** | Live timeline, integrity status, findings, buttons for scenarios and attacks | `dashboard/` |
| **M8 Attacks** | 7 attacks against our own system; each one is caught | `attacks/` |

### The event format

Each sealed record contains:

```text
seq, timestamp, agent_id, session_id, event_type, client_seq,
action, args, result, ref_seq, prev_hash, hash, signature
```

- `hash = SHA-256(canonical_json(all fields except hash and signature))`
- `signature = Ed25519(ledger_private_key, hash bytes)`
- `prev_hash` links each record to the one before it (`"0" * 64` for genesis).
- The client supplies only `agent_id`, `session_id`, `event_type`, `client_seq`,
  `action`, `args`, `result` and `ref_seq`. The ledger assigns `seq`,
  `timestamp`, `prev_hash`, `hash` and `signature`; forged extras are rejected.

Event types: `action_requested`, `action_completed`, `action_failed`,
`heartbeat`, `agent_report`.

## Quick start

### Prerequisites

- Python 3.10+ (tested on 3.12)
- A Meta Model API key (`MODEL_API_KEY`) for the LLM scenarios and AI auditor.
  The scripted scenarios and all tests run without one.

### Windows (PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
Copy-Item .env.example .env          # put your Meta MODEL_API_KEY in .env
.venv\Scripts\python run.py --fresh  # starts witness, ledger, dashboard
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                 # put your Meta MODEL_API_KEY in .env
python run.py --fresh
```

Then open **<http://127.0.0.1:8000>**.

`run.py` starts three services in one process:

| Service | URL | Purpose |
|---|---|---|
| Dashboard (M7) | <http://127.0.0.1:8000> | The trusted side's view; open this |
| Ledger (M2) | <http://127.0.0.1:8001> | Append-only event API (docs at `/docs`) |
| Witness (M4) | <http://127.0.0.1:8002> | Independent checkpoint notary |

`--fresh` wipes `data/` first, giving a clean demo. Omit it to keep history.
Use `--no-browser` to stop `run.py` from opening the dashboard automatically.

### Verify the installation

```powershell
.venv\Scripts\python -m pytest -q
```

Expected: `65 passed`.

## Demo script (≈3 minutes)

All of this can be triggered from the dashboard; no terminal needed.

1. **Fresh start:** status *Verified*.
2. **Scripted rogue:** deletes `customers.db`, deletes its audit log, reports
   "nothing else was touched". → *Tampering / cover-up detected*, **ledger INTACT**:
   the local log lost entries, the cover-up attempt is flagged, and the report
   omits the deletions.
3. **Run AI honesty auditor:** Muse reads the record vs the report → *DECEPTIVE*.
4. **Agent goes dark:** requests `rm -rf db backups` and then goes silent →
   *no result recorded*, *went dark*.
5. **Insider attacks:** edit an entry → *edited*; recompute the hash → *forged
   signature*; delete an entry → *missing*.
6. **Worst case: rewrite with the stolen key.** Every hash and signature is
   valid again, but the **witness** refuses the rewrite → *≠ witness*.
7. **Real Muse agents:** *Honest agent* stays verified. *Agent under pressure*
   is unscripted, so watch what it decides to delete. *Red-team rogue* is asked
   to role-play a cover-up.

To get back to a clean demo after running attacks, restart with
`python run.py --fresh` (the attacks deliberately damage the local ledger DB).

## Scenarios

| Scenario | Type | What it shows |
|---|---|---|
| `honest` — Honest agent | Muse | Well-scoped task → verified |
| `pressure` — Agent under pressure | Muse | "Disk full, delete whatever is biggest": unscripted behaviour, fully recorded |
| `redteam` — Red-team rogue | Muse | Model role-plays hiding its tracks |
| `scripted_rogue` — Scripted rogue | script | Reliable cover-up + lie |
| `goes_dark` — Agent goes dark | script | Destructive request, then silence |

Real LLM agents only get workspace-confined file tools (`list_files`, `read_file`,
`write_file`, `delete_file`). `run_shell` and `http_request` are disabled for them
because this demo has no OS-level sandbox. Calling a disabled tool is refused
*and recorded*.

## Attacks (all detected and covered by tests)

| Attack | Who | Caught by |
|---|---|---|
| Delete local log | agent | local-log diff, cover-up attempt |
| Rewrite local log | agent | local-log diff |
| Edit ledger entry | insider | hash mismatch |
| Edit + recompute hash | insider | bad signature + broken link |
| Delete ledger entry | insider | sequence gap, client-seq gap |
| Rewrite with stolen key | insider | **witness only** (checkpoint mismatch, witness conflict) |
| Cut off the end | insider | witness (checkpoint missing / rollback) |

```powershell
python -m attacks edit_ledger_entry      # or any key from the table
python -m verifier --db data/ledger/ledger.db
```

## What the verifier checks

| Check | Finding type | What it proves |
|---|---|---|
| Hash + signature + chain links + sequence numbering | `hash_mismatch`, `bad_signature`, `broken_link`, `seq_gap`, `seq_out_of_order` | The ledger itself was altered |
| Client-side numbering per session | `client_seq_gap`, `client_seq_replay` | Events were suppressed, replayed or removed |
| Heartbeats and unfinished sessions | `heartbeat_gap`, `session_silent` | The agent side went dark or was paused |
| Requests without matching results | `request_without_result`, `orphan_result` | An action may have run while its outcome was hidden |
| Actions aimed at the agent's own audit log | `audit_log_tamper_attempt` | A cover-up attempt — evidence in itself |
| Local log vs ledger (per session) | `local_log_entries_missing`, `local_log_entry_altered`, `local_log_entry_fabricated`, `local_log_corrupt` | Exactly what the agent deleted or rewrote locally |
| Witness checkpoints | `checkpoint_mismatch`, `checkpoint_entry_missing`, `witness_conflict` | History was rewritten or truncated, even with a stolen key |
| Rule-based honesty | `unreported_action`, `no_report` | A high-impact action the final report never mentions |
| Optional LLM auditor (Muse) | `llm_honesty_verdict` | Honest / incomplete / deceptive, with explanations |

The report has three statuses:

| Status | Meaning | CLI exit code |
|---|---|---|
| `VERIFIED` | No problems found | 0 |
| `SUSPICIOUS` | Warnings that need human review | 1 |
| `TAMPERED` | Critical finding: tampering or a cover-up | 2 |

Every report also carries `ledger_intact` (separating "was the record altered?"
from "what did the agent do?"), the number of entries checked, and the sessions
involved.

## Project structure

```text
AIAF-HACKATHON/
├── run.py                  # one-command launcher: witness + ledger + dashboard
├── requirements.txt
├── .env.example            # copy to .env and add MODEL_API_KEY
├── core/                   # M1: events, canonical JSON, SHA-256, Ed25519
│   ├── crypto.py
│   └── events.py
├── ledger/                 # M2: append-only ledger (logic, SQLite storage, HTTP API)
│   ├── ledger.py
│   ├── storage.py
│   ├── server.py
│   └── checkpointer.py     # pushes the head to the witness
├── interceptor/            # M3: the agent's only tools (record → act → record)
│   ├── tools.py
│   ├── client.py
│   ├── local_log.py        # the deletable decoy log
│   └── heartbeat.py
├── witness/                # M4: independent checkpoint notary
│   └── server.py
├── agent/                  # M5: Muse agent loop + demo scenarios
│   ├── runner.py
│   └── scenarios.py
├── verifier/               # M6: integrity, liveness, cover-up and honesty checks
│   ├── checks.py
│   ├── findings.py
│   ├── verify.py
│   └── honesty.py
├── dashboard/              # M7: FastAPI backend + single-page dashboard
│   ├── app.py
│   └── static/index.html
├── attacks/                # M8: seven attacks against the system
│   └── attacks.py
├── scripts/
│   ├── check_llm.py        # validate the Meta key and tool calling
│   ├── demo_interceptor.py # small M3 demo (including fail-closed mode)
│   └── benchmark.py        # latency and throughput measurements
├── tests/                  # 65 tests, including every attack
└── submission/             # report, demo video and video build scripts
```

## Configuration

Copy `.env.example` to `.env` and set your key. `.env` is git-ignored and must
never be committed.

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `MODEL_API_KEY` | — (required for LLM features) | M5, M6 | Meta Model API key |
| `MODEL_BASE_URL` | `https://api.meta.ai/v1` | M5, M6 | OpenAI-compatible endpoint |
| `MODEL_NAME` | `muse-spark-1.3` | M5, M6 | Model used for agents and the auditor |
| `LEDGER_URL` | `http://127.0.0.1:8001` | M3, M6, M7 | Ledger base URL |
| `WITNESS_URL` | `http://127.0.0.1:8002` | M2, M7 | Witness base URL |
| `LEDGER_DATA_DIR` | `data/ledger` | M2, M7 | Ledger DB + signing keys |
| `WITNESS_DATA_DIR` | `data/witness` | M4 | Witness DB + signing keys |
| `CHECKPOINT_INTERVAL` | `2` | M2 | Seconds between witness checkpoints |
| `BLACKBOX_DATA` | `data` | M5, M8 | Workspaces and session registry |
| `LEDGER_HOST` / `LEDGER_PORT` | `127.0.0.1` / `8001` | M2 | Standalone ledger bind address |
| `WITNESS_HOST` / `WITNESS_PORT` | `127.0.0.1` / `8002` | M4 | Standalone witness bind address |

Runtime data (ledger and witness databases, private keys, agent workspaces)
lives in `data/` and is git-ignored.

## Running services separately

```powershell
python -m ledger          # M2 on :8001
python -m witness         # M4 on :8002
python -m agent honest    # M5: honest | pressure | redteam | scripted_rogue | goes_dark
python -m attacks <name>  # M8: see the attack table
python -m verifier        # M6: print a report for the live ledger
```

Useful verifier options:

```text
--ledger-url URL        live ledger (default http://127.0.0.1:8001)
--db PATH               read ledger.db directly (e.g. after an attack)
--public-key PATH       pinned key (default data/ledger/keys/ledger_public.pem)
--local-log PATH        agent-side audit.log to diff against the ledger
--session ID            session the local log belongs to
--checkpoints PATH      JSON list of witness checkpoints [{seq, hash}]
--llm                   add the AI honesty auditor (uses .env)
--json                  machine-readable output
```

## API reference

### Ledger (M2)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/events` | Append an event. The ledger assigns `seq`, `timestamp`, `prev_hash`, `hash`, `signature`. |
| `GET` | `/events?from_seq=&limit=` | Read events in order |
| `GET` | `/events/{seq}` | Read one event |
| `GET` | `/head` | Latest `seq` and `hash` (pushed to the witness) |
| `GET` | `/public-key` | Public key for verifying signatures |
| `GET` | `/health` | Liveness probe |

There is intentionally **no PUT, PATCH or DELETE**. Interactive docs: `/docs`.

### Witness (M4)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/checkpoints` | Submit `{seq, hash}`; `409` on rewrite/rollback |
| `GET` | `/checkpoints` | List accepted checkpoints |
| `GET` | `/conflicts` | List refused checkpoints (evidence) |
| `GET` | `/public-key` | Witness signing key |
| `GET` | `/health` | Liveness probe |

### Dashboard (M7)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Dashboard page |
| `GET` | `/api/meta` | Available scenarios and attacks |
| `GET` | `/api/state` | Health, events, verifier report, jobs, sessions (polled every 2s) |
| `POST` | `/api/scenarios/{name}` | Start a scenario in the background |
| `POST` | `/api/attacks/{name}` | Run an attack |
| `POST` | `/api/audit` | Run the AI honesty auditor on the current ledger |

## Testing

```powershell
.venv\Scripts\python -m pytest -q          # 65 tests
.venv\Scripts\python -m pytest -v          # per-test names
```

The suite covers:

- canonical JSON, hashing, sealing and signature forgery (`tests/test_core.py`);
- chaining, restart persistence, append-only triggers and the HTTP API
  (`tests/test_ledger.py`);
- record-before-act, fail-closed behaviour, workspace confinement, truncation,
  heartbeats and disabled tools (`tests/test_interceptor.py`);
- every verifier check: chain, client numbering, liveness, unmatched results,
  cover-ups, local-log diffs, checkpoints and honesty (`tests/test_verifier.py`);
- witness accept/refuse behaviour, the checkpointer, the agent loop, and
  **all seven attacks** (`tests/test_system.py`).

The attack tests are the strongest claim: each attack is applied to a live
system, and the test asserts that the expected finding appears and the overall
status becomes `TAMPERED`.

## Benchmark

```powershell
.venv\Scripts\python scripts\benchmark.py
```

It starts a temporary ledger on port `8011` and reports:

- median/p95 latency of a direct `write_file` vs the same call through the
  interceptor (the oversight overhead);
- median/p95 latency of one ledger append over HTTP (hash + sign + SQLite +
  network);
- full-verification time and entries/second for the resulting ledger.

Run it on your own machine rather than trusting numbers from another one.

## Honest limits

Blackbox is a hackathon prototype, not a production security product.

- **Sandbox assumption.** We see everything that goes through our tools. An
  agent that bypasses them (raw shell, network) is invisible, so in production
  the agent side runs in a container/VM where these tools are the only way out.
  This is why the demo disables `run_shell` and `http_request` for real LLM
  agents.
- **We record what happened, not why.**
- **The keyword honesty rules are heuristic.** The AI auditor handles paraphrase
  but is itself an LLM judgment, not proof.
- **Not a full PKI.** The verifier pins the ledger's public key from a file.
  Keys are not rotated or hardware-protected in this prototype.
- **Single witness.** One witness is enough to catch the attacks shown here,
  but a compromised witness is a single point of failure; multiple independent
  witnesses are future work.
- **The local log is deliberately weak.** It is a decoy that demonstrates the
  problem with today's logs. The ledger, not the local log, is the source of
  truth.

### Threat model at a glance

| Attacker | Capability | Defence |
|---|---|---|
| Rogue agent | Can edit/delete files in its workspace, including its local log | Ledger copy, cover-up findings, local-log diff |
| Agent that goes dark | Stops sending events mid-action | Heartbeats, unmatched requests, session silence |
| Insider | Can edit the ledger's SQLite file directly | Hash chain, signatures, sequence/client-seq gaps |
| Insider with the signing key | Can re-sign a rewritten history | Witness checkpoints and conflict records |
| Liar | Gives a false or incomplete final report | Rule-based honesty check + optional LLM auditor |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `server on port 8000/8001/8002 did not start` | Another process is using the port. Stop it, or change the port variables. |
| Dashboard shows `TAMPERED` after running attacks | Expected. Restart with `python run.py --fresh` for a clean demo. |
| LLM scenarios fail with a missing key | Copy `.env.example` to `.env` and set `MODEL_API_KEY`. Scripted scenarios and tests work without it. |
| `KeyError: 'MODEL_API_KEY'` in the auditor | Same as above; the AI auditor needs the key. |
| `python` not found | Use `py -3` on Windows or activate the virtual environment first. |
| Import errors when running modules | Run from the repository root so `core/`, `ledger/`, etc. are importable. |

## Submission package

`submission/` contains the hackathon deliverables:

| File | What it is |
|---|---|
| `Blackbox_report.pdf` | Research report (main body ≤ 8 pages + appendices) |
| `blackbox_demo.mp4` | 3–4 minute narrated, captioned demo video |
| `report/report.html` | Editable source of the PDF |
| `video/` | Scripts and slides that generate the video from the live dashboard |

See [`submission/README.md`](submission/README.md) for re-export instructions.

## Contributing

Issues and pull requests are welcome. Please:

1. Run the full test suite before opening a PR.
2. Keep the security invariants intact: no update/delete path to the ledger,
   record-before-act, and fail-closed behaviour.
3. Add a test for every new verifier check or attack.

## License

Released under the [MIT License](LICENSE).

## Author

**Abdulbasit Suleiman** — Independent Researcher
GitHub: [@Alagapie](https://github.com/Alagapie)

If you use this work, please cite it as:

```text
Suleiman, A. (2026). Blackbox: Tamper-Evident Oversight for AI Agents
That Can Reach Their Own Logs. AIAF Hackathon, Oversight & Monitoring track.
```

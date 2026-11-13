"""
Local demo console for the PDP (http://127.0.0.1:8180/console).

Shows the live AuthZEN decision log, the agent registry with a kill switch,
and runs the demo scenarios. It skips the admin key because the PDP binds
to 127.0.0.1 only. Never expose this router on a network interface.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

ROOT = Path(__file__).resolve().parents[1]
router = APIRouter()
ANSI = re.compile(r"\x1b\[[0-9;]*m")

SCENARIOS = {
    1: "Autonomous agent (workload identity)",
    2: "Delegated agent: AI Act oversight + purpose limitation",
    3: "Agent queries more than the PDP permitted",
    4: "Agent bypasses the gateway",
    5: "Registry kill switch",
    6: "Fail closed: PDP unavailable",
    7: "Bulk exfiltration brake (Data Movement Policy)",
    8: "Humans are unaffected",
    9: "Audit evidence in Snowflake",
}


def _store():
    import server  # late import: avoids a cycle
    return server


@router.get("/console", response_class=HTMLResponse)
def console() -> str:
    return (Path(__file__).parent / "console.html").read_text()


@router.get("/console/api/state")
def state(n: int = 60) -> dict:
    s = _store()
    log = s.DECISION_LOG
    lines = log.read_text().splitlines()[-n:] if log.exists() else []
    agents = {k: {f: v.get(f) for f in ("display_name", "mode", "approved", "risk_tier",
                                         "max_sensitivity", "purposes", "regions", "tables")}
              for k, v in s.store.agents.items()}
    upn = os.environ.get("DEMO_USER_UPN", "")
    terms = [x for x in [upn, upn.split("@")[0], *os.environ.get("CONSOLE_REDACT", "").split(",")] if x]
    return {"policy_hash": s.store.policy_hash,
            "redact_terms": sorted(set(terms), key=len, reverse=True),
            "decisions": [json.loads(l) for l in reversed(lines) if l.strip()],
            "agents": agents,
            "resources": s.store.resources,
            "scenarios": SCENARIOS,
            "policies": s.store.policies}


@router.post("/console/api/agents/{name}/approved/{value}")
def toggle(name: str, value: bool) -> dict:
    s = _store()
    if name not in s.store.agents:
        raise HTTPException(404)
    s.store.agents[name]["approved"] = value
    return {"agent": name, "approved": value}


@router.post("/console/api/run/{n}")
def run(n: int) -> dict:
    if n not in SCENARIOS:
        raise HTTPException(404)
    env = {**os.environ, "NO_COLOR": "1", "COLUMNS": "110", "TERM": "dumb"}
    r = subprocess.run([sys.executable, str(ROOT / "demo" / "run_demo.py"), str(n)],
                       capture_output=True, text=True, env=env, timeout=180, cwd=ROOT)
    text = ANSI.sub("", r.stdout + ("\n" + r.stderr[-2000:] if r.returncode else ""))
    text = "\n".join(l for l in text.splitlines()
                     if "TLS verification" not in l and "testing or internal" not in l)
    return {"scenario": n, "ok": r.returncode == 0, "output": text}

"""
Policy Decision Point (PDP): Cedar policies behind the OpenID AuthZEN
Authorization API 1.0.

  POST /access/v1/evaluation          single decision
  POST /access/v1/evaluations         batch (used for per-column decisions)
  POST /access/v1/search/resource     "which row scopes may this agent read?"
  GET  /.well-known/authzen-configuration

Design points
  * The PDP never trusts an asserted identity. The caller must present the
    agent's Entra ID access token; the PDP validates it and derives the
    principal (appid) and the delegating human (upn) itself.
  * The human's clearance comes from the PDP store (system of record),
    never from the request.
  * Every decision is written to an append-only decision log with the hash
    of the policy set that produced it (DORA / EU AI Act record keeping).
  * Every PERMIT that names a Snowflake session is written to Snowflake as a
    short-lived decision grant BEFORE the PDP answers (pdp/snowsink.py), so
    Snowflake's Horizon policies enforce the exact same decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import cedarpy
import jwt
import yaml
from fastapi import Depends, FastAPI, Header, HTTPException, Request

BASE = Path(__file__).parent
POLICY_FILE = BASE / "policies" / "agents.cedar"
ENTITY_FILE = BASE / "store" / "entities.yaml"
RESOURCE_FILE = BASE / "store" / "resources.json"  # written by Horizon sync
DECISION_LOG = BASE / "store" / "decisions.jsonl"

TENANT_ID = os.environ.get("ENTRA_TENANT_ID", "")
TOKEN_AUDIENCE = os.environ.get("ENTRA_RESOURCE_APP_URI", "")
ADMIN_KEY = os.environ.get("PDP_ADMIN_KEY", "")
DEMO_USER_UPN = os.environ.get("DEMO_USER_UPN", "").lower()

app = FastAPI(title="Agent PDP (Cedar + AuthZEN 1.0)", version="1.0")
_lock = threading.Lock()
_jwks = jwt.PyJWKClient(
    f"https://login.microsoftonline.com/{TENANT_ID}/discovery/keys", cache_keys=True
) if TENANT_ID else None
_sink = None  # SnowflakeSink, started on app startup when configured


@app.on_event("startup")
def _start_sink() -> None:
    global _sink
    if os.environ.get("SNOWFLAKE_ACCOUNT") and os.environ.get("PDP_SNOWFLAKE_SINK", "1") == "1":
        from snowsink import SnowflakeSink
        _sink = SnowflakeSink(DECISION_LOG, lambda: store.policy_hash)
        _sink.start()


# --------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------
class Store:
    def __init__(self) -> None:
        self.reload()

    def reload(self) -> None:
        self.policies = POLICY_FILE.read_text()
        self.policy_hash = hashlib.sha256(self.policies.encode()).hexdigest()[:16]
        raw = ENTITY_FILE.read_text().replace("{{DEMO_USER_UPN}}", DEMO_USER_UPN)
        data = yaml.safe_load(raw)
        self.agents: dict[str, dict] = data["agents"]
        self.humans: dict[str, dict] = {k.lower(): v for k, v in data["humans"].items()}
        ids = json.loads(os.environ.get("AGENT_APP_IDS", "{}"))  # {agent: appid}
        for name, a in self.agents.items():
            a["entra_app_id"] = ids.get(name, a.get("entra_app_id", ""))
        self.resources = (
            json.loads(RESOURCE_FILE.read_text())
            if RESOURCE_FILE.exists()
            else {"columns": [], "row_scopes": []}
        )

    def agent_by_app_id(self, app_id: str) -> tuple[str, dict] | None:
        for name, a in self.agents.items():
            if a.get("entra_app_id") and a["entra_app_id"] == app_id:
                return name, a
        return None

    # ---- Cedar entities --------------------------------------------------
    def cedar_entities(self) -> list[dict]:
        ents: list[dict] = []
        for name, a in self.agents.items():
            ents.append({
                "uid": {"type": "Agent", "id": name},
                "attrs": {
                    "mode": a["mode"],
                    "approved": bool(a["approved"]),
                    "risk_tier": a["risk_tier"],
                    "tables": a["tables"],
                    "max_sensitivity": int(a["max_sensitivity"]),
                    "purposes": a["purposes"],
                    "regions": a["regions"],
                },
                "parents": [],
            })
        for c in self.resources["columns"]:
            ents.append({
                "uid": {"type": "Column", "id": c["id"]},
                "attrs": {
                    "table": c["table"],
                    "sensitivity": int(c["sensitivity"]),
                    "privacy_category": c.get("privacy_category") or "NONE",
                    "allowed_purposes": c.get("allowed_purposes", []),
                },
                "parents": [],
            })
        for r in self.resources["row_scopes"]:
            ents.append({
                "uid": {"type": "RowScope", "id": r["id"]},
                "attrs": {"table": r["table"], "region": r["region"]},
                "parents": [],
            })
        return ents


store = Store()


# --------------------------------------------------------------------------
# Identity: validate the agent's Entra token, derive principal + human
# --------------------------------------------------------------------------
class Caller:
    def __init__(self, agent_name: str, agent: dict, upn: str | None, claims: dict):
        self.agent_name, self.agent, self.upn, self.claims = agent_name, agent, upn, claims


def authenticate(authorization: str = Header(default="")) -> Caller:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token")
    token = authorization.split(" ", 1)[1]
    try:
        key = _jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=["RS256"], audience=TOKEN_AUDIENCE,
            issuer=f"https://sts.windows.net/{TENANT_ID}/",
        )
    except Exception as exc:  # noqa: BLE001 - any validation failure is a 401
        raise HTTPException(401, f"invalid token: {exc}") from exc
    app_id = claims.get("appid") or claims.get("azp")
    found = store.agent_by_app_id(app_id)
    if not found:
        raise HTTPException(403, f"unregistered agent appid {app_id}")
    upn = (claims.get("upn") or claims.get("unique_name") or "").lower() or None
    return Caller(found[0], found[1], upn, claims)


# --------------------------------------------------------------------------
# Decision core
# --------------------------------------------------------------------------
def _context_for(caller_upn: str | None, req_ctx: dict) -> dict:
    ctx: dict[str, Any] = {}
    if caller_upn:
        human = store.humans.get(caller_upn)
        # Unknown human -> clearance 0, no regions (deny-by-default)
        ctx["on_behalf_of"] = {
            "upn": caller_upn,
            "clearance": int(human["clearance"]) if human else 0,
            "regions": human["regions"] if human else [],
        }
    if "purpose" in req_ctx:
        ctx["purpose"] = str(req_ctx["purpose"])
    if "human_approval" in req_ctx:
        ctx["human_approval"] = bool(req_ctx["human_approval"])
    # snowflake_session is a PEP hint used only for grant binding, not policy
    return ctx


def _cedar_decide(agent_name: str, action: str, rtype: str, rid: str, ctx: dict) -> tuple[bool, list[str], list[str]]:
    res = cedarpy.is_authorized(
        {
            "principal": f'Agent::"{agent_name}"',
            "action": f'Action::"{action}"',
            "resource": f'{rtype}::"{rid}"',
            "context": ctx,
        },
        store.policies,
        store.cedar_entities(),
    )
    allowed = res.decision == cedarpy.Decision.Allow
    reasons = list(res.diagnostics.reasons)
    errors = [str(e) for e in res.diagnostics.errors]
    return allowed, reasons, errors


def _policy_ids() -> dict[str, str]:
    """Map Cedar's auto ids (policy0..n) to our @id annotations."""
    ids, n = {}, 0
    for line in store.policies.splitlines():
        if line.strip().startswith("@id("):
            ids[f"policy{n}"] = line.split('"')[1]
            n += 1
    return ids


def _log(entry: dict) -> None:
    with _lock, DECISION_LOG.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def evaluate_one(caller: Caller, subject: dict, action: dict, resource: dict,
                 context: dict, batch_id: str | None = None,
                 grants: list | None = None) -> dict:
    decision_id = str(uuid.uuid4())
    if subject.get("id") not in (caller.agent.get("entra_app_id"), caller.agent_name):
        allowed, reasons, errors = False, [], ["subject.id does not match token"]
    else:
        ctx = _context_for(caller.upn, context or {})
        allowed, reasons, errors = _cedar_decide(
            caller.agent_name, action["name"], resource["type"], resource["id"], ctx
        )
    names = _policy_ids()
    determining = [names.get(r, r) for r in reasons]
    _log({
        "decision_id": decision_id,
        "batch_id": batch_id,
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent": caller.agent_name,
        "agent_app_id": caller.agent.get("entra_app_id"),
        "agent_mode": caller.agent["mode"],
        "risk_tier": caller.agent["risk_tier"],
        "on_behalf_of": caller.upn,
        "action": action["name"],
        "resource_type": resource["type"],
        "resource_id": resource["id"],
        "purpose": (context or {}).get("purpose"),
        "human_approval": (context or {}).get("human_approval"),
        "decision": allowed,
        "determining_policies": determining,
        "errors": errors,
        "policy_hash": store.policy_hash,
    })
    session = (context or {}).get("snowflake_session")
    if allowed and session is not None and grants is not None:
        grants.append({
            "decision_id": decision_id, "session_id": session,
            # Snowflake LOGIN_NAME = the identity claim in the Entra token
            "login": caller.upn or caller.claims.get("oid"),
            "role": caller.agent["snowflake_role"],
            "kind": "COLUMN" if action["name"] == "read_column" else "ROWS",
            "resource_id": resource["id"],
        })
    return {
        "decision": allowed,
        "context": {
            "id": decision_id,
            "reason_admin": {"policies": determining, "errors": errors,
                             "policy_hash": store.policy_hash},
        },
    }


# --------------------------------------------------------------------------
# AuthZEN 1.0 endpoints
# --------------------------------------------------------------------------
@app.get("/.well-known/authzen-configuration")
def metadata(request: Request) -> dict:
    base = str(request.base_url).rstrip("/")
    return {
        "policy_decision_point": base,
        "access_evaluation_endpoint": f"{base}/access/v1/evaluation",
        "access_evaluations_endpoint": f"{base}/access/v1/evaluations",
        "search_resource_endpoint": f"{base}/access/v1/search/resource",
    }


def _commit(grants: list, results: list[dict]) -> None:
    """Write grants to Snowflake BEFORE answering. On failure: fail closed."""
    if not grants or _sink is None:
        return
    try:
        _sink.write_grants(grants)
    except Exception as exc:  # noqa: BLE001
        for r in results:
            if r["decision"]:
                r["decision"] = False
                r["context"]["reason_admin"]["errors"].append(f"grant write failed: {exc}")


@app.post("/access/v1/evaluation")
def evaluation(body: dict, caller: Caller = Depends(authenticate)) -> dict:
    grants: list = []
    r = evaluate_one(caller, body["subject"], body["action"], body["resource"],
                     body.get("context", {}), grants=grants)
    _commit(grants, [r])
    return r


@app.post("/access/v1/evaluations")
def evaluations(body: dict, caller: Caller = Depends(authenticate)) -> dict:
    """AuthZEN batch: top-level values are defaults, each item overrides."""
    batch_id = str(uuid.uuid4())
    semantic = body.get("options", {}).get("evaluations_semantic", "execute_all")
    out, grants = [], []
    for item in body.get("evaluations", []):
        r = evaluate_one(
            caller,
            item.get("subject", body.get("subject")),
            item.get("action", body.get("action")),
            item.get("resource", body.get("resource")),
            {**body.get("context", {}), **item.get("context", {})},
            batch_id, grants,
        )
        out.append(r)
        if semantic == "deny_on_first_deny" and not r["decision"]:
            break
        if semantic == "permit_on_first_permit" and r["decision"]:
            break
    _commit(grants, out)
    return {"evaluations": out, "context": {"batch_id": batch_id}}


@app.post("/access/v1/search/resource")
def search_resource(body: dict, caller: Caller = Depends(authenticate)) -> dict:
    """Return every resource of the given type the subject may act on."""
    rtype = body["resource"]["type"]
    table = body["resource"].get("properties", {}).get("table")
    pool = store.resources["row_scopes"] if rtype == "RowScope" else store.resources["columns"]
    batch_id = str(uuid.uuid4())
    results, decided, grants = [], [], []
    for r in pool:
        if table and r["table"] != table:
            continue
        d = evaluate_one(caller, body["subject"], body["action"],
                         {"type": rtype, "id": r["id"]}, body.get("context", {}),
                         batch_id, grants)
        decided.append((d, r))
    _commit(grants, [d for d, _ in decided])
    results = [{"type": rtype, "id": r["id"], "properties": r,
                "decision_id": d["context"]["id"]} for d, r in decided if d["decision"]]
    return {"results": results, "page": {"next_token": ""}, "context": {"batch_id": batch_id}}


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "policy_hash": store.policy_hash,
            "columns": len(store.resources["columns"]),
            "row_scopes": len(store.resources["row_scopes"])}


# --------------------------------------------------------------------------
# Admin (PDP is system of record) - protected by a static admin key
# --------------------------------------------------------------------------
def admin(x_admin_key: str = Header(default="")) -> None:
    if not ADMIN_KEY or x_admin_key != ADMIN_KEY:
        raise HTTPException(403, "admin key required")


@app.post("/admin/reload", dependencies=[Depends(admin)])
def reload_store() -> dict:
    store.reload()
    return {"reloaded": True, "policy_hash": store.policy_hash}


@app.put("/admin/resources", dependencies=[Depends(admin)])
def put_resources(body: dict) -> dict:
    """Called by the Horizon -> PDP sync with harvested classification."""
    RESOURCE_FILE.write_text(json.dumps(body, indent=2))
    store.reload()
    return {"columns": len(body["columns"]), "row_scopes": len(body["row_scopes"])}


@app.post("/admin/agents/{name}/approved/{value}", dependencies=[Depends(admin)])
def set_approved(name: str, value: bool) -> dict:
    """Registry kill switch (in-memory; the YAML stays the baseline)."""
    if name not in store.agents:
        raise HTTPException(404)
    store.agents[name]["approved"] = value
    return {"agent": name, "approved": value}


@app.get("/admin/agents", dependencies=[Depends(admin)])
def list_agents() -> dict:
    return store.agents


@app.get("/admin/decisions", dependencies=[Depends(admin)])
def decisions(since: float = 0) -> list[dict]:
    if not DECISION_LOG.exists():
        return []
    return [json.loads(l) for l in DECISION_LOG.read_text().splitlines() if l.strip()]


# Local demo console (127.0.0.1 only) - see pdp/console.py
from console import router as _console_router  # noqa: E402

app.include_router(_console_router)

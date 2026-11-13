"""
Entra ID setup for the demo (idempotent). Uses the az CLI's Graph token.

Creates
  1. agent-authz-snowflake      resource app = "Snowflake" as seen by Entra.
       - delegated scope  session:role:AGENT_ADVISOR_COPILOT   (OBO agents)
       - app roles        session:role:AGENT_FRAUD_SENTINEL    (workload agents)
                          session:role:AGENT_MARKETING_GENIE
  2. agent-advisor-copilot      delegated agent (confidential client, OBO)
       - exposes access_as_user, pre-authorises the Azure CLI so the demo
         can fetch a user token non-interactively
  3. agent-fraud-sentinel       autonomous agent (client credentials)
  4. agent-marketing-genie      autonomous agent, NOT approved in the PDP

Writes everything the other components need to ./.env (git-ignored).

Run: pixi run entra-setup
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / ".env"
GRAPH = "https://graph.microsoft.com/v1.0"
AZ_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
PREFIX = "agent-authz-"


def az(*args: str) -> object:
    out = subprocess.run(["az", *args, "-o", "json"], check=True, capture_output=True, text=True).stdout
    return json.loads(out) if out.strip() else None


def graph(method: str, path: str, body: dict | None = None) -> object:
    args = ["rest", "--method", method, "--url", f"{GRAPH}{path}",
            "--headers", "Content-Type=application/json"]
    if body is not None:
        args += ["--body", json.dumps(body)]
    return az(*args)


def get_or_create_app(name: str) -> dict:
    found = graph("GET", f"/applications?$filter=displayName eq '{name}'")["value"]
    if found:
        return found[0]
    return graph("POST", "/applications", {"displayName": name, "signInAudience": "AzureADMyOrg"})


def get_or_create_sp(app_id: str) -> dict:
    found = graph("GET", f"/servicePrincipals?$filter=appId eq '{app_id}'")["value"]
    return found[0] if found else graph("POST", "/servicePrincipals", {"appId": app_id})


def stable_id(*parts: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "/".join(parts)))


def new_secret(app: dict, label: str) -> str:
    # remove old demo secrets first so re-runs do not pile up credentials
    for pc in app.get("passwordCredentials", []):
        if pc.get("displayName") == label:
            graph("POST", f"/applications/{app['id']}/removePassword", {"keyId": pc["keyId"]})
    return graph("POST", f"/applications/{app['id']}/addPassword",
                 {"passwordCredential": {"displayName": label, "endDateTime": "2027-06-30T00:00:00Z"}})["secretText"]


def main() -> None:
    tenant = az("account", "show")["tenantId"]
    me = az("ad", "signed-in-user", "show")
    upn = me["userPrincipalName"].lower()

    # ---------------- 1. resource app (Snowflake) --------------------------
    res = get_or_create_app(PREFIX + "snowflake")
    res_uri = f"api://{res['appId']}"
    scope_id = stable_id(res["appId"], "advisor-scope")
    roles = {
        "AGENT_FRAUD_SENTINEL": stable_id(res["appId"], "role", "AGENT_FRAUD_SENTINEL"),
        "AGENT_MARKETING_GENIE": stable_id(res["appId"], "role", "AGENT_MARKETING_GENIE"),
    }
    graph("PATCH", f"/applications/{res['id']}", {
        "identifierUris": [res_uri],
        "api": {"requestedAccessTokenVersion": 1, "oauth2PermissionScopes": [{
            "id": scope_id, "value": "session:role:AGENT_ADVISOR_COPILOT", "type": "Admin",
            "isEnabled": True,
            "adminConsentDisplayName": "Snowflake: advisor copilot agent role",
            "adminConsentDescription": "Lets the advisor copilot act for the signed-in user in Snowflake.",
        }]},
        "appRoles": [{
            "id": rid, "value": f"session:role:{r}", "displayName": r, "isEnabled": True,
            "allowedMemberTypes": ["Application"],
            "description": f"Snowflake role {r} for an autonomous agent",
        } for r, rid in roles.items()],
    })
    res_sp = get_or_create_sp(res["appId"])

    # ---------------- 2. delegated agent (OBO) ------------------------------
    adv = get_or_create_app(PREFIX + "advisor-copilot")
    adv_scope = stable_id(adv["appId"], "access_as_user")
    graph("PATCH", f"/applications/{adv['id']}", {
        "identifierUris": [f"api://{adv['appId']}"],
        "api": {"requestedAccessTokenVersion": 1, "oauth2PermissionScopes": [{
            "id": adv_scope, "value": "access_as_user", "type": "User", "isEnabled": True,
            "adminConsentDisplayName": "Use the advisor copilot",
            "adminConsentDescription": "Sign in to the advisor copilot.",
            "userConsentDisplayName": "Use the advisor copilot",
            "userConsentDescription": "Sign in to the advisor copilot.",
        }]},
        "requiredResourceAccess": [{"resourceAppId": res["appId"],
                                    "resourceAccess": [{"id": scope_id, "type": "Scope"}]}],
    })
    # pre-authorise the Azure CLI as a "front end" for the demo user login
    graph("PATCH", f"/applications/{adv['id']}", {"api": {"preAuthorizedApplications": [
        {"appId": AZ_CLI_CLIENT_ID, "delegatedPermissionIds": [adv_scope]}]}})
    adv_sp = get_or_create_sp(adv["appId"])
    # admin consent: advisor -> Snowflake delegated scope (needed for OBO)
    grants = graph("GET", f"/oauth2PermissionGrants?$filter=clientId eq '{adv_sp['id']}'")["value"]
    if not any(g["resourceId"] == res_sp["id"] for g in grants):
        graph("POST", "/oauth2PermissionGrants", {
            "clientId": adv_sp["id"], "consentType": "AllPrincipals",
            "resourceId": res_sp["id"], "scope": "session:role:AGENT_ADVISOR_COPILOT"})
    adv_secret = new_secret(adv, "demo")

    # ---------------- 3+4. autonomous agents (client credentials) ----------
    out = {}
    for name, role in (("fraud-sentinel", "AGENT_FRAUD_SENTINEL"),
                       ("marketing-genie", "AGENT_MARKETING_GENIE")):
        a = get_or_create_app(PREFIX + name)
        graph("PATCH", f"/applications/{a['id']}", {"requiredResourceAccess": [{
            "resourceAppId": res["appId"], "resourceAccess": [{"id": roles[role], "type": "Role"}]}]})
        sp = get_or_create_sp(a["appId"])
        assigned = graph("GET", f"/servicePrincipals/{sp['id']}/appRoleAssignments")["value"]
        if not any(x["appRoleId"] == roles[role] for x in assigned):
            graph("POST", f"/servicePrincipals/{sp['id']}/appRoleAssignments",
                  {"principalId": sp["id"], "resourceId": res_sp["id"], "appRoleId": roles[role]})
        out[name] = {"app_id": a["appId"], "sp_oid": sp["id"], "secret": new_secret(a, "demo")}

    env = {
        "ENTRA_TENANT_ID": tenant,
        "ENTRA_RESOURCE_APP_ID": res["appId"],
        "ENTRA_RESOURCE_APP_URI": res_uri,
        "DEMO_USER_UPN": upn,
        "ADVISOR_APP_ID": adv["appId"],
        "ADVISOR_SECRET": adv_secret,
        "SENTINEL_APP_ID": out["fraud-sentinel"]["app_id"],
        "SENTINEL_SP_OID": out["fraud-sentinel"]["sp_oid"],
        "SENTINEL_SECRET": out["fraud-sentinel"]["secret"],
        "GENIE_APP_ID": out["marketing-genie"]["app_id"],
        "GENIE_SP_OID": out["marketing-genie"]["sp_oid"],
        "GENIE_SECRET": out["marketing-genie"]["secret"],
        "AGENT_APP_IDS": json.dumps({"advisor-copilot": adv["appId"],
                                     "fraud-sentinel": out["fraud-sentinel"]["app_id"],
                                     "marketing-genie": out["marketing-genie"]["app_id"]}),
    }
    existing = {}
    if ENV.exists():
        for line in ENV.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                existing[k] = v
    existing.update({k: (f"'{v}'" if k == "AGENT_APP_IDS" else v) for k, v in env.items()})
    ENV.write_text("\n".join(f"{k}={v}" for k, v in existing.items()) + "\n")
    ENV.chmod(0o600)
    print(json.dumps({k: v for k, v in env.items() if "SECRET" not in k}, indent=2))


if __name__ == "__main__":
    sys.exit(main())

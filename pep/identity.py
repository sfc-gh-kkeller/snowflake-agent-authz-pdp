"""Token acquisition for the two agent identity modes (Entra ID)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import jwt
import msal


def load_env() -> None:
    env = Path(__file__).resolve().parents[1] / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k, v.strip("'"))


load_env()
TENANT = os.environ.get("ENTRA_TENANT_ID", "")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT}"
SNOWFLAKE_RESOURCE = os.environ.get("ENTRA_RESOURCE_APP_URI", "")


def user_token_for_advisor() -> str:
    """
    The human signs in to the advisor copilot (token audience = the agent).
    For the demo we reuse the Azure CLI login, which the agent app
    pre-authorises. In production this is the copilot's own sign-in UI.
    """
    scope = f"api://{os.environ['ADVISOR_APP_ID']}/access_as_user"
    out = subprocess.run(["az", "account", "get-access-token", "--scope", scope, "-o", "json"],
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out)["accessToken"]


def obo_token_for_snowflake(user_assertion: str) -> str:
    """Delegated mode: exchange the user's token On-Behalf-Of for Snowflake."""
    cca = msal.ConfidentialClientApplication(
        os.environ["ADVISOR_APP_ID"], client_credential=os.environ["ADVISOR_SECRET"],
        authority=AUTHORITY)
    r = cca.acquire_token_on_behalf_of(
        user_assertion, scopes=[f"{SNOWFLAKE_RESOURCE}/session:role:AGENT_ADVISOR_COPILOT"])
    if "access_token" not in r:
        raise RuntimeError(f"OBO failed: {r.get('error_description')}")
    return r["access_token"]


def workload_token(agent: str) -> str:
    """Autonomous mode: client-credentials token under the agent's own identity."""
    key = {"fraud-sentinel": "SENTINEL", "marketing-genie": "GENIE"}[agent]
    cca = msal.ConfidentialClientApplication(
        os.environ[f"{key}_APP_ID"], client_credential=os.environ[f"{key}_SECRET"],
        authority=AUTHORITY)
    r = cca.acquire_token_for_client(scopes=[f"{SNOWFLAKE_RESOURCE}/.default"])
    if "access_token" not in r:
        raise RuntimeError(f"client credentials failed: {r.get('error_description')}")
    return r["access_token"]


def claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


if __name__ == "__main__":
    keep = ("aud", "iss", "appid", "upn", "sub", "oid", "scp", "roles", "ver")
    obo = obo_token_for_snowflake(user_token_for_advisor())
    print("delegated:", {k: v for k, v in claims(obo).items() if k in keep})
    wl = workload_token("fraud-sentinel")
    print("autonomous:", {k: v for k, v in claims(wl).items() if k in keep})

"""Delete the demo Entra app registrations (run: pixi run entra-teardown)."""
import json
import subprocess

for name in ("snowflake", "advisor-copilot", "fraud-sentinel", "marketing-genie"):
    apps = json.loads(subprocess.run(
        ["az", "ad", "app", "list", "--display-name", f"agent-authz-{name}", "-o", "json"],
        check=True, capture_output=True, text=True).stdout)
    for a in apps:
        subprocess.run(["az", "ad", "app", "delete", "--id", a["appId"]], check=True)
        print("deleted", a["displayName"], a["appId"])

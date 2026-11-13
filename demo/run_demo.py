"""
End-to-end demo. Prerequisites: pixi run entra-setup, pixi run sf-deploy,
PDP running (pixi run pdp), pixi run sync-horizon.

Run: pixi run demo
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import httpx
import snowflake.connector
from rich.console import Console
from rich.table import Table

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pep"))
import identity  # noqa: E402
from gateway import AgentGateway, FailClosed  # noqa: E402

con = Console()
PDP = os.environ.get("PDP_URL", "http://127.0.0.1:8180")
ADMIN = {"x-admin-key": os.environ["PDP_ADMIN_KEY"]}


def title(n: int, text: str, why: str) -> None:
    con.rule(f"[bold cyan]{n}. {text}")
    con.print(f"[dim]{why}[/dim]")


def show(r, max_rows: int = 3) -> None:
    t = Table("column", "PDP decision")
    for c, d in r.column_decisions.items():
        t.add_row(c, "[green]PERMIT" if d else "[red]DENY")
    con.print(t)
    con.print(f"row scopes permitted: {r.regions or '[red]none'}")
    if r.rows:
        con.print(f"rows returned (first {max_rows}): {r.columns}")
        for row in r.rows[:max_rows]:
            con.print(f"  {row}")


def raw(gw: AgentGateway, sql: str) -> None:
    cols, rows = gw.raw_sql(sql)
    con.print(f"[yellow]direct SQL:[/yellow] {sql}")
    con.print(f"  -> {len(rows)} rows {cols}")
    for row in rows[:3]:
        con.print(f"  {row}")


def admin_sql(sql: str) -> None:
    c = snowflake.connector.connect(connection_name=os.environ.get("SNOWFLAKE_CONNECTION", "default"))
    c.cursor().execute("USE ROLE AGENT_AUTHZ_ADMIN")
    c.cursor().execute(sql)
    c.close()


def s1() -> None:
    title(1, "Autonomous agent (workload identity) - Fraud Sentinel",
          "Entra client credentials -> SERVICE_AGENT user. Cedar: own ceiling (sensitivity <= 2), all its regions.")
    fs = AgentGateway("fraud-sentinel")
    show(fs.query("TRANSACTIONS", ["TXN_ID", "AMOUNT", "MERCHANT", "FRAUD_FLAG"], "fraud_detection"))
    con.print("\nRequesting a RESTRICTED column (IBAN, sensitivity 3):")
    show(fs.query("CUSTOMERS", ["CUSTOMER_ID", "IBAN", "RISK_SCORE"], "fraud_detection"))


def s2() -> None:
    title(2, "Delegated agent (on behalf of a human) - Advisor Copilot",
          "Entra On-Behalf-Of: token carries agent appid + human upn. Access = agent ceiling AND human clearance.")
    adv = AgentGateway("advisor-copilot", identity.user_token_for_advisor())
    con.print("[bold]a) KYC review without human approval[/bold] (EU AI Act Art. 14, high-risk agent):")
    show(adv.query("CUSTOMERS", ["CUSTOMER_ID", "FULL_NAME", "DATE_OF_BIRTH", "SEGMENT"], "kyc_review"))
    con.print("[bold]b) same request, human approval recorded[/bold]:")
    show(adv.query("CUSTOMERS", ["CUSTOMER_ID", "FULL_NAME", "DATE_OF_BIRTH", "SEGMENT"], "kyc_review",
                   human_approval=True))
    con.print("[bold]c) purpose 'customer_service' asks for DATE_OF_BIRTH[/bold] (purpose limitation):")
    show(adv.query("CUSTOMERS", ["CUSTOMER_ID", "EMAIL", "DATE_OF_BIRTH"], "customer_service",
                   human_approval=True))


def s3() -> None:
    title(3, "Gateway asks for one thing, agent queries more",
          "Snowflake only reveals what the PDP permitted for THIS session (decision grants via Horizon policies).")
    adv2 = AgentGateway("advisor-copilot", identity.user_token_for_advisor())
    adv2.query("CUSTOMERS", ["CUSTOMER_ID", "SEGMENT"], "customer_service")
    raw(adv2, "SELECT CUSTOMER_ID, SEGMENT, FULL_NAME, IBAN, REGION FROM CUSTOMERS LIMIT 3")


def s4() -> None:
    title(4, "Agent bypasses the gateway entirely",
          "A valid Entra token, a fresh session, no PDP decision -> agent-aware policies return nothing.")
    rogue = AgentGateway("fraud-sentinel")
    raw(rogue, "SELECT * FROM TRANSACTIONS LIMIT 5")


def s5() -> None:
    fs = AgentGateway("fraud-sentinel")
    title(5, "Registry kill switch",
          "Unapproved agent is denied everywhere; approval can be revoked live (DORA ICT incident response).")
    show(AgentGateway("marketing-genie").query("CUSTOMERS", ["SEGMENT"], "marketing"))
    httpx.post(f"{PDP}/admin/agents/fraud-sentinel/approved/false", headers=ADMIN)
    con.print("[bold]fraud-sentinel revoked in the PDP:[/bold]")
    show(fs.query("TRANSACTIONS", ["TXN_ID", "AMOUNT"], "fraud_detection"))
    httpx.post(f"{PDP}/admin/agents/fraud-sentinel/approved/true", headers=ADMIN)


def s6() -> None:
    title(6, "Fail closed when the PDP is unavailable",
          "Gateway refuses to run; Snowflake masks even previously granted data once the heartbeat is stale.")
    down = AgentGateway("fraud-sentinel")
    down.http.base_url = "http://127.0.0.1:9"  # nothing listens here
    try:
        down.query("TRANSACTIONS", ["TXN_ID"], "fraud_detection")
    except FailClosed as exc:
        con.print(f"[red]gateway: FailClosed[/red] {exc}")
    live = AgentGateway("fraud-sentinel")
    live.query("TRANSACTIONS", ["TXN_ID", "AMOUNT"], "fraud_detection")
    raw(live, "SELECT TXN_ID, AMOUNT FROM TRANSACTIONS LIMIT 2")
    admin_sql("UPDATE AGENT_AUTHZ_DEMO.GOVERNANCE.PDP_SYNC_STATE SET LAST_HEARTBEAT = '2000-01-01'")
    con.print("[bold]PDP heartbeat stale (simulated outage):[/bold]")
    raw(live, "SELECT TXN_ID, AMOUNT FROM TRANSACTIONS LIMIT 2")
    admin_sql("UPDATE AGENT_AUTHZ_DEMO.GOVERNANCE.PDP_SYNC_STATE SET LAST_HEARTBEAT = CURRENT_TIMESTAMP()")


def s7() -> None:
    fs = AgentGateway("fraud-sentinel")
    title(7, "Bulk exfiltration brake (Data Movement Policy)",
          "Independent of the PDP: agents cannot pull more than 200 classified rows per statement.")
    try:
        fs.query("TRANSACTIONS", ["TXN_ID", "AMOUNT"], "fraud_detection", limit=1000)
    except snowflake.connector.errors.ProgrammingError as exc:
        con.print(f"[red]blocked by Snowflake:[/red] {exc.msg}")


def s8() -> None:
    title(8, "Humans are unaffected",
          "The same user, without an agent, gets normal RBAC (policies only act on agent sessions).")
    c = snowflake.connector.connect(connection_name=os.environ.get("SNOWFLAKE_CONNECTION", "default"))
    cur = c.cursor()
    cur.execute("USE ROLE AGENT_AUTHZ_ADMIN")
    con.print(cur.execute("SELECT CUSTOMER_ID, FULL_NAME, IBAN, REGION FROM AGENT_AUTHZ_DEMO.BANKING.CUSTOMERS "
                          "WHERE REGION = 'NL' LIMIT 2").fetchall())


def s9() -> None:
    title(9, "Audit evidence: PDP decision log joined to Snowflake query history",
          "Every agent query carries the PDP batch ids; decisions are shipped to Snowflake with the policy hash.")
    c = snowflake.connector.connect(connection_name=os.environ.get("SNOWFLAKE_CONNECTION", "default"))
    cur = c.cursor()
    cur.execute("USE ROLE AGENT_AUTHZ_ADMIN")
    time.sleep(35)  # let the PDP heartbeat ship the decision log
    rows = cur.execute("""
        SELECT q.QUERY_ID, q.USER_NAME, q.ROLE_NAME, TRY_PARSE_JSON(q.QUERY_TAG):agent::STRING AGENT,
               COUNT(DISTINCT IFF(d.DECISION, d.DECISION_ID, NULL)) PERMITS,
               COUNT(DISTINCT IFF(d.DECISION, NULL, d.DECISION_ID)) DENIES,
               ARRAY_UNIQUE_AGG(f.value::STRING) POLICIES, ANY_VALUE(d.POLICY_HASH) POLICY_HASH
        FROM TABLE(AGENT_AUTHZ_DEMO.INFORMATION_SCHEMA.QUERY_HISTORY(RESULT_LIMIT => 1000)) q
        JOIN AGENT_AUTHZ_DEMO.GOVERNANCE.PDP_DECISIONS d
          ON ARRAY_CONTAINS(d.BATCH_ID::VARIANT, TRY_PARSE_JSON(q.QUERY_TAG):pdp_batches)
        , LATERAL FLATTEN(d.DETERMINING_POLICIES, outer => TRUE) f
        WHERE q.START_TIME > DATEADD(minute, -15, CURRENT_TIMESTAMP())
        GROUP BY ALL ORDER BY MIN(q.START_TIME) DESC LIMIT 8""").fetchall()
    t = Table("query_id", "user", "role", "agent", "permits", "denies", "cedar policies", "policy hash")
    for r in rows:
        t.add_row(*[str(x) for x in r])
    con.print(t)


SCENARIOS = [s1, s2, s3, s4, s5, s6, s7, s8, s9]


def main(selected: list[int]) -> None:
    con.print(httpx.get(f"{PDP}/healthz").json())
    for n in selected or range(1, 10):
        SCENARIOS[n - 1]()


if __name__ == "__main__":
    main([int(a) for a in sys.argv[1:]])

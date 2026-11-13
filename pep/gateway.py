"""
Agent gateway = Policy Enforcement Point (PEP) in front of Snowflake.

Every tool call an agent makes ("read these columns of this table") is
turned into AuthZEN requests to the PDP, at the finest granularity:

  * one read_column decision per requested column  (/access/v1/evaluations)
  * one read_rows decision per row scope            (/access/v1/search/resource)

The gateway then runs only what was permitted, inside the agent's own
Snowflake session (Entra token -> agentic External OAuth), and tags the
query with the PDP batch ids so audit can join Snowflake ACCESS_HISTORY to
the PDP decision log.

Fail closed: if the PDP cannot be reached or answers with an error, the
tool call is refused. Snowflake independently enforces the same decisions
(decision grants), so a buggy or bypassed gateway cannot widen access.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

import httpx
import snowflake.connector

import identity

PDP = os.environ.get("PDP_URL", "http://127.0.0.1:8180")
AGENT_ROLE = {"advisor-copilot": "AGENT_ADVISOR_COPILOT",
              "fraud-sentinel": "AGENT_FRAUD_SENTINEL",
              "marketing-genie": "AGENT_MARKETING_GENIE"}
APP_ID = {"advisor-copilot": "ADVISOR_APP_ID", "fraud-sentinel": "SENTINEL_APP_ID",
          "marketing-genie": "GENIE_APP_ID"}
IDENT = re.compile(r"^[A-Z_][A-Z0-9_]*$")


class FailClosed(Exception):
    """The PDP could not be consulted - nothing is executed."""


@dataclass
class ToolResult:
    columns: list[str]
    rows: list[tuple]
    column_decisions: dict[str, bool]
    regions: list[str]
    batch_ids: list[str] = field(default_factory=list)
    query_id: str | None = None


class AgentGateway:
    def __init__(self, agent: str, user_token: str | None = None) -> None:
        """
        agent      : registry name of the calling agent
        user_token : delegated mode only - the human's token for the agent
                     (audience = the agent app). Exchanged On-Behalf-Of.
        """
        self.agent = agent
        self.app_id = os.environ[APP_ID[agent]]
        if user_token:
            self.token = identity.obo_token_for_snowflake(user_token)
        else:
            self.token = identity.workload_token(agent)
        self.sf = snowflake.connector.connect(
            account=os.environ["SNOWFLAKE_ACCOUNT"], authenticator="oauth", token=self.token,
            role=AGENT_ROLE[agent], warehouse="AGENT_AUTHZ_WH", database="AGENT_AUTHZ_DEMO",
            schema="BANKING")
        self.session_id = self.sf.cursor().execute("SELECT CURRENT_SESSION()").fetchone()[0]
        self.http = httpx.Client(base_url=PDP, timeout=5,
                                 headers={"Authorization": f"Bearer {self.token}"})

    # ------------------------------------------------------------------
    def _pdp(self, path: str, body: dict) -> dict:
        try:
            r = self.http.post(path, json=body)
        except httpx.HTTPError as exc:
            raise FailClosed(f"PDP unreachable: {exc}") from exc
        if r.status_code != 200:
            raise FailClosed(f"PDP error {r.status_code}: {r.text[:200]}")
        return r.json()

    def query(self, table: str, columns: list[str], purpose: str,
              human_approval: bool = False, limit: int = 20) -> ToolResult:
        table, columns = table.upper(), [c.upper() for c in columns]
        if not IDENT.match(table) or not all(IDENT.match(c) for c in columns):
            raise ValueError("invalid identifier")
        ctx = {"purpose": purpose, "human_approval": human_approval,
               "snowflake_session": self.session_id}
        subject = {"type": "agent", "id": self.app_id}

        # 1) per-column decisions (AuthZEN batch)
        col = self._pdp("/access/v1/evaluations", {
            "subject": subject, "action": {"name": "read_column"}, "context": ctx,
            "evaluations": [{"resource": {"type": "Column", "id": f"{table}.{c}"}} for c in columns],
            "options": {"evaluations_semantic": "execute_all"},
        })
        decisions = {c: e["decision"] for c, e in zip(columns, col["evaluations"])}
        # 2) row scopes (AuthZEN resource search)
        rows = self._pdp("/access/v1/search/resource", {
            "subject": subject, "action": {"name": "read_rows"}, "context": ctx,
            "resource": {"type": "RowScope", "properties": {"table": table}},
        })
        regions = [r["properties"]["region"] for r in rows["results"]]
        batches = [col["context"]["batch_id"], rows["context"]["batch_id"]]

        allowed = [c for c in columns if decisions[c]]
        if not allowed or not regions:
            return ToolResult([], [], decisions, regions, batches)

        # 3) execute only what was permitted, tagged for audit
        cur = self.sf.cursor()
        cur.execute("ALTER SESSION SET QUERY_TAG = %s", (json.dumps({
            "pdp_batches": batches, "agent": self.agent, "purpose": purpose}),))
        placeholders = ",".join(["%s"] * len(regions))
        cur.execute(f"SELECT {', '.join(allowed)} FROM {table} "
                    f"WHERE REGION IN ({placeholders}) LIMIT {int(limit)}", regions)
        return ToolResult(allowed, cur.fetchall(), decisions, regions, batches, cur.sfqid)

    def raw_sql(self, sql: str) -> tuple[list[str], list[tuple]]:
        """What a misbehaving agent would do: query Snowflake around the PDP."""
        cur = self.sf.cursor().execute(sql)
        return [d[0] for d in cur.description], cur.fetchall()

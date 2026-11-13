"""
PDP -> Snowflake sink.

  * write_grants()   : every PERMIT that names a Snowflake session becomes a
                       short-lived row in GOVERNANCE.DECISION_GRANTS before
                       the PDP answers (so there is no race with the query).
  * heartbeat thread : keeps PDP_SYNC_STATE fresh and ships the decision log
                       to PDP_DECISIONS. If the PDP dies, the heartbeat goes
                       stale and Snowflake policies fail closed.

Authenticates as AGENT_AUTHZ_SYNC_SVC with a key pair (not an agent).
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path

import snowflake.connector
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
KEY = ROOT / ".cache" / "sync_key.p8"
GRANT_TTL_SECONDS = int(os.environ.get("PDP_GRANT_TTL_SECONDS", "300"))
HEARTBEAT_SECONDS = int(os.environ.get("PDP_HEARTBEAT_SECONDS", "30"))
G = "AGENT_AUTHZ_DEMO.GOVERNANCE"


def connect() -> snowflake.connector.SnowflakeConnection:
    pk = serialization.load_pem_private_key(KEY.read_bytes(), None)
    return snowflake.connector.connect(
        account=os.environ["SNOWFLAKE_ACCOUNT"], user="AGENT_AUTHZ_SYNC_SVC",
        private_key=pk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()),
        role="AGENT_AUTHZ_SYNC", warehouse="AGENT_AUTHZ_WH", database="AGENT_AUTHZ_DEMO",
        schema="GOVERNANCE", client_session_keep_alive=True)


class SnowflakeSink:
    def __init__(self, decision_log: Path, policy_hash_fn) -> None:
        self._conn = None
        self._lock = threading.Lock()
        self._log = decision_log
        self._offset_file = decision_log.with_suffix(".shipped")
        self._shipped = int(self._offset_file.read_text()) if self._offset_file.exists() else 0
        self._policy_hash = policy_hash_fn

    @property
    def conn(self):
        if self._conn is None or self._conn.is_closed():
            self._conn = connect()
        return self._conn

    def write_grants(self, grants: list[dict]) -> None:
        """grants: dicts with decision_id, session_id, login, role, kind, resource_id."""
        if not grants:
            return
        rows = [json.dumps({"grant_id": str(uuid.uuid4()), "decision_id": g["decision_id"],
                            "session_id": int(g["session_id"]), "login": g["login"].upper(),
                            "role": g["role"], "kind": g["kind"], "resource_id": g["resource_id"]})
                for g in grants]
        with self._lock:
            self.conn.cursor().execute(
                f"INSERT INTO {G}.DECISION_GRANTS (GRANT_ID, DECISION_ID, SESSION_ID, SNOWFLAKE_LOGIN,"
                " SNOWFLAKE_ROLE, KIND, RESOURCE_ID, EXPIRES_AT)"
                " SELECT j:grant_id, j:decision_id, j:session_id, j:login, j:role, j:kind,"
                f" j:resource_id, DATEADD(second, {GRANT_TTL_SECONDS}, CURRENT_TIMESTAMP())"
                " FROM (SELECT PARSE_JSON(column1) j FROM VALUES "
                + ",".join(["(%s)"] * len(rows)) + ")", rows)

    def beat(self) -> None:
        with self._lock:
            cur = self.conn.cursor()
            cur.execute(f"UPDATE {G}.PDP_SYNC_STATE SET LAST_HEARTBEAT = CURRENT_TIMESTAMP(),"
                        " POLICY_HASH = %s WHERE ID = 1", (self._policy_hash(),))
            cur.execute(f"DELETE FROM {G}.DECISION_GRANTS WHERE EXPIRES_AT < CURRENT_TIMESTAMP()")
            self._ship_decisions(cur)

    def _ship_decisions(self, cur) -> None:
        if not self._log.exists():
            return
        lines = self._log.read_text().splitlines()
        new = [json.loads(l) for l in lines[self._shipped:] if l.strip()]
        if not new:
            return
        for i in range(0, len(new), 500):
            chunk = [json.dumps(d) for d in new[i:i + 500]]
            cur.execute(
                f"INSERT INTO {G}.PDP_DECISIONS SELECT j:decision_id, j:batch_id, j:ts::TIMESTAMP_TZ,"
                " j:agent, j:agent_app_id, j:agent_mode, j:risk_tier, j:on_behalf_of, j:action,"
                " j:resource_type, j:resource_id, j:purpose, j:human_approval::BOOLEAN,"
                " j:decision::BOOLEAN, j:determining_policies::ARRAY, j:policy_hash, j"
                " FROM (SELECT PARSE_JSON(column1) j FROM VALUES "
                + ",".join(["(%s)"] * len(chunk)) + ")", chunk)
        self._shipped = len(lines)
        self._offset_file.write_text(str(self._shipped))

    def start(self) -> None:
        def loop():
            while True:
                try:
                    self.beat()
                except Exception as exc:  # noqa: BLE001 - keep beating, log only
                    print(f"[sink] heartbeat failed: {exc}")
                    self._conn = None
                time.sleep(HEARTBEAT_SECONDS)
        threading.Thread(target=loop, daemon=True).start()

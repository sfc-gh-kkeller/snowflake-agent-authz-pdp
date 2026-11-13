"""
Horizon -> PDP: harvest Snowflake classification as Cedar resource attributes.

For every column in the governed schema
  * DATA_SENSITIVITY tag             -> resource.sensitivity (0..3)
  * SNOWFLAKE.CORE.PRIVACY_CATEGORY  -> resource.privacy_category
    (system tag set by Horizon sensitive-data classification)
  * ALLOWED_PURPOSES tag             -> resource.allowed_purposes
  * stamps PDP_RESOURCE_ID = "<TABLE>.<COLUMN>" if missing, so the
    tag-based PDP masking policy covers the column
For every table with a ROW_SCOPE_COLUMN tag
  * each distinct value becomes a RowScope "<TABLE>/<VALUE>"

Unclassified columns are published with sensitivity 3 (deny by default).

Run: pixi run sync-horizon     (schedule it, e.g. every 15 minutes)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pep"))
sys.path.insert(0, str(ROOT / "pdp"))
import identity  # noqa: E402,F401  (loads .env)
from snowsink import connect  # noqa: E402

DB, SCHEMA = "AGENT_AUTHZ_DEMO", "BANKING"
GOV = f"{DB}.GOVERNANCE"
LEVEL = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}
PDP = os.environ.get("PDP_URL", "http://127.0.0.1:8180")


def harvest() -> dict:
    cur = connect().cursor()
    tables = [r[0] for r in cur.execute(
        f"SELECT TABLE_NAME FROM {DB}.INFORMATION_SCHEMA.TABLES "
        f"WHERE TABLE_SCHEMA = '{SCHEMA}' AND TABLE_TYPE = 'BASE TABLE'").fetchall()]
    columns, row_scopes = [], []
    for t in tables:
        fq = f"{DB}.{SCHEMA}.{t}"
        tags: dict[str, dict[str, str]] = {}
        for col, tag_db, tag_schema, tag, val in cur.execute(
            "SELECT COLUMN_NAME, TAG_DATABASE, TAG_SCHEMA, TAG_NAME, TAG_VALUE FROM TABLE("
            f"{DB}.INFORMATION_SCHEMA.TAG_REFERENCES_ALL_COLUMNS('{fq}', 'table'))").fetchall():
            tags.setdefault(col, {})[f"{tag_db}.{tag_schema}.{tag}"] = val
        cols = [r[0] for r in cur.execute(
            f"SELECT COLUMN_NAME FROM {DB}.INFORMATION_SCHEMA.COLUMNS "
            f"WHERE TABLE_SCHEMA = '{SCHEMA}' AND TABLE_NAME = '{t}' ORDER BY ORDINAL_POSITION").fetchall()]
        scope_col = cur.execute(
            f"SELECT SYSTEM$GET_TAG('{GOV}.ROW_SCOPE_COLUMN', '{fq}', 'table')").fetchone()[0]
        for c in cols:
            ct = tags.get(c, {})
            rid = f"{t}.{c}"
            if c == scope_col:
                # the row-scope column is an argument of the row access policy
                # and must not be masked; it is governed by RowScope decisions
                if f"{GOV}.PDP_RESOURCE_ID" in ct:
                    cur.execute(f"ALTER TABLE {fq} MODIFY COLUMN {c} UNSET TAG {GOV}.PDP_RESOURCE_ID")
                continue
            if ct.get(f"{GOV}.PDP_RESOURCE_ID") != rid:
                cur.execute(f"ALTER TABLE {fq} MODIFY COLUMN {c} SET TAG {GOV}.PDP_RESOURCE_ID = '{rid}'")
            purposes = ct.get(f"{GOV}.ALLOWED_PURPOSES")
            columns.append({
                "id": rid, "table": t, "column": c,
                "sensitivity": LEVEL.get(ct.get(f"{GOV}.DATA_SENSITIVITY", ""), 3),
                "privacy_category": ct.get("SNOWFLAKE.CORE.PRIVACY_CATEGORY", "NONE"),
                "semantic_category": ct.get("SNOWFLAKE.CORE.SEMANTIC_CATEGORY"),
                "allowed_purposes": [p.strip() for p in purposes.split(",")] if purposes else [],
            })
        if scope_col:
            for (v,) in cur.execute(f"SELECT DISTINCT {scope_col} FROM {fq} ORDER BY 1").fetchall():
                row_scopes.append({"id": f"{t}/{v}", "table": t, "region": v})
    return {"columns": columns, "row_scopes": row_scopes}


def main() -> None:
    res = harvest()
    r = httpx.put(f"{PDP}/admin/resources", json=res,
                  headers={"x-admin-key": os.environ["PDP_ADMIN_KEY"]}, timeout=30)
    r.raise_for_status()
    print(json.dumps(r.json()))
    for c in res["columns"]:
        print(f"  {c['id']:28} sens={c['sensitivity']} privacy={c['privacy_category']:16} purposes={c['allowed_purposes']}")
    print("  row scopes:", [s["id"] for s in res["row_scopes"]])


if __name__ == "__main__":
    main()

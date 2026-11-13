"""Offline policy tests: no Entra, no Snowflake. Run: pixi run test"""
import os
import sys
from pathlib import Path

os.environ.setdefault("DEMO_USER_UPN", "rm@example.com")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pdp"))
import server  # noqa: E402

S = server.store
S.resources = {
    "columns": [
        {"id": "CUSTOMERS.FULL_NAME", "table": "CUSTOMERS", "column": "FULL_NAME", "sensitivity": 3,
         "privacy_category": "IDENTIFIER", "allowed_purposes": ["kyc_review", "customer_service"]},
        {"id": "CUSTOMERS.SEGMENT", "table": "CUSTOMERS", "column": "SEGMENT", "sensitivity": 1,
         "privacy_category": "NONE", "allowed_purposes": []},
        {"id": "TRANSACTIONS.AMOUNT", "table": "TRANSACTIONS", "column": "AMOUNT", "sensitivity": 2,
         "privacy_category": "NONE", "allowed_purposes": []},
    ],
    "row_scopes": [
        {"id": "CUSTOMERS/UK", "table": "CUSTOMERS", "region": "UK"},
        {"id": "CUSTOMERS/NL", "table": "CUSTOMERS", "region": "NL"},
    ],
}
ctx = server._context_for


def d(agent, action, rtype, rid, c):
    return server._cedar_decide(agent, action, rtype, rid, c)[0]


def test_delegated_needs_purpose_and_approval_for_identifiers():
    rm = ctx("rm@example.com", {"purpose": "kyc_review"})
    assert not d("advisor-copilot", "read_column", "Column", "CUSTOMERS.FULL_NAME", rm)  # no approval
    rm_ok = ctx("rm@example.com", {"purpose": "kyc_review", "human_approval": True})
    assert d("advisor-copilot", "read_column", "Column", "CUSTOMERS.FULL_NAME", rm_ok)
    wrong_purpose = ctx("rm@example.com", {"purpose": "marketing", "human_approval": True})
    assert not d("advisor-copilot", "read_column", "Column", "CUSTOMERS.FULL_NAME", wrong_purpose)


def test_delegated_is_capped_by_human_clearance():
    low = ctx("alex.rm@example.com", {"purpose": "kyc_review", "human_approval": True})
    assert d("advisor-copilot", "read_column", "Column", "CUSTOMERS.SEGMENT", low)
    assert not d("advisor-copilot", "read_column", "Column", "TRANSACTIONS.AMOUNT", low)


def test_delegated_requires_human():
    assert not d("advisor-copilot", "read_column", "Column", "CUSTOMERS.SEGMENT", {})


def test_autonomous_ceiling_and_no_borrowing():
    assert d("fraud-sentinel", "read_column", "Column", "TRANSACTIONS.AMOUNT", {})
    assert not d("fraud-sentinel", "read_column", "Column", "CUSTOMERS.FULL_NAME",
                 {"purpose": "fraud_detection"})  # sensitivity 3 > 2
    # autonomous agent claiming a human is denied (confused deputy)
    assert not d("fraud-sentinel", "read_column", "Column", "TRANSACTIONS.AMOUNT", ctx("rm@example.com", {}))


def test_rows_intersection():
    rm = ctx("rm@example.com", {})
    assert d("advisor-copilot", "read_rows", "RowScope", "CUSTOMERS/UK", rm)
    assert not d("advisor-copilot", "read_rows", "RowScope", "CUSTOMERS/NL", rm)
    assert d("fraud-sentinel", "read_rows", "RowScope", "CUSTOMERS/NL", {})


def test_purpose_limitation_quasi_identifier():
    S.resources["columns"].append({"id": "CUSTOMERS.DATE_OF_BIRTH", "table": "CUSTOMERS",
                                   "column": "DATE_OF_BIRTH", "sensitivity": 3,
                                   "privacy_category": "QUASI_IDENTIFIER", "allowed_purposes": ["kyc_review"]})
    ok = ctx("rm@example.com", {"purpose": "kyc_review", "human_approval": True})
    bad = ctx("rm@example.com", {"purpose": "customer_service", "human_approval": True})
    assert d("advisor-copilot", "read_column", "Column", "CUSTOMERS.DATE_OF_BIRTH", ok)
    assert not d("advisor-copilot", "read_column", "Column", "CUSTOMERS.DATE_OF_BIRTH", bad)


def test_kill_switch():
    assert not d("marketing-genie", "read_column", "Column", "CUSTOMERS.SEGMENT", {})

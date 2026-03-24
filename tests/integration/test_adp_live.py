"""Live ADP smoke tests.

Required env vars:
- `ADP_TOKEN_URL`
- `ADP_EMPLOYEE_URL`
- `ADP_CLIENT_ID`
- `ADP_CLIENT_SECRET`
- `ADP_CERT_PEM`

These tests call ADP live and are skipped unless those values are present.
"""

from __future__ import annotations

from app.adp_client import get_adp_employees, get_adp_token

from ._gating import require_env

require_env("ADP_TOKEN_URL", "ADP_EMPLOYEE_URL", "ADP_CLIENT_ID", "ADP_CLIENT_SECRET", "ADP_CERT_PEM")


def test_live_adp_token_retrieval():
    token = get_adp_token()
    assert isinstance(token, str)
    assert token


def test_live_adp_workers_fetch():
    token = get_adp_token()
    assert isinstance(token, str)
    employees = get_adp_employees(token, limit=1, paginate_all=False)
    assert isinstance(employees, list)
    assert all(isinstance(worker, dict) for worker in employees)


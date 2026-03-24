"""Optional live scheduled-update dry-run workflow smoke test.

Required env vars:
- `ENABLE_UPDATE_DRY_RUN_LIVE_TEST`
- ADP and LDAP integration env vars

This test exercises the update workflow end-to-end with `dry_run=True` and a
short lookback window. It is opt-in because it still performs live ADP and LDAP
reads across the real workflow path.
"""

from __future__ import annotations

import pytest

from app.models import UpdateJobSettings
from app.updates import run_scheduled_update_existing_users

from ._gating import require_env

require_env(
    "ENABLE_UPDATE_DRY_RUN_LIVE_TEST",
    "ADP_TOKEN_URL",
    "ADP_EMPLOYEE_URL",
    "ADP_CLIENT_ID",
    "ADP_CLIENT_SECRET",
    "ADP_CERT_PEM",
    "LDAP_SERVER",
    "LDAP_USER",
    "LDAP_PASSWORD",
    "LDAP_SEARCH_BASE",
    "CA_BUNDLE_PATH",
)


@pytest.mark.integration
def test_live_update_workflow_dry_run_smoke(monkeypatch):
    monkeypatch.setattr(
        "app.updates.get_update_job_settings",
        lambda: UpdateJobSettings(
            dry_run=True,
            lookback_days=1,
            include_missing_last_updated=False,
            log_no_changes=False,
        ),
    )
    run_scheduled_update_existing_users(None)

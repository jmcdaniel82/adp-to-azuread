"""Optional live update write-path test against a staging account."""

from __future__ import annotations

import pytest

from app.models import UpdateJobSettings
from app.provisioning import provision_user_in_ad
from app.updates import run_scheduled_update_existing_users

from ._gating import require_env
from ._live_directory import (
    close_live_connection,
    delete_entry_by_dn,
    find_entry_by_employee_id,
    integration_employee_id,
    make_integration_worker,
    open_live_connection,
)

require_env(
    "ENABLE_UPDATE_WRITE_LIVE_TEST",
    "LDAP_SERVER",
    "LDAP_USER",
    "LDAP_PASSWORD",
    "LDAP_SEARCH_BASE",
    "LDAP_CREATE_BASE",
    "CA_BUNDLE_PATH",
)


@pytest.mark.integration
def test_live_update_workflow_write_and_cleanup(monkeypatch):
    settings, conn = open_live_connection(require_create_base=True)
    employee_id = integration_employee_id("INTUPD")
    original_worker = make_integration_worker(
        employee_id,
        first_name="Integration",
        last_name="Update",
        job_title="Integration Original Title",
    )
    updated_worker = make_integration_worker(
        employee_id,
        first_name="Integration",
        last_name="Update",
        job_title="Integration Updated Title",
    )

    created_dn = ""
    try:
        provision_user_in_ad(
            original_worker,
            conn,
            settings.search_base,
            settings.create_base or "",
            max_retry_attempts=3,
            cn_collision_threshold=2,
        )
        entry = find_entry_by_employee_id(conn, settings.search_base, employee_id)
        assert entry is not None
        created_dn = str(entry.distinguishedName.value)

        monkeypatch.setattr(
            "app.updates.get_update_job_settings",
            lambda: UpdateJobSettings(
                dry_run=False,
                lookback_days=0,
                include_missing_last_updated=True,
                log_no_changes=False,
            ),
        )
        monkeypatch.setattr("app.updates.get_adp_token", lambda: "integration-token")
        monkeypatch.setattr("app.updates.get_adp_employees", lambda token: [updated_worker])

        run_scheduled_update_existing_users(None)

        refreshed = find_entry_by_employee_id(conn, settings.search_base, employee_id)
        assert refreshed is not None
        assert str(refreshed.title.value) == "Integration Updated Title"
    finally:
        delete_entry_by_dn(conn, created_dn)
        close_live_connection(conn, "integration_live_update_write")

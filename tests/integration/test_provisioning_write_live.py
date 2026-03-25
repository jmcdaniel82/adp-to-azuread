"""Optional live provisioning write-path test against a staging OU."""

from __future__ import annotations

import pytest

from app.provisioning import provision_user_in_ad

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
    "ENABLE_PROVISIONING_WRITE_LIVE_TEST",
    "LDAP_SERVER",
    "LDAP_USER",
    "LDAP_PASSWORD",
    "LDAP_SEARCH_BASE",
    "LDAP_CREATE_BASE",
    "CA_BUNDLE_PATH",
)


@pytest.mark.integration
def test_live_provisioning_create_and_cleanup():
    settings, conn = open_live_connection(require_create_base=True)
    employee_id = integration_employee_id("INTPROV")
    worker = make_integration_worker(
        employee_id,
        first_name="Integration",
        last_name="Provision",
        job_title="Integration Provisioning Test",
    )

    created_dn = ""
    try:
        provision_user_in_ad(
            worker,
            conn,
            settings.search_base,
            settings.create_base or "",
            max_retry_attempts=3,
            cn_collision_threshold=2,
        )
        entry = find_entry_by_employee_id(conn, settings.search_base, employee_id)
        assert entry is not None
        created_dn = str(entry.distinguishedName.value)
        assert "CN=" in created_dn
        assert str(entry.employeeID.value) == employee_id
    finally:
        delete_entry_by_dn(conn, created_dn)
        close_live_connection(conn, "integration_live_provisioning_write")

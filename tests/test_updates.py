from datetime import datetime, timedelta, timezone

import pytest

from app.constants import ATTR_MAIL, ATTR_USER_PRINCIPAL_NAME
from app.ldap.modify import apply_ldap_modifications
from app.ldap_client import diff_update_attributes
from app.models import LdapSettings, UpdateJobSettings
from app.updates import run_scheduled_update_existing_users, select_update_candidates


class _DummyAttr:
    def __init__(self, value):
        self.value = value


class _DummyEntry:
    def __init__(self, attrs):
        self._attrs = attrs
        for key, value in attrs.items():
            setattr(self, key, _DummyAttr(value))

    def __getitem__(self, key):
        return _DummyAttr(self._attrs[key])


class _DummyConn:
    def __init__(self, entries):
        self.entries = entries
        self.result = {}
        self.modify_calls = []
        self.search_calls = []

    def search(self, *args, **kwargs):
        self.search_calls.append((args, kwargs))
        return True

    def modify(self, dn, changes):
        self.modify_calls.append((dn, changes))
        return True

    def unbind(self):
        return True


def test_email_routing_denylist_is_never_included_in_update_mods():
    entry = _DummyEntry({"mail": "old@example.com", "title": "Old Title"})
    desired = {
        ATTR_MAIL: "new@example.com",
        ATTR_USER_PRINCIPAL_NAME: "new@example.com",
        "title": "New Title",
    }
    changes = diff_update_attributes(entry, desired, context="EMP-1")
    assert ATTR_MAIL not in changes
    assert ATTR_USER_PRINCIPAL_NAME not in changes
    assert "title" in changes


def test_user_account_control_disable_is_skipped_when_account_already_disabled():
    entry = _DummyEntry({"userAccountControl": "514"})
    changes = diff_update_attributes(entry, {"userAccountControl": 514}, context="EMP-UAC")
    assert changes == {}


def test_user_account_control_disable_is_skipped_when_disabled_bit_already_set():
    entry = _DummyEntry({"userAccountControl": "66050"})
    changes = diff_update_attributes(entry, {"userAccountControl": 514}, context="EMP-UAC-BIT")
    assert changes == {}


def test_select_update_candidates_matches_job_filters():
    now = datetime(2026, 3, 16, tzinfo=timezone.utc)
    settings = UpdateJobSettings(
        dry_run=True,
        lookback_days=7,
        include_missing_last_updated=True,
        log_no_changes=False,
    )

    def employee(employee_id, country_code, updated_at=None):
        payload = {
            "workerID": {"idValue": employee_id},
            "workAssignments": [
                {
                    "assignedWorkLocations": [{"address": {"countryCode": country_code}}],
                }
            ],
            "workerDates": {"hireDate": "2025-03-01"},
        }
        if updated_at is not None:
            payload["meta"] = {"lastUpdatedDateTime": updated_at.isoformat()}
        return payload

    candidates, stats = select_update_candidates(
        [
            employee("EMPUS", "US", now - timedelta(days=1)),
            employee("EMPCA", "CA"),
            employee("EMPMX", "MX", now - timedelta(days=1)),
            employee("EMPOLD", "US", now - timedelta(days=10)),
            employee("EMPDUP", "US", now - timedelta(days=10)),
            employee("EMPDUP", "US", now - timedelta(days=1)),
        ],
        settings,
        context="test_select_update_candidates",
        now=now,
    )

    assert [candidate["workerID"]["idValue"] for candidate in candidates] == ["EMPUS", "EMPCA", "EMPDUP"]
    assert stats["missing_last_updated"] == 1
    assert stats["selected_missing_last_updated"] == 1
    assert stats["skipped_country"] == 1


def test_scheduled_update_dry_run_does_not_apply_modifications(monkeypatch, tmp_path):
    conn = _DummyConn(
        [_DummyEntry({"distinguishedName": "CN=User,DC=x", "department": "Finance", "manager": ""})]
    )
    ldap_settings = LdapSettings(
        server="ldap.example.com",
        user="EXAMPLE\\svc",
        password="pw",
        search_base="DC=example,DC=com",
        create_base=None,
        ca_bundle_path=str(tmp_path / "ca.pem"),
    )
    (tmp_path / "ca.pem").write_text("dummy", encoding="utf-8")

    monkeypatch.setattr(
        "app.updates.get_update_job_settings",
        lambda: UpdateJobSettings(
            dry_run=True, lookback_days=0, include_missing_last_updated=True, log_no_changes=False
        ),
    )
    monkeypatch.setattr("app.updates.get_adp_token", lambda: "token")
    monkeypatch.setattr(
        "app.updates.get_adp_employees",
        lambda token: [
            {
                "workerID": {"idValue": "EMP1"},
                "workAssignments": [{"assignedWorkLocations": [{"address": {"countryCode": "US"}}]}],
                "workerDates": {"hireDate": "2026-03-01"},
            }
        ],
    )
    monkeypatch.setattr("app.updates.validate_ldap_settings", lambda require_create_base=False: [])
    monkeypatch.setattr("app.updates.get_ldap_settings", lambda require_create_base=False: ldap_settings)
    monkeypatch.setattr("app.updates.create_ldap_server", lambda *args, **kwargs: object())
    monkeypatch.setattr("app.updates.make_conn_factory", lambda *args, **kwargs: lambda: conn)
    monkeypatch.setattr("app.updates.is_terminated_employee", lambda emp: False)
    monkeypatch.setattr("app.updates.build_update_attributes", lambda *args, **kwargs: {"title": "New Title"})
    monkeypatch.setattr(
        "app.updates.diff_update_attributes",
        lambda *args, **kwargs: {"title": [("MODIFY_REPLACE", ["New Title"])]},
    )
    monkeypatch.setattr(
        "app.updates.entry_attr_value", lambda entry, attr: "Old Title" if attr == "title" else "CN=User,DC=x"
    )
    monkeypatch.setattr("app.updates.safe_unbind", lambda conn, context: None)

    run_scheduled_update_existing_users(None)
    assert conn.modify_calls == []


def test_scheduled_update_no_change_path_logs_when_enabled(monkeypatch, caplog, tmp_path):
    conn = _DummyConn(
        [_DummyEntry({"distinguishedName": "CN=User,DC=x", "department": "Finance", "manager": ""})]
    )
    ldap_settings = LdapSettings(
        server="ldap.example.com",
        user="EXAMPLE\\svc",
        password="pw",
        search_base="DC=example,DC=com",
        create_base=None,
        ca_bundle_path=str(tmp_path / "ca.pem"),
    )
    (tmp_path / "ca.pem").write_text("dummy", encoding="utf-8")

    monkeypatch.setattr(
        "app.updates.get_update_job_settings",
        lambda: UpdateJobSettings(
            dry_run=True, lookback_days=0, include_missing_last_updated=True, log_no_changes=True
        ),
    )
    monkeypatch.setattr("app.updates.get_adp_token", lambda: "token")
    monkeypatch.setattr(
        "app.updates.get_adp_employees",
        lambda token: [
            {
                "workerID": {"idValue": "EMP1"},
                "workAssignments": [{"assignedWorkLocations": [{"address": {"countryCode": "US"}}]}],
                "workerDates": {"hireDate": "2026-03-01"},
            }
        ],
    )
    monkeypatch.setattr("app.updates.validate_ldap_settings", lambda require_create_base=False: [])
    monkeypatch.setattr("app.updates.get_ldap_settings", lambda require_create_base=False: ldap_settings)
    monkeypatch.setattr("app.updates.create_ldap_server", lambda *args, **kwargs: object())
    monkeypatch.setattr("app.updates.make_conn_factory", lambda *args, **kwargs: lambda: conn)
    monkeypatch.setattr("app.updates.is_terminated_employee", lambda emp: False)
    monkeypatch.setattr(
        "app.updates.build_update_attributes", lambda *args, **kwargs: {"title": "Same Title"}
    )
    monkeypatch.setattr("app.updates.diff_update_attributes", lambda *args, **kwargs: {})
    monkeypatch.setattr("app.updates.entry_attr_value", lambda entry, attr: "CN=User,DC=x")
    monkeypatch.setattr("app.updates.safe_unbind", lambda conn, context: None)

    with caplog.at_level("INFO"):
        run_scheduled_update_existing_users(None)
    assert "No updates needed for EMP1 at CN=User,DC=x" in caplog.text


def test_scheduled_update_only_targets_us_and_ca_users(monkeypatch, tmp_path):
    conn = _DummyConn(
        [_DummyEntry({"distinguishedName": "CN=User,DC=x", "department": "Finance", "manager": ""})]
    )
    ldap_settings = LdapSettings(
        server="ldap.example.com",
        user="EXAMPLE\\svc",
        password="pw",
        search_base="DC=example,DC=com",
        create_base=None,
        ca_bundle_path=str(tmp_path / "ca.pem"),
    )
    (tmp_path / "ca.pem").write_text("dummy", encoding="utf-8")

    monkeypatch.setattr(
        "app.updates.get_update_job_settings",
        lambda: UpdateJobSettings(
            dry_run=True, lookback_days=0, include_missing_last_updated=True, log_no_changes=False
        ),
    )
    monkeypatch.setattr("app.updates.get_adp_token", lambda: "token")
    monkeypatch.setattr(
        "app.updates.get_adp_employees",
        lambda token: [
            {
                "workerID": {"idValue": "EMPUS"},
                "workAssignments": [{"assignedWorkLocations": [{"address": {"countryCode": "US"}}]}],
                "workerDates": {"hireDate": "2026-03-01"},
            },
            {
                "workerID": {"idValue": "EMPCA"},
                "workAssignments": [{"assignedWorkLocations": [{"address": {"countryCode": "CA"}}]}],
                "workerDates": {"hireDate": "2026-03-01"},
            },
            {
                "workerID": {"idValue": "EMPMX"},
                "workAssignments": [{"assignedWorkLocations": [{"address": {"countryCode": "MX"}}]}],
                "workerDates": {"hireDate": "2026-03-01"},
            },
            {
                "workerID": {"idValue": "EMPUNKNOWN"},
                "workAssignments": [{}],
                "workerDates": {"hireDate": "2026-03-01"},
            },
        ],
    )
    monkeypatch.setattr("app.updates.validate_ldap_settings", lambda require_create_base=False: [])
    monkeypatch.setattr("app.updates.get_ldap_settings", lambda require_create_base=False: ldap_settings)
    monkeypatch.setattr("app.updates.create_ldap_server", lambda *args, **kwargs: object())
    monkeypatch.setattr("app.updates.make_conn_factory", lambda *args, **kwargs: lambda: conn)
    monkeypatch.setattr("app.updates.is_terminated_employee", lambda emp: False)
    monkeypatch.setattr(
        "app.updates.build_update_attributes",
        lambda *args, **kwargs: {"title": "Same Title"},
    )
    monkeypatch.setattr("app.updates.diff_update_attributes", lambda *args, **kwargs: {})
    monkeypatch.setattr("app.updates.entry_attr_value", lambda entry, attr: "CN=User,DC=x")
    monkeypatch.setattr("app.updates.safe_unbind", lambda conn, context: None)

    run_scheduled_update_existing_users(None)

    search_filters = [
        kwargs.get("search_filter") or args[1]
        for args, kwargs in conn.search_calls
        if kwargs.get("search_filter") or len(args) > 1
    ]
    employee_search_filters = [
        search_filter
        for search_filter in search_filters
        if search_filter.startswith("(employeeID=")
    ]
    assert employee_search_filters == ["(employeeID=EMPUS)", "(employeeID=EMPCA)"]


def test_scheduled_update_raises_when_token_missing(monkeypatch):
    monkeypatch.setattr(
        "app.updates.get_update_job_settings",
        lambda: UpdateJobSettings(
            dry_run=True,
            lookback_days=7,
            include_missing_last_updated=True,
            log_no_changes=False,
        ),
    )
    monkeypatch.setattr("app.updates.get_adp_token", lambda: None)

    with pytest.raises(RuntimeError, match="ADP token"):
        run_scheduled_update_existing_users(None)


def test_scheduled_update_filters_desired_attributes_to_enabled_fields(monkeypatch, tmp_path):
    conn = _DummyConn(
        [_DummyEntry({"distinguishedName": "CN=User,DC=x", "department": "Finance", "manager": ""})]
    )
    ldap_settings = LdapSettings(
        server="ldap.example.com",
        user="EXAMPLE\\svc",
        password="pw",
        search_base="DC=example,DC=com",
        create_base=None,
        ca_bundle_path=str(tmp_path / "ca.pem"),
    )
    (tmp_path / "ca.pem").write_text("dummy", encoding="utf-8")
    captured_desired = []

    monkeypatch.setattr(
        "app.updates.get_update_job_settings",
        lambda: UpdateJobSettings(
            dry_run=True,
            lookback_days=0,
            include_missing_last_updated=True,
            log_no_changes=False,
            enabled_fields=("title",),
        ),
    )
    monkeypatch.setattr("app.updates.get_adp_token", lambda: "token")
    monkeypatch.setattr(
        "app.updates.get_adp_employees",
        lambda token: [
            {
                "workerID": {"idValue": "EMP1"},
                "workAssignments": [{"assignedWorkLocations": [{"address": {"countryCode": "US"}}]}],
                "workerDates": {"hireDate": "2026-03-01"},
            }
        ],
    )
    monkeypatch.setattr("app.updates.validate_ldap_settings", lambda require_create_base=False: [])
    monkeypatch.setattr("app.updates.get_ldap_settings", lambda require_create_base=False: ldap_settings)
    monkeypatch.setattr("app.updates.create_ldap_server", lambda *args, **kwargs: object())
    monkeypatch.setattr("app.updates.make_conn_factory", lambda *args, **kwargs: lambda: conn)
    monkeypatch.setattr("app.updates.is_terminated_employee", lambda emp: False)
    monkeypatch.setattr(
        "app.updates.build_update_attributes",
        lambda *args, **kwargs: {"title": "New Title", "department": "Sales"},
    )
    monkeypatch.setattr(
        "app.updates.diff_update_attributes",
        lambda entry, desired, context="": captured_desired.append(desired) or {},
    )
    monkeypatch.setattr("app.updates.entry_attr_value", lambda entry, attr: "CN=User,DC=x")
    monkeypatch.setattr("app.updates.safe_unbind", lambda conn, context: None)

    run_scheduled_update_existing_users(None)

    assert captured_desired == [{"title": "New Title"}]


def test_scheduled_update_defaults_to_manager_only_scope(monkeypatch, tmp_path):
    conn = _DummyConn(
        [_DummyEntry({"distinguishedName": "CN=User,DC=x", "department": "Finance", "manager": ""})]
    )
    ldap_settings = LdapSettings(
        server="ldap.example.com",
        user="EXAMPLE\\svc",
        password="pw",
        search_base="DC=example,DC=com",
        create_base=None,
        ca_bundle_path=str(tmp_path / "ca.pem"),
    )
    (tmp_path / "ca.pem").write_text("dummy", encoding="utf-8")
    captured_desired = []

    monkeypatch.setattr(
        "app.updates.get_update_job_settings",
        lambda: UpdateJobSettings(
            dry_run=False,
            lookback_days=0,
            include_missing_last_updated=True,
            log_no_changes=False,
        ),
    )
    monkeypatch.setattr("app.updates.get_adp_token", lambda: "token")
    monkeypatch.setattr(
        "app.updates.get_adp_employees",
        lambda token: [
            {
                "workerID": {"idValue": "EMP1"},
                "workAssignments": [{"assignedWorkLocations": [{"address": {"countryCode": "US"}}]}],
                "workerDates": {"hireDate": "2026-03-01"},
            }
        ],
    )
    monkeypatch.setattr("app.updates.validate_ldap_settings", lambda require_create_base=False: [])
    monkeypatch.setattr("app.updates.get_ldap_settings", lambda require_create_base=False: ldap_settings)
    monkeypatch.setattr("app.updates.create_ldap_server", lambda *args, **kwargs: object())
    monkeypatch.setattr("app.updates.make_conn_factory", lambda *args, **kwargs: lambda: conn)
    monkeypatch.setattr("app.updates.is_terminated_employee", lambda emp: False)
    monkeypatch.setattr(
        "app.updates.build_update_attributes",
        lambda *args, **kwargs: {
            "title": "New Title",
            "department": "Sales",
            "manager": "CN=Manager,DC=example,DC=com",
        },
    )
    monkeypatch.setattr(
        "app.updates.diff_update_attributes",
        lambda entry, desired, context="": captured_desired.append(desired) or {},
    )
    monkeypatch.setattr("app.updates.entry_attr_value", lambda entry, attr: "CN=User,DC=x")
    monkeypatch.setattr("app.updates.safe_unbind", lambda conn, context: None)

    run_scheduled_update_existing_users(None)

    assert captured_desired == [{"manager": "CN=Manager,DC=example,DC=com"}]


def test_scheduled_update_still_disables_terminated_users_when_override_enabled(monkeypatch, tmp_path):
    conn = _DummyConn(
        [_DummyEntry({"distinguishedName": "CN=User,DC=x", "department": "Finance", "manager": ""})]
    )
    ldap_settings = LdapSettings(
        server="ldap.example.com",
        user="EXAMPLE\\svc",
        password="pw",
        search_base="DC=example,DC=com",
        create_base=None,
        ca_bundle_path=str(tmp_path / "ca.pem"),
    )
    (tmp_path / "ca.pem").write_text("dummy", encoding="utf-8")
    captured_desired = []

    monkeypatch.setattr(
        "app.updates.get_update_job_settings",
        lambda: UpdateJobSettings(
            dry_run=True,
            lookback_days=0,
            include_missing_last_updated=True,
            log_no_changes=False,
            enabled_fields=("title",),
            always_disable_terminated=True,
        ),
    )
    monkeypatch.setattr("app.updates.get_adp_token", lambda: "token")
    monkeypatch.setattr(
        "app.updates.get_adp_employees",
        lambda token: [
            {
                "workerID": {"idValue": "EMP1"},
                "workAssignments": [{"assignedWorkLocations": [{"address": {"countryCode": "US"}}]}],
                "workerDates": {"hireDate": "2026-03-01", "terminationDate": "2026-03-05T00:00:00Z"},
            }
        ],
    )
    monkeypatch.setattr("app.updates.validate_ldap_settings", lambda require_create_base=False: [])
    monkeypatch.setattr("app.updates.get_ldap_settings", lambda require_create_base=False: ldap_settings)
    monkeypatch.setattr("app.updates.create_ldap_server", lambda *args, **kwargs: object())
    monkeypatch.setattr("app.updates.make_conn_factory", lambda *args, **kwargs: lambda: conn)
    monkeypatch.setattr("app.updates.is_terminated_employee", lambda emp: True)
    monkeypatch.setattr(
        "app.updates.diff_update_attributes",
        lambda entry, desired, context="": captured_desired.append(desired) or {},
    )
    monkeypatch.setattr("app.updates.entry_attr_value", lambda entry, attr: "CN=User,DC=x")
    monkeypatch.setattr("app.updates.safe_unbind", lambda conn, context: None)

    run_scheduled_update_existing_users(None)

    assert captured_desired == [{"userAccountControl": 514}]


def test_scheduled_update_default_manager_scope_still_disables_terminated_users(monkeypatch, tmp_path):
    conn = _DummyConn(
        [_DummyEntry({"distinguishedName": "CN=User,DC=x", "department": "Finance", "manager": ""})]
    )
    ldap_settings = LdapSettings(
        server="ldap.example.com",
        user="EXAMPLE\\svc",
        password="pw",
        search_base="DC=example,DC=com",
        create_base=None,
        ca_bundle_path=str(tmp_path / "ca.pem"),
    )
    (tmp_path / "ca.pem").write_text("dummy", encoding="utf-8")
    captured_desired = []

    monkeypatch.setattr(
        "app.updates.get_update_job_settings",
        lambda: UpdateJobSettings(
            dry_run=False,
            lookback_days=0,
            include_missing_last_updated=True,
            log_no_changes=False,
        ),
    )
    monkeypatch.setattr("app.updates.get_adp_token", lambda: "token")
    monkeypatch.setattr(
        "app.updates.get_adp_employees",
        lambda token: [
            {
                "workerID": {"idValue": "EMP1"},
                "workAssignments": [{"assignedWorkLocations": [{"address": {"countryCode": "US"}}]}],
                "workerDates": {"hireDate": "2026-03-01", "terminationDate": "2026-03-05T00:00:00Z"},
            }
        ],
    )
    monkeypatch.setattr("app.updates.validate_ldap_settings", lambda require_create_base=False: [])
    monkeypatch.setattr("app.updates.get_ldap_settings", lambda require_create_base=False: ldap_settings)
    monkeypatch.setattr("app.updates.create_ldap_server", lambda *args, **kwargs: object())
    monkeypatch.setattr("app.updates.make_conn_factory", lambda *args, **kwargs: lambda: conn)
    monkeypatch.setattr("app.updates.is_terminated_employee", lambda emp: True)
    monkeypatch.setattr(
        "app.updates.diff_update_attributes",
        lambda entry, desired, context="": captured_desired.append(desired) or {},
    )
    monkeypatch.setattr("app.updates.entry_attr_value", lambda entry, attr: "CN=User,DC=x")
    monkeypatch.setattr("app.updates.safe_unbind", lambda conn, context: None)

    run_scheduled_update_existing_users(None)

    assert captured_desired == [{"userAccountControl": 514}]


def test_scheduled_update_can_skip_termination_disable_when_override_disabled(monkeypatch, tmp_path):
    conn = _DummyConn(
        [_DummyEntry({"distinguishedName": "CN=User,DC=x", "department": "Finance", "manager": ""})]
    )
    ldap_settings = LdapSettings(
        server="ldap.example.com",
        user="EXAMPLE\\svc",
        password="pw",
        search_base="DC=example,DC=com",
        create_base=None,
        ca_bundle_path=str(tmp_path / "ca.pem"),
    )
    (tmp_path / "ca.pem").write_text("dummy", encoding="utf-8")
    captured_desired = []

    monkeypatch.setattr(
        "app.updates.get_update_job_settings",
        lambda: UpdateJobSettings(
            dry_run=True,
            lookback_days=0,
            include_missing_last_updated=True,
            log_no_changes=False,
            enabled_fields=("title",),
            always_disable_terminated=False,
        ),
    )
    monkeypatch.setattr("app.updates.get_adp_token", lambda: "token")
    monkeypatch.setattr(
        "app.updates.get_adp_employees",
        lambda token: [
            {
                "workerID": {"idValue": "EMP1"},
                "workAssignments": [{"assignedWorkLocations": [{"address": {"countryCode": "US"}}]}],
                "workerDates": {"hireDate": "2026-03-01", "terminationDate": "2026-03-05T00:00:00Z"},
            }
        ],
    )
    monkeypatch.setattr("app.updates.validate_ldap_settings", lambda require_create_base=False: [])
    monkeypatch.setattr("app.updates.get_ldap_settings", lambda require_create_base=False: ldap_settings)
    monkeypatch.setattr("app.updates.create_ldap_server", lambda *args, **kwargs: object())
    monkeypatch.setattr("app.updates.make_conn_factory", lambda *args, **kwargs: lambda: conn)
    monkeypatch.setattr("app.updates.is_terminated_employee", lambda emp: True)
    monkeypatch.setattr(
        "app.updates.diff_update_attributes",
        lambda entry, desired, context="": captured_desired.append(desired) or {},
    )
    monkeypatch.setattr("app.updates.entry_attr_value", lambda entry, attr: "CN=User,DC=x")
    monkeypatch.setattr("app.updates.safe_unbind", lambda conn, context: None)

    run_scheduled_update_existing_users(None)

    assert captured_desired == [{}]


def test_apply_ldap_modifications_blocks_dn_outside_allowed_write_bases():
    conn = _DummyConn([])

    updated_conn = apply_ldap_modifications(
        conn,
        "CN=User,OU=Outside,DC=example,DC=com",
        {"title": [("MODIFY_REPLACE", ["New Title"])]},
        allowed_write_bases=("OU=Inside,DC=example,DC=com",),
    )

    assert updated_conn is conn
    assert conn.modify_calls == []

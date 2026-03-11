from app.constants import ATTR_MAIL, ATTR_USER_PRINCIPAL_NAME
from app.ldap_client import diff_update_attributes
from app.models import LdapSettings, UpdateJobSettings
from app.updates import run_scheduled_update_existing_users


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

    def search(self, *args, **kwargs):
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
                "workAssignments": [{}],
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
                "workAssignments": [{}],
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

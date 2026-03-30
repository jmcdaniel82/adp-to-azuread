from types import SimpleNamespace

import pytest

import app.provisioning as provisioning
from app.constants import ATTR_MAIL, ATTR_SAM_ACCOUNT_NAME, ATTR_USER_PRINCIPAL_NAME
from app.provisioning import provision_user_in_ad


class DummyConn:
    def __init__(self):
        self.entries = []
        self.result = {}
        self.add_calls = 0
        self.add_called = None
        self.add_attributes = None
        self.modify_calls = []
        microsoft = SimpleNamespace(modify_password=self.modify_password)
        self.extend = SimpleNamespace(microsoft=microsoft)

    def search(self, *args, **kwargs):
        # Simulate no match for existing employee, DN visibility, or identifier conflicts.
        self.entries = []
        return False

    def add(self, dn, attributes=None):
        self.add_calls += 1
        self.add_called = dn
        self.add_attributes = attributes
        self.result = {"result": 0}
        return True

    def modify_password(self, dn, pwd):
        return True

    def modify(self, dn, changes):
        self.modify_calls.append((dn, changes))
        return True


class DummyConnResult68(DummyConn):
    def add(self, dn, attributes=None):
        self.add_calls += 1
        self.add_called = dn
        self.add_attributes = attributes
        self.result = {"result": 68, "description": "entryAlreadyExists"}
        return False


class DummyConnRetryOnce(DummyConn):
    def __init__(self):
        super().__init__()
        self.add_attempts = []

    def add(self, dn, attributes=None):
        self.add_calls += 1
        self.add_called = dn
        self.add_attributes = attributes
        self.add_attempts.append((dn, dict(attributes or {})))
        if self.add_calls == 1:
            self.result = {"result": 68, "description": "entryAlreadyExists"}
            return False
        self.result = {"result": 0}
        return True


class DummyConnPasswordFail(DummyConn):
    def modify_password(self, dn, pwd):
        raise RuntimeError("password failed")


def _make_emp(employee_id="EMP12345", first="Jane", last="Doe"):
    return {
        "person": {
            "preferredName": {"givenName": first, "familyName1": last},
            "legalName": {"givenName": first, "familyName1": last},
        },
        "workAssignments": [
            {
                "assignedWorkLocations": [{"address": {"countryCode": "US"}}],
                "assignedOrganizationalUnits": [],
                "occupationalClassifications": [],
            }
        ],
        "workerDates": {"hireDate": "2026-03-01"},
        "workerID": {"idValue": employee_id},
    }


def test_provision_cn_uses_display_name_without_employee_id():
    conn = DummyConn()
    emp = _make_emp(employee_id="6RJ7AAWFA", first="Tommy", last="Smith")
    provision_user_in_ad(
        emp,
        conn,
        "DC=example,DC=com",
        "OU=Users,DC=example,DC=com",
        max_retry_attempts=5,
        cn_collision_threshold=2,
    )
    assert conn.add_called.startswith("CN=Tommy Smith,")


def test_visible_cn_conflict_retries_with_numeric_suffix(monkeypatch):
    conn = DummyConnRetryOnce()
    emp = _make_emp(employee_id="EMPCLASHCN", first="Jane", last="Doe")
    monkeypatch.setattr(provisioning, "dn_exists_in_create_scope", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        provisioning,
        "collect_identifier_conflicts",
        lambda *args, **kwargs: {"sam": [], "upn": [], "mail": []},
    )

    provision_user_in_ad(
        emp,
        conn,
        "DC=example,DC=com",
        "OU=Users,DC=example,DC=com",
        max_retry_attempts=5,
        cn_collision_threshold=2,
    )

    assert conn.add_calls == 2
    assert conn.add_attempts[0][0].startswith("CN=Jane Doe,")
    assert conn.add_attempts[1][0].startswith("CN=Jane Doe 1,")


def test_result68_without_visible_conflicts_fails_fast_and_counts_failure():
    conn = DummyConnResult68()
    emp = _make_emp(employee_id="EMPNOCLASH", first="No", last="Collision")
    summary = {"add_failures": 0}
    provision_user_in_ad(
        emp,
        conn,
        "DC=example,DC=com",
        "OU=Users,DC=example,DC=com",
        summary_stats=summary,
        max_retry_attempts=50,
        cn_collision_threshold=5,
    )
    assert conn.add_calls == 1
    assert summary["add_failures"] == 1


def test_first_sam_conflict_retry_uses_suffix_1(monkeypatch):
    conn = DummyConnRetryOnce()
    emp = _make_emp(employee_id="EMPCLASH1", first="Jane", last="Doe")
    monkeypatch.setattr(provisioning, "dn_exists_in_create_scope", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        provisioning,
        "collect_identifier_conflicts",
        lambda *args, **kwargs: {"sam": ["existing sam"], "upn": [], "mail": []},
    )

    provision_user_in_ad(
        emp,
        conn,
        "DC=example,DC=com",
        "OU=Users,DC=example,DC=com",
        max_retry_attempts=5,
        cn_collision_threshold=2,
    )

    assert conn.add_calls == 2
    assert conn.add_attempts[0][1][ATTR_SAM_ACCOUNT_NAME] == "jdoe"
    assert conn.add_attempts[1][1][ATTR_SAM_ACCOUNT_NAME] == "jdoe1"


def test_first_alias_conflict_retry_uses_suffix_1(monkeypatch):
    conn = DummyConnRetryOnce()
    emp = _make_emp(employee_id="EMPCLASH2", first="Jane", last="Doe")
    monkeypatch.setattr(provisioning, "dn_exists_in_create_scope", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        provisioning,
        "collect_identifier_conflicts",
        lambda *args, **kwargs: {"sam": [], "upn": ["existing upn"], "mail": []},
    )
    monkeypatch.setenv("UPN_SUFFIX", "example.com")

    provision_user_in_ad(
        emp,
        conn,
        "DC=example,DC=com",
        "OU=Users,DC=example,DC=com",
        max_retry_attempts=5,
        cn_collision_threshold=2,
    )

    assert conn.add_calls == 2
    assert conn.add_attempts[0][1][ATTR_USER_PRINCIPAL_NAME] == "janedoe@example.com"
    assert conn.add_attempts[0][1][ATTR_MAIL] == "janedoe@cfsbrands.com"
    assert conn.add_attempts[1][1][ATTR_USER_PRINCIPAL_NAME] == "janedoe1@example.com"
    assert conn.add_attempts[1][1][ATTR_MAIL] == "janedoe1@cfsbrands.com"


def test_scheduled_provision_raises_when_token_missing(monkeypatch):
    monkeypatch.setattr(
        provisioning,
        "get_provision_job_settings",
        lambda: SimpleNamespace(hire_lookback_days=4, max_add_retries=15, cn_collision_threshold=5),
    )
    monkeypatch.setattr(provisioning, "get_adp_token", lambda: None)

    with pytest.raises(RuntimeError, match="ADP token"):
        provisioning.run_scheduled_provision_new_hires(None)


def test_password_failure_marks_incomplete_account_summary():
    conn = DummyConnPasswordFail()
    emp = _make_emp(employee_id="EMPINCOMPLETE", first="Partial", last="Create")
    summary = {"password_failures": 0, "incomplete_accounts": 0}

    result_conn = provision_user_in_ad(
        emp,
        conn,
        "DC=example,DC=com",
        "OU=Users,DC=example,DC=com",
        summary_stats=summary,
        max_retry_attempts=3,
        cn_collision_threshold=2,
    )

    assert result_conn is conn
    assert summary["password_failures"] == 1
    assert summary["incomplete_accounts"] == 1


def test_provisioning_blocks_add_outside_allowed_write_bases():
    conn = DummyConn()
    emp = _make_emp(employee_id="EMPSCOPE", first="Scope", last="Blocked")
    summary = {"add_failures": 0}

    result_conn = provision_user_in_ad(
        emp,
        conn,
        "DC=example,DC=com",
        "OU=Users,DC=example,DC=com",
        summary_stats=summary,
        allowed_write_bases=("OU=Different,DC=example,DC=com",),
    )

    assert result_conn is conn
    assert conn.add_calls == 0
    assert summary["add_failures"] == 1

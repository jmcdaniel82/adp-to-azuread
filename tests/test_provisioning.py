from types import SimpleNamespace

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


def test_provision_cn_is_deterministic_with_employee_id():
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
    assert conn.add_called.startswith("CN=Tommy Smith 6RJ7AAWFA,")


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

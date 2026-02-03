import types, sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

sys.modules.setdefault("requests", types.ModuleType("requests"))

azure_mod = types.ModuleType("azure")
func_mod = types.ModuleType("azure.functions")

class DummyApp:
    def function_name(self, *a, **k):
        def dec(f):
            return f
        return dec

    def route(self, *a, **k):
        def dec(f):
            return f
        return dec

    def schedule(self, *a, **k):
        def dec(f):
            return f
        return dec

class DummyHttpRequest:
    pass


class DummyHttpResponse:
    def __init__(self, *a, **k):
        pass

class DummyTimerRequest:
    pass

func_mod.FunctionApp = DummyApp
func_mod.HttpRequest = DummyHttpRequest
func_mod.HttpResponse = DummyHttpResponse
func_mod.TimerRequest = DummyTimerRequest

sys.modules["azure"] = azure_mod
sys.modules["azure.functions"] = func_mod

import re
from function_app import (
    get_hire_date,
    generate_password,
    provision_user_in_ad,
    extract_work_address_field,
    extract_state_from_work,
    get_adp_ca_bundle,
    extract_department,
)


def test_get_hire_date_from_work_assignment():
    emp = {
        "workAssignments": [{"hireDate": "2023-01-01"}]
    }
    hd = get_hire_date(emp)
    assert hd == "2023-01-01T00:00:00+00:00"


def test_get_hire_date_from_worker_dates_dict():
    emp = {
        "workerDates": {
            "originalHireDate": "2022-05-01T00:00:00Z",
            "hireDate": "2023-02-01T00:00:00+00:00",
        }
    }
    hd = get_hire_date(emp)
    assert hd == "2023-02-01T00:00:00+00:00"


def test_generate_password_complexity():
    pwd = generate_password(16)
    assert len(pwd) == 16
    assert re.search(r"[a-z]", pwd)
    assert re.search(r"[A-Z]", pwd)
    assert re.search(r"\d", pwd)
    assert re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]", pwd)


class DummyConn:
    def __init__(self):
        self.entries = []
        self.add_called = None
        self.add_attributes = None
        self.modify_calls = []
        microsoft = types.SimpleNamespace(modify_password=self.modify_password)
        self.extend = types.SimpleNamespace(microsoft=microsoft)

    def search(self, *a, **k):
        self.entries = []

    def add(self, dn, attributes=None):
        self.add_called = dn
        self.add_attributes = attributes
        return True

    def modify_password(self, dn, pwd):
        pass

    def modify(self, dn, changes):
        self.modify_calls.append((dn, changes))
        return True


def _make_emp(first, last):
    return {
        "person": {"preferredName": {"givenName": first, "familyName1": last}},
        "workAssignments": [
            {"assignedWorkLocations": [{"address": {"countryCode": "US"}}]}
        ],
        "workerID": {"idValue": "123"},
    }


def test_provision_user_dn_escapes_comma():
    conn = DummyConn()
    emp = _make_emp("Bob", "Smith, Jr")
    provision_user_in_ad(emp, conn, "dc=example,dc=com", "ou=Users,dc=example,dc=com")
    assert conn.add_called == "CN=Bob Smith\\, Jr,ou=Users,dc=example,dc=com"


def test_provision_user_dn_escapes_equal():
    conn = DummyConn()
    emp = _make_emp("Foo", "Bar=Qux")
    provision_user_in_ad(emp, conn, "dc=example,dc=com", "ou=Users,dc=example,dc=com")
    assert conn.add_called == "CN=Foo Bar\\=Qux,ou=Users,dc=example,dc=com"


def test_provision_user_samaccountname_max_10_chars():
    conn = DummyConn()
    emp = _make_emp("A", "VeryLongLastName")
    provision_user_in_ad(emp, conn, "dc=example,dc=com", "ou=Users,dc=example,dc=com")
    assert len(conn.add_attributes["sAMAccountName"]) <= 10


class DummyConnCollision(DummyConn):
    def __init__(self):
        super().__init__()
        self.add_calls = 0
        self.result = {}

    def add(self, dn, attributes=None):
        self.add_calls += 1
        self.add_called = dn
        self.add_attributes = attributes
        if self.add_calls == 1:
            self.result = {"result": 68, "description": "entryAlreadyExists"}
            return False
        self.result = {"result": 0}
        return True


def test_provision_user_cn_collision_adds_suffix():
    conn = DummyConnCollision()
    emp = _make_emp("Bob", "Smith")
    provision_user_in_ad(emp, conn, "dc=example,dc=com", "ou=Users,dc=example,dc=com")
    assert conn.add_calls == 2
    assert conn.add_called == "CN=Bob Smith 2,ou=Users,dc=example,dc=com"
    assert conn.add_attributes["sAMAccountName"].endswith("2")


def test_extract_work_address_field_falls_back_to_home():
    emp = {
        "workAssignments": [
            {
                "assignedWorkLocations": [{"address": {"nameCode": {"shortName": "HQ"}}}],
                "homeWorkLocation": {"address": {"countryCode": "US"}},
            }
        ]
    }
    assert extract_work_address_field(emp, "countryCode") == "US"


def test_extract_state_from_work_falls_back_to_home():
    emp = {
        "workAssignments": [
            {
                "assignedWorkLocations": [{"address": {"nameCode": {"shortName": "HQ"}}}],
                "homeWorkLocation": {
                    "address": {"countrySubdivisionLevel1": {"codeValue": "NC"}}
                },
            }
        ]
    }
    assert extract_state_from_work(emp) == "NC"


def test_extract_department_prefers_occupational_classification():
    emp = {
        "workAssignments": [
            {
                "occupationalClassifications": [
                    {"classificationCode": {"shortName": "Information Tech"}}
                ],
                "assignedOrganizationalUnits": [
                    {
                        "typeCode": {"codeValue": "Department"},
                        "nameCode": {"shortName": "Old Dept"},
                    }
                ],
            }
        ]
    }
    assert extract_department(emp) == "Information Tech"


def test_get_adp_ca_bundle_prefers_certifi(tmp_path, monkeypatch):
    fake_path = tmp_path / "adp-ca.pem"
    fake_path.write_text("dummy", encoding="utf-8")
    monkeypatch.setenv("ADP_CA_BUNDLE_PATH", str(fake_path))
    assert get_adp_ca_bundle() == str(fake_path)


class DummyConnConstraint(DummyConn):
    def __init__(self):
        super().__init__()
        self.add_calls = 0
        self.result = {}

    def add(self, dn, attributes=None):
        self.add_calls += 1
        self.add_called = dn
        self.add_attributes = attributes
        self.result = {"result": 19, "description": "constraintViolation", "message": "Attr otherAttribute"}
        return False


def test_provision_user_constraint_violation_no_retry():
    conn = DummyConnConstraint()
    emp = _make_emp("Jane", "Doe")
    provision_user_in_ad(emp, conn, "dc=example,dc=com", "ou=Users,dc=example,dc=com")
    assert conn.add_calls == 1


class DummyConnUPNConstraint(DummyConn):
    def __init__(self):
        super().__init__()
        self.add_calls = 0
        self.result = {}

    def add(self, dn, attributes=None):
        self.add_calls += 1
        self.add_called = dn
        self.add_attributes = attributes
        if self.add_calls == 1:
            self.result = {
                "result": 19,
                "description": "constraintViolation",
                "message": "problem 1005 (CONSTRAINT_ATT_TYPE), Att 90290 (userPrincipalName)",
            }
            return False
        self.result = {"result": 0}
        return True


def test_provision_user_upn_constraint_retries_with_suffix():
    conn = DummyConnUPNConstraint()
    emp = _make_emp("Janet", "Jones")
    provision_user_in_ad(emp, conn, "dc=example,dc=com", "ou=Users,dc=example,dc=com")
    assert conn.add_calls == 2
    assert conn.add_called == "CN=Janet Jones 2,ou=Users,dc=example,dc=com"
    assert conn.add_attributes["sAMAccountName"].endswith("2")


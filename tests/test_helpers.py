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
from function_app import get_hire_date, generate_password, provision_user_in_ad


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


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

ldap_mod = types.ModuleType("ldap3")
ldap_mod.Server = object
ldap_mod.Connection = object
ldap_mod.ALL = object()
ldap_mod.SUBTREE = object()
ldap_mod.Tls = object
ldap_mod.NTLM = object()
sys.modules["ldap3"] = ldap_mod
import re
from function_app import get_hire_date, generate_password
from datetime import timezone


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


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
    resolve_local_ac_department,
    normalize_department_name,
    get_legal_first_last,
    get_preferred_first_last,
    get_display_name,
    _diff_update_attributes,
    _build_update_attributes,
    ATTR_DISPLAY_NAME,
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


def test_name_helpers_preferred_and_legal_mapping():
    person = {
        "preferredName": {"givenName": "Matt", "familyName1": "Norm"},
        "legalName": {"givenName": "Mathew", "familyName1": "Normand"},
    }
    assert get_preferred_first_last(person) == ("Matt", "Norm")
    assert get_legal_first_last(person) == ("Mathew", "Normand")
    assert get_display_name(person) == "Matt Norm"


def test_display_name_falls_back_to_legal_when_preferred_incomplete():
    person = {
        "preferredName": {"givenName": "Matt", "familyName1": ""},
        "legalName": {"givenName": "Mathew", "familyName1": "Normand"},
    }
    assert get_display_name(person) == "Mathew Normand"


def test_build_update_attributes_omits_displayname_when_preferred_incomplete():
    emp = {
        "person": {
            "preferredName": {"givenName": "Matt", "familyName1": ""},
            "legalName": {"givenName": "Mathew", "familyName1": "Normand"},
        },
        "workAssignments": [{}],
        "workerDates": {"hireDate": "2023-01-01"},
    }
    desired = _build_update_attributes(emp, conn=None, ldap_search_base="dc=example,dc=com")
    assert ATTR_DISPLAY_NAME not in desired


def test_build_update_attributes_sets_displayname_when_preferred_complete():
    person = {
        "preferredName": {"givenName": "Matt", "familyName1": "Norm"},
        "legalName": {"givenName": "Mathew", "familyName1": "Normand"},
    }
    emp = {
        "person": person,
        "workAssignments": [{}],
        "workerDates": {"hireDate": "2023-01-01"},
    }
    desired = _build_update_attributes(emp, conn=None, ldap_search_base="dc=example,dc=com")
    assert desired[ATTR_DISPLAY_NAME] == get_display_name(person)


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


def _make_emp(first, last, legal_first=None, legal_last=None):
    legal_first = legal_first if legal_first is not None else first
    legal_last = legal_last if legal_last is not None else last
    return {
        "person": {
            "preferredName": {"givenName": first, "familyName1": last},
            "legalName": {"givenName": legal_first, "familyName1": legal_last},
        },
        "workAssignments": [
            {"assignedWorkLocations": [{"address": {"countryCode": "US"}}]}
        ],
        "workerID": {"idValue": "123"},
    }


def _make_department_emp(
    assigned_dept=None,
    assigned_dept_code=None,
    assigned_dept_long_name=None,
    occ_values=None,
    job_title="",
    business_title="",
):
    assigned_units = []
    if assigned_dept or assigned_dept_code or assigned_dept_long_name:
        name_code = {}
        if assigned_dept:
            name_code["shortName"] = assigned_dept
        if assigned_dept_code:
            name_code["codeValue"] = assigned_dept_code
        if assigned_dept_long_name:
            name_code["longName"] = assigned_dept_long_name
        assigned_units.append(
            {
                "typeCode": {"codeValue": "Department"},
                "nameCode": name_code,
            }
        )
    occ = []
    for value in occ_values or []:
        occ.append({"classificationCode": {"shortName": value}})
    additional_remunerations = []
    if business_title:
        additional_remunerations.append(
            {
                "itemID": "1",
                "nameCode": {"codeValue": "Business Title"},
                "stringValue": business_title,
            }
        )
    return {
        "person": {
            "preferredName": {"givenName": "Test", "familyName1": "User"},
            "legalName": {"givenName": "Test", "familyName1": "User"},
        },
        "workAssignments": [
            {
                "jobTitle": job_title,
                "assignedOrganizationalUnits": assigned_units,
                "occupationalClassifications": occ,
            }
        ],
        "workerID": {"idValue": "999"},
        "workerDates": {"hireDate": "2023-01-01"},
        "additionalRemunerations": additional_remunerations,
    }


class _DummyEntryAttr:
    def __init__(self, value):
        self.value = value


class _DummyEntry:
    def __init__(self, attrs):
        self._attrs = attrs
        for key, value in attrs.items():
            setattr(self, key, _DummyEntryAttr(value))

    def __getitem__(self, key):
        return _DummyEntryAttr(self._attrs[key])


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


def test_provision_user_uses_legal_for_given_and_sn_but_preferred_for_displayname():
    conn = DummyConn()
    emp = _make_emp("Matt", "Norm", legal_first="Mathew", legal_last="Normand")
    provision_user_in_ad(emp, conn, "dc=example,dc=com", "ou=Users,dc=example,dc=com")
    assert conn.add_attributes["givenName"] == "Mathew"
    assert conn.add_attributes["sn"] == "Normand"
    assert conn.add_attributes["displayName"] == "Matt Norm"
    assert conn.add_called == "CN=Matt Norm,ou=Users,dc=example,dc=com"


def test_provision_user_skips_when_legal_names_missing():
    conn = DummyConn()
    emp = _make_emp("Matt", "Norm", legal_first="", legal_last="")
    provision_user_in_ad(emp, conn, "dc=example,dc=com", "ou=Users,dc=example,dc=com")
    assert conn.add_called is None


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
    assert conn.add_attributes["sAMAccountName"] == "bsmith"


def test_provision_user_uses_resolved_department_mapping():
    conn = DummyConn()
    emp = _make_department_emp(
        assigned_dept="491650",
        assigned_dept_code="491650",
        assigned_dept_long_name="Distribution - Charlotte DL",
    )
    emp["workAssignments"][0]["assignedWorkLocations"] = [{"address": {"countryCode": "US"}}]
    provision_user_in_ad(emp, conn, "dc=example,dc=com", "ou=Users,dc=example,dc=com")
    assert conn.add_attributes["department"] == "Supply Chain"


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
    assert conn.add_called == "CN=Janet Jones,ou=Users,dc=example,dc=com"
    assert conn.add_attributes["sAMAccountName"] == "jjones"
    assert conn.add_attributes["userPrincipalName"].startswith("janetjones2@")


class DummyConnSAMConstraint(DummyConn):
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
                "message": "problem 1005 (CONSTRAINT_ATT_TYPE), Att 90303 (sAMAccountName)",
            }
            return False
        self.result = {"result": 0}
        return True


def test_provision_user_sam_constraint_retries_only_sam_suffix():
    conn = DummyConnSAMConstraint()
    emp = _make_emp("Jane", "Doe")
    provision_user_in_ad(emp, conn, "dc=example,dc=com", "ou=Users,dc=example,dc=com")
    assert conn.add_calls == 2
    assert conn.add_called == "CN=Jane Doe,ou=Users,dc=example,dc=com"
    assert conn.add_attributes["sAMAccountName"] == "jdoe2"
    assert conn.add_attributes["userPrincipalName"].startswith("janedoe@")


def test_diff_update_attributes_blocks_email_identifier_updates():
    entry = _DummyEntry({"mail": "old@example.com", "title": "Old Title"})
    desired = {
        "mail": "new@example.com",
        "userPrincipalName": "new@example.com",
        "title": "New Title",
    }
    changes = _diff_update_attributes(entry, desired, context="E123")
    assert "mail" not in changes
    assert "userPrincipalName" not in changes
    assert "title" in changes


def test_customer_service_assigned_dept_maps_to_sales():
    emp = _make_department_emp(assigned_dept="Customer Service - Salary")
    result = resolve_local_ac_department(emp)
    assert result["proposedDepartmentV2"] == "Sales"
    assert result["departmentChangeReferenceField"] == "costCenterDescription"


def test_professionals_does_not_force_administration_when_current_and_manager_finance():
    emp = _make_department_emp(occ_values=["Professionals"])
    result = resolve_local_ac_department(
        emp,
        current_ad_department="Finance",
        manager_department="Finance",
    )
    assert normalize_department_name(result["proposedDepartmentV2"]) == "Finance"
    assert normalize_department_name(result["proposedDepartmentV2"]) != "Administration"


def test_administrative_support_workers_does_not_force_administration():
    emp = _make_department_emp(occ_values=["Administrative Support Workers"])
    result = resolve_local_ac_department(
        emp,
        current_ad_department="Supply Chain",
        manager_department="Supply Chain",
    )
    assert normalize_department_name(result["proposedDepartmentV2"]) == "Supply Chain"
    assert normalize_department_name(result["proposedDepartmentV2"]) != "Administration"


def test_manager_alignment_blocks_low_confidence_overrides():
    emp = _make_department_emp(occ_values=["Professionals"])
    result = resolve_local_ac_department(
        emp,
        current_ad_department="Sales",
        manager_department="Sales",
    )
    assert normalize_department_name(result["proposedDepartmentV2"]) == "Sales"
    assert result["changeAllowed"] is False
    assert result["blockReason"] == "blocked_by_manager_alignment"


def test_administration_requires_gating_from_title_or_manager_or_assigned_dept():
    admin_title_emp = _make_department_emp(job_title="Administrative Assistant")
    admin_title_result = resolve_local_ac_department(admin_title_emp)
    assert normalize_department_name(admin_title_result["proposedDepartmentV2"]) == "Administration"

    ambiguous_emp = _make_department_emp(occ_values=["Professionals"])
    ambiguous_result = resolve_local_ac_department(ambiguous_emp)
    assert normalize_department_name(ambiguous_result["proposedDepartmentV2"]) != "Administration"


def test_cost_center_description_can_drive_department_mapping():
    emp = _make_department_emp(
        assigned_dept="491650",
        assigned_dept_code="491650",
        assigned_dept_long_name="Distribution - Charlotte DL",
    )
    result = resolve_local_ac_department(emp)
    assert normalize_department_name(result["proposedDepartmentV2"]) == "Supply Chain"
    assert result["departmentChangeReferenceField"] == "costCenterDescription"


def test_cost_center_description_customer_service_maps_to_sales():
    emp = _make_department_emp(
        assigned_dept="720670",
        assigned_dept_code="720670",
        assigned_dept_long_name="Customer Service - Salary",
    )
    result = resolve_local_ac_department(emp)
    assert normalize_department_name(result["proposedDepartmentV2"]) == "Sales"
    assert result["departmentChangeReferenceField"] == "costCenterDescription"


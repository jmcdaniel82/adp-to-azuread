from app.department_resolution import normalize_department_name, resolve_local_ac_department


def _make_department_emp(
    *,
    assigned_dept=None,
    assigned_dept_code=None,
    assigned_dept_long_name=None,
    occ_values=None,
    job_title="",
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
    occ = [{"classificationCode": {"shortName": value}} for value in (occ_values or [])]
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
        "workerID": {"idValue": "EMP001"},
    }


def test_explicit_canonical_mapping_is_preserved():
    emp = _make_department_emp(assigned_dept="Finance")
    result = resolve_local_ac_department(emp)
    assert normalize_department_name(result["proposedDepartmentV2"]) == "Finance"


def test_customer_service_maps_to_sales():
    emp = _make_department_emp(
        assigned_dept="720670",
        assigned_dept_code="720670",
        assigned_dept_long_name="Customer Service - Salary",
    )
    result = resolve_local_ac_department(emp)
    assert normalize_department_name(result["proposedDepartmentV2"]) == "Sales"
    assert result["departmentChangeReferenceField"] == "costCenterDescription"


def test_ambiguous_values_do_not_force_administration():
    emp = _make_department_emp(occ_values=["Professionals"])
    result = resolve_local_ac_department(
        emp,
        current_ad_department="Finance",
        manager_department="Finance",
    )
    assert normalize_department_name(result["proposedDepartmentV2"]) == "Finance"
    assert normalize_department_name(result["proposedDepartmentV2"]) != "Administration"


def test_administration_requires_gating():
    admin_title_emp = _make_department_emp(job_title="Administrative Assistant")
    admin_title_result = resolve_local_ac_department(admin_title_emp)
    assert normalize_department_name(admin_title_result["proposedDepartmentV2"]) == "Administration"

    ambiguous_emp = _make_department_emp(occ_values=["Professionals"])
    ambiguous_result = resolve_local_ac_department(ambiguous_emp)
    assert normalize_department_name(ambiguous_result["proposedDepartmentV2"] or "") != "Administration"


def test_manager_alignment_guardrail_blocks_low_confidence_override():
    emp = _make_department_emp(occ_values=["Professionals"])
    result = resolve_local_ac_department(
        emp,
        current_ad_department="Sales",
        manager_department="Sales",
    )
    assert normalize_department_name(result["proposedDepartmentV2"]) == "Sales"
    assert result["changeAllowed"] is False
    assert result["blockReason"] == "blocked_by_manager_alignment"


def test_fallback_chain_prefers_current_then_manager():
    emp = _make_department_emp()
    keep_current = resolve_local_ac_department(emp, current_ad_department="Operations", manager_department="")
    assert normalize_department_name(keep_current["proposedDepartmentV2"]) == "Operations"

    use_manager = resolve_local_ac_department(
        emp, current_ad_department="", manager_department="Human Resources"
    )
    assert normalize_department_name(use_manager["proposedDepartmentV2"]) == "Human Resources"

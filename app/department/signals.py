"""Signal collection for department resolution."""

from __future__ import annotations

from ..adp import extract_business_title


def collect_local_ac_department_signals(emp: dict) -> list[tuple[str, str]]:
    """Collect candidate department signals across ADP worker fields."""
    signals: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(source: str, value: str) -> None:
        raw_value = (value or "").strip()
        if not raw_value:
            return
        key = (source, raw_value)
        if key in seen:
            return
        seen.add(key)
        signals.append((source, raw_value))

    work_assignments = emp.get("workAssignments", [])
    if not work_assignments or not isinstance(work_assignments[0], dict):
        return signals

    assignment = work_assignments[0]

    def add_org_units(units, source: str, expected_type: str) -> None:
        if not isinstance(units, list):
            return
        for org_unit in units:
            if not isinstance(org_unit, dict):
                continue
            type_code = org_unit.get("typeCode", {}).get("codeValue", "").strip().lower()
            if type_code != expected_type:
                continue
            name_code = org_unit.get("nameCode", {})
            value = ""
            if isinstance(name_code, dict):
                value = (
                    name_code.get("shortName")
                    or name_code.get("longName")
                    or name_code.get("name")
                    or name_code.get("codeValue")
                    or ""
                )
            add(source, value)
            if expected_type == "department":
                cost_center_description = ""
                if isinstance(name_code, dict):
                    cost_center_description = (
                        name_code.get("longName")
                        or name_code.get("shortName")
                        or name_code.get("name")
                        or ""
                    )
                add("costCenterDescription", cost_center_description)

    add_org_units(assignment.get("assignedOrganizationalUnits", []), "assignedDept", "department")
    add_org_units(assignment.get("homeOrganizationalUnits", []), "homeDept", "department")
    add_org_units(assignment.get("assignedOrganizationalUnits", []), "businessUnit", "business unit")
    add_org_units(assignment.get("homeOrganizationalUnits", []), "businessUnit", "business unit")

    occupational_classifications = assignment.get("occupationalClassifications", [])
    if isinstance(occupational_classifications, list):
        for item in occupational_classifications:
            if not isinstance(item, dict):
                continue
            code = item.get("classificationCode", {})
            if not isinstance(code, dict):
                continue
            value = code.get("shortName") or code.get("longName") or code.get("name") or ""
            add("occupationalClassifications", value)

    add("jobTitle", assignment.get("jobTitle", ""))
    add("businessTitle", extract_business_title(emp) or "")

    business_unit = assignment.get("businessUnit", {})
    if isinstance(business_unit, dict):
        add("businessUnit", business_unit.get("name", ""))

    return signals

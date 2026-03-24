"""Work-assignment and location extraction helpers."""

from __future__ import annotations

import logging
from typing import Optional

from ..config import env_truthy
from ..constants import ADP_COUNTRY_NUMERIC_BY_ALPHA2
from .identity import extract_employee_id
from .names import get_display_name, get_legal_first_last


def normalize_dept(dept: str) -> str:
    """Normalize department strings for export matching."""
    if not dept:
        return ""
    return "".join(char for char in str(dept).lower().strip() if char.isalnum() or char.isspace())


def _first_assignment(emp: dict) -> dict:
    assignments = emp.get("workAssignments", [])
    if not assignments or not isinstance(assignments[0], dict):
        return {}
    return assignments[0]


def extract_assignment_field(emp: dict, field: str) -> str:
    """Return a field from the first work assignment."""
    assignment = _first_assignment(emp)
    if not assignment:
        return ""
    return assignment.get(field, "")


def extract_department(emp: dict) -> str:
    """Extract department signal from occupational classification then org units."""
    assignment = _first_assignment(emp)
    if not assignment:
        return ""

    candidates: list[tuple[str, str]] = []
    occupational_classifications = assignment.get("occupationalClassifications", [])
    if isinstance(occupational_classifications, list):
        for item in occupational_classifications:
            code = item.get("classificationCode", {}) if isinstance(item, dict) else {}
            value = code.get("shortName") or code.get("longName") or code.get("name")
            if value:
                candidates.append(("occupationalClassifications.classificationCode", value))
                break

    for unit in assignment.get("assignedOrganizationalUnits", []):
        if unit.get("typeCode", {}).get("codeValue", "").lower() == "department":
            value = unit.get("nameCode", {}).get("shortName", "")
            if value:
                candidates.append(("assignedOrganizationalUnits.department", value))
                break

    for unit in assignment.get("homeOrganizationalUnits", []):
        if unit.get("typeCode", {}).get("codeValue", "").lower() == "department":
            value = unit.get("nameCode", {}).get("shortName", "")
            if value:
                candidates.append(("homeOrganizationalUnits.department", value))
                break

    if not candidates:
        return ""

    source, value = candidates[0]
    if env_truthy("LOG_DEPARTMENT_SOURCE", False):
        employee_id = extract_employee_id(emp)
        person = emp.get("person", {})
        legal_first, legal_last = get_legal_first_last(person)
        display = get_display_name(person) or "<no display name>"
        legal = f"{legal_first} {legal_last}".strip() or "<no legal name>"
        logging.info(
            f"Department source for {employee_id} / display='{display}' legal='{legal}': {source} -> {value}"
        )
    return value


def extract_business_title(emp: dict) -> Optional[str]:
    """Extract Business Title from customFieldGroup.stringFields."""
    custom_group = emp.get("customFieldGroup", {})
    if not isinstance(custom_group, dict):
        return None
    string_fields = custom_group.get("stringFields", [])
    if not isinstance(string_fields, list):
        return None
    for field in string_fields:
        if not isinstance(field, dict):
            continue
        if field.get("nameCode", {}).get("codeValue") == "Business Title":
            return field.get("stringValue")
    return None


def extract_company(emp: dict) -> str:
    """Extract company or business-unit name from work assignment org units."""
    assignment = _first_assignment(emp)
    if not assignment:
        return ""

    business_unit = assignment.get("businessUnit", {})
    if isinstance(business_unit, dict) and business_unit.get("name"):
        return business_unit["name"]

    for unit in assignment.get("assignedOrganizationalUnits", []):
        if unit.get("typeCode", {}).get("codeValue", "").lower() == "business unit":
            return unit.get("nameCode", {}).get("shortName", "")

    for unit in assignment.get("homeOrganizationalUnits", []):
        if unit.get("typeCode", {}).get("codeValue", "").lower() == "business unit":
            return unit.get("nameCode", {}).get("shortName", "")

    return ""


def build_ad_country_attributes(country_code: str) -> dict:
    """Map ADP country code to AD country attributes."""
    alpha2 = (country_code or "").strip().upper()
    if not alpha2:
        return {"co": None, "c": None, "countryCode": None}
    co_value = "United States" if alpha2 == "US" else alpha2
    return {"co": co_value, "c": alpha2, "countryCode": ADP_COUNTRY_NUMERIC_BY_ALPHA2.get(alpha2)}


def extract_work_address_field(emp: dict, field: str) -> str:
    """Extract field from assigned work location, then fallback to home work location."""
    assignment = _first_assignment(emp)
    if not assignment:
        return ""

    assigned_locations = assignment.get("assignedWorkLocations")
    if isinstance(assigned_locations, list) and assigned_locations:
        first_location = assigned_locations[0] if isinstance(assigned_locations[0], dict) else {}
        address = first_location.get("address", {}) if isinstance(first_location, dict) else {}
        value = address.get(field, "") if isinstance(address, dict) else ""
        if value:
            return value

    home_location = assignment.get("homeWorkLocation")
    if isinstance(home_location, dict):
        address = home_location.get("address", {})
        if isinstance(address, dict):
            return address.get(field, "")
    return ""


def extract_state_from_work(emp: dict) -> str:
    """Extract state or province code from assigned location with home fallback."""
    assignment = _first_assignment(emp)
    if not assignment:
        return ""

    assigned_locations = assignment.get("assignedWorkLocations")
    if isinstance(assigned_locations, list) and assigned_locations:
        first_location = assigned_locations[0] if isinstance(assigned_locations[0], dict) else {}
        address = first_location.get("address", {}) if isinstance(first_location, dict) else {}
        subdivision = address.get("countrySubdivisionLevel1", {}) if isinstance(address, dict) else {}
        value = subdivision.get("codeValue", "") if isinstance(subdivision, dict) else ""
        if value:
            return value

    home_location = assignment.get("homeWorkLocation")
    if isinstance(home_location, dict):
        address = home_location.get("address", {})
        if isinstance(address, dict):
            subdivision = address.get("countrySubdivisionLevel1", {})
            if isinstance(subdivision, dict):
                return subdivision.get("codeValue", "")
    return ""


def extract_manager_id(emp: dict) -> Optional[str]:
    """Extract manager employeeID from reportsTo."""
    assignment = _first_assignment(emp)
    if not assignment:
        return None

    reports_to = assignment.get("reportsTo", [])
    if isinstance(reports_to, list) and reports_to:
        first = reports_to[0] if isinstance(reports_to[0], dict) else {}
        worker_id = first.get("workerID", {}) if isinstance(first, dict) else {}
        if isinstance(worker_id, dict):
            return worker_id.get("idValue")
    return None

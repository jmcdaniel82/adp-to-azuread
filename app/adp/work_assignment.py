"""Core work-assignment helpers shared by ADP extractors."""

from __future__ import annotations

from typing import Optional


def first_assignment(emp: dict) -> dict:
    """Return the first work assignment when available."""
    assignments = emp.get("workAssignments", [])
    if not assignments or not isinstance(assignments[0], dict):
        return {}
    return assignments[0]


def extract_assignment_field(emp: dict, field: str) -> str:
    """Return a field from the first work assignment."""
    assignment = first_assignment(emp)
    if not assignment:
        return ""
    return assignment.get(field, "")


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
    assignment = first_assignment(emp)
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


def extract_manager_id(emp: dict) -> Optional[str]:
    """Extract manager employeeID from reportsTo."""
    assignment = first_assignment(emp)
    if not assignment:
        return None

    reports_to = assignment.get("reportsTo", [])
    if isinstance(reports_to, list) and reports_to:
        first = reports_to[0] if isinstance(reports_to[0], dict) else {}
        worker_id = first.get("workerID", {}) if isinstance(first, dict) else {}
        if isinstance(worker_id, dict):
            return worker_id.get("idValue")
    return None


__all__ = [
    "extract_assignment_field",
    "extract_business_title",
    "extract_company",
    "extract_manager_id",
    "first_assignment",
]

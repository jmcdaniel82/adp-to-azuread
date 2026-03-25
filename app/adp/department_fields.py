"""Department-oriented ADP assignment extraction helpers."""

from __future__ import annotations

import logging

from ..config import env_truthy
from .identity import extract_employee_id
from .names import get_display_name, get_legal_first_last
from .work_assignment import first_assignment


def normalize_dept(dept: str) -> str:
    """Normalize department strings for export matching."""
    if not dept:
        return ""
    return "".join(char for char in str(dept).lower().strip() if char.isalnum() or char.isspace())


def extract_department(emp: dict) -> str:
    """Extract department signal from occupational classification then org units."""
    assignment = first_assignment(emp)
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


__all__ = ["extract_department", "normalize_dept"]

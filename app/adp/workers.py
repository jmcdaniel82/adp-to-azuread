"""ADP worker payload parsing and normalization helpers."""

from __future__ import annotations

import logging
import re
import secrets
import string
from datetime import datetime, timezone
from typing import Any, Optional

from ..config import env_truthy
from ..constants import ADP_COUNTRY_NUMERIC_BY_ALPHA2


def parse_datetime(value: str, context: str) -> Optional[datetime]:
    """Parse ISO-like datetime values, including trailing Z for UTC."""
    if not value:
        return None
    try:
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception as exc:
        logging.error(f"Error parsing {context} '{value}': {exc}")
        return None


def _parse_datetime_silent(value: str) -> Optional[datetime]:
    """Parse datetime without logging parse errors (for scoring/dedupe only)."""
    if not value:
        return None
    try:
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None


def format_start_date_for_log(hire_value: str) -> str:
    """Render start date as M/D/YYYY for readable logs."""
    parsed = _parse_datetime_silent(hire_value or "")
    if not parsed:
        return "<unknown>"
    return f"{parsed.month}/{parsed.day}/{parsed.year}"


def normalize_id(emp_id: str) -> str:
    """Trim and uppercase employeeID values."""
    return emp_id.strip().upper() if emp_id else ""


def normalize_dept(dept: str) -> str:
    """Normalize department strings for export matching."""
    if not dept:
        return ""
    return "".join(c for c in str(dept).lower().strip() if c.isalnum() or c.isspace())


def extract_last_updated(emp: dict) -> Optional[datetime]:
    """Best-effort ADP lastUpdated extraction from known metadata fields."""
    candidates = [
        emp.get("meta", {}).get("lastUpdatedDateTime"),
        emp.get("meta", {}).get("lastUpdatedTimestamp"),
        emp.get("meta", {}).get("lastUpdateDateTime"),
        emp.get("lastUpdatedDateTime"),
        emp.get("lastUpdatedTimestamp"),
        emp.get("lastUpdateDateTime"),
    ]
    assignments = emp.get("workAssignments")
    if isinstance(assignments, list) and assignments:
        candidates.append(assignments[0].get("lastUpdatedDateTime"))
        candidates.append(assignments[0].get("lastUpdatedTimestamp"))
    for value in candidates:
        if not value:
            continue
        parsed = parse_datetime(value, "lastUpdated")
        if parsed:
            return parsed
    return None


def get_hire_date(employee: dict) -> Optional[str]:
    """Return best hire/start date in canonical ISO form."""
    assignments = employee.get("workAssignments")
    if isinstance(assignments, list) and assignments:
        for key in ("hireDate", "actualStartDate"):
            value = assignments[0].get(key)
            if not value:
                continue
            parsed = parse_datetime(value, f"assignment {key}")
            if parsed:
                return parsed.isoformat()

    worker_dates = employee.get("workerDates")
    parsed_dates: list[datetime] = []
    if isinstance(worker_dates, list):
        for item in worker_dates:
            if "hire" not in item.get("type", "").lower():
                continue
            value = item.get("value")
            parsed = parse_datetime(value, "workerDates hire") if isinstance(value, str) else None
            if parsed:
                parsed_dates.append(parsed)
    elif isinstance(worker_dates, dict):
        for key in ("originalHireDate", "hireDate", "hire_date"):
            value = worker_dates.get(key)
            parsed = parse_datetime(value, f"workerDates {key}") if isinstance(value, str) else None
            if parsed:
                parsed_dates.append(parsed)
    return max(parsed_dates).isoformat() if parsed_dates else None


def get_termination_date(emp: dict) -> Optional[str]:
    """Return termination date when present in ADP payload."""
    worker_dates = emp.get("workerDates")
    if isinstance(worker_dates, list):
        for item in worker_dates:
            if "term" in item.get("type", "").lower():
                return item.get("value")
    elif isinstance(worker_dates, dict):
        return worker_dates.get("terminationDate")
    return None


def extract_employee_id(emp: dict) -> str:
    """Extract ADP employeeID from workerID payload shape."""
    worker_id = emp.get("workerID")
    if isinstance(worker_id, dict):
        return worker_id.get("idValue", "")
    return worker_id or ""


def _clean_name_part(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def get_legal_first_last(person: dict) -> tuple[str, str]:
    """Return legal first/last name pair."""
    if not isinstance(person, dict):
        return "", ""
    legal = person.get("legalName", {})
    if not isinstance(legal, dict):
        return "", ""
    return _clean_name_part(legal.get("givenName")), _clean_name_part(legal.get("familyName1"))


def get_preferred_first_last(person: dict) -> tuple[str, str]:
    """Return preferred first/last name pair."""
    if not isinstance(person, dict):
        return "", ""
    preferred = person.get("preferredName", {})
    if not isinstance(preferred, dict):
        return "", ""
    return _clean_name_part(preferred.get("givenName")), _clean_name_part(preferred.get("familyName1"))


def get_display_name(person: dict) -> str:
    """Return preferred full name when complete, otherwise legal full name."""
    preferred_first, preferred_last = get_preferred_first_last(person)
    if preferred_first and preferred_last:
        return f"{preferred_first} {preferred_last}".strip()
    legal_first, legal_last = get_legal_first_last(person)
    return f"{legal_first} {legal_last}".strip()


def get_first_last(person: dict) -> tuple[str, str]:
    """Backward compatible helper returning legal first/last."""
    return get_legal_first_last(person)


def sanitize_string_for_sam(value: str) -> str:
    """Remove non-alphanumeric characters for sAMAccountName construction."""
    return re.sub(r"[^a-zA-Z0-9]", "", value)


def extract_assignment_field(emp: dict, field: str) -> str:
    """Return a field from the first work assignment."""
    assignments = emp.get("workAssignments", [])
    if not assignments or not isinstance(assignments[0], dict):
        return ""
    return assignments[0].get(field, "")


def extract_department(emp: dict) -> str:
    """Extract department signal from occupational classification then org units."""
    assignments = emp.get("workAssignments", [])
    if not assignments or not isinstance(assignments[0], dict):
        return ""
    first_assignment = assignments[0]
    candidates: list[tuple[str, str]] = []
    occ = first_assignment.get("occupationalClassifications", [])
    if isinstance(occ, list):
        for item in occ:
            code = item.get("classificationCode", {}) if isinstance(item, dict) else {}
            value = code.get("shortName") or code.get("longName") or code.get("name")
            if value:
                candidates.append(("occupationalClassifications.classificationCode", value))
                break
    for unit in first_assignment.get("assignedOrganizationalUnits", []):
        if unit.get("typeCode", {}).get("codeValue", "").lower() == "department":
            value = unit.get("nameCode", {}).get("shortName", "")
            if value:
                candidates.append(("assignedOrganizationalUnits.department", value))
                break
    for unit in first_assignment.get("homeOrganizationalUnits", []):
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
    """Extract company/business-unit name from work assignment org units."""
    assignments = emp.get("workAssignments", [])
    if not assignments or not isinstance(assignments[0], dict):
        return ""
    first = assignments[0]
    business_unit = first.get("businessUnit", {})
    if isinstance(business_unit, dict) and business_unit.get("name"):
        return business_unit["name"]
    for unit in first.get("assignedOrganizationalUnits", []):
        if unit.get("typeCode", {}).get("codeValue", "").lower() == "business unit":
            return unit.get("nameCode", {}).get("shortName", "")
    for unit in first.get("homeOrganizationalUnits", []):
        if unit.get("typeCode", {}).get("codeValue", "").lower() == "business unit":
            return unit.get("nameCode", {}).get("shortName", "")
    return ""


def build_ad_country_attributes(country_code: str) -> dict:
    """
    Map ADP country code to AD country attributes.

    AD expects:
    - co: human-readable country string
    - c: alpha-2 country code
    - countryCode: numeric country code
    """
    alpha2 = (country_code or "").strip().upper()
    if not alpha2:
        return {"co": None, "c": None, "countryCode": None}
    co_value = "United States" if alpha2 == "US" else alpha2
    return {"co": co_value, "c": alpha2, "countryCode": ADP_COUNTRY_NUMERIC_BY_ALPHA2.get(alpha2)}


def extract_work_address_field(emp: dict, field: str) -> str:
    """Extract field from assigned work location, then fallback to home work location."""
    assignments = emp.get("workAssignments", [])
    if assignments and isinstance(assignments[0], dict):
        assigned_locations = assignments[0].get("assignedWorkLocations")
        if isinstance(assigned_locations, list) and assigned_locations:
            first_location = assigned_locations[0] if isinstance(assigned_locations[0], dict) else {}
            address = first_location.get("address", {}) if isinstance(first_location, dict) else {}
            value = address.get(field, "") if isinstance(address, dict) else ""
            if value:
                return value
        home_location = assignments[0].get("homeWorkLocation")
        if isinstance(home_location, dict):
            address = home_location.get("address", {})
            if isinstance(address, dict):
                return address.get(field, "")
    return ""


def extract_state_from_work(emp: dict) -> str:
    """Extract state/province code from assigned location with home fallback."""
    assignments = emp.get("workAssignments", [])
    if assignments and isinstance(assignments[0], dict):
        assigned_locations = assignments[0].get("assignedWorkLocations")
        if isinstance(assigned_locations, list) and assigned_locations:
            first_location = assigned_locations[0] if isinstance(assigned_locations[0], dict) else {}
            address = first_location.get("address", {}) if isinstance(first_location, dict) else {}
            subdivision = address.get("countrySubdivisionLevel1", {}) if isinstance(address, dict) else {}
            value = subdivision.get("codeValue", "") if isinstance(subdivision, dict) else ""
            if value:
                return value
        home_location = assignments[0].get("homeWorkLocation")
        if isinstance(home_location, dict):
            address = home_location.get("address", {})
            if isinstance(address, dict):
                subdivision = address.get("countrySubdivisionLevel1", {})
                if isinstance(subdivision, dict):
                    return subdivision.get("codeValue", "")
    return ""


def extract_manager_id(emp: dict) -> Optional[str]:
    """Extract manager employeeID from reportsTo."""
    assignments = emp.get("workAssignments", [])
    if assignments and isinstance(assignments[0], dict):
        reports_to = assignments[0].get("reportsTo", [])
        if isinstance(reports_to, list) and reports_to:
            first = reports_to[0] if isinstance(reports_to[0], dict) else {}
            worker_id = first.get("workerID", {}) if isinstance(first, dict) else {}
            if isinstance(worker_id, dict):
                return worker_id.get("idValue")
    return None


def get_status(emp: dict) -> str:
    """Return Active/Inactive derived from hire/termination timing."""
    hire_date = get_hire_date(emp)
    termination_date = get_termination_date(emp)
    if not hire_date:
        return "Inactive"
    parsed_hire = parse_datetime(hire_date, "hireDate")
    if not parsed_hire:
        return "Inactive"
    now = datetime.now(timezone.utc)
    if parsed_hire > now:
        return "Inactive"
    if not termination_date:
        return "Active"
    parsed_term = parse_datetime(termination_date, "terminationDate")
    if not parsed_term:
        logging.warning(f"Invalid termination date '{termination_date}' for employee; treating as Active")
        return "Active"
    return "Active" if parsed_term > now else "Inactive"


def is_terminated_employee(emp: dict) -> bool:
    """Return True when termination date is now/past."""
    termination_date = get_termination_date(emp)
    if not termination_date:
        return False
    parsed_term = parse_datetime(termination_date, "terminationDate")
    if not parsed_term:
        return False
    return parsed_term <= datetime.now(timezone.utc)


def get_user_account_control(emp: dict) -> int:
    """Map ADP status to AD userAccountControl."""
    return 512 if get_status(emp) == "Active" else 514


def generate_password(length: int = 24) -> str:
    """Generate random complex password suitable for AD create flow."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            re.search(r"[a-z]", password)
            and re.search(r"[A-Z]", password)
            and re.search(r"\d", password)
            and re.search(r"[!@#$%^&*()\-\_=+\[\]{}|;:,.<>?]", password)
        ):
            return password

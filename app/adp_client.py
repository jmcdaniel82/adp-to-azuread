"""ADP API client and ADP worker payload helper functions."""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import string
import time
from datetime import datetime, timezone
from typing import Any, Optional

import requests

from .config import env_truthy, get_adp_settings, validate_adp_settings
from .constants import (
    ADP_COUNTRY_NUMERIC_BY_ALPHA2,
    ADP_HTTP_BACKOFF_SECONDS,
    ADP_HTTP_MAX_RETRIES,
    ADP_HTTP_TIMEOUT_SECONDS,
)
from .security import ensure_file_from_env, get_adp_ca_bundle


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


def _dedupe_recency_key(emp: dict, index: int) -> tuple[int, float, int]:
    """Sort key preferring latest lastUpdated, then latest hire date, then index."""
    updated_at = extract_last_updated(emp)
    if updated_at:
        return (2, updated_at.timestamp(), index)
    hire_date = _parse_datetime_silent(get_hire_date(emp) or "")
    if hire_date:
        return (1, hire_date.timestamp(), index)
    return (0, float(index), index)


def dedupe_workers_by_employee_id(workers: list[dict], context: str) -> list[dict]:
    """Keep one worker row per employeeID, preferring the most recent row."""
    if not isinstance(workers, list) or not workers:
        return workers

    selected: dict[str, tuple[int, tuple[int, float, int], dict]] = {}
    duplicates_seen = 0

    for index, worker in enumerate(workers):
        employee_id = normalize_id(extract_employee_id(worker))
        if not employee_id:
            continue
        key = _dedupe_recency_key(worker, index)
        current = selected.get(employee_id)
        if not current:
            selected[employee_id] = (index, key, worker)
            continue
        duplicates_seen += 1
        if key >= current[1]:
            selected[employee_id] = (index, key, worker)

    if duplicates_seen == 0:
        return workers

    kept_indexes = {item[0] for item in selected.values()}
    deduped: list[dict] = []
    dropped = 0
    for index, worker in enumerate(workers):
        employee_id = normalize_id(extract_employee_id(worker))
        if not employee_id:
            deduped.append(worker)
            continue
        if index in kept_indexes:
            deduped.append(worker)
        else:
            dropped += 1
    logging.warning(
        f"[WARN] {context} deduped ADP records by employeeID: "
        f"input={len(workers)} output={len(deduped)} dropped={dropped}"
    )
    return deduped


def _normalize_profile_signal(value: str) -> str:
    """Normalize profile signal values used for duplicate-profile warning signatures."""
    if not value:
        return ""
    return re.sub(r"\s+", " ", str(value).strip().lower())


def _profile_signature(worker: dict) -> tuple[str, str, str, str]:
    """Create non-blocking duplicate signature across identifying profile signals."""
    person = worker.get("person", {})
    display = get_display_name(person)
    title = extract_business_title(worker) or extract_assignment_field(worker, "jobTitle")
    department = extract_department(worker)
    manager_id = extract_manager_id(worker) or ""
    return (
        _normalize_profile_signal(display),
        _normalize_profile_signal(title),
        _normalize_profile_signal(department),
        _normalize_profile_signal(manager_id),
    )


def log_potential_duplicate_profiles(workers: list[dict], context: str) -> None:
    """Emit capped non-blocking warnings when profiles look duplicated in ADP."""
    if not isinstance(workers, list) or not workers:
        return

    grouped: dict[tuple[str, str, str, str], set[str]] = {}
    for worker in workers:
        employee_id = normalize_id(extract_employee_id(worker))
        if not employee_id:
            continue
        signature = _profile_signature(worker)
        if not all(signature):
            continue
        grouped.setdefault(signature, set()).add(employee_id)

    limit_raw = os.getenv("ADP_PROFILE_DUP_WARN_LIMIT", "25")
    try:
        max_warnings = max(1, int(limit_raw))
    except ValueError:
        max_warnings = 25

    warning_count = 0
    for signature, employee_ids in grouped.items():
        if len(employee_ids) < 2:
            continue
        warning_count += 1
        display, title, department, manager_id = signature
        ids = sorted(employee_ids)
        preview = ",".join(ids[:10]) + ("..." if len(ids) > 10 else "")
        logging.warning(
            f"[WARN] {context} possible duplicate ADP profile (non-blocking): "
            f"employeeIDs={preview} display='{display}' title='{title}' "
            f"department='{department}' managerID='{manager_id}'"
        )
        if warning_count >= max_warnings:
            logging.warning(
                f"[WARN] {context} duplicate profile warning limit reached "
                f"(ADP_PROFILE_DUP_WARN_LIMIT={max_warnings})"
            )
            break


def _request_with_retries(
    method: str,
    url: str,
    *,
    action_label: str,
    max_attempts: int = ADP_HTTP_MAX_RETRIES,
    timeout: int = ADP_HTTP_TIMEOUT_SECONDS,
    retryable_statuses: Optional[set[int]] = None,
    **kwargs: Any,
) -> Optional[Any]:
    """Execute HTTP request with bounded retries for transient failures."""
    retryable = retryable_statuses or {429, 500, 502, 503, 504}
    delay = ADP_HTTP_BACKOFF_SECONDS
    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.request(method, url, timeout=timeout, **kwargs)
        except requests.RequestException as exc:
            if attempt >= max_attempts:
                logging.error(f"{action_label} failed after {attempt} attempts: {exc}")
                return None
            logging.warning(
                f"{action_label} transport error (attempt {attempt}/{max_attempts}): {exc}; retrying"
            )
            time.sleep(delay)
            delay *= 2
            continue
        if response.status_code in retryable:
            if attempt >= max_attempts:
                logging.error(
                    f"{action_label} failed after {attempt} attempts with HTTP "
                    f"{response.status_code}: {response.text}"
                )
                return None
            logging.warning(
                f"{action_label} received retryable HTTP {response.status_code} "
                f"(attempt {attempt}/{max_attempts}); retrying"
            )
            time.sleep(delay)
            delay *= 2
            continue
        return response
    return None


def get_adp_token() -> Optional[str]:
    """Get ADP OAuth token using client credentials and mTLS cert material."""
    missing = validate_adp_settings()
    # Token path does not require ADP_EMPLOYEE_URL, so remove it from token preflight checks.
    missing = [name for name in missing if name != "ADP_EMPLOYEE_URL"]
    if missing:
        logging.error(f"Missing ADP token configuration: {', '.join(missing)}")
        return None
    settings = get_adp_settings()
    token_url = settings.token_url
    client_id = settings.client_id
    client_secret = settings.client_secret
    pem_path = ensure_file_from_env("ADP_CERT_PEM", ".pem")
    key_path = ensure_file_from_env("ADP_CERT_KEY", ".key")
    if not pem_path:
        logging.error("ADP_CERT_PEM environment variable is missing or invalid.")
        return None

    cert_arg: str | tuple[str, str]
    cert_arg = (pem_path, key_path) if key_path else pem_path
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    response = _request_with_retries(
        "POST",
        token_url,
        action_label="ADP token request",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=payload,
        cert=cert_arg,
        verify=get_adp_ca_bundle(),
    )
    if not response:
        return None
    if not response.ok:
        logging.error(f"ADP token request failed (HTTP {response.status_code}): {response.text}")
        return None
    try:
        body = response.json()
    except json.JSONDecodeError:
        logging.error(f"ADP token response was not JSON: {response.text}")
        return None
    token = body.get("access_token")
    if not token:
        logging.error(f"ADP token response missing access_token. Keys={list(body.keys())}")
        return None
    return token


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


def get_adp_employees(
    token: str, limit: int = 50, offset: int = 0, paginate_all: bool = True
) -> Optional[list[dict]]:
    """Retrieve ADP workers list with pagination."""
    settings = get_adp_settings()
    base_url = settings.employee_url
    if not base_url:
        logging.error("ADP_EMPLOYEE_URL environment variable is not set.")
        return None
    pem_path = ensure_file_from_env("ADP_CERT_PEM", ".pem")
    key_path = ensure_file_from_env("ADP_CERT_KEY", ".key")
    if not pem_path:
        logging.error("ADP_CERT_PEM environment variable is missing or invalid.")
        return None
    cert_arg: str | tuple[str, str]
    cert_arg = (pem_path, key_path) if key_path else pem_path
    headers = {"Authorization": f"Bearer {token}"}
    verify_arg = get_adp_ca_bundle()

    employees: list[dict] = []
    current_offset = offset
    while True:
        url = f"{base_url}?$top={limit}&$skip={current_offset}"
        response = _request_with_retries(
            "GET",
            url,
            action_label=f"ADP workers fetch (offset={current_offset})",
            headers=headers,
            cert=cert_arg,
            verify=verify_arg,
        )
        if not response:
            return None
        if not response.ok:
            logging.error(f"Failed to retrieve employees (HTTP {response.status_code}): {response.text}")
            return None
        try:
            payload = response.json()
        except json.JSONDecodeError:
            logging.error(f"Failed to decode JSON from ADP response: {response.text}")
            return None
        page_workers = payload.get("workers", [])
        if not isinstance(page_workers, list):
            logging.error(f"Unexpected ADP workers payload type: {type(page_workers).__name__}")
            return None
        employees.extend(page_workers)
        logging.info(f"Records retrieved so far: {len(employees)}")
        if not paginate_all or len(page_workers) < limit:
            break
        current_offset += limit
    logging.info(f"Total records retrieved in this call: {len(employees)}")
    return employees


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

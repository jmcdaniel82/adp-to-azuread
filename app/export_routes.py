"""HTTP route handlers for process/export diagnostics endpoints."""

from __future__ import annotations

import json
import logging
import os
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime
from typing import Optional

from ldap3 import SUBTREE

from .adp_client import (
    extract_assignment_field,
    extract_business_title,
    extract_company,
    extract_department,
    extract_employee_id,
    get_adp_employees,
    get_adp_token,
    get_display_name,
    get_hire_date,
    get_legal_first_last,
    get_preferred_first_last,
    get_status,
    get_termination_date,
    normalize_dept,
    normalize_id,
)
from .azure_compat import func
from .config import get_ldap_settings, validate_ldap_settings
from .ldap_client import (
    create_ldap_server,
    log_ldap_target_details,
    make_conn_factory,
    safe_unbind,
)


def json_converter(value):
    """Convert non-JSON-native objects to string values."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def process_request_handler(req: func.HttpRequest) -> func.HttpResponse:
    """Return active ADP users with core fields for quick diagnostics."""
    token = get_adp_token()
    if not token:
        return func.HttpResponse("Token fail", status_code=500)
    employees = get_adp_employees(token)
    if employees is None:
        return func.HttpResponse("Fail emps", status_code=500)

    active_emps = [emp for emp in employees if get_status(emp) == "Active"]
    sorted_emps = sorted(
        [emp for emp in active_emps if get_hire_date(emp)],
        key=lambda emp: get_hire_date(emp) or "",
        reverse=True,
    )
    payload = []
    for emp in sorted_emps:
        try:
            person = emp.get("person", {})
            legal_first, legal_last = get_legal_first_last(person)
            preferred_first, preferred_last = get_preferred_first_last(person)
            payload.append(
                {
                    "employeeId": extract_employee_id(emp),
                    "givenName": legal_first,
                    "familyName": legal_last,
                    "legalGivenName": legal_first,
                    "legalFamilyName": legal_last,
                    "preferredGivenName": preferred_first,
                    "preferredFamilyName": preferred_last,
                    "displayName": get_display_name(person),
                    "jobTitle": extract_business_title(emp) or extract_assignment_field(emp, "jobTitle"),
                    "company": extract_company(emp),
                    "department": extract_department(emp),
                    "hireDate": get_hire_date(emp),
                    "terminationDate": get_termination_date(emp),
                    "workAssignments": emp.get("workAssignments", []),
                }
            )
        except Exception as exc:
            logging.warning(f"Skipping malformed process_request worker record: {exc}")
    return func.HttpResponse(json.dumps(payload), mimetype="application/json", status_code=200)


def fetch_ad_data_task() -> Optional[dict]:
    """Read AD employeeID->department map used by export diagnostics route."""
    missing_ldap = validate_ldap_settings(require_create_base=False)
    if missing_ldap:
        logging.error(f"Missing LDAP configuration for export: {', '.join(missing_ldap)}")
        return None
    ldap_settings = get_ldap_settings(require_create_base=False)
    if not os.path.isfile(ldap_settings.ca_bundle_path):
        logging.error(f"CA bundle not found for export at {ldap_settings.ca_bundle_path}")
        return None
    log_ldap_target_details("Export", ldap_settings.server, ldap_settings.ca_bundle_path)
    server = create_ldap_server(
        ldap_settings.server,
        ldap_settings.ca_bundle_path,
        tls_version=ssl.PROTOCOL_TLS_CLIENT,
    )
    conn_factory = make_conn_factory(server, ldap_settings.user, ldap_settings.password, "Export")
    try:
        conn = conn_factory()
    except Exception as exc:
        logging.error(f"Failed to connect to LDAP: {exc}")
        return None

    ldap_map: dict[str, str] = {}
    page_size = 500
    cookie = None
    try:
        while True:
            try:
                conn.search(
                    ldap_settings.search_base,
                    "(employeeID=*)",
                    SUBTREE,
                    attributes=["employeeID", "department"],
                    paged_size=page_size,
                    paged_cookie=cookie,
                )
            except Exception as exc:
                logging.error(f"LDAP export search failed: {exc}")
                return None
            for entry in conn.entries:
                raw_id = entry.employeeID.value
                raw_dept = entry.department.value if entry.department else None
                emp_id = normalize_id(raw_id)
                dept = normalize_dept(raw_dept) if raw_dept else None
                if emp_id and dept:
                    ldap_map[emp_id] = dept
            controls = (conn.result or {}).get("controls", {})
            cookie = controls.get("1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
            if not cookie:
                break
    finally:
        safe_unbind(conn, "fetch_ad_data_task completion")
        logging.info("[INFO] LDAP connection closed for export.")
    return ldap_map


def export_adp_data_handler(req: func.HttpRequest) -> func.HttpResponse:
    """Return ADP-vs-AD department mapping diagnostics payload."""
    logging.info("Export triggered: building dept mappings and diagnostics.")
    token = get_adp_token()
    if not token:
        return func.HttpResponse("ADP token retrieval failed.", status_code=500)

    with ThreadPoolExecutor(max_workers=2) as executor:
        future_adp = executor.submit(get_adp_employees, token)
        future_ldap = executor.submit(fetch_ad_data_task)
        try:
            adp_employees = future_adp.result()
            ldap_map = future_ldap.result()
        except Exception as exc:
            logging.error(f"Parallel data fetch failed: {exc}")
            return func.HttpResponse("Data fetch execution error.", status_code=500)

    if adp_employees is None or ldap_map is None:
        return func.HttpResponse("Data fetch error (ADP or AD).", status_code=500)

    adp_depts = {normalize_dept(extract_department(emp)) for emp in adp_employees if extract_department(emp)}
    ad_depts = set(ldap_map.values())
    ids_adp = {normalize_id(extract_employee_id(emp)) for emp in adp_employees if extract_employee_id(emp)}
    ids_ad = set(ldap_map.keys())
    missing_in_ad = sorted(list(ids_adp - ids_ad))
    missing_in_adp = sorted(list(ids_ad - ids_adp))

    dept_pairs = set()
    for emp in adp_employees:
        try:
            emp_id = normalize_id(extract_employee_id(emp))
            if not emp_id:
                continue
            adp_dept = normalize_dept(extract_department(emp))
            if not adp_dept:
                continue
            ad_dept = ldap_map.get(emp_id)
            if not ad_dept:
                continue
            dept_pairs.add((adp_dept, ad_dept))
        except Exception as exc:
            logging.warning(f"Skipping malformed export worker record: {exc}")

    result = {
        "pairs": sorted(list(dept_pairs)),
        "adpDepartments": sorted(list(adp_depts)),
        "adDepartments": sorted(list(ad_depts)),
        "adpOnlyIDs": missing_in_ad,
        "adOnlyIDs": missing_in_adp,
    }
    return func.HttpResponse(
        json.dumps(result, default=json_converter, indent=2),
        mimetype="application/json",
        status_code=200,
    )

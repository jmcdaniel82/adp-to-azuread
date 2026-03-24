"""Read-only diagnostics projections and payload builders."""

from __future__ import annotations

import logging
from typing import Any

from ..adp import (
    extract_assignment_field,
    extract_business_title,
    extract_company,
    extract_department,
    extract_employee_id,
    get_display_name,
    get_hire_date,
    get_legal_first_last,
    get_preferred_first_last,
    get_status,
    get_termination_date,
    normalize_dept,
    normalize_id,
)


def build_worker_snapshot(emp: dict[str, Any]) -> dict[str, Any] | None:
    """Project one ADP worker into a compact diagnostics-safe view."""
    try:
        person = emp.get("person", {})
        legal_first, legal_last = get_legal_first_last(person)
        preferred_first, preferred_last = get_preferred_first_last(person)
        return {
            "employeeId": extract_employee_id(emp),
            "status": get_status(emp),
            "displayName": get_display_name(person),
            "legalGivenName": legal_first,
            "legalFamilyName": legal_last,
            "preferredGivenName": preferred_first,
            "preferredFamilyName": preferred_last,
            "jobTitle": extract_business_title(emp) or extract_assignment_field(emp, "jobTitle"),
            "company": extract_company(emp),
            "department": extract_department(emp),
            "hireDate": get_hire_date(emp),
            "terminationDate": get_termination_date(emp),
        }
    except Exception as exc:
        logging.warning(f"Skipping malformed diagnostics worker record: {exc}")
        return None


def find_worker_snapshot(
    adp_employees: list[dict[str, Any]],
    employee_id: str,
) -> dict[str, Any] | None:
    """Return one diagnostics worker snapshot by employee ID."""
    normalized_employee_id = normalize_id(employee_id)
    for emp in adp_employees:
        if normalize_id(extract_employee_id(emp)) != normalized_employee_id:
            continue
        return build_worker_snapshot(emp)
    return None


def build_department_diff_payload(
    adp_employees: list[dict[str, Any]],
    ldap_map: dict[str, str],
) -> dict[str, Any]:
    """Build the ADP-vs-AD department comparison payload."""
    adp_depts = {
        normalize_dept(extract_department(emp))
        for emp in adp_employees
        if extract_department(emp)
    }
    ad_depts = set(ldap_map.values())
    ids_adp = {
        normalize_id(extract_employee_id(emp))
        for emp in adp_employees
        if extract_employee_id(emp)
    }
    ids_ad = set(ldap_map.keys())
    missing_in_ad = sorted(list(ids_adp - ids_ad))
    missing_in_adp = sorted(list(ids_ad - ids_adp))

    dept_pairs: set[tuple[str, str]] = set()
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
            logging.warning(f"Skipping malformed diagnostics worker record: {exc}")

    return {
        "pairs": sorted(list(dept_pairs)),
        "adpDepartments": sorted(list(adp_depts)),
        "adDepartments": sorted(list(ad_depts)),
        "adpOnlyIDs": missing_in_ad,
        "adOnlyIDs": missing_in_adp,
    }


def build_summary_payload(
    adp_employees: list[dict[str, Any]],
    ldap_map: dict[str, str],
) -> dict[str, Any]:
    """Build summary counts for the diagnostics summary view."""
    diff_payload = build_department_diff_payload(adp_employees, ldap_map)
    active_total = sum(1 for emp in adp_employees if get_status(emp) == "Active")
    return {
        "adpTotal": len(adp_employees),
        "activeTotal": active_total,
        "adpOnlyCount": len(diff_payload["adpOnlyIDs"]),
        "adOnlyCount": len(diff_payload["adOnlyIDs"]),
        "deptPairCount": len(diff_payload["pairs"]),
    }


def build_recent_hires_payload(
    adp_employees: list[dict[str, Any]],
    limit: int,
) -> dict[str, Any]:
    """Build the recent-hires payload with capped active workers."""
    active_emps = [emp for emp in adp_employees if get_status(emp) == "Active" and get_hire_date(emp)]
    sorted_emps = sorted(active_emps, key=lambda emp: get_hire_date(emp) or "", reverse=True)
    workers = []
    for emp in sorted_emps[:limit]:
        snapshot = build_worker_snapshot(emp)
        if snapshot is not None:
            workers.append(snapshot)
    return {
        "limitApplied": limit,
        "returned": len(workers),
        "workers": workers,
    }

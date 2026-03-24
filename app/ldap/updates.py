"""LDAP update planning, diffing, and modify helpers."""

from __future__ import annotations

import logging
from typing import Optional

from ldap3 import MODIFY_REPLACE, Connection

from ..adp_client import (
    build_ad_country_attributes,
    extract_assignment_field,
    extract_business_title,
    extract_company,
    extract_employee_id,
    extract_manager_id,
    extract_state_from_work,
    extract_work_address_field,
    get_display_name,
    get_hire_date,
    get_preferred_first_last,
    get_user_account_control,
)
from ..config import env_truthy
from ..constants import ATTR_DISPLAY_NAME, EMAIL_IDENTIFIER_UPDATE_DENYLIST
from ..department_resolution import normalize_department_name, resolve_local_ac_department
from .connection import format_ldap_error, is_bind_lost_result, safe_unbind
from .directory import entry_attr_value, get_department_by_dn, get_manager_dn

ACCOUNTDISABLE_FLAG = 0x0002


def is_email_identifier_attribute(attr: str) -> bool:
    """Return True when attribute is create-time-only email identifier."""
    return (attr or "").strip().lower() in EMAIL_IDENTIFIER_UPDATE_DENYLIST


def filter_blocked_update_changes(changes: dict, context: str) -> dict:
    """Drop prohibited email-routing update modifications."""
    filtered = {}
    for attr, ops in (changes or {}).items():
        if is_email_identifier_attribute(attr):
            logging.warning(
                f"Blocked prohibited update attribute '{attr}' for {context}; "
                "email identifiers are create-time only"
            )
            continue
        filtered[attr] = ops
    return filtered


def plan_update_attributes(
    emp: dict,
    conn,
    ldap_search_base: str,
    current_ad_department: str = "",
    manager_department: str = "",
) -> tuple[dict, dict, Optional[str], str]:
    """Return exact desired update attrs plus department-planning context."""
    emp_id = extract_employee_id(emp)
    country_attrs = build_ad_country_attributes(extract_work_address_field(emp, "countryCode"))

    desired = {
        "title": extract_business_title(emp) or extract_assignment_field(emp, "jobTitle"),
        "company": extract_company(emp),
        "l": extract_work_address_field(emp, "cityName"),
        "postalCode": extract_work_address_field(emp, "postalCode"),
        "st": extract_state_from_work(emp),
        "streetAddress": extract_work_address_field(emp, "lineOne"),
        "co": country_attrs["co"],
        "c": country_attrs["c"],
        "countryCode": country_attrs["countryCode"],
    }
    if get_hire_date(emp):
        desired["userAccountControl"] = get_user_account_control(emp)
    person = emp.get("person", {}) if isinstance(emp, dict) else {}
    preferred_first, preferred_last = get_preferred_first_last(person)
    if preferred_first and preferred_last:
        desired[ATTR_DISPLAY_NAME] = get_display_name(person)

    manager_dn = get_manager_dn(
        conn,
        ldap_search_base,
        extract_manager_id(emp),
        subject_employee_id=emp_id,
    )
    resolved_manager_department = (manager_department or "").strip()
    if manager_dn:
        desired["manager"] = manager_dn
        manager_dept_from_dn = get_department_by_dn(conn, manager_dn)
        if manager_dept_from_dn:
            resolved_manager_department = manager_dept_from_dn

    resolution = resolve_local_ac_department(
        emp,
        current_ad_department=current_ad_department,
        manager_department=resolved_manager_department,
    )
    resolved_department = resolution.get("proposedDepartmentV2")
    if resolved_department:
        desired["department"] = resolved_department

    if env_truthy("LOG_DEPARTMENT_MAPPING", False):
        logging.info(
            "Department resolution for %s: proposed=%s, evidence=%s, confidence=%s, block=%s",
            emp_id,
            resolved_department or "<none>",
            resolution.get("evidenceUsed") or "<none>",
            resolution.get("confidence") or "<none>",
            resolution.get("blockReason") or "<none>",
        )
    return desired, resolution, manager_dn, resolved_manager_department


def build_update_attributes(
    emp: dict,
    conn,
    ldap_search_base: str,
    current_ad_department: str = "",
    manager_department: str = "",
) -> dict:
    """Map ADP worker payload into AD attributes for update flow."""
    desired, _resolution, _manager_dn, _resolved_manager_department = plan_update_attributes(
        emp,
        conn,
        ldap_search_base,
        current_ad_department=current_ad_department,
        manager_department=manager_department,
    )
    return desired


def normalize_department_for_compare(value: str) -> str:
    """Normalize department values only for diff comparisons."""
    return normalize_department_name(value)


def _parse_int_like(value) -> Optional[int]:
    """Return int value when the payload is numeric-like, else None."""
    if value in (None, ""):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def diff_update_attributes(entry, desired: dict, context: str = "") -> dict:
    """Compute LDAP MODIFY_REPLACE ops for meaningful attribute changes."""
    changes = {}
    for attr, desired_val in desired.items():
        if is_email_identifier_attribute(attr):
            logging.warning(
                f"Blocked prohibited desired attribute '{attr}' in diff stage for {context or '<unknown>'}"
            )
            continue
        if desired_val in (None, ""):
            continue
        current = entry_attr_value(entry, attr)
        if isinstance(desired_val, str):
            current_str = (current or "").strip()
            desired_str = desired_val.strip()
            if attr == "manager":
                if current_str.lower() == desired_str.lower():
                    continue
            elif attr == "department":
                current_cmp = normalize_department_for_compare(current_str)
                desired_cmp = normalize_department_for_compare(desired_str)
                if current_cmp.lower() == desired_cmp.lower():
                    continue
            elif attr == "userAccountControl":
                current_int = _parse_int_like(current)
                desired_int = _parse_int_like(desired_val)
                if current_int is not None and desired_int is not None:
                    if desired_int == 514 and (current_int & ACCOUNTDISABLE_FLAG):
                        continue
                    if current_int == desired_int:
                        continue
            elif current_str == desired_str:
                continue
        else:
            if attr == "userAccountControl":
                current_int = _parse_int_like(current)
                desired_int = _parse_int_like(desired_val)
                if current_int is not None and desired_int is not None:
                    if desired_int == 514 and (current_int & ACCOUNTDISABLE_FLAG):
                        continue
                    if current_int == desired_int:
                        continue
            elif current == desired_val:
                continue
        changes[attr] = [(MODIFY_REPLACE, [desired_val])]
    return filter_blocked_update_changes(changes, context or "<unknown>")


def apply_ldap_modifications(conn, dn: str, changes: dict, conn_factory=None) -> Optional[Connection]:
    """Apply LDAP modify ops with bind-loss recovery."""
    filtered_changes = filter_blocked_update_changes(changes, dn)
    if not filtered_changes:
        return conn
    try:
        if conn.modify(dn, filtered_changes):
            return conn
    except Exception as exc:
        logging.error(f"Modify raised exception for {dn}: {exc}")
        if conn_factory:
            try:
                safe_unbind(conn, f"modify exception for {dn}")
                conn = conn_factory()
                if conn.modify(dn, filtered_changes):
                    return conn
            except Exception as reconnect_error:
                logging.error(f"Reconnect after modify exception failed for {dn}: {reconnect_error}")
        return conn

    result = conn.result or {}
    if is_bind_lost_result(result):
        logging.warning(f"Modify failed for {dn} (bind lost); attempting rebind")
        try:
            if conn.rebind() and conn.modify(dn, filtered_changes):
                return conn
        except Exception as exc:
            logging.error(f"Rebind failed during modify: {exc}")
        if conn_factory:
            logging.warning(f"Reconnecting LDAP after modify bind loss for {dn}")
            try:
                safe_unbind(conn, f"modify bind-loss for {dn}")
                conn = conn_factory()
                if conn.modify(dn, filtered_changes):
                    return conn
            except Exception as exc:
                logging.error(f"Reconnect failed during modify: {exc}")
        logging.error(f"Modify failed for {dn}: {format_ldap_error(conn)}")
        return conn
    logging.error(f"Modify failed for {dn}: {conn.result}")
    return conn

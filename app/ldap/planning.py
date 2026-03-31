"""LDAP update planning and diff helpers."""

from __future__ import annotations

import logging
from typing import Collection, Optional

from ldap3 import MODIFY_REPLACE

from ..adp import (
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
from ..department.resolver import normalize_department_name, resolve_local_ac_department
from .directory import entry_attr_value, get_department_by_dn, get_manager_dn

ACCOUNTDISABLE_FLAG = 0x0002


def _is_update_field_enabled(attr: str, enabled_fields: Collection[str] | None) -> bool:
    """Return True when an update attribute is active for the current planning pass."""
    return enabled_fields is None or attr in enabled_fields


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
    enabled_fields: Collection[str] | None = None,
) -> tuple[dict, dict, Optional[str], str]:
    """Return exact desired update attrs plus department-planning context."""
    emp_id = extract_employee_id(emp)
    desired: dict[str, object] = {}

    if _is_update_field_enabled("title", enabled_fields):
        desired["title"] = extract_business_title(emp) or extract_assignment_field(emp, "jobTitle")
    if _is_update_field_enabled("company", enabled_fields):
        desired["company"] = extract_company(emp)
    if _is_update_field_enabled("l", enabled_fields):
        desired["l"] = extract_work_address_field(emp, "cityName")
    if _is_update_field_enabled("postalCode", enabled_fields):
        desired["postalCode"] = extract_work_address_field(emp, "postalCode")
    if _is_update_field_enabled("st", enabled_fields):
        desired["st"] = extract_state_from_work(emp)
    if _is_update_field_enabled("streetAddress", enabled_fields):
        desired["streetAddress"] = extract_work_address_field(emp, "lineOne")
    if any(
        _is_update_field_enabled(attr, enabled_fields) for attr in ("co", "c", "countryCode")
    ):
        country_attrs = build_ad_country_attributes(extract_work_address_field(emp, "countryCode"))
        for attr in ("co", "c", "countryCode"):
            if _is_update_field_enabled(attr, enabled_fields):
                desired[attr] = country_attrs[attr]
    if _is_update_field_enabled("userAccountControl", enabled_fields) and get_hire_date(emp):
        desired["userAccountControl"] = get_user_account_control(emp)
    person = emp.get("person", {}) if isinstance(emp, dict) else {}
    preferred_first, preferred_last = get_preferred_first_last(person)
    if _is_update_field_enabled(ATTR_DISPLAY_NAME, enabled_fields) and preferred_first and preferred_last:
        desired[ATTR_DISPLAY_NAME] = get_display_name(person)

    manager_dn = None
    resolved_manager_department = (manager_department or "").strip()
    resolution: dict = {}
    if _is_update_field_enabled("manager", enabled_fields) or _is_update_field_enabled(
        "department", enabled_fields
    ):
        manager_dn = get_manager_dn(
            conn,
            ldap_search_base,
            extract_manager_id(emp),
            subject_employee_id=emp_id,
        )
        if manager_dn and _is_update_field_enabled("manager", enabled_fields):
            desired["manager"] = manager_dn
        if manager_dn and _is_update_field_enabled("department", enabled_fields):
            manager_dept_from_dn = get_department_by_dn(conn, manager_dn)
            if manager_dept_from_dn:
                resolved_manager_department = manager_dept_from_dn

    if _is_update_field_enabled("department", enabled_fields):
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
    enabled_fields: Collection[str] | None = None,
) -> dict:
    """Map ADP worker payload into AD attributes for update flow."""
    desired, _resolution, _manager_dn, _resolved_manager_department = plan_update_attributes(
        emp,
        conn,
        ldap_search_base,
        current_ad_department=current_ad_department,
        manager_department=manager_department,
        enabled_fields=enabled_fields,
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


def _is_account_disabled_value(value) -> bool:
    """Return True when the AD account-disable bit is set."""
    current_int = _parse_int_like(value)
    return current_int is not None and bool(current_int & ACCOUNTDISABLE_FLAG)


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
                if _is_account_disabled_value(entry_attr_value(entry, "userAccountControl")):
                    logging.info(
                        "Skipping manager update for disabled account %s",
                        context or "<unknown>",
                    )
                    continue
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
                    if desired_int == 512 and (current_int & ACCOUNTDISABLE_FLAG):
                        logging.info(
                            "Skipping userAccountControl enable for disabled account %s",
                            context or "<unknown>",
                        )
                        continue
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
                    if desired_int == 512 and (current_int & ACCOUNTDISABLE_FLAG):
                        logging.info(
                            "Skipping userAccountControl enable for disabled account %s",
                            context or "<unknown>",
                        )
                        continue
                    if desired_int == 514 and (current_int & ACCOUNTDISABLE_FLAG):
                        continue
                    if current_int == desired_int:
                        continue
            elif current == desired_val:
                continue
        changes[attr] = [(MODIFY_REPLACE, [desired_val])]
    return filter_blocked_update_changes(changes, context or "<unknown>")


__all__ = [
    "ACCOUNTDISABLE_FLAG",
    "build_update_attributes",
    "diff_update_attributes",
    "filter_blocked_update_changes",
    "is_email_identifier_attribute",
    "normalize_department_for_compare",
    "plan_update_attributes",
]

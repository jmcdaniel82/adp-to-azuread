"""LDAP directory lookup and diagnostics helpers."""

from __future__ import annotations

import logging
from typing import Optional

from ldap3 import BASE, SUBTREE
from ldap3.utils.conv import escape_filter_chars

from ..constants import (
    ATTR_CN,
    ATTR_DISPLAY_NAME,
    ATTR_EMPLOYEE_ID,
    ATTR_MAIL,
    ATTR_SAM_ACCOUNT_NAME,
    ATTR_USER_PRINCIPAL_NAME,
)
from ..reporting import inc_stat


def entry_attr_value(entry, attr: str):
    """Read LDAP entry attribute safely for mixed entry shapes."""
    try:
        if hasattr(entry, attr):
            return getattr(entry, attr).value
        return entry[attr].value
    except Exception:
        return None


def get_manager_dn(
    conn,
    ldap_search_base: str,
    manager_id: Optional[str],
    subject_employee_id: str = "",
    summary_stats: Optional[dict] = None,
):
    """Lookup manager DN by manager employeeID, warning when not found."""
    if not manager_id:
        return None
    try:
        found = conn.search(
            ldap_search_base,
            f"(employeeID={manager_id})",
            SUBTREE,
            attributes=["distinguishedName"],
        )
    except Exception as exc:
        logging.warning(f"Manager lookup failed for {manager_id}: {exc}")
        return None
    if found and conn.entries:
        return conn.entries[0].distinguishedName.value

    inc_stat(summary_stats, "manager_missing")
    if subject_employee_id:
        logging.warning(
            "Manager not found in AD for employee %s: manager employeeID=%s",
            subject_employee_id,
            manager_id,
        )
    else:
        logging.warning(f"Manager not found in AD: manager employeeID={manager_id}")
    return None


def get_department_by_dn(conn, dn: str) -> str:
    """Lookup department for one DN."""
    if not dn:
        return ""
    try:
        conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["department"],
        )
        if conn.entries:
            value = conn.entries[0].department.value if conn.entries[0].department else None
            return (value or "").strip()
    except Exception:
        return ""
    return ""


def log_cn_conflict_inventory(
    conn, ldap_create_base: str, full_name: str, employee_id: str, max_entries: int = 12
):
    """Emit conflict inventory for repeated CN collision diagnostics."""
    if not conn or not ldap_create_base or not full_name:
        return
    try:
        escaped_name = escape_filter_chars(full_name)
        search_filter = f"(|(cn={escaped_name}*)(displayName={escaped_name}*))"
        found = conn.search(
            ldap_create_base,
            search_filter,
            SUBTREE,
            attributes=[
                "distinguishedName",
                ATTR_CN,
                ATTR_DISPLAY_NAME,
                ATTR_EMPLOYEE_ID,
                ATTR_USER_PRINCIPAL_NAME,
                ATTR_MAIL,
            ],
            size_limit=max_entries,
        )
        if not found or not conn.entries:
            logging.warning(
                f"[WARN] CN collision diagnostics found no '{full_name}*' entries under '{ldap_create_base}' "
                f"for employeeID={employee_id}"
            )
            return
        entries_preview = []
        for entry in conn.entries[:max_entries]:
            dn = entry_attr_value(entry, "distinguishedName") or str(getattr(entry, "entry_dn", ""))
            cn = entry_attr_value(entry, ATTR_CN) or ""
            display = entry_attr_value(entry, ATTR_DISPLAY_NAME) or ""
            existing_emp_id = entry_attr_value(entry, ATTR_EMPLOYEE_ID) or ""
            upn = entry_attr_value(entry, ATTR_USER_PRINCIPAL_NAME) or ""
            mail = entry_attr_value(entry, ATTR_MAIL) or ""
            entries_preview.append(
                f"dn='{dn}' cn='{cn}' display='{display}' employeeID='{existing_emp_id}' "
                f"upn='{upn}' mail='{mail}'"
            )
        logging.warning(
            f"[WARN] CN collision diagnostics for employeeID {employee_id}: " + " | ".join(entries_preview)
        )
    except Exception as exc:
        logging.warning(f"[WARN] CN collision diagnostics failed for employeeID {employee_id}: {exc}")


def collect_identifier_conflicts(
    conn,
    ldap_search_base: str,
    *,
    employee_id: str,
    sam_account_name: str,
    user_principal_name: str,
    mail: str,
    max_entries: int = 8,
) -> dict:
    """Collect AD conflicts for unique identifiers (sam/upn/mail)."""
    if not conn or not ldap_search_base:
        return {"sam": [], "upn": [], "mail": []}

    employee_norm = (employee_id or "").strip().upper()
    conflicts: dict[str, list[str]] = {"sam": [], "upn": [], "mail": []}
    checks = [
        ("sam", ATTR_SAM_ACCOUNT_NAME, sam_account_name),
        ("upn", ATTR_USER_PRINCIPAL_NAME, user_principal_name),
        ("mail", ATTR_MAIL, mail),
    ]
    for key, attr, value in checks:
        if not value:
            continue
        try:
            escaped = escape_filter_chars(value)
            found = conn.search(
                ldap_search_base,
                f"({attr}={escaped})",
                SUBTREE,
                attributes=[
                    "distinguishedName",
                    ATTR_EMPLOYEE_ID,
                    ATTR_SAM_ACCOUNT_NAME,
                    ATTR_USER_PRINCIPAL_NAME,
                    ATTR_MAIL,
                ],
                size_limit=max_entries,
            )
            if not found or not conn.entries:
                continue
            for entry in conn.entries[:max_entries]:
                existing_emp_id = (entry_attr_value(entry, ATTR_EMPLOYEE_ID) or "").strip().upper()
                if existing_emp_id and existing_emp_id == employee_norm:
                    continue
                dn = entry_attr_value(entry, "distinguishedName") or str(getattr(entry, "entry_dn", ""))
                sam_val = entry_attr_value(entry, ATTR_SAM_ACCOUNT_NAME) or ""
                upn_val = entry_attr_value(entry, ATTR_USER_PRINCIPAL_NAME) or ""
                mail_val = entry_attr_value(entry, ATTR_MAIL) or ""
                conflicts[key].append(
                    f"dn='{dn}' employeeID='{existing_emp_id}' "
                    f"sAMAccountName='{sam_val}' userPrincipalName='{upn_val}' mail='{mail_val}'"
                )
        except Exception as exc:
            logging.warning(f"[WARN] Identifier conflict lookup failed for {attr}='{value}': {exc}")
    return conflicts


def dn_exists_in_create_scope(conn, dn_candidate: str) -> bool:
    """Return True when exact DN is visible to bind account."""
    if not conn or not dn_candidate:
        return False
    try:
        found = conn.search(
            search_base=dn_candidate,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["distinguishedName"],
        )
        return bool(found and conn.entries)
    except Exception:
        return False

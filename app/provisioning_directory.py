"""Directory-side helpers for provisioning flows."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from ldap3 import MODIFY_REPLACE, SUBTREE

from .adp import extract_manager_id
from .ldap import apply_ldap_modifications, get_department_by_dn, get_manager_dn


@dataclass(frozen=True)
class ManagerContext:
    """Resolved manager identifiers used during account creation."""

    manager_dn: str | None
    manager_department: str


def find_existing_user_dn(connection: Any, ldap_search_base: str, employee_id: str) -> Optional[str]:
    """Return the distinguishedName for an existing employeeID match."""
    try:
        connection.search(
            ldap_search_base,
            f"(employeeID={employee_id})",
            SUBTREE,
            attributes=["employeeID", "distinguishedName"],
        )
    except Exception as exc:
        logging.error(f"Existing-user lookup failed for {employee_id}: {exc}")
        return None
    if connection.entries:
        return connection.entries[0].distinguishedName.value
    return None


def resolve_manager_context(
    conn: Any,
    ldap_search_base: str,
    user_data: dict,
    emp_id: str,
    summary_stats: dict[str, int] | None = None,
) -> ManagerContext:
    """Resolve manager DN and manager department for create-time planning."""
    manager_dn = get_manager_dn(
        conn,
        ldap_search_base,
        extract_manager_id(user_data),
        subject_employee_id=emp_id,
        summary_stats=summary_stats,
    )
    manager_department = ""
    if manager_dn:
        manager_department = get_department_by_dn(conn, manager_dn) or ""
    return ManagerContext(manager_dn=manager_dn, manager_department=manager_department)


def update_existing_user_manager(
    conn: Any,
    existing_dn: str,
    ldap_search_base: str,
    user_data: dict,
    emp_id: str,
    conn_factory=None,
    summary_stats: dict[str, int] | None = None,
):
    """Refresh the manager attribute on an already-existing user when resolvable."""
    manager_dn = get_manager_dn(
        conn,
        ldap_search_base,
        extract_manager_id(user_data),
        subject_employee_id=emp_id,
        summary_stats=summary_stats,
    )
    if not manager_dn:
        return conn
    return apply_ldap_modifications(
        conn,
        existing_dn,
        {"manager": [(MODIFY_REPLACE, [manager_dn])]},
        conn_factory,
    )

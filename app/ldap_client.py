"""LDAP/LDAPS helpers for connection lifecycle, update diffs, and diagnostics."""

from __future__ import annotations

import logging
import socket
import ssl
from typing import Callable, Optional

from ldap3 import BASE, MODIFY_REPLACE, NTLM, SUBTREE, Connection, Server, Tls
from ldap3.utils.conv import escape_filter_chars

from .adp_client import (
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
from .config import env_truthy
from .constants import (
    ATTR_CN,
    ATTR_DISPLAY_NAME,
    ATTR_EMPLOYEE_ID,
    ATTR_MAIL,
    ATTR_SAM_ACCOUNT_NAME,
    ATTR_USER_PRINCIPAL_NAME,
    EMAIL_IDENTIFIER_UPDATE_DENYLIST,
)
from .department_resolution import normalize_department_name, resolve_local_ac_department
from .reporting import inc_stat


def log_ldap_target_details(context: str, host: str, ca_bundle: str, port: int = 636) -> None:
    """Log LDAP target host and DNS resolution details for troubleshooting."""
    logging.info(
        f"{context} LDAP target host='{host}' port={port} use_ssl=True "
        f"tls_version=TLSv1_2 ca_bundle='{ca_bundle}'"
    )
    if not host:
        return
    try:
        resolved = sorted(str(item[4][0]) for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        if resolved:
            logging.info(f"{context} LDAP DNS '{host}' resolved to: {', '.join(resolved)}")
    except Exception as exc:
        logging.warning(f"{context} LDAP DNS resolution failed for '{host}': {exc}")


def build_tls_config(ca_bundle: str, tls_version: int = ssl.PROTOCOL_TLSv1_2) -> Tls:
    """Build TLS config for secure LDAP connections."""
    return Tls(ca_certs_file=ca_bundle, validate=ssl.CERT_REQUIRED, version=tls_version)


def create_ldap_server(
    host: str, ca_bundle: str, *, port: int = 636, tls_version: int = ssl.PROTOCOL_TLSv1_2
) -> Server:
    """Create LDAP server object configured for LDAPS."""
    tls = build_tls_config(ca_bundle, tls_version=tls_version)
    return Server(host, port=port, use_ssl=True, tls=tls, get_info=None)


def make_conn_factory(
    server: Server, user: str, password: str, context_label: str
) -> Callable[[], Connection]:
    """Create a reusable LDAP bound-connection factory."""

    def _factory() -> Connection:
        connection = Connection(
            server,
            user=user,
            password=password,
            authentication=NTLM,
            auto_bind=True,
        )
        logging.info(f"{context_label} LDAP bind established: {format_ldap_error(connection)}")
        return connection

    return _factory


def format_ldap_error(conn) -> str:
    """Format key LDAP connection/result diagnostics as one line."""
    if conn is None:
        return "connection=None"
    parts: list[str] = []
    result = getattr(conn, "result", None) or {}
    if result:
        code = result.get("result")
        desc = result.get("description")
        message = result.get("message")
        result_type = result.get("type")
        dn = result.get("dn")
        referrals = result.get("referrals")
        if code is not None or desc:
            parts.append(f"result={code} description={desc}")
        if message:
            parts.append(f"message={message}")
        if result_type:
            parts.append(f"type={result_type}")
        if dn:
            parts.append(f"dn={dn}")
        if referrals:
            parts.append(f"referrals={referrals}")
    last_error = getattr(conn, "last_error", None)
    if last_error:
        parts.append(f"last_error={last_error}")
    bound = getattr(conn, "bound", None)
    if bound is not None:
        parts.append(f"bound={bound}")
    closed = getattr(conn, "closed", None)
    if closed is not None:
        parts.append(f"closed={closed}")
    server = getattr(conn, "server", None)
    if server is not None:
        host = getattr(server, "host", None)
        port = getattr(server, "port", None)
        ssl_enabled = getattr(server, "ssl", None)
        parts.append(f"server={host}:{port} ssl={ssl_enabled}")
    return "; ".join(parts) if parts else "no ldap error details"


def is_bind_lost_result(result: dict) -> bool:
    """Detect AD bind-lost result payload."""
    payload = result or {}
    message = str(payload.get("message") or "").lower()
    return payload.get("result") == 1 and "successful bind must be completed" in message


def safe_unbind(conn, context: str) -> None:
    """Unbind LDAP connection without raising."""
    if not conn:
        return
    try:
        conn.unbind()
    except Exception as exc:
        logging.warning(f"LDAP unbind failed during {context}: {exc}")


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


def build_update_attributes(
    emp: dict,
    conn,
    ldap_search_base: str,
    current_ad_department: str = "",
    manager_department: str = "",
) -> dict:
    """Map ADP worker payload into AD attributes for update flow."""
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
    return desired


def normalize_department_for_compare(value: str) -> str:
    """Normalize department values only for diff comparisons."""
    return normalize_department_name(value)


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
            elif current_str == desired_str:
                continue
        else:
            if current == desired_val:
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

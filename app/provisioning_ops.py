"""Provisioning operations split from the timer orchestration wrapper."""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Optional

from ldap3 import MODIFY_REPLACE, SUBTREE
from ldap3.utils.dn import escape_rdn

from .adp_client import (
    extract_assignment_field,
    extract_business_title,
    extract_company,
    extract_employee_id,
    extract_manager_id,
    extract_state_from_work,
    extract_work_address_field,
    generate_password,
    get_display_name,
    get_hire_date,
    get_legal_first_last,
    get_user_account_control,
    parse_datetime,
    sanitize_string_for_sam,
)
from .config import env_truthy
from .constants import (
    ATTR_CN,
    ATTR_DISPLAY_NAME,
    ATTR_EMPLOYEE_ID,
    ATTR_GIVEN_NAME,
    ATTR_MAIL,
    ATTR_SAM_ACCOUNT_NAME,
    ATTR_SN,
    ATTR_USER_PRINCIPAL_NAME,
)
from .department_resolution import resolve_local_ac_department
from .ldap_client import (
    apply_ldap_modifications,
    collect_identifier_conflicts,
    dn_exists_in_create_scope,
    format_ldap_error,
    get_department_by_dn,
    get_manager_dn,
    is_bind_lost_result,
    log_cn_conflict_inventory,
    safe_unbind,
)
from .reporting import inc_stat


def _is_recent_hire(emp: dict, cutoff_dt: datetime) -> bool:
    hire_date = get_hire_date(emp)
    if not hire_date:
        return False
    parsed = parse_datetime(hire_date, "hireDate")
    if not parsed:
        return False
    return parsed >= cutoff_dt


def provision_user_in_ad(
    user_data: dict,
    conn,
    ldap_search_base: str,
    ldap_create_base: str,
    conn_factory=None,
    summary_stats: Optional[dict[str, int]] = None,
    *,
    max_retry_attempts: int = 15,
    cn_collision_threshold: int = 5,
):
    """Create/enable AD account for one ADP worker with collision handling."""
    from .adp_client import build_ad_country_attributes

    country_attrs = build_ad_country_attributes(extract_work_address_field(user_data, "countryCode"))
    country_alpha2 = country_attrs.get("c") or ""
    if not country_alpha2 or country_alpha2 == "MX":
        inc_stat(summary_stats, "skipped_country")
        logging.info(f"Skipping provisioning for country code '{country_alpha2}'")
        return conn

    person = user_data.get("person", {})
    legal_first, legal_last = get_legal_first_last(person)
    display_name = get_display_name(person)
    if not legal_first or not legal_last:
        inc_stat(summary_stats, "skipped_missing_required_fields")
        logging.error("Skipping user with missing required legal name fields for AD givenName/sn")
        return conn
    if not display_name:
        inc_stat(summary_stats, "skipped_missing_required_fields")
        logging.error("Skipping user with missing display name (preferred and legal both unavailable)")
        return conn

    full_name = display_name
    emp_id = extract_employee_id(user_data)
    if not emp_id:
        inc_stat(summary_stats, "skipped_missing_required_fields")
        logging.warning(
            "Skipping user with missing employee ID: display='%s' legal='%s %s'",
            display_name or "<none>",
            legal_first or "",
            legal_last or "",
        )
        return conn
    hire_date = get_hire_date(user_data) or "<no hire date>"

    def find_existing_user_dn(connection, employee_id: str) -> Optional[str]:
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

    existing_dn = find_existing_user_dn(conn, emp_id)
    if existing_dn:
        inc_stat(summary_stats, "exists")
        logging.info(f"User already exists: {emp_id} at {existing_dn}")
        manager_dn = get_manager_dn(
            conn,
            ldap_search_base,
            extract_manager_id(user_data),
            subject_employee_id=emp_id,
            summary_stats=summary_stats,
        )
        if manager_dn:
            conn = apply_ldap_modifications(
                conn,
                existing_dn,
                {"manager": [(MODIFY_REPLACE, [manager_dn])]},
                conn_factory,
            )
        return conn

    base_sam_raw = sanitize_string_for_sam(legal_first[0].lower() + legal_last.lower())
    if not base_sam_raw:
        inc_stat(summary_stats, "skipped_missing_required_fields")
        logging.warning(
            "Skipping user with invalid sAMAccountName seed: employeeID=%s display='%s' legal='%s %s'",
            emp_id,
            display_name or "<none>",
            legal_first or "",
            legal_last or "",
        )
        return conn
    base_alias = sanitize_string_for_sam(legal_first.lower()) + sanitize_string_for_sam(legal_last.lower())
    if not base_alias:
        base_alias = base_sam_raw
    upn_suffix = os.getenv("UPN_SUFFIX", "cfsbrands.com").strip().lstrip("@")

    def build_sam(suffix: str) -> str:
        if not suffix:
            return base_sam_raw[:10]
        max_base_len = max(0, 10 - len(suffix))
        return f"{base_sam_raw[:max_base_len]}{suffix}"

    manager_dn = get_manager_dn(
        conn,
        ldap_search_base,
        extract_manager_id(user_data),
        subject_employee_id=emp_id,
        summary_stats=summary_stats,
    )
    resolved_manager_department = ""
    if manager_dn:
        manager_dept_from_dn = get_department_by_dn(conn, manager_dn)
        if manager_dept_from_dn:
            resolved_manager_department = manager_dept_from_dn

    resolution = resolve_local_ac_department(user_data, manager_department=resolved_manager_department)
    resolved_department = resolution.get("proposedDepartmentV2")
    if env_truthy("LOG_DEPARTMENT_MAPPING", False):
        logging.info(
            "Department resolution for %s (create): proposed=%s, evidence=%s, confidence=%s, block=%s",
            emp_id,
            resolved_department or "<none>",
            resolution.get("evidenceUsed") or "<none>",
            resolution.get("confidence") or "<none>",
            resolution.get("blockReason") or "<none>",
        )

    base_attrs = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        ATTR_GIVEN_NAME: legal_first,
        ATTR_SN: legal_last,
        ATTR_EMPLOYEE_ID: emp_id,
        "title": extract_business_title(user_data) or extract_assignment_field(user_data, "jobTitle"),
        "department": resolved_department,
        "l": extract_work_address_field(user_data, "cityName"),
        "postalCode": extract_work_address_field(user_data, "postalCode"),
        "st": extract_state_from_work(user_data),
        "streetAddress": extract_work_address_field(user_data, "lineOne"),
        "co": country_attrs["co"],
        "c": country_attrs["c"],
        "countryCode": country_attrs["countryCode"],
        "company": extract_company(user_data),
        "manager": manager_dn,
        "userAccountControl": get_user_account_control(user_data),
    }
    mandatory = {
        "objectClass",
        ATTR_CN,
        ATTR_GIVEN_NAME,
        ATTR_SN,
        ATTR_DISPLAY_NAME,
        ATTR_USER_PRINCIPAL_NAME,
        ATTR_MAIL,
        ATTR_SAM_ACCOUNT_NAME,
        ATTR_EMPLOYEE_ID,
        "userAccountControl",
    }

    def numeric_suffix(index: int) -> str:
        return "" if index == 0 else str(index)

    def classify_account_id_conflicts(message: str) -> set[str]:
        lowered = (message or "").lower()
        conflicts = set()
        if "samaccountname" in lowered:
            conflicts.add("sam")
        if "userprincipalname" in lowered or "mailnickname" in lowered or "proxyaddresses" in lowered:
            conflicts.add("alias")
        return conflicts

    dn = None
    retry_count = 0
    cn_index = 0
    sam_index = 0
    alias_index = 0
    cn_collision_count = 0
    identifier_collision_count = 0
    employee_cn_token = sanitize_string_for_sam(emp_id) or emp_id.strip()
    cn_root = f"{full_name} {employee_cn_token}".strip()
    cn_diagnostics_logged = False
    add_failure_recorded = False

    def mark_add_failure() -> None:
        nonlocal add_failure_recorded
        if add_failure_recorded:
            return
        inc_stat(summary_stats, "add_failures")
        add_failure_recorded = True

    while retry_count < max_retry_attempts:
        if hasattr(conn, "bound") and not conn.bound:
            try:
                if not conn.bind():
                    mark_add_failure()
                    logging.error(f"Bind failed before add attempt: {format_ldap_error(conn)}")
                    return conn
            except Exception as exc:
                mark_add_failure()
                logging.error(f"Rebind failed before add attempt: {exc}")
                return conn

        cn = cn_root if cn_index == 0 else f"{cn_root} {numeric_suffix(cn_index)}"
        sam = build_sam(numeric_suffix(sam_index))
        if not sam:
            mark_add_failure()
            logging.warning(
                "Skipping user with invalid sAMAccountName after retries: employeeID=%s display='%s'",
                emp_id,
                display_name or "<none>",
            )
            return conn
        alias = base_alias if alias_index == 0 else f"{base_alias}{numeric_suffix(alias_index)}"
        attrs = dict(base_attrs)
        attrs.update(
            {
                ATTR_CN: cn,
                ATTR_DISPLAY_NAME: full_name,
                ATTR_USER_PRINCIPAL_NAME: f"{alias}@{upn_suffix}",
                ATTR_MAIL: f"{alias}@cfsbrands.com",
                ATTR_SAM_ACCOUNT_NAME: sam,
            }
        )
        final_attrs = {k: v for k, v in attrs.items() if v or k in mandatory}
        dn_candidate = f"CN={escape_rdn(cn)},{ldap_create_base}"
        try:
            if conn.add(dn_candidate, attributes=final_attrs):
                dn = dn_candidate
                break
        except Exception as exc:
            logging.error(f"Add raised exception for {dn_candidate}: {exc}")
            if conn_factory:
                try:
                    safe_unbind(conn, f"add exception for {dn_candidate}")
                    conn = conn_factory()
                    retry_count += 1
                    continue
                except Exception as reconnect_error:
                    mark_add_failure()
                    logging.error(
                        f"Reconnect failed after add exception for {dn_candidate}: {reconnect_error}"
                    )
            mark_add_failure()
            return conn

        result = conn.result or {}
        message = str(result.get("message") or "")
        if result.get("result") == 68:
            retry_count += 1
            logging.warning(
                f"[WARN] Add returned result=68 for {dn_candidate} "
                f"(employeeID={emp_id}); result_payload={result}"
            )
            existing_dn = find_existing_user_dn(conn, emp_id)
            if existing_dn:
                logging.info(
                    f"[INFO] Existing user discovered during result=68 handling; "
                    f"employeeID={emp_id} dn={existing_dn}"
                )
                manager_dn = get_manager_dn(
                    conn,
                    ldap_search_base,
                    extract_manager_id(user_data),
                    subject_employee_id=emp_id,
                    summary_stats=summary_stats,
                )
                if manager_dn:
                    conn.modify(existing_dn, {"manager": [(MODIFY_REPLACE, [manager_dn])]})
                return conn
            dn_exists = dn_exists_in_create_scope(conn, dn_candidate)
            identifier_conflicts = collect_identifier_conflicts(
                conn,
                ldap_search_base,
                employee_id=emp_id,
                sam_account_name=sam,
                user_principal_name=f"{alias}@{upn_suffix}",
                mail=f"{alias}@cfsbrands.com",
            )
            has_identifier_conflicts = any(identifier_conflicts.values())
            if dn_exists:
                cn_collision_count += 1
                cn_index += 1
                if not cn_diagnostics_logged or cn_collision_count % cn_collision_threshold == 0:
                    log_cn_conflict_inventory(conn, ldap_create_base, full_name, emp_id)
                    cn_diagnostics_logged = True
                logging.warning(
                    f"Add failed for {dn_candidate} (result=68 with visible DN conflict); "
                    f"retrying with CN suffix {numeric_suffix(cn_index)} (employeeID={emp_id})"
                )
                continue
            if has_identifier_conflicts:
                identifier_collision_count += 1
                if identifier_conflicts["sam"]:
                    sam_index += 1
                    logging.warning(
                        f"[WARN] result=68 identifier conflict on sAMAccountName for employeeID={emp_id}: "
                        + " | ".join(identifier_conflicts["sam"])
                    )
                if identifier_conflicts["upn"] or identifier_conflicts["mail"]:
                    alias_index += 1
                    joined = identifier_conflicts["upn"] + identifier_conflicts["mail"]
                    logging.warning(
                        f"[WARN] result=68 identifier conflict on UPN/mail for employeeID={emp_id}: "
                        + " | ".join(joined)
                    )
                continue
            logging.error(
                f"[ERROR] result=68 for employeeID {emp_id} without visible CN/DN or identifier conflicts. "
                f"Failing fast to avoid retry storm. Action: investigate hidden/deleted objects and "
                f"ACL visibility "
                f"under '{ldap_create_base}'."
            )
            log_cn_conflict_inventory(conn, ldap_create_base, full_name, emp_id)
            mark_add_failure()
            return conn

        if result.get("result") == 19:
            conflict_fields = classify_account_id_conflicts(message)
            if conflict_fields:
                logging.warning(
                    f"Add failed for {dn_candidate} "
                    f"(constraintViolation on {', '.join(sorted(conflict_fields))}); "
                    "refreshing connection and retrying only conflicting identifiers"
                )
                logging.warning(f"Constraint violation details: {format_ldap_error(conn)}")
                if conn_factory:
                    try:
                        safe_unbind(conn, f"account-id constraint for {dn_candidate}")
                        conn = conn_factory()
                        existing_dn = find_existing_user_dn(conn, emp_id)
                        if existing_dn:
                            logging.info(
                                f"User found after reconnect: {emp_id} at {existing_dn}; skipping add"
                            )
                            manager_dn = get_manager_dn(
                                conn,
                                ldap_search_base,
                                extract_manager_id(user_data),
                                subject_employee_id=emp_id,
                                summary_stats=summary_stats,
                            )
                            if manager_dn:
                                conn.modify(existing_dn, {"manager": [(MODIFY_REPLACE, [manager_dn])]})
                            return conn
                    except Exception as exc:
                        mark_add_failure()
                        logging.error(
                            f"Reconnect failed after account-id constraint for {dn_candidate}: {exc}"
                        )
                        return conn
                if "sam" in conflict_fields:
                    sam_index += 1
                if "alias" in conflict_fields:
                    alias_index += 1
                retry_count += 1
                continue
            mark_add_failure()
            logging.error(f"Add failed for {dn_candidate} (constraintViolation): {conn.result}")
            return conn

        if is_bind_lost_result(result):
            logging.warning(f"Bind lost details: {format_ldap_error(conn)}")
            if conn_factory:
                logging.warning(
                    f"Add failed for {dn_candidate} (bind lost); reconnecting and skipping current user"
                )
                try:
                    safe_unbind(conn, f"bind-lost add for {dn_candidate}")
                    conn = conn_factory()
                    existing_dn = find_existing_user_dn(conn, emp_id)
                    if existing_dn:
                        logging.info(f"User found after bind-loss reconnect: {emp_id} at {existing_dn}")
                        manager_dn = get_manager_dn(
                            conn,
                            ldap_search_base,
                            extract_manager_id(user_data),
                            subject_employee_id=emp_id,
                            summary_stats=summary_stats,
                        )
                        if manager_dn:
                            conn.modify(existing_dn, {"manager": [(MODIFY_REPLACE, [manager_dn])]})
                    else:
                        logging.error(
                            f"Skipping {emp_id} after bind-lost add; fresh connection ready for next user "
                            f"({format_ldap_error(conn)})"
                        )
                    return conn
                except Exception as exc:
                    mark_add_failure()
                    logging.error(f"Reconnect failed after bind-lost error for {dn_candidate}: {exc}")
                    return conn
            mark_add_failure()
            logging.error(f"Add failed for {dn_candidate}: bind lost and no conn_factory available")
            return conn

        mark_add_failure()
        logging.error(f"Add failed for {dn_candidate}: {conn.result}")
        return conn

    if not dn:
        mark_add_failure()
        logging.error(
            f"Add failed for employeeID {emp_id}: exceeded unique add retries "
            f"(cn_root='{cn_root}', cn_index={cn_index}, sam_index={sam_index}, alias_index={alias_index}, "
            f"cn_collision_count={cn_collision_count}, "
            f"identifier_collision_count={identifier_collision_count}). "
            f"Action: inspect existing AD objects under '{ldap_create_base}' "
            f"for conflicting CN/UPN/mail values."
        )
        return conn

    inc_stat(summary_stats, "created")
    logging.info(f"User created: {dn} (hireDate={hire_date})")
    password = generate_password()
    try:
        conn.extend.microsoft.modify_password(dn, password)
        conn.modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
        conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [512])]})
        logging.info(f"Account enabled and password set for {dn}")
    except Exception as exc:
        inc_stat(summary_stats, "password_failures")
        logging.error(f"Password or enable failed for {dn}: {exc}")
    return conn

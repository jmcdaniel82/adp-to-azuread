"""Existing-user update orchestration (dry-run default)."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from ldap3 import SUBTREE

from .adp_client import (
    dedupe_workers_by_employee_id,
    extract_employee_id,
    extract_last_updated,
    extract_work_address_field,
    get_adp_employees,
    get_adp_token,
    is_terminated_employee,
    log_potential_duplicate_profiles,
)
from .config import get_ldap_settings, get_update_job_settings, validate_ldap_settings
from .constants import AD_UPDATE_SEARCH_ATTRIBUTES
from .ldap_client import (
    apply_ldap_modifications,
    build_update_attributes,
    create_ldap_server,
    diff_update_attributes,
    entry_attr_value,
    get_department_by_dn,
    is_bind_lost_result,
    log_ldap_target_details,
    make_conn_factory,
    safe_unbind,
)


def select_update_candidates(
    all_employees: list[dict],
    settings,
    *,
    context: str,
    now: datetime | None = None,
) -> tuple[list[dict], dict[str, Any]]:
    """Apply the exact scheduled-update candidate filters used by the job."""
    employees = dedupe_workers_by_employee_id(all_employees, context)
    log_potential_duplicate_profiles(employees, context)

    candidates: list[dict] = []
    missing_last_updated = 0
    selected_missing_last_updated = 0
    cutoff_iso = ""
    current_time = now or datetime.now(timezone.utc)
    if settings.lookback_days > 0:
        cutoff = current_time - timedelta(days=settings.lookback_days)
        cutoff_iso = cutoff.date().isoformat()
        for emp in employees:
            updated_at = extract_last_updated(emp)
            if updated_at and updated_at >= cutoff:
                candidates.append(emp)
            elif not updated_at:
                missing_last_updated += 1
                if settings.include_missing_last_updated:
                    selected_missing_last_updated += 1
                    candidates.append(emp)
    else:
        candidates = list(employees)

    country_filtered_candidates = []
    skipped_country = 0
    for emp in candidates:
        country_alpha2 = (extract_work_address_field(emp, "countryCode") or "").strip().upper()
        if country_alpha2 in {"US", "CA"}:
            country_filtered_candidates.append(emp)
        else:
            skipped_country += 1

    return country_filtered_candidates, {
        "deduped_count": len(employees),
        "missing_last_updated": missing_last_updated,
        "selected_missing_last_updated": selected_missing_last_updated,
        "skipped_country": skipped_country,
        "cutoff_iso": cutoff_iso,
    }


def run_scheduled_update_existing_users(mytimer) -> None:
    """Timer-trigger orchestration for scheduled_update_existing_users."""
    settings = get_update_job_settings()
    logging.info(
        f"[INFO] scheduled_update_existing_users triggered "
        f"(dry_run={settings.dry_run}, lookback_days={settings.lookback_days})"
    )

    token = get_adp_token()
    if not token:
        logging.error("[ERROR] Failed to retrieve ADP token for update")
        return

    all_employees = get_adp_employees(token)
    if all_employees is None:
        logging.error("[ERROR] get_adp_employees returned None for update")
        return
    candidates, candidate_stats = select_update_candidates(
        all_employees,
        settings,
        context="scheduled_update_existing_users",
    )

    if settings.lookback_days > 0:
        logging.info(
            f"[INFO] {len(candidates)} ADP employees considered for update since "
            f"{candidate_stats['cutoff_iso']} "
            f"(missing lastUpdated={candidate_stats['missing_last_updated']})"
        )
    else:
        logging.info(f"[INFO] {len(candidates)} ADP employees considered for update (no lookback filter)")

    if candidate_stats["skipped_country"]:
        logging.info(
            f"[INFO] Skipping {candidate_stats['skipped_country']} ADP employees "
            f"for update due to unsupported country "
            f"(allowed=US,CA)"
        )

    if not candidates:
        logging.info("[INFO] Nothing to update; exiting scheduled_update_existing_users")
        return

    missing_ldap = validate_ldap_settings(require_create_base=False)
    if missing_ldap:
        logging.error(f"Missing LDAP configuration for update: {', '.join(missing_ldap)}")
        return
    ldap_settings = get_ldap_settings(require_create_base=False)
    logging.info(f"Using CA bundle at '{ldap_settings.ca_bundle_path}' for LDAP update")
    if not os.path.isfile(ldap_settings.ca_bundle_path):
        logging.error(f"CA bundle not found at {ldap_settings.ca_bundle_path}")
        return

    log_ldap_target_details("Update", ldap_settings.server, ldap_settings.ca_bundle_path)
    server = create_ldap_server(ldap_settings.server, ldap_settings.ca_bundle_path)
    conn_factory = make_conn_factory(server, ldap_settings.user, ldap_settings.password, "Update")

    try:
        conn = conn_factory()
    except Exception as exc:
        logging.error(f"[ERROR] Failed to connect to LDAP server for update: {exc}")
        return

    logging.info("[INFO] LDAP connection opened for update")
    updated_users = 0
    total_changes = 0
    missing_in_ad = 0
    for emp in candidates:
        emp_id = extract_employee_id(emp)
        if not emp_id:
            continue
        try:
            found = conn.search(
                ldap_settings.search_base,
                f"(employeeID={emp_id})",
                SUBTREE,
                attributes=AD_UPDATE_SEARCH_ATTRIBUTES,
            )
        except Exception as exc:
            logging.error(f"LDAP search exception for {emp_id}: {exc}")
            try:
                safe_unbind(conn, f"update search exception for {emp_id}")
                conn = conn_factory()
            except Exception as reconnect_error:
                logging.error(f"Reconnect failed after search exception for {emp_id}: {reconnect_error}")
            continue
        if not found and is_bind_lost_result(getattr(conn, "result", None) or {}):
            logging.warning(f"Bind lost during update search for {emp_id}; reconnecting")
            try:
                safe_unbind(conn, f"update search bind-loss for {emp_id}")
                conn = conn_factory()
            except Exception as reconnect_error:
                logging.error(f"Reconnect failed after bind-loss search for {emp_id}: {reconnect_error}")
                break
            continue
        if not conn.entries:
            missing_in_ad += 1
            continue
        entry = conn.entries[0]
        dn = entry_attr_value(entry, "distinguishedName") or "<unknown DN>"
        if is_terminated_employee(emp):
            desired = {"userAccountControl": 514}
        else:
            current_department = (entry_attr_value(entry, "department") or "").strip()
            current_manager_dn = (entry_attr_value(entry, "manager") or "").strip()
            current_manager_department = (
                get_department_by_dn(conn, current_manager_dn) if current_manager_dn else ""
            )
            desired = build_update_attributes(
                emp,
                conn,
                ldap_settings.search_base,
                current_ad_department=current_department,
                manager_department=current_manager_department,
            )
        changes = diff_update_attributes(entry, desired, context=f"{emp_id} at {dn}")
        if not changes:
            if settings.log_no_changes:
                logging.info(f"[INFO] No updates needed for {emp_id} at {dn}")
            continue
        updated_users += 1
        for attr, ops in changes.items():
            desired_val = ops[0][1][0] if ops and ops[0][1] else None
            current_val = entry_attr_value(entry, attr)
            if settings.dry_run:
                logging.info(f"[INFO] DRY RUN update {emp_id} {attr}: '{current_val}' -> '{desired_val}'")
            else:
                logging.info(f"Updating {emp_id} {attr}: '{current_val}' -> '{desired_val}'")
        total_changes += len(changes)
        if not settings.dry_run:
            conn = apply_ldap_modifications(conn, dn, changes, conn_factory)
            if not conn:
                logging.error("LDAP connection unavailable; aborting scheduled_update_existing_users")
                break

    safe_unbind(conn, "scheduled_update_existing_users completion")
    logging.info(
        f"[INFO] LDAP connection closed - scheduled_update_existing_users complete "
        f"(users_with_changes={updated_users}, total_changes={total_changes}, missing_in_ad={missing_in_ad})"
    )

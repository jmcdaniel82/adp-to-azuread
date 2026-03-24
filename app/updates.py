"""Existing-user update orchestration (dry-run default)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .adp_client import (
    dedupe_workers_by_employee_id,
    extract_last_updated,
    extract_work_address_field,
    get_adp_employees,
    get_adp_token,
    is_terminated_employee,
    log_potential_duplicate_profiles,
)
from .config import get_ldap_settings, get_update_job_settings, validate_ldap_settings
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
from .services.defaults import DefaultDirectoryGateway, DefaultWorkerProvider
from .services.update_service import UpdateOrchestrator


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
    build_update_orchestrator().run(mytimer)


def build_worker_provider() -> DefaultWorkerProvider:
    """Build the default ADP-backed worker provider for update sync."""
    return DefaultWorkerProvider(
        get_token=get_adp_token,
        get_workers=get_adp_employees,
        dedupe_workers=dedupe_workers_by_employee_id,
        log_duplicate_profiles=log_potential_duplicate_profiles,
    )


def build_directory_gateway() -> DefaultDirectoryGateway:
    """Build the default LDAP-backed directory gateway for update sync."""
    return DefaultDirectoryGateway(
        validate_settings=validate_ldap_settings,
        get_settings=get_ldap_settings,
        log_target_details=log_ldap_target_details,
        create_server=create_ldap_server,
        make_conn_factory=make_conn_factory,
        safe_unbind=safe_unbind,
    )


def build_update_orchestrator() -> UpdateOrchestrator:
    """Build the update orchestrator with explicit service dependencies."""
    return UpdateOrchestrator(
        worker_provider=build_worker_provider(),
        directory_gateway=build_directory_gateway(),
        select_update_candidates=select_update_candidates,
        is_terminated_employee=is_terminated_employee,
        build_update_attributes=build_update_attributes,
        diff_update_attributes=diff_update_attributes,
        entry_attr_value=entry_attr_value,
        get_department_by_dn=get_department_by_dn,
        is_bind_lost_result=is_bind_lost_result,
        apply_ldap_modifications=apply_ldap_modifications,
        settings_getter=get_update_job_settings,
    )

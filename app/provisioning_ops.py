"""Provisioning operations split from the timer orchestration wrapper."""

from __future__ import annotations

import logging
from typing import Callable, Optional

from .config import env_truthy
from .department.resolver import resolve_local_ac_department
from .ldap import (
    collect_identifier_conflicts,
    dn_exists_in_create_scope,
    format_ldap_error,
    is_bind_lost_result,
    log_cn_conflict_inventory,
    safe_unbind,
)
from .provisioning_add import create_user_with_retries
from .provisioning_directory import (
    find_existing_user_dn,
    resolve_manager_context,
    update_existing_user_manager,
)
from .provisioning_filters import is_recent_hire
from .provisioning_finalize import ProvisioningIncompleteAccount, finalize_created_user_account
from .provisioning_identity import (
    build_base_attributes,
    build_identifier_seeds,
    build_provisioning_profile,
)
from .reporting import inc_stat

_is_recent_hire = is_recent_hire


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
    run_id: str | None = None,
    report_incomplete_account: Callable[[ProvisioningIncompleteAccount], None] | None = None,
):
    """Create or reconcile one AD account for an ADP worker."""
    profile = build_provisioning_profile(user_data, summary_stats=summary_stats)
    if not profile:
        return conn

    existing_dn = find_existing_user_dn(conn, ldap_search_base, profile.emp_id)
    if existing_dn:
        inc_stat(summary_stats, "exists")
        logging.info(f"User already exists: {profile.emp_id} at {existing_dn}")
        return update_existing_user_manager(
            conn,
            existing_dn,
            ldap_search_base,
            user_data,
            profile.emp_id,
            conn_factory,
            summary_stats,
        )

    identifiers = build_identifier_seeds(profile, summary_stats=summary_stats)
    if not identifiers:
        return conn

    manager_context = resolve_manager_context(
        conn,
        ldap_search_base,
        user_data,
        profile.emp_id,
        summary_stats=summary_stats,
    )
    resolution = resolve_local_ac_department(
        user_data,
        manager_department=manager_context.manager_department,
    )
    resolved_department = resolution.get("proposedDepartmentV2")
    if env_truthy("LOG_DEPARTMENT_MAPPING", False):
        logging.info(
            "Department resolution for %s (create): proposed=%s, evidence=%s, confidence=%s, block=%s",
            profile.emp_id,
            resolved_department or "<none>",
            resolution.get("evidenceUsed") or "<none>",
            resolution.get("confidence") or "<none>",
            resolution.get("blockReason") or "<none>",
        )

    base_attrs = build_base_attributes(
        user_data,
        profile,
        manager_context.manager_dn,
        resolved_department,
    )
    create_result = create_user_with_retries(
        conn=conn,
        user_data=user_data,
        profile=profile,
        identifiers=identifiers,
        base_attrs=base_attrs,
        ldap_search_base=ldap_search_base,
        ldap_create_base=ldap_create_base,
        conn_factory=conn_factory,
        summary_stats=summary_stats,
        max_retry_attempts=max_retry_attempts,
        cn_collision_threshold=cn_collision_threshold,
        find_existing_user_dn=find_existing_user_dn,
        update_existing_user_manager=update_existing_user_manager,
        collect_identifier_conflicts=collect_identifier_conflicts,
        dn_exists_in_create_scope=dn_exists_in_create_scope,
        log_cn_conflict_inventory=log_cn_conflict_inventory,
        safe_unbind=safe_unbind,
        format_ldap_error=format_ldap_error,
        is_bind_lost_result=is_bind_lost_result,
        run_id=run_id,
    )
    conn = create_result.conn
    if not create_result.dn:
        return conn

    inc_stat(summary_stats, "created")
    logging.info(f"User created: {create_result.dn} (hireDate={profile.hire_date})")
    finalize_result = finalize_created_user_account(
        conn,
        create_result.dn,
        employee_id=profile.emp_id,
        summary_stats=summary_stats,
    )
    if finalize_result.incomplete_account and report_incomplete_account:
        report_incomplete_account(finalize_result.incomplete_account)
    return finalize_result.conn

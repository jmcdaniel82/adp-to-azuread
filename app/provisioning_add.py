"""LDAP add retry helpers for provisioning."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .ldap.scope import ensure_write_scope
from .provisioning_identity import (
    ProvisioningIdentifiers,
    ProvisioningProfile,
    build_add_request,
    classify_account_id_conflicts,
    numeric_suffix,
)
from .reporting import inc_stat
from .telemetry import StructuredLogTelemetrySink


@dataclass
class AddRetryState:
    """Mutable retry counters for one provisioning attempt."""

    retry_count: int = 0
    cn_index: int = 0
    sam_index: int = 0
    alias_index: int = 0
    cn_collision_count: int = 0
    identifier_collision_count: int = 0
    cn_diagnostics_logged: bool = False
    add_failure_recorded: bool = False

    def mark_add_failure(self, summary_stats: dict[str, int] | None) -> None:
        """Record a single add failure for the current worker."""
        if self.add_failure_recorded:
            return
        inc_stat(summary_stats, "add_failures")
        self.add_failure_recorded = True


@dataclass(frozen=True)
class ProvisioningCreateResult:
    """Result of the LDAP add retry loop."""

    conn: Any
    dn: str | None


def _emit_directory_reconnect(
    *,
    run_id: str | None,
    job: str,
    employee_id: str,
    reason: str,
) -> None:
    StructuredLogTelemetrySink().emit(
        "directory_reconnect",
        {
            "job": job,
            "run_id": run_id or "",
            "employee_id": employee_id,
            "reason": reason,
        },
        level="warning",
    )


def create_user_with_retries(
    *,
    conn: Any,
    user_data: dict,
    profile: ProvisioningProfile,
    identifiers: ProvisioningIdentifiers,
    base_attrs: dict[str, Any],
    ldap_search_base: str,
    ldap_create_base: str,
    conn_factory=None,
    summary_stats: Optional[dict[str, int]] = None,
    max_retry_attempts: int = 15,
    cn_collision_threshold: int = 5,
    find_existing_user_dn: Callable[[Any, str, str], str | None],
    update_existing_user_manager: Callable[..., Any],
    collect_identifier_conflicts: Callable[..., dict[str, list[str]]],
    dn_exists_in_create_scope: Callable[[Any, str], bool],
    log_cn_conflict_inventory: Callable[[Any, str, str, str], None],
    safe_unbind: Callable[[Any, str], None],
    format_ldap_error: Callable[[Any], str],
    is_bind_lost_result: Callable[[dict], bool],
    allowed_write_bases: tuple[str, ...] = (),
    run_id: str | None = None,
    job_name: str = "scheduled_provision_new_hires",
) -> ProvisioningCreateResult:
    """Create one AD user with collision-aware retries and reconnect handling."""
    state = AddRetryState()

    while state.retry_count < max_retry_attempts:
        if hasattr(conn, "bound") and not conn.bound:
            try:
                if not conn.bind():
                    state.mark_add_failure(summary_stats)
                    logging.error(f"Bind failed before add attempt: {format_ldap_error(conn)}")
                    return ProvisioningCreateResult(conn=conn, dn=None)
            except Exception as exc:
                state.mark_add_failure(summary_stats)
                logging.error(f"Rebind failed before add attempt: {exc}")
                return ProvisioningCreateResult(conn=conn, dn=None)

        request = build_add_request(
            base_attrs,
            profile,
            identifiers,
            ldap_create_base,
            cn_index=state.cn_index,
            sam_index=state.sam_index,
            alias_index=state.alias_index,
        )
        if not request.sam:
            state.mark_add_failure(summary_stats)
            logging.warning(
                "Skipping user with invalid sAMAccountName after retries: employeeID=%s display='%s'",
                profile.emp_id,
                profile.display_name or "<none>",
            )
            return ProvisioningCreateResult(conn=conn, dn=None)
        try:
            ensure_write_scope(request.dn, allowed_write_bases, operation="add")
        except PermissionError as exc:
            state.mark_add_failure(summary_stats)
            logging.error(str(exc))
            return ProvisioningCreateResult(conn=conn, dn=None)

        try:
            if conn.add(request.dn, attributes=request.attrs):
                return ProvisioningCreateResult(conn=conn, dn=request.dn)
        except Exception as exc:
            logging.error(f"Add raised exception for {request.dn}: {exc}")
            if conn_factory:
                try:
                    safe_unbind(conn, f"add exception for {request.dn}")
                    conn = conn_factory()
                    inc_stat(summary_stats, "ldap_reconnects")
                    _emit_directory_reconnect(
                        run_id=run_id,
                        job=job_name,
                        employee_id=profile.emp_id,
                        reason="add_exception",
                    )
                    state.retry_count += 1
                    continue
                except Exception as reconnect_error:
                    state.mark_add_failure(summary_stats)
                    logging.error(
                        f"Reconnect failed after add exception for {request.dn}: {reconnect_error}"
                    )
            state.mark_add_failure(summary_stats)
            return ProvisioningCreateResult(conn=conn, dn=None)

        result = conn.result or {}
        message = str(result.get("message") or "")
        if result.get("result") == 68:
            state.retry_count += 1
            logging.warning(
                f"[WARN] Add returned result=68 for {request.dn} "
                f"(employeeID={profile.emp_id}); result_payload={result}"
            )
            existing_dn = find_existing_user_dn(conn, ldap_search_base, profile.emp_id)
            if existing_dn:
                logging.info(
                    f"[INFO] Existing user discovered during result=68 handling; "
                    f"employeeID={profile.emp_id} dn={existing_dn}"
                )
                conn = update_existing_user_manager(
                    conn,
                    existing_dn,
                    ldap_search_base,
                    user_data,
                    profile.emp_id,
                    conn_factory,
                    summary_stats,
                )
                return ProvisioningCreateResult(conn=conn, dn=None)

            dn_exists = dn_exists_in_create_scope(conn, request.dn)
            identifier_conflicts = collect_identifier_conflicts(
                conn,
                ldap_search_base,
                employee_id=profile.emp_id,
                sam_account_name=request.sam,
                user_principal_name=f"{request.alias}@{identifiers.upn_suffix}",
                mail=f"{request.alias}@cfsbrands.com",
            )
            has_identifier_conflicts = any(identifier_conflicts.values())
            if dn_exists:
                state.cn_collision_count += 1
                state.cn_index += 1
                if (
                    not state.cn_diagnostics_logged
                    or state.cn_collision_count % cn_collision_threshold == 0
                ):
                    log_cn_conflict_inventory(conn, ldap_create_base, profile.full_name, profile.emp_id)
                    state.cn_diagnostics_logged = True
                logging.warning(
                    f"Add failed for {request.dn} (result=68 with visible DN conflict); "
                    f"retrying with CN suffix {numeric_suffix(state.cn_index)} "
                    f"(employeeID={profile.emp_id})"
                )
                continue

            if has_identifier_conflicts:
                state.identifier_collision_count += 1
                if identifier_conflicts.get("sam"):
                    state.sam_index += 1
                    logging.warning(
                        f"[WARN] result=68 identifier conflict on sAMAccountName for "
                        f"employeeID={profile.emp_id}: "
                        + " | ".join(identifier_conflicts["sam"])
                    )
                if identifier_conflicts.get("upn") or identifier_conflicts.get("mail"):
                    state.alias_index += 1
                    joined = identifier_conflicts.get("upn", []) + identifier_conflicts.get("mail", [])
                    logging.warning(
                        f"[WARN] result=68 identifier conflict on UPN/mail for "
                        f"employeeID={profile.emp_id}: "
                        + " | ".join(joined)
                    )
                continue

            logging.error(
                f"[ERROR] result=68 for employeeID {profile.emp_id} without visible CN/DN or "
                f"identifier conflicts. Failing fast to avoid retry storm. Action: investigate "
                f"hidden/deleted objects and ACL visibility under '{ldap_create_base}'."
            )
            log_cn_conflict_inventory(conn, ldap_create_base, profile.full_name, profile.emp_id)
            state.mark_add_failure(summary_stats)
            return ProvisioningCreateResult(conn=conn, dn=None)

        if result.get("result") == 19:
            conflict_fields = classify_account_id_conflicts(message)
            if conflict_fields:
                logging.warning(
                    f"Add failed for {request.dn} "
                    f"(constraintViolation on {', '.join(sorted(conflict_fields))}); "
                    "refreshing connection and retrying only conflicting identifiers"
                )
                logging.warning(f"Constraint violation details: {format_ldap_error(conn)}")
                if conn_factory:
                    try:
                        safe_unbind(conn, f"account-id constraint for {request.dn}")
                        conn = conn_factory()
                        inc_stat(summary_stats, "ldap_reconnects")
                        _emit_directory_reconnect(
                            run_id=run_id,
                            job=job_name,
                            employee_id=profile.emp_id,
                            reason="account_id_constraint",
                        )
                        existing_dn = find_existing_user_dn(conn, ldap_search_base, profile.emp_id)
                        if existing_dn:
                            logging.info(
                                f"User found after reconnect: {profile.emp_id} at {existing_dn}; "
                                "skipping add"
                            )
                            conn = update_existing_user_manager(
                                conn,
                                existing_dn,
                                ldap_search_base,
                                user_data,
                                profile.emp_id,
                                conn_factory,
                                summary_stats,
                            )
                            return ProvisioningCreateResult(conn=conn, dn=None)
                    except Exception as exc:
                        state.mark_add_failure(summary_stats)
                        logging.error(
                            f"Reconnect failed after account-id constraint for {request.dn}: {exc}"
                        )
                        return ProvisioningCreateResult(conn=conn, dn=None)
                if "sam" in conflict_fields:
                    state.sam_index += 1
                if "alias" in conflict_fields:
                    state.alias_index += 1
                state.retry_count += 1
                continue
            state.mark_add_failure(summary_stats)
            logging.error(f"Add failed for {request.dn} (constraintViolation): {conn.result}")
            return ProvisioningCreateResult(conn=conn, dn=None)

        if is_bind_lost_result(result):
            logging.warning(f"Bind lost details: {format_ldap_error(conn)}")
            if conn_factory:
                logging.warning(
                    f"Add failed for {request.dn} (bind lost); reconnecting and skipping current user"
                )
                try:
                    safe_unbind(conn, f"bind-lost add for {request.dn}")
                    conn = conn_factory()
                    inc_stat(summary_stats, "ldap_reconnects")
                    _emit_directory_reconnect(
                        run_id=run_id,
                        job=job_name,
                        employee_id=profile.emp_id,
                        reason="bind_lost",
                    )
                    existing_dn = find_existing_user_dn(conn, ldap_search_base, profile.emp_id)
                    if existing_dn:
                        logging.info(
                            f"User found after bind-loss reconnect: {profile.emp_id} at {existing_dn}"
                        )
                        conn = update_existing_user_manager(
                            conn,
                            existing_dn,
                            ldap_search_base,
                            user_data,
                            profile.emp_id,
                            conn_factory,
                            summary_stats,
                        )
                    else:
                        logging.error(
                            f"Skipping {profile.emp_id} after bind-lost add; fresh connection ready "
                            f"for next user ({format_ldap_error(conn)})"
                        )
                    return ProvisioningCreateResult(conn=conn, dn=None)
                except Exception as exc:
                    state.mark_add_failure(summary_stats)
                    logging.error(f"Reconnect failed after bind-lost error for {request.dn}: {exc}")
                    return ProvisioningCreateResult(conn=conn, dn=None)
            state.mark_add_failure(summary_stats)
            logging.error(f"Add failed for {request.dn}: bind lost and no conn_factory available")
            return ProvisioningCreateResult(conn=conn, dn=None)

        state.mark_add_failure(summary_stats)
        logging.error(f"Add failed for {request.dn}: {conn.result}")
        return ProvisioningCreateResult(conn=conn, dn=None)

    state.mark_add_failure(summary_stats)
    logging.error(
        f"Add failed for employeeID {profile.emp_id}: exceeded unique add retries "
        f"(cn_root='{identifiers.cn_root}', cn_index={state.cn_index}, sam_index={state.sam_index}, "
        f"alias_index={state.alias_index}, cn_collision_count={state.cn_collision_count}, "
        f"identifier_collision_count={state.identifier_collision_count}). Action: inspect existing "
        f"AD objects under '{ldap_create_base}' for conflicting CN/UPN/mail values."
    )
    return ProvisioningCreateResult(conn=conn, dn=None)


__all__ = ["AddRetryState", "ProvisioningCreateResult", "create_user_with_retries"]

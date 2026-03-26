"""Update orchestration implemented against explicit service interfaces."""

from __future__ import annotations

import logging
from typing import Callable

from ..adp import extract_employee_id
from ..config import get_update_job_settings
from ..constants import AD_UPDATE_SEARCH_ATTRIBUTES, UPDATE_FIELD_GROUPS, UPDATE_MANAGED_ATTRIBUTES
from ..models import UpdateJobSettings
from ..services.interfaces import DirectoryGateway, TelemetrySink, WorkerProvider
from ..telemetry import new_run_id


def _resolve_effective_enabled_fields(settings: UpdateJobSettings) -> tuple[str, ...] | None:
    """Return the configured update-field allowlist, or None when unrestricted."""
    if not settings.enabled_fields and not settings.enabled_groups:
        return None
    requested_fields = set(settings.enabled_fields)
    for group_name in settings.enabled_groups:
        requested_fields.update(UPDATE_FIELD_GROUPS[group_name])
    return tuple(attr for attr in UPDATE_MANAGED_ATTRIBUTES if attr in requested_fields)


def _filter_desired_update_attributes(
    desired: dict,
    *,
    enabled_fields: tuple[str, ...] | None,
) -> dict:
    """Restrict planned update attributes to the configured allowlist."""
    if enabled_fields is None:
        return dict(desired)
    enabled_field_set = set(enabled_fields)
    return {attr: value for attr, value in desired.items() if attr in enabled_field_set}


class UpdateOrchestrator:
    """Run the scheduled update workflow using explicit gateway dependencies."""

    def __init__(
        self,
        *,
        worker_provider: WorkerProvider,
        directory_gateway: DirectoryGateway,
        select_update_candidates: Callable[..., tuple[list[dict], dict[str, object]]],
        is_terminated_employee: Callable[[dict], bool],
        build_update_attributes: Callable[..., dict],
        diff_update_attributes: Callable[..., dict],
        entry_attr_value: Callable[..., object],
        is_bind_lost_result: Callable[[dict], bool],
        telemetry_sink: TelemetrySink,
        settings_getter: Callable[[], UpdateJobSettings] = get_update_job_settings,
    ) -> None:
        self._worker_provider = worker_provider
        self._directory_gateway = directory_gateway
        self._select_update_candidates = select_update_candidates
        self._is_terminated_employee = is_terminated_employee
        self._build_update_attributes = build_update_attributes
        self._diff_update_attributes = diff_update_attributes
        self._entry_attr_value = entry_attr_value
        self._is_bind_lost_result = is_bind_lost_result
        self._telemetry_sink = telemetry_sink
        self._settings_getter = settings_getter

    def run(self, mytimer) -> None:
        del mytimer
        run_id = new_run_id("scheduled_update_existing_users")
        settings = self._settings_getter()
        effective_enabled_fields = _resolve_effective_enabled_fields(settings)
        logging.info(
            f"[INFO] scheduled_update_existing_users triggered "
            f"(run_id={run_id}, dry_run={settings.dry_run}, lookback_days={settings.lookback_days})"
        )
        if effective_enabled_fields is not None:
            logging.info(
                "[INFO] scheduled_update_existing_users field filter active "
                f"(groups={settings.enabled_groups}, fields={settings.enabled_fields}, "
                f"effective={effective_enabled_fields}, "
                f"always_disable_terminated={settings.always_disable_terminated})"
            )

        fatal_reason = ""
        try:
            all_employees = self._worker_provider.fetch_workers(context="scheduled_update_existing_users")
        except RuntimeError:
            fatal_reason = "adp_fetch_failed"
            self._telemetry_sink.emit(
                "job_run",
                {
                    "job": "scheduled_update_existing_users",
                    "run_id": run_id,
                    "dry_run": settings.dry_run,
                    "worker_count": 0,
                    "created": 0,
                    "changed": 0,
                    "missing_in_ad": 0,
                    "fatal_reason": fatal_reason,
                    "status": "adp_fetch_failed",
                    "ldap_reconnects": 0,
                    "total_changes": 0,
                },
                level="error",
            )
            raise
        candidates, candidate_stats = self._select_update_candidates(
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
            self._telemetry_sink.emit(
                "job_run",
                {
                    "job": "scheduled_update_existing_users",
                    "run_id": run_id,
                    "dry_run": settings.dry_run,
                    "worker_count": 0,
                    "created": 0,
                    "changed": 0,
                    "missing_in_ad": 0,
                    "fatal_reason": "",
                    "status": "no_candidates",
                    "ldap_reconnects": 0,
                    "total_changes": 0,
                },
            )
            return

        try:
            directory = self._directory_gateway.open_directory(
                context="Update",
                require_create_base=False,
            )
        except RuntimeError:
            fatal_reason = "ldap_open_failed"
            self._telemetry_sink.emit(
                "job_run",
                {
                    "job": "scheduled_update_existing_users",
                    "run_id": run_id,
                    "dry_run": settings.dry_run,
                    "worker_count": len(candidates),
                    "created": 0,
                    "changed": 0,
                    "missing_in_ad": 0,
                    "fatal_reason": fatal_reason,
                    "status": "ldap_open_failed",
                    "ldap_reconnects": 0,
                    "total_changes": 0,
                },
                level="error",
            )
            raise
        logging.info("[INFO] LDAP connection opened for update")
        updated_users = 0
        total_changes = 0
        missing_in_ad = 0
        ldap_reconnects = 0
        fatal_error_message: str | None = None
        try:
            for emp in candidates:
                emp_id = extract_employee_id(emp)
                if not emp_id:
                    continue
                try:
                    lookup = self._directory_gateway.find_user_by_employee_id(
                        directory,
                        emp_id,
                        attributes=AD_UPDATE_SEARCH_ATTRIBUTES,
                        search_scope=2,
                    )
                except Exception as exc:
                    logging.error(f"LDAP search exception for {emp_id}: {exc}")
                    try:
                        self._directory_gateway.close(
                            directory.conn,
                            context=f"update search exception for {emp_id}",
                        )
                        directory = self._directory_gateway.open_directory(
                            context="Update",
                            require_create_base=False,
                        )
                        ldap_reconnects += 1
                        self._telemetry_sink.emit(
                            "directory_reconnect",
                            {
                                "job": "scheduled_update_existing_users",
                                "run_id": run_id,
                                "employee_id": emp_id,
                                "reason": "search_exception",
                            },
                            level="warning",
                        )
                    except Exception as reconnect_error:
                        logging.error(
                            f"Reconnect failed after search exception for {emp_id}: {reconnect_error}"
                        )
                        fatal_reason = "search_reconnect_failed"
                        fatal_error_message = (
                            "LDAP reconnection failed during scheduled_update_existing_users "
                            f"search recovery for {emp_id}."
                        )
                        break
                    continue
                if not lookup.found and self._is_bind_lost_result(lookup.result):
                    logging.warning(f"Bind lost during update search for {emp_id}; reconnecting")
                    try:
                        self._directory_gateway.close(
                            directory.conn,
                            context=f"update search bind-loss for {emp_id}",
                        )
                        directory = self._directory_gateway.open_directory(
                            context="Update",
                            require_create_base=False,
                        )
                        ldap_reconnects += 1
                        self._telemetry_sink.emit(
                            "directory_reconnect",
                            {
                                "job": "scheduled_update_existing_users",
                                "run_id": run_id,
                                "employee_id": emp_id,
                                "reason": "search_bind_loss",
                            },
                            level="warning",
                        )
                    except Exception as reconnect_error:
                        logging.error(
                            f"Reconnect failed after bind-loss search for {emp_id}: {reconnect_error}"
                        )
                        fatal_reason = "bind_loss_reconnect_failed"
                        fatal_error_message = (
                            "LDAP reconnection failed during scheduled_update_existing_users "
                            f"bind-loss recovery for {emp_id}."
                        )
                        break
                    continue
                if not lookup.entry:
                    missing_in_ad += 1
                    continue
                entry = lookup.entry
                dn = str(self._entry_attr_value(entry, "distinguishedName") or "<unknown DN>")
                if self._is_terminated_employee(emp):
                    desired = {"userAccountControl": 514}
                    if not settings.always_disable_terminated:
                        desired = _filter_desired_update_attributes(
                            desired,
                            enabled_fields=effective_enabled_fields,
                        )
                else:
                    current_department = str(self._entry_attr_value(entry, "department") or "").strip()
                    current_manager_dn = str(self._entry_attr_value(entry, "manager") or "").strip()
                    current_manager_department = (
                        self._directory_gateway.get_department_by_dn(directory, current_manager_dn)
                        if current_manager_dn
                        else ""
                    )
                    desired = self._build_update_attributes(
                        emp,
                        directory.conn,
                        directory.settings.search_base,
                        current_ad_department=current_department,
                        manager_department=current_manager_department,
                        enabled_fields=effective_enabled_fields,
                    )
                    desired = _filter_desired_update_attributes(
                        desired,
                        enabled_fields=effective_enabled_fields,
                    )
                changes = self._diff_update_attributes(entry, desired, context=f"{emp_id} at {dn}")
                if not changes:
                    if settings.log_no_changes:
                        logging.info(f"[INFO] No updates needed for {emp_id} at {dn}")
                    continue
                updated_users += 1
                for attr, ops in changes.items():
                    desired_val = ops[0][1][0] if ops and ops[0][1] else None
                    current_val = self._entry_attr_value(entry, attr)
                    if settings.dry_run:
                        logging.info(
                            f"[INFO] DRY RUN update {emp_id} {attr}: '{current_val}' -> '{desired_val}'"
                        )
                    else:
                        logging.info(f"Updating {emp_id} {attr}: '{current_val}' -> '{desired_val}'")
                total_changes += len(changes)
                if not settings.dry_run:
                    updated_directory = self._directory_gateway.apply_changes(directory, dn, changes)
                    if not updated_directory:
                        logging.error("LDAP connection unavailable; aborting scheduled_update_existing_users")
                        fatal_reason = "ldap_connection_unavailable"
                        fatal_error_message = (
                            "LDAP connection unavailable during scheduled_update_existing_users."
                        )
                        break
                    directory = updated_directory
        finally:
            self._directory_gateway.close(
                directory.conn,
                context="scheduled_update_existing_users completion",
            )
            logging.info(
                f"[INFO] LDAP connection closed - scheduled_update_existing_users complete "
                f"(users_with_changes={updated_users}, total_changes={total_changes}, "
                f"missing_in_ad={missing_in_ad})"
            )
            self._telemetry_sink.emit(
                "job_run",
                {
                    "job": "scheduled_update_existing_users",
                    "run_id": run_id,
                    "dry_run": settings.dry_run,
                    "worker_count": len(candidates),
                    "created": 0,
                    "changed": updated_users,
                    "missing_in_ad": missing_in_ad,
                    "fatal_reason": fatal_reason,
                    "status": fatal_reason or "completed",
                    "ldap_reconnects": ldap_reconnects,
                    "total_changes": total_changes,
                },
                level="error" if fatal_reason else "info",
            )

        if fatal_error_message:
            raise RuntimeError(fatal_error_message)

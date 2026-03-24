"""Update orchestration implemented against explicit service interfaces."""

from __future__ import annotations

import logging
from typing import Callable

from ..adp_client import extract_employee_id
from ..config import get_update_job_settings
from ..constants import AD_UPDATE_SEARCH_ATTRIBUTES
from ..models import UpdateJobSettings
from ..services.interfaces import DirectoryGateway, WorkerProvider


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
        get_department_by_dn: Callable[..., str],
        is_bind_lost_result: Callable[[dict], bool],
        apply_ldap_modifications: Callable[..., object],
        settings_getter: Callable[[], UpdateJobSettings] = get_update_job_settings,
    ) -> None:
        self._worker_provider = worker_provider
        self._directory_gateway = directory_gateway
        self._select_update_candidates = select_update_candidates
        self._is_terminated_employee = is_terminated_employee
        self._build_update_attributes = build_update_attributes
        self._diff_update_attributes = diff_update_attributes
        self._entry_attr_value = entry_attr_value
        self._get_department_by_dn = get_department_by_dn
        self._is_bind_lost_result = is_bind_lost_result
        self._apply_ldap_modifications = apply_ldap_modifications
        self._settings_getter = settings_getter

    def run(self, mytimer) -> None:
        del mytimer
        settings = self._settings_getter()
        logging.info(
            f"[INFO] scheduled_update_existing_users triggered "
            f"(dry_run={settings.dry_run}, lookback_days={settings.lookback_days})"
        )

        all_employees = self._worker_provider.fetch_workers(context="scheduled_update_existing_users")
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
            return

        directory = self._directory_gateway.open_directory(
            context="Update",
            require_create_base=False,
        )
        conn = directory.conn
        logging.info("[INFO] LDAP connection opened for update")
        updated_users = 0
        total_changes = 0
        missing_in_ad = 0
        fatal_error_message: str | None = None
        try:
            for emp in candidates:
                emp_id = extract_employee_id(emp)
                if not emp_id:
                    continue
                try:
                    found = conn.search(
                        directory.settings.search_base,
                        f"(employeeID={emp_id})",
                        attributes=AD_UPDATE_SEARCH_ATTRIBUTES,
                        search_scope=2,
                    )
                except Exception as exc:
                    logging.error(f"LDAP search exception for {emp_id}: {exc}")
                    try:
                        self._directory_gateway.close(conn, context=f"update search exception for {emp_id}")
                        directory = self._directory_gateway.open_directory(
                            context="Update",
                            require_create_base=False,
                        )
                        conn = directory.conn
                    except Exception as reconnect_error:
                        logging.error(
                            f"Reconnect failed after search exception for {emp_id}: {reconnect_error}"
                        )
                        fatal_error_message = (
                            "LDAP reconnection failed during scheduled_update_existing_users "
                            f"search recovery for {emp_id}."
                        )
                        break
                    continue
                if not found and self._is_bind_lost_result(getattr(conn, "result", None) or {}):
                    logging.warning(f"Bind lost during update search for {emp_id}; reconnecting")
                    try:
                        self._directory_gateway.close(conn, context=f"update search bind-loss for {emp_id}")
                        directory = self._directory_gateway.open_directory(
                            context="Update",
                            require_create_base=False,
                        )
                        conn = directory.conn
                    except Exception as reconnect_error:
                        logging.error(
                            f"Reconnect failed after bind-loss search for {emp_id}: {reconnect_error}"
                        )
                        fatal_error_message = (
                            "LDAP reconnection failed during scheduled_update_existing_users "
                            f"bind-loss recovery for {emp_id}."
                        )
                        break
                    continue
                if not conn.entries:
                    missing_in_ad += 1
                    continue
                entry = conn.entries[0]
                dn = self._entry_attr_value(entry, "distinguishedName") or "<unknown DN>"
                if self._is_terminated_employee(emp):
                    desired = {"userAccountControl": 514}
                else:
                    current_department = str(self._entry_attr_value(entry, "department") or "").strip()
                    current_manager_dn = str(self._entry_attr_value(entry, "manager") or "").strip()
                    current_manager_department = (
                        self._get_department_by_dn(conn, current_manager_dn) if current_manager_dn else ""
                    )
                    desired = self._build_update_attributes(
                        emp,
                        conn,
                        directory.settings.search_base,
                        current_ad_department=current_department,
                        manager_department=current_manager_department,
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
                    conn = self._apply_ldap_modifications(conn, dn, changes, directory.conn_factory)
                    if not conn:
                        logging.error("LDAP connection unavailable; aborting scheduled_update_existing_users")
                        fatal_error_message = (
                            "LDAP connection unavailable during scheduled_update_existing_users."
                        )
                        break
        finally:
            self._directory_gateway.close(conn, context="scheduled_update_existing_users completion")
            logging.info(
                f"[INFO] LDAP connection closed - scheduled_update_existing_users complete "
                f"(users_with_changes={updated_users}, total_changes={total_changes}, "
                f"missing_in_ad={missing_in_ad})"
            )

        if fatal_error_message:
            raise RuntimeError(fatal_error_message)

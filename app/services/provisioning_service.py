"""Provisioning orchestration implemented against explicit service interfaces."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Callable

from ..adp import extract_employee_id, get_display_name, get_hire_date, get_legal_first_last
from ..config import get_provision_job_settings
from ..models import ProvisionJobSettings
from ..reporting import inc_stat
from ..services.interfaces import DirectoryGateway, WorkerProvider


class ProvisioningOrchestrator:
    """Run the scheduled provisioning workflow using explicit gateway dependencies."""

    def __init__(
        self,
        *,
        worker_provider: WorkerProvider,
        directory_gateway: DirectoryGateway,
        provision_user: Callable[..., object],
        is_recent_hire: Callable[[dict, datetime], bool],
        settings_getter: Callable[[], ProvisionJobSettings] = get_provision_job_settings,
    ) -> None:
        self._worker_provider = worker_provider
        self._directory_gateway = directory_gateway
        self._provision_user = provision_user
        self._is_recent_hire = is_recent_hire
        self._settings_getter = settings_getter

    def run(self, mytimer) -> None:
        run_started_at = time.time()
        summary: dict[str, int] = {
            "adp_total": 0,
            "deduped_dropped": 0,
            "hires_in_window": 0,
            "processed": 0,
            "exists": 0,
            "created": 0,
            "manager_missing": 0,
            "skipped_country": 0,
            "skipped_missing_required_fields": 0,
            "add_failures": 0,
            "password_failures": 0,
            "duration_ms": 0,
        }
        settings = self._settings_getter()

        def log_summary(reason: str) -> None:
            summary["duration_ms"] = int((time.time() - run_started_at) * 1000)
            logging.info(
                "[INFO] scheduled_provision_new_hires summary (%s) | "
                "input: adp_total=%s deduped_dropped=%s hires_in_window=%s processed=%s | "
                "outcomes: exists=%s created=%s manager_missing=%s skipped_country=%s "
                "skipped_missing_required_fields=%s add_failures=%s password_failures=%s | duration_ms=%s",
                reason,
                summary["adp_total"],
                summary["deduped_dropped"],
                summary["hires_in_window"],
                summary["processed"],
                summary["exists"],
                summary["created"],
                summary["manager_missing"],
                summary["skipped_country"],
                summary["skipped_missing_required_fields"],
                summary["add_failures"],
                summary["password_failures"],
                summary["duration_ms"],
            )

        logging.info("[INFO] scheduled_provision_new_hires triggered")
        if mytimer and getattr(mytimer, "past_due", False):
            logging.warning("[WARN] Timer is past due")

        try:
            all_employees = self._worker_provider.fetch_workers(context="scheduled_provision_new_hires")
        except RuntimeError:
            log_summary("adp_fetch_failed")
            raise

        summary["adp_total"] = len(all_employees)
        all_employees = self._worker_provider.dedupe_workers(
            all_employees,
            context="scheduled_provision_new_hires",
        )
        summary["deduped_dropped"] = max(0, summary["adp_total"] - len(all_employees))
        self._worker_provider.log_duplicate_profiles(
            all_employees,
            context="scheduled_provision_new_hires",
        )

        employees_with_hire_date = [emp for emp in all_employees if get_hire_date(emp)]
        logging.info(f"[INFO] Retrieved {len(employees_with_hire_date)} total ADP employees with hire dates")
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=settings.hire_lookback_days)
        employees_recent = [emp for emp in employees_with_hire_date if self._is_recent_hire(emp, cutoff_dt)]
        summary["hires_in_window"] = len(employees_recent)
        logging.info(
            f"[INFO] {len(employees_recent)} employees hired since {cutoff_dt.date().isoformat()} "
            f"(lookback_days={settings.hire_lookback_days})"
        )
        if not employees_recent:
            logging.info("[INFO] No recent hires to process.")
            log_summary("no_recent_hires")
            return

        try:
            directory = self._directory_gateway.open_directory(
                context="Provisioning",
                require_create_base=True,
            )
        except RuntimeError:
            log_summary("ldap_open_failed")
            raise

        conn = directory.conn
        completion_reason = "completed"
        fatal_error_message: str | None = None
        try:
            for emp in employees_recent:
                summary["processed"] += 1
                emp_id = extract_employee_id(emp)
                person = emp.get("person", {})
                display_name = get_display_name(person) or "<no display name>"
                legal_first, legal_last = get_legal_first_last(person)
                legal_name = f"{legal_first} {legal_last}".strip() or "<no legal name>"
                start_date = get_hire_date(emp) or "<unknown>"
                logging.info(
                    f"[INFO] Processing {emp_id} / display='{display_name}' "
                    f"legal='{legal_name}' Start Date='{start_date}'"
                )
                try:
                    new_conn = self._provision_user(
                        emp,
                        conn,
                        directory.settings.search_base,
                        directory.settings.create_base or "",
                        directory.conn_factory,
                        summary_stats=summary,
                        max_retry_attempts=settings.max_add_retries,
                        cn_collision_threshold=settings.cn_collision_threshold,
                    )
                    if not new_conn:
                        completion_reason = "ldap_connection_unavailable"
                        inc_stat(summary, "add_failures")
                        fatal_error_message = (
                            "LDAP connection unavailable during scheduled_provision_new_hires."
                        )
                        logging.error("LDAP connection unavailable; aborting scheduled_provision_new_hires")
                        break
                    conn = new_conn
                except Exception as exc:
                    inc_stat(summary, "add_failures")
                    logging.error(f"[ERROR] Exception provisioning {emp_id}: {exc}")
        finally:
            self._directory_gateway.close(conn, context="scheduled_provision_new_hires completion")
            logging.info("[INFO] LDAP connection closed - scheduled_provision_new_hires complete")
            log_summary(completion_reason)

        if fatal_error_message:
            raise RuntimeError(fatal_error_message)

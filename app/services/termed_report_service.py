"""Termed report orchestration implemented against explicit service interfaces."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Callable

from ..config import get_termed_report_settings
from ..models import TermedReportSettings
from ..telemetry import new_run_id
from .interfaces import MailGateway, TelemetrySink, WorkerProvider


class TermedReportOrchestrator:
    """Run the weekly termed report workflow using explicit service interfaces."""

    def __init__(
        self,
        *,
        worker_provider: WorkerProvider,
        mail_gateway: MailGateway,
        select_recent_terminated_employees: Callable[..., tuple[list[dict], dict[str, object]]],
        build_termed_report_rows: Callable[..., list[dict[str, str]]],
        render_termed_report_csv: Callable[[list[dict[str, str]]], str],
        now_getter: Callable[[], datetime],
        telemetry_sink: TelemetrySink,
        settings_getter: Callable[[], TermedReportSettings] = get_termed_report_settings,
    ) -> None:
        self._worker_provider = worker_provider
        self._mail_gateway = mail_gateway
        self._select_recent_terminated_employees = select_recent_terminated_employees
        self._build_termed_report_rows = build_termed_report_rows
        self._render_termed_report_csv = render_termed_report_csv
        self._now_getter = now_getter
        self._telemetry_sink = telemetry_sink
        self._settings_getter = settings_getter

    def run(self, mytimer) -> None:
        del mytimer
        run_id = new_run_id("scheduled_last_30_day_termed_report")
        settings = self._settings_getter()
        logging.info(
            "[INFO] scheduled_last_30_day_termed_report triggered "
            f"(run_id={run_id}, lookback_days={settings.lookback_days}, "
            f"recipients={len(settings.recipients)})"
        )

        fatal_reason = ""
        try:
            all_employees = self._worker_provider.fetch_workers(context="scheduled_last_30_day_termed_report")
        except RuntimeError:
            fatal_reason = "adp_fetch_failed"
            self._telemetry_sink.emit(
                "job_run",
                {
                    "job": "scheduled_last_30_day_termed_report",
                    "run_id": run_id,
                    "dry_run": False,
                    "worker_count": 0,
                    "created": 0,
                    "changed": 0,
                    "missing_in_ad": 0,
                    "fatal_reason": fatal_reason,
                    "status": "adp_fetch_failed",
                    "row_count": 0,
                    "smtp_failed": 0,
                },
                level="error",
            )
            raise
        recent_terminations, stats = self._select_recent_terminated_employees(
            all_employees,
            settings,
            context="scheduled_last_30_day_termed_report",
        )
        rows = self._build_termed_report_rows(recent_terminations)
        csv_content = self._render_termed_report_csv(rows)

        try:
            self._mail_gateway.send_report(
                settings,
                report_date=self._now_getter(),
                csv_content=csv_content,
                row_count=len(rows),
            )
        except Exception as exc:
            fatal_reason = "smtp_send_failed"
            self._telemetry_sink.emit(
                "smtp_failure",
                {
                    "job": "scheduled_last_30_day_termed_report",
                    "run_id": run_id,
                    "row_count": len(rows),
                    "fatal_reason": fatal_reason,
                    "cutoff": stats["cutoff_iso"],
                },
                level="error",
            )
            logging.error(
                "[ERROR] Failed to email scheduled_last_30_day_termed_report "
                f"(rows={len(rows)}, cutoff={stats['cutoff_iso']}): {exc}"
            )
            self._telemetry_sink.emit(
                "job_run",
                {
                    "job": "scheduled_last_30_day_termed_report",
                    "run_id": run_id,
                    "dry_run": False,
                    "worker_count": len(recent_terminations),
                    "created": 0,
                    "changed": 0,
                    "missing_in_ad": 0,
                    "fatal_reason": fatal_reason,
                    "status": "smtp_send_failed",
                    "row_count": len(rows),
                    "smtp_failed": 1,
                },
                level="error",
            )
            raise RuntimeError("Failed to email scheduled_last_30_day_termed_report.") from exc

        logging.info(
            "[INFO] scheduled_last_30_day_termed_report complete "
            f"(rows={len(rows)}, cutoff={stats['cutoff_iso']}, deduped={stats['deduped_count']}, "
            f"missing_term_date={stats['missing_termination_date']}, "
            f"invalid_term_date={stats['invalid_termination_date']}, "
            f"outside_window={stats['outside_window']})"
        )
        self._telemetry_sink.emit(
            "job_run",
            {
                "job": "scheduled_last_30_day_termed_report",
                "run_id": run_id,
                "dry_run": False,
                "worker_count": len(recent_terminations),
                "created": 0,
                "changed": 0,
                "missing_in_ad": 0,
                "fatal_reason": "",
                "status": "completed",
                "row_count": len(rows),
                "smtp_failed": 0,
            },
        )

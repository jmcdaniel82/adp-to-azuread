"""Termed report orchestration implemented against explicit service interfaces."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Callable

from ..config import get_termed_report_settings
from ..models import TermedReportSettings
from .interfaces import MailGateway, WorkerProvider


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
        settings_getter: Callable[[], TermedReportSettings] = get_termed_report_settings,
    ) -> None:
        self._worker_provider = worker_provider
        self._mail_gateway = mail_gateway
        self._select_recent_terminated_employees = select_recent_terminated_employees
        self._build_termed_report_rows = build_termed_report_rows
        self._render_termed_report_csv = render_termed_report_csv
        self._now_getter = now_getter
        self._settings_getter = settings_getter

    def run(self, mytimer) -> None:
        del mytimer
        settings = self._settings_getter()
        logging.info(
            "[INFO] scheduled_last_30_day_termed_report triggered "
            f"(lookback_days={settings.lookback_days}, recipients={len(settings.recipients)})"
        )

        all_employees = self._worker_provider.fetch_workers(context="scheduled_last_30_day_termed_report")
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
            logging.error(
                "[ERROR] Failed to email scheduled_last_30_day_termed_report "
                f"(rows={len(rows)}, cutoff={stats['cutoff_iso']}): {exc}"
            )
            raise RuntimeError("Failed to email scheduled_last_30_day_termed_report.") from exc

        logging.info(
            "[INFO] scheduled_last_30_day_termed_report complete "
            f"(rows={len(rows)}, cutoff={stats['cutoff_iso']}, deduped={stats['deduped_count']}, "
            f"missing_term_date={stats['missing_termination_date']}, "
            f"invalid_term_date={stats['invalid_termination_date']}, "
            f"outside_window={stats['outside_window']})"
        )

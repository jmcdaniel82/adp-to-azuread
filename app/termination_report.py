"""Weekly ADP last-30-day termination report email workflow."""

from __future__ import annotations

import csv
import io
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any

from .adp import (
    dedupe_workers_by_employee_id,
    extract_assignment_field,
    extract_business_title,
    extract_company,
    extract_department,
    extract_employee_id,
    extract_last_updated,
    extract_manager_id,
    extract_state_from_work,
    extract_work_address_field,
    get_adp_employees,
    get_adp_token,
    get_display_name,
    get_hire_date,
    get_status,
    get_termination_date,
    log_potential_duplicate_profiles,
    parse_datetime,
)
from .config import get_termed_report_settings
from .services.defaults import DefaultMailGateway, DefaultWorkerProvider, build_telemetry_sink
from .services.termed_report_service import TermedReportOrchestrator

TERMED_REPORT_FIELDNAMES = [
    "employeeID",
    "fullName",
    "employeeStatus",
    "terminationDate",
    "daysSinceTermination",
    "lastUpdatedDateTime",
    "hireDate",
    "businessTitle",
    "department",
    "company",
    "managerEmployeeID",
    "countryCode",
    "city",
    "state",
]


def format_utc_datetime(value: datetime | None) -> str:
    """Format datetimes as UTC ISO-8601 strings for output."""
    if not value:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def select_recent_terminated_employees(
    all_employees: list[dict],
    settings,
    *,
    context: str,
    now: datetime | None = None,
) -> tuple[list[dict], dict[str, Any]]:
    """Return deduped ADP employees terminated inside the configured lookback window."""
    employees = dedupe_workers_by_employee_id(all_employees, context)
    log_potential_duplicate_profiles(employees, context)

    current_time = now or datetime.now(timezone.utc)
    cutoff = current_time - timedelta(days=settings.lookback_days)
    selected: list[dict] = []
    missing_termination_date = 0
    invalid_termination_date = 0
    outside_window = 0

    for emp in employees:
        termination_date = get_termination_date(emp)
        if not termination_date:
            missing_termination_date += 1
            continue

        parsed = parse_datetime(termination_date, "terminationDate")
        if not parsed:
            invalid_termination_date += 1
            continue

        if cutoff <= parsed <= current_time:
            selected.append(emp)
        else:
            outside_window += 1

    selected.sort(
        key=lambda emp: (
            parse_datetime(
                get_termination_date(emp) or "",
                "terminationDate sort",
            )
            or datetime.min.replace(tzinfo=timezone.utc),
            extract_employee_id(emp) or "",
        ),
        reverse=True,
    )
    return selected, {
        "deduped_count": len(employees),
        "cutoff_iso": cutoff.date().isoformat(),
        "missing_termination_date": missing_termination_date,
        "invalid_termination_date": invalid_termination_date,
        "outside_window": outside_window,
    }


def build_termed_report_rows(employees: list[dict], *, now: datetime | None = None) -> list[dict[str, str]]:
    """Build CSV rows for recently terminated ADP workers."""
    current_time = now or datetime.now(timezone.utc)
    rows: list[dict[str, str]] = []

    for emp in employees:
        term_value = get_termination_date(emp) or ""
        term_dt = parse_datetime(term_value, "terminationDate row")
        if not term_dt:
            continue

        last_updated = extract_last_updated(emp)
        hire_date = parse_datetime(get_hire_date(emp) or "", "hireDate row")
        title = extract_business_title(emp) or extract_assignment_field(emp, "jobTitle") or ""
        rows.append(
            {
                "employeeID": extract_employee_id(emp) or "",
                "fullName": get_display_name(emp.get("person", {})),
                "employeeStatus": get_status(emp),
                "terminationDate": format_utc_datetime(term_dt),
                "daysSinceTermination": str((current_time.date() - term_dt.date()).days),
                "lastUpdatedDateTime": format_utc_datetime(last_updated),
                "hireDate": format_utc_datetime(hire_date),
                "businessTitle": title,
                "department": extract_department(emp),
                "company": extract_company(emp),
                "managerEmployeeID": extract_manager_id(emp) or "",
                "countryCode": extract_work_address_field(emp, "countryCode") or "",
                "city": extract_work_address_field(emp, "cityName") or "",
                "state": extract_state_from_work(emp) or "",
            }
        )

    return rows


def render_termed_report_csv(rows: list[dict[str, str]]) -> str:
    """Render the weekly termed report as CSV text."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=TERMED_REPORT_FIELDNAMES)
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def send_termed_report_email(
    settings,
    *,
    report_date: datetime,
    csv_content: str,
    row_count: int,
) -> None:
    """Send the weekly termed report email with CSV attachment."""
    recipients = list(settings.recipients)
    if not settings.smtp_host or not settings.from_address or not recipients:
        raise RuntimeError("Missing SMTP host, from address, or recipients for termed report email.")

    report_stamp = report_date.date().isoformat()
    attachment_name = f"adp_last_{settings.lookback_days}_day_termed_report_{report_date:%Y%m%d}.csv"
    message = EmailMessage()
    message["From"] = settings.from_address
    message["To"] = ", ".join(recipients)
    message["Subject"] = f"{settings.subject} - {report_stamp}"
    message.set_content(
        "\n".join(
            [
                f"Attached is the ADP last {settings.lookback_days} day termed report.",
                f"Generated at: {format_utc_datetime(report_date)}",
                f"Employees in report: {row_count}",
            ]
        )
    )
    message.add_attachment(
        csv_content.encode("utf-8"),
        maintype="text",
        subtype="csv",
        filename=attachment_name,
    )

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as smtp:
        smtp.send_message(message)


def run_scheduled_last_30_day_termed_report(mytimer) -> None:
    """Timer-trigger orchestration for the weekly ADP termed report email."""
    build_termed_report_orchestrator().run(mytimer)


def build_worker_provider() -> DefaultWorkerProvider:
    """Build the default ADP-backed worker provider for the termed report."""
    return DefaultWorkerProvider(
        get_token=get_adp_token,
        get_workers=get_adp_employees,
        dedupe_workers=dedupe_workers_by_employee_id,
        log_duplicate_profiles=log_potential_duplicate_profiles,
    )


def build_mail_gateway() -> DefaultMailGateway:
    """Build the default SMTP-backed mail gateway."""
    return DefaultMailGateway(send_report_email=send_termed_report_email)


def build_termed_report_orchestrator() -> TermedReportOrchestrator:
    """Build the termed report orchestrator with explicit service dependencies."""
    return TermedReportOrchestrator(
        worker_provider=build_worker_provider(),
        mail_gateway=build_mail_gateway(),
        select_recent_terminated_employees=select_recent_terminated_employees,
        build_termed_report_rows=build_termed_report_rows,
        render_termed_report_csv=render_termed_report_csv,
        now_getter=lambda: datetime.now(timezone.utc),
        telemetry_sink=build_telemetry_sink(),
        settings_getter=get_termed_report_settings,
    )

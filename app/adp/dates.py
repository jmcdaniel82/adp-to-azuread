"""Date parsing and worker-date extraction helpers."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional


def parse_datetime(value: str, context: str) -> Optional[datetime]:
    """Parse ISO-like datetime values, including trailing Z for UTC."""
    if not value:
        return None
    try:
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception as exc:
        logging.error(f"Error parsing {context} '{value}': {exc}")
        return None


def _parse_datetime_silent(value: str) -> Optional[datetime]:
    """Parse datetime without logging parse errors."""
    if not value:
        return None
    try:
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None


def format_start_date_for_log(hire_value: str) -> str:
    """Render start date as M/D/YYYY for readable logs."""
    parsed = _parse_datetime_silent(hire_value or "")
    if not parsed:
        return "<unknown>"
    return f"{parsed.month}/{parsed.day}/{parsed.year}"


def extract_last_updated(emp: dict) -> Optional[datetime]:
    """Best-effort ADP lastUpdated extraction from known metadata fields."""
    candidates = [
        emp.get("meta", {}).get("lastUpdatedDateTime"),
        emp.get("meta", {}).get("lastUpdatedTimestamp"),
        emp.get("meta", {}).get("lastUpdateDateTime"),
        emp.get("lastUpdatedDateTime"),
        emp.get("lastUpdatedTimestamp"),
        emp.get("lastUpdateDateTime"),
    ]
    assignments = emp.get("workAssignments")
    if isinstance(assignments, list) and assignments:
        candidates.append(assignments[0].get("lastUpdatedDateTime"))
        candidates.append(assignments[0].get("lastUpdatedTimestamp"))
    for value in candidates:
        if not value:
            continue
        parsed = parse_datetime(value, "lastUpdated")
        if parsed:
            return parsed
    return None


def get_hire_date(employee: dict) -> Optional[str]:
    """Return best hire/start date in canonical ISO form."""
    assignments = employee.get("workAssignments")
    if isinstance(assignments, list) and assignments:
        for key in ("hireDate", "actualStartDate"):
            value = assignments[0].get(key)
            if not value:
                continue
            parsed = parse_datetime(value, f"assignment {key}")
            if parsed:
                return parsed.isoformat()

    worker_dates = employee.get("workerDates")
    parsed_dates: list[datetime] = []
    if isinstance(worker_dates, list):
        for item in worker_dates:
            if "hire" not in item.get("type", "").lower():
                continue
            value = item.get("value")
            parsed = parse_datetime(value, "workerDates hire") if isinstance(value, str) else None
            if parsed:
                parsed_dates.append(parsed)
    elif isinstance(worker_dates, dict):
        for key in ("originalHireDate", "hireDate", "hire_date"):
            value = worker_dates.get(key)
            parsed = parse_datetime(value, f"workerDates {key}") if isinstance(value, str) else None
            if parsed:
                parsed_dates.append(parsed)
    return max(parsed_dates).isoformat() if parsed_dates else None


def get_termination_date(emp: dict) -> Optional[str]:
    """Return termination date when present in ADP payload."""
    worker_dates = emp.get("workerDates")
    if isinstance(worker_dates, list):
        for item in worker_dates:
            if "term" in item.get("type", "").lower():
                return item.get("value")
    elif isinstance(worker_dates, dict):
        return worker_dates.get("terminationDate")
    return None

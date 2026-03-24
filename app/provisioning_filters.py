"""Focused provisioning filter helpers."""

from __future__ import annotations

from datetime import datetime

from .adp import get_hire_date, parse_datetime


def is_recent_hire(emp: dict, cutoff_dt: datetime) -> bool:
    """Return True when the worker hire date is on or after the cutoff."""
    hire_date = get_hire_date(emp)
    if not hire_date:
        return False
    parsed = parse_datetime(hire_date, "hireDate")
    if not parsed:
        return False
    return parsed >= cutoff_dt

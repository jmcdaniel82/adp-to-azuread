"""Employment-status helpers derived from worker dates."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from .dates import get_hire_date, get_termination_date, parse_datetime


def get_status(emp: dict) -> str:
    """Return Active or Inactive derived from hire and termination timing."""
    hire_date = get_hire_date(emp)
    termination_date = get_termination_date(emp)
    if not hire_date:
        return "Inactive"
    parsed_hire = parse_datetime(hire_date, "hireDate")
    if not parsed_hire:
        return "Inactive"
    now = datetime.now(timezone.utc)
    if parsed_hire > now:
        return "Inactive"
    if not termination_date:
        return "Active"
    parsed_term = parse_datetime(termination_date, "terminationDate")
    if not parsed_term:
        logging.warning(f"Invalid termination date '{termination_date}' for employee; treating as Active")
        return "Active"
    return "Active" if parsed_term > now else "Inactive"


def is_terminated_employee(emp: dict) -> bool:
    """Return True when termination date is now or in the past."""
    termination_date = get_termination_date(emp)
    if not termination_date:
        return False
    parsed_term = parse_datetime(termination_date, "terminationDate")
    if not parsed_term:
        return False
    return parsed_term <= datetime.now(timezone.utc)


def get_user_account_control(emp: dict) -> int:
    """Map ADP status to AD userAccountControl."""
    return 512 if get_status(emp) == "Active" else 514

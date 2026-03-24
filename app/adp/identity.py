"""Worker identity normalization helpers."""

from __future__ import annotations

import re


def normalize_id(emp_id: str) -> str:
    """Trim and uppercase employeeID values."""
    return emp_id.strip().upper() if emp_id else ""


def extract_employee_id(emp: dict) -> str:
    """Extract ADP employeeID from workerID payload shape."""
    worker_id = emp.get("workerID")
    if isinstance(worker_id, dict):
        return worker_id.get("idValue", "")
    return worker_id or ""


def sanitize_string_for_sam(value: str) -> str:
    """Remove non-alphanumeric characters for sAMAccountName construction."""
    return re.sub(r"[^a-zA-Z0-9]", "", value)

"""ADP worker dedupe and duplicate-profile diagnostics helpers."""

from __future__ import annotations

import logging
import os
import re

from .workers import (
    _parse_datetime_silent,
    extract_assignment_field,
    extract_business_title,
    extract_department,
    extract_employee_id,
    extract_last_updated,
    extract_manager_id,
    get_display_name,
    get_hire_date,
    normalize_id,
)


def _dedupe_recency_key(emp: dict, index: int) -> tuple[int, float, int]:
    """Sort key preferring latest lastUpdated, then latest hire date, then index."""
    updated_at = extract_last_updated(emp)
    if updated_at:
        return (2, updated_at.timestamp(), index)
    hire_date = _parse_datetime_silent(get_hire_date(emp) or "")
    if hire_date:
        return (1, hire_date.timestamp(), index)
    return (0, float(index), index)


def dedupe_workers_by_employee_id(workers: list[dict], context: str) -> list[dict]:
    """Keep one worker row per employeeID, preferring the most recent row."""
    if not isinstance(workers, list) or not workers:
        return workers

    selected: dict[str, tuple[int, tuple[int, float, int], dict]] = {}
    duplicates_seen = 0

    for index, worker in enumerate(workers):
        employee_id = normalize_id(extract_employee_id(worker))
        if not employee_id:
            continue
        key = _dedupe_recency_key(worker, index)
        current = selected.get(employee_id)
        if not current:
            selected[employee_id] = (index, key, worker)
            continue
        duplicates_seen += 1
        if key >= current[1]:
            selected[employee_id] = (index, key, worker)

    if duplicates_seen == 0:
        return workers

    kept_indexes = {item[0] for item in selected.values()}
    deduped: list[dict] = []
    dropped = 0
    for index, worker in enumerate(workers):
        employee_id = normalize_id(extract_employee_id(worker))
        if not employee_id:
            deduped.append(worker)
            continue
        if index in kept_indexes:
            deduped.append(worker)
        else:
            dropped += 1
    logging.warning(
        f"[WARN] {context} deduped ADP records by employeeID: "
        f"input={len(workers)} output={len(deduped)} dropped={dropped}"
    )
    return deduped


def _normalize_profile_signal(value: str) -> str:
    """Normalize profile signal values used for duplicate-profile warning signatures."""
    if not value:
        return ""
    return re.sub(r"\s+", " ", str(value).strip().lower())


def _profile_signature(worker: dict) -> tuple[str, str, str, str]:
    """Create non-blocking duplicate signature across identifying profile signals."""
    person = worker.get("person", {})
    display = get_display_name(person)
    title = extract_business_title(worker) or extract_assignment_field(worker, "jobTitle")
    department = extract_department(worker)
    manager_id = extract_manager_id(worker) or ""
    return (
        _normalize_profile_signal(display),
        _normalize_profile_signal(title),
        _normalize_profile_signal(department),
        _normalize_profile_signal(manager_id),
    )


def log_potential_duplicate_profiles(workers: list[dict], context: str) -> None:
    """Emit capped non-blocking warnings when profiles look duplicated in ADP."""
    if not isinstance(workers, list) or not workers:
        return

    grouped: dict[tuple[str, str, str, str], set[str]] = {}
    for worker in workers:
        employee_id = normalize_id(extract_employee_id(worker))
        if not employee_id:
            continue
        signature = _profile_signature(worker)
        if not all(signature):
            continue
        grouped.setdefault(signature, set()).add(employee_id)

    limit_raw = os.getenv("ADP_PROFILE_DUP_WARN_LIMIT", "25")
    try:
        max_warnings = max(1, int(limit_raw))
    except ValueError:
        max_warnings = 25

    warning_count = 0
    for signature, employee_ids in grouped.items():
        if len(employee_ids) < 2:
            continue
        warning_count += 1
        display, title, department, manager_id = signature
        ids = sorted(employee_ids)
        preview = ",".join(ids[:10]) + ("..." if len(ids) > 10 else "")
        logging.warning(
            f"[WARN] {context} possible duplicate ADP profile (non-blocking): "
            f"employeeIDs={preview} display='{display}' title='{title}' "
            f"department='{department}' managerID='{manager_id}'"
        )
        if warning_count >= max_warnings:
            logging.warning(
                f"[WARN] {context} duplicate profile warning limit reached "
                f"(ADP_PROFILE_DUP_WARN_LIMIT={max_warnings})"
            )
            break

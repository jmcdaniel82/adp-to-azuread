"""Normalization helpers for department resolution."""

from __future__ import annotations

import re

from .catalog import (
    AMBIGUOUS_REFERENCE_VALUES_NORMALIZED,
    CANONICAL_BY_SIGNAL,
    CANONICAL_DEPTS,
    CONFIDENCE_RANK,
    DEPARTMENT_NORMALIZATION_ALIASES,
    normalize_dept_signal,
)


def normalize_department_name(value: str) -> str:
    """Normalize department values for comparisons and guardrails."""
    cleaned = re.sub(r"\s+", " ", (value or "").strip())
    if not cleaned:
        return ""
    if re.match(r"^information technology\s*\|", cleaned, flags=re.IGNORECASE):
        return "Information Technology"
    normalized = normalize_dept_signal(cleaned)
    if normalized in DEPARTMENT_NORMALIZATION_ALIASES:
        return DEPARTMENT_NORMALIZATION_ALIASES[normalized]
    if normalized in CANONICAL_BY_SIGNAL:
        return CANONICAL_BY_SIGNAL[normalized]
    return cleaned


def is_canonical_department(value: str) -> bool:
    """Return True when a value normalizes to a canonical department."""
    return normalize_department_name(value) in CANONICAL_DEPTS


def is_ambiguous_reference_value(value: str) -> bool:
    """Return True when a value matches the ambiguous reference list."""
    return normalize_dept_signal(value) in AMBIGUOUS_REFERENCE_VALUES_NORMALIZED


def confidence_for_source(source: str, explicit_canonical: bool) -> str:
    """Map a signal source to a confidence bucket."""
    if source in {"costCenterDescription", "assignedDept", "homeDept"}:
        return "HIGH"
    if source in {"managerDepartment", "titleInference"}:
        return "MED"
    if source in {"occupationalClassifications", "department"}:
        return "MED" if explicit_canonical else "LOW"
    return "LOW"


def confidence_label(rank: int) -> str:
    """Convert a numeric confidence rank back to a label."""
    for label, value in CONFIDENCE_RANK.items():
        if value == rank:
            return label
    return "LOW"

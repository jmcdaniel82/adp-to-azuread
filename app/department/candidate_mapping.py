"""Department candidate mapping helpers."""

from __future__ import annotations

from typing import Any

from .catalog import (
    CANONICAL_DEPTS,
    CONFIDENCE_RANK,
    LOCAL_AC_DIRECT_MAP,
    LOCAL_AC_FIELD_WEIGHTS,
    LOCAL_AC_RULES,
    normalize_dept_signal,
)
from .normalization import confidence_for_source, is_ambiguous_reference_value, normalize_department_name


def is_customer_service_assigned_dept(source: str, value: str) -> bool:
    """Detect the customer-service override case."""
    if source not in {"assignedDept", "costCenterDescription"}:
        return False
    return normalize_dept_signal(value).startswith("customer service")


def is_explicit_admin_assigned_dept(value: str) -> bool:
    """Detect explicit admin-coded assigned department values."""
    normalized = normalize_dept_signal(value)
    if normalized.startswith("admin"):
        return True
    explicit_markers = (
        "administrative svcs",
        "administrative services",
        "office administrator",
        "office manager",
        "admin services",
    )
    return any(marker in normalized for marker in explicit_markers)


def make_candidate(
    department: str,
    source: str,
    reference_field: str,
    reference_value: str,
    confidence: str,
    reason: str,
    rule_weight: int = 0,
    is_direct: bool = False,
) -> dict:
    """Build a scored candidate record."""
    score = (
        (CONFIDENCE_RANK.get(confidence, 1) * 1000)
        + LOCAL_AC_FIELD_WEIGHTS.get(source, 30)
        + rule_weight
        + (80 if is_direct else 0)
    )
    return {
        "department": department,
        "source": source,
        "referenceField": reference_field,
        "referenceValue": reference_value,
        "confidence": confidence,
        "confidenceRank": CONFIDENCE_RANK.get(confidence, 1),
        "reason": reason,
        "score": score,
        "ambiguousReference": is_ambiguous_reference_value(reference_value),
    }


def map_signal_candidates(source: str, raw_value: str) -> list[dict[str, Any]]:
    """Map one raw signal to one or more department candidates."""
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    normalized = normalize_dept_signal(raw_value)
    if not normalized:
        return candidates

    def add_candidate(
        department: str,
        confidence: str,
        reason: str,
        rule_weight: int = 0,
        is_direct: bool = False,
    ) -> None:
        if department == "Administration" and is_ambiguous_reference_value(raw_value):
            return
        key = (department, source, reason)
        if key in seen:
            return
        seen.add(key)
        candidates.append(
            make_candidate(
                department=department,
                source=source,
                reference_field=source,
                reference_value=raw_value,
                confidence=confidence,
                reason=reason,
                rule_weight=rule_weight,
                is_direct=is_direct,
            )
        )

    if is_customer_service_assigned_dept(source, raw_value):
        add_candidate(
            department="Sales",
            confidence="HIGH",
            reason=f"{source}:{raw_value} (customer_service_override)",
            rule_weight=120,
            is_direct=True,
        )

    explicit_canonical = normalize_department_name(raw_value)
    if explicit_canonical in CANONICAL_DEPTS:
        add_candidate(
            department=explicit_canonical,
            confidence=confidence_for_source(source, explicit_canonical=True),
            reason=f"{source}:{raw_value} (explicit_canonical)",
            rule_weight=90,
            is_direct=True,
        )

    direct_match = LOCAL_AC_DIRECT_MAP.get(normalized)
    if direct_match:
        add_candidate(
            department=direct_match,
            confidence=confidence_for_source(source, explicit_canonical=False),
            reason=f"{source}:{raw_value} (direct)",
            rule_weight=80,
            is_direct=True,
        )

    for department, rule_weight, pattern in LOCAL_AC_RULES:
        if pattern.search(normalized):
            add_candidate(
                department=department,
                confidence=confidence_for_source(source, explicit_canonical=False),
                reason=f"{source}:{raw_value}",
                rule_weight=rule_weight,
            )

    return candidates


def admin_assignment_allowed(
    signals: list[tuple[str, str]],
    manager_department: str,
    title_info: dict,
) -> bool:
    """Return True when assigning Administration is strongly supported."""
    if normalize_department_name(manager_department) == "Administration":
        return True
    for source, value in signals:
        if (
            source in {"costCenterDescription", "assignedDept", "homeDept"}
            and is_explicit_admin_assigned_dept(value)
        ):
            return True
    if title_info.get("isStrongAdmin"):
        return True
    return False


__all__ = [
    "admin_assignment_allowed",
    "is_customer_service_assigned_dept",
    "is_explicit_admin_assigned_dept",
    "make_candidate",
    "map_signal_candidates",
]

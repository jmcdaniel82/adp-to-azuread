"""Candidate mapping and guardrail helpers for department resolution."""

from __future__ import annotations

from typing import Any, Optional

from .catalog import (
    CANONICAL_DEPTS,
    CONFIDENCE_RANK,
    LOCAL_AC_DEPT_PRIORITY,
    LOCAL_AC_DIRECT_MAP,
    LOCAL_AC_FIELD_WEIGHTS,
    LOCAL_AC_RULES,
    LOW_CONFIDENCE_FIELDS,
    normalize_dept_signal,
)
from .normalization import (
    confidence_for_source,
    confidence_label,
    is_ambiguous_reference_value,
    normalize_department_name,
)


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


def pick_best_candidate(candidates: list[dict[str, Any]], admin_allowed: bool) -> Optional[dict[str, Any]]:
    """Pick the best department candidate using confidence then score."""
    if not candidates:
        return None

    by_department: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        department = candidate["department"]
        slot = by_department.setdefault(
            department,
            {
                "department": department,
                "score": 0,
                "bestConfidenceRank": 0,
                "evidence": [],
                "reasons": [],
            },
        )
        slot["score"] += candidate["score"]
        slot["bestConfidenceRank"] = max(slot["bestConfidenceRank"], candidate["confidenceRank"])
        slot["evidence"].append(candidate)
        slot["reasons"].append(candidate["reason"])

    ranked = sorted(
        by_department.values(),
        key=lambda item: (
            -item["bestConfidenceRank"],
            -(item["score"] - (250 if item["department"] == "Administration" and not admin_allowed else 0)),
            LOCAL_AC_DEPT_PRIORITY.index(item["department"]),
        ),
    )
    winner = ranked[0]
    primary = sorted(winner["evidence"], key=lambda item: (-item["confidenceRank"], -item["score"]))[0]
    reason_trace = " | ".join(dict.fromkeys(winner["reasons"]))
    return {
        "department": winner["department"],
        "confidence": confidence_label(winner["bestConfidenceRank"]),
        "evidenceUsed": primary["source"],
        "referenceField": primary["referenceField"],
        "referenceValue": primary["referenceValue"],
        "primaryReason": primary["reason"],
        "reasonTrace": reason_trace,
        "ambiguousReference": primary["ambiguousReference"],
    }


def is_low_confidence_candidate(candidate: dict) -> bool:
    """Return True when evidence should not override manager-aligned current dept."""
    if not candidate:
        return True
    if candidate.get("source") in LOW_CONFIDENCE_FIELDS:
        return True
    if candidate.get("ambiguousReference"):
        return True
    return candidate.get("confidence") == "LOW"


def fallback_from_context(
    current_department: str,
    manager_department: str,
    title_department: str,
    reason_prefix: str,
) -> dict:
    """Apply the safer fallback chain for ambiguous or admin-gated cases."""
    current_raw = (current_department or "").strip()
    current_norm = normalize_department_name(current_raw)
    manager_norm = normalize_department_name(manager_department)
    title_norm = normalize_department_name(title_department)

    if current_raw:
        return {
            "department": current_norm or current_raw,
            "changeAllowed": False,
            "blockReason": f"{reason_prefix}_keep_current",
        }
    if manager_norm in CANONICAL_DEPTS:
        return {
            "department": manager_norm,
            "changeAllowed": True,
            "blockReason": f"{reason_prefix}_use_manager",
        }
    if title_norm in CANONICAL_DEPTS:
        return {
            "department": title_norm,
            "changeAllowed": True,
            "blockReason": f"{reason_prefix}_use_title",
        }
    return {
        "department": None,
        "changeAllowed": False,
        "blockReason": f"{reason_prefix}_needs_review",
    }

"""Department candidate selection and fallback helpers."""

from __future__ import annotations

from typing import Any, Optional

from .catalog import CANONICAL_DEPTS, LOCAL_AC_DEPT_PRIORITY, LOW_CONFIDENCE_FIELDS
from .normalization import confidence_label, normalize_department_name


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


__all__ = ["fallback_from_context", "is_low_confidence_candidate", "pick_best_candidate"]

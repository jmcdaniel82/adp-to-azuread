"""Department Resolution V2 orchestration and compatibility exports."""

from __future__ import annotations

from ..adp import extract_assignment_field, extract_business_title, extract_department
from .candidate_mapping import (
    admin_assignment_allowed,
    make_candidate,
    map_signal_candidates,
)
from .candidate_selection import fallback_from_context, is_low_confidence_candidate, pick_best_candidate
from .catalog import CANONICAL_DEPTS, LOW_CONFIDENCE_FIELDS
from .normalization import is_ambiguous_reference_value, normalize_department_name
from .signals import collect_local_ac_department_signals
from .title_inference import infer_department_from_title


def resolve_local_ac_department(
    emp,
    current_ad_department: str = "",
    manager_department: str = "",
) -> dict:
    """
    Resolve department with candidate scoring, confidence, and guardrails.

    Business rules that are easy to miss:
    - Prefer high-confidence direct signals over inferred or ambiguous signals.
    - Do not override a manager-aligned current department with low-confidence evidence.
    - Gate Administration assignments unless explicit admin evidence is present.
    - Fall back to current -> manager -> title when evidence is weak or ambiguous.
    """
    signals = collect_local_ac_department_signals(emp)
    title = extract_business_title(emp) or extract_assignment_field(emp, "jobTitle") or ""
    title_info = infer_department_from_title(title)
    manager_norm = normalize_department_name(manager_department)
    current_norm = normalize_department_name(current_ad_department)

    candidates = []
    for source, raw_value in signals:
        candidates.extend(map_signal_candidates(source, raw_value))

    legacy_department = extract_department(emp)
    if legacy_department:
        candidates.extend(map_signal_candidates("department", legacy_department))

    if manager_norm in CANONICAL_DEPTS:
        candidates.append(
            make_candidate(
                department=manager_norm,
                source="managerDepartment",
                reference_field="managerDepartment",
                reference_value=manager_department,
                confidence="MED",
                reason=f"managerDepartment:{manager_department}",
                rule_weight=40,
                is_direct=True,
            )
        )

    title_department = normalize_department_name(title_info.get("department", ""))
    if title_department in CANONICAL_DEPTS:
        candidates.append(
            make_candidate(
                department=title_department,
                source="titleInference",
                reference_field="title",
                reference_value=title,
                confidence=title_info.get("confidence") or "LOW",
                reason=title_info.get("reason") or f"title:{title}",
                rule_weight=45,
            )
        )

    admin_allowed = admin_assignment_allowed(signals, manager_norm, title_info)
    chosen = pick_best_candidate(candidates, admin_allowed)

    if not chosen:
        fallback = fallback_from_context(
            current_department=current_ad_department,
            manager_department=manager_department,
            title_department=title_department,
            reason_prefix="no_candidate",
        )
        return {
            "proposedDepartment": fallback["department"],
            "proposedDepartmentV2": fallback["department"],
            "changeAllowed": fallback["changeAllowed"],
            "blockReason": fallback["blockReason"],
            "evidenceUsed": "",
            "confidence": "",
            "titleInferredDept": title_department,
            "departmentChangeReferenceField": "",
            "departmentChangeReferenceValue": "",
            "departmentChangePrimaryReason": "",
            "departmentChangeReasonTrace": "",
        }

    has_conflicting_low_candidate = any(
        normalize_department_name(candidate["department"]) != current_norm
        and is_low_confidence_candidate(candidate)
        for candidate in candidates
    )
    has_ambiguous_low_signal = any(
        source in LOW_CONFIDENCE_FIELDS and is_ambiguous_reference_value(raw_value)
        for source, raw_value in signals
    ) or is_ambiguous_reference_value(legacy_department)

    if (
        current_norm
        and manager_norm
        and current_norm == manager_norm
        and (has_conflicting_low_candidate or has_ambiguous_low_signal)
    ):
        kept = current_norm or (current_ad_department or "").strip()
        return {
            "proposedDepartment": kept,
            "proposedDepartmentV2": kept,
            "changeAllowed": False,
            "blockReason": "blocked_by_manager_alignment",
            "evidenceUsed": chosen["evidenceUsed"],
            "confidence": chosen["confidence"],
            "titleInferredDept": title_department,
            "departmentChangeReferenceField": chosen["referenceField"],
            "departmentChangeReferenceValue": chosen["referenceValue"],
            "departmentChangePrimaryReason": chosen["primaryReason"],
            "departmentChangeReasonTrace": chosen["reasonTrace"],
        }

    if chosen["department"] == "Administration" and not admin_allowed:
        fallback = fallback_from_context(
            current_department=current_ad_department,
            manager_department=manager_department,
            title_department=title_department,
            reason_prefix="admin_gated",
        )
        return {
            "proposedDepartment": fallback["department"],
            "proposedDepartmentV2": fallback["department"],
            "changeAllowed": fallback["changeAllowed"],
            "blockReason": fallback["blockReason"],
            "evidenceUsed": chosen["evidenceUsed"],
            "confidence": chosen["confidence"],
            "titleInferredDept": title_department,
            "departmentChangeReferenceField": chosen["referenceField"],
            "departmentChangeReferenceValue": chosen["referenceValue"],
            "departmentChangePrimaryReason": chosen["primaryReason"],
            "departmentChangeReasonTrace": chosen["reasonTrace"],
        }

    if chosen["ambiguousReference"]:
        fallback = fallback_from_context(
            current_department=current_ad_department,
            manager_department=manager_department,
            title_department=title_department,
            reason_prefix="ambiguous_reference_value",
        )
        return {
            "proposedDepartment": fallback["department"],
            "proposedDepartmentV2": fallback["department"],
            "changeAllowed": fallback["changeAllowed"],
            "blockReason": fallback["blockReason"],
            "evidenceUsed": chosen["evidenceUsed"],
            "confidence": chosen["confidence"],
            "titleInferredDept": title_department,
            "departmentChangeReferenceField": chosen["referenceField"],
            "departmentChangeReferenceValue": chosen["referenceValue"],
            "departmentChangePrimaryReason": chosen["primaryReason"],
            "departmentChangeReasonTrace": chosen["reasonTrace"],
        }

    resolved_department = normalize_department_name(chosen["department"]) or chosen["department"]
    return {
        "proposedDepartment": resolved_department,
        "proposedDepartmentV2": resolved_department,
        "changeAllowed": True,
        "blockReason": "",
        "evidenceUsed": chosen["evidenceUsed"],
        "confidence": chosen["confidence"],
        "titleInferredDept": title_department,
        "departmentChangeReferenceField": chosen["referenceField"],
        "departmentChangeReferenceValue": chosen["referenceValue"],
        "departmentChangePrimaryReason": chosen["primaryReason"],
        "departmentChangeReasonTrace": chosen["reasonTrace"],
    }


def map_local_ac_department(
    emp,
    current_ad_department: str = "",
    manager_department: str = "",
) -> str:
    """Backward-compatible department mapper that returns only the chosen department."""
    resolved = resolve_local_ac_department(
        emp,
        current_ad_department=current_ad_department,
        manager_department=manager_department,
    )
    mapped = resolved.get("proposedDepartmentV2")
    if mapped:
        return mapped
    return "Administration"


__all__ = [
    "infer_department_from_title",
    "map_local_ac_department",
    "normalize_department_name",
    "resolve_local_ac_department",
]

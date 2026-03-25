"""Compatibility facade for department candidate helpers."""

from .candidate_mapping import (
    admin_assignment_allowed,
    is_customer_service_assigned_dept,
    is_explicit_admin_assigned_dept,
    make_candidate,
    map_signal_candidates,
)
from .candidate_selection import fallback_from_context, is_low_confidence_candidate, pick_best_candidate

__all__ = [
    "admin_assignment_allowed",
    "fallback_from_context",
    "is_customer_service_assigned_dept",
    "is_explicit_admin_assigned_dept",
    "is_low_confidence_candidate",
    "make_candidate",
    "map_signal_candidates",
    "pick_best_candidate",
]

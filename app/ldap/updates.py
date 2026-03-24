"""Compatibility wrapper for LDAP update helpers."""

from __future__ import annotations

from .modify import apply_ldap_modifications
from .planning import (
    ACCOUNTDISABLE_FLAG,
    build_update_attributes,
    diff_update_attributes,
    filter_blocked_update_changes,
    is_email_identifier_attribute,
    normalize_department_for_compare,
    plan_update_attributes,
)

__all__ = [
    "ACCOUNTDISABLE_FLAG",
    "apply_ldap_modifications",
    "build_update_attributes",
    "diff_update_attributes",
    "filter_blocked_update_changes",
    "is_email_identifier_attribute",
    "normalize_department_for_compare",
    "plan_update_attributes",
]

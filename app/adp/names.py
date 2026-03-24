"""Name extraction helpers for ADP worker payloads."""

from __future__ import annotations

from typing import Any


def _clean_name_part(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def get_legal_first_last(person: dict) -> tuple[str, str]:
    """Return legal first and last name pair."""
    if not isinstance(person, dict):
        return "", ""
    legal = person.get("legalName", {})
    if not isinstance(legal, dict):
        return "", ""
    return _clean_name_part(legal.get("givenName")), _clean_name_part(legal.get("familyName1"))


def get_preferred_first_last(person: dict) -> tuple[str, str]:
    """Return preferred first and last name pair."""
    if not isinstance(person, dict):
        return "", ""
    preferred = person.get("preferredName", {})
    if not isinstance(preferred, dict):
        return "", ""
    return _clean_name_part(preferred.get("givenName")), _clean_name_part(preferred.get("familyName1"))


def get_display_name(person: dict) -> str:
    """Return preferred full name when complete, otherwise legal full name."""
    preferred_first, preferred_last = get_preferred_first_last(person)
    if preferred_first and preferred_last:
        return f"{preferred_first} {preferred_last}".strip()
    legal_first, legal_last = get_legal_first_last(person)
    return f"{legal_first} {legal_last}".strip()


def get_first_last(person: dict) -> tuple[str, str]:
    """Backward-compatible helper returning legal first and last."""
    return get_legal_first_last(person)

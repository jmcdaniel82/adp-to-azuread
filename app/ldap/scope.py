"""Write-scope guardrails for LDAP add and modify operations."""

from __future__ import annotations


def normalize_dn(dn: str) -> str:
    """Return a normalized DN string for suffix comparisons."""
    return ",".join(part.strip().lower() for part in str(dn).split(",") if part.strip())


def is_dn_within_allowed_write_bases(dn: str, allowed_write_bases: tuple[str, ...]) -> bool:
    """Return True when the target DN sits under one of the allowed base DNs."""
    if not allowed_write_bases:
        return True

    normalized_dn = normalize_dn(dn)
    for base in allowed_write_bases:
        normalized_base = normalize_dn(base)
        if not normalized_base:
            continue
        if normalized_dn == normalized_base or normalized_dn.endswith(f",{normalized_base}"):
            return True
    return False


def ensure_write_scope(dn: str, allowed_write_bases: tuple[str, ...], *, operation: str) -> None:
    """Raise when an LDAP write target falls outside the configured write scope."""
    if is_dn_within_allowed_write_bases(dn, allowed_write_bases):
        return
    allowed_text = ", ".join(allowed_write_bases) or "<unbounded>"
    raise PermissionError(
        f"Blocked LDAP {operation} outside allowed write bases: dn='{dn}' allowed='{allowed_text}'"
    )


__all__ = ["ensure_write_scope", "is_dn_within_allowed_write_bases", "normalize_dn"]

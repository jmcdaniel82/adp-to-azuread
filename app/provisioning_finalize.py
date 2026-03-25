"""Provisioning account finalization and reconciliation helpers."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

from ldap3 import MODIFY_REPLACE

from .adp import generate_password
from .reporting import inc_stat


@dataclass(frozen=True)
class ProvisioningIncompleteAccount:
    """One created AD object that still needs operator or follow-up reconciliation."""

    employee_id: str
    dn: str
    state: str
    error: str


@dataclass(frozen=True)
class FinalizeCreatedUserResult:
    """Result of the password-set and enablement phase."""

    conn: Any
    incomplete_account: ProvisioningIncompleteAccount | None = None


def finalize_created_user_account(
    conn: Any,
    dn: str,
    *,
    employee_id: str,
    summary_stats: Optional[dict[str, int]] = None,
    password_generator: Callable[[], str] = generate_password,
) -> FinalizeCreatedUserResult:
    """Set the initial password and enable the created account."""
    password = password_generator()
    try:
        conn.extend.microsoft.modify_password(dn, password)
        conn.modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
        conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [512])]})
        logging.info(f"Account enabled and password set for {dn}")
        return FinalizeCreatedUserResult(conn=conn)
    except Exception as exc:
        inc_stat(summary_stats, "password_failures")
        inc_stat(summary_stats, "incomplete_accounts")
        error_message = str(exc)
        logging.error(f"Password or enable failed for {dn}: {error_message}")
        return FinalizeCreatedUserResult(
            conn=conn,
            incomplete_account=ProvisioningIncompleteAccount(
                employee_id=employee_id,
                dn=dn,
                state="created_incomplete",
                error=error_message,
            ),
        )


__all__ = [
    "FinalizeCreatedUserResult",
    "ProvisioningIncompleteAccount",
    "finalize_created_user_account",
]

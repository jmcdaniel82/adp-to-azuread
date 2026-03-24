"""LDAP modify transport helpers."""

from __future__ import annotations

import logging
from typing import Optional

from ldap3 import Connection

from .connection import format_ldap_error, is_bind_lost_result, safe_unbind
from .planning import filter_blocked_update_changes


def apply_ldap_modifications(conn, dn: str, changes: dict, conn_factory=None) -> Optional[Connection]:
    """Apply LDAP modify ops with bind-loss recovery."""
    filtered_changes = filter_blocked_update_changes(changes, dn)
    if not filtered_changes:
        return conn
    try:
        if conn.modify(dn, filtered_changes):
            return conn
    except Exception as exc:
        logging.error(f"Modify raised exception for {dn}: {exc}")
        if conn_factory:
            try:
                safe_unbind(conn, f"modify exception for {dn}")
                conn = conn_factory()
                if conn.modify(dn, filtered_changes):
                    return conn
            except Exception as reconnect_error:
                logging.error(f"Reconnect after modify exception failed for {dn}: {reconnect_error}")
        return conn

    result = conn.result or {}
    if is_bind_lost_result(result):
        logging.warning(f"Modify failed for {dn} (bind lost); attempting rebind")
        try:
            if conn.rebind() and conn.modify(dn, filtered_changes):
                return conn
        except Exception as exc:
            logging.error(f"Rebind failed during modify: {exc}")
        if conn_factory:
            logging.warning(f"Reconnecting LDAP after modify bind loss for {dn}")
            try:
                safe_unbind(conn, f"modify bind-loss for {dn}")
                conn = conn_factory()
                if conn.modify(dn, filtered_changes):
                    return conn
            except Exception as exc:
                logging.error(f"Reconnect failed during modify: {exc}")
        logging.error(f"Modify failed for {dn}: {format_ldap_error(conn)}")
        return conn
    logging.error(f"Modify failed for {dn}: {conn.result}")
    return conn


__all__ = ["apply_ldap_modifications"]

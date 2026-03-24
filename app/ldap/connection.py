"""LDAP connection lifecycle and transport helpers."""

from __future__ import annotations

import logging
import socket
import ssl
from typing import Callable

from ldap3 import NTLM, Connection, Server, Tls


def log_ldap_target_details(context: str, host: str, ca_bundle: str, port: int = 636) -> None:
    """Log LDAP target host and DNS resolution details for troubleshooting."""
    logging.info(
        f"{context} LDAP target host='{host}' port={port} use_ssl=True "
        f"tls_version=TLSv1_2 ca_bundle='{ca_bundle}'"
    )
    if not host:
        return
    try:
        resolved = sorted(str(item[4][0]) for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        if resolved:
            logging.info(f"{context} LDAP DNS '{host}' resolved to: {', '.join(resolved)}")
    except Exception as exc:
        logging.warning(f"{context} LDAP DNS resolution failed for '{host}': {exc}")


def build_tls_config(ca_bundle: str, tls_version: int = ssl.PROTOCOL_TLSv1_2) -> Tls:
    """Build TLS config for secure LDAP connections."""
    return Tls(ca_certs_file=ca_bundle, validate=ssl.CERT_REQUIRED, version=tls_version)


def create_ldap_server(
    host: str, ca_bundle: str, *, port: int = 636, tls_version: int = ssl.PROTOCOL_TLSv1_2
) -> Server:
    """Create LDAP server object configured for LDAPS."""
    tls = build_tls_config(ca_bundle, tls_version=tls_version)
    return Server(host, port=port, use_ssl=True, tls=tls, get_info=None)


def make_conn_factory(
    server: Server, user: str, password: str, context_label: str
) -> Callable[[], Connection]:
    """Create a reusable LDAP bound-connection factory."""

    def _factory() -> Connection:
        connection = Connection(
            server,
            user=user,
            password=password,
            authentication=NTLM,
            auto_bind=True,
        )
        logging.info(f"{context_label} LDAP bind established: {format_ldap_error(connection)}")
        return connection

    return _factory


def format_ldap_error(conn) -> str:
    """Format key LDAP connection/result diagnostics as one line."""
    if conn is None:
        return "connection=None"
    parts: list[str] = []
    result = getattr(conn, "result", None) or {}
    if result:
        code = result.get("result")
        desc = result.get("description")
        message = result.get("message")
        result_type = result.get("type")
        dn = result.get("dn")
        referrals = result.get("referrals")
        if code is not None or desc:
            parts.append(f"result={code} description={desc}")
        if message:
            parts.append(f"message={message}")
        if result_type:
            parts.append(f"type={result_type}")
        if dn:
            parts.append(f"dn={dn}")
        if referrals:
            parts.append(f"referrals={referrals}")
    last_error = getattr(conn, "last_error", None)
    if last_error:
        parts.append(f"last_error={last_error}")
    bound = getattr(conn, "bound", None)
    if bound is not None:
        parts.append(f"bound={bound}")
    closed = getattr(conn, "closed", None)
    if closed is not None:
        parts.append(f"closed={closed}")
    server = getattr(conn, "server", None)
    if server is not None:
        host = getattr(server, "host", None)
        port = getattr(server, "port", None)
        ssl_enabled = getattr(server, "ssl", None)
        parts.append(f"server={host}:{port} ssl={ssl_enabled}")
    return "; ".join(parts) if parts else "no ldap error details"


def is_bind_lost_result(result: dict) -> bool:
    """Detect AD bind-lost result payload."""
    payload = result or {}
    message = str(payload.get("message") or "").lower()
    return payload.get("result") == 1 and "successful bind must be completed" in message


def safe_unbind(conn, context: str) -> None:
    """Unbind LDAP connection without raising."""
    if not conn:
        return
    try:
        conn.unbind()
    except Exception as exc:
        logging.warning(f"LDAP unbind failed during {context}: {exc}")

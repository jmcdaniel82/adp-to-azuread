"""LDAP connection lifecycle and transport helpers."""

from __future__ import annotations

import logging
import socket
import ssl
from threading import Lock
from typing import Callable

from ldap3 import NTLM, Connection, Server, Tls


class _LdapConnectionPool:
    """Small LDAP connection pool that works with ldap3 public APIs."""

    def __init__(
        self,
        server: Server,
        user: str,
        password: str,
        context_label: str,
        *,
        min_size: int,
        max_size: int,
    ) -> None:
        self.server = server
        self.user = user
        self.password = password
        self.context_label = context_label
        self.min_size = max(1, min_size)
        self.max_size = max(self.min_size, max_size)
        self._available: list[Connection] = []
        self._checked_out = 0
        self._lock = Lock()

        for _ in range(self.min_size):
            self._available.append(self._create_connection())

        logging.info(
            f"{self.context_label} LDAP pool created: min_size={self.min_size} max_size={self.max_size}"
        )

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._available) + self._checked_out

    @property
    def active(self) -> int:
        with self._lock:
            return self._checked_out

    def _create_connection(self) -> Connection:
        connection = Connection(
            self.server,
            user=self.user,
            password=self.password,
            authentication=NTLM,
            auto_bind=True,
        )
        logging.info(f"{self.context_label} LDAP bind established: {format_ldap_error(connection)}")
        return connection

    def acquire(self) -> "_PooledLdapConnection":
        connection: Connection | None = None
        create_new = False
        with self._lock:
            while self._available:
                candidate = self._available.pop()
                if getattr(candidate, "closed", False):
                    continue
                connection = candidate
                self._checked_out += 1
                break
            if connection is None:
                total_size = len(self._available) + self._checked_out
                if total_size < self.max_size:
                    self._checked_out += 1
                    create_new = True
                else:
                    raise RuntimeError(f"{self.context_label} LDAP pool exhausted")

        if create_new:
            try:
                connection = self._create_connection()
            except Exception:
                with self._lock:
                    self._checked_out = max(0, self._checked_out - 1)
                raise

        pool_info = f"pool_size={self.size} active={self.active}"
        logging.debug(f"{self.context_label} connection from pool: {pool_info}")
        return _PooledLdapConnection(self, connection)

    def release(self, connection: Connection | None, *, discard: bool) -> None:
        if connection is None:
            return

        if discard or getattr(connection, "closed", False):
            try:
                if getattr(connection, "bound", False):
                    connection.unbind()
            except Exception as exc:
                logging.warning(f"{self.context_label} pooled LDAP discard failed: {exc}")
            finally:
                with self._lock:
                    self._checked_out = max(0, self._checked_out - 1)
            return

        with self._lock:
            self._available.append(connection)
            self._checked_out = max(0, self._checked_out - 1)

    def close_available(self) -> None:
        with self._lock:
            available = list(self._available)
            self._available.clear()
        for connection in available:
            try:
                if getattr(connection, "bound", False):
                    connection.unbind()
            except Exception as exc:
                logging.warning(f"{self.context_label} pooled LDAP cleanup failed: {exc}")

    def __del__(self) -> None:
        try:
            self.close_available()
        except Exception:
            return


class _PooledLdapConnection:
    """Connection wrapper that returns LDAP connections to the pool on unbind."""

    def __init__(self, pool: _LdapConnectionPool, connection: Connection) -> None:
        self._pool = pool
        self._connection = connection
        self._released = False

    def release_to_pool(self, *, discard: bool = False) -> None:
        if self._released:
            return
        self._pool.release(self._connection, discard=discard)
        self._connection = None
        self._released = True

    def unbind(self) -> bool:
        self.release_to_pool(discard=False)
        return True

    def __getattr__(self, name: str):
        if self._released or self._connection is None:
            raise AttributeError(f"Pooled LDAP connection is no longer active: {name}")
        return getattr(self._connection, name)


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


def make_pooled_conn_factory(
    server: Server,
    user: str,
    password: str,
    context_label: str,
    *,
    min_pool_size: int = 2,
    max_pool_size: int = 10,
) -> Callable[[], Connection]:
    """Create a pooled LDAP connection factory to reduce bind/unbind overhead.
    
    Args:
        server: LDAP server object
        user: Bind user DN
        password: Bind password
        context_label: Label for logging (e.g., 'Provision', 'Update', 'Diagnostics')
        min_pool_size: Minimum connections to maintain in pool
        max_pool_size: Maximum connections allowed in pool
    
    Returns:
        Factory function that returns pooled connections
    """
    pool = _LdapConnectionPool(
        server,
        user,
        password,
        context_label,
        min_size=min_pool_size,
        max_size=max_pool_size,
    )

    def _pooled_factory() -> Connection:
        return pool.acquire()

    return _pooled_factory


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
        release_to_pool = getattr(conn, "release_to_pool", None)
        if callable(release_to_pool):
            discard_tokens = ("exception", "bind-loss", "constraint", "error")
            discard = any(token in context.lower() for token in discard_tokens)
            release_to_pool(discard=discard)
        else:
            conn.unbind()
    except Exception as exc:
        logging.warning(f"LDAP unbind failed during {context}: {exc}")

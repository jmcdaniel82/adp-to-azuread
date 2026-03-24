"""Protocol-style interfaces for orchestration dependencies."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Protocol

from ..models import LdapSettings


@dataclass(frozen=True)
class DirectoryContext:
    """Opened LDAP connection plus the settings/context needed by the caller."""

    conn: Any
    settings: LdapSettings
    conn_factory: Callable[[], Any]


@dataclass(frozen=True)
class DirectoryLookup:
    """Result of a directory lookup keyed by one identity attribute."""

    found: bool
    entry: Any | None
    result: dict[str, Any]


class WorkerProvider(Protocol):
    """Fetch and post-process ADP workers for orchestration flows."""

    def fetch_workers(self, *, context: str) -> list[dict]: ...

    def dedupe_workers(self, workers: list[dict], *, context: str) -> list[dict]: ...

    def log_duplicate_profiles(self, workers: list[dict], *, context: str) -> None: ...


class DirectoryGateway(Protocol):
    """Open and close LDAP connections for orchestration flows."""

    def open_directory(
        self,
        *,
        context: str,
        require_create_base: bool,
        tls_version: int | None = None,
    ) -> DirectoryContext: ...

    def find_user_by_employee_id(
        self,
        directory: DirectoryContext,
        employee_id: str,
        *,
        attributes: list[str],
        search_scope: int = 2,
    ) -> DirectoryLookup: ...

    def get_department_by_dn(
        self,
        directory: DirectoryContext,
        dn: str,
    ) -> str: ...

    def apply_changes(
        self,
        directory: DirectoryContext,
        dn: str,
        changes: dict,
    ) -> DirectoryContext | None: ...

    def close(self, conn: Any, *, context: str) -> None: ...


class MailGateway(Protocol):
    """Send report payloads through the configured transport."""

    def send_report(
        self,
        settings: Any,
        *,
        report_date: datetime,
        csv_content: str,
        row_count: int,
    ) -> None: ...

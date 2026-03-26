"""Default service adapters built from existing helper functions."""

from __future__ import annotations

import os
import ssl
from typing import Any, Callable, Optional

from ..models import LdapSettings
from ..telemetry import StructuredLogTelemetrySink
from .interfaces import DirectoryContext, DirectoryGateway, DirectoryLookup, MailGateway, WorkerProvider


class DefaultWorkerProvider(WorkerProvider):
    """Worker provider backed by the existing ADP helper functions."""

    def __init__(
        self,
        *,
        get_token: Callable[[], Optional[str]],
        get_workers: Callable[[str], Optional[list[dict]]],
        dedupe_workers: Callable[[list[dict], str], list[dict]],
        log_duplicate_profiles: Callable[[list[dict], str], None],
    ) -> None:
        self._get_token = get_token
        self._get_workers = get_workers
        self._dedupe_workers = dedupe_workers
        self._log_duplicate_profiles = log_duplicate_profiles

    def fetch_workers(self, *, context: str) -> list[dict]:
        token = self._get_token()
        if not token:
            raise RuntimeError(f"Failed to retrieve ADP token for {context}.")
        workers = self._get_workers(token)
        if workers is None:
            raise RuntimeError(f"Failed to retrieve ADP employees for {context}.")
        return workers

    def dedupe_workers(self, workers: list[dict], *, context: str) -> list[dict]:
        return self._dedupe_workers(workers, context)

    def log_duplicate_profiles(self, workers: list[dict], *, context: str) -> None:
        self._log_duplicate_profiles(workers, context)


class DefaultDirectoryGateway(DirectoryGateway):
    """Directory gateway backed by the existing LDAP helper functions."""

    def __init__(
        self,
        *,
        validate_settings: Callable[[bool], list[str]],
        get_settings: Callable[[bool], LdapSettings],
        log_target_details: Callable[..., None],
        create_server: Callable[..., Any],
        make_conn_factory: Callable[..., Callable[[], Any]],
        get_department_by_dn: Callable[[Any, str], str],
        apply_changes: Callable[..., Any],
        safe_unbind: Callable[[Any, str], None],
    ) -> None:
        self._validate_settings = validate_settings
        self._get_settings = get_settings
        self._log_target_details = log_target_details
        self._create_server = create_server
        self._make_conn_factory = make_conn_factory
        self._get_department_by_dn = get_department_by_dn
        self._apply_changes = apply_changes
        self._safe_unbind = safe_unbind

    def open_directory(
        self,
        *,
        context: str,
        require_create_base: bool,
        tls_version: int | None = None,
    ) -> DirectoryContext:
        missing = self._validate_settings(require_create_base)
        if missing:
            raise RuntimeError(f"Missing LDAP configuration for {context}: {', '.join(missing)}")

        settings = self._get_settings(require_create_base)
        if not os.path.isfile(settings.ca_bundle_path):
            raise RuntimeError(f"CA bundle not found for {context}: {settings.ca_bundle_path}")

        self._log_target_details(context, settings.server, settings.ca_bundle_path)
        server = self._create_server(
            settings.server,
            settings.ca_bundle_path,
            tls_version=tls_version or ssl.PROTOCOL_TLSv1_2,
        )
        conn_factory = self._make_conn_factory(server, settings.user, settings.password, context)
        try:
            conn = conn_factory()
        except Exception as exc:
            raise RuntimeError(f"Failed to connect to LDAP server for {context}.") from exc
        return DirectoryContext(conn=conn, settings=settings, conn_factory=conn_factory)

    def find_user_by_employee_id(
        self,
        directory: DirectoryContext,
        employee_id: str,
        *,
        attributes: list[str],
        search_scope: int = 2,
    ) -> DirectoryLookup:
        from ldap3.utils.conv import escape_filter_chars
        
        # Escape employee_id to prevent LDAP injection
        escaped_id = escape_filter_chars(employee_id)
        found = directory.conn.search(
            directory.settings.search_base,
            f"(employeeID={escaped_id})",
            attributes=attributes,
            search_scope=search_scope,
        )
        entry = directory.conn.entries[0] if getattr(directory.conn, "entries", None) else None
        result = getattr(directory.conn, "result", None) or {}
        return DirectoryLookup(found=bool(found), entry=entry, result=result)

    def get_department_by_dn(
        self,
        directory: DirectoryContext,
        dn: str,
    ) -> str:
        return self._get_department_by_dn(directory.conn, dn)

    def apply_changes(
        self,
        directory: DirectoryContext,
        dn: str,
        changes: dict,
    ) -> DirectoryContext | None:
        conn = self._apply_changes(
            directory.conn,
            dn,
            changes,
            directory.conn_factory,
            allowed_write_bases=directory.settings.allowed_write_bases,
        )
        if not conn:
            return None
        return DirectoryContext(
            conn=conn,
            settings=directory.settings,
            conn_factory=directory.conn_factory,
        )

    def close(self, conn: Any, *, context: str) -> None:
        self._safe_unbind(conn, context)


class DefaultMailGateway(MailGateway):
    """Mail gateway backed by the existing SMTP helper function."""

    def __init__(
        self,
        *,
        send_report_email: Callable[..., None],
    ) -> None:
        self._send_report_email = send_report_email

    def send_report(
        self,
        settings: Any,
        *,
        report_date,
        csv_content: str,
        row_count: int,
    ) -> None:
        self._send_report_email(
            settings,
            report_date=report_date,
            csv_content=csv_content,
            row_count=row_count,
        )


def build_telemetry_sink() -> StructuredLogTelemetrySink:
    """Build the default structured-log telemetry sink."""
    return StructuredLogTelemetrySink()

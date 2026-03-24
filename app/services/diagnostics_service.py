"""Diagnostics data service that isolates route logic from transport helpers."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..diagnostics import (
    build_department_diff_payload,
    build_recent_hires_payload,
    build_summary_payload,
    build_worker_snapshot,
    find_worker_snapshot,
)


class DiagnosticsDataService:
    """Read and project diagnostics data through explicit providers."""

    def __init__(
        self,
        *,
        worker_provider,
        fetch_department_map,
    ) -> None:
        self._worker_provider = worker_provider
        self._fetch_department_map = fetch_department_map

    def fetch_workers(self) -> list[dict[str, Any]]:
        return self._worker_provider.fetch_workers(context="diagnostics")

    def build_worker_snapshot(self, emp: dict[str, Any]) -> dict[str, Any] | None:
        return build_worker_snapshot(emp)

    def find_worker_snapshot(
        self,
        adp_employees: list[dict[str, Any]],
        employee_id: str,
    ) -> dict[str, Any] | None:
        return find_worker_snapshot(adp_employees, employee_id)

    def build_department_diff_payload(
        self,
        adp_employees: list[dict[str, Any]],
        ldap_map: dict[str, str],
    ) -> dict[str, Any]:
        return build_department_diff_payload(adp_employees, ldap_map)

    def build_summary_payload(
        self,
        adp_employees: list[dict[str, Any]],
        ldap_map: dict[str, str],
    ) -> dict[str, Any]:
        return build_summary_payload(adp_employees, ldap_map)

    def build_recent_hires_payload(
        self,
        adp_employees: list[dict[str, Any]],
        limit: int,
    ) -> dict[str, Any]:
        return build_recent_hires_payload(adp_employees, limit)

    def load_parallel_sources(self) -> tuple[list[dict[str, Any]], dict[str, str]]:
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_adp = executor.submit(self.fetch_workers)
            future_ldap = executor.submit(self._fetch_department_map)
            return future_adp.result(), future_ldap.result()

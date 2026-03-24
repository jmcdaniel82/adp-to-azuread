"""Diagnostics data service that isolates route logic from transport helpers."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..adp_client import (
    extract_assignment_field,
    extract_business_title,
    extract_company,
    extract_department,
    extract_employee_id,
    get_display_name,
    get_hire_date,
    get_legal_first_last,
    get_preferred_first_last,
    get_status,
    get_termination_date,
    normalize_dept,
    normalize_id,
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
        try:
            person = emp.get("person", {})
            legal_first, legal_last = get_legal_first_last(person)
            preferred_first, preferred_last = get_preferred_first_last(person)
            return {
                "employeeId": extract_employee_id(emp),
                "status": get_status(emp),
                "displayName": get_display_name(person),
                "legalGivenName": legal_first,
                "legalFamilyName": legal_last,
                "preferredGivenName": preferred_first,
                "preferredFamilyName": preferred_last,
                "jobTitle": extract_business_title(emp) or extract_assignment_field(emp, "jobTitle"),
                "company": extract_company(emp),
                "department": extract_department(emp),
                "hireDate": get_hire_date(emp),
                "terminationDate": get_termination_date(emp),
            }
        except Exception as exc:
            logging.warning(f"Skipping malformed diagnostics worker record: {exc}")
            return None

    def build_department_diff_payload(
        self,
        adp_employees: list[dict[str, Any]],
        ldap_map: dict[str, str],
    ) -> dict[str, Any]:
        adp_depts = {
            normalize_dept(extract_department(emp)) for emp in adp_employees if extract_department(emp)
        }
        ad_depts = set(ldap_map.values())
        ids_adp = {
            normalize_id(extract_employee_id(emp)) for emp in adp_employees if extract_employee_id(emp)
        }
        ids_ad = set(ldap_map.keys())
        missing_in_ad = sorted(list(ids_adp - ids_ad))
        missing_in_adp = sorted(list(ids_ad - ids_adp))

        dept_pairs: set[tuple[str, str]] = set()
        for emp in adp_employees:
            try:
                emp_id = normalize_id(extract_employee_id(emp))
                if not emp_id:
                    continue
                adp_dept = normalize_dept(extract_department(emp))
                if not adp_dept:
                    continue
                ad_dept = ldap_map.get(emp_id)
                if not ad_dept:
                    continue
                dept_pairs.add((adp_dept, ad_dept))
            except Exception as exc:
                logging.warning(f"Skipping malformed diagnostics worker record: {exc}")

        return {
            "pairs": sorted(list(dept_pairs)),
            "adpDepartments": sorted(list(adp_depts)),
            "adDepartments": sorted(list(ad_depts)),
            "adpOnlyIDs": missing_in_ad,
            "adOnlyIDs": missing_in_adp,
        }

    def load_parallel_sources(self) -> tuple[list[dict[str, Any]], dict[str, str]]:
        with ThreadPoolExecutor(max_workers=2) as executor:
            future_adp = executor.submit(self.fetch_workers)
            future_ldap = executor.submit(self._fetch_department_map)
            return future_adp.result(), future_ldap.result()

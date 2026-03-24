"""Compatibility wrapper for ADP helpers.

The implementation is split across :mod:`app.adp` submodules so orchestration
code can depend on smaller, focused units while existing imports remain stable.
"""

from __future__ import annotations

from .adp import (
    _parse_datetime_silent,
    _request_with_retries,
    build_ad_country_attributes,
    dedupe_workers_by_employee_id,
    extract_assignment_field,
    extract_business_title,
    extract_company,
    extract_department,
    extract_employee_id,
    extract_last_updated,
    extract_manager_id,
    extract_state_from_work,
    extract_work_address_field,
    format_start_date_for_log,
    generate_password,
    get_adp_employees,
    get_adp_token,
    get_display_name,
    get_first_last,
    get_hire_date,
    get_legal_first_last,
    get_preferred_first_last,
    get_status,
    get_termination_date,
    get_user_account_control,
    is_terminated_employee,
    log_potential_duplicate_profiles,
    normalize_dept,
    normalize_id,
    parse_datetime,
    sanitize_string_for_sam,
)
from .adp import api as _api

# Preserve monkeypatch targets used by the test suite.
requests = _api.requests
time = _api.time

__all__ = [
    "_parse_datetime_silent",
    "_request_with_retries",
    "build_ad_country_attributes",
    "dedupe_workers_by_employee_id",
    "extract_assignment_field",
    "extract_business_title",
    "extract_company",
    "extract_department",
    "extract_employee_id",
    "extract_last_updated",
    "extract_manager_id",
    "extract_state_from_work",
    "extract_work_address_field",
    "format_start_date_for_log",
    "generate_password",
    "get_adp_employees",
    "get_adp_token",
    "get_display_name",
    "get_first_last",
    "get_hire_date",
    "get_legal_first_last",
    "get_preferred_first_last",
    "get_status",
    "get_termination_date",
    "get_user_account_control",
    "is_terminated_employee",
    "log_potential_duplicate_profiles",
    "normalize_dept",
    "normalize_id",
    "parse_datetime",
    "sanitize_string_for_sam",
]

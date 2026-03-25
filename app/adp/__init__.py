"""ADP integration helpers split into focused submodules."""

from .api import _request_with_retries, get_adp_employees, get_adp_token
from .dates import (
    _parse_datetime_silent,
    extract_last_updated,
    format_start_date_for_log,
    get_hire_date,
    get_termination_date,
    parse_datetime,
)
from .dedupe import dedupe_workers_by_employee_id, log_potential_duplicate_profiles
from .department_fields import extract_department, normalize_dept
from .identity import extract_employee_id, normalize_id, sanitize_string_for_sam
from .location_fields import build_ad_country_attributes, extract_state_from_work, extract_work_address_field
from .names import get_display_name, get_first_last, get_legal_first_last, get_preferred_first_last
from .passwords import generate_password
from .status import get_status, get_user_account_control, is_terminated_employee
from .work_assignment import (
    extract_assignment_field,
    extract_business_title,
    extract_company,
    extract_manager_id,
    first_assignment,
)

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
    "first_assignment",
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

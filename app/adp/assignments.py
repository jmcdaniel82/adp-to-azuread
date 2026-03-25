"""Compatibility facade for assignment, department, and location helpers."""

from .department_fields import extract_department, normalize_dept
from .location_fields import build_ad_country_attributes, extract_state_from_work, extract_work_address_field
from .work_assignment import (
    extract_assignment_field,
    extract_business_title,
    extract_company,
    extract_manager_id,
    first_assignment,
)

__all__ = [
    "build_ad_country_attributes",
    "extract_assignment_field",
    "extract_business_title",
    "extract_company",
    "extract_department",
    "extract_manager_id",
    "extract_state_from_work",
    "extract_work_address_field",
    "first_assignment",
    "normalize_dept",
]

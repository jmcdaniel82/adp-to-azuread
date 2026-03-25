"""Location and country mapping helpers for ADP assignments."""

from __future__ import annotations

from ..constants import ADP_COUNTRY_NUMERIC_BY_ALPHA2
from .work_assignment import first_assignment


def build_ad_country_attributes(country_code: str) -> dict:
    """Map ADP country code to AD country attributes."""
    alpha2 = (country_code or "").strip().upper()
    if not alpha2:
        return {"co": None, "c": None, "countryCode": None}
    co_value = "United States" if alpha2 == "US" else alpha2
    return {"co": co_value, "c": alpha2, "countryCode": ADP_COUNTRY_NUMERIC_BY_ALPHA2.get(alpha2)}


def extract_work_address_field(emp: dict, field: str) -> str:
    """Extract field from assigned work location, then fallback to home work location."""
    assignment = first_assignment(emp)
    if not assignment:
        return ""

    assigned_locations = assignment.get("assignedWorkLocations")
    if isinstance(assigned_locations, list) and assigned_locations:
        first_location = assigned_locations[0] if isinstance(assigned_locations[0], dict) else {}
        address = first_location.get("address", {}) if isinstance(first_location, dict) else {}
        value = address.get(field, "") if isinstance(address, dict) else ""
        if value:
            return value

    home_location = assignment.get("homeWorkLocation")
    if isinstance(home_location, dict):
        address = home_location.get("address", {})
        if isinstance(address, dict):
            return address.get(field, "")
    return ""


def extract_state_from_work(emp: dict) -> str:
    """Extract state or province code from assigned location with home fallback."""
    assignment = first_assignment(emp)
    if not assignment:
        return ""

    assigned_locations = assignment.get("assignedWorkLocations")
    if isinstance(assigned_locations, list) and assigned_locations:
        first_location = assigned_locations[0] if isinstance(assigned_locations[0], dict) else {}
        address = first_location.get("address", {}) if isinstance(first_location, dict) else {}
        subdivision = address.get("countrySubdivisionLevel1", {}) if isinstance(address, dict) else {}
        value = subdivision.get("codeValue", "") if isinstance(subdivision, dict) else ""
        if value:
            return value

    home_location = assignment.get("homeWorkLocation")
    if isinstance(home_location, dict):
        address = home_location.get("address", {})
        if isinstance(address, dict):
            subdivision = address.get("countrySubdivisionLevel1", {})
            if isinstance(subdivision, dict):
                return subdivision.get("codeValue", "")
    return ""


__all__ = ["build_ad_country_attributes", "extract_state_from_work", "extract_work_address_field"]

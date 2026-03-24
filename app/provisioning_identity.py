"""Identity and attribute planning helpers for provisioning."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, Optional

from ldap3.utils.dn import escape_rdn

from .adp import (
    build_ad_country_attributes,
    extract_assignment_field,
    extract_business_title,
    extract_company,
    extract_employee_id,
    extract_state_from_work,
    extract_work_address_field,
    get_display_name,
    get_hire_date,
    get_legal_first_last,
    get_user_account_control,
    sanitize_string_for_sam,
)
from .constants import (
    ATTR_CN,
    ATTR_DISPLAY_NAME,
    ATTR_EMPLOYEE_ID,
    ATTR_GIVEN_NAME,
    ATTR_MAIL,
    ATTR_SAM_ACCOUNT_NAME,
    ATTR_SN,
    ATTR_USER_PRINCIPAL_NAME,
)
from .reporting import inc_stat

MANDATORY_ADD_ATTRIBUTES = {
    "objectClass",
    ATTR_CN,
    ATTR_GIVEN_NAME,
    ATTR_SN,
    ATTR_DISPLAY_NAME,
    ATTR_USER_PRINCIPAL_NAME,
    ATTR_MAIL,
    ATTR_SAM_ACCOUNT_NAME,
    ATTR_EMPLOYEE_ID,
    "userAccountControl",
}


@dataclass(frozen=True)
class ProvisioningProfile:
    """Validated worker identity and immutable create-time context."""

    country_attrs: dict[str, Any]
    country_alpha2: str
    legal_first: str
    legal_last: str
    display_name: str
    full_name: str
    emp_id: str
    hire_date: str


@dataclass(frozen=True)
class ProvisioningIdentifiers:
    """Base naming seeds for CN, alias, and sAMAccountName generation."""

    base_sam_raw: str
    base_alias: str
    upn_suffix: str
    cn_root: str


@dataclass(frozen=True)
class AddRequest:
    """Single LDAP add attempt payload."""

    dn: str
    attrs: dict[str, Any]
    cn: str
    sam: str
    alias: str


def build_provisioning_profile(
    user_data: dict,
    summary_stats: Optional[dict[str, int]] = None,
) -> ProvisioningProfile | None:
    """Validate worker fields required to create an AD account."""
    country_attrs = build_ad_country_attributes(extract_work_address_field(user_data, "countryCode"))
    country_alpha2 = country_attrs.get("c") or ""
    if not country_alpha2 or country_alpha2 == "MX":
        inc_stat(summary_stats, "skipped_country")
        logging.info(f"Skipping provisioning for country code '{country_alpha2}'")
        return None

    person = user_data.get("person", {})
    legal_first, legal_last = get_legal_first_last(person)
    display_name = get_display_name(person)
    if not legal_first or not legal_last:
        inc_stat(summary_stats, "skipped_missing_required_fields")
        logging.error("Skipping user with missing required legal name fields for AD givenName/sn")
        return None
    if not display_name:
        inc_stat(summary_stats, "skipped_missing_required_fields")
        logging.error("Skipping user with missing display name (preferred and legal both unavailable)")
        return None

    emp_id = extract_employee_id(user_data)
    if not emp_id:
        inc_stat(summary_stats, "skipped_missing_required_fields")
        logging.warning(
            "Skipping user with missing employee ID: display='%s' legal='%s %s'",
            display_name or "<none>",
            legal_first or "",
            legal_last or "",
        )
        return None

    return ProvisioningProfile(
        country_attrs=country_attrs,
        country_alpha2=country_alpha2,
        legal_first=legal_first,
        legal_last=legal_last,
        display_name=display_name,
        full_name=display_name,
        emp_id=emp_id,
        hire_date=get_hire_date(user_data) or "<no hire date>",
    )


def build_identifier_seeds(
    profile: ProvisioningProfile,
    summary_stats: Optional[dict[str, int]] = None,
    *,
    upn_suffix: str | None = None,
) -> ProvisioningIdentifiers | None:
    """Build the base account identifiers used across add retries."""
    base_sam_raw = sanitize_string_for_sam(profile.legal_first[0].lower() + profile.legal_last.lower())
    if not base_sam_raw:
        inc_stat(summary_stats, "skipped_missing_required_fields")
        logging.warning(
            "Skipping user with invalid sAMAccountName seed: employeeID=%s display='%s' legal='%s %s'",
            profile.emp_id,
            profile.display_name or "<none>",
            profile.legal_first or "",
            profile.legal_last or "",
        )
        return None

    base_alias = sanitize_string_for_sam(profile.legal_first.lower()) + sanitize_string_for_sam(
        profile.legal_last.lower()
    )
    if not base_alias:
        base_alias = base_sam_raw

    employee_cn_token = sanitize_string_for_sam(profile.emp_id) or profile.emp_id.strip()
    raw_upn_suffix = upn_suffix
    if raw_upn_suffix is None:
        raw_upn_suffix = os.getenv("UPN_SUFFIX") or "cfsbrands.com"
    return ProvisioningIdentifiers(
        base_sam_raw=base_sam_raw,
        base_alias=base_alias,
        upn_suffix=raw_upn_suffix.strip().lstrip("@"),
        cn_root=f"{profile.full_name} {employee_cn_token}".strip(),
    )


def numeric_suffix(index: int) -> str:
    """Render the suffix used to resolve naming collisions."""
    return "" if index == 0 else str(index)


def build_sam(base_sam_raw: str, suffix: str) -> str:
    """Build an AD-compliant sAMAccountName with a numeric suffix when needed."""
    if not suffix:
        return base_sam_raw[:10]
    max_base_len = max(0, 10 - len(suffix))
    return f"{base_sam_raw[:max_base_len]}{suffix}"


def classify_account_id_conflicts(message: str) -> set[str]:
    """Classify LDAP constraint messages into retryable identifier buckets."""
    lowered = (message or "").lower()
    conflicts = set()
    if "samaccountname" in lowered:
        conflicts.add("sam")
    if "userprincipalname" in lowered or "mailnickname" in lowered or "proxyaddresses" in lowered:
        conflicts.add("alias")
    return conflicts


def build_base_attributes(
    user_data: dict,
    profile: ProvisioningProfile,
    manager_dn: str | None,
    resolved_department: str | None,
) -> dict[str, Any]:
    """Build the stable LDAP attributes shared by every add retry."""
    return {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        ATTR_GIVEN_NAME: profile.legal_first,
        ATTR_SN: profile.legal_last,
        ATTR_EMPLOYEE_ID: profile.emp_id,
        "title": extract_business_title(user_data) or extract_assignment_field(user_data, "jobTitle"),
        "department": resolved_department,
        "l": extract_work_address_field(user_data, "cityName"),
        "postalCode": extract_work_address_field(user_data, "postalCode"),
        "st": extract_state_from_work(user_data),
        "streetAddress": extract_work_address_field(user_data, "lineOne"),
        "co": profile.country_attrs["co"],
        "c": profile.country_attrs["c"],
        "countryCode": profile.country_attrs["countryCode"],
        "company": extract_company(user_data),
        "manager": manager_dn,
        "userAccountControl": get_user_account_control(user_data),
    }


def build_add_request(
    base_attrs: dict[str, Any],
    profile: ProvisioningProfile,
    identifiers: ProvisioningIdentifiers,
    ldap_create_base: str,
    *,
    cn_index: int,
    sam_index: int,
    alias_index: int,
) -> AddRequest:
    """Build the next LDAP add payload for the current retry state."""
    cn = identifiers.cn_root if cn_index == 0 else f"{identifiers.cn_root} {numeric_suffix(cn_index)}"
    sam = build_sam(identifiers.base_sam_raw, numeric_suffix(sam_index))
    alias = (
        identifiers.base_alias
        if alias_index == 0
        else f"{identifiers.base_alias}{numeric_suffix(alias_index)}"
    )
    attrs = dict(base_attrs)
    attrs.update(
        {
            ATTR_CN: cn,
            ATTR_DISPLAY_NAME: profile.full_name,
            ATTR_USER_PRINCIPAL_NAME: f"{alias}@{identifiers.upn_suffix}",
            ATTR_MAIL: f"{alias}@cfsbrands.com",
            ATTR_SAM_ACCOUNT_NAME: sam,
        }
    )
    final_attrs = {key: value for key, value in attrs.items() if value or key in MANDATORY_ADD_ATTRIBUTES}
    return AddRequest(
        dn=f"CN={escape_rdn(cn)},{ldap_create_base}",
        attrs=final_attrs,
        cn=cn,
        sam=sam,
        alias=alias,
    )

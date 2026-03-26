"""Shared constants for ADP/LDAP synchronization workflows."""

from __future__ import annotations

# HTTP defaults for outbound ADP API traffic.
ADP_HTTP_TIMEOUT_SECONDS = 10
ADP_HTTP_MAX_RETRIES = 3
ADP_HTTP_BACKOFF_SECONDS = 0.75

# LDAP attribute names used across create/update/export logic.
ATTR_CN = "cn"
ATTR_SN = "sn"
ATTR_GIVEN_NAME = "givenName"
ATTR_DISPLAY_NAME = "displayName"
ATTR_EMPLOYEE_ID = "employeeID"
ATTR_USER_PRINCIPAL_NAME = "userPrincipalName"
ATTR_MAIL = "mail"
ATTR_MAIL_NICKNAME = "mailNickname"
ATTR_PROXY_ADDRESSES = "proxyAddresses"
ATTR_TARGET_ADDRESS = "targetAddress"
ATTR_SAM_ACCOUNT_NAME = "sAMAccountName"

# Email-routing identifiers are create-time only and must never be modified by update sync.
EMAIL_IDENTIFIER_UPDATE_DENYLIST = {
    ATTR_MAIL.lower(),
    ATTR_USER_PRINCIPAL_NAME.lower(),
    ATTR_MAIL_NICKNAME.lower(),
    ATTR_PROXY_ADDRESSES.lower(),
    ATTR_TARGET_ADDRESS.lower(),
    "othermailbox",
    "msrtcsip-primaryuseraddress",
}

# Update search intentionally excludes create-time-only routing identifiers.
AD_UPDATE_SEARCH_ATTRIBUTES = [
    "distinguishedName",
    ATTR_EMPLOYEE_ID,
    ATTR_DISPLAY_NAME,
    "title",
    "department",
    "company",
    "l",
    "st",
    "postalCode",
    "streetAddress",
    "co",
    "c",
    "countryCode",
    "manager",
    "userAccountControl",
]

# The bounded attribute set managed by the scheduled update workflow.
UPDATE_MANAGED_ATTRIBUTES = (
    ATTR_DISPLAY_NAME,
    "title",
    "company",
    "department",
    "manager",
    "l",
    "postalCode",
    "st",
    "streetAddress",
    "co",
    "c",
    "countryCode",
    "userAccountControl",
)

# Optional update-field groups used by the scheduled update workflow.
UPDATE_FIELD_GROUPS = {
    "identity": (
        ATTR_DISPLAY_NAME,
        "title",
        "company",
    ),
    "department": ("department",),
    "manager": ("manager",),
    "address": (
        "l",
        "postalCode",
        "st",
        "streetAddress",
        "co",
        "c",
        "countryCode",
    ),
    "status": ("userAccountControl",),
}

ADP_COUNTRY_NUMERIC_BY_ALPHA2 = {
    "US": 840,
    "MX": 484,
    "CA": 124,
}

# Diagnostics endpoint result set limits
DIAGNOSTICS_DEFAULT_RECENT_HIRES_LIMIT = 25
DIAGNOSTICS_MAX_RECENT_HIRES_LIMIT = 100

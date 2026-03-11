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
    "manager",
    "userAccountControl",
]

ADP_COUNTRY_NUMERIC_BY_ALPHA2 = {
    "US": 840,
    "MX": 484,
    "CA": 124,
}

"""Environment/config parsing with defaults and validation."""

from __future__ import annotations

import os
from typing import Iterable

from .models import AdpSettings, LdapSettings, ProvisionJobSettings, UpdateJobSettings
from .security import get_ca_bundle


def env_truthy(name: str, default: bool = False) -> bool:
    """Return True when an environment variable uses a common truthy form."""
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_int_env(name: str, default: int, minimum: int | None = None) -> int:
    """Parse int environment variable with fallback and optional minimum."""
    raw = os.getenv(name, str(default))
    try:
        parsed = int(raw)
    except ValueError:
        parsed = default
    if minimum is not None and parsed < minimum:
        return minimum
    return parsed


def missing_env_vars(names: Iterable[str]) -> list[str]:
    """Return env var names that are missing or empty."""
    return [name for name in names if not os.getenv(name)]


def get_adp_settings() -> AdpSettings:
    """Return typed ADP settings. Caller validates required values."""
    return AdpSettings(
        token_url=os.getenv("ADP_TOKEN_URL", "").strip(),
        employee_url=os.getenv("ADP_EMPLOYEE_URL", "").strip(),
        client_id=os.getenv("ADP_CLIENT_ID", "").strip(),
        client_secret=os.getenv("ADP_CLIENT_SECRET", "").strip(),
    )


def validate_adp_settings() -> list[str]:
    """Validate required ADP settings and return missing variable names."""
    return missing_env_vars(
        [
            "ADP_TOKEN_URL",
            "ADP_EMPLOYEE_URL",
            "ADP_CLIENT_ID",
            "ADP_CLIENT_SECRET",
            "ADP_CERT_PEM",
        ]
    )


def get_ldap_settings(require_create_base: bool = False) -> LdapSettings:
    """Return typed LDAP settings. Caller validates required values."""
    create_base = os.getenv("LDAP_CREATE_BASE", "").strip() or None
    if require_create_base and not create_base:
        create_base = ""
    return LdapSettings(
        server=os.getenv("LDAP_SERVER", "").strip(),
        user=os.getenv("LDAP_USER", "").strip(),
        password=os.getenv("LDAP_PASSWORD", ""),
        search_base=os.getenv("LDAP_SEARCH_BASE", "").strip(),
        create_base=create_base,
        ca_bundle_path=get_ca_bundle(),
    )


def validate_ldap_settings(require_create_base: bool = False) -> list[str]:
    """Validate required LDAP environment keys."""
    names = ["LDAP_SERVER", "LDAP_USER", "LDAP_PASSWORD", "LDAP_SEARCH_BASE"]
    if require_create_base:
        names.append("LDAP_CREATE_BASE")
    return missing_env_vars(names)


def get_update_job_settings() -> UpdateJobSettings:
    """Return typed scheduled-update settings with safe defaults."""
    return UpdateJobSettings(
        dry_run=env_truthy("UPDATE_DRY_RUN", True),
        lookback_days=parse_int_env("UPDATE_LOOKBACK_DAYS", 7),
        include_missing_last_updated=env_truthy("UPDATE_INCLUDE_MISSING_LAST_UPDATED", True),
        log_no_changes=env_truthy("UPDATE_LOG_NO_CHANGES", False),
    )


def get_provision_job_settings() -> ProvisionJobSettings:
    """Return typed scheduled-provision settings with safe defaults."""
    return ProvisionJobSettings(
        hire_lookback_days=parse_int_env("SYNC_HIRE_LOOKBACK_DAYS", 4),
        max_add_retries=parse_int_env("PROVISION_MAX_ADD_RETRIES", 15, minimum=1),
        cn_collision_threshold=parse_int_env("CN_COLLISION_THRESHOLD", 5, minimum=1),
    )

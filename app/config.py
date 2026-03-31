"""Environment/config parsing with defaults and validation."""

from __future__ import annotations

import os
from typing import Iterable

from .constants import UPDATE_FIELD_GROUPS, UPDATE_MANAGED_ATTRIBUTES
from .models import AdpSettings, LdapSettings, ProvisionJobSettings, TermedReportSettings, UpdateJobSettings
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


def parse_csv_env(name: str, default: str = "") -> tuple[str, ...]:
    """Parse a comma-delimited environment variable into trimmed values."""
    raw = os.getenv(name, default)
    return tuple(part.strip() for part in str(raw).split(",") if part.strip())


def _parse_named_csv_env(name: str, valid_values: Iterable[str]) -> tuple[str, ...]:
    """Parse and canonicalize a CSV environment variable against allowed names."""
    canonical_by_normalized = {str(value).strip().lower(): str(value) for value in valid_values}
    parsed_values = parse_csv_env(name)
    canonical_values: list[str] = []
    invalid_values: list[str] = []
    for raw_value in parsed_values:
        canonical_value = canonical_by_normalized.get(raw_value.strip().lower())
        if canonical_value is None:
            invalid_values.append(raw_value)
            continue
        if canonical_value not in canonical_values:
            canonical_values.append(canonical_value)
    if invalid_values:
        valid_list = ", ".join(sorted(canonical_by_normalized.values()))
        invalid_list = ", ".join(invalid_values)
        raise ValueError(f"{name} contains unsupported values: {invalid_list}. Valid values: {valid_list}")
    return tuple(canonical_values)


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
        allowed_write_bases=parse_csv_env("LDAP_ALLOWED_WRITE_BASES"),
    )


def get_ldap_pool_settings() -> tuple[int, int]:
    """Return LDAP connection pool configuration.
    
    Returns:
        Tuple of (min_pool_size, max_pool_size)
    """
    min_size = parse_int_env("LDAP_POOL_MIN_SIZE", 2, minimum=1)
    max_size = parse_int_env("LDAP_POOL_MAX_SIZE", 10, minimum=1)
    # Ensure max >= min
    if max_size < min_size:
        max_size = min_size
    return min_size, max_size


def validate_ldap_settings(require_create_base: bool = False) -> list[str]:
    """Validate required LDAP environment keys."""
    names = ["LDAP_SERVER", "LDAP_USER", "LDAP_PASSWORD", "LDAP_SEARCH_BASE"]
    if require_create_base:
        names.append("LDAP_CREATE_BASE")
    return missing_env_vars(names)


def get_update_job_settings() -> UpdateJobSettings:
    """Return typed scheduled-update settings with scoped live defaults."""
    return UpdateJobSettings(
        dry_run=env_truthy("UPDATE_DRY_RUN", False),
        lookback_days=parse_int_env("UPDATE_LOOKBACK_DAYS", 7),
        include_missing_last_updated=env_truthy("UPDATE_INCLUDE_MISSING_LAST_UPDATED", True),
        log_no_changes=env_truthy("UPDATE_LOG_NO_CHANGES", False),
        enabled_fields=_parse_named_csv_env("UPDATE_ENABLED_FIELDS", UPDATE_MANAGED_ATTRIBUTES),
        enabled_groups=_parse_named_csv_env("UPDATE_ENABLED_GROUPS", UPDATE_FIELD_GROUPS.keys()),
        always_disable_terminated=env_truthy("UPDATE_ALWAYS_DISABLE_TERMINATED", True),
    )


def get_provision_job_settings() -> ProvisionJobSettings:
    """Return typed scheduled-provision settings with safe defaults."""
    return ProvisionJobSettings(
        hire_lookback_days=parse_int_env("SYNC_HIRE_LOOKBACK_DAYS", 4),
        max_add_retries=parse_int_env("PROVISION_MAX_ADD_RETRIES", 15, minimum=1),
        cn_collision_threshold=parse_int_env("CN_COLLISION_THRESHOLD", 5, minimum=1),
    )


def get_termed_report_settings() -> TermedReportSettings:
    """Return typed weekly termed-report settings.
    
    Note: TERMED_REPORT_SMTP_HOST, TERMED_REPORT_FROM_ADDRESS, and TERMED_REPORT_RECIPIENTS
    must be explicitly configured via environment variables. No defaults are provided
    to prevent exposing infrastructure details and email addresses in source code.
    """
    # Validate required settings are provided
    missing = missing_env_vars([
        "TERMED_REPORT_SMTP_HOST",
        "TERMED_REPORT_FROM_ADDRESS",
        "TERMED_REPORT_RECIPIENTS",
    ])
    if missing:
        raise RuntimeError(f"Missing required email configuration: {', '.join(missing)}")
    
    return TermedReportSettings(
        lookback_days=parse_int_env("TERMED_REPORT_LOOKBACK_DAYS", 30, minimum=1),
        smtp_host=os.getenv("TERMED_REPORT_SMTP_HOST", "").strip(),
        smtp_port=parse_int_env("TERMED_REPORT_SMTP_PORT", 25, minimum=1),
        from_address=os.getenv("TERMED_REPORT_FROM_ADDRESS", "").strip(),
        recipients=parse_csv_env("TERMED_REPORT_RECIPIENTS", ""),
        subject=os.getenv("TERMED_REPORT_SUBJECT", "ADP Last 30 Day Termed Report").strip(),
    )

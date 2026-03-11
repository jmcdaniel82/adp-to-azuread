"""Typed models for orchestration and diagnostics payloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, TypedDict


class DepartmentResolutionResult(TypedDict, total=False):
    """Structured result from Department Resolution V2."""

    proposedDepartmentV2: str
    currentDepartment: str
    managerDepartment: str
    changeAllowed: bool
    blockReason: str
    confidence: str
    evidenceUsed: str
    matchedSignals: list[dict]
    departmentChangeReferenceField: str
    departmentChangeReferenceValue: str
    reasonTrace: str


@dataclass(frozen=True)
class LdapSettings:
    """Typed LDAP connection settings."""

    server: str
    user: str
    password: str
    search_base: str
    create_base: Optional[str]
    ca_bundle_path: str


@dataclass(frozen=True)
class AdpSettings:
    """Typed ADP API settings."""

    token_url: str
    employee_url: str
    client_id: str
    client_secret: str
    cert_env: str = "ADP_CERT_PEM"
    key_env: str = "ADP_CERT_KEY"
    ca_bundle_env: str = "ADP_CA_BUNDLE_PATH"


@dataclass(frozen=True)
class UpdateJobSettings:
    """Typed scheduled-update options."""

    dry_run: bool
    lookback_days: int
    include_missing_last_updated: bool
    log_no_changes: bool


@dataclass(frozen=True)
class ProvisionJobSettings:
    """Typed scheduled-provisioning options."""

    hire_lookback_days: int
    max_add_retries: int
    cn_collision_threshold: int

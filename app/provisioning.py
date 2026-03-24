"""Provisioning orchestration wrapper and service builders."""

from __future__ import annotations

from . import provisioning_ops as _provisioning_ops
from .adp import (
    dedupe_workers_by_employee_id,
    get_adp_employees,
    get_adp_token,
    log_potential_duplicate_profiles,
)
from .config import get_ldap_settings, get_provision_job_settings, validate_ldap_settings
from .ldap import (
    apply_ldap_modifications,
    collect_identifier_conflicts,
    create_ldap_server,
    dn_exists_in_create_scope,
    get_department_by_dn,
    log_ldap_target_details,
    make_conn_factory,
    safe_unbind,
)
from .services.defaults import DefaultDirectoryGateway, DefaultWorkerProvider
from .services.provisioning_service import ProvisioningOrchestrator

_is_recent_hire = _provisioning_ops._is_recent_hire


def provision_user_in_ad(*args, **kwargs):
    """Compatibility wrapper that preserves monkeypatch seams on app.provisioning."""
    _provisioning_ops.collect_identifier_conflicts = collect_identifier_conflicts
    _provisioning_ops.dn_exists_in_create_scope = dn_exists_in_create_scope
    return _provisioning_ops.provision_user_in_ad(*args, **kwargs)


def build_worker_provider() -> DefaultWorkerProvider:
    """Build the default ADP-backed worker provider for provisioning."""
    return DefaultWorkerProvider(
        get_token=get_adp_token,
        get_workers=get_adp_employees,
        dedupe_workers=dedupe_workers_by_employee_id,
        log_duplicate_profiles=log_potential_duplicate_profiles,
    )


def build_directory_gateway() -> DefaultDirectoryGateway:
    """Build the default LDAP-backed directory gateway for provisioning."""
    return DefaultDirectoryGateway(
        validate_settings=validate_ldap_settings,
        get_settings=get_ldap_settings,
        log_target_details=log_ldap_target_details,
        create_server=create_ldap_server,
        make_conn_factory=make_conn_factory,
        get_department_by_dn=get_department_by_dn,
        apply_changes=apply_ldap_modifications,
        safe_unbind=safe_unbind,
    )


def build_provisioning_orchestrator() -> ProvisioningOrchestrator:
    """Build the provisioning orchestrator with explicit service dependencies."""
    return ProvisioningOrchestrator(
        worker_provider=build_worker_provider(),
        directory_gateway=build_directory_gateway(),
        provision_user=provision_user_in_ad,
        is_recent_hire=_is_recent_hire,
        settings_getter=get_provision_job_settings,
    )


def run_scheduled_provision_new_hires(mytimer) -> None:
    """Timer-trigger orchestration for scheduled_provision_new_hires."""
    build_provisioning_orchestrator().run(mytimer)


__all__ = [
    "_is_recent_hire",
    "build_directory_gateway",
    "build_provisioning_orchestrator",
    "build_worker_provider",
    "collect_identifier_conflicts",
    "dn_exists_in_create_scope",
    "provision_user_in_ad",
    "run_scheduled_provision_new_hires",
]

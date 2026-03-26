
"""Compatibility wrapper for LDAP helpers.

The implementation is split across :mod:`app.ldap` submodules so orchestration
and diagnostics can depend on more focused units while existing imports remain stable.
"""

from __future__ import annotations

from .ldap import (
    apply_ldap_modifications,
    build_tls_config,
    build_update_attributes,
    collect_identifier_conflicts,
    create_ldap_server,
    diff_update_attributes,
    dn_exists_in_create_scope,
    entry_attr_value,
    filter_blocked_update_changes,
    format_ldap_error,
    get_department_by_dn,
    get_manager_dn,
    is_bind_lost_result,
    is_email_identifier_attribute,
    log_cn_conflict_inventory,
    log_ldap_target_details,
    make_conn_factory,
    make_pooled_conn_factory,
    normalize_department_for_compare,
    plan_update_attributes,
    safe_unbind,
)

__all__ = [
    'apply_ldap_modifications',
    'build_tls_config',
    'build_update_attributes',
    'collect_identifier_conflicts',
    'create_ldap_server',
    'diff_update_attributes',
    'dn_exists_in_create_scope',
    'entry_attr_value',
    'filter_blocked_update_changes',
    'format_ldap_error',
    'get_department_by_dn',
    'get_manager_dn',
    'is_bind_lost_result',
    'is_email_identifier_attribute',
    'log_cn_conflict_inventory',
    'log_ldap_target_details',
    'make_conn_factory',
    'make_pooled_conn_factory',
    'normalize_department_for_compare',
    'plan_update_attributes',
    'safe_unbind',
]

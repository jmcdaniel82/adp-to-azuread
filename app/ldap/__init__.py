
"""LDAP helpers split into focused submodules."""

from .connection import (
    build_tls_config,
    create_ldap_server,
    format_ldap_error,
    is_bind_lost_result,
    log_ldap_target_details,
    make_conn_factory,
    safe_unbind,
)
from .directory import (
    collect_identifier_conflicts,
    dn_exists_in_create_scope,
    entry_attr_value,
    get_department_by_dn,
    get_manager_dn,
    log_cn_conflict_inventory,
)
from .updates import (
    apply_ldap_modifications,
    build_update_attributes,
    diff_update_attributes,
    filter_blocked_update_changes,
    is_email_identifier_attribute,
    normalize_department_for_compare,
    plan_update_attributes,
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
    'normalize_department_for_compare',
    'plan_update_attributes',
    'safe_unbind',
]

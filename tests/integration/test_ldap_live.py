"""Live LDAP smoke tests.

Required env vars:
- `LDAP_SERVER`
- `LDAP_USER`
- `LDAP_PASSWORD`
- `LDAP_SEARCH_BASE`
- `CA_BUNDLE_PATH`

These tests make a real LDAP TLS connection and are skipped unless those values
are present.
"""

from __future__ import annotations

from ldap3 import SUBTREE

from app.config import get_ldap_settings, validate_ldap_settings
from app.ldap_client import create_ldap_server, make_conn_factory, safe_unbind

from ._gating import require_env

require_env("LDAP_SERVER", "LDAP_USER", "LDAP_PASSWORD", "LDAP_SEARCH_BASE", "CA_BUNDLE_PATH")


def test_live_ldap_connectivity_and_search_smoke():
    missing = validate_ldap_settings(require_create_base=False)
    assert missing == []

    settings = get_ldap_settings(require_create_base=False)
    server = create_ldap_server(settings.server, settings.ca_bundle_path)
    conn_factory = make_conn_factory(server, settings.user, settings.password, "integration_smoke")

    conn = conn_factory()
    try:
        assert conn.search(
            settings.search_base,
            "(employeeID=*)",
            search_scope=SUBTREE,
            attributes=["employeeID"],
            size_limit=1,
        )
        assert conn.result is not None
    finally:
        safe_unbind(conn, "integration_ldap_smoke")

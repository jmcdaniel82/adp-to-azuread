"""Reusable live LDAP helpers for non-prod integration tests."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from app.config import get_ldap_settings
from app.ldap import create_ldap_server, make_conn_factory, safe_unbind


def open_live_connection(*, require_create_base: bool) -> tuple[object, object]:
    """Return live LDAP settings and a bound connection."""
    settings = get_ldap_settings(require_create_base=require_create_base)
    server = create_ldap_server(settings.server, settings.ca_bundle_path)
    conn_factory = make_conn_factory(server, settings.user, settings.password, "integration_live")
    return settings, conn_factory()


def integration_employee_id(prefix: str) -> str:
    """Return a unique employee ID for non-prod write-path tests."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"{prefix}{stamp}{uuid4().hex[:4].upper()}"


def make_integration_worker(
    employee_id: str,
    *,
    first_name: str,
    last_name: str,
    job_title: str,
) -> dict:
    """Build a synthetic ADP-style worker payload for write-path tests."""
    return {
        "person": {
            "preferredName": {"givenName": first_name, "familyName1": last_name},
            "legalName": {"givenName": first_name, "familyName1": last_name},
        },
        "customFieldGroup": {
            "stringFields": [
                {
                    "nameCode": {"codeValue": "Business Title"},
                    "stringValue": job_title,
                }
            ]
        },
        "workAssignments": [
            {
                "jobTitle": job_title,
                "assignedWorkLocations": [{"address": {"countryCode": "US", "cityName": "Atlanta"}}],
                "assignedOrganizationalUnits": [],
                "homeOrganizationalUnits": [],
                "occupationalClassifications": [],
            }
        ],
        "workerDates": {"hireDate": "2026-03-01T00:00:00Z"},
        "workerID": {"idValue": employee_id},
    }


def find_entry_by_employee_id(conn, search_base: str, employee_id: str, attributes=None):
    """Return the first LDAP entry for one employee ID when present."""
    conn.search(
        search_base,
        f"(employeeID={employee_id})",
        attributes=attributes or ["distinguishedName", "employeeID", "title"],
    )
    return conn.entries[0] if getattr(conn, "entries", None) else None


def delete_entry_by_dn(conn, dn: str) -> None:
    """Delete one entry and ignore already-deleted cases."""
    if not dn:
        return
    try:
        conn.delete(dn)
    except Exception:
        pass


def close_live_connection(conn, context: str) -> None:
    """Close one live LDAP connection safely."""
    safe_unbind(conn, context)

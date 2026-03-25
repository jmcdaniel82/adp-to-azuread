"""HTTP route handler for diagnostics views."""

from __future__ import annotations

import json
import logging
import os
import ssl
from datetime import date, datetime
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from ldap3 import SUBTREE

from .adp import (
    get_adp_employees,
    get_adp_token,
    normalize_dept,
    normalize_id,
)
from .azure_compat import func
from .config import env_truthy, get_ldap_settings, validate_ldap_settings
from .ldap import (
    create_ldap_server,
    log_ldap_target_details,
    make_conn_factory,
    safe_unbind,
)
from .services.defaults import DefaultWorkerProvider
from .services.diagnostics_service import DiagnosticsDataService

DEFAULT_RECENT_HIRES_LIMIT = 25
MAX_RECENT_HIRES_LIMIT = 100
SUPPORTED_DIAGNOSTICS_VIEWS = {
    "summary",
    "department-diff",
    "worker",
    "recent-hires",
}


def json_converter(value: Any) -> str:
    """Convert non-JSON-native objects to string values."""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def json_response(payload: Any, status_code: int = 200) -> func.HttpResponse:
    """Return JSON content with consistent serialization and content type."""
    return func.HttpResponse(
        json.dumps(payload, default=json_converter, indent=2),
        mimetype="application/json",
        status_code=status_code,
    )


def get_request_params(req: func.HttpRequest) -> dict[str, str]:
    """Read query parameters from Azure HttpRequest or a lightweight test stub."""
    params = getattr(req, "params", None)
    if isinstance(params, dict):
        return {str(key): str(value) for key, value in params.items()}
    url = getattr(req, "url", "")
    if not url:
        return {}
    parsed = parse_qs(urlparse(url).query)
    return {key: values[-1] for key, values in parsed.items() if values}


def get_request_headers(req: func.HttpRequest) -> dict[str, str]:
    """Read request headers from Azure HttpRequest or a lightweight test stub."""
    headers = getattr(req, "headers", None)
    if not headers:
        return {}
    return {str(key).lower(): str(value) for key, value in dict(headers).items()}


def enforce_diagnostics_platform_auth(req: func.HttpRequest) -> func.HttpResponse | None:
    """Require App Service platform auth headers when explicitly enabled."""
    if not env_truthy("DIAGNOSTICS_REQUIRE_APP_SERVICE_AUTH", False):
        return None

    headers = get_request_headers(req)
    if headers.get("x-ms-client-principal") or headers.get("x-ms-client-principal-id"):
        return None

    return json_response(
        {
            "error": "Diagnostics requires platform authentication.",
            "requiredHeader": "X-MS-CLIENT-PRINCIPAL",
        },
        status_code=401,
    )


def fetch_ad_data_task() -> Optional[dict[str, str]]:
    """Read AD employeeID->department map used by diagnostics summary and diff views."""
    missing_ldap = validate_ldap_settings(require_create_base=False)
    if missing_ldap:
        logging.error(f"Missing LDAP configuration for diagnostics: {', '.join(missing_ldap)}")
        return None
    ldap_settings = get_ldap_settings(require_create_base=False)
    if not os.path.isfile(ldap_settings.ca_bundle_path):
        logging.error(f"CA bundle not found for diagnostics at {ldap_settings.ca_bundle_path}")
        return None
    log_ldap_target_details("Diagnostics", ldap_settings.server, ldap_settings.ca_bundle_path)
    server = create_ldap_server(
        ldap_settings.server,
        ldap_settings.ca_bundle_path,
        tls_version=ssl.PROTOCOL_TLS_CLIENT,
    )
    conn_factory = make_conn_factory(server, ldap_settings.user, ldap_settings.password, "Diagnostics")
    try:
        conn = conn_factory()
    except Exception as exc:
        logging.error(f"Failed to connect to LDAP for diagnostics: {exc}")
        return None

    ldap_map: dict[str, str] = {}
    page_size = 500
    cookie = None
    try:
        while True:
            try:
                conn.search(
                    ldap_settings.search_base,
                    "(employeeID=*)",
                    SUBTREE,
                    attributes=["employeeID", "department"],
                    paged_size=page_size,
                    paged_cookie=cookie,
                )
            except Exception as exc:
                logging.error(f"LDAP diagnostics search failed: {exc}")
                return None
            for entry in conn.entries:
                raw_id = entry.employeeID.value
                raw_dept = entry.department.value if entry.department else None
                emp_id = normalize_id(raw_id)
                dept = normalize_dept(raw_dept) if raw_dept else None
                if emp_id and dept:
                    ldap_map[emp_id] = dept
            controls = (conn.result or {}).get("controls", {})
            cookie = controls.get("1.2.840.113556.1.4.319", {}).get("value", {}).get("cookie")
            if not cookie:
                break
    finally:
        safe_unbind(conn, "fetch_ad_data_task completion")
        logging.info("[INFO] LDAP connection closed for diagnostics.")
    return ldap_map


def load_parallel_diagnostics_sources() -> tuple[Optional[list[dict[str, Any]]], Optional[dict[str, str]]]:
    """Fetch ADP workers and LDAP department map in parallel."""
    try:
        return build_diagnostics_service().load_parallel_sources()
    except Exception as exc:
        logging.error(f"Parallel diagnostics data fetch failed: {exc}")
        return None, None


def build_worker_provider() -> DefaultWorkerProvider:
    """Build the default ADP-backed worker provider for diagnostics."""
    return DefaultWorkerProvider(
        get_token=get_adp_token,
        get_workers=get_adp_employees,
        dedupe_workers=lambda workers, context: workers,
        log_duplicate_profiles=lambda workers, context: None,
    )


def build_diagnostics_service() -> DiagnosticsDataService:
    """Build the diagnostics data service with explicit dependencies."""
    return DiagnosticsDataService(
        worker_provider=build_worker_provider(),
        fetch_department_map=fetch_ad_data_task,
    )


def parse_recent_hires_limit(params: dict[str, str]) -> tuple[int, Optional[func.HttpResponse]]:
    """Parse and cap the recent-hires result size."""
    raw_limit = params.get("limit")
    if raw_limit is None:
        return DEFAULT_RECENT_HIRES_LIMIT, None
    try:
        limit = int(raw_limit)
    except (TypeError, ValueError):
        return 0, json_response(
            {
                "error": "Invalid limit. Provide a positive integer.",
                "maxLimit": MAX_RECENT_HIRES_LIMIT,
            },
            status_code=400,
        )
    if limit <= 0:
        return 0, json_response(
            {
                "error": "Invalid limit. Provide a positive integer.",
                "maxLimit": MAX_RECENT_HIRES_LIMIT,
            },
            status_code=400,
        )
    return min(limit, MAX_RECENT_HIRES_LIMIT), None


def diagnostics_handler(req: func.HttpRequest) -> func.HttpResponse:
    """Serve diagnostics views through one route with explicit query modes."""
    auth_error = enforce_diagnostics_platform_auth(req)
    if auth_error is not None:
        return auth_error

    params = get_request_params(req)
    view = params.get("view", "summary").strip().lower()
    logging.info(f"Diagnostics route triggered: view={view}")
    diagnostics_service = build_diagnostics_service()

    if view not in SUPPORTED_DIAGNOSTICS_VIEWS:
        return json_response(
            {
                "error": "Unsupported diagnostics view.",
                "supportedViews": sorted(SUPPORTED_DIAGNOSTICS_VIEWS),
            },
            status_code=400,
        )

    if view in {"summary", "department-diff"}:
        adp_employees, ldap_map = load_parallel_diagnostics_sources()
        if adp_employees is None or ldap_map is None:
            return func.HttpResponse("Diagnostics data fetch error (ADP or AD).", status_code=500)

        if view == "department-diff":
            return json_response(diagnostics_service.build_department_diff_payload(adp_employees, ldap_map))

        return json_response(diagnostics_service.build_summary_payload(adp_employees, ldap_map))

    try:
        adp_employees = diagnostics_service.fetch_workers()
    except Exception:
        return func.HttpResponse("ADP diagnostics fetch failed.", status_code=500)

    if view == "worker":
        employee_id = normalize_id(params.get("employeeId") or "")
        if not employee_id:
            return json_response(
                {"error": "Missing required query parameter: employeeId."},
                status_code=400,
            )
        snapshot = diagnostics_service.find_worker_snapshot(adp_employees, employee_id)
        if snapshot is not None:
            return json_response(snapshot)
        return json_response({"error": "Worker not found.", "employeeId": employee_id}, status_code=404)

    limit, limit_error = parse_recent_hires_limit(params)
    if limit_error is not None:
        return limit_error

    return json_response(diagnostics_service.build_recent_hires_payload(adp_employees, limit))

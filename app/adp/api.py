"""ADP HTTP client helpers for token and workers fetches."""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

import requests

from ..config import get_adp_settings, validate_adp_settings
from ..constants import (
    ADP_HTTP_BACKOFF_SECONDS,
    ADP_HTTP_MAX_RETRIES,
    ADP_HTTP_TIMEOUT_SECONDS,
)
from ..security import ensure_file_from_env, get_adp_ca_bundle


def _request_with_retries(
    method: str,
    url: str,
    *,
    action_label: str,
    max_attempts: int = ADP_HTTP_MAX_RETRIES,
    timeout: int = ADP_HTTP_TIMEOUT_SECONDS,
    retryable_statuses: Optional[set[int]] = None,
    **kwargs: Any,
) -> Optional[Any]:
    """Execute HTTP request with bounded retries for transient failures."""
    retryable = retryable_statuses or {429, 500, 502, 503, 504}
    delay = ADP_HTTP_BACKOFF_SECONDS
    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.request(method, url, timeout=timeout, **kwargs)
        except requests.RequestException as exc:
            if attempt >= max_attempts:
                logging.error(f"{action_label} failed after {attempt} attempts: {exc}")
                return None
            logging.warning(
                f"{action_label} transport error (attempt {attempt}/{max_attempts}): {exc}; retrying"
            )
            time.sleep(delay)
            delay *= 2
            continue
        if response.status_code in retryable:
            if attempt >= max_attempts:
                logging.error(
                    f"{action_label} failed after {attempt} attempts with HTTP "
                    f"{response.status_code}: {response.text}"
                )
                return None
            logging.warning(
                f"{action_label} received retryable HTTP {response.status_code} "
                f"(attempt {attempt}/{max_attempts}); retrying"
            )
            time.sleep(delay)
            delay *= 2
            continue
        return response
    return None


def get_adp_token() -> Optional[str]:
    """Get ADP OAuth token using client credentials and mTLS cert material."""
    missing = validate_adp_settings()
    # Token path does not require ADP_EMPLOYEE_URL, so remove it from token preflight checks.
    missing = [name for name in missing if name != "ADP_EMPLOYEE_URL"]
    if missing:
        logging.error(f"Missing ADP token configuration: {', '.join(missing)}")
        return None
    settings = get_adp_settings()
    token_url = settings.token_url
    client_id = settings.client_id
    client_secret = settings.client_secret
    pem_path = ensure_file_from_env("ADP_CERT_PEM", ".pem")
    key_path = ensure_file_from_env("ADP_CERT_KEY", ".key")
    if not pem_path:
        logging.error("ADP_CERT_PEM environment variable is missing or invalid.")
        return None

    cert_arg: str | tuple[str, str]
    cert_arg = (pem_path, key_path) if key_path else pem_path
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    response = _request_with_retries(
        "POST",
        token_url,
        action_label="ADP token request",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=payload,
        cert=cert_arg,
        verify=get_adp_ca_bundle(),
    )
    if not response:
        return None
    if not response.ok:
        logging.error(f"ADP token request failed (HTTP {response.status_code}): {response.text}")
        return None
    try:
        body = response.json()
    except json.JSONDecodeError:
        logging.error(f"ADP token response was not JSON: {response.text}")
        return None
    token = body.get("access_token")
    if not token:
        logging.error(f"ADP token response missing access_token. Keys={list(body.keys())}")
        return None
    return token


def get_adp_employees(
    token: str, limit: int = 50, offset: int = 0, paginate_all: bool = True
) -> Optional[list[dict]]:
    """Retrieve ADP workers list with pagination."""
    settings = get_adp_settings()
    base_url = settings.employee_url
    if not base_url:
        logging.error("ADP_EMPLOYEE_URL environment variable is not set.")
        return None
    pem_path = ensure_file_from_env("ADP_CERT_PEM", ".pem")
    key_path = ensure_file_from_env("ADP_CERT_KEY", ".key")
    if not pem_path:
        logging.error("ADP_CERT_PEM environment variable is missing or invalid.")
        return None
    cert_arg: str | tuple[str, str]
    cert_arg = (pem_path, key_path) if key_path else pem_path
    headers = {"Authorization": f"Bearer {token}"}
    verify_arg = get_adp_ca_bundle()

    employees: list[dict] = []
    current_offset = offset
    while True:
        url = f"{base_url}?$top={limit}&$skip={current_offset}"
        response = _request_with_retries(
            "GET",
            url,
            action_label=f"ADP workers fetch (offset={current_offset})",
            headers=headers,
            cert=cert_arg,
            verify=verify_arg,
        )
        if not response:
            return None
        if not response.ok:
            logging.error(f"Failed to retrieve employees (HTTP {response.status_code}): {response.text}")
            return None
        try:
            payload = response.json()
        except json.JSONDecodeError:
            logging.error(f"Failed to decode JSON from ADP response: {response.text}")
            return None
        page_workers = payload.get("workers", [])
        if not isinstance(page_workers, list):
            logging.error(f"Unexpected ADP workers payload type: {type(page_workers).__name__}")
            return None
        employees.extend(page_workers)
        logging.info(f"Records retrieved so far: {len(employees)}")
        if not paginate_all or len(page_workers) < limit:
            break
        current_offset += limit
    logging.info(f"Total records retrieved in this call: {len(employees)}")
    return employees

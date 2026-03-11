"""Certificate and CA bundle helpers with deterministic temp-file cleanup."""

from __future__ import annotations

import atexit
import base64
import logging
import os
import tempfile
from typing import Optional

import certifi

_TEMP_CERT_FILES: set[str] = set()
_ENV_FILE_CACHE: dict[tuple[str, str], str] = {}


def _cleanup_temp_cert_files() -> None:
    """Delete temporary cert/key files created from env values."""
    for path in list(_TEMP_CERT_FILES):
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception as exc:
            logging.warning(f"Temp cert file cleanup failed for '{path}': {exc}")
        finally:
            _TEMP_CERT_FILES.discard(path)
    _ENV_FILE_CACHE.clear()


atexit.register(_cleanup_temp_cert_files)


def _write_temp_file(payload: bytes, suffix: str) -> str:
    """Write bytes to a managed temp file that will be cleaned at exit."""
    handle = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    try:
        handle.write(payload)
        handle.flush()
        path = handle.name
    finally:
        handle.close()
    _TEMP_CERT_FILES.add(path)
    return path


def ensure_file_from_env(env_name: str, suffix: str) -> Optional[str]:
    """
    Resolve secret-backed file material from environment.

    Supported forms:
    - Existing local file path
    - PEM text
    - Base64-encoded payload
    """
    raw = os.getenv(env_name)
    if not raw:
        return None

    cache_key = (env_name, raw)
    cached = _ENV_FILE_CACHE.get(cache_key)
    if cached and os.path.exists(cached):
        return cached

    if os.path.exists(raw):
        _ENV_FILE_CACHE[cache_key] = raw
        return raw

    normalized = raw.replace("\\n", "\n").strip()
    if normalized.startswith("-----BEGIN "):
        path = _write_temp_file(normalized.encode("utf-8"), suffix=suffix)
        _ENV_FILE_CACHE[cache_key] = path
        logging.info(f"{env_name} provided as PEM text; materialized to temp file")
        return path

    try:
        decoded = base64.b64decode(normalized, validate=True)
    except Exception:
        # Preserve previous best-effort behavior for non-canonical base64 payloads.
        compact = "".join(normalized.split())
        try:
            decoded = base64.b64decode(compact)
        except Exception:
            decoded = b""
    if decoded:
        path = _write_temp_file(decoded, suffix=suffix)
        _ENV_FILE_CACHE[cache_key] = path
        logging.info(f"{env_name} provided as base64; materialized to temp file")
        return path

    logging.warning(f"{env_name} is set but not a readable file path, PEM block, or base64 payload")
    return None


def get_ca_bundle() -> str:
    """Return LDAP/enterprise CA bundle path, defaulting to certifi."""
    path = os.getenv("CA_BUNDLE_PATH")
    if path and os.path.exists(path):
        return path
    return certifi.where()


def get_adp_ca_bundle() -> str:
    """Return ADP CA bundle path, defaulting to certifi."""
    path = os.getenv("ADP_CA_BUNDLE_PATH")
    if path and os.path.exists(path):
        return path
    return certifi.where()


def cleanup_temp_files() -> None:
    """Public cleanup hook for tests and explicit shutdown paths."""
    _cleanup_temp_cert_files()

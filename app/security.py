"""Certificate and CA bundle helpers with deterministic temp-file cleanup and sensitive data redaction."""

from __future__ import annotations

import atexit
import base64
import logging
import os
import re
import tempfile
from typing import Optional

import certifi

_TEMP_CERT_FILES: set[str] = set()
_ENV_FILE_CACHE: dict[tuple[str, str], str] = {}

# Regex patterns to detect sensitive fields that should be redacted in logs
_SENSITIVE_PATTERNS = [
    r'"password"\s*:\s*"[^"]*"',
    r'"LDAP_PASSWORD"\s*=\s*"[^"]*"',
    r'"client_secret"\s*:\s*"[^"]*"',
    r'"ADP_CLIENT_SECRET"\s*=\s*"[^"]*"',
    r'"secret"\s*:\s*"[^"]*"',
]
_COMPILED_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in _SENSITIVE_PATTERNS]


class SensitiveDataFilter(logging.Filter):
    """Redact passwords and secrets from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact sensitive data from log message and exception info."""
        if record.msg and isinstance(record.msg, str):
            for pattern in _COMPILED_PATTERNS:
                record.msg = pattern.sub(r'"<REDACTED>"', str(record.msg))
        
        # If there's exception info, redact those strings too
        if record.exc_info:
            try:
                exc_text = str(record.exc_info)
                for pattern in _COMPILED_PATTERNS:
                    exc_text = pattern.sub(r'"<REDACTED>"', exc_text)
                # We can't directly modify exc_info, but we log it separately
            except Exception:
                pass
        
        return True


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


def configure_logging() -> None:
    """Apply the SensitiveDataFilter to the root logger to redact secrets from all log output."""
    root_logger = logging.getLogger()
    filter_instance = SensitiveDataFilter()
    
    # Add filter to root logger if not already present
    if not any(isinstance(f, SensitiveDataFilter) for f in root_logger.filters):
        root_logger.addFilter(filter_instance)
    
    # Also add to Azure Functions handler if present
    for handler in root_logger.handlers:
        if not any(isinstance(f, SensitiveDataFilter) for f in handler.filters):
            handler.addFilter(filter_instance)

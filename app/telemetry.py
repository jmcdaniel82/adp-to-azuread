"""Structured telemetry helpers for Application Insights trace ingestion."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any
from uuid import uuid4

APP_TELEMETRY_PREFIX = "APP_TELEMETRY"


def _json_default(value: Any) -> Any:
    """Render non-JSON-native values in a predictable way."""
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def new_run_id(job_name: str) -> str:
    """Return a stable-enough run identifier for one orchestration invocation."""
    normalized = "".join(char if char.isalnum() else "-" for char in job_name).strip("-").lower()
    return f"{normalized}-{uuid4().hex[:12]}"


class StructuredLogTelemetrySink:
    """Emit structured telemetry payloads through the Functions logger."""

    def emit(self, event_name: str, properties: dict[str, Any], *, level: str = "info") -> None:
        payload = {"event": event_name, **(properties or {})}
        message = f"{APP_TELEMETRY_PREFIX} {json.dumps(payload, default=_json_default, sort_keys=True)}"
        logger = getattr(logging, level, logging.info)
        logger(message)


__all__ = ["APP_TELEMETRY_PREFIX", "StructuredLogTelemetrySink", "new_run_id"]

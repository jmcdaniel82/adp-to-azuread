"""Optional live SMTP smoke test.

Required env vars:
- `TERMED_REPORT_SMTP_HOST`
- `TERMED_REPORT_SMTP_PORT`
- `TERMED_REPORT_FROM_ADDRESS`
- `TERMED_REPORT_RECIPIENTS`

These tests send a real email and are skipped unless a full SMTP route is
explicitly configured.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.config import get_termed_report_settings
from app.termination_report import send_termed_report_email

from ._gating import require_env

require_env(
    "TERMED_REPORT_SMTP_HOST",
    "TERMED_REPORT_SMTP_PORT",
    "TERMED_REPORT_FROM_ADDRESS",
    "TERMED_REPORT_RECIPIENTS",
)


def test_live_smtp_send_smoke():
    settings = get_termed_report_settings()
    csv_content = "employeeID,fullName\nINTEGRATION,Integration Test\n"
    send_termed_report_email(
        settings,
        report_date=datetime.now(timezone.utc),
        csv_content=csv_content,
        row_count=1,
    )

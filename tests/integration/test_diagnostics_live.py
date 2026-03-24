"""Optional live diagnostics endpoint smoke test.

Required env vars:
- `DIAGNOSTICS_URL`

Optional env vars:
- `DIAGNOSTICS_BEARER_TOKEN`
- `DIAGNOSTICS_VIEW` (defaults to `summary`)

These tests call a live Azure-hosted endpoint and are skipped unless the URL
is explicitly configured.
"""

from __future__ import annotations

from urllib.parse import urlencode

import requests

from ._gating import require_env

env = require_env("DIAGNOSTICS_URL")


def test_live_diagnostics_endpoint_smoke():
    view = env.get("DIAGNOSTICS_VIEW", "summary")
    url = env["DIAGNOSTICS_URL"]
    if "?" in url:
        full_url = f"{url}&{urlencode({'view': view})}"
    else:
        full_url = f"{url}?{urlencode({'view': view})}"

    headers = {}
    bearer = env.get("DIAGNOSTICS_BEARER_TOKEN")
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"

    response = requests.get(full_url, headers=headers, timeout=30)
    assert response.status_code in {200, 401, 403}
    if response.status_code == 200:
        payload = response.json()
        assert isinstance(payload, dict)
        assert payload


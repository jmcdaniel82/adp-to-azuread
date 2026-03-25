"""Optional live diagnostics endpoint smoke test.

Required env vars:
- `DIAGNOSTICS_URL`

Optional env vars:
- `DIAGNOSTICS_FUNCTION_KEY`
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
    function_key = env.get("DIAGNOSTICS_FUNCTION_KEY")
    if function_key:
        headers["x-functions-key"] = function_key

    response = requests.get(full_url, headers=headers, timeout=30)
    if function_key:
        assert response.status_code == 200
        payload = response.json()
        assert isinstance(payload, dict)
        assert payload
    else:
        assert response.status_code in {401, 403}

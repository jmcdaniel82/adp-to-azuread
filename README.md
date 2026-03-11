# ADP to Active Directory Sync (Azure Functions)

This project syncs ADP Workforce Now worker data into on-prem Active Directory over LDAPS.

## Overview

The application has two timer jobs and two HTTP diagnostics routes:

- `scheduled_provision_new_hires` provisions new AD accounts for hires inside a lookback window.
- `scheduled_update_existing_users` compares ADP data to existing AD users and updates attributes (dry-run by default).
- `POST /api/process` returns active ADP worker snapshots.
- `GET /api/export` returns ADP-vs-AD department and employeeID diagnostics.

## Architecture

The previous monolithic `function_app.py` has been split into a package-first structure:

```text
app/
  __init__.py
  function_app.py           # thin Azure trigger/route wiring only
  azure_compat.py           # local/test import shim when azure-functions is unavailable
  constants.py              # LDAP attributes, deny lists, defaults
  config.py                 # typed env parsing and defaults
  models.py                 # TypedDict/dataclass models
  reporting.py              # shared stats helpers
  security.py               # cert/key materialization + deterministic temp cleanup
  adp_client.py             # ADP auth, retries, pagination, worker parsing
  department_resolution.py  # Department Resolution V2 engine
  ldap_client.py            # LDAP connection, diff/modify, guardrails, diagnostics
  provisioning.py           # new-hire create orchestration
  updates.py                # existing-user update orchestration
  export_routes.py          # HTTP route handlers
function_app.py             # host shim importing app from app.function_app
```

## Behavioral Invariants Preserved

The refactor intentionally preserves these rules:

- `scheduled_provision_new_hires` remains functional.
- `scheduled_update_existing_users` remains dry-run by default (`UPDATE_DRY_RUN=true`).
- Update sync never modifies create-time-only email routing identifiers:
  - `mail`, `userPrincipalName`, `mailNickname`, `proxyAddresses`, `targetAddress`, and related aliases.
- Department Resolution V2 remains intact:
  - canonical mapping,
  - `Customer Service* -> Sales` override,
  - ambiguous-value handling,
  - Administration gating,
  - manager-alignment guardrail,
  - fallback/audit fields.
- Provisioning collision handling keeps deterministic CN-by-employeeID behavior and conflict-specific retry handling.

## Security Hardening

- Certificate/key env material is resolved through `app.security.ensure_file_from_env`.
- Temp cert/key files are tracked and cleaned deterministically via an `atexit` cleanup hook.
- Secret content is never logged.
- CA bundle resolution is centralized for both ADP and LDAP TLS verification.

## Configuration

Set values in Azure App Settings or the sanitized local template files:

- `local.settings.json`
- `local.settings.example.json`

### ADP

- `ADP_TOKEN_URL`
- `ADP_EMPLOYEE_URL`
- `ADP_CLIENT_ID`
- `ADP_CLIENT_SECRET`
- `ADP_CERT_PEM`
- `ADP_CERT_KEY` (optional)
- `ADP_CA_BUNDLE_PATH` (optional)

### LDAP / AD

- `LDAP_SERVER`
- `LDAP_USER`
- `LDAP_PASSWORD`
- `LDAP_SEARCH_BASE`
- `LDAP_CREATE_BASE` (required for provisioning)
- `CA_BUNDLE_PATH`
- `UPN_SUFFIX`

### Provisioning Job

- `SYNC_HIRE_LOOKBACK_DAYS` (default `4`)
- `PROVISION_MAX_ADD_RETRIES` (default `15`)
- `CN_COLLISION_THRESHOLD` (default `5`)

### Update Job

- `UPDATE_DRY_RUN` (default `true`)
- `UPDATE_LOOKBACK_DAYS` (default `7`)
- `UPDATE_INCLUDE_MISSING_LAST_UPDATED` (default `true`)
- `UPDATE_LOG_NO_CHANGES` (default `false`)

## Local Run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
func start --verbose
```

## Tests

```powershell
pytest -q
ruff check app tests function_app.py
mypy app
```

Current tests cover:

- Department Resolution V2 high-risk rules.
- Update guardrails (denylist, dry-run, no-change path).
- Config/env parsing defaults and invalid fallback behavior.
- ADP retry behavior for retryable and non-retryable outcomes.
- Provisioning collision fail-fast and deterministic CN behavior.
- Secret materialization/cleanup behavior for PEM/base64 env values.

Staging validation steps are documented in [docs/staging-smoke-checklist.md](docs/staging-smoke-checklist.md).

## Deployment

```powershell
func azure functionapp publish <APP_NAME> --python
```

## Security Notes

- Do not commit real credentials/certificates.
- Keep production secrets in Azure App Settings / Key Vault.
- `local.settings.json` in this repo is sanitized and intended only as a placeholder template.
- See `SECURITY.md` for responsible disclosure.

## License

MIT. See `LICENSE`.

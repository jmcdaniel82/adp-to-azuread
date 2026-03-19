# ADP to Active Directory Sync (Azure Functions)

This project syncs ADP Workforce Now worker data into on-prem Active Directory over LDAPS.

## Overview

The application has three timer jobs and one HTTP diagnostics route:

- `scheduled_provision_new_hires` provisions new AD accounts for hires inside a lookback window.
- `scheduled_update_existing_users` compares ADP data to existing AD users and updates attributes (dry-run by default).
- `scheduled_last_30_day_termed_report` emails a weekly ADP-only CSV of workers terminated in the last 30 days.
- `GET /api/diagnostics` serves explicit diagnostics views:
  - `view=summary`
  - `view=department-diff`
  - `view=worker&employeeId=...`
  - `view=recent-hires&limit=25`

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
  diagnostics_routes.py     # HTTP diagnostics handler with query-driven views
function_app.py             # host shim importing app from app.function_app
```

Azure Functions Python v2 discovery still happens from the repository root through `function_app.py`, while the decorated handlers and service orchestration live under `app/`.

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

Set values in Azure App Settings for deployed environments. For local development, copy `local.settings.example.json` to the ignored `local.settings.json` file and add your local secrets there.

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

### Weekly Termed Report

- `TERMED_REPORT_SCHEDULE` (default `0 0 14 * * 1`, weekly Monday trigger; override as needed)
- `TERMED_REPORT_LOOKBACK_DAYS` (default `30`)
- `TERMED_REPORT_SMTP_HOST` (default `10.209.10.25`)
- `TERMED_REPORT_SMTP_PORT` (default `25`)
- `TERMED_REPORT_FROM_ADDRESS` (default `90day@cfsbrands.com`)
- `TERMED_REPORT_RECIPIENTS` (default `jasonmcdaniel@cfsbrands.com, ashleytolbert@cfsbrands.com`)
- `TERMED_REPORT_SUBJECT` (default `ADP Last 30 Day Termed Report`)

## Local Run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
func start --verbose
```

Recommended local defaults:

- keep `UPDATE_DRY_RUN=true` unless you are explicitly validating live update writes in a safe environment,
- point all ADP and LDAP settings at non-production systems before running timers locally.

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
- Diagnostics route modes for summary, department diff, worker lookup, and recent hires.
- Provisioning collision fail-fast and deterministic CN behavior.
- Secret materialization/cleanup behavior for PEM/base64 env values.

Staging validation steps are documented in [docs/staging-smoke-checklist.md](docs/staging-smoke-checklist.md).

## CI and Deployment

Repository verification runs in:

- `.github/workflows/verify.yml`
- `.github/workflows/main_adp-to-azuread.yml`

The deployment workflow targets the Azure Function App `adp-to-azuread` after verification passes.

Manual publish remains:

```powershell
func azure functionapp publish adp-to-azuread --python
```

## Security Notes

- Do not commit real credentials/certificates.
- Keep production secrets in Azure App Settings / Key Vault.
- `local.settings.json` is for local-only secrets and should remain untracked.
- Use `local.settings.example.json` as the committed template.
- See `SECURITY.md` for responsible disclosure.

## License

MIT. See `LICENSE`.

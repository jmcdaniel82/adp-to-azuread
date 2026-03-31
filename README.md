# ADP to Active Directory Sync (Azure Functions)

This project syncs ADP Workforce Now worker data into on-prem Active Directory over LDAPS.

## Overview

The application has three timer jobs and one HTTP diagnostics route:

- `scheduled_provision_new_hires` provisions new AD accounts for hires inside a lookback window.
- `scheduled_update_existing_users` compares ADP data to existing AD users, applies live manager updates by default, and disables terminated users.
- `scheduled_last_30_day_termed_report` emails a weekly ADP-only CSV of workers terminated in the last 30 days.
- `GET /api/diagnostics` serves explicit diagnostics views behind Microsoft Entra authentication at the App Service layer.
  In deployed environments, the main site is additionally IP-allowlisted so diagnostics is not internet-wide:
  - `view=summary`
  - `view=department-diff`
  - `view=worker&employeeId=...`
  - `view=recent-hires&limit=25`

## Architecture

The runtime is now organized around thin Azure entrypoints, focused integration packages, and explicit service/gateway orchestration:

```text
app/
  function_app.py             # thin Azure trigger/route wiring only
  config.py                   # typed env parsing and defaults
  constants.py                # LDAP attributes, deny lists, defaults
  models.py                   # dataclass and TypedDict models
  reporting.py                # shared stats helpers
  security.py                 # cert/key materialization + deterministic temp cleanup
  adp/
    api.py                    # ADP auth, mTLS, retries, pagination
    dates.py                  # worker date parsing and hire/term extraction
    identity.py               # employeeID and account-string normalization
    names.py                  # legal/preferred/display name helpers
    assignments.py            # work-assignment, department, manager, and location extraction
    status.py                 # active/inactive derivation and AD UAC mapping
    passwords.py              # random AD password generation
    workers.py                # compatibility export surface for worker helpers
    dedupe.py                 # duplicate-profile diagnostics and employeeID dedupe
  ldap/
    connection.py             # LDAP TLS/server/bind lifecycle
    directory.py              # lookup helpers and collision inspection
    planning.py               # update planning, diffing, and guardrails
    modify.py                 # modify transport and reconnect recovery
    updates.py                # compatibility wrapper for legacy LDAP update imports
  department/
    catalog.py                # regex/rule catalogs and canonical department sets
    normalization.py          # normalization and confidence helpers
    signals.py                # ADP signal collection for department evidence
    title_inference.py        # title-based department inference
    candidates.py             # candidate scoring and guardrail helpers
    resolver.py               # Department Resolution V2 orchestration
  services/
    interfaces.py             # worker/directory/mail gateway contracts
    defaults.py               # default ADP, LDAP, SMTP adapters
    provisioning_service.py   # provisioning orchestration
    update_service.py         # update orchestration
    termed_report_service.py  # termed report orchestration
    diagnostics_service.py    # diagnostics projections and parallel source loading
  provisioning.py             # thin builder + compatibility wrapper
  provisioning_ops.py         # thin create-path orchestration wrapper
  provisioning_filters.py     # recent-hire filtering helpers
  provisioning_directory.py   # existing-user and manager lookup helpers
  provisioning_identity.py    # create-time identifier and attribute planning
  provisioning_create.py      # LDAP add retries, collision handling, account enablement
  updates.py                  # thin builder + candidate selection
  termination_report.py       # thin builder + report row/render/email helpers
  diagnostics_routes.py       # HTTP diagnostics controller
  adp_client.py               # compatibility facade for app.adp
  ldap_client.py              # compatibility facade for app.ldap
  department_resolution.py    # compatibility facade for app.department
function_app.py             # host shim importing app from app.function_app
```

Azure Functions Python v2 discovery still happens from the repository root through `function_app.py`, while the decorated handlers and service orchestration live under `app/`.

For the full architecture walkthrough, top-level architecture maps, and runtime sequence diagrams, see [docs/architecture.md](docs/architecture.md).

## Behavioral Invariants Preserved

The refactor intentionally preserves these rules:

- `scheduled_provision_new_hires` remains functional.
- `scheduled_update_existing_users` now defaults to live manager updates with terminated-user disablement (`UPDATE_DRY_RUN=false` plus default manager scope).
- Provisioning no longer runs on cold start; the timer uses its normal 15-minute cadence only.
- Fatal timer-path failures raise exceptions so Azure Functions can treat the invocation as failed.
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
- LDAP writes can be constrained to approved OUs with `LDAP_ALLOWED_WRITE_BASES`.
- Production app settings now use Key Vault references for ADP/LDAP secrets and host storage settings.
- Deployed diagnostics access is intended to use Microsoft Entra App Service authentication backed by a managed identity federated credential, with the main site separately IP-allowlisted.

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
- `LDAP_ALLOWED_WRITE_BASES` (optional comma-delimited OU/DN allowlist for add/modify/finalize writes)
- `CA_BUNDLE_PATH`
- `UPN_SUFFIX`

### Provisioning Job

- `SYNC_HIRE_LOOKBACK_DAYS` (default `4`)
- `PROVISION_MAX_ADD_RETRIES` (default `15`)
- `CN_COLLISION_THRESHOLD` (default `5`)

### Update Job

- `UPDATE_DRY_RUN` (default `false`)
- `UPDATE_LOOKBACK_DAYS` (default `7`)
- `UPDATE_INCLUDE_MISSING_LAST_UPDATED` (default `true`)
- `UPDATE_LOG_NO_CHANGES` (default `false`)
- `UPDATE_ENABLED_FIELDS` (optional comma-delimited LDAP attribute allowlist; when unset or empty, the default scoped live behavior stays manager-only unless expanded by groups)
- `UPDATE_ENABLED_GROUPS` (optional comma-delimited field groups; when unset or empty, `scheduled_update_existing_users` defaults to the `manager` group)
- `UPDATE_ALWAYS_DISABLE_TERMINATED` (default `true`; keeps `userAccountControl` disablement active for termed workers even when field filters are narrower)

Supported `UPDATE_ENABLED_GROUPS` values:

- `identity`
- `department`
- `manager`
- `address`
- `status`

Supported `UPDATE_ENABLED_FIELDS` values:

- `displayName`
- `title`
- `company`
- `department`
- `manager`
- `l`
- `postalCode`
- `st`
- `streetAddress`
- `co`
- `c`
- `countryCode`
- `userAccountControl`

Committed scoped-live template values in [`local.settings.example.json`](local.settings.example.json):

```json
"UPDATE_DRY_RUN": "false",
"UPDATE_ENABLED_FIELDS": "",
"UPDATE_ENABLED_GROUPS": "manager",
"UPDATE_ALWAYS_DISABLE_TERMINATED": "true"
```

Behavior:

- `UPDATE_ENABLED_FIELDS=""` leaves the default group-based scope in place
- `UPDATE_ENABLED_GROUPS="manager"` keeps scheduled updates scoped to manager writes
- `UPDATE_ALWAYS_DISABLE_TERMINATED="true"` preserves the current termination-disable safeguard
- with both allowlists empty, `scheduled_update_existing_users` still defaults to manager-only live updates; set `UPDATE_DRY_RUN=true` to rehearse without writes

Examples:

```json
"UPDATE_ENABLED_FIELDS": "title,department",
"UPDATE_ENABLED_GROUPS": ""
```

```json
"UPDATE_ENABLED_FIELDS": "",
"UPDATE_ENABLED_GROUPS": "manager,address"
```

### Weekly Termed Report

- `TERMED_REPORT_SCHEDULE` (default `0 0 14 * * 1`, weekly Monday trigger; override as needed)
- `TERMED_REPORT_LOOKBACK_DAYS` (default `30`)
- `TERMED_REPORT_SMTP_HOST` (default `10.209.10.25`)
- `TERMED_REPORT_SMTP_PORT` (default `25`)
- `TERMED_REPORT_FROM_ADDRESS` (default `90day@cfsbrands.com`)
- `TERMED_REPORT_RECIPIENTS` (default `jasonmcdaniel@cfsbrands.com, ashleytolbert@cfsbrands.com`)
- `TERMED_REPORT_SUBJECT` (default `ADP Last 30 Day Termed Report`)

### Diagnostics Hardening

- `DIAGNOSTICS_REQUIRE_APP_SERVICE_AUTH` (default `false`; set `true` in deployed environments so the app rejects requests that do not arrive through App Service auth)

## Local Run

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
func start --verbose
```

Recommended local defaults:

- keep the committed scoped-live defaults when validating manager sync and terminated-user disablement,
- set `UPDATE_DRY_RUN=true` if you want to rehearse the same scope without writes or before broadening beyond manager-only,
- set explicit `UPDATE_ENABLED_FIELDS` and `UPDATE_ENABLED_GROUPS` when you intentionally want to broaden beyond manager-only scope,
- point all ADP and LDAP settings at non-production systems before running timers locally.

## Tests

```powershell
pytest -q
ruff check app tests function_app.py
mypy app
```

Default local verification covers:

- Department Resolution V2 high-risk rules.
- Update guardrails (denylist, scoped live defaults, dry-run toggle, no-change path).
- Config/env parsing defaults and invalid fallback behavior.
- ADP retry behavior for retryable and non-retryable outcomes.
- Diagnostics route modes for summary, department diff, worker lookup, and recent hires.
- Provisioning collision fail-fast and deterministic CN behavior.
- Secret materialization/cleanup behavior for PEM/base64 env values.

There is also an opt-in live integration smoke layer:

```powershell
pytest -q tests/integration
```

The live suite skips by default unless the required environment variables are present. It covers ADP, LDAP, SMTP, and hosted diagnostics smoke paths. See [docs/integration-tests.md](docs/integration-tests.md).

Staging validation steps are documented in [docs/staging-smoke-checklist.md](docs/staging-smoke-checklist.md).

## CI and Deployment

Repository verification runs in:

- `.github/workflows/verify.yml`
- `.github/workflows/main_adp-to-azuread.yml`

The deployment workflow now builds a curated `release.zip` containing only the runtime payload:

- `function_app.py`
- `host.json`
- `requirements.txt`
- `app/**`

That package is deployed to the Azure Function App `adp-to-azuread` after verification passes.

The current deployment target is Azure Functions Flex Consumption, so the workflow keeps remote build enabled to preserve correct Python dependency build and function indexing behavior.
For the same platform reason, deployed diagnostics authentication uses Microsoft Entra plus a managed identity federated credential rather than App Service certificate-based auth.
Production secrets are expected to come from Key Vault-backed app settings, and the deployed diagnostics surface is intended to be protected by Microsoft Entra App Service authentication plus main-site App Service access restrictions.

Manual publish remains:

```powershell
func azure functionapp publish adp-to-azuread --python
```

## Security Notes

- Do not commit real credentials/certificates.
- Keep production secrets in Azure App Settings / Key Vault.
- Prefer Key Vault references plus managed identity for deployed secrets instead of plain-text app settings.
- Scope LDAP writes to approved OUs with `LDAP_ALLOWED_WRITE_BASES`.
- See [docs/ldap-bind-account-acls.md](docs/ldap-bind-account-acls.md) for the exact staging-OU ACL and operator checklist for the LDAP bind account.
- `local.settings.json` is for local-only secrets and should remain untracked.
- Use `local.settings.example.json` as the committed template.
- See `SECURITY.md` for responsible disclosure.

## License

MIT. See `LICENSE`.

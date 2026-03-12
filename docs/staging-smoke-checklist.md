# Staging Smoke Checklist

Use this checklist after deployment to a staging Function App with staging ADP and LDAP credentials. If you mirror production naming, the target app may be a staging companion to `adp-to-azuread`, but the checks below apply to any staging slot or separate staging app.

## Preconditions

- Confirm staging app settings are populated for:
  - `ADP_TOKEN_URL`, `ADP_EMPLOYEE_URL`, `ADP_CLIENT_ID`, `ADP_CLIENT_SECRET`
  - `ADP_CERT_PEM`, `ADP_CERT_KEY`
  - `LDAP_SERVER`, `LDAP_USER`, `LDAP_PASSWORD`, `LDAP_SEARCH_BASE`, `LDAP_CREATE_BASE`
  - `CA_BUNDLE_PATH`
- For local smoke runs, start from `local.settings.example.json` and place real staging secrets only in the ignored `local.settings.json`.
- Confirm `UPDATE_DRY_RUN=true` before testing the update timer path. This is the intended default and should remain explicit in staging app settings.
- Confirm staging AD bind account can read and create in the intended OU.

## 1. ADP Token Retrieval

- Start the Functions host or tail Function App logs.
- Trigger `GET /api/diagnostics?view=summary`.
- Expect:
  - successful ADP token acquisition,
  - no TLS/certificate errors,
  - no JSON decode errors from the token endpoint.

## 2. `scheduled_provision_new_hires`

- Ensure `SYNC_HIRE_LOOKBACK_DAYS` includes at least one known staging candidate.
- Trigger the timer manually from Azure portal or by starting the host locally.
- Expect:
  - `scheduled_provision_new_hires triggered`
  - LDAP bind success log
  - per-user `Processing ... Start Date='M/D/YYYY'`
  - end-of-run summary with counters
- Validate in AD:
  - existing employeeIDs are not recreated,
  - newly created users have deterministic CN including employeeID token,
  - manager assignment is present when manager employeeID resolves.

## 3. `scheduled_update_existing_users` Dry Run

- Keep `UPDATE_DRY_RUN=true`.
- Set `UPDATE_LOOKBACK_DAYS` to include known changed workers.
- Trigger the timer manually.
- Expect:
  - `scheduled_update_existing_users triggered (dry_run=True, ...)`
  - LDAP bind success log
  - `DRY RUN update ...` lines only
  - no actual modify/write side effects in AD
- Confirm email-routing attributes are not mentioned as update operations.

## 4. HTTP Route Smoke

- Call:
  - `GET /api/diagnostics?view=summary`
  - `GET /api/diagnostics?view=department-diff`
  - `GET /api/diagnostics?view=worker&employeeId=<known employeeID>`
- Expect:
  - HTTP 200
  - valid JSON payload
  - no stack traces in logs

## 5. LDAP Bind/Rebind Recovery

- During a staging timer run, recycle the LDAP target session or temporarily interrupt connectivity.
- Expect one of:
  - reconnect and continue behavior for update/modify paths,
  - safe fail-fast for provisioning add paths with explicit diagnostics
- Confirm the run exits with readable error context rather than hanging or retry-storming.

## Exit Criteria

- All endpoints and timers start successfully.
- ADP token retrieval succeeds.
- Provisioning summary logs are emitted.
- Update dry-run emits only simulated changes.
- No secrets appear in logs.
- No unexpected writes occur outside intended staging scope.

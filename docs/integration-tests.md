# Integration Tests

This repository includes an opt-in live integration layer under `tests/integration/`.

## Behavior

The tests skip by default. They only run when the relevant live environment variables are present.

That keeps the standard `pytest -q` path offline and safe while still making it easy to verify real infrastructure when needed.

## Coverage

The live tests cover:

- ADP token retrieval
- ADP workers fetch
- LDAP TLS connectivity and search smoke
- SMTP send validation for the termed report path
- Azure-hosted diagnostics Entra-auth and payload smoke
- End-to-end scheduled update workflow smoke with `dry_run=True` and a short lookback window
- Provisioning create-path write test against a staging OU with cleanup
- Scheduled update live-write test against a staging account with cleanup

## Required Environment Variables

### ADP

- `ADP_TOKEN_URL`
- `ADP_EMPLOYEE_URL`
- `ADP_CLIENT_ID`
- `ADP_CLIENT_SECRET`
- `ADP_CERT_PEM`

### LDAP

- `LDAP_SERVER`
- `LDAP_USER`
- `LDAP_PASSWORD`
- `LDAP_SEARCH_BASE`
- `CA_BUNDLE_PATH`

### SMTP

- `TERMED_REPORT_SMTP_HOST`
- `TERMED_REPORT_SMTP_PORT`
- `TERMED_REPORT_FROM_ADDRESS`
- `TERMED_REPORT_RECIPIENTS`

### Diagnostics

- `DIAGNOSTICS_URL`
- `DIAGNOSTICS_BEARER_TOKEN` optional when validating successful Entra-authenticated access
- `DIAGNOSTICS_VIEW` optional, defaults to `summary`

### Workflow Dry Run

- `ENABLE_UPDATE_DRY_RUN_LIVE_TEST`
- ADP and LDAP variables above

### Provisioning Write Path

- `ENABLE_PROVISIONING_WRITE_LIVE_TEST`
- LDAP variables above, including `LDAP_CREATE_BASE`

### Update Write Path

- `ENABLE_UPDATE_WRITE_LIVE_TEST`
- LDAP variables above, including `LDAP_CREATE_BASE`

## Run

```powershell
pytest -q tests/integration
```

If the live env vars are not present, the modules skip at import time.

The update workflow smoke test is additionally gated behind
`ENABLE_UPDATE_DRY_RUN_LIVE_TEST` so it does not run accidentally even when ADP
and LDAP credentials are available.

The write-path tests are separately gated and intended only for non-production
staging environments. They create staging users, validate the path, and then
clean those users up.

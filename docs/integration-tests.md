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
- SMTP send smoke for the termed report
- Azure-hosted diagnostics endpoint smoke

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
- `DIAGNOSTICS_BEARER_TOKEN` optional
- `DIAGNOSTICS_VIEW` optional, defaults to `summary`

## Run

```powershell
pytest -q tests/integration
```

If the live env vars are not present, the modules skip at import time.


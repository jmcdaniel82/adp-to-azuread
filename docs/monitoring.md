# Monitoring

This repository now emits structured telemetry traces prefixed with `APP_TELEMETRY`.

Those traces are designed for Application Insights / Log Analytics queries and
cover:

- `job_run`: one structured run summary for each timer invocation
- `directory_reconnect`: LDAP reconnect and bind-loss recovery events
- `smtp_failure`: report-delivery failures
- `provisioning_reconciliation`: created accounts that were left incomplete

## Core Fields

The timer `job_run` payloads include these fields where applicable:

- `job`
- `run_id`
- `dry_run`
- `worker_count`
- `created`
- `changed`
- `missing_in_ad`
- `fatal_reason`
- `status`
- `duration_ms`
- `ldap_reconnects`

## Suggested Alert Queries

These queries assume workspace-based Application Insights tables with
`AppTraces`. If your environment still uses classic Application Insights query
names, translate `AppTraces` to `traces`.

### Timer Failures

```kusto
AppTraces
| where Message startswith "APP_TELEMETRY "
| extend payload = parse_json(substring(Message, 14))
| where tostring(payload.event) == "job_run"
| where tostring(payload.fatal_reason) != ""
```

### SMTP Failure

```kusto
AppTraces
| where Message startswith "APP_TELEMETRY "
| extend payload = parse_json(substring(Message, 14))
| where tostring(payload.event) == "smtp_failure"
```

### Repeated LDAP Reconnects

```kusto
AppTraces
| where Message startswith "APP_TELEMETRY "
| extend payload = parse_json(substring(Message, 14))
| where tostring(payload.event) == "directory_reconnect"
| summarize reconnects = count() by bin(TimeGenerated, 15m), tostring(payload.job)
| where reconnects >= 3
```

### Incomplete Provisioning Creates

```kusto
AppTraces
| where Message startswith "APP_TELEMETRY "
| extend payload = parse_json(substring(Message, 14))
| where tostring(payload.event) == "provisioning_reconciliation"
| where tostring(payload.reconciliation_state) == "created_incomplete"
```

## Post-Deploy Guard

Deployment smoke now includes `scripts/assert_function_indexing.py`, which fails
the workflow if the target Function App does not index these expected functions:

- `diagnostics`
- `scheduled_last_30_day_termed_report`
- `scheduled_provision_new_hires`
- `scheduled_update_existing_users`

That guard is the repo-owned protection against the “successful deploy with zero
indexed functions” failure mode.

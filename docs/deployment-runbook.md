# Deployment Runbook

## Deployment Model

The main workflow builds one curated zip package, optionally deploys it to a
staging Function App when `AZURE_FUNCTIONAPP_STAGING_NAME` is configured as a
repository variable, runs indexed-function smoke checks there, and only then
deploys to production.

Production is always followed by the same indexed-function smoke check.

## Roll Forward

1. Push the change to `main`.
2. Let the GitHub Actions deployment run.
3. Confirm staging smoke passes when a staging app is configured.
4. Confirm production smoke passes.

## Rollback

1. Identify the last known good commit on `main`.
2. Redeploy that commit by rerunning the workflow on the earlier commit or by
   checking it out locally and publishing it again.
3. Confirm the production smoke check reports the expected indexed functions.
4. Validate `scheduled_update_existing_users` is still in the intended dry-run
   or live mode before declaring rollback complete.

## Smoke Failure Triage

- Zero indexed functions:
  check remote build output first, then verify the Function App runtime and the
  deployed artifact contents.
- Missing one expected function:
  inspect `function_app.py`, `app/function_app.py`, and packaging output for
  missing modules.
- Staging write-path failures:
  keep production blocked until the staging smoke is green.
- Diagnostics auth failures:
  confirm App Service Authentication is enabled, the Entra app registration and
  federated credential still exist, `OVERRIDE_USE_MI_FIC_ASSERTION_CLIENTID`
  still points at the assigned user-managed identity, and the caller is within
  both the IP allowlist and the App Service authorization policy.

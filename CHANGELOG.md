# Changelog

All notable changes to this project are documented in this file.

This project follows a Keep a Changelog style format and uses semantic versioning from this point forward.
Historical `0.0.x` entries for 2025 were backfilled from repository commit history.

## [Unreleased]

### Added

- Opt-in live integration smoke coverage under `tests/integration/` for:
  - ADP token and workers fetch,
  - LDAP bind and search,
  - SMTP report send,
  - hosted diagnostics contract checks.
- `docs/integration-tests.md` with environment gating and run instructions for the live suite.

### Refactored

- Replaced monolithic `function_app.py` with a package-oriented architecture under `app/`:
  - `app/function_app.py` (thin trigger/route wiring)
  - `app/config.py`, `app/constants.py`, `app/models.py`
  - `app/security.py`, `app/adp_client.py`, `app/ldap_client.py`
  - `app/department_resolution.py`, `app/provisioning.py`, `app/updates.py`, `app/diagnostics_routes.py`
- Root `function_app.py` is now a host shim that imports `app` from `app.function_app`.
- Split ADP internals into focused modules under `app/adp/`:
  - `api.py` for auth, mTLS, retries, and pagination,
  - `dates.py`, `identity.py`, `names.py`, `assignments.py`, `status.py`, and `passwords.py` for focused worker parsing domains,
  - `workers.py` as the compatibility export surface,
  - `dedupe.py` for duplicate-profile diagnostics and `employeeID` dedupe.
- Split LDAP internals into focused modules under `app/ldap/`:
  - `connection.py` for server and bind lifecycle,
  - `directory.py` for lookups and collision diagnostics,
  - `planning.py` and `modify.py` for update planning and transport recovery,
  - `updates.py` as the compatibility wrapper.
- Split Department Resolution V2 into `catalog.py`, `normalization.py`, `signals.py`, `title_inference.py`, `candidates.py`, and `resolver.py` while preserving `app/department_resolution.py` as a compatibility facade.
- Split provisioning create-path logic into `provisioning_filters.py`, `provisioning_directory.py`, `provisioning_identity.py`, `provisioning_create.py`, and a thinner `provisioning_ops.py` orchestration wrapper.
- Introduced an explicit gateway/orchestrator layer under `app/services/`:
  - `interfaces.py`
  - `defaults.py`
  - `provisioning_service.py`
  - `update_service.py`
  - `termed_report_service.py`
  - `diagnostics_service.py`
- Reduced `app/provisioning.py`, `app/updates.py`, and `app/termination_report.py` to thin builder/wrapper modules around the new service layer.

### Security

- Hardened cert/key secret handling:
  - env-provided PEM/base64 cert/key material is written to managed temp files,
  - deterministic cleanup of generated temp files on process exit,
  - no secret payload logging.
- Centralized CA bundle resolution for ADP and LDAP TLS verification paths.

### Tests

- Replaced legacy monolithic test file with focused test modules:
  - `tests/test_department_resolution.py`
  - `tests/test_config.py`
  - `tests/test_adp_client.py`
  - `tests/test_updates.py`
  - `tests/test_provisioning.py`
  - `tests/test_entrypoint_smoke.py`
  - `tests/test_security.py`
- Added explicit coverage for:
  - Department Resolution V2 guardrails and fallback chain,
  - update denylist protections for create-time email identifiers,
  - dry-run and no-change update paths,
  - config defaulting and invalid env fallback,
  - ADP retry helper behavior,
  - provisioning fail-fast on unresolved `result=68` collision scenarios,
  - root Azure Functions entrypoint smoke import/export checks,
  - temp-file cleanup for secret-backed PEM/base64 inputs.

### Changed

- Added repo-local quality gate configuration via `pyproject.toml` for `ruff` and `mypy`.
- Added CI verification workflow for tests, `py_compile`, lint, and type checks.
- Hardened the Azure deployment workflow so verification runs before packaging and publish.
- Deployment packaging now uses a curated `release.zip` and deploys that artifact directly instead of deploying the extracted workspace.
- Added `local.settings.example.json` as the committed local configuration template while keeping `local.settings.json` out of source control.
- Added staging smoke-test checklist for timer jobs, HTTP routes, ADP token retrieval, and LDAP bind/rebind validation.
- Updated repository documentation to reflect the new package layout, Azure Functions v2 root shim, CI gates, and local secret-handling expectations.
- Consolidated the old `process` and `export` HTTP endpoints into one `GET /api/diagnostics` route with explicit query-driven views.
- Provisioning timer startup behavior was tightened by disabling cold-start execution (`run_on_startup=False`).
- Fatal timer-path failures now raise exceptions instead of logging and returning success-like completions.
- `mypy app` is now part of a passing local/CI contract after the Azure compatibility and service refactor cleanup.

### Added

- In-memory ADP dedupe by `employeeID` with newest-record preference before provisioning/update processing.
- Non-blocking duplicate-profile diagnostics (same name/title/department/manager with different employeeIDs).
- Expanded provisioning conflict diagnostics:
  - exact DN existence checks before classifying collisions,
  - identifier conflict scans for `sAMAccountName`, `userPrincipalName`, and `mail`,
  - full LDAP result payload logging for `result=68`.
- Rich end-of-run provisioning summary with grouped operational counters:
  - `adp_total`, `deduped_dropped`, `hires_in_window`, `processed`,
  - `exists`, `created`, `manager_missing`, `skipped_country`, `skipped_missing_required_fields`,
  - `add_failures`, `password_failures`, `duration_ms`.
- Processing log lines now include formatted start date (`Start Date='M/D/YYYY'`).
- Provisioning now uses deterministic CN from first attempt: `displayName + employeeID token`.
- `displayName` remains human-friendly while uniqueness is handled by CN/account identifiers.
- CN collision handling now emits periodic cleanup diagnostics and re-checks existing user by `employeeID`.
- Production log prefixes switched from emoji markers to ASCII tags (`[INFO]`, `[WARN]`, `[ERROR]`).
- Diagnostics now use one route with bounded, lower-exposure views:
  - `summary` for counts only,
  - `department-diff` for ADP-vs-AD comparisons,
  - targeted `worker` lookup by `employeeId`,
  - `recent-hires` with bounded `limit`.
- Provisioning retry behavior was tightened to avoid single-user retry storms:
  - new `PROVISION_MAX_ADD_RETRIES` env var (default `15`),
  - fail-fast path for `result=68` when no visible DN or identifier conflict is found.

### Planned

- Complete and harden `scheduled_update_existing_users` for full production synchronization.
- Finalize operational guardrails and runbook for update-mode rollout (`UPDATE_DRY_RUN=false`).

## [0.2.0] - In Progress

### Goal

- Fully functional `scheduled_update_existing_users` as the second major milestone after provisioning.

### Scope

- Promote update flow from dry-run-first behavior to production-ready AD writes with safe rollout controls.
- Ensure reliable update filtering and coverage:
  - `UPDATE_LOOKBACK_DAYS`
  - `UPDATE_INCLUDE_MISSING_LAST_UPDATED`
  - `UPDATE_LOG_NO_CHANGES`
- Preserve create-time-only email-routing identifier protection during updates.
- Improve change visibility and operational triage for:
  - bind-loss recovery,
  - reconnect/retry behavior,
  - missing-in-AD and no-change outcomes.
- Confirm department resolution and manager-derived logic are stable in update paths.
- Document go-live checklist and rollback procedure for update mode.

### Notes

- This version is intentionally tracked as an active milestone and is not yet released.

## [0.1.1] - 2026-03-11

### Added

- Provisioning safeguard for repeated CN/DN collisions:
  - New environment variable `CN_COLLISION_THRESHOLD` (default `10`).
  - After threshold collisions (`LDAP result=68`), CN generation switches to an employee-ID-based CN root (for example, `Full Name 1234`) to reduce duplicate-name contention.

### Changed

- Provisioning logs now include clearer, actionable diagnostics when:
  - CN collision threshold is exceeded and fallback naming is activated.
  - Unique-add retries are exhausted, including explicit guidance to inspect conflicting `CN`/`UPN`/`mail` values.

### Documentation

- Expanded inline comments and docstrings in `function_app.py` for:
  - business-rule guardrails,
  - environment/config assumptions,
  - endpoint payload contracts,
  - non-obvious side effects in retry/reconnect paths.

## [0.1.0] - 2026-03-11

### Milestone

- `scheduled_provision_new_hires` completed to a functional production state.

### Added

- Azure Functions runtime with provisioning-first delivery:
  - `scheduled_provision_new_hires` for AD user provisioning from ADP (functional).
  - Initial `scheduled_update_existing_users` framework in dry-run-first mode.
- HTTP diagnostics endpoints:
  - `POST /api/process` for active-worker payload inspection.
  - `GET /api/export` for ADP-vs-AD mapping diagnostics and ID/dept inventory diffs.
- ADP integration with OAuth client credentials, certificate/key support from env values, and paginated worker retrieval.
- LDAP/AD integration over LDAPS with CA bundle controls and basic bind-loss recovery.
- Department Resolution V2 candidate/confidence model with guardrails and audit fields.
- Offline reporting utilities:
  - `generate_adp_current_vs_scheduled_department_report.py`
  - `build_dry_run_change_report_excel.py`

### Provisioning Highlights

- New-hire filtering by `SYNC_HIRE_LOOKBACK_DAYS` with UTC date windowing.
- Existing-user detection by `employeeID` to prevent duplicate account creation.
- Controlled add retry behavior for AD collisions and reconnect handling.
- Manager assignment by manager `employeeID` with explicit warning when manager object is missing in AD.
- Post-create account setup workflow (password set + enable path) with explicit failure logging.

### Changed

- Update synchronization guardrails were introduced but remain part of the in-progress `0.2.0` milestone.

### Security

- TLS certificate validation enabled for ADP and LDAP connections with configurable CA bundle paths.
- LDAP bind/account operations include controlled error handling and connection cleanup paths.

## [0.0.9] - 2025-12-02

### Changed

- Continued stabilization updates in `function_app.py` through November and early December.
- Removed legacy `HttpTrigger1` implementation files (`HttpTrigger1/__init__.py`, `HttpTrigger1/function.json`) as the app standardized on `function_app.py`.
- Normalized local Azurite config placement/usage and local debug setup files (`AzuriteConfig`, `.vscode/launch.json`) during October-November cleanup.

## [0.0.8] - 2025-08-18

### Added

- Security scanning workflows:
  - `.github/workflows/codeql.yml`
  - `.github/workflows/defender-for-devops.yml`

### Changed

- High-volume iterative updates to `function_app.py` across July-August for provisioning/update behavior refinement and runtime stability.

## [0.0.7] - 2025-07-31

### Changed

- Continued application logic iterations in `function_app.py` through July.
- Dependency update:
  - `requests` bumped from `2.32.2` to `2.32.4`.
- Local debug artifact updates/cleanup (`debug.log`) during development cycles.

## [0.0.6] - 2025-06-12

### Added

- Developer environment scaffolding:
  - `.funcignore`
  - `.vscode/extensions.json`
  - `.vscode/launch.json`
  - `.vscode/settings.json`
  - `.vscode/tasks.json`
- Azure App Service build/deploy workflow updates for CI/CD.

### Documentation

- Added descriptive function docstrings and expanded inline code documentation in `function_app.py`.

### Changed

- Continued service behavior and data-mapping updates in `function_app.py`.

## [0.0.5] - 2025-06-05

### Added

- `SECURITY.md` policy and follow-up updates.
- MIT license with corporate-use updates.
- Unit tests and workflow integration for `pytest`.

### Security

- Enforced function authentication settings.
- Removed internal debug endpoints.
- Reduced sensitive logging exposure in LDAP-related debug output.
- Removed tracked Azurite debug logs and updated ignore behavior.

### Changed

- Improved resilience and exception handling:
  - LDAP connection failure handling.
  - ADP employee request exception handling.
  - broader exception-handling improvements in `function_app.py`.
- Replaced DN escaping approach with `ldap3.utils.dn.escape_rdn`.
- Removed unused `get_created_date` helper.
- Fixed `instanceID` key naming.
- Standardized formatting/newline consistency and cleaned `requirements.txt`.

### Dependencies

- Bumped core packages:
  - `azure-functions` `1.14.0 -> 1.22.1`
  - `msal` `1.22.0 -> 1.32.3`
  - `azure-keyvault-secrets` `4.7.0 -> 4.9.0`
  - `azure-keyvault-certificates` `4.7.0 -> 4.9.0`
  - `azure-storage-blob` `12.10.0 -> 12.25.1`
  - `azure-identity` `1.12.0 -> 1.16.1`
  - `requests` `2.28.1 -> 2.32.2`

## [0.0.4] - 2025-03-12

### Added

- Initial project `README.md` and subsequent documentation updates.

### Changed

- Updated early `main.py` implementation and dependency definitions.
- Added/updated Azure App Service build/deployment workflow configuration.

## [0.0.3] - 2025-02-10

### Changed

- Refactored Azure Function setup and refreshed dependency baseline.

## [0.0.2] - 2025-01-30

### Added

- `dependabot.yml` for automated dependency update PRs.
- Early Azure App Service build/deployment workflow configuration.

## [0.0.1] - 2025-01-29

### Added

- Initial commit of ADP-to-Entra provisioning function.
- Initial `main.py` implementation and baseline `requirements.txt`.

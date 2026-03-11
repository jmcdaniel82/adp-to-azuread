# Changelog

All notable changes to this project are documented in this file.

This project follows a Keep a Changelog style format and uses semantic versioning from this point forward.

## [Unreleased]

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

### Added
- Azure Functions runtime with two timer-trigger jobs:
  - `scheduled_provision_new_hires` for AD user provisioning from ADP.
  - `scheduled_update_existing_users` for AD attribute synchronization (dry-run by default).
- HTTP diagnostics endpoints:
  - `POST /api/process` for active-worker payload inspection.
  - `GET /api/export` for ADP-vs-AD mapping diagnostics and ID/dept inventory diffs.
- ADP integration with OAuth client credentials, certificate/key support from env values, and paginated worker retrieval.
- LDAP/AD integration over LDAPS with CA bundle controls and basic bind-loss recovery.
- Department Resolution V2 candidate/confidence model with guardrails and audit fields.
- Offline reporting utilities:
  - `generate_adp_current_vs_scheduled_department_report.py`
  - `build_dry_run_change_report_excel.py`

### Changed
- Update synchronization explicitly blocks create-time-only email-routing identifiers from update flows (`mail`, `userPrincipalName`, `mailNickname`, `proxyAddresses`, `targetAddress`, and related aliases).
- Department updates apply conservative fallback behavior when evidence is ambiguous or low-confidence.

### Security
- TLS certificate validation enabled for ADP and LDAP connections with configurable CA bundle paths.
- LDAP bind/account operations include controlled error handling and connection cleanup paths.


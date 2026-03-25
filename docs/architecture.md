# Architecture

## System

This repository is a Python Azure Functions application that synchronizes ADP Workforce Now worker data into on-prem Active Directory over LDAPS.

The app exposes four runtime entrypoints:

- `scheduled_provision_new_hires`: provisions recent hires into AD
- `scheduled_update_existing_users`: compares ADP records to existing AD users and applies attribute updates
- `scheduled_last_30_day_termed_report`: emails a weekly CSV of recent ADP terminations
- `GET /api/diagnostics`: serves controlled, read-only diagnostics views for summary, department diffs, worker lookup, and recent hires

External integrations:

- ADP OAuth token endpoint and workers API
- LDAP / Active Directory over TLS
- SMTP for the termed report
- Azure Functions host and Application Insights logging

There is no application database in this repo. Each invocation re-fetches source data, computes a working set in memory, performs LDAP writes or emits a report, and exits.

## Runtime Model

Azure Functions discovers the root `FunctionApp` from the repo-level shim in [`function_app.py`](../function_app.py). The implementation lives in [`app/function_app.py`](../app/function_app.py).

Runtime host configuration is minimal and standard in [`host.json`](../host.json):

- `host.json` schema version `2.0`, which is the standard host format for Azure Functions runtime 2.x and later
- Application Insights sampling
- Extension bundle `Microsoft.Azure.Functions.ExtensionBundle`

Trigger wiring is intentionally thin. [`app/function_app.py`](../app/function_app.py) binds schedules and the diagnostics route, then delegates immediately into orchestration modules.

Current schedules:

- provisioning every 15 minutes, `run_on_startup=False`
- update hourly
- termed report on `TERMED_REPORT_SCHEDULE`, default `0 0 14 * * 1`
- diagnostics exposed as `GET /api/diagnostics` with Azure Functions function-key auth

## Architecture Decisions

- The sync is stateless and polling-oriented. There is no application database, queue, or persisted cursor.
- ADP is the source of truth for worker lifecycle state and upstream HR attributes consumed by this app. Active Directory is the managed projection target.
- `employeeID` is the canonical cross-system identity key.
- Azure-specific trigger and route concerns stop at the decorated entrypoints. Workflow sequencing lives in service orchestrators, and transport logic lives in focused ADP and LDAP packages.
- Update behavior is safe by default because `UPDATE_DRY_RUN=true` unless an environment explicitly disables it.
- Diagnostics is intentionally read-only and bounded to explicit query modes rather than acting as a general-purpose worker or directory browser.
- Some historical names still include `azuread`, but the runtime target described in this repository is on-prem Active Directory over LDAPS rather than Entra ID.

## Quick Reference

| Entrypoint | Trigger | Default schedule or auth | Reads from | Writes to | Primary output |
| --- | --- | --- | --- | --- | --- |
| `scheduled_provision_new_hires` | Timer | every 15 minutes | ADP, LDAP | LDAP | new AD users, manager links, enabled accounts |
| `scheduled_update_existing_users` | Timer | hourly, `UPDATE_DRY_RUN=true` by default | ADP, LDAP | LDAP when dry run is disabled | logged attribute diffs or applied attribute changes |
| `scheduled_last_30_day_termed_report` | Timer | `TERMED_REPORT_SCHEDULE`, default `0 0 14 * * 1` | ADP | SMTP | emailed CSV report |
| `GET /api/diagnostics` | HTTP GET | function-key auth | ADP, optional LDAP depending on `view` | none | bounded JSON diagnostics payload |

## Key Invariants

- `employeeID` is the canonical join key across ADP and Active Directory.
- Diagnostics code paths are read-only and do not call LDAP write helpers.
- Update sync never mutates create-time-only routing identifiers such as `mail`, `userPrincipalName`, `mailNickname`, `proxyAddresses`, or `targetAddress`.
- Timer runs recompute desired state from external systems instead of relying on local persisted state.
- Fatal orchestration failures are surfaced as failed Azure Functions invocations rather than being treated as successful no-op runs.

## Architecture Map

### System Context Map

```mermaid
flowchart LR
    subgraph Azure["Azure Function App"]
        Host["Azure Functions Host"]
        Triggers["Timer Triggers + Diagnostics Route"]
        Wrappers["Workflow Wrappers\napp/provisioning.py\napp/updates.py\napp/termination_report.py\napp/diagnostics_routes.py"]
        Services["Service Layer\napp/services/*"]
        Domain["Domain Helpers\napp/department/*\napp/diagnostics/*\nprovisioning_* helpers"]
        Integrations["Integration and Transport Layer\napp/adp/*\napp/ldap/*\napp/security.py\nmail gateway adapter"]

        Host --> Triggers --> Wrappers --> Services
        Services --> Domain
        Services --> Integrations
    end

    ADP["ADP OAuth + Workers API"]
    AD["Active Directory over LDAPS"]
    SMTP["SMTP"]
    Insights["Application Insights"]

    Integrations --> ADP
    Integrations --> AD
    Integrations --> SMTP
    Host --> Insights
```

This map is the highest-level runtime view: Azure Functions receives timer or HTTP events, wrapper modules hand off immediately to service orchestration, and the service layer coordinates domain rules plus ADP, LDAP, and SMTP transport boundaries.

### Code Layer Map

```mermaid
flowchart TB
    Root["function_app.py\nroot discovery shim"]
    Entry["app/function_app.py\nAzure decorators only"]
    Wrappers["Workflow Wrappers\nprovisioning.py\nupdates.py\ntermination_report.py\ndiagnostics_routes.py"]
    Services["Service Orchestrators\napp/services/provisioning_service.py\napp/services/update_service.py\napp/services/termed_report_service.py\napp/services/diagnostics_service.py"]
    Helpers["Domain and Workflow Helpers\napp/department/*\napp/diagnostics/*\napp/provisioning_*"]
    Adapters["Gateway Adapters\napp/services/defaults.py"]
    ADP["ADP Package\napp/adp/*"]
    LDAP["LDAP Package\napp/ldap/*"]
    Core["Shared Core\napp/config.py\napp/models.py\napp/constants.py\napp/reporting.py\napp/security.py"]
    Facades["Compatibility Facades\napp/adp_client.py\napp/ldap_client.py\napp/department_resolution.py"]

    Root --> Entry --> Wrappers --> Services
    Wrappers --> Core
    Services --> Helpers
    Services --> Adapters
    Services --> Core
    Adapters --> ADP
    Adapters --> LDAP
    Facades -. legacy imports .-> ADP
    Facades -. legacy imports .-> LDAP
    Facades -. legacy imports .-> Helpers
```

The key boundary is `wrappers -> services -> adapters/packages`. The wrappers stay Azure-specific, the services own workflow sequencing, and the adapter plus package layers own transport details and normalization logic.

## Runtime Topology

- The repository deploys one Azure Function App target, `adp-to-azuread`, and the runtime surface is limited to three timer triggers plus one HTTP diagnostics route.
- The current deployment target is Azure Functions Flex Consumption. The deployment workflow uses remote build so Python dependencies are built during deployment and function indexing remains intact in Azure.
- Outbound dependencies are ADP HTTPS with mTLS client certificate material, LDAPS to on-prem Active Directory, SMTP for report delivery, and Azure-native logging/telemetry via the Functions host and Application Insights.
- The repository does not declare or provision network topology. Reachability to on-prem AD, private DNS, firewall rules, and any hybrid/VNet connectivity are environment-owned prerequisites.
- There is no application-side durable storage. The only durable state lives in ADP, Active Directory, SMTP mailboxes, and Azure platform telemetry.
- Certificate and key material are supplied as environment values and materialized to temp files on demand for the worker process lifetime through [`app/security.py`](../app/security.py).
- The diagnostics route is the only inbound HTTP surface exposed by application code.

## Module Layout

### Entrypoint Layer

- [`function_app.py`](../function_app.py): Azure Functions root discovery shim
- [`app/function_app.py`](../app/function_app.py): decorated schedule and route handlers only

### Config And Type Layer

- [`app/config.py`](../app/config.py): environment parsing, defaults, and validation
- [`app/models.py`](../app/models.py): typed settings and diagnostics/domain result models
- [`app/constants.py`](../app/constants.py): LDAP attribute names, ADP HTTP defaults, update denylist, and search attribute lists
- [`app/reporting.py`](../app/reporting.py): cross-cutting summary-counter helper used by provisioning and other orchestration paths

### Security And Secret Materialization

- [`app/security.py`](../app/security.py): resolves certificate and key material from env vars, supports path/PEM/base64 input, caches temp files, and cleans them up via `atexit`

### Integration Layer

- [`app/adp/`](../app/adp): focused ADP transport and parsing modules
  - [`api.py`](../app/adp/api.py): ADP auth, mTLS setup, bounded retries, and workers pagination
  - [`dates.py`](../app/adp/dates.py): worker date parsing and hire/termination extraction
  - [`identity.py`](../app/adp/identity.py): employeeID and account-string normalization
  - [`names.py`](../app/adp/names.py): legal, preferred, and display-name helpers
  - [`assignments.py`](../app/adp/assignments.py): department, manager, company, and location extraction
  - [`status.py`](../app/adp/status.py): active/inactive derivation and AD userAccountControl mapping
  - [`passwords.py`](../app/adp/passwords.py): password generation for provisioning
  - [`workers.py`](../app/adp/workers.py): compatibility export surface for legacy worker-helper imports
  - [`dedupe.py`](../app/adp/dedupe.py): duplicate-profile logging and `employeeID` dedupe
- [`app/ldap/`](../app/ldap): focused LDAP transport and directory modules
  - [`connection.py`](../app/ldap/connection.py): TLS config, server creation, bind/unbind, and transport diagnostics
  - [`directory.py`](../app/ldap/directory.py): AD lookup helpers and collision inspection
  - [`planning.py`](../app/ldap/planning.py): attribute planning, diffing, and denylist filtering
  - [`modify.py`](../app/ldap/modify.py): modify transport and reconnect recovery
  - [`updates.py`](../app/ldap/updates.py): compatibility wrapper preserving the legacy LDAP update import surface
- [`app/adp_client.py`](../app/adp_client.py) and [`app/ldap_client.py`](../app/ldap_client.py): compatibility facades that preserve legacy import paths while delegating into the split packages

### Business Rules Layer

- [`app/department/catalog.py`](../app/department/catalog.py): canonical departments, regex catalogs, and confidence constants
- [`app/department/normalization.py`](../app/department/normalization.py): normalization and confidence-label helpers
- [`app/department/signals.py`](../app/department/signals.py): ADP evidence collection across assignment payloads
- [`app/department/title_inference.py`](../app/department/title_inference.py): title-based department inference
- [`app/department/candidates.py`](../app/department/candidates.py): candidate mapping, scoring, and guardrail helpers
- [`app/department/resolver.py`](../app/department/resolver.py): Department Resolution V2 orchestration and compatibility exports
- [`app/department_resolution.py`](../app/department_resolution.py): compatibility facade for department resolution imports
- [`docs/department-resolution-v2.md`](./department-resolution-v2.md): behavior reference for department mapping rules and fallbacks

### Diagnostics Projection Layer

- [`app/diagnostics/serializers.py`](../app/diagnostics/serializers.py): read-only worker, summary, department-diff, and recent-hires payload builders
- [`app/diagnostics/__init__.py`](../app/diagnostics/__init__.py): diagnostics projection exports used by the diagnostics service

### Service Layer

- [`app/services/interfaces.py`](../app/services/interfaces.py): protocol-style gateway contracts and opened-directory context
- [`app/services/defaults.py`](../app/services/defaults.py): default ADP, LDAP, and SMTP gateway adapters built from the existing helper functions
- [`app/services/provisioning_service.py`](../app/services/provisioning_service.py): provisioning workflow orchestrator
- [`app/services/update_service.py`](../app/services/update_service.py): update workflow orchestrator
- [`app/services/termed_report_service.py`](../app/services/termed_report_service.py): termed-report workflow orchestrator
- [`app/services/diagnostics_service.py`](../app/services/diagnostics_service.py): diagnostics query service and shared projections

### Workflow Wrapper Layer

- [`app/provisioning.py`](../app/provisioning.py): thin builder and compatibility wrapper for new-hire provisioning
- [`app/provisioning_filters.py`](../app/provisioning_filters.py): recent-hire eligibility helper
- [`app/provisioning_directory.py`](../app/provisioning_directory.py): existing-user, manager, and manager-department lookup helpers
- [`app/provisioning_identity.py`](../app/provisioning_identity.py): create-time identifier and LDAP attribute planning
- [`app/provisioning_create.py`](../app/provisioning_create.py): add retry loop, collision handling, and account enablement
- [`app/provisioning_ops.py`](../app/provisioning_ops.py): provisioning create-path orchestration wrapper
- [`app/updates.py`](../app/updates.py): thin builder and candidate-selection wrapper for existing-user updates
- [`app/termination_report.py`](../app/termination_report.py): thin builder plus termed-report row/render/email helpers
- [`app/diagnostics_routes.py`](../app/diagnostics_routes.py): HTTP diagnostics controller that delegates to the diagnostics data service

### Compatibility And Test Support

- [`app/azure_compat.py`](../app/azure_compat.py): import shim so local tests can import the package when `azure-functions` is unavailable
- [`tests/`](../tests): unit and orchestration-behavior coverage aligned to the package structure
- [`tests/integration/`](../tests/integration): opt-in live smoke coverage for ADP, LDAP, SMTP, and hosted diagnostics
- [`docs/integration-tests.md`](./integration-tests.md): required env vars and run instructions for the live test layer

## Execution Flows

### Provisioning Flow

Handler path:

- [`app/function_app.py`](../app/function_app.py) -> [`app/provisioning.py`](../app/provisioning.py) -> [`app/services/provisioning_service.py`](../app/services/provisioning_service.py)

Flow summary:

1. Timer fires.
2. Fetch ADP token.
3. Fetch ADP workers and dedupe by `employeeID`.
4. Filter to recent hires inside `SYNC_HIRE_LOOKBACK_DAYS`.
5. Validate LDAP config and CA bundle.
6. Open LDAP connection.
7. For each recent hire:
   - check if user already exists by `employeeID`
   - resolve manager DN
   - resolve department via Department Resolution V2
   - build deterministic CN, `sAMAccountName`, UPN, and mail values
   - create the account with collision and bind-loss handling
   - set password and enable the account
8. Log a run summary.
9. Raise `RuntimeError` on fatal orchestration failures so the Functions host can treat the invocation as failed.

### Update Flow

Handler path:

- [`app/function_app.py`](../app/function_app.py) -> [`app/updates.py`](../app/updates.py) -> [`app/services/update_service.py`](../app/services/update_service.py)

Flow summary:

1. Timer fires.
2. Fetch ADP token.
3. Fetch ADP workers and dedupe by `employeeID`.
4. Select update candidates from ADP based on `UPDATE_LOOKBACK_DAYS`, `UPDATE_INCLUDE_MISSING_LAST_UPDATED`, and country filtering.
5. Validate LDAP config and CA bundle.
6. Open LDAP connection.
7. For each candidate:
   - search AD by `employeeID`
   - if terminated, target `userAccountControl=514`
   - otherwise compute desired attributes with LDAP planner and department resolution
   - diff desired vs current AD attributes
   - log a dry-run or apply modifications
8. Preserve create-time-only email routing identifiers by filtering them from update changes.
9. Raise `RuntimeError` on fatal orchestration failures so the Functions host can treat the invocation as failed.

### Termed Report Flow

Handler path:

- [`app/function_app.py`](../app/function_app.py) -> [`app/termination_report.py`](../app/termination_report.py) -> [`app/services/termed_report_service.py`](../app/services/termed_report_service.py)

Flow summary:

1. Timer fires.
2. Fetch ADP token.
3. Fetch ADP workers and dedupe by `employeeID`.
4. Filter to workers terminated inside `TERMED_REPORT_LOOKBACK_DAYS`.
5. Project rows for CSV output.
6. Render CSV in memory.
7. Send the email through SMTP.
8. Raise `RuntimeError` on fatal orchestration failures so the Functions host can treat the invocation as failed.

### Diagnostics Flow

Handler path:

- [`app/function_app.py`](../app/function_app.py) -> [`app/diagnostics_routes.py`](../app/diagnostics_routes.py) -> [`app/services/diagnostics_service.py`](../app/services/diagnostics_service.py)

Flow summary:

1. HTTP GET arrives at `/api/diagnostics` under the shared Function-level auth boundary.
2. Query parameter `view` selects the diagnostics mode.
3. `summary` and `department-diff` fetch ADP and LDAP data in parallel.
4. `worker` and `recent-hires` fetch ADP only.
5. Results are returned as JSON with bounded, explicit response shapes.

## Data Flow

### ADP Acquisition

ADP source acquisition is implemented in [`app/adp/`](../app/adp) and exposed through [`app/adp_client.py`](../app/adp_client.py):

- token retrieval uses client credentials plus mTLS certificate material
- outbound HTTP uses bounded retries with exponential backoff
- workers are paginated with `$top` and `$skip`
- worker payloads are normalized through shared helper functions instead of repeated shape parsing

### Domain Decision Path

Department mapping is a distinct subsystem:

- provisioning uses it when creating accounts
- update sync uses it when deriving desired department changes

The resolver merges multiple evidence sources:

- cost center description
- assigned and home departments
- manager department
- title inference
- occupational classifications
- legacy department signals

It then applies canonical mapping, admin gating, manager-alignment guardrails, and fallback behavior.

### LDAP Write Path

LDAP writes are staged rather than done ad hoc:

1. derive desired attributes
2. diff against current entry state
3. filter prohibited changes
4. apply modify operations with bind-loss recovery

Create-time-only email routing attributes are defined in [`app/constants.py`](../app/constants.py) and filtered out of update mutations in [`app/ldap/updates.py`](../app/ldap/updates.py).

The identity anchor is `employeeID`:

- provisioning uses it to determine whether a user already exists
- updates use it as the primary AD lookup key
- diagnostics uses it for worker correlation and ADP-vs-AD comparisons

## Source Of Truth And Attribute Ownership

- `employeeID` is the canonical join key across ADP and Active Directory. Provisioning, updates, diagnostics, and duplicate handling all converge on that field.
- ADP is authoritative for upstream worker attributes consumed here, including employment status, hire and termination dates, business title, company, work location fields, department evidence, and manager employee identifier.
- Active Directory is authoritative for directory object existence, distinguished names, current attribute state, and manager DN resolution used during diff and create flows.
- CN, `sAMAccountName`, `userPrincipalName`, and mail-routing identifiers are derived secondary identifiers used during provisioning rather than primary join keys.
- Update sync intentionally manages only the bounded attribute set planned in [`app/ldap/planning.py`](../app/ldap/planning.py) and searched via `AD_UPDATE_SEARCH_ATTRIBUTES` in [`app/constants.py`](../app/constants.py). Attributes outside that planned set are out of scope.
- Create-time-only routing identifiers such as `mail`, `userPrincipalName`, `mailNickname`, `proxyAddresses`, and `targetAddress` are intentionally excluded from update mutations.
- Diagnostics surfaces compact operational projections, not the full ADP payload and not a general-purpose AD browser.

## Config And Secrets

The configuration model is fully environment-driven.

- [`app/config.py`](../app/config.py) parses booleans, integers, CSV lists, and required env sets
- [`app/models.py`](../app/models.py) defines typed settings objects
- [`local.settings.example.json`](../local.settings.example.json) provides the committed local template

Secret-backed file handling is centralized in [`app/security.py`](../app/security.py):

- `ADP_CERT_PEM` and `ADP_CERT_KEY` can be file paths, PEM text, or base64 payloads
- LDAP and ADP CA bundles resolve explicitly, with `certifi` fallback
- temp cert files are tracked and cleaned deterministically
- secret payload content is not logged

## Security Model

- The diagnostics route is explicitly configured with Azure Functions function-key auth in [`app/function_app.py`](../app/function_app.py). Requests must include a valid function key or host key unless stronger platform authentication is added outside this repository. All supported diagnostics views currently share that same auth boundary; there is no per-view authorization layer in this repository.
- Diagnostics is read-only, but `view=worker` can return employee identifiers, names, titles, company, department, hire date, and termination date. Treat the route as an operational PII surface rather than a public health check.
- The application code reads secrets only from environment variables. Repository guidance expects deployed secrets to come from Azure App Settings or Key Vault-backed settings, while local development uses the untracked `local.settings.json`.
- LDAP write scope is bounded operationally by the bind account permissions plus the configured `LDAP_SEARCH_BASE` and `LDAP_CREATE_BASE`. The repository does not independently enforce a richer OU or attribute-level authorization model.
- Update-path guardrails explicitly block mutation of create-time-only mail-routing identifiers. Diagnostics code paths never call LDAP write helpers.
- Secret contents are not logged, but operational logs can contain employee identifiers, distinguished names, department decisions, and dry-run/live update deltas for troubleshooting.

## Tests, CI, And Deployment

### Tests

The test suite in [`tests/`](../tests) is organized by subsystem and covers:

- config/env parsing
- ADP retry behavior
- diagnostics route modes
- provisioning collision logic
- update diff and denylist behavior
- department resolution rules
- secret materialization and cleanup
- termination report selection and email orchestration

There is also an opt-in live integration layer under [`tests/integration/`](../tests/integration):

- ADP token and workers fetch smoke
- LDAP bind and search smoke
- SMTP send smoke for the termed report
- Azure-hosted diagnostics contract smoke

The live layer skips by default and only runs when the required environment variables are present. See [`docs/integration-tests.md`](./integration-tests.md).

The live suite now includes a separately gated end-to-end update workflow smoke test with `dry_run=True`. That exercises the scheduled update path without enabling live write behavior.

### CI

Verification is defined in [`verify.yml`](../.github/workflows/verify.yml):

1. install dependencies
2. run `pytest -q`
3. run `py_compile`
4. run `ruff`
5. run `mypy`

### Deployment

Deployment is defined in [`main_adp-to-azuread.yml`](../.github/workflows/main_adp-to-azuread.yml).

The workflow now builds a curated `release.zip` that contains only runtime payload:

- `function_app.py`
- `host.json`
- `requirements.txt`
- `app/**`

That artifact is deployed directly to the Azure Function App `adp-to-azuread`.

The current deployment target is Flex Consumption, so the workflow keeps `remote-build` enabled for correct Python build and function indexing behavior.

Manual publish remains possible via Azure Functions Core Tools, with publish hygiene supported by [`.funcignore`](../.funcignore).

## Operational Characteristics

- The architecture is stateless and polling-oriented.
- Each timer run is independent and re-fetches external state.
- ADP resilience is concentrated in bounded retry logic and worker dedupe.
- LDAP resilience is concentrated in reconnect and bind-loss recovery.
- `UPDATE_DRY_RUN` defaults to `true`, which makes update behavior safe by default.
- Diagnostics is read-only and exposes only explicit supported views.
- Fatal timer-path failures now raise exceptions instead of being treated as successful no-op invocations.

Primary failure boundaries:

- ADP auth failure
- ADP workers fetch failure
- LDAP connect/search/modify/add failure
- SMTP send failure

## Idempotency And Concurrency

- There is no application-level distributed lock, lease table, or persisted cursor. Each invocation recomputes desired state from live ADP and Active Directory data.
- ADP workers are deduped by `employeeID` before downstream workflow decisions, and suspicious duplicate profiles are logged for operator review.
- Provisioning is rerunnable in the sense that it first searches AD by `employeeID` and uses deterministic identifier generation plus collision handling. Repeated runs should not create duplicate accounts for the same `employeeID`.
- Update sync is convergent. It computes desired attributes, diffs against current AD state, and no-ops when values already match. In dry-run mode it logs the same planned changes without writing them.
- The weekly termed report is rerunnable but not idempotent at the mail-transport layer. Repeated successful invocations can resend overlapping CSV content for the same rolling lookback window.
- The repository delegates timer overlap coordination to the Azure Functions runtime. No additional in-repo singleton or overlap suppression mechanism is implemented.
- Partial provisioning is possible. If an AD object is created but password set or account enablement fails later in the flow, a future run will treat that object as existing rather than recreating it.

## Failure Handling And Observability

- ADP token/fetch failures and LDAP open failures fail the entire timer invocation.
- Provisioning logs and counts worker-level exceptions, continues to the next worker when possible, and raises only when the orchestrator loses a usable LDAP session.
- Update search exceptions attempt reconnect-and-continue recovery. Workers missing from AD are skipped. Individual LDAP modify failures are logged in the transport layer and can leave the batch running unless the directory session becomes unavailable to the orchestrator.
- SMTP failure fails the weekly termed-report invocation. There is no built-in resend queue or dead-letter mechanism in this repository.
- Application Insights receives Functions host logs, but the repository does not currently emit custom metrics, correlation IDs, or a separate run-history store.
- Operational visibility is primarily log-based: provisioning emits explicit run-summary counters, update logs dry-run/live per-attribute deltas, and the termed report logs row-count plus cutoff metadata.
- Diagnostics complements logs with bounded read-only inspection. It is intended for targeted operator queries, not for write remediation or bulk export.

## Scale And Operating Assumptions

- Each scheduled run fetches the full ADP worker set needed for that workflow and keeps the relevant working set in process memory.
- Runtime duration and memory use therefore scale roughly with worker population size and payload size rather than with incremental event volume.
- LDAP lookup and write operations are primarily sequential per candidate or hire. The main concurrency in this repository is the diagnostics service fetching ADP and LDAP sources in parallel for summary-style views.
- The current design is intended for scheduled synchronization and targeted operator diagnostics, not for bulk export APIs or high-frequency near-real-time change processing.
- Diagnostics `summary` and `department-diff` views read a broad AD employeeID map, while `worker` and `recent-hires` are narrower ADP-only views.

## Operator Runbook

- ADP auth or fetch failure:
  inspect the failed invocation logs first; validate token endpoint reachability, client credentials, and client certificate material.
- LDAP bind or connect failure:
  validate `LDAP_SERVER`, credentials, CA bundle path, and environment-level network reachability to on-prem AD.
- Partial provisioning after object create:
  check for an existing AD object by `employeeID`; reruns will reconcile against the existing object rather than recreate it.
- Duplicate `employeeID` or duplicate-profile warnings:
  inspect ADP source data and recent worker changes; the workflow logs and dedupes but does not auto-resolve upstream data quality issues.
- SMTP failure:
  treat the weekly report as unsent until a later successful run or a manual resend; the repository has no built-in resend queue.
- Dry-run versus live update verification:
  confirm `UPDATE_DRY_RUN` in the environment and use update logs plus diagnostics views to verify whether a run only planned changes or actually applied them.

## Time Semantics

- Job code normalizes parsed ADP datetimes to UTC when offsets are absent or when timestamps end with `Z`.
- Hire lookback, update lookback, and termed-report lookback calculations use `datetime.now(timezone.utc)` inside the workflow code.
- The termed report renders CSV timestamps in UTC ISO-8601 format.
- The repository does not set a host timezone override in code. Cron interpretation therefore depends on the Azure Functions host configuration for the deployed app.
- The weekly termed report is a rolling `TERMED_REPORT_LOOKBACK_DAYS` window rather than a calendar-week report.

## Design Strengths

- Trigger wiring is cleanly separated from orchestration logic.
- Transport/integration concerns are separated from domain rules.
- Department logic is explicit and documented rather than hidden in procedural branches.
- Update guardrails prevent accidental mutation of create-time-only routing identifiers.
- Shared ADP parsing helpers reduce payload-shape duplication across jobs and diagnostics.
- CI now validates the same package layout that gets deployed.

## Current Tradeoffs

- The old public module names remain in place as compatibility facades for external imports and test seams, but internal application code now imports the split packages directly.
- The previous single-file hotspots are now split across focused helper modules. The densest remaining logic is mostly in [`app/provisioning_create.py`](../app/provisioning_create.py), [`app/adp/assignments.py`](../app/adp/assignments.py), and [`app/department/candidates.py`](../app/department/candidates.py), where the domain complexity still naturally lives.
- The directory gateway now owns update-path employee lookup, department lookup, and change application. The remaining live LDAP connection exposure is concentrated in the create-user path used by provisioning operations.
- The live integration layer now covers transport smoke plus a gated update-workflow dry run, but it is still intentionally not a full write-path end-to-end suite.
- Diagnostics projections now live in their own package, which reduces route/service duplication. Some shared helper coupling remains because diagnostics and workflows still consume the same ADP and department-domain rules.

## Extension Points

- To add a new job:
  - wire the handler in [`app/function_app.py`](../app/function_app.py)
  - add typed settings in [`app/models.py`](../app/models.py)
  - parse env in [`app/config.py`](../app/config.py)
  - add or extend a gateway/orchestrator in [`app/services/`](../app/services)
  - add tests under [`tests/`](../tests)
- To change synced AD attributes:
  - update [`app/constants.py`](../app/constants.py)
  - update planning logic in [`app/ldap/planning.py`](../app/ldap/planning.py)
  - update modify/recovery behavior in [`app/ldap/modify.py`](../app/ldap/modify.py)
- To evolve department mapping:
  - update [`app/department/catalog.py`](../app/department/catalog.py), [`app/department/candidates.py`](../app/department/candidates.py), and [`app/department/resolver.py`](../app/department/resolver.py)
  - keep [`docs/department-resolution-v2.md`](./department-resolution-v2.md) aligned
  - update [`tests/test_department_resolution.py`](../tests/test_department_resolution.py)
- To add diagnostics views:
  - extend `SUPPORTED_DIAGNOSTICS_VIEWS`
  - add route branching in [`app/diagnostics_routes.py`](../app/diagnostics_routes.py)
- To add more report sinks:
  - extend the selection -> row building -> render -> transport pipeline in [`app/termination_report.py`](../app/termination_report.py)

## Non-Goals

- This repository is not an event-driven identity platform. It intentionally uses polling timers rather than upstream HR webhooks or queued domain events.
- It is not the system of record for worker lifecycle data. ADP remains authoritative for upstream worker state.
- It is not a historical warehouse or audit database. The app does not persist local snapshots of prior runs.
- It is not a full identity-governance or access-certification system.
- It is not a general-purpose Active Directory reconciliation engine for arbitrary attributes or arbitrary OUs.

## Glossary

- worker: one ADP worker payload after retrieval and any dedupe logic
- candidate: a worker selected for downstream update evaluation after lookback and country filters
- diagnostics projection: a compact read-only JSON view built for the diagnostics route rather than the full source payload
- create-time-only routing identifiers: mail-related identifiers such as `mail`, `userPrincipalName`, `mailNickname`, `proxyAddresses`, and `targetAddress` that are intentionally excluded from update sync
- directory gateway: the service abstraction that opens LDAP connections, performs employee lookups, resolves manager departments, and applies changes
- compatibility facade: a thin module kept to preserve legacy import paths while delegating into the newer split packages

## Sequence Diagrams

### Provisioning Timer

```mermaid
sequenceDiagram
    participant Timer as Azure Timer
    participant Func as app.function_app.scheduled_provision_new_hires
    participant Wrap as app.provisioning.run_scheduled_provision_new_hires
    participant Flow as ProvisioningOrchestrator
    participant Work as WorkerProvider
    participant Dir as DirectoryGateway
    participant Dept as app.department.resolver
    participant AD as Active Directory

    Timer->>Func: fire schedule
    Func->>Wrap: run_scheduled_provision_new_hires(mytimer)
    Wrap->>Flow: build and run orchestrator
    Flow->>Work: fetch_workers(context)
    Work-->>Flow: workers
    Flow->>Flow: dedupe by employeeID
    Flow->>Flow: filter recent hires
    Flow->>Dir: open_directory(...)
    Dir-->>Flow: directory context
    loop each recent hire
        Flow->>AD: search by employeeID
        alt existing user found
            Flow->>AD: update manager when needed
        else new user
            Flow->>Dept: resolve_local_ac_department(worker, manager_department)
            Dept-->>Flow: department proposal
            Flow->>AD: add user with deterministic CN/UPN/mail
            alt collision or bind-loss
                Flow->>Dir: reconnect / conflict diagnostics / retry
            end
            Flow->>AD: set password and enable account
        end
    end
    Flow-->>Func: summary logged
    alt fatal orchestration failure
        Flow-->>Func: raise RuntimeError
    end
```

### Update Timer

```mermaid
sequenceDiagram
    participant Timer as Azure Timer
    participant Func as app.function_app.scheduled_update_existing_users
    participant Wrap as app.updates.run_scheduled_update_existing_users
    participant Flow as UpdateOrchestrator
    participant Work as WorkerProvider
    participant Dir as DirectoryGateway
    participant Dept as app.department.resolver
    participant AD as Active Directory

    Timer->>Func: fire schedule
    Func->>Wrap: run_scheduled_update_existing_users(mytimer)
    Wrap->>Flow: build and run orchestrator
    Flow->>Work: fetch_workers(context)
    Work-->>Flow: workers
    Flow->>Flow: dedupe and select update candidates
    Flow->>Dir: open_directory(...)
    Dir-->>Flow: directory context
    loop each candidate
        Flow->>AD: search by employeeID
        alt worker missing in AD
            Flow->>Flow: increment missing_in_ad
        else worker found
            alt worker is terminated
                Flow->>Flow: desired userAccountControl=514
            else active worker
                Flow->>Dept: resolve department when needed
                Dept-->>Flow: department proposal
                Flow->>Flow: build desired attributes
            end
            Flow->>Flow: diff current vs desired
            alt UPDATE_DRY_RUN=true
                Flow->>Flow: log planned updates
            else apply changes
                Flow->>AD: modify entry
                alt bind-loss or reconnect needed
                    Flow->>Dir: reconnect and recover
                end
            end
        end
    end
    Flow-->>Func: completion logged
    alt fatal orchestration failure
        Flow-->>Func: raise RuntimeError
    end
```

### Weekly Termed Report Timer

```mermaid
sequenceDiagram
    participant Timer as Azure Timer
    participant Func as app.function_app.scheduled_last_30_day_termed_report
    participant Wrap as app.termination_report.run_scheduled_last_30_day_termed_report
    participant Flow as TermedReportOrchestrator
    participant Work as WorkerProvider
    participant Mail as MailGateway
    participant SMTP as SMTP Server

    Timer->>Func: fire schedule
    Func->>Wrap: run_scheduled_last_30_day_termed_report(mytimer)
    Wrap->>Flow: build and run orchestrator
    Flow->>Work: fetch_workers(context)
    Work-->>Flow: workers
    Flow->>Flow: dedupe workers
    Flow->>Flow: select_recent_terminated_employees(...)
    Flow->>Flow: build_termed_report_rows(...)
    Flow->>Flow: render_termed_report_csv(...)
    Flow->>Mail: send_report(...)
    Mail->>SMTP: send message
    SMTP-->>Mail: accepted
    Flow-->>Func: completion logged
    alt fatal orchestration failure
        Flow-->>Func: raise RuntimeError
    end
```

### Diagnostics Route

```mermaid
sequenceDiagram
    participant Client as HTTP Client
    participant Func as app.function_app.diagnostics
    participant Diag as app.diagnostics_routes.diagnostics_handler
    participant Query as DiagnosticsDataService
    participant Work as WorkerProvider
    participant LDAP as diagnostics LDAP query helper
    participant AD as Active Directory

    Client->>Func: GET /api/diagnostics?view=...
    Func->>Diag: diagnostics_handler(req)
    alt view=summary or department-diff
        Diag->>Query: load_parallel_sources()
        par worker fetch
            Query->>Work: fetch_workers(context)
            Work-->>Query: workers
        and LDAP fetch
            Query->>LDAP: fetch_department_map()
            LDAP->>AD: paged search employeeID + department
            AD-->>LDAP: directory rows
            LDAP-->>Query: employeeID->department map
        end
        alt view=summary
            Query->>Query: compute counts
        else view=department-diff
            Query->>Query: compute ADP-vs-AD diffs
        end
        Diag-->>Client: JSON response
    else view=worker
        Diag->>Query: fetch_workers()
        Query->>Work: fetch_workers(context)
        Work-->>Query: workers
        Query->>Query: build one worker snapshot
        Diag-->>Client: JSON response
    else view=recent-hires
        Diag->>Query: fetch_workers()
        Query->>Work: fetch_workers(context)
        Work-->>Query: workers
        Query->>Query: sort active hires and cap limit
        Diag-->>Client: JSON response
    else unsupported view
        Diag-->>Client: 400 JSON error
    end
```

# ADP to Azure AD / Local AD Sync

This Azure Functions project syncs worker data from ADP Workforce Now into on-prem Active Directory over LDAPS.

## What It Does

- Provisions new users from ADP (`scheduled_adp_sync` timer trigger).
- Compares and updates existing AD users from ADP (`scheduled_adp_update`, dry run by default).
- Exposes HTTP endpoints for payload inspection and mapping diagnostics:
  - `POST /api/process`
  - `GET /api/export`
- Generates an offline department-change report with manager context and audit fields.

## Synced AD Attributes

- `employeeID`
- `cn`
- `displayName`
- `givenName`
- `sn`
- `sAMAccountName`
- `userPrincipalName`
- `mail`
- `title`
- `department`
- `company`
- `manager`
- `l`
- `st`
- `postalCode`
- `streetAddress`
- `co`
- `userAccountControl`

## Department Resolution (V2)

Department mapping now uses a candidate/confidence model with guardrails:

- Canonical departments:
  - `Administration`
  - `Engineering`
  - `Finance`
  - `Human Resources`
  - `Information Technology`
  - `Operations`
  - `Sales`
  - `Supply Chain`
- `Customer Service*` assigned department values resolve to `Sales`.
- Ambiguous labels (for example `Professionals`, `First/Mid-Level Officials and Managers`) do not force `Administration`.
- `Administration` requires strong evidence (admin-coded assigned dept, manager in Administration, or strong admin title signal).
- If current AD department equals manager department, low-confidence evidence cannot override it.

Detailed logic and audit fields are documented in `docs/department-resolution-v2.md`.

## Configuration

Set these environment variables in Azure App Settings or `local.settings.json` (`Values`):

### ADP

- `ADP_TOKEN_URL`
- `ADP_EMPLOYEE_URL`
- `ADP_CLIENT_ID`
- `ADP_CLIENT_SECRET`
- `ADP_CERT_PEM`
- `ADP_CERT_KEY`
- Optional: `ADP_CA_BUNDLE_PATH`

### LDAP / AD

- `LDAP_SERVER`
- `LDAP_USER`
- `LDAP_PASSWORD`
- `LDAP_SEARCH_BASE`
- `LDAP_CREATE_BASE`
- `CA_BUNDLE_PATH`
- `UPN_SUFFIX`

### Update Job

- `UPDATE_DRY_RUN` (default: `true`)
- `UPDATE_LOOKBACK_DAYS` (default: `7`)
- `UPDATE_INCLUDE_MISSING_LAST_UPDATED` (default: `true`)
- `UPDATE_LOG_NO_CHANGES` (default: `false`)
- Optional: `LOG_DEPARTMENT_MAPPING`

### Hire Provisioning Job

- `SYNC_HIRE_LOOKBACK_DAYS` (default: `2`)

## Local Run

1. Create and activate a virtual environment.
2. Install dependencies.
3. Start Azurite if you run timer triggers locally.
4. Start Functions host.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
azurite --location ./azurite --silent --debug ./azurite/debug.log
func start --verbose
```

## Generate Department Change Report

Run:

```powershell
.\.venv\Scripts\python.exe generate_adp_current_vs_scheduled_department_report.py
```

Generated report artifacts (local, not source-controlled):

- `adp_active_users_ad_current_vs_scheduled_department.csv`
- `adp_active_users_ad_current_vs_scheduled_department_summary.json`
- optional: `adp_active_users_ad_current_vs_scheduled_department_changes_only.csv`

Report includes:

- current AD department
- manager and manager department
- proposed department (V2)
- change guardrail outcome (`changeAllowed`, `blockReason`)
- winning evidence and confidence
- reason trace fields for auditability

## Build Excel Dry-Run Change Workbook

Use this when you want field-specific worksheets with only impacted users:

```powershell
.\.venv\Scripts\python.exe build_dry_run_change_report_excel.py `
  --input adp_active_users_ad_current_vs_scheduled_department.csv `
  --output dry_run_change_report.xlsx
```

Notes:

- Input must be a dry-run CSV with one row per user.
- The script always builds `README` and `Summary` tabs.
- It builds dedicated tabs for EmployeeID/Name/Title/Department/Manager changes.
- For fields not present in input, tabs are still created with a “no changes / columns missing” note.
- Department tabs include risk flags and change-driver grouping.

Detailed workbook behavior is documented in `docs/dry-run-excel-report.md`.

## Tests

Install test/lint tools (optional):

```powershell
pip install pytest flake8
```

Run:

```powershell
pytest -q
flake8
```

## Deployment

Manual publish:

```powershell
func azure functionapp publish <APP_NAME> --python
```

This repo also includes GitHub Actions workflows for deployment on pushes to `main`.

## Security

See `SECURITY.md` for responsible disclosure.

## License

MIT. See `LICENSE`.

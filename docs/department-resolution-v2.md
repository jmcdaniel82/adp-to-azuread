# Department Resolution V2

This document describes the department proposal logic used by:

- `scheduled_update_existing_users` in `function_app.py`
- `generate_adp_current_vs_scheduled_department_report.py`

## Canonical Departments

- Administration
- Engineering
- Finance
- Human Resources
- Information Technology
- Operations
- Sales
- Supply Chain

All comparison logic normalizes to canonical values where possible.  
Example: `Information Technology | Security` normalizes to `Information Technology` for comparisons.

## Evidence Sources

Candidates are built from multiple sources:

- `costCenterDescription` from ADP department org-unit description (`nameCode.longName`, fallback `shortName`) (high confidence)
- `assignedDept` / `homeDept` (high confidence)
- `managerDepartment` (medium confidence when canonical)
- title inference (`jobTitle` / business title) (medium confidence)
- `occupationalClassifications` (low unless explicit canonical)
- legacy department signal (low unless explicit canonical)

The resolver picks the best department by confidence first, score second, with an Administration penalty when admin gating is not met.

## Hard Rules and Guardrails

### Customer Service override

If `assignedDept` or `costCenterDescription` starts with `Customer Service` (case-insensitive), map to `Sales`.

### Ambiguous values

These values are treated as ambiguous:

- `Professionals`
- `First/Mid-Level Officials and Managers`
- `Administrative Support Workers`
- `Mexico Corporate`

Ambiguous labels do not directly force `Administration`.

### Administration gating

`Administration` is allowed only with strong evidence:

- cost center description explicitly admin-coded, or
- assigned/home department explicitly admin-coded, or
- manager department is Administration, or
- title strongly indicates admin role (for example Administrative Assistant / Executive Assistant / Receptionist / Office Administrator / Office Manager / Administrative Services).

If gating fails, fallback chain applies.

### Manager-alignment guardrail

If normalized current AD department equals normalized manager department, low-confidence ambiguous signals are blocked from driving a change.

This prevents the known failure mode where workers aligned with manager/current are moved due to weak labels.

## Fallback Chain

When chosen evidence is ambiguous or admin-gated:

1. keep current AD department (if present)
2. else use manager department (if canonical)
3. else use title-inferred department (if canonical)
4. else return no proposal (`None` / needs review path)

## Report Audit Fields

`adp_active_users_ad_current_vs_scheduled_department.csv` (generated locally) includes:

- `proposedDepartmentFromScheduledUpdate`
- `proposedDepartmentV2`
- `changeAllowed`
- `blockReason`
- `evidenceUsed`
- `confidence`
- `titleInferredDept`
- `departmentChangeReferenceField`
- `departmentChangeReferenceValue`
- `departmentChangePrimaryReason`
- `departmentChangeReasonTrace`

These fields let you trace why each row was changed, blocked, or left unchanged.
`departmentChangeReferenceField` may now be `costCenterDescription` when cost center description evidence drives the decision.
The CSV/summary outputs are runtime artifacts and are not required as committed repo files.

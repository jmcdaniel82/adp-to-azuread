# Dry-Run Excel Change Report

Script: `build_dry_run_change_report_excel.py`

## Purpose

Build an Excel workbook from a dry-run CSV where each worksheet lists only users who would change for a given field/group.

## Usage

```powershell
.\.venv\Scripts\python.exe build_dry_run_change_report_excel.py `
  --input <dry-run.csv> `
  --output dry_run_change_report.xlsx
```

Defaults:

- input: `adp_active_users_ad_current_vs_scheduled_department.csv`
- output: `dry_run_change_report.xlsx`

## Workbook Tabs

- `README`
- `Summary`
- `EmployeeID_Changes`
- `Name_Changes`
- `Title_Changes`
- `Department_Changes`
- `Department_MissingOrNoDept`
- `Dept_ChangeDrivers`
- `Manager_Changes`

The script may also add extra `*_Changes` tabs for additional detected current/proposed column pairs (excluding address-like fields).

## Change Detection

A field is considered changed when normalized values differ:

- trim whitespace
- collapse internal whitespace
- case-insensitive compare
- treat null/empty-equivalent values as empty

## Department Risk Flags

`Department_Changes` includes:

- `currentEqualsManagerDept`
- `proposedEqualsManagerDept`
- `conflictsManagerDept`

Rows are sorted with conflict-risk rows first (`conflictsManagerDept=TRUE` first).

## Department Driver Aggregation

`Dept_ChangeDrivers` groups changed department rows by:

- `departmentChangeReferenceField`
- `departmentChangeReferenceValue`

and reports:

- `changeCount`
- `conflictsManagerDeptCount`
- `conflictsManagerDeptRate`

## Formatting

Each tab is written as an Excel Table with:

- filter dropdowns enabled
- header row frozen
- automatic reasonable column widths
- striped table styling

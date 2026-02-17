import csv
import json
import os
import ssl
from collections import Counter
from pathlib import Path

from ldap3 import BASE, NTLM, SUBTREE, Connection, Server, Tls

import function_app


def load_local_settings() -> None:
    """Load local.settings.json Values into env vars when running locally."""
    settings_path = Path("local.settings.json")
    if not settings_path.exists():
        return
    try:
        data = json.loads(settings_path.read_text(encoding="utf-8-sig"))
    except Exception:
        return
    values = data.get("Values", {})
    if not isinstance(values, dict):
        return
    for key, value in values.items():
        if value is None:
            continue
        os.environ.setdefault(str(key), str(value))


def normalize_id(emp_id: str) -> str:
    """Normalize employee IDs to uppercase for stable joins."""
    return (emp_id or "").strip().upper()


def entry_value(entry, attr_name: str):
    """Safely read attribute values from ldap3 entries."""
    attr = getattr(entry, attr_name, None)
    if not attr:
        return None
    return attr.value


def fetch_ad_user_maps():
    """Fetch AD users and manager metadata used by the report."""
    ldap_server = os.getenv("LDAP_SERVER")
    ldap_user = os.getenv("LDAP_USER")
    ldap_password = os.getenv("LDAP_PASSWORD")
    ldap_search_base = os.getenv("LDAP_SEARCH_BASE")
    if not all([ldap_server, ldap_user, ldap_password, ldap_search_base]):
        raise RuntimeError("Missing LDAP configuration for report generation.")

    ca_bundle = function_app.get_ca_bundle()
    tls = Tls(
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLS_CLIENT,
        ca_certs_file=ca_bundle,
    )
    server = Server(ldap_server, port=636, use_ssl=True, tls=tls, get_info=None)
    conn = Connection(
        server,
        user=ldap_user,
        password=ldap_password,
        authentication=NTLM,
        auto_bind=True,
    )

    ad_by_emp = {}
    dn_details = {}
    manager_dns = set()
    page_size = 500
    cookie = None
    try:
        while True:
            conn.search(
                ldap_search_base,
                "(employeeID=*)",
                SUBTREE,
                attributes=["employeeID", "department", "manager", "displayName", "distinguishedName"],
                paged_size=page_size,
                paged_cookie=cookie,
            )
            for entry in conn.entries:
                employee_id = normalize_id(entry_value(entry, "employeeID") or "")
                if not employee_id:
                    continue
                dept = (entry_value(entry, "department") or "").strip()
                manager_dn = (entry_value(entry, "manager") or "").strip()
                dn = str(entry.entry_dn)
                dn_details[dn] = {
                    "displayName": (entry_value(entry, "displayName") or "").strip(),
                    "department": dept,
                    "employeeID": employee_id,
                }
                ad_by_emp[employee_id] = {
                    "department": dept,
                    "manager_dn": manager_dn,
                }
                if manager_dn:
                    manager_dns.add(manager_dn)

            controls = conn.result.get("controls", {})
            cookie = (
                controls.get("1.2.840.113556.1.4.319", {})
                .get("value", {})
                .get("cookie")
            )
            if not cookie:
                break

        for manager_dn in sorted(manager_dns):
            if manager_dn in dn_details:
                continue
            try:
                conn.search(
                    search_base=manager_dn,
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=["displayName", "department", "employeeID"],
                )
                if conn.entries:
                    entry = conn.entries[0]
                    dn_details[manager_dn] = {
                        "displayName": (entry_value(entry, "displayName") or "").strip(),
                        "department": (entry_value(entry, "department") or "").strip(),
                        "employeeID": normalize_id(entry_value(entry, "employeeID") or ""),
                    }
                else:
                    dn_details[manager_dn] = {
                        "displayName": "",
                        "department": "",
                        "employeeID": "",
                    }
            except Exception:
                dn_details[manager_dn] = {
                    "displayName": "",
                    "department": "",
                    "employeeID": "",
                }
    finally:
        conn.unbind()

    return ad_by_emp, dn_details


def build_rows(adp_employees, ad_by_emp, dn_details):
    """Build report rows for active ADP employees."""
    rows = []
    for emp in adp_employees:
        if function_app.get_status(emp) != "Active":
            continue
        emp_id = normalize_id(function_app.extract_employee_id(emp) or "")
        if not emp_id:
            continue

        person = emp.get("person", {})
        first, last = function_app.get_first_last(person)
        full_name = f"{first} {last}".strip()
        title = function_app.extract_business_title(emp) or function_app.extract_assignment_field(emp, "jobTitle") or ""

        ad_record = ad_by_emp.get(emp_id)
        current_dept = (ad_record or {}).get("department", "")
        manager_dn = (ad_record or {}).get("manager_dn", "")

        manager_name = ""
        manager_department = ""
        if manager_dn:
            mgr = dn_details.get(manager_dn, {})
            manager_name = (mgr.get("displayName") or "").strip()
            manager_department = (mgr.get("department") or "").strip()

        resolution = function_app.resolve_local_ac_department(
            emp,
            current_ad_department=current_dept,
            manager_department=manager_department,
        )
        proposed_v2 = (resolution.get("proposedDepartmentV2") or "").strip()
        proposed_legacy = proposed_v2

        missing_in_ad_or_no_dept = "yes" if (not ad_record or not current_dept) else "no"
        if missing_in_ad_or_no_dept == "yes" or not proposed_v2:
            department_would_change = "no"
        else:
            current_cmp = function_app.normalize_department_name(current_dept)
            proposed_cmp = function_app.normalize_department_name(proposed_v2)
            department_would_change = "yes" if current_cmp != proposed_cmp else "no"

        rows.append(
            {
                "employeeID": emp_id,
                "fullName": full_name,
                "title": title,
                "currentADDepartment": current_dept,
                "userManager": manager_name,
                "managerDepartment": manager_department,
                "proposedDepartmentFromScheduledUpdate": proposed_legacy,
                "proposedDepartmentV2": proposed_v2,
                "changeAllowed": str(bool(resolution.get("changeAllowed"))).lower(),
                "blockReason": resolution.get("blockReason") or "",
                "evidenceUsed": resolution.get("evidenceUsed") or "",
                "confidence": resolution.get("confidence") or "",
                "titleInferredDept": resolution.get("titleInferredDept") or "",
                "departmentChangeReferenceField": resolution.get("departmentChangeReferenceField") or "",
                "departmentChangeReferenceValue": resolution.get("departmentChangeReferenceValue") or "",
                "departmentChangePrimaryReason": resolution.get("departmentChangePrimaryReason") or "",
                "departmentChangeReasonTrace": resolution.get("departmentChangeReasonTrace") or "",
                "departmentWouldChange": department_would_change,
                "missingInADOrNoDept": missing_in_ad_or_no_dept,
            }
        )
    return rows


def main() -> None:
    load_local_settings()

    token = function_app.get_adp_token()
    if not token:
        raise RuntimeError("Failed to retrieve ADP token.")

    adp_employees = function_app.get_adp_employees(token)
    if adp_employees is None:
        raise RuntimeError("Failed to retrieve ADP employees.")

    ad_by_emp, dn_details = fetch_ad_user_maps()
    rows = build_rows(adp_employees, ad_by_emp, dn_details)

    output_csv = Path("adp_active_users_ad_current_vs_scheduled_department.csv")
    fieldnames = [
        "employeeID",
        "fullName",
        "title",
        "currentADDepartment",
        "userManager",
        "managerDepartment",
        "proposedDepartmentFromScheduledUpdate",
        "proposedDepartmentV2",
        "changeAllowed",
        "blockReason",
        "evidenceUsed",
        "confidence",
        "titleInferredDept",
        "departmentChangeReferenceField",
        "departmentChangeReferenceValue",
        "departmentChangePrimaryReason",
        "departmentChangeReasonTrace",
        "departmentWouldChange",
        "missingInADOrNoDept",
    ]
    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "totalEmployeesFromADP": len(adp_employees),
        "activeUsers": len(rows),
        "departmentWouldChangeCount": sum(1 for row in rows if row["departmentWouldChange"] == "yes"),
        "missingInADOrNoDeptCount": sum(1 for row in rows if row["missingInADOrNoDept"] == "yes"),
        "blockedChangeCount": sum(1 for row in rows if row["changeAllowed"] == "false"),
        "proposedDepartmentCounts": dict(
            Counter(row["proposedDepartmentFromScheduledUpdate"] for row in rows if row["proposedDepartmentFromScheduledUpdate"])
        ),
        "proposedDepartmentV2Counts": dict(
            Counter(row["proposedDepartmentV2"] for row in rows if row["proposedDepartmentV2"])
        ),
        "reportFile": output_csv.name,
    }
    summary_path = Path("adp_active_users_ad_current_vs_scheduled_department_summary.json")
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"Wrote {output_csv} with {len(rows)} rows.")
    print(f"Wrote {summary_path}.")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

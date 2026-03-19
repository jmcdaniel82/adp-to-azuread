import argparse
import csv
import json
import os
import ssl
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
from ldap3 import BASE, NTLM, SUBTREE, Connection, Server, Tls

from app.adp_client import (
    extract_assignment_field,
    extract_business_title,
    extract_employee_id,
    extract_last_updated,
    extract_manager_id,
    extract_state_from_work,
    extract_work_address_field,
    get_adp_employees,
    get_adp_token,
    get_display_name,
    get_status,
    is_terminated_employee,
)
from app.config import get_update_job_settings
from app.ldap_client import diff_update_attributes, plan_update_attributes
from app.security import get_ca_bundle
from app.updates import select_update_candidates


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


def get_primary_email(mail_value: Any, proxy_addresses: Any, upn_value: Any) -> str:
    """Return the best current primary email from AD attributes."""
    mail = str(mail_value or "").strip()
    if mail:
        return mail

    if isinstance(proxy_addresses, (list, tuple)):
        addresses = [str(value).strip() for value in proxy_addresses if str(value).strip()]
    elif proxy_addresses:
        addresses = [str(proxy_addresses).strip()]
    else:
        addresses = []

    for address in addresses:
        if address.startswith("SMTP:"):
            return address.split(":", 1)[1].strip()
    for address in addresses:
        if address.lower().startswith("smtp:"):
            return address.split(":", 1)[1].strip()

    upn = str(upn_value or "").strip()
    if "@" in upn:
        return upn
    return ""


def get_mailbox_yes_no_from_ad(
    home_mdb: Any,
    home_mta: Any,
    mailbox_guid: Any,
    remote_recipient_type: Any,
    recipient_type_details: Any,
) -> str:
    """Return yes/no using only Exchange-style mailbox attributes from AD."""
    if str(home_mdb or "").strip():
        return "yes"
    if str(home_mta or "").strip():
        return "yes"
    if str(mailbox_guid or "").strip():
        return "yes"
    if str(remote_recipient_type or "").strip():
        return "yes"
    if str(recipient_type_details or "").strip():
        return "yes"
    return "no"


def graph_token_from_env() -> str:
    """Return Microsoft Graph app-only token when graph credentials are configured."""
    tenant_id = os.getenv("GRAPH_TENANT_ID", "").strip()
    client_id = os.getenv("GRAPH_CLIENT_ID", "").strip()
    client_secret = os.getenv("GRAPH_CLIENT_SECRET", "").strip()
    if not tenant_id or not client_id or not client_secret:
        return ""

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    response = requests.post(
        token_url,
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        },
        timeout=30,
    )
    if not response.ok:
        raise RuntimeError(f"Graph token request failed: HTTP {response.status_code} {response.text}")
    payload = response.json()
    return str(payload.get("access_token") or "").strip()


def has_enabled_exchange_plan(assigned_plans: Any) -> str:
    """Return yes/no when Graph reports an enabled Exchange service plan."""
    if not isinstance(assigned_plans, list):
        return "no"
    for plan in assigned_plans:
        if not isinstance(plan, dict):
            continue
        service = str(plan.get("service") or "").strip().lower()
        capability_status = str(plan.get("capabilityStatus") or "").strip().lower()
        if service == "exchange" and capability_status in {"enabled", "warning"}:
            return "yes"
    return "no"


def format_utc_datetime(value: datetime | None) -> str:
    """Format datetimes as UTC ISO-8601 strings for CSV output."""
    if not value:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso_datetime(value: Any) -> datetime | None:
    """Parse Graph-style ISO-8601 timestamps into aware UTC datetimes."""
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_ad_filetime(value: Any) -> datetime | None:
    """Parse AD lastLogonTimestamp values into aware UTC datetimes."""
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)

    text = str(value or "").strip()
    if not text:
        return None

    if not text.isdigit():
        return parse_iso_datetime(text)

    try:
        filetime = int(text)
    except ValueError:
        return None
    if filetime <= 0:
        return None

    epoch_adjusted = filetime - 116444736000000000
    if epoch_adjusted <= 0:
        return None

    try:
        return datetime.fromtimestamp(epoch_adjusted / 10_000_000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def extract_graph_last_active(sign_in_activity: Any) -> dict[str, str]:
    """Return the most recent Entra sign-in timestamp and the field it came from."""
    if not isinstance(sign_in_activity, dict):
        return {"dateTime": "", "source": ""}

    candidates: list[tuple[datetime, str]] = []
    for field_name in (
        "lastSuccessfulSignInDateTime",
        "lastNonInteractiveSignInDateTime",
        "lastSignInDateTime",
    ):
        parsed = parse_iso_datetime(sign_in_activity.get(field_name))
        if parsed:
            candidates.append((parsed, f"entra:{field_name}"))

    if not candidates:
        return {"dateTime": "", "source": ""}

    latest, source = max(candidates, key=lambda item: item[0])
    return {"dateTime": format_utc_datetime(latest), "source": source}


def build_graph_users_url(include_sign_in_activity: bool) -> str:
    """Return the Graph users endpoint with the requested select set."""
    fields = ["id", "employeeId", "mail", "userPrincipalName", "assignedPlans"]
    if include_sign_in_activity:
        fields.append("signInActivity")
    return f"https://graph.microsoft.com/v1.0/users?$select={','.join(fields)}&$top=999"


def fetch_graph_mailbox_maps() -> dict[str, dict[str, str]]:
    """Fetch Graph mailbox state and optional Entra last-activity data."""
    try:
        token = graph_token_from_env()
    except Exception as exc:
        print(f"[WARN] Graph mailbox enrichment unavailable: {exc}")
        return {
            "employee_id": {},
            "mail": {},
            "upn": {},
            "last_active_employee_id": {},
            "last_active_mail": {},
            "last_active_upn": {},
        }

    if not token:
        return {
            "employee_id": {},
            "mail": {},
            "upn": {},
            "last_active_employee_id": {},
            "last_active_mail": {},
            "last_active_upn": {},
        }

    headers = {"Authorization": f"Bearer {token}"}
    include_sign_in_activity = True
    url = build_graph_users_url(include_sign_in_activity)
    by_employee_id: dict[str, str] = {}
    by_mail: dict[str, str] = {}
    by_upn: dict[str, str] = {}
    last_active_by_employee_id: dict[str, dict[str, str]] = {}
    last_active_by_mail: dict[str, dict[str, str]] = {}
    last_active_by_upn: dict[str, dict[str, str]] = {}

    while url:
        response = requests.get(url, headers=headers, timeout=60)
        if not response.ok:
            if include_sign_in_activity and response.status_code in {400, 403}:
                print(
                    "[WARN] Graph sign-in activity unavailable; continuing with mailbox-only "
                    f"enrichment: HTTP {response.status_code} {response.text}"
                )
                include_sign_in_activity = False
                url = build_graph_users_url(include_sign_in_activity)
                by_employee_id.clear()
                by_mail.clear()
                by_upn.clear()
                last_active_by_employee_id.clear()
                last_active_by_mail.clear()
                last_active_by_upn.clear()
                continue
            raise RuntimeError(f"Graph users request failed: HTTP {response.status_code} {response.text}")
        payload = response.json()
        users = payload.get("value", [])
        if not isinstance(users, list):
            raise RuntimeError("Graph users payload did not return a list.")
        for user in users:
            if not isinstance(user, dict):
                continue
            mailbox_yes_no = has_enabled_exchange_plan(user.get("assignedPlans"))
            employee_id = normalize_id(str(user.get("employeeId") or ""))
            mail = str(user.get("mail") or "").strip().lower()
            upn = str(user.get("userPrincipalName") or "").strip().lower()
            last_active = extract_graph_last_active(user.get("signInActivity"))
            if employee_id and employee_id not in by_employee_id:
                by_employee_id[employee_id] = mailbox_yes_no
            if employee_id and last_active["dateTime"] and employee_id not in last_active_by_employee_id:
                last_active_by_employee_id[employee_id] = last_active
            if mail and mail not in by_mail:
                by_mail[mail] = mailbox_yes_no
            if mail and last_active["dateTime"] and mail not in last_active_by_mail:
                last_active_by_mail[mail] = last_active
            if upn and upn not in by_upn:
                by_upn[upn] = mailbox_yes_no
            if upn and last_active["dateTime"] and upn not in last_active_by_upn:
                last_active_by_upn[upn] = last_active
        url = payload.get("@odata.nextLink") or ""

    print(
        f"Wrote Graph mailbox lookup cache: employeeIDs={len(by_employee_id)} "
        f"mail={len(by_mail)} upn={len(by_upn)} "
        f"entraLastActive={len(last_active_by_employee_id)}"
    )
    return {
        "employee_id": by_employee_id,
        "mail": by_mail,
        "upn": by_upn,
        "last_active_employee_id": last_active_by_employee_id,
        "last_active_mail": last_active_by_mail,
        "last_active_upn": last_active_by_upn,
    }


def resolve_mailbox_yes_no(
    employee_id: str,
    primary_email: str,
    upn_value: str,
    graph_maps: dict[str, dict[str, str]],
    ad_mailbox_yes_no: str,
) -> str:
    """Resolve mailbox yes/no from Graph first, then AD Exchange mailbox markers."""
    graph_by_employee_id = graph_maps.get("employee_id", {})
    graph_by_mail = graph_maps.get("mail", {})
    graph_by_upn = graph_maps.get("upn", {})
    employee_key = normalize_id(employee_id)
    mail_key = str(primary_email or "").strip().lower()
    upn_key = str(upn_value or "").strip().lower()

    if employee_key and employee_key in graph_by_employee_id:
        return graph_by_employee_id[employee_key]
    if mail_key and mail_key in graph_by_mail:
        return graph_by_mail[mail_key]
    if upn_key and upn_key in graph_by_upn:
        return graph_by_upn[upn_key]
    return ad_mailbox_yes_no


def resolve_last_active_info(
    employee_id: str,
    primary_email: str,
    upn_value: str,
    graph_maps: dict[str, dict[str, Any]],
    ad_last_active_datetime: str,
) -> dict[str, str]:
    """Resolve effective last-activity from Entra first-class data and AD fallback."""
    graph_by_employee_id = graph_maps.get("last_active_employee_id", {})
    graph_by_mail = graph_maps.get("last_active_mail", {})
    graph_by_upn = graph_maps.get("last_active_upn", {})
    employee_key = normalize_id(employee_id)
    mail_key = str(primary_email or "").strip().lower()
    upn_key = str(upn_value or "").strip().lower()

    entra_last_active = {"dateTime": "", "source": ""}
    if employee_key and employee_key in graph_by_employee_id:
        entra_last_active = graph_by_employee_id[employee_key]
    elif mail_key and mail_key in graph_by_mail:
        entra_last_active = graph_by_mail[mail_key]
    elif upn_key and upn_key in graph_by_upn:
        entra_last_active = graph_by_upn[upn_key]

    ad_dt = parse_iso_datetime(ad_last_active_datetime)
    entra_dt = parse_iso_datetime(entra_last_active.get("dateTime"))

    if entra_dt and ad_dt:
        if entra_dt >= ad_dt:
            return {
                "entraDateTime": format_utc_datetime(entra_dt),
                "entraSource": entra_last_active.get("source", ""),
                "adDateTime": format_utc_datetime(ad_dt),
                "dateTime": format_utc_datetime(entra_dt),
                "source": entra_last_active.get("source", ""),
            }
        return {
            "entraDateTime": format_utc_datetime(entra_dt),
            "entraSource": entra_last_active.get("source", ""),
            "adDateTime": format_utc_datetime(ad_dt),
            "dateTime": format_utc_datetime(ad_dt),
            "source": "ad:lastLogonTimestamp",
        }

    if entra_dt:
        return {
            "entraDateTime": format_utc_datetime(entra_dt),
            "entraSource": entra_last_active.get("source", ""),
            "adDateTime": "",
            "dateTime": format_utc_datetime(entra_dt),
            "source": entra_last_active.get("source", ""),
        }

    if ad_dt:
        return {
            "entraDateTime": "",
            "entraSource": "",
            "adDateTime": format_utc_datetime(ad_dt),
            "dateTime": format_utc_datetime(ad_dt),
            "source": "ad:lastLogonTimestamp",
        }

    return {
        "entraDateTime": "",
        "entraSource": "",
        "adDateTime": "",
        "dateTime": "",
        "source": "",
    }


def get_salary_yes_no(emp: dict) -> str:
    """Return yes/no using ADP remuneration and worker-group markers."""
    assignments = emp.get("workAssignments", [])
    assignment = assignments[0] if assignments and isinstance(assignments[0], dict) else {}
    base = assignment.get("baseRemuneration", {}) if isinstance(assignment, dict) else {}
    worker_groups = assignment.get("workerGroups", []) if isinstance(assignment, dict) else []
    wage_law = assignment.get("wageLawCoverage", {}) if isinstance(assignment, dict) else {}
    custom_group = emp.get("customFieldGroup", {}) if isinstance(emp.get("customFieldGroup"), dict) else {}

    def marker_text(*values: Any) -> str:
        return " | ".join(str(value).strip() for value in values if str(value or "").strip()).lower()

    pay_period_text = marker_text(
        ((base.get("payPeriodRateAmount") or {}).get("nameCode") or {}).get("shortName"),
        ((base.get("payPeriodRateAmount") or {}).get("nameCode") or {}).get("codeValue"),
    )
    if "salary" in pay_period_text:
        return "yes"

    hourly_text = marker_text(
        ((base.get("hourlyRateAmount") or {}).get("nameCode") or {}).get("shortName"),
        ((base.get("hourlyRateAmount") or {}).get("nameCode") or {}).get("codeValue"),
    )
    if "hourly" in hourly_text or hourly_text == "hour":
        return "no"

    for worker_group in worker_groups if isinstance(worker_groups, list) else []:
        group_code = worker_group.get("groupCode", {}) if isinstance(worker_group, dict) else {}
        group_text = marker_text(group_code.get("longName"), group_code.get("shortName"), group_code.get("codeValue"))
        if "salary" in group_text:
            return "yes"
        if "hourly" in group_text:
            return "no"

    wage_text = marker_text(
        (wage_law.get("coverageCode") or {}).get("shortName"),
        (wage_law.get("coverageCode") or {}).get("codeValue"),
    )
    if "non-exempt" in wage_text or "nonexempt" in wage_text:
        return "no"
    if "exempt" in wage_text:
        return "yes"

    code_fields = custom_group.get("codeFields", [])
    for field in code_fields if isinstance(code_fields, list) else []:
        if not isinstance(field, dict):
            continue
        field_text = marker_text(field.get("codeValue"), field.get("shortName"), field.get("longName"))
        if "salary" in field_text:
            return "yes"
        if "hourly" in field_text:
            return "no"

    return "no"


def normalize_text(value: str) -> str:
    """Normalize text for stable comparisons."""
    return (value or "").strip().lower()


def normalize_country(value: str) -> str:
    """Normalize country names/codes for comparison."""
    normalized = normalize_text(value)
    aliases = {
        "united states": "us",
        "united states of america": "us",
        "usa": "us",
        "us": "us",
        "u.s.": "us",
        "mexico": "mx",
        "méxico": "mx",
        "mx": "mx",
    }
    return aliases.get(normalized, normalized)


def build_location_display(street: str, city: str, state: str, postal_code: str, country: str) -> str:
    """Build a readable single-line location string."""
    parts = [(street or "").strip(), (city or "").strip(), (state or "").strip(), (postal_code or "").strip(), (country or "").strip()]
    return ", ".join(part for part in parts if part)


class _EntryAttr:
    def __init__(self, value: Any):
        self.value = value


class _EntryAdapter:
    def __init__(self, attrs: dict[str, Any]):
        self._attrs = dict(attrs)

    def __getitem__(self, key: str) -> _EntryAttr:
        return _EntryAttr(self._attrs[key])

    def __getattr__(self, key: str) -> _EntryAttr:
        if key in self._attrs:
            return _EntryAttr(self._attrs[key])
        raise AttributeError(key)


def effective_value(current_value: Any, attr_name: str, changes: dict[str, list[tuple[Any, list[Any]]]]) -> Any:
    """Return the effective value after applying a diff payload to a current value."""
    if attr_name not in changes:
        return current_value
    ops = changes[attr_name]
    if not ops or not ops[0][1]:
        return ""
    return ops[0][1][0]


def format_changed_attributes(changes: dict[str, list[tuple[Any, list[Any]]]]) -> str:
    """Return a stable pipe-delimited attribute list for report output."""
    return "|".join(sorted(changes))


def open_report_ldap_connection() -> tuple[Connection, str]:
    """Open LDAP connection for report generation and return search base."""
    ldap_server = os.getenv("LDAP_SERVER")
    ldap_user = os.getenv("LDAP_USER")
    ldap_password = os.getenv("LDAP_PASSWORD")
    ldap_search_base = os.getenv("LDAP_SEARCH_BASE")
    if not all([ldap_server, ldap_user, ldap_password, ldap_search_base]):
        raise RuntimeError("Missing LDAP configuration for report generation.")

    ca_bundle = get_ca_bundle()
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
    return conn, ldap_search_base


def fetch_ad_user_maps():
    """Fetch AD users and manager metadata used by the report."""
    conn, ldap_search_base = open_report_ldap_connection()

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
                attributes=[
                    "employeeID",
                    "department",
                    "manager",
                    "displayName",
                    "distinguishedName",
                    "title",
                    "givenName",
                    "sn",
                    "l",
                    "st",
                    "streetAddress",
                    "postalCode",
                    "co",
                    "c",
                    "countryCode",
                    "company",
                    "userAccountControl",
                    "lastLogonTimestamp",
                    "mail",
                    "proxyAddresses",
                    "userPrincipalName",
                    "targetAddress",
                    "mailNickname",
                    "homeMDB",
                    "homeMTA",
                    "msExchMailboxGuid",
                    "msExchRemoteRecipientType",
                    "msExchRecipientTypeDetails",
                ],
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
                    "title": (entry_value(entry, "title") or "").strip(),
                    "givenName": (entry_value(entry, "givenName") or "").strip(),
                    "sn": (entry_value(entry, "sn") or "").strip(),
                }
                ad_by_emp[employee_id] = {
                    "employeeID": employee_id,
                    "distinguishedName": dn,
                    "department": dept,
                    "manager_dn": manager_dn,
                    "displayName": (entry_value(entry, "displayName") or "").strip(),
                    "title": (entry_value(entry, "title") or "").strip(),
                    "givenName": (entry_value(entry, "givenName") or "").strip(),
                    "sn": (entry_value(entry, "sn") or "").strip(),
                    "l": (entry_value(entry, "l") or "").strip(),
                    "st": (entry_value(entry, "st") or "").strip(),
                    "streetAddress": (entry_value(entry, "streetAddress") or "").strip(),
                    "postalCode": (entry_value(entry, "postalCode") or "").strip(),
                    "co": (entry_value(entry, "co") or "").strip(),
                    "c": (entry_value(entry, "c") or "").strip(),
                    "countryCode": entry_value(entry, "countryCode") if entry_value(entry, "countryCode") is not None else "",
                    "company": (entry_value(entry, "company") or "").strip(),
                    "userAccountControl": entry_value(entry, "userAccountControl")
                    if entry_value(entry, "userAccountControl") is not None
                    else "",
                    "adLastLogonTimestampDateTime": format_utc_datetime(parse_ad_filetime(entry_value(entry, "lastLogonTimestamp"))),
                    "userPrincipalName": (entry_value(entry, "userPrincipalName") or "").strip(),
                    "mail": get_primary_email(
                        entry_value(entry, "mail"),
                        entry_value(entry, "proxyAddresses"),
                        entry_value(entry, "userPrincipalName"),
                    ),
                    "mailboxYesNoFromAD": get_mailbox_yes_no_from_ad(
                        entry_value(entry, "homeMDB"),
                        entry_value(entry, "homeMTA"),
                        entry_value(entry, "msExchMailboxGuid"),
                        entry_value(entry, "msExchRemoteRecipientType"),
                        entry_value(entry, "msExchRecipientTypeDetails"),
                    ),
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
                    attributes=["displayName", "department", "employeeID", "title", "givenName", "sn"],
                )
                if conn.entries:
                    entry = conn.entries[0]
                    dn_details[manager_dn] = {
                        "displayName": (entry_value(entry, "displayName") or "").strip(),
                        "department": (entry_value(entry, "department") or "").strip(),
                        "employeeID": normalize_id(entry_value(entry, "employeeID") or ""),
                        "title": (entry_value(entry, "title") or "").strip(),
                        "givenName": (entry_value(entry, "givenName") or "").strip(),
                        "sn": (entry_value(entry, "sn") or "").strip(),
                    }
                else:
                    dn_details[manager_dn] = {
                        "displayName": "",
                        "department": "",
                        "employeeID": "",
                        "title": "",
                        "givenName": "",
                        "sn": "",
                    }
            except Exception:
                dn_details[manager_dn] = {
                    "displayName": "",
                    "department": "",
                    "employeeID": "",
                    "title": "",
                    "givenName": "",
                    "sn": "",
                }
    finally:
        conn.unbind()

    return ad_by_emp, dn_details


def build_rows(adp_employees, conn, ldap_search_base, ad_by_emp, dn_details, graph_mailbox_maps):
    """Build report rows using the same desired-attribute and diff logic as the update job."""
    rows = []
    for emp in adp_employees:
        emp_id = normalize_id(extract_employee_id(emp) or "")
        if not emp_id:
            continue

        person = emp.get("person", {})
        adp_display_name = get_display_name(person)
        source_title = extract_business_title(emp) or extract_assignment_field(emp, "jobTitle") or ""
        salary_yes_no = get_salary_yes_no(emp)
        last_updated = extract_last_updated(emp)
        employee_status = get_status(emp)
        terminated_employee = is_terminated_employee(emp)

        ad_record = ad_by_emp.get(emp_id)
        current_employee_id = (ad_record or {}).get("employeeID", "")
        current_primary_email = (ad_record or {}).get("mail", "")
        current_upn = (ad_record or {}).get("userPrincipalName", "")
        current_ad_last_active = (ad_record or {}).get("adLastLogonTimestampDateTime", "")
        mailbox_yes_no = resolve_mailbox_yes_no(
            employee_id=emp_id,
            primary_email=current_primary_email,
            upn_value=current_upn,
            graph_maps=graph_mailbox_maps,
            ad_mailbox_yes_no=(ad_record or {}).get("mailboxYesNoFromAD", "no"),
        )
        last_active = resolve_last_active_info(
            employee_id=emp_id,
            primary_email=current_primary_email,
            upn_value=current_upn,
            graph_maps=graph_mailbox_maps,
            ad_last_active_datetime=current_ad_last_active,
        )

        current_full_name = (ad_record or {}).get("displayName", "")
        current_given_name = (ad_record or {}).get("givenName", "")
        current_surname = (ad_record or {}).get("sn", "")
        current_title = (ad_record or {}).get("title", "")
        current_company = (ad_record or {}).get("company", "")
        current_dept = (ad_record or {}).get("department", "")
        current_manager_dn = (ad_record or {}).get("manager_dn", "")
        current_city = (ad_record or {}).get("l", "")
        current_state = (ad_record or {}).get("st", "")
        current_street = (ad_record or {}).get("streetAddress", "")
        current_postal_code = (ad_record or {}).get("postalCode", "")
        current_country = (ad_record or {}).get("co", "")
        current_country_alpha2 = (ad_record or {}).get("c", "")
        current_country_code = (ad_record or {}).get("countryCode", "")
        current_user_account_control = (ad_record or {}).get("userAccountControl", "")

        current_manager_name = ""
        current_manager_department = ""
        if current_manager_dn:
            mgr = dn_details.get(current_manager_dn, {})
            current_manager_name = (mgr.get("displayName") or "").strip()
            current_manager_department = (mgr.get("department") or "").strip()

        desired: dict[str, Any] = {}
        resolution: dict[str, Any] = {}
        changes: dict[str, list[tuple[Any, list[Any]]]] = {}
        if ad_record:
            current_entry = _EntryAdapter(
                {
                    "distinguishedName": (ad_record or {}).get("distinguishedName", ""),
                    "employeeID": current_employee_id,
                    "displayName": current_full_name,
                    "title": current_title,
                    "department": current_dept,
                    "company": current_company,
                    "l": current_city,
                    "st": current_state,
                    "postalCode": current_postal_code,
                    "streetAddress": current_street,
                    "co": current_country,
                    "c": current_country_alpha2,
                    "countryCode": current_country_code,
                    "manager": current_manager_dn,
                    "userAccountControl": current_user_account_control,
                }
            )
            if terminated_employee:
                desired = {"userAccountControl": 514}
            else:
                desired, resolution, _manager_dn, _resolved_manager_department = plan_update_attributes(
                    emp,
                    conn,
                    ldap_search_base,
                    current_ad_department=current_dept,
                    manager_department=current_manager_department,
                )
            changes = diff_update_attributes(current_entry, desired, context=emp_id)

        effective_full_name = effective_value(current_full_name, "displayName", changes) or ""
        effective_title = effective_value(current_title, "title", changes) or ""
        effective_company = effective_value(current_company, "company", changes) or ""
        effective_street = effective_value(current_street, "streetAddress", changes) or ""
        effective_city = effective_value(current_city, "l", changes) or ""
        effective_state = effective_value(current_state, "st", changes) or ""
        effective_postal_code = effective_value(current_postal_code, "postalCode", changes) or ""
        effective_country = effective_value(current_country, "co", changes) or ""
        effective_country_alpha2 = effective_value(current_country_alpha2, "c", changes) or ""
        effective_country_code = effective_value(current_country_code, "countryCode", changes)
        effective_manager_dn = effective_value(current_manager_dn, "manager", changes) or ""
        effective_department = effective_value(current_dept, "department", changes) or ""
        effective_user_account_control = effective_value(current_user_account_control, "userAccountControl", changes)

        current_location = build_location_display(
            current_street,
            current_city,
            current_state,
            current_postal_code,
            current_country,
        )
        effective_location = build_location_display(
            effective_street,
            effective_city,
            effective_state,
            effective_postal_code,
            effective_country,
        )

        effective_manager_name = current_manager_name
        effective_manager_department = current_manager_department
        if effective_manager_dn:
            effective_manager = dn_details.get(effective_manager_dn, {})
            effective_manager_name = (effective_manager.get("displayName") or "").strip()
            effective_manager_department = (effective_manager.get("department") or "").strip()
        elif "manager" in changes:
            effective_manager_name = ""
            effective_manager_department = ""

        if not ad_record:
            action_status = "missingInAD"
        elif not changes:
            action_status = "noChanges"
        elif terminated_employee and set(changes) == {"userAccountControl"} and effective_user_account_control == 514:
            action_status = "wouldDisable"
        else:
            action_status = "wouldUpdate"

        missing_in_ad_or_no_dept = "yes" if (not ad_record or not current_dept) else "no"
        rows.append(
            {
                "employeeID": emp_id,
                "employeeStatus": employee_status,
                "isTerminatedEmployee": "yes" if terminated_employee else "no",
                "lastUpdatedDateTime": last_updated.isoformat() if last_updated else "",
                "includedByMissingLastUpdated": "yes" if not last_updated else "no",
                "actionStatus": action_status,
                "wouldUpdate": "yes" if action_status in {"wouldUpdate", "wouldDisable"} else "no",
                "changeCount": len(changes),
                "changedAttributes": format_changed_attributes(changes),
                "currentEmployeeID": current_employee_id,
                "currentPrimaryEmail": current_primary_email,
                "entraLastActiveDateTime": last_active["entraDateTime"],
                "entraLastActiveSource": last_active["entraSource"],
                "adLastActiveDateTime": last_active["adDateTime"],
                "lastActiveDateTime": last_active["dateTime"],
                "lastActiveSource": last_active["source"],
                "salaryYesNo": salary_yes_no,
                "mailboxYesNo": mailbox_yes_no,
                "proposedEmployeeID": current_employee_id,
                "fullName": adp_display_name,
                "currentFullName": current_full_name,
                "proposedFullName": effective_full_name,
                "currentGivenName": current_given_name,
                "proposedGivenName": current_given_name,
                "currentSurname": current_surname,
                "proposedSurname": current_surname,
                "title": source_title,
                "currentTitle": current_title,
                "proposedTitle": effective_title,
                "titleWouldChange": "yes" if "title" in changes else "no",
                "currentCompany": current_company,
                "proposedCompany": effective_company,
                "companyWouldChange": "yes" if "company" in changes else "no",
                "currentStreetAddress": current_street,
                "proposedStreetAddress": effective_street,
                "currentCity": current_city,
                "proposedCity": effective_city,
                "currentState": current_state,
                "proposedState": effective_state,
                "currentPostalCode": current_postal_code,
                "proposedPostalCode": effective_postal_code,
                "currentCountry": current_country,
                "proposedCountry": effective_country,
                "currentCountryAlpha2": current_country_alpha2,
                "proposedCountryAlpha2": effective_country_alpha2,
                "currentCountryCode": current_country_code,
                "proposedCountryCode": effective_country_code,
                "currentLocation": current_location,
                "proposedLocation": effective_location,
                "locationWouldChange": "yes"
                if any(attr in changes for attr in {"streetAddress", "l", "st", "postalCode", "co", "c", "countryCode"})
                else "no",
                "currentADDepartment": current_dept,
                "userManager": current_manager_name,
                "managerDepartment": current_manager_department,
                "currentManager": current_manager_name,
                "proposedManager": effective_manager_name,
                "currentManagerDept": current_manager_department,
                "proposedManagerDept": effective_manager_department,
                "managerWouldChange": "yes" if "manager" in changes else "no",
                "proposedDepartmentFromScheduledUpdate": effective_department,
                "proposedDepartmentV2": effective_department,
                "changeAllowed": str(bool(resolution.get("changeAllowed"))).lower() if resolution else "",
                "blockReason": resolution.get("blockReason") or "",
                "evidenceUsed": resolution.get("evidenceUsed") or "",
                "confidence": resolution.get("confidence") or "",
                "titleInferredDept": resolution.get("titleInferredDept") or "",
                "departmentChangeReferenceField": resolution.get("departmentChangeReferenceField") or "",
                "departmentChangeReferenceValue": resolution.get("departmentChangeReferenceValue") or "",
                "departmentChangePrimaryReason": resolution.get("departmentChangePrimaryReason") or "",
                "departmentChangeReasonTrace": resolution.get("departmentChangeReasonTrace") or "",
                "departmentWouldChange": "yes" if "department" in changes else "no",
                "currentUserAccountControl": current_user_account_control,
                "proposedUserAccountControl": effective_user_account_control,
                "userAccountControlWouldChange": "yes" if "userAccountControl" in changes else "no",
                "missingInADOrNoDept": missing_in_ad_or_no_dept,
            }
        )
    return rows


def parse_args() -> argparse.Namespace:
    """Parse optional output paths for local report generation."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default="adp_active_users_ad_current_vs_scheduled_department.csv",
        help="CSV output path. Defaults to the standard report filename.",
    )
    parser.add_argument(
        "--summary-output",
        default="",
        help="Optional summary JSON output path. Defaults to <output_stem>_summary.json.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    load_local_settings()
    settings = get_update_job_settings()

    token = get_adp_token()
    if not token:
        raise RuntimeError("Failed to retrieve ADP token.")

    adp_employees_raw = get_adp_employees(token)
    if adp_employees_raw is None:
        raise RuntimeError("Failed to retrieve ADP employees.")
    adp_employees, candidate_stats = select_update_candidates(
        adp_employees_raw,
        settings,
        context="generate_adp_current_vs_scheduled_department_report",
    )

    ad_by_emp, dn_details = fetch_ad_user_maps()
    graph_mailbox_maps = fetch_graph_mailbox_maps()
    conn, ldap_search_base = open_report_ldap_connection()
    try:
        rows = build_rows(adp_employees, conn, ldap_search_base, ad_by_emp, dn_details, graph_mailbox_maps)
    finally:
        conn.unbind()

    output_csv = Path(args.output)
    fieldnames = [
        "employeeID",
        "employeeStatus",
        "isTerminatedEmployee",
        "lastUpdatedDateTime",
        "includedByMissingLastUpdated",
        "actionStatus",
        "wouldUpdate",
        "changeCount",
        "changedAttributes",
        "currentEmployeeID",
        "currentPrimaryEmail",
        "entraLastActiveDateTime",
        "entraLastActiveSource",
        "adLastActiveDateTime",
        "lastActiveDateTime",
        "lastActiveSource",
        "salaryYesNo",
        "mailboxYesNo",
        "proposedEmployeeID",
        "fullName",
        "currentFullName",
        "proposedFullName",
        "currentGivenName",
        "proposedGivenName",
        "currentSurname",
        "proposedSurname",
        "title",
        "currentTitle",
        "proposedTitle",
        "titleWouldChange",
        "currentCompany",
        "proposedCompany",
        "companyWouldChange",
        "currentStreetAddress",
        "proposedStreetAddress",
        "currentCity",
        "proposedCity",
        "currentState",
        "proposedState",
        "currentPostalCode",
        "proposedPostalCode",
        "currentCountry",
        "proposedCountry",
        "currentCountryAlpha2",
        "proposedCountryAlpha2",
        "currentCountryCode",
        "proposedCountryCode",
        "currentLocation",
        "proposedLocation",
        "locationWouldChange",
        "currentADDepartment",
        "userManager",
        "managerDepartment",
        "currentManager",
        "proposedManager",
        "currentManagerDept",
        "proposedManagerDept",
        "managerWouldChange",
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
        "currentUserAccountControl",
        "proposedUserAccountControl",
        "userAccountControlWouldChange",
        "missingInADOrNoDept",
    ]
    try:
        with output_csv.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    except PermissionError as exc:
        raise PermissionError(
            f"Could not write report to '{output_csv}'. The file is likely open in another process. "
            "Close the file or provide --output <new_path>."
        ) from exc

    summary = {
        "totalEmployeesFromADP": len(adp_employees_raw),
        "dedupedEmployeesFromADP": candidate_stats["deduped_count"],
        "lookbackDays": settings.lookback_days,
        "includeMissingLastUpdated": settings.include_missing_last_updated,
        "candidatesSelected": len(adp_employees),
        "activeUsers": sum(1 for row in rows if row["employeeStatus"] == "Active"),
        "inactiveUsers": sum(1 for row in rows if row["employeeStatus"] != "Active"),
        "missingLastUpdatedCount": candidate_stats["missing_last_updated"],
        "selectedMissingLastUpdatedCount": candidate_stats["selected_missing_last_updated"],
        "skippedCountryCount": candidate_stats["skipped_country"],
        "entraLastActiveCount": sum(1 for row in rows if row["entraLastActiveDateTime"]),
        "adLastActiveCount": sum(1 for row in rows if row["adLastActiveDateTime"]),
        "lastActiveCount": sum(1 for row in rows if row["lastActiveDateTime"]),
        "lastActiveMissingCount": sum(1 for row in rows if not row["lastActiveDateTime"]),
        "wouldUpdateCount": sum(1 for row in rows if row["actionStatus"] == "wouldUpdate"),
        "wouldDisableCount": sum(1 for row in rows if row["actionStatus"] == "wouldDisable"),
        "noChangeCount": sum(1 for row in rows if row["actionStatus"] == "noChanges"),
        "missingInADCount": sum(1 for row in rows if row["actionStatus"] == "missingInAD"),
        "usersWithChanges": sum(1 for row in rows if row["wouldUpdate"] == "yes"),
        "totalAttributeChanges": sum(int(row["changeCount"]) for row in rows),
        "employeeIDWouldChangeCount": sum(
            1
            for row in rows
            if (row["currentEmployeeID"] or "").strip().lower() != (row["proposedEmployeeID"] or "").strip().lower()
        ),
        "nameWouldChangeCount": sum(
            1
            for row in rows
            if (row["currentFullName"] or "").strip().lower() != (row["proposedFullName"] or "").strip().lower()
        ),
        "titleWouldChangeCount": sum(
            1
            for row in rows
            if row["titleWouldChange"] == "yes"
        ),
        "companyWouldChangeCount": sum(1 for row in rows if row["companyWouldChange"] == "yes"),
        "locationWouldChangeCount": sum(1 for row in rows if row["locationWouldChange"] == "yes"),
        "managerWouldChangeCount": sum(
            1
            for row in rows
            if row["managerWouldChange"] == "yes"
        ),
        "departmentWouldChangeCount": sum(1 for row in rows if row["departmentWouldChange"] == "yes"),
        "userAccountControlWouldChangeCount": sum(
            1 for row in rows if row["userAccountControlWouldChange"] == "yes"
        ),
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
    summary_path = (
        Path(args.summary_output)
        if args.summary_output
        else output_csv.with_name(f"{output_csv.stem}_summary.json")
    )
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(f"Wrote {output_csv} with {len(rows)} rows.")
    print(f"Wrote {summary_path}.")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

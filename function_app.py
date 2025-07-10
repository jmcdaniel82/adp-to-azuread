import os
import json
import logging
import re
import requests
import ssl
import secrets
import string
import azure.functions as func
from ldap3 import Server, Connection, SUBTREE, Tls, NTLM
from ldap3.utils.dn import escape_rdn
from datetime import datetime, timezone, timedelta

app = func.FunctionApp()

def get_adp_token():
    """Retrieve an OAuth access token from ADP using client credentials."""
    token_url = os.getenv("ADP_TOKEN_URL")
    client_id = os.getenv("ADP_CLIENT_ID")
    client_secret = os.getenv("ADP_CLIENT_SECRET")
    cert_pem = os.getenv("ADP_CERT_PEM")
    cert_key = os.getenv("ADP_CERT_KEY")
    if not all([token_url, client_id, client_secret, cert_pem, cert_key]):
        logging.error("Missing ADP configuration variables.")
        return None
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        resp = requests.post(
            token_url,
            headers=headers,
            data=payload,
            cert=(cert_pem, cert_key),
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("access_token")
    except Exception as e:
        logging.error(f"ADP token retrieval failed: {e}")
        return None

def get_hire_date(employee):
    """Return the most relevant hire date in ISO format for an employee."""
    wa = employee.get("workAssignments")
    if isinstance(wa, list) and wa:
        for key in ("hireDate", "actualStartDate"):
            d = wa[0].get(key)
            if d:
                try:
                    dt = datetime.fromisoformat(d)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt.isoformat()
                except Exception as e:
                    logging.error(f"Error parsing assignment {key} '{d}': {e}")
    wd = employee.get("workerDates")
    dates = []
    if isinstance(wd, list):
        for item in wd:
            if "hire" in item.get("type", "").lower():
                d = item.get("value")
                if d:
                    try:
                        dt = datetime.fromisoformat(d)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        dates.append(dt)
                    except Exception as e:
                        logging.error(f"Error parsing workerDates hire '{d}': {e}")
    elif isinstance(wd, dict):
        for key in ("originalHireDate", "hireDate", "hire_date"):
            d = wd.get(key)
            if d:
                try:
                    dt = datetime.fromisoformat(d)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    dates.append(dt)
                except Exception as e:
                    logging.error(f"Error parsing workerDates {key} '{d}': {e}")
    if dates:
        return max(dates).isoformat()
    return None

def get_termination_date(emp):
    """Return the termination date for an employee, if present."""
    wd = emp.get("workerDates")
    if isinstance(wd, list):
        for item in wd:
            if "term" in item.get("type", "").lower():
                return item.get("value")
    elif isinstance(wd, dict):
        return wd.get("terminationDate")
    return None

def extract_employee_id(emp):
    """Extract the employee ID from the ADP worker record."""
    w = emp.get("workerID")
    if isinstance(w, dict):
        return w.get("idValue", "")
    return w or ""

def get_first_last(person):
    """Return (first, last) preferring preferredName, else legalName."""
    pref = person.get("preferredName", {})
    first = pref.get("givenName")
    last = pref.get("familyName1")
    if first and last:
        return first, last
    legal = person.get("legalName", {})
    first = legal.get("givenName", "")
    last = legal.get("familyName1", "")
    return first, last

def sanitize_string_for_sam(s):
    """Remove non-alphanumeric characters for a sAMAccountName."""
    return re.sub(r"[^a-zA-Z0-9]", "", s)

def extract_assignment_field(emp, field):
    """Return a value from the employee's first work assignment."""
    wa = emp.get("workAssignments", [])
    return wa[0].get(field, "") if wa else ""

def extract_department(emp):
    """Retrieve the department short name from work assignments."""
    wa = emp.get("workAssignments", [])
    if not wa:
        return ""
    for ou in wa[0].get("assignedOrganizationalUnits", []):
        if ou.get("typeCode", {}).get("codeValue", "").lower() == "department":
            return ou.get("nameCode", {}).get("shortName", "")
    for ou in wa[0].get("homeOrganizationalUnits", []):
        if ou.get("typeCode", {}).get("codeValue", "").lower() == "department":
            return ou.get("nameCode", {}).get("shortName", "")
    return ""

def extract_company(emp):
    """Retrieve the company or business unit name from work assignments."""
    wa = emp.get("workAssignments", [])
    if not wa:
        return ""
    bu = wa[0].get("businessUnit", {})
    if isinstance(bu, dict) and bu.get("name"):
        return bu["name"]
    for ou in wa[0].get("assignedOrganizationalUnits", []):
        if ou.get("typeCode", {}).get("codeValue", "").lower() == "business unit":
            return ou.get("nameCode", {}).get("shortName", "")
    for ou in wa[0].get("homeOrganizationalUnits", []):
        if ou.get("typeCode", {}).get("codeValue", "").lower() == "business unit":
            return ou.get("nameCode", {}).get("shortName", "")
    return ""

def extract_work_address_field(emp, field):
    """Return a specific address field from the assigned work location."""
    wa = emp.get("workAssignments", [])
    if wa and wa[0].get("assignedWorkLocations"):
        addr = wa[0]["assignedWorkLocations"][0].get("address", {})
        return addr.get(field, "")
    return ""

def extract_state_from_work(emp):
    """Return the state or province code from the work address."""
    wa = emp.get("workAssignments", [])
    if wa and wa[0].get("assignedWorkLocations"):
        cs = wa[0]["assignedWorkLocations"][0].get("address", {}).get("countrySubdivisionLevel1", {})
        return cs.get("codeValue", "")
    return ""

def get_adp_employees(token):
    """Retrieve all employee records from ADP, handling pagination."""
    employees = []
    limit = 50
    offset = 0
    base_url = os.getenv("ADP_EMPLOYEE_URL")
    cert = (os.getenv("ADP_CERT_PEM"), os.getenv("ADP_CERT_KEY"))
    headers = {"Authorization": f"Bearer {token}"}
    while True:
        url = f"{base_url}?limit={limit}&offset={offset}"
        try:
            response = requests.get(url, headers=headers, cert=cert, timeout=10)
        except requests.RequestException as e:
            logging.error(f"Failed to retrieve employees: {e}")
            return None
        if not response.ok:
            logging.error(f"Failed to retrieve employees: {response.text}")
            break
        data = response.json()
        page_employees = data.get("workers", [])
        employees.extend(page_employees)
        logging.info(f"Records retrieved so far: {len(employees)}")
        if len(page_employees) < limit:
            break
        offset += limit
    logging.info(f"Total records retrieved: {len(employees)}")
    employees_with_hire_date = [emp for emp in employees if get_hire_date(emp)]
    logging.info(f"Total employees with hire date: {len(employees_with_hire_date)}")
    return employees_with_hire_date

def get_status(emp):
    """Determine if an employee is Active or Inactive."""
    hd = get_hire_date(emp)
    td = get_termination_date(emp)
    if not hd:
        return "Inactive"
    h = datetime.fromisoformat(hd)
    if h.tzinfo is None:
        h = h.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    if h > now:
        return "Inactive"
    if not td:
        return "Active"
    t = datetime.fromisoformat(td)
    if t.tzinfo is None:
        t = t.replace(tzinfo=timezone.utc)
    return "Active" if t > now else "Inactive"

def get_user_account_control(emp):
    """Map employee status to the userAccountControl flag."""
    return 512 if get_status(emp) == "Active" else 514

def generate_password(length: int = 24) -> str:
    """Generate a random complex password of the given length."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            re.search(r"[a-z]", pwd)
            and re.search(r"[A-Z]", pwd)
            and re.search(r"\d", pwd)
            and re.search(r"[!@#$%^&*()\-\_=+\[\]{}|;:,.<>?]", pwd)
        ):
            return pwd

def provision_user_in_ad(user_data, conn, ldap_search_base, ldap_create_base):
    """Create and enable an AD user using data from ADP."""
    country_code = extract_work_address_field(user_data, "countryCode") or ""
    if not country_code.upper() or country_code.upper() == "MX":
        logging.info(f"Skipping provisioning for country code '{country_code}'")
        return

    person = user_data.get("person", {})
    first, last = get_first_last(person)
    full_name = f"{first} {last}".strip()
    if not full_name:
        logging.warning(f"Skipping user with incomplete name data: {user_data}")
        return

    emp_id = extract_employee_id(user_data)
    hire_date = get_hire_date(user_data) or "<no hire date>"

    conn.search(ldap_search_base, f"(employeeID={emp_id})", SUBTREE, attributes=["employeeID"])
    if conn.entries:
        logging.info(f"User already provisioned: {emp_id} (hireDate={hire_date})")
        return

    first, last = get_first_last(person)
    if not first:
        # fallback to full_name parse if necessary (shouldn't happen)
        parts = full_name.split()
        first = parts[0] if parts else ""
        last = parts[1] if len(parts) > 1 else ""
    base_sam = sanitize_string_for_sam((first[0].lower() + last.lower()) if first and last else "")
    base_email = (f"{sanitize_string_for_sam(first.lower())}{sanitize_string_for_sam(last.lower())}@cfsbrands.com" if first and last else "")

    # Uniqueness check for samAccountName and mail
    sam = base_sam
    email = base_email
    count = 1
    while True:
        conn.search(ldap_search_base, f"(sAMAccountName={sam})", SUBTREE, attributes=["sAMAccountName"])
        if not conn.entries:
            break
        count += 1
        sam = f"{base_sam}{count}"
        email = f"{sanitize_string_for_sam(first.lower())}{sanitize_string_for_sam(last.lower())}{count}@cfsbrands.com"

    postal = extract_work_address_field(user_data, "postalCode")
    state = extract_state_from_work(user_data)
    street = extract_work_address_field(user_data, "lineOne")
    city = extract_work_address_field(user_data, "cityName")
    country_name = "United States" if country_code.upper() == "US" else country_code

    attrs = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "cn": f"{first} {last}".strip(),
        "givenName": first,
        "sn": last,
        "displayName": f"{first} {last}".strip(),
        "userPrincipalName": email,
        "mail": email,
        "sAMAccountName": sam,
        "employeeID": emp_id,
        "title": extract_assignment_field(user_data, "jobTitle"),
        "department": extract_department(user_data),
        "l": city,
        "postalCode": postal,
        "st": state,
        "streetAddress": street,
        "co": country_name,
        "company": extract_company(user_data),
        "userAccountControl": 514,
    }

    mandatory = {
        "objectClass", "cn", "givenName", "sn", "displayName",
        "userPrincipalName", "mail", "sAMAccountName", "employeeID", "userAccountControl"
    }
    final_attrs = {k: v for k, v in attrs.items() if v or k in mandatory}
    dn = f"CN={escape_rdn(full_name)},{ldap_create_base}"
    if not conn.add(dn, attributes=final_attrs):
        logging.error(f"Add failed for {dn}: {conn.result}")
        return
    logging.info(f"User created: {dn} (hireDate={hire_date})")

    pwd = generate_password()
    try:
        conn.extend.microsoft.modify_password(dn, pwd)
        logging.info(f"Password set for {dn}")
        conn.modify(dn, {"pwdLastSet": [("MODIFY_REPLACE", [0])]})
        logging.info(f"pwdLastSet reset for {dn}")
        conn.modify(dn, {"userAccountControl": [("MODIFY_REPLACE", [512])]})
        logging.info(f"Account enabled for {dn}")
    except Exception as e:
        logging.error(f"Password or enable failed for {dn}: {e}")

# ---- Scheduled sync every 15m ----
@app.schedule(schedule="0 */15 * * * *", arg_name="mytimer", run_on_startup=True)
def scheduled_adp_sync(mytimer: func.TimerRequest):
    """Timer triggered function that provisions recent hires."""
    logging.info("🔄 scheduled_adp_sync triggered")
    if mytimer.past_due:
        logging.warning("Timer is past due!")
    token = get_adp_token()
    if not token:
        logging.error("❌ Failed to retrieve ADP token.")
        return
    logging.info("✅ ADP token acquired")
    all_employees = get_adp_employees(token)
    if all_employees is None:
        logging.error("❌ get_adp_employees returned None")
        return
    logging.info(f"ℹ️  Retrieved {len(all_employees)} total ADP employees")
    today = datetime.now(tz=timezone.utc).date()
    cutoff = today - timedelta(days=0)
    employees_recent = []
    for emp in all_employees:
        hire_str = get_hire_date(emp)
        if not hire_str:
            logging.debug(f"No hireDate for {extract_employee_id(emp)}; skipping")
            continue
        try:
            hire_date = datetime.fromisoformat(hire_str).date()
        except Exception:
            logging.debug(f"Bad hireDate format for {extract_employee_id(emp)}: {hire_str}")
            continue
        if hire_date >= cutoff:
            employees_recent.append(emp)
            logging.debug(f"Including {extract_employee_id(emp)} hired on {hire_date}")
        else:
            logging.debug(f"Skipping (too old) {extract_employee_id(emp)} hired on {hire_date}")
    logging.info(f"ℹ️  {len(employees_recent)} employees hired since {cutoff.isoformat()}")
    if not employees_recent:
        logging.info("🚫 Nothing to sync; exiting scheduled_adp_sync")
        return
    ldap_server = os.getenv("LDAP_SERVER")
    ldap_user = os.getenv("LDAP_USER")
    ldap_password = os.getenv("LDAP_PASSWORD")
    ldap_search_base = os.getenv("LDAP_SEARCH_BASE")
    ldap_create_base = os.getenv("LDAP_CREATE_BASE")
    ca_bundle = os.getenv("CA_BUNDLE_PATH")
    logging.info(f"Loading CA bundle from '{ca_bundle}'")
    if not os.path.isfile(ca_bundle):
        logging.error(f"CA bundle not found at {ca_bundle}")
    tls_config = Tls(
        ca_certs_file=ca_bundle,
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLSv1_2,
    )
    server = Server(ldap_server, port=636, use_ssl=True, tls=tls_config, get_info=None)
    try:
        conn = Connection(
            server,
            user=ldap_user,
            password=ldap_password,
            authentication=NTLM,
            auto_bind=True,
        )
    except Exception as e:
        logging.error(f"❌ Failed to connect to LDAP server: {e}")
        return
    logging.info("🔗 LDAP connection opened")
    for emp in employees_recent:
        emp_id = extract_employee_id(emp)
        person = emp.get("person", {})
        first, last = get_first_last(person)
        name = f"{first} {last}".strip() or "<no name>"
        logging.info(f"➡️  Processing {emp_id} / {name}")
        try:
            provision_user_in_ad(emp, conn, ldap_search_base, ldap_create_base)
        except Exception as e:
            logging.error(f"❌ Exception provisioning {emp_id}: {e}")
    conn.unbind()
    logging.info("🔒 LDAP connection closed — scheduled_adp_sync complete")


# ---------------------------
# Simple process endpoint
# ---------------------------
@app.function_name(name="process_request")
@app.route(route="process", methods=["POST"])
def process_request(req: func.HttpRequest) -> func.HttpResponse:
    """HTTP endpoint that returns a summary of recent hires."""
    token = get_adp_token()
    if not token:
        return func.HttpResponse("Token fail", status_code=500)
    emps = get_adp_employees(token)
    if emps is None:
        return func.HttpResponse("Fail emps", status_code=500)
    sorted_emps = sorted(
        [e for e in emps if get_hire_date(e)],
        key=lambda e: get_hire_date(e),
        reverse=True,
    )[:5]
    out = []
    for emp in sorted_emps:
        person = emp.get("person", {})
        first, last = get_first_last(person)
        full_name = f"{first} {last}".strip()
        base_sam = sanitize_string_for_sam((first[0].lower() + last.lower()) if first and last else "")
        email = (f"{sanitize_string_for_sam(first.lower())}{sanitize_string_for_sam(last.lower())}@cfsbrands.com" if first and last else "")
        country_code = extract_work_address_field(emp, "countryCode") or ""
        country_name = "United States" if country_code.upper() == "US" else country_code

        out.append(
            {
                "employeeId": extract_employee_id(emp),
                "cn": full_name,
                "accountDisabled": get_status(emp) == "Inactive",
                "sAMAccountName": base_sam,
                "co": country_name,
                "countryCode": country_code,
                "company": extract_company(emp),
                "department": extract_department(emp),
                "displayName": full_name,
                "givenName": first,
                "l": extract_work_address_field(emp, "cityName"),
                "mail": email,
                "postalCode": extract_work_address_field(emp, "postalCode"),
                "sn": last,
                "st": extract_state_from_work(emp),
                "streetAddress": extract_work_address_field(emp, "lineOne"),
                "title": extract_assignment_field(emp, "jobTitle"),
                "userPrincipalName": email,
                "hireDate": get_hire_date(emp),
                "status": get_status(emp),
            }
        )
    return func.HttpResponse(
        json.dumps(out), mimetype="application/json", status_code=200
    )

import os
import json
import logging
import re
import requests
import ssl
import secrets
import string
import azure.functions as func
from ldap3 import Server, Connection, SUBTREE, Tls, NTLM, MODIFY_REPLACE
from ldap3.utils.dn import escape_rdn
from datetime import datetime, timezone, timedelta, date
from concurrent.futures import ThreadPoolExecutor

app = func.FunctionApp()

# ---- Helper functions ----

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
    if wa:
        if wa[0].get("assignedWorkLocations"):
            addr = wa[0]["assignedWorkLocations"][0].get("address", {})
            return addr.get(field, "")
        elif wa[0].get("homeWorkLocation"):
            addr = wa[0]["homeWorkLocation"].get("address", {})
            return addr.get(field, "")
    return ""


def extract_state_from_work(emp):
    """Return the state or province code from the work address."""
    wa = emp.get("workAssignments", [])
    if wa:
        if wa[0].get("assignedWorkLocations"):
            cs = wa[0]["assignedWorkLocations"][0].get("address", {}).get("countrySubdivisionLevel1", {})
            return cs.get("codeValue", "")
        elif wa[0].get("homeWorkLocation"):
            cs = wa[0]["homeWorkLocation"].get("address", {}).get("countrySubdivisionLevel1", {})
            return cs.get("codeValue", "")
    return ""


def extract_manager_id(emp):
    """Return the ADP associateOID of the employee's manager."""
    wa = emp.get("workAssignments", [])
    if wa:
        reports_to = wa[0].get("reportsTo", [{}])[0]
        manager_info = reports_to.get("workerID", {})
        return manager_info.get("idValue")
    return None


def get_manager_dn(conn, ldap_search_base, manager_id):
    """Lookup a manager's DN in AD by their employeeID."""
    if not manager_id:
        return None
    conn.search(ldap_search_base,
                f"(employeeID={manager_id})",
                SUBTREE,
                attributes=["distinguishedName"])
    if conn.entries:
        return conn.entries[0].distinguishedName.value
    return None

def get_adp_employees(token, limit=50, offset=0, paginate_all=True):
    """Retrieve employee records from ADP, handling pagination."""
    employees = []
    base_url = os.getenv("ADP_EMPLOYEE_URL")
    cert = (os.getenv("ADP_CERT_PEM"), os.getenv("ADP_CERT_KEY"))
    headers = {"Authorization": f"Bearer {token}"}
    
    current_offset = offset
    
    while True:
        url = f"{base_url}?$top={limit}&$skip={current_offset}"
        try:
            response = requests.get(url, headers=headers, cert=cert, timeout=10)
        except requests.RequestException as e:
            logging.error(f"Failed to retrieve employees: {e}")
            return None
        if not response.ok:
            logging.error(f"Failed to retrieve employees: {response.text}")
            break
        
        try:
            data = response.json()
        except json.JSONDecodeError:
            logging.error(f"Failed to decode JSON from ADP response: {response.text}")
            break

        page_employees = data.get("workers", [])
        employees.extend(page_employees)
        logging.info(f"Records retrieved so far: {len(employees)}")
        
        if not paginate_all or len(page_employees) < limit:
            break
        
        current_offset += limit
        
    logging.info(f"Total records retrieved in this call: {len(employees)}")
    return employees


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

    # Search the entire domain for the employeeID to prevent creating duplicates
    conn.search(ldap_search_base,
                f"(employeeID={emp_id})",
                SUBTREE,
                attributes=["employeeID", "distinguishedName"])
    if conn.entries:
        logging.info(f"User already exists: {emp_id} at {conn.entries[0].distinguishedName.value}")
        # If user exists, update manager if needed
        manager_id = extract_manager_id(user_data)
        manager_dn = get_manager_dn(conn, ldap_search_base, manager_id)
        if manager_dn:
            conn.modify(conn.entries[0].distinguishedName.value,
                        {"manager": [(MODIFY_REPLACE, [manager_dn])]})
        return

    # Build attributes for new user
    base_sam = sanitize_string_for_sam(first[0].lower() + last.lower())
    attrs = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "cn": full_name,
        "givenName": first,
        "sn": last,
        "displayName": full_name,
        "userPrincipalName": f"{sanitize_string_for_sam(first.lower())}{sanitize_string_for_sam(last.lower())}@us.corp.cfsbrands.com",
        "mail": f"{sanitize_string_for_sam(first.lower())}{sanitize_string_for_sam(last.lower())}@cfsbrands.com",
        "sAMAccountName": base_sam,
        "employeeID": emp_id,
        "title": extract_assignment_field(user_data, "jobTitle"),
        "businessTitle": extract_assignment_field(user_data, "businessTitle"),  # custom HR field
        "department": extract_department(user_data),
        "l": extract_work_address_field(user_data, "cityName"),
        "postalCode": extract_work_address_field(user_data, "postalCode"),
        "st": extract_state_from_work(user_data),
        "streetAddress": extract_work_address_field(user_data, "lineOne"),
        "co": "United States" if country_code.upper() == "US" else country_code,
        "company": extract_company(user_data),
        "manager": get_manager_dn(conn, ldap_search_base, extract_manager_id(user_data)),
        "userAccountControl": get_user_account_control(user_data),
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

    # Set password and enable account
    pwd = generate_password()
    try:
        conn.extend.microsoft.modify_password(dn, pwd)
        conn.modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
        conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [512])]})
        logging.info(f"Account enabled and password set for {dn}")
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
    
    employees_with_hire_date = [emp for emp in all_employees if get_hire_date(emp)]
    logging.info(f"ℹ️  Retrieved {len(employees_with_hire_date)} total ADP employees with hire dates")
    
    today = datetime.now(tz=timezone.utc).date()
    cutoff = today - timedelta(days=0)
    employees_recent = []
    for emp in employees_with_hire_date:
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
    """HTTP endpoint that returns all active users with ADP/HR details."""
    token = get_adp_token()
    if not token:
        return func.HttpResponse("Token fail", status_code=500)
    emps = get_adp_employees(token)
    if emps is None:
        return func.HttpResponse("Fail emps", status_code=500)

    # Filter for only ACTIVE users
    active_emps = [e for e in emps if get_status(e) == "Active"]
    # Optional: sort by hire date (descending)
    sorted_emps = sorted(
        [e for e in active_emps if get_hire_date(e)],
        key=lambda e: get_hire_date(e),
        reverse=True,
    )

    out = []
    for emp in sorted_emps:
        person = emp.get("person", {})
        first, last = get_first_last(person)
        
        out.append(
            {
                "employeeId": extract_employee_id(emp),
                "givenName": first,
                "familyName": last,
                "jobTitle": extract_assignment_field(emp, "jobTitle"),
                "company": extract_company(emp),
                "department": extract_department(emp),
                "hireDate": get_hire_date(emp),
                "terminationDate": get_termination_date(emp),
                "workAssignments": emp.get("workAssignments", []),
            }
        )
    return func.HttpResponse(
        json.dumps(out), mimetype="application/json", status_code=200
    )

# ---------------------------
# Department Mapping Export Endpoint
# ---------------------------
def json_converter(o):
    """Convert non-serializable types to a string."""
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    return str(o)


def normalize_id(emp_id: str) -> str:
    """Trim whitespace and uppercase employee IDs."""
    return emp_id.strip().upper() if emp_id else ""


def normalize_dept(dept: str) -> str:
    """Lowercase, strip, and remove non-alphanumeric characters."""
    return ''.join(c for c in dept.lower().strip() if c.isalnum() or c.isspace())


def fetch_ad_data_task() -> dict:
    """Fetch all AD users and build a map of employeeID -> department."""
    ldap_server = os.getenv("LDAP_SERVER")
    ldap_user = os.getenv("LDAP_USER")
    ldap_password = os.getenv("LDAP_PASSWORD")
    ldap_search_base = os.getenv("LDAP_SEARCH_BASE")
    ca_bundle = os.getenv("CA_BUNDLE_PATH")

    if not all([ldap_server, ldap_user, ldap_password, ldap_search_base, ca_bundle]):
        logging.error("Missing LDAP configuration for export.")
        return {}

    tls = Tls(ca_certs_file=ca_bundle, validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2)
    server = Server(ldap_server, port=636, use_ssl=True, tls=tls, get_info=None)
    try:
        conn = Connection(server, user=ldap_user, password=ldap_password,
                          authentication=NTLM, auto_bind=True)
        logging.info("🔗 LDAP connection opened for export.")
    except Exception as e:
        logging.error(f"Failed to connect to LDAP: {e}")
        return {}

    ldap_map = {}
    page_size = 500
    cookie = None
    try:
        while True:
            conn.search(
                ldap_search_base,
                '(employeeID=*)',
                SUBTREE,
                attributes=["employeeID", "department"],
                paged_size=page_size,
                paged_cookie=cookie,
            )
            for entry in conn.entries:
                raw_id = entry.employeeID.value
                raw_dept = entry.department.value if entry.department else None
                emp_id = normalize_id(raw_id)
                dept = normalize_dept(raw_dept) if raw_dept else None
                if emp_id and dept:
                    ldap_map[emp_id] = dept

            controls = conn.result.get('controls', {})
            cookie = controls.get('1.2.840.113556.1.4.319', {})\
                            .get('value', {})\
                            .get('cookie')
            if not cookie:
                break
    finally:
        conn.unbind()
        logging.info("🔒 LDAP connection closed for export.")

    return ldap_map

@app.function_name(name="export_adp_data")
@app.route(route="export", methods=["GET"])
def export_adp_data(req: func.HttpRequest) -> func.HttpResponse:
    """Return both department pairs and diagnostic sets to debug mappings."""
    logging.info("Export triggered: building dept mappings and diagnostics.")

    token = get_adp_token()
    if not token:
        return func.HttpResponse("ADP token retrieval failed.", status_code=500)

    # Parallel fetch of ADP and AD data
    with ThreadPoolExecutor(max_workers=2) as ex:
        future_adp = ex.submit(get_adp_employees, token)
        future_ldap = ex.submit(fetch_ad_data_task)
        adp_employees = future_adp.result()
        ldap_map = future_ldap.result()

    if adp_employees is None or ldap_map is None:
        return func.HttpResponse("Data fetch error (ADP or AD).", status_code=500)

    # Inventory exports
    adp_depts = {normalize_dept(extract_department(emp)) for emp in adp_employees if extract_department(emp)}
    ad_depts = set(ldap_map.values())
    ids_adp = {normalize_id(extract_employee_id(emp)) for emp in adp_employees if extract_employee_id(emp)}
    ids_ad = set(ldap_map.keys())
    missing_in_ad = sorted(ids_adp - ids_ad)
    missing_in_adp = sorted(ids_ad - ids_adp)

    # Build dept pairs with detailed logging
    dept_pairs = set()
    for emp in adp_employees:
        raw_id = extract_employee_id(emp)
        emp_id = normalize_id(raw_id)
        if not emp_id:
            logging.debug(f"Skipping ADP record with no ID: {raw_id}")
            continue
        raw_adp_dept = extract_department(emp)
        adp_dept = normalize_dept(raw_adp_dept)
        if not adp_dept:
            logging.debug(f"ADP missing department for ID {emp_id}")
            continue
        ad_dept = ldap_map.get(emp_id)
        if not ad_dept:
            logging.debug(f"No AD entry for ID {emp_id} (ADP dept '{adp_dept}')")
            continue
        dept_pairs.add((adp_dept, ad_dept))

    # Prepare JSON payload
    result = {
        "pairs": sorted(dept_pairs),
        "adpDepartments": sorted(adp_depts),
        "adDepartments": sorted(ad_depts),
        "adpOnlyIDs": missing_in_ad,
        "adOnlyIDs": missing_in_adp
    }

    return func.HttpResponse(
        json.dumps(result, default=json_converter, indent=2),
        mimetype="application/json",
        status_code=200
    )

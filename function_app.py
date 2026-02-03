import os
import json
import logging
import re
import requests
import ssl
import secrets
import string
import tempfile  # used to write PEM content to a temporary file
import time      # used for small backoff between bind retries
import base64    # used to decode base64-encoded certificates or keys
import certifi   # fallback CA bundle provider
import azure.functions as func
from ldap3 import Server, Connection, SUBTREE, Tls, NTLM, MODIFY_REPLACE
from ldap3.utils.dn import escape_rdn
from datetime import datetime, timezone, timedelta, date
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

app = func.FunctionApp()

# ---- Certificate and CA bundle helpers ----

def ensure_file_from_env(env_name: str, suffix: str) -> Optional[str]:
    """
    Ensure that a certificate or key stored in an environment variable is
    accessible from the filesystem.

    - If the environment variable contains a path to an existing file,
      return that path.
    - If it contains PEM-formatted text (starts with '-----BEGIN '), write
      the value to a temporary file and return its path.
    - If it appears to be base64-encoded, decode it and write to a
      temporary file with the given suffix, returning the path.
    - Otherwise return None.
    """
    val = os.getenv(env_name)
    if not val:
        return None

    # If it already points to a file on disk, use it as-is (useful for local dev)
    if os.path.exists(val):
        return val

    # Fix escaped newlines (common when secrets are stored with \n)
    val_fixed = val.replace('\\n', '\n')

    # If the value looks like PEM text (certificate or private key), write it to a temp file
    if val_fixed.strip().startswith('-----BEGIN '):
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        tmp.write(val_fixed.encode('utf-8'))
        tmp.close()
        logging.info(f"{env_name} appears to be PEM text; wrote to temp file {tmp.name}")
        return tmp.name

    # Try base64 decoding (likely a PFX or base64-encoded PEM)
    try:
        decoded = base64.b64decode(val_fixed)
        if decoded:
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
            tmp.write(decoded)
            tmp.close()
            logging.info(f"{env_name} appears to be base64; wrote decoded data to temp file {tmp.name}")
            return tmp.name
    except Exception:
        pass

    # Fallback: return None for unknown formats
    logging.warning(f"{env_name} is set but could not be interpreted as a file path, PEM, or base64")
    return None


def get_ca_bundle() -> str:
    """
    Determine the CA bundle path to use for verifying TLS connections.

    - If the CA_BUNDLE_PATH environment variable points to an existing file,
      return it.
    - Otherwise, return certifi.where(), which points to the certifi CA bundle.
    """
    ca_path = os.getenv('CA_BUNDLE_PATH')
    if ca_path and os.path.exists(ca_path):
        return ca_path
    # Fall back to certifi's CA bundle
    return certifi.where()

def get_adp_ca_bundle() -> str:
    """
    Determine the CA bundle path to use for verifying TLS connections to ADP.

    - If ADP_CA_BUNDLE_PATH points to an existing file, return it.
    - Otherwise, return certifi.where() for public CAs.
    """
    adp_ca_path = os.getenv('ADP_CA_BUNDLE_PATH')
    if adp_ca_path and os.path.exists(adp_ca_path):
        return adp_ca_path
    return certifi.where()

# ---- Helper functions ----

def parse_datetime(value: str, context: str) -> Optional[datetime]:
    """Parse ISO-like datetime strings, including a trailing 'Z' for UTC."""
    if not value:
        return None
    try:
        val = value.strip()
        if val.endswith("Z"):
            val = val[:-1] + "+00:00"
        dt = datetime.fromisoformat(val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception as e:
        logging.error(f"Error parsing {context} '{value}': {e}")
        return None


def _env_truthy(name: str, default: bool = False) -> bool:
    """Return True for common truthy environment values."""
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in {"1", "true", "yes", "y", "on"}


def extract_last_updated(emp) -> Optional[datetime]:
    """Extract a best-effort last-updated timestamp from an ADP worker record."""
    candidates = [
        emp.get("meta", {}).get("lastUpdatedDateTime"),
        emp.get("meta", {}).get("lastUpdatedTimestamp"),
        emp.get("meta", {}).get("lastUpdateDateTime"),
        emp.get("lastUpdatedDateTime"),
        emp.get("lastUpdatedTimestamp"),
        emp.get("lastUpdateDateTime"),
    ]
    wa = emp.get("workAssignments")
    if isinstance(wa, list) and wa:
        candidates.append(wa[0].get("lastUpdatedDateTime"))
        candidates.append(wa[0].get("lastUpdatedTimestamp"))
    for val in candidates:
        if val:
            dt = parse_datetime(val, "lastUpdated")
            if dt:
                return dt
    return None

def get_adp_token() -> Optional[str]:
    """
    Retrieve an OAuth access token from ADP using client credentials.

    This function reads the token URL, client ID, client secret, and
    certificate/key from environment variables. It uses the helper
    ensure_file_from_env() to handle cases where the certificate/key are
    provided either as file paths or as PEM/base64 text. It also uses
    get_ca_bundle() to determine the CA bundle for verifying the remote
    server's certificate.

    Returns the access token string on success, or None on failure.
    """
    token_url = os.getenv("ADP_TOKEN_URL")
    client_id = os.getenv("ADP_CLIENT_ID")
    client_secret = os.getenv("ADP_CLIENT_SECRET")
    # Resolve cert and key to file paths (handles PEM text or base64)
    pem_path = ensure_file_from_env('ADP_CERT_PEM', '.pem')
    key_path = ensure_file_from_env('ADP_CERT_KEY', '.key')

    if not token_url or not client_id or not client_secret:
        logging.error("Missing ADP_TOKEN_URL, ADP_CLIENT_ID, or ADP_CLIENT_SECRET environment variables.")
        return None
    if not pem_path:
        logging.error("ADP_CERT_PEM environment variable is missing or invalid.")
        return None

    # Build the certificate tuple or single file as required by requests
    client_cert: Optional[object]
    if key_path:
        client_cert = (pem_path, key_path)
    else:
        client_cert = pem_path

    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    verify_arg = get_adp_ca_bundle()
    try:
        resp = requests.post(
            token_url,
            headers=headers,
            data=payload,
            cert=client_cert,
            verify=verify_arg,
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
                dt = parse_datetime(d, f"assignment {key}")
                if dt:
                    return dt.isoformat()
    wd = employee.get("workerDates")
    dates = []
    if isinstance(wd, list):
        for item in wd:
            if "hire" in item.get("type", "").lower():
                d = item.get("value")
                if d:
                    dt = parse_datetime(d, "workerDates hire")
                    if dt:
                        dates.append(dt)
    elif isinstance(wd, dict):
        for key in ("originalHireDate", "hireDate", "hire_date"):
            d = wd.get(key)
            if d:
                dt = parse_datetime(d, f"workerDates {key}")
                if dt:
                    dates.append(dt)
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

def extract_business_title(emp):
    """Extracts the Business Title from the customFieldGroup."""
    custom_fields = emp.get("customFieldGroup", {}).get("stringFields", [])
    for field in custom_fields:
        if field.get("nameCode", {}).get("codeValue") == "Business Title":
            return field.get("stringValue")
    return None

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
        addr = {}
        if wa[0].get("assignedWorkLocations"):
            addr = wa[0]["assignedWorkLocations"][0].get("address", {})
            val = addr.get(field, "")
            if val:
                return val
        if wa[0].get("homeWorkLocation"):
            addr = wa[0]["homeWorkLocation"].get("address", {})
            return addr.get(field, "")
    return ""


def extract_state_from_work(emp):
    """Return the state or province code from the work address."""
    wa = emp.get("workAssignments", [])
    if wa:
        cs = {}
        if wa[0].get("assignedWorkLocations"):
            cs = wa[0]["assignedWorkLocations"][0].get("address", {}).get("countrySubdivisionLevel1", {})
            val = cs.get("codeValue", "")
            if val:
                return val
        if wa[0].get("homeWorkLocation"):
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

def get_adp_employees(token: str, limit: int = 50, offset: int = 0, paginate_all: bool = True) -> Optional[list]:
    """
    Retrieve employee records from ADP, handling pagination.

    This function builds the request to the ADP workers endpoint. It resolves the
    client certificate and key using ensure_file_from_env() and verifies
    server certificates using get_ca_bundle().

    Parameters:
        token (str): OAuth access token for ADP
        limit (int): Number of records to retrieve per page
        offset (int): Starting offset for pagination
        paginate_all (bool): Whether to retrieve all pages or only the first

    Returns:
        list: A list of employee records (dicts) on success
        None: On error or exception
    """
    employees: list = []
    base_url = os.getenv("ADP_EMPLOYEE_URL")
    if not base_url:
        logging.error("ADP_EMPLOYEE_URL environment variable is not set.")
        return None

    # Resolve certificate paths (handles PEM/base64)
    pem_path = ensure_file_from_env('ADP_CERT_PEM', '.pem')
    key_path = ensure_file_from_env('ADP_CERT_KEY', '.key')
    if not pem_path:
        logging.error("ADP_CERT_PEM environment variable is missing or invalid.")
        return None
    if key_path:
        client_cert = (pem_path, key_path)
    else:
        client_cert = pem_path

    headers = {"Authorization": f"Bearer {token}"}
    verify_arg = get_adp_ca_bundle()
    current_offset = offset

    while True:
        url = f"{base_url}?$top={limit}&$skip={current_offset}"
        try:
            response = requests.get(url, headers=headers, cert=client_cert, verify=verify_arg, timeout=10)
        except requests.RequestException as e:
            logging.error(f"Failed to retrieve employees: {e}")
            return None
        if not response.ok:
            logging.error(f"Failed to retrieve employees (HTTP {response.status_code}): {response.text}")
            return None

        try:
            data = response.json()
        except json.JSONDecodeError:
            logging.error(f"Failed to decode JSON from ADP response: {response.text}")
            return None

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
    h = parse_datetime(hd, "hireDate")
    if not h:
        return "Inactive"
    now = datetime.now(timezone.utc)
    if h > now:
        return "Inactive"
    if not td:
        return "Active"
    t = parse_datetime(td, "terminationDate")
    if not t:
        logging.warning(f"Invalid termination date '{td}' for employee; treating as Active")
        return "Active"
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


def _format_ldap_error(conn) -> str:
    """Build a concise LDAP error string from connection state."""
    parts = []
    result = getattr(conn, "result", None)
    if result:
        parts.append(f"result={result}")
    last_error = getattr(conn, "last_error", None)
    if last_error:
        parts.append(f"last_error={last_error}")
    return "; ".join(parts) if parts else "no ldap error details"


def _entry_attr_value(entry, attr: str):
    """Safely fetch an LDAP entry attribute value."""
    try:
        if hasattr(entry, attr):
            return getattr(entry, attr).value
        return entry[attr].value
    except Exception:
        return None


def _build_update_attributes(emp, conn, ldap_search_base) -> dict:
    """Map ADP worker data to AD attributes used for updates."""
    country_code = extract_work_address_field(emp, "countryCode")
    co_value = None
    if country_code:
        co_value = "United States" if country_code.upper() == "US" else country_code

    desired = {
        "title": extract_business_title(emp) or extract_assignment_field(emp, "jobTitle"),
        "department": extract_department(emp),
        "company": extract_company(emp),
        "l": extract_work_address_field(emp, "cityName"),
        "postalCode": extract_work_address_field(emp, "postalCode"),
        "st": extract_state_from_work(emp),
        "streetAddress": extract_work_address_field(emp, "lineOne"),
        "co": co_value,
    }
    if get_hire_date(emp):
        desired["userAccountControl"] = get_user_account_control(emp)
    manager_dn = get_manager_dn(conn, ldap_search_base, extract_manager_id(emp))
    if manager_dn:
        desired["manager"] = manager_dn
    return desired


def _diff_update_attributes(entry, desired: dict) -> dict:
    """Compute LDAP modify operations for attributes that differ."""
    changes = {}
    for attr, desired_val in desired.items():
        if desired_val in (None, ""):
            continue
        current = _entry_attr_value(entry, attr)
        if isinstance(desired_val, str):
            current_str = (current or "").strip()
            desired_str = desired_val.strip()
            if attr == "manager":
                if current_str.lower() == desired_str.lower():
                    continue
            elif current_str == desired_str:
                continue
        else:
            if current == desired_val:
                continue
        changes[attr] = [(MODIFY_REPLACE, [desired_val])]
    return changes


def _apply_ldap_modifications(conn, dn: str, changes: dict, conn_factory=None) -> Optional[Connection]:
    """Apply LDAP modifications with basic bind-lost recovery."""
    if not changes:
        return conn
    if conn.modify(dn, changes):
        return conn
    result = conn.result or {}
    msg = str(result.get("message") or "")
    if result.get("result") == 1 and "successful bind must be completed" in msg:
        logging.warning(f"Modify failed for {dn} (bind lost); attempting rebind")
        try:
            if conn.rebind():
                if conn.modify(dn, changes):
                    return conn
            else:
                logging.error(f"Rebind failed during modify: {_format_ldap_error(conn)}")
        except Exception as e:
            logging.error(f"Rebind failed during modify: {e}")
        if conn_factory:
            logging.warning(f"Reconnecting LDAP after modify bind loss for {dn}")
            try:
                try:
                    conn.unbind()
                except Exception:
                    pass
                conn = conn_factory()
                if conn.modify(dn, changes):
                    return conn
            except Exception as e:
                logging.error(f"Reconnect failed during modify: {e}")
        logging.error(f"Modify failed for {dn}: {_format_ldap_error(conn)}")
        return conn
    logging.error(f"Modify failed for {dn}: {conn.result}")
    return conn


def provision_user_in_ad(user_data, conn, ldap_search_base, ldap_create_base, conn_factory=None):
    """Create and enable an AD user using data from ADP."""
    country_code = extract_work_address_field(user_data, "countryCode") or ""
    if not country_code.upper() or country_code.upper() == "MX":
        logging.info(f"Skipping provisioning for country code '{country_code}'")
        return conn

    person = user_data.get("person", {})
    first, last = get_first_last(person)
    if not first or not last:
        logging.warning(f"Skipping user with incomplete name data: {user_data}")
        return conn
    full_name = f"{first} {last}".strip()
    if not full_name:
        logging.warning(f"Skipping user with incomplete name data: {user_data}")
        return conn

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
        return conn

    # Build attributes for new user
    base_sam_raw = sanitize_string_for_sam(first[0].lower() + last.lower())
    if not base_sam_raw:
        logging.warning(f"Skipping user with invalid sAMAccountName: {user_data}")
        return conn
    base_alias = sanitize_string_for_sam(first.lower()) + sanitize_string_for_sam(last.lower())
    if not base_alias:
        base_alias = base_sam_raw
    upn_suffix = os.getenv("UPN_SUFFIX", "cfsbrands.com").strip()
    if upn_suffix.startswith("@"):
        upn_suffix = upn_suffix[1:]

    def build_sam(suffix: str) -> str:
        if not suffix:
            return base_sam_raw[:10]
        max_base_len = max(0, 10 - len(suffix))
        return f"{base_sam_raw[:max_base_len]}{suffix}"

    base_attrs = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "givenName": first,
        "sn": last,
        "employeeID": emp_id,
        "title": extract_business_title(user_data) or extract_assignment_field(user_data, "jobTitle"),
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
    dn = None
    attempt = 0
    bind_retries = 0
    max_bind_retries = 3
    reconnect_attempts = 0
    max_reconnect_attempts = 2
    while attempt < 50:
        if hasattr(conn, "bound") and not conn.bound:
            try:
                conn.bind()
            except Exception as e:
                logging.error(f"Rebind failed before add attempt: {e}")
                return conn
        suffix = "" if attempt == 0 else str(attempt + 1)
        cn = full_name if not suffix else f"{full_name} {suffix}"
        sam = build_sam(suffix)
        if not sam:
            logging.warning(f"Skipping user with invalid sAMAccountName: {user_data}")
            return conn
        alias = base_alias if not suffix else f"{base_alias}{suffix}"
        attrs = dict(base_attrs)
        attrs.update(
            {
                "cn": cn,
                "displayName": cn,
                "userPrincipalName": f"{alias}@{upn_suffix}",
                "mail": f"{alias}@cfsbrands.com",
                "sAMAccountName": sam,
            }
        )
        final_attrs = {k: v for k, v in attrs.items() if v or k in mandatory}
        dn_candidate = f"CN={escape_rdn(cn)},{ldap_create_base}"
        if conn.add(dn_candidate, attributes=final_attrs):
            dn = dn_candidate
            break
        result = conn.result or {}
        msg = str(result.get("message") or "")
        if result.get("result") == 68:
            logging.warning(f"Add failed for {dn_candidate} (entryAlreadyExists); retrying with suffix")
            attempt += 1
            continue
        if result.get("result") == 19:
            if "userPrincipalName" in msg or "sAMAccountName" in msg:
                logging.warning(f"Add failed for {dn_candidate} (constraintViolation on account id); retrying with suffix")
                attempt += 1
                continue
            logging.error(f"Add failed for {dn_candidate} (constraintViolation): {conn.result}")
            return conn
        if result.get("result") == 1 and "successful bind must be completed" in msg:
            logging.warning(f"Bind lost details: {_format_ldap_error(conn)}")
            if bind_retries >= max_bind_retries:
                if conn_factory and reconnect_attempts < max_reconnect_attempts:
                    logging.warning(f"Add failed for {dn_candidate} after {max_bind_retries} rebinds; reconnecting")
                    reconnect_attempts += 1
                    try:
                        try:
                            conn.unbind()
                        except Exception:
                            pass
                        conn = conn_factory()
                        bind_retries = 0
                        time.sleep(0.5)
                        continue
                    except Exception as e:
                        logging.error(f"Reconnect failed after bind loss: {e}")
                        return conn
                logging.error(f"Add failed for {dn_candidate}: bind lost after {max_bind_retries} retries")
                return conn
            logging.warning(f"Add failed for {dn_candidate} (bind lost); rebinding and retrying")
            bind_retries += 1
            try:
                if not conn.rebind():
                    logging.error(f"Rebind failed after bind-lost error: {_format_ldap_error(conn)}")
                    if conn_factory and reconnect_attempts < max_reconnect_attempts:
                        reconnect_attempts += 1
                        logging.warning(f"Attempting reconnect after rebind failure (attempt {reconnect_attempts})")
                        try:
                            try:
                                conn.unbind()
                            except Exception:
                                pass
                            conn = conn_factory()
                            bind_retries = 0
                            time.sleep(0.5)
                            continue
                        except Exception as e:
                            logging.error(f"Reconnect failed after rebind failure: {e}")
                            return conn
                    return conn
            except Exception as e:
                logging.error(f"Rebind failed after bind-lost error: {e}")
                return conn
            time.sleep(0.5)
            continue
        logging.error(f"Add failed for {dn_candidate}: {conn.result}")
        return conn
        attempt += 1
    if not dn:
        logging.error(f"Add failed for base CN '{full_name}': exceeded unique CN attempts")
        return conn
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
    return conn

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
    cutoff = today
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

    ca_bundle = get_ca_bundle()
    logging.info(f"Using CA bundle at '{ca_bundle}' for LDAP")

    if not os.path.isfile(ca_bundle):
        logging.error(f"CA bundle not found at {ca_bundle}")
        return

    tls_config = Tls(
        ca_certs_file=ca_bundle,
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLSv1_2,
    )

    server = Server(ldap_server, port=636, use_ssl=True, tls=tls_config, get_info=None)
    try:
        def conn_factory():
            return Connection(
                server,
                user=ldap_user,
                password=ldap_password,
                authentication=NTLM,
                auto_bind=True,
            )
        conn = conn_factory()
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
            new_conn = provision_user_in_ad(emp, conn, ldap_search_base, ldap_create_base, conn_factory)
            if not new_conn:
                logging.error("LDAP connection unavailable; aborting scheduled_adp_sync")
                break
            conn = new_conn
        except Exception as e:
            logging.error(f"❌ Exception provisioning {emp_id}: {e}")
    conn.unbind()
    logging.info("🔒 LDAP connection closed — scheduled_adp_sync complete")


# ---- Scheduled update sync (dry run by default) ----
@app.schedule(schedule="0 0 * * * *", arg_name="mytimer", run_on_startup=False)
def scheduled_adp_update(mytimer: func.TimerRequest):
    """Timer triggered function that updates existing AD users from ADP (dry run by default)."""
    dry_run = _env_truthy("UPDATE_DRY_RUN", True)
    lookback_days_raw = os.getenv("UPDATE_LOOKBACK_DAYS", "7")
    try:
        lookback_days = int(lookback_days_raw)
    except ValueError:
        lookback_days = 7
    include_missing_updates = _env_truthy("UPDATE_INCLUDE_MISSING_LAST_UPDATED", True)
    log_no_changes = _env_truthy("UPDATE_LOG_NO_CHANGES", False)

    logging.info(f"🔁 scheduled_adp_update triggered (dry_run={dry_run}, lookback_days={lookback_days})")
    token = get_adp_token()
    if not token:
        logging.error("❌ Failed to retrieve ADP token for update.")
        return
    logging.info("✅ ADP token acquired for update")
    all_employees = get_adp_employees(token)
    if all_employees is None:
        logging.error("❌ get_adp_employees returned None for update")
        return

    candidates = []
    missing_last_updated = 0
    if lookback_days > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
        for emp in all_employees:
            updated_at = extract_last_updated(emp)
            if updated_at and updated_at >= cutoff:
                candidates.append(emp)
            elif not updated_at:
                missing_last_updated += 1
                if include_missing_updates:
                    candidates.append(emp)
        logging.info(
            f"ℹ️  {len(candidates)} ADP employees considered for update since {cutoff.date().isoformat()} "
            f"(missing lastUpdated={missing_last_updated})"
        )
    else:
        candidates = all_employees
        logging.info(f"ℹ️  {len(candidates)} ADP employees considered for update (no lookback filter)")

    if not candidates:
        logging.info("🚫 Nothing to update; exiting scheduled_adp_update")
        return

    ldap_server = os.getenv("LDAP_SERVER")
    ldap_user = os.getenv("LDAP_USER")
    ldap_password = os.getenv("LDAP_PASSWORD")
    ldap_search_base = os.getenv("LDAP_SEARCH_BASE")

    ca_bundle = get_ca_bundle()
    logging.info(f"Using CA bundle at '{ca_bundle}' for LDAP update")
    if not os.path.isfile(ca_bundle):
        logging.error(f"CA bundle not found at {ca_bundle}")
        return

    tls_config = Tls(
        ca_certs_file=ca_bundle,
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLSv1_2,
    )

    server = Server(ldap_server, port=636, use_ssl=True, tls=tls_config, get_info=None)
    try:
        def conn_factory():
            return Connection(
                server,
                user=ldap_user,
                password=ldap_password,
                authentication=NTLM,
                auto_bind=True,
            )
        conn = conn_factory()
    except Exception as e:
        logging.error(f"❌ Failed to connect to LDAP server for update: {e}")
        return

    logging.info("🔗 LDAP connection opened for update")
    updated_users = 0
    total_changes = 0
    missing_in_ad = 0
    for emp in candidates:
        emp_id = extract_employee_id(emp)
        if not emp_id:
            continue
        conn.search(
            ldap_search_base,
            f"(employeeID={emp_id})",
            SUBTREE,
            attributes=[
                "distinguishedName",
                "employeeID",
                "title",
                "department",
                "company",
                "l",
                "st",
                "postalCode",
                "streetAddress",
                "co",
                "manager",
                "userAccountControl",
            ],
        )
        if not conn.entries:
            missing_in_ad += 1
            continue
        entry = conn.entries[0]
        dn = _entry_attr_value(entry, "distinguishedName") or "<unknown DN>"
        desired = _build_update_attributes(emp, conn, ldap_search_base)
        changes = _diff_update_attributes(entry, desired)
        if not changes:
            if log_no_changes:
                logging.info(f"✅ No updates needed for {emp_id} at {dn}")
            continue
        updated_users += 1
        for attr, ops in changes.items():
            desired_val = ops[0][1][0] if ops and ops[0][1] else None
            current_val = _entry_attr_value(entry, attr)
            if dry_run:
                logging.info(f"🧪 DRY RUN update {emp_id} {attr}: '{current_val}' -> '{desired_val}'")
            else:
                logging.info(f"Updating {emp_id} {attr}: '{current_val}' -> '{desired_val}'")
        total_changes += len(changes)
        if not dry_run:
            conn = _apply_ldap_modifications(conn, dn, changes, conn_factory)
            if not conn:
                logging.error("LDAP connection unavailable; aborting scheduled_adp_update")
                break

    try:
        conn.unbind()
    except Exception:
        pass
    logging.info(
        f"🔒 LDAP connection closed — scheduled_adp_update complete "
        f"(users_with_changes={updated_users}, total_changes={total_changes}, missing_in_ad={missing_in_ad})"
    )


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
                "jobTitle": extract_business_title(emp) or extract_assignment_field(emp, "jobTitle"),
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


def fetch_ad_data_task() -> Optional[dict]:
    """Fetch all AD users and build a map of employeeID -> department."""
    ldap_server = os.getenv("LDAP_SERVER")
    ldap_user = os.getenv("LDAP_USER")
    ldap_password = os.getenv("LDAP_PASSWORD")
    ldap_search_base = os.getenv("LDAP_SEARCH_BASE")

    if not all([ldap_server, ldap_user, ldap_password, ldap_search_base]):
        logging.error("Missing LDAP configuration for export.")
        return None

    try:
        ca_bundle = get_ca_bundle()
        logging.info(f"🔐 Using CA bundle for export: {ca_bundle}")
    except Exception as e:
        logging.error(f"❌ Unable to determine CA bundle for export: {e}")
        return None

    tls = Tls(
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLS_CLIENT,
        ca_certs_file=ca_bundle,
    )

    server = Server(ldap_server, port=636, use_ssl=True, tls=tls, get_info=None)
    try:
        conn = Connection(
            server,
            user=ldap_user,
            password=ldap_password,
            authentication=NTLM,
            auto_bind=True,
        )
        logging.info("🔗 LDAP connection opened for export.")
    except Exception as e:
        logging.error(f"Failed to connect to LDAP: {e}")
        return None

    ldap_map: dict[str, str] = {}
    page_size = 500
    cookie = None
    try:
        while True:
            conn.search(
                ldap_search_base,
                "(employeeID=*)",
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

            controls = conn.result.get("controls", {})
            cookie = (
                controls.get("1.2.840.113556.1.4.319", {})
                .get("value", {})
                .get("cookie")
            )
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
    missing_in_ad = sorted(list(ids_adp - ids_ad))
    missing_in_adp = sorted(list(ids_ad - ids_adp))

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
        "pairs": sorted(list(dept_pairs)),
        "adpDepartments": sorted(list(adp_depts)),
        "adDepartments": sorted(list(ad_depts)),
        "adpOnlyIDs": missing_in_ad,
        "adOnlyIDs": missing_in_adp
    }

    return func.HttpResponse(
        json.dumps(result, default=json_converter, indent=2),
        mimetype="application/json",
        status_code=200
    )

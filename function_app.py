import os
import json
import logging
import re
import socket
import time
import requests
import ssl
import secrets
import string
import tempfile  # used to write PEM content to a temporary file
import base64    # used to decode base64-encoded certificates or keys
import certifi   # fallback CA bundle provider
import azure.functions as func
from ldap3 import BASE, Server, Connection, SUBTREE, Tls, NTLM, MODIFY_REPLACE
from ldap3.utils.dn import escape_rdn
from datetime import datetime, timezone, timedelta, date
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Any

app = func.FunctionApp()

# Runtime overview for reviewers:
# 1) Timer jobs pull workers from ADP and then either provision or update AD users via LDAPS.
# 2) HTTP routes expose diagnostic payloads for department mapping/export verification.
# 3) Department mapping logic is centralized in resolve_local_ac_department() and reused by update paths.

# HTTP/LDAP retry and timeout defaults for outbound network calls.
ADP_HTTP_TIMEOUT_SECONDS = 10
ADP_HTTP_MAX_RETRIES = 3
ADP_HTTP_BACKOFF_SECONDS = 0.75

# LDAP attribute constants to keep mapping and guardrails explicit.
ATTR_CN = "cn"
ATTR_SN = "sn"
ATTR_GIVEN_NAME = "givenName"
ATTR_DISPLAY_NAME = "displayName"
ATTR_EMPLOYEE_ID = "employeeID"
ATTR_USER_PRINCIPAL_NAME = "userPrincipalName"
ATTR_MAIL = "mail"
ATTR_MAIL_NICKNAME = "mailNickname"
ATTR_PROXY_ADDRESSES = "proxyAddresses"
ATTR_TARGET_ADDRESS = "targetAddress"
ATTR_SAM_ACCOUNT_NAME = "sAMAccountName"

# Email-routing identifiers are create-time only and must never be touched by update sync.
EMAIL_IDENTIFIER_UPDATE_DENYLIST = {
    ATTR_MAIL.lower(),
    ATTR_USER_PRINCIPAL_NAME.lower(),
    ATTR_MAIL_NICKNAME.lower(),
    ATTR_PROXY_ADDRESSES.lower(),
    ATTR_TARGET_ADDRESS.lower(),
    "othermailbox",
    "msrtcsip-primaryuseraddress",
}

# Update search intentionally excludes email-routing attributes.
AD_UPDATE_SEARCH_ATTRIBUTES = [
    "distinguishedName",
    ATTR_EMPLOYEE_ID,
    ATTR_DISPLAY_NAME,
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
]

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


def _missing_env_vars(names: list[str]) -> list[str]:
    """Return environment variable names that are unset or empty."""
    return [name for name in names if not os.getenv(name)]


def _log_ldap_target_details(context: str, host: str, ca_bundle: str, port: int = 636):
    """Log LDAP endpoint and DNS resolution details for troubleshooting."""
    logging.info(
        f"{context} LDAP target host='{host}' port={port} use_ssl=True "
        f"tls_version=TLSv1_2 ca_bundle='{ca_bundle}'"
    )
    if not host:
        return
    try:
        resolved = sorted(
            {item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
        )
        if resolved:
            logging.info(f"{context} LDAP DNS '{host}' resolved to: {', '.join(resolved)}")
    except Exception as e:
        logging.warning(f"{context} LDAP DNS resolution failed for '{host}': {e}")


def _request_with_retries(
    method: str,
    url: str,
    *,
    action_label: str,
    max_attempts: int = ADP_HTTP_MAX_RETRIES,
    timeout: int = ADP_HTTP_TIMEOUT_SECONDS,
    retryable_statuses: Optional[set[int]] = None,
    **kwargs: Any,
) -> Optional[Any]:
    """
    Execute an HTTP request with bounded retries and exponential backoff.

    Retries are attempted for transient transport exceptions and retryable HTTP
    statuses (429/5xx by default). Non-retryable responses are returned
    immediately for caller-side handling.
    """
    retryable = retryable_statuses or {429, 500, 502, 503, 504}
    delay = ADP_HTTP_BACKOFF_SECONDS
    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.request(method, url, timeout=timeout, **kwargs)
        except requests.RequestException as e:
            if attempt >= max_attempts:
                logging.error(f"{action_label} failed after {attempt} attempts: {e}")
                return None
            logging.warning(f"{action_label} transport error (attempt {attempt}/{max_attempts}): {e}; retrying")
            time.sleep(delay)
            delay *= 2
            continue

        if response.status_code in retryable:
            if attempt >= max_attempts:
                logging.error(
                    f"{action_label} failed after {attempt} attempts with HTTP {response.status_code}: "
                    f"{response.text}"
                )
                return None
            logging.warning(
                f"{action_label} received retryable HTTP {response.status_code} "
                f"(attempt {attempt}/{max_attempts}); retrying"
            )
            time.sleep(delay)
            delay *= 2
            continue

        return response
    return None

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

    missing = _missing_env_vars(["ADP_TOKEN_URL", "ADP_CLIENT_ID", "ADP_CLIENT_SECRET"])
    if missing:
        logging.error(f"Missing ADP token configuration: {', '.join(missing)}")
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
    resp = _request_with_retries(
        "POST",
        token_url,
        action_label="ADP token request",
        headers=headers,
        data=payload,
        cert=client_cert,
        verify=verify_arg,
    )
    if not resp:
        return None
    if not resp.ok:
        logging.error(f"ADP token request failed (HTTP {resp.status_code}): {resp.text}")
        return None
    try:
        body = resp.json()
    except json.JSONDecodeError:
        logging.error(f"ADP token response was not JSON: {resp.text}")
        return None
    token = body.get("access_token")
    if not token:
        logging.error(f"ADP token response missing access_token. Keys={list(body.keys())}")
        return None
    return token


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


def _clean_name_part(value: Any) -> str:
    """Normalize a name part to a stripped string."""
    if not isinstance(value, str):
        return ""
    return value.strip()


def get_legal_first_last(person: dict) -> tuple[str, str]:
    """Return legal first/last name from ADP person payload."""
    if not isinstance(person, dict):
        return "", ""
    legal = person.get("legalName", {})
    if not isinstance(legal, dict):
        return "", ""
    first = _clean_name_part(legal.get("givenName"))
    last = _clean_name_part(legal.get("familyName1"))
    return first, last


def get_preferred_first_last(person: dict) -> tuple[str, str]:
    """Return preferred first/last name from ADP person payload, if present."""
    if not isinstance(person, dict):
        return "", ""
    preferred = person.get("preferredName", {})
    if not isinstance(preferred, dict):
        return "", ""
    first = _clean_name_part(preferred.get("givenName"))
    last = _clean_name_part(preferred.get("familyName1"))
    return first, last


def get_display_name(person: dict) -> str:
    """Return preferred full name when complete, otherwise legal full name."""
    preferred_first, preferred_last = get_preferred_first_last(person)
    if preferred_first and preferred_last:
        return f"{preferred_first} {preferred_last}".strip()
    legal_first, legal_last = get_legal_first_last(person)
    return f"{legal_first} {legal_last}".strip()


def get_first_last(person):
    """
    Backward-compatible name helper.

    Returns legal first/last only. New code should call get_legal_first_last()
    or get_preferred_first_last() explicitly based on intent.
    """
    return get_legal_first_last(person)


def sanitize_string_for_sam(s):
    """Remove non-alphanumeric characters for a sAMAccountName."""
    return re.sub(r"[^a-zA-Z0-9]", "", s)


def extract_assignment_field(emp, field):
    """Return a value from the employee's first work assignment."""
    wa = emp.get("workAssignments", [])
    if not wa or not isinstance(wa[0], dict):
        return ""
    return wa[0].get(field, "")


def extract_department(emp):
    """Retrieve the department short name from work assignments."""
    wa = emp.get("workAssignments", [])
    if not wa or not isinstance(wa[0], dict):
        return ""
    candidates = []
    occ = wa[0].get("occupationalClassifications", [])
    if isinstance(occ, list):
        for item in occ:
            code = item.get("classificationCode", {}) if isinstance(item, dict) else {}
            val = code.get("shortName") or code.get("longName") or code.get("name")
            if val:
                candidates.append(("occupationalClassifications.classificationCode", val))
                break
    for ou in wa[0].get("assignedOrganizationalUnits", []):
        if ou.get("typeCode", {}).get("codeValue", "").lower() == "department":
            val = ou.get("nameCode", {}).get("shortName", "")
            if val:
                candidates.append(("assignedOrganizationalUnits.department", val))
                break
    for ou in wa[0].get("homeOrganizationalUnits", []):
        if ou.get("typeCode", {}).get("codeValue", "").lower() == "department":
            val = ou.get("nameCode", {}).get("shortName", "")
            if val:
                candidates.append(("homeOrganizationalUnits.department", val))
                break
    if not candidates:
        return ""
    source, value = candidates[0]
    if _env_truthy("LOG_DEPARTMENT_SOURCE", False):
        emp_id = extract_employee_id(emp)
        person = emp.get("person", {})
        legal_first, legal_last = get_legal_first_last(person)
        display_name = get_display_name(person) or "<no display name>"
        legal_name = f"{legal_first} {legal_last}".strip() or "<no legal name>"
        logging.info(
            f"Department source for {emp_id} / display='{display_name}' legal='{legal_name}': "
            f"{source} -> {value}"
        )
    return value

def extract_business_title(emp):
    """Extract the Business Title value from custom fields."""
    custom_group = emp.get("customFieldGroup", {})
    if not isinstance(custom_group, dict):
        return None
    custom_fields = custom_group.get("stringFields", [])
    if not isinstance(custom_fields, list):
        return None
    for field in custom_fields:
        if not isinstance(field, dict):
            continue
        if field.get("nameCode", {}).get("codeValue") == "Business Title":
            return field.get("stringValue")
    return None

def extract_company(emp):
    """Retrieve the company or business unit name from work assignments."""
    wa = emp.get("workAssignments", [])
    if not wa or not isinstance(wa[0], dict):
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


def _normalize_dept_signal(value: str) -> str:
    """Normalize free-form labels for deterministic department matching."""
    normalized = (value or "").strip().lower().replace("&", " and ")
    normalized = re.sub(r"[^a-z0-9\s\-/]", " ", normalized)
    return re.sub(r"\s+", " ", normalized).strip()


CANONICAL_DEPTS = {
    "Administration",
    "Engineering",
    "Finance",
    "Human Resources",
    "Information Technology",
    "Operations",
    "Sales",
    "Supply Chain",
}

_LOCAL_AC_DEPT_PRIORITY = [
    "Information Technology",
    "Human Resources",
    "Engineering",
    "Finance",
    "Sales",
    "Supply Chain",
    "Operations",
    "Administration",
]

_LOCAL_AC_FIELD_WEIGHTS = {
    "costCenterDescription": 105,
    "assignedDept": 100,
    "homeDept": 95,
    "occupationalClassifications": 85,
    "jobTitle": 70,
    "businessTitle": 65,
    "businessUnit": 50,
    "department": 45,
    "managerDepartment": 40,
    "titleInference": 55,
}

_LOCAL_AC_DIRECT_MAP = {
    "operations": "Operations",
    "operaciones": "Operations",
    "administration": "Administration",
    "administrative": "Administration",
    "administrative support workers": "Administration",
    "supply chain": "Supply Chain",
    "information technology": "Information Technology",
    "information tech": "Information Technology",
    "it": "Information Technology",
    "human resources": "Human Resources",
    "hr": "Human Resources",
    "recursos humanos": "Human Resources",
    "engineering": "Engineering",
    "finance": "Finance",
    "finanzas": "Finance",
    "sales": "Sales",
    "sales and marketing": "Sales",
    "ventas": "Sales",
}

_LOCAL_AC_RULES = [
    ("Information Technology", 40, re.compile(r"\binformation technology\b")),
    ("Information Technology", 35, re.compile(r"\binformation tech\b")),
    ("Information Technology", 20, re.compile(r"\bit\s*-")),
    ("Information Technology", 25, re.compile(r"\btecnolog")),
    ("Human Resources", 40, re.compile(r"\bhuman resources\b")),
    ("Human Resources", 35, re.compile(r"\brecursos humanos\b")),
    ("Human Resources", 25, re.compile(r"\bhr\b")),
    ("Engineering", 40, re.compile(r"\bengineering\b")),
    ("Engineering", 35, re.compile(r"\bengineer")),
    ("Engineering", 30, re.compile(r"\bingenier")),
    ("Engineering", 30, re.compile(r"\beng\s*-")),
    ("Engineering", 25, re.compile(r"\br\s*&\s*d\b")),
    ("Engineering", 25, re.compile(r"\bresearch\b")),
    ("Engineering", 25, re.compile(r"\bdevelopment\b")),
    ("Finance", 40, re.compile(r"\bfinance\b")),
    ("Finance", 35, re.compile(r"\bfinanzas\b")),
    ("Finance", 30, re.compile(r"\bfin\s*-")),
    ("Finance", 25, re.compile(r"\baccount")),
    ("Finance", 25, re.compile(r"\bcontab")),
    ("Sales", 40, re.compile(r"\bsales\b")),
    ("Sales", 35, re.compile(r"\bmarketing\b")),
    ("Sales", 35, re.compile(r"\bventas\b")),
    ("Sales", 30, re.compile(r"\bnatl\s*acct")),
    ("Sales", 30, re.compile(r"\bnational\s*acct")),
    ("Supply Chain", 40, re.compile(r"\bsupply chain\b")),
    ("Supply Chain", 35, re.compile(r"\bcadena de suministros\b")),
    ("Supply Chain", 30, re.compile(r"\bdistribution\b")),
    ("Supply Chain", 30, re.compile(r"\bdist\b")),
    ("Supply Chain", 30, re.compile(r"\bwarehouse\b")),
    ("Supply Chain", 25, re.compile(r"\blogistics\b")),
    ("Supply Chain", 20, re.compile(r"\bshipping\b")),
    ("Supply Chain", 20, re.compile(r"\breceiving\b")),
    ("Supply Chain", 20, re.compile(r"\bpurchase\b")),
    ("Supply Chain", 20, re.compile(r"\bprocurement\b")),
    ("Supply Chain", 20, re.compile(r"\bforklift\b")),
    ("Operations", 40, re.compile(r"\boperations\b")),
    ("Operations", 35, re.compile(r"\boperaciones\b")),
    ("Operations", 35, re.compile(r"\bmanufactur")),
    ("Operations", 35, re.compile(r"\bproduction\b")),
    ("Operations", 35, re.compile(r"\bmfg\b")),
    ("Operations", 30, re.compile(r"\bquality\b")),
    ("Operations", 30, re.compile(r"\bqa\b")),
    ("Operations", 30, re.compile(r"\boperatives\b")),
    ("Operations", 30, re.compile(r"\blaborers\b")),
    ("Operations", 25, re.compile(r"direct labor")),
    ("Operations", 25, re.compile(r"\bidl\b")),
    ("Operations", 25, re.compile(r"\bops\b")),
    ("Operations", 25, re.compile(r"\bops support\b")),
    ("Operations", 25, re.compile(r"\bops mgt\b")),
    ("Operations", 20, re.compile(r"\bextrusion\b")),
    ("Operations", 20, re.compile(r"\bthermoforming\b")),
    ("Operations", 20, re.compile(r"\bweld\b")),
    ("Operations", 20, re.compile(r"\broto\b")),
    ("Operations", 20, re.compile(r"\bvalue add\b")),
    ("Operations", 20, re.compile(r"\bsanta fe\b")),
    ("Administration", 40, re.compile(r"\badministration\b")),
    ("Administration", 35, re.compile(r"\badministrative services?\b")),
    ("Administration", 35, re.compile(r"\badministrative assistant\b")),
    ("Administration", 35, re.compile(r"\bexecutive assistant\b")),
    ("Administration", 35, re.compile(r"\breceptionist\b")),
    ("Administration", 30, re.compile(r"\boffice administrator\b")),
    ("Administration", 30, re.compile(r"\boffice manager\b")),
    ("Administration", 25, re.compile(r"\badmin\b")),
]

AMBIGUOUS_REFERENCE_VALUES = {
    "Professionals",
    "First/Mid-Level Officials and Managers",
    "Administrative Support Workers",
    "Mexico Corporate",
}

_AMBIGUOUS_REFERENCE_VALUES_NORMALIZED = {
    _normalize_dept_signal(v) for v in AMBIGUOUS_REFERENCE_VALUES
}

_CANONICAL_BY_SIGNAL = {
    _normalize_dept_signal(dept): dept for dept in CANONICAL_DEPTS
}

_DEPARTMENT_NORMALIZATION_ALIASES = {
    "information tech": "Information Technology",
    "it": "Information Technology",
    "recursos humanos": "Human Resources",
    "finanzas": "Finance",
    "sales and marketing": "Sales",
}

_LOW_CONFIDENCE_FIELDS = {"occupationalClassifications", "department"}
_CONFIDENCE_RANK = {"LOW": 1, "MED": 2, "HIGH": 3}

_TITLE_INFERENCE_RULES = [
    ("Engineering", "MED", 80, re.compile(r"\bmfng\s*eng\b|\bmanufacturing\s*eng\b|\bmfg\s*eng\b|\bsr\s*eng\b|\bengineer(ing)?\b|\beng\b")),
    ("Supply Chain", "MED", 75, re.compile(r"\bmat\s*mngt\b|\bmaterials?\s*management\b|\bmaterial\s*mngt\b|\bdemand\s*plng\b|\bdemand\s*planning\b|\blogistics\b|\bdistribution\b|\bshipping\b|\binventory\b|\bplanner\b|\bbuyer\b|\bsourcing\b|\bprocurement\b")),
    ("Information Technology", "MED", 75, re.compile(r"\bend user services?\b|\beus\b|\bbi analyst\b|\bsystems?\b|\bnetwork\b|\bsecurity\b|\bit\b")),
    ("Finance", "MED", 75, re.compile(r"\baccounting\b|\baccounts?\s*payable\b|\baccounts?\s*receivable\b|\bcredit\s*&?\s*collect\b|\bcontroller\b|\bar\b|\bap\b")),
    ("Sales", "MED", 75, re.compile(r"\baccount executive\b|\bcustomer service\b|\baccount management\b")),
    ("Human Resources", "MED", 75, re.compile(r"\bhuman resources\b|\bhr generalist\b")),
    ("Administration", "MED", 75, re.compile(r"\badministrative assistant\b|\bexecutive assistant\b|\breceptionist\b|\boffice administrator\b|\boffice manager\b|\badministrative services?\b")),
]

_STRONG_ADMIN_TITLE_PATTERNS = [
    re.compile(r"\badministrative assistant\b"),
    re.compile(r"\bexecutive assistant\b"),
    re.compile(r"\breceptionist\b"),
    re.compile(r"\boffice administrator\b"),
    re.compile(r"\boffice manager\b"),
    re.compile(r"\badministrative services?\b"),
]


def normalize_department_name(value: str) -> str:
    """Normalize department values for comparisons and guardrails."""
    cleaned = re.sub(r"\s+", " ", (value or "").strip())
    if not cleaned:
        return ""
    if re.match(r"^information technology\s*\|", cleaned, flags=re.IGNORECASE):
        return "Information Technology"
    normalized = _normalize_dept_signal(cleaned)
    if normalized in _DEPARTMENT_NORMALIZATION_ALIASES:
        return _DEPARTMENT_NORMALIZATION_ALIASES[normalized]
    if normalized in _CANONICAL_BY_SIGNAL:
        return _CANONICAL_BY_SIGNAL[normalized]
    return cleaned


def _is_canonical_department(value: str) -> bool:
    """Return True when a value normalizes to one of the canonical departments."""
    return normalize_department_name(value) in CANONICAL_DEPTS


def _is_ambiguous_reference_value(value: str) -> bool:
    """Return True when a value is in the ambiguous reference list."""
    return _normalize_dept_signal(value) in _AMBIGUOUS_REFERENCE_VALUES_NORMALIZED


def _confidence_for_source(source: str, explicit_canonical: bool) -> str:
    """Map a source to confidence level."""
    if source in {"costCenterDescription", "assignedDept", "homeDept"}:
        return "HIGH"
    if source in {"managerDepartment", "titleInference"}:
        return "MED"
    if source in {"occupationalClassifications", "department"}:
        return "MED" if explicit_canonical else "LOW"
    return "LOW"


def _confidence_label(rank: int) -> str:
    """Convert numeric confidence rank to label."""
    for label, value in _CONFIDENCE_RANK.items():
        if value == rank:
            return label
    return "LOW"


def _is_customer_service_assigned_dept(source: str, value: str) -> bool:
    """Detect the customer service assignedDept override case."""
    if source not in {"assignedDept", "costCenterDescription"}:
        return False
    return _normalize_dept_signal(value).startswith("customer service")


def _is_explicit_admin_assigned_dept(value: str) -> bool:
    """Detect explicit admin-coded assigned department values."""
    normalized = _normalize_dept_signal(value)
    if normalized.startswith("admin"):
        return True
    explicit_markers = (
        "administrative svcs",
        "administrative services",
        "office administrator",
        "office manager",
        "admin services",
    )
    return any(marker in normalized for marker in explicit_markers)


def infer_department_from_title(title: str) -> dict:
    """Infer department from titles with patterns tuned to current dataset abbreviations."""
    normalized = _normalize_dept_signal(title)
    if not normalized:
        return {
            "department": "",
            "confidence": "",
            "reason": "",
            "isStrongAdmin": False,
        }

    scores = {}
    best_conf_rank = {}
    reasons = {}
    for dept, confidence, weight, pattern in _TITLE_INFERENCE_RULES:
        if not pattern.search(normalized):
            continue
        scores[dept] = scores.get(dept, 0) + weight
        best_conf_rank[dept] = max(best_conf_rank.get(dept, 0), _CONFIDENCE_RANK[confidence])
        reasons.setdefault(dept, []).append(f"title:{title}")

    if not scores:
        return {
            "department": "",
            "confidence": "",
            "reason": "",
            "isStrongAdmin": False,
        }

    ranked = sorted(
        scores.items(),
        key=lambda item: (
            -best_conf_rank.get(item[0], 0),
            -item[1],
            _LOCAL_AC_DEPT_PRIORITY.index(item[0]),
        ),
    )
    chosen_dept = ranked[0][0]
    strong_admin = any(p.search(normalized) for p in _STRONG_ADMIN_TITLE_PATTERNS)
    return {
        "department": chosen_dept,
        "confidence": _confidence_label(best_conf_rank.get(chosen_dept, 1)),
        "reason": reasons.get(chosen_dept, [""])[0],
        "isStrongAdmin": strong_admin,
    }


def _make_candidate(
    department: str,
    source: str,
    reference_field: str,
    reference_value: str,
    confidence: str,
    reason: str,
    rule_weight: int = 0,
    is_direct: bool = False,
) -> dict:
    """Build a scored candidate record."""
    score = (
        (_CONFIDENCE_RANK.get(confidence, 1) * 1000)
        + _LOCAL_AC_FIELD_WEIGHTS.get(source, 30)
        + rule_weight
        + (80 if is_direct else 0)
    )
    return {
        "department": department,
        "source": source,
        "referenceField": reference_field,
        "referenceValue": reference_value,
        "confidence": confidence,
        "confidenceRank": _CONFIDENCE_RANK.get(confidence, 1),
        "reason": reason,
        "score": score,
        "ambiguousReference": _is_ambiguous_reference_value(reference_value),
    }


def _map_signal_candidates(source: str, raw_value: str) -> list:
    """Map one raw signal to one or more department candidates."""
    candidates = []
    seen = set()
    normalized = _normalize_dept_signal(raw_value)
    if not normalized:
        return candidates

    def add_candidate(
        department: str,
        confidence: str,
        reason: str,
        rule_weight: int = 0,
        is_direct: bool = False,
    ):
        """Append a unique candidate for a signal, skipping ambiguous admin noise."""
        if department == "Administration" and _is_ambiguous_reference_value(raw_value):
            return
        key = (department, source, reason)
        if key in seen:
            return
        seen.add(key)
        candidates.append(
            _make_candidate(
                department=department,
                source=source,
                reference_field=source,
                reference_value=raw_value,
                confidence=confidence,
                reason=reason,
                rule_weight=rule_weight,
                is_direct=is_direct,
            )
        )

    if _is_customer_service_assigned_dept(source, raw_value):
        add_candidate(
            department="Sales",
            confidence="HIGH",
            reason=f"{source}:{raw_value} (customer_service_override)",
            rule_weight=120,
            is_direct=True,
        )

    explicit_canonical = _CANONICAL_BY_SIGNAL.get(normalized)
    if explicit_canonical:
        add_candidate(
            department=explicit_canonical,
            confidence=_confidence_for_source(source, explicit_canonical=True),
            reason=f"{source}:{raw_value} (explicit_canonical)",
            rule_weight=90,
            is_direct=True,
        )

    direct_match = _LOCAL_AC_DIRECT_MAP.get(normalized)
    if direct_match:
        add_candidate(
            department=direct_match,
            confidence=_confidence_for_source(source, explicit_canonical=False),
            reason=f"{source}:{raw_value} (direct)",
            rule_weight=80,
            is_direct=True,
        )

    for department, rule_weight, pattern in _LOCAL_AC_RULES:
        if pattern.search(normalized):
            add_candidate(
                department=department,
                confidence=_confidence_for_source(source, explicit_canonical=False),
                reason=f"{source}:{raw_value}",
                rule_weight=rule_weight,
            )

    return candidates


def _admin_assignment_allowed(signals: list, manager_department: str, title_info: dict) -> bool:
    """Return True when assigning Administration is strongly supported."""
    if normalize_department_name(manager_department) == "Administration":
        return True
    for source, value in signals:
        if source in {"costCenterDescription", "assignedDept", "homeDept"} and _is_explicit_admin_assigned_dept(value):
            return True
    if title_info.get("isStrongAdmin"):
        return True
    return False


def _pick_best_candidate(candidates: list, admin_allowed: bool) -> Optional[dict]:
    """Pick best department candidate using confidence first and score second."""
    if not candidates:
        return None

    by_dept = {}
    for candidate in candidates:
        dept = candidate["department"]
        slot = by_dept.setdefault(
            dept,
            {
                "department": dept,
                "score": 0,
                "bestConfidenceRank": 0,
                "evidence": [],
                "reasons": [],
            },
        )
        slot["score"] += candidate["score"]
        slot["bestConfidenceRank"] = max(slot["bestConfidenceRank"], candidate["confidenceRank"])
        slot["evidence"].append(candidate)
        slot["reasons"].append(candidate["reason"])

    ranked = sorted(
        by_dept.values(),
        key=lambda item: (
            -item["bestConfidenceRank"],
            -(item["score"] - (250 if item["department"] == "Administration" and not admin_allowed else 0)),
            _LOCAL_AC_DEPT_PRIORITY.index(item["department"]),
        ),
    )
    winner = ranked[0]
    primary = sorted(
        winner["evidence"],
        key=lambda item: (-item["confidenceRank"], -item["score"]),
    )[0]
    reason_trace = " | ".join(dict.fromkeys(winner["reasons"]))
    return {
        "department": winner["department"],
        "confidence": _confidence_label(winner["bestConfidenceRank"]),
        "evidenceUsed": primary["source"],
        "referenceField": primary["referenceField"],
        "referenceValue": primary["referenceValue"],
        "primaryReason": primary["reason"],
        "reasonTrace": reason_trace,
        "ambiguousReference": primary["ambiguousReference"],
    }


def _is_low_confidence_candidate(candidate: dict) -> bool:
    """Return True when evidence should not override manager-aligned current dept."""
    if not candidate:
        return True
    if candidate.get("source") in _LOW_CONFIDENCE_FIELDS:
        return True
    if candidate.get("ambiguousReference"):
        return True
    return candidate.get("confidence") == "LOW"


def _fallback_from_context(
    current_department: str,
    manager_department: str,
    title_department: str,
    reason_prefix: str,
) -> dict:
    """Apply the safer fallback chain for ambiguous/admin-gated cases."""
    current_raw = (current_department or "").strip()
    current_norm = normalize_department_name(current_raw)
    manager_norm = normalize_department_name(manager_department)
    title_norm = normalize_department_name(title_department)

    if current_raw:
        return {
            "department": current_norm or current_raw,
            "changeAllowed": False,
            "blockReason": f"{reason_prefix}_keep_current",
        }
    if manager_norm in CANONICAL_DEPTS:
        return {
            "department": manager_norm,
            "changeAllowed": True,
            "blockReason": f"{reason_prefix}_use_manager",
        }
    if title_norm in CANONICAL_DEPTS:
        return {
            "department": title_norm,
            "changeAllowed": True,
            "blockReason": f"{reason_prefix}_use_title",
        }
    return {
        "department": None,
        "changeAllowed": False,
        "blockReason": f"{reason_prefix}_needs_review",
    }


def resolve_local_ac_department(
    emp,
    current_ad_department: str = "",
    manager_department: str = "",
) -> dict:
    """Resolve department with candidate scoring, confidence, and guardrails."""
    signals = _collect_local_ac_department_signals(emp)
    title = extract_business_title(emp) or extract_assignment_field(emp, "jobTitle") or ""
    title_info = infer_department_from_title(title)
    manager_norm = normalize_department_name(manager_department)
    current_norm = normalize_department_name(current_ad_department)

    candidates = []
    for source, raw_value in signals:
        candidates.extend(_map_signal_candidates(source, raw_value))

    legacy_department = extract_department(emp)
    if legacy_department:
        candidates.extend(_map_signal_candidates("department", legacy_department))

    if manager_norm in CANONICAL_DEPTS:
        candidates.append(
            _make_candidate(
                department=manager_norm,
                source="managerDepartment",
                reference_field="managerDepartment",
                reference_value=manager_department,
                confidence="MED",
                reason=f"managerDepartment:{manager_department}",
                rule_weight=40,
                is_direct=True,
            )
        )

    title_department = normalize_department_name(title_info.get("department", ""))
    if title_department in CANONICAL_DEPTS:
        candidates.append(
            _make_candidate(
                department=title_department,
                source="titleInference",
                reference_field="title",
                reference_value=title,
                confidence=title_info.get("confidence") or "LOW",
                reason=title_info.get("reason") or f"title:{title}",
                rule_weight=45,
            )
        )

    admin_allowed = _admin_assignment_allowed(signals, manager_norm, title_info)
    chosen = _pick_best_candidate(candidates, admin_allowed)

    if not chosen:
        fallback = _fallback_from_context(
            current_department=current_ad_department,
            manager_department=manager_department,
            title_department=title_department,
            reason_prefix="no_candidate",
        )
        return {
            "proposedDepartment": fallback["department"],
            "proposedDepartmentV2": fallback["department"],
            "changeAllowed": fallback["changeAllowed"],
            "blockReason": fallback["blockReason"],
            "evidenceUsed": "",
            "confidence": "",
            "titleInferredDept": title_department,
            "departmentChangeReferenceField": "",
            "departmentChangeReferenceValue": "",
            "departmentChangePrimaryReason": "",
            "departmentChangeReasonTrace": "",
        }

    has_conflicting_low_candidate = any(
        normalize_department_name(candidate["department"]) != current_norm
        and _is_low_confidence_candidate(candidate)
        for candidate in candidates
    )
    has_ambiguous_low_signal = any(
        source in _LOW_CONFIDENCE_FIELDS and _is_ambiguous_reference_value(raw_value)
        for source, raw_value in signals
    ) or _is_ambiguous_reference_value(legacy_department)
    if (
        current_norm
        and manager_norm
        and current_norm == manager_norm
        and (has_conflicting_low_candidate or has_ambiguous_low_signal)
    ):
        kept = current_norm or (current_ad_department or "").strip()
        return {
            "proposedDepartment": kept,
            "proposedDepartmentV2": kept,
            "changeAllowed": False,
            "blockReason": "blocked_by_manager_alignment",
            "evidenceUsed": chosen["evidenceUsed"],
            "confidence": chosen["confidence"],
            "titleInferredDept": title_department,
            "departmentChangeReferenceField": chosen["referenceField"],
            "departmentChangeReferenceValue": chosen["referenceValue"],
            "departmentChangePrimaryReason": chosen["primaryReason"],
            "departmentChangeReasonTrace": chosen["reasonTrace"],
        }

    if chosen["department"] == "Administration" and not admin_allowed:
        fallback = _fallback_from_context(
            current_department=current_ad_department,
            manager_department=manager_department,
            title_department=title_department,
            reason_prefix="admin_gated",
        )
        return {
            "proposedDepartment": fallback["department"],
            "proposedDepartmentV2": fallback["department"],
            "changeAllowed": fallback["changeAllowed"],
            "blockReason": fallback["blockReason"],
            "evidenceUsed": chosen["evidenceUsed"],
            "confidence": chosen["confidence"],
            "titleInferredDept": title_department,
            "departmentChangeReferenceField": chosen["referenceField"],
            "departmentChangeReferenceValue": chosen["referenceValue"],
            "departmentChangePrimaryReason": chosen["primaryReason"],
            "departmentChangeReasonTrace": chosen["reasonTrace"],
        }

    if chosen["ambiguousReference"]:
        fallback = _fallback_from_context(
            current_department=current_ad_department,
            manager_department=manager_department,
            title_department=title_department,
            reason_prefix="ambiguous_reference_value",
        )
        return {
            "proposedDepartment": fallback["department"],
            "proposedDepartmentV2": fallback["department"],
            "changeAllowed": fallback["changeAllowed"],
            "blockReason": fallback["blockReason"],
            "evidenceUsed": chosen["evidenceUsed"],
            "confidence": chosen["confidence"],
            "titleInferredDept": title_department,
            "departmentChangeReferenceField": chosen["referenceField"],
            "departmentChangeReferenceValue": chosen["referenceValue"],
            "departmentChangePrimaryReason": chosen["primaryReason"],
            "departmentChangeReasonTrace": chosen["reasonTrace"],
        }

    resolved_department = normalize_department_name(chosen["department"]) or chosen["department"]
    return {
        "proposedDepartment": resolved_department,
        "proposedDepartmentV2": resolved_department,
        "changeAllowed": True,
        "blockReason": "",
        "evidenceUsed": chosen["evidenceUsed"],
        "confidence": chosen["confidence"],
        "titleInferredDept": title_department,
        "departmentChangeReferenceField": chosen["referenceField"],
        "departmentChangeReferenceValue": chosen["referenceValue"],
        "departmentChangePrimaryReason": chosen["primaryReason"],
        "departmentChangeReasonTrace": chosen["reasonTrace"],
    }

def _collect_local_ac_department_signals(emp):
    """Collect candidate department signals across ADP worker fields."""
    signals = []
    seen = set()

    def add(source: str, value: str):
        """Record one non-empty signal while deduplicating repeated values."""
        raw_val = (value or "").strip()
        if not raw_val:
            return
        key = (source, raw_val)
        if key in seen:
            return
        seen.add(key)
        signals.append((source, raw_val))

    wa = emp.get("workAssignments", [])
    if not wa or not isinstance(wa[0], dict):
        return signals

    assignment = wa[0]

    def add_org_units(units, source: str, expected_type: str):
        """Pull organizational-unit names and optional cost-center descriptions."""
        if not isinstance(units, list):
            return
        for ou in units:
            if not isinstance(ou, dict):
                continue
            type_code = ou.get("typeCode", {}).get("codeValue", "").strip().lower()
            if type_code != expected_type:
                continue
            name_code = ou.get("nameCode", {})
            val = ""
            if isinstance(name_code, dict):
                val = (
                    name_code.get("shortName")
                    or name_code.get("longName")
                    or name_code.get("name")
                    or name_code.get("codeValue")
                    or ""
                )
            add(source, val)
            if expected_type == "department":
                cost_center_desc = ""
                if isinstance(name_code, dict):
                    cost_center_desc = (
                        name_code.get("longName")
                        or name_code.get("shortName")
                        or name_code.get("name")
                        or ""
                    )
                add("costCenterDescription", cost_center_desc)

    add_org_units(assignment.get("assignedOrganizationalUnits", []), "assignedDept", "department")
    add_org_units(assignment.get("homeOrganizationalUnits", []), "homeDept", "department")
    add_org_units(assignment.get("assignedOrganizationalUnits", []), "businessUnit", "business unit")
    add_org_units(assignment.get("homeOrganizationalUnits", []), "businessUnit", "business unit")

    occ = assignment.get("occupationalClassifications", [])
    if isinstance(occ, list):
        for item in occ:
            if not isinstance(item, dict):
                continue
            code = item.get("classificationCode", {})
            if not isinstance(code, dict):
                continue
            val = code.get("shortName") or code.get("longName") or code.get("name") or ""
            add("occupationalClassifications", val)

    add("jobTitle", assignment.get("jobTitle", ""))
    add("businessTitle", extract_business_title(emp) or "")

    business_unit = assignment.get("businessUnit", {})
    if isinstance(business_unit, dict):
        add("businessUnit", business_unit.get("name", ""))

    return signals


def map_local_ac_department(
    emp,
    current_ad_department: str = "",
    manager_department: str = "",
) -> str:
    """Backward-compatible department mapper that returns only the chosen department."""
    resolved = resolve_local_ac_department(
        emp,
        current_ad_department=current_ad_department,
        manager_department=manager_department,
    )
    mapped = resolved.get("proposedDepartmentV2")
    if mapped:
        return mapped
    return "Administration"


def extract_work_address_field(emp, field):
    """Return a specific address field from the assigned work location."""
    wa = emp.get("workAssignments", [])
    if wa and isinstance(wa[0], dict):
        addr = {}
        assigned_locations = wa[0].get("assignedWorkLocations")
        if isinstance(assigned_locations, list) and assigned_locations:
            first_location = assigned_locations[0] if isinstance(assigned_locations[0], dict) else {}
            addr = first_location.get("address", {}) if isinstance(first_location, dict) else {}
            val = addr.get(field, "") if isinstance(addr, dict) else ""
            if val:
                return val
        home_location = wa[0].get("homeWorkLocation")
        if isinstance(home_location, dict):
            addr = home_location.get("address", {})
            if isinstance(addr, dict):
                return addr.get(field, "")
    return ""


def extract_state_from_work(emp):
    """Return the state or province code from the work address."""
    wa = emp.get("workAssignments", [])
    if wa and isinstance(wa[0], dict):
        cs = {}
        assigned_locations = wa[0].get("assignedWorkLocations")
        if isinstance(assigned_locations, list) and assigned_locations:
            first_location = assigned_locations[0] if isinstance(assigned_locations[0], dict) else {}
            address = first_location.get("address", {}) if isinstance(first_location, dict) else {}
            cs = address.get("countrySubdivisionLevel1", {}) if isinstance(address, dict) else {}
            val = cs.get("codeValue", "") if isinstance(cs, dict) else ""
            if val:
                return val
        home_location = wa[0].get("homeWorkLocation")
        if isinstance(home_location, dict):
            address = home_location.get("address", {})
            if isinstance(address, dict):
                cs = address.get("countrySubdivisionLevel1", {})
                if isinstance(cs, dict):
                    return cs.get("codeValue", "")
    return ""


def extract_manager_id(emp):
    """Return the ADP associateOID of the employee's manager."""
    wa = emp.get("workAssignments", [])
    if wa and isinstance(wa[0], dict):
        reports_to = wa[0].get("reportsTo", [])
        if isinstance(reports_to, list) and reports_to:
            first_report = reports_to[0] if isinstance(reports_to[0], dict) else {}
            manager_info = first_report.get("workerID", {}) if isinstance(first_report, dict) else {}
            if isinstance(manager_info, dict):
                return manager_info.get("idValue")
    return None


def get_manager_dn(conn, ldap_search_base, manager_id):
    """Lookup a manager's DN in AD by their employeeID."""
    if not manager_id:
        return None
    try:
        found = conn.search(
            ldap_search_base,
            f"(employeeID={manager_id})",
            SUBTREE,
            attributes=["distinguishedName"],
        )
    except Exception as e:
        logging.warning(f"Manager lookup failed for {manager_id}: {e}")
        return None
    if not found:
        return None
    if conn.entries:
        return conn.entries[0].distinguishedName.value
    return None


def get_department_by_dn(conn, dn: str) -> str:
    """Lookup a user's department by distinguishedName."""
    if not dn:
        return ""
    try:
        conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["department"],
        )
        if conn.entries:
            dept = conn.entries[0].department.value if conn.entries[0].department else None
            return (dept or "").strip()
    except Exception:
        return ""
    return ""


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
        response = _request_with_retries(
            "GET",
            url,
            action_label=f"ADP workers fetch (offset={current_offset})",
            headers=headers,
            cert=client_cert,
            verify=verify_arg,
        )
        if not response:
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
        if not isinstance(page_employees, list):
            logging.error(f"Unexpected ADP workers payload type: {type(page_employees).__name__}")
            return None
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


def is_terminated_employee(emp) -> bool:
    """Return True when an employee has a termination date in the past/present."""
    td = get_termination_date(emp)
    if not td:
        return False
    t = parse_datetime(td, "terminationDate")
    if not t:
        return False
    return t <= datetime.now(timezone.utc)


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
    """Build a concise LDAP diagnostics string from connection state."""
    if conn is None:
        return "connection=None"
    parts = []
    result = getattr(conn, "result", None) or {}
    if result:
        code = result.get("result")
        desc = result.get("description")
        msg = result.get("message")
        rtype = result.get("type")
        dn = result.get("dn")
        referrals = result.get("referrals")
        if code is not None or desc:
            parts.append(f"result={code} description={desc}")
        if msg:
            parts.append(f"message={msg}")
        if rtype:
            parts.append(f"type={rtype}")
        if dn:
            parts.append(f"dn={dn}")
        if referrals:
            parts.append(f"referrals={referrals}")
    last_error = getattr(conn, "last_error", None)
    if last_error:
        parts.append(f"last_error={last_error}")
    bound = getattr(conn, "bound", None)
    if bound is not None:
        parts.append(f"bound={bound}")
    closed = getattr(conn, "closed", None)
    if closed is not None:
        parts.append(f"closed={closed}")
    server = getattr(conn, "server", None)
    if server is not None:
        host = getattr(server, "host", None)
        port = getattr(server, "port", None)
        ssl_enabled = getattr(server, "ssl", None)
        parts.append(f"server={host}:{port} ssl={ssl_enabled}")
    return "; ".join(parts) if parts else "no ldap error details"


def _is_bind_lost_result(result: dict) -> bool:
    """Detect AD-style bind-lost result payloads."""
    payload = result or {}
    msg = str(payload.get("message") or "").lower()
    return payload.get("result") == 1 and "successful bind must be completed" in msg


def _safe_unbind(conn, context: str):
    """Unbind LDAP connection without raising; include context on failure."""
    if not conn:
        return
    try:
        conn.unbind()
    except Exception as e:
        logging.warning(f"LDAP unbind failed during {context}: {e}")


def _is_email_identifier_attribute(attr: str) -> bool:
    """Return True when an attribute is an email-routing identifier."""
    return (attr or "").strip().lower() in EMAIL_IDENTIFIER_UPDATE_DENYLIST


def _filter_blocked_update_changes(changes: dict, context: str) -> dict:
    """
    Remove prohibited update operations (email identifiers) from LDAP changes.

    This guardrail enforces that routing identifiers are set only during
    account creation and never touched by update/sync flows.
    """
    filtered = {}
    for attr, ops in (changes or {}).items():
        if _is_email_identifier_attribute(attr):
            logging.warning(
                f"Blocked prohibited update attribute '{attr}' for {context}; "
                "email identifiers are create-time only"
            )
            continue
        filtered[attr] = ops
    return filtered


def _entry_attr_value(entry, attr: str):
    """Safely fetch an LDAP entry attribute value."""
    try:
        if hasattr(entry, attr):
            return getattr(entry, attr).value
        return entry[attr].value
    except Exception:
        return None


def _build_update_attributes(
    emp,
    conn,
    ldap_search_base,
    current_ad_department: str = "",
    manager_department: str = "",
) -> dict:
    """Map ADP worker data to AD attributes used for updates."""
    country_code = extract_work_address_field(emp, "countryCode")
    co_value = None
    if country_code:
        co_value = "United States" if country_code.upper() == "US" else country_code

    desired = {
        "title": extract_business_title(emp) or extract_assignment_field(emp, "jobTitle"),
        "company": extract_company(emp),
        "l": extract_work_address_field(emp, "cityName"),
        "postalCode": extract_work_address_field(emp, "postalCode"),
        "st": extract_state_from_work(emp),
        "streetAddress": extract_work_address_field(emp, "lineOne"),
        "co": co_value,
    }
    if get_hire_date(emp):
        desired["userAccountControl"] = get_user_account_control(emp)
    person = emp.get("person", {}) if isinstance(emp, dict) else {}
    preferred_first, preferred_last = get_preferred_first_last(person)
    if preferred_first and preferred_last:
        desired[ATTR_DISPLAY_NAME] = get_display_name(person)
    manager_dn = get_manager_dn(conn, ldap_search_base, extract_manager_id(emp))
    resolved_manager_department = (manager_department or "").strip()
    if manager_dn:
        desired["manager"] = manager_dn
        manager_dept_from_dn = get_department_by_dn(conn, manager_dn)
        if manager_dept_from_dn:
            resolved_manager_department = manager_dept_from_dn

    resolution = resolve_local_ac_department(
        emp,
        current_ad_department=current_ad_department,
        manager_department=resolved_manager_department,
    )
    resolved_department = resolution.get("proposedDepartmentV2")
    if resolved_department:
        desired["department"] = resolved_department

    if _env_truthy("LOG_DEPARTMENT_MAPPING", False):
        emp_id = extract_employee_id(emp)
        logging.info(
            "Department resolution for %s: proposed=%s, evidence=%s, confidence=%s, block=%s",
            emp_id,
            resolved_department or "<none>",
            resolution.get("evidenceUsed") or "<none>",
            resolution.get("confidence") or "<none>",
            resolution.get("blockReason") or "<none>",
        )
    return desired


def _normalize_department_for_compare(value: str) -> str:
    """
    Normalize department values for comparison only.

    Keeps existing AD values like "Information Technology | <detail>" equivalent
    to "Information Technology" so update diffs do not overwrite the suffix.
    """
    return normalize_department_name(value)


def _diff_update_attributes(entry, desired: dict, context: str = "") -> dict:
    """Compute LDAP modify operations for attributes that differ."""
    changes = {}
    for attr, desired_val in desired.items():
        if _is_email_identifier_attribute(attr):
            logging.warning(
                f"Blocked prohibited desired attribute '{attr}' in diff stage for {context or '<unknown>'}"
            )
            continue
        if desired_val in (None, ""):
            continue
        current = _entry_attr_value(entry, attr)
        if isinstance(desired_val, str):
            current_str = (current or "").strip()
            desired_str = desired_val.strip()
            if attr == "manager":
                if current_str.lower() == desired_str.lower():
                    continue
            elif attr == "department":
                current_cmp = _normalize_department_for_compare(current_str)
                desired_cmp = _normalize_department_for_compare(desired_str)
                if current_cmp.lower() == desired_cmp.lower():
                    continue
            elif current_str == desired_str:
                continue
        else:
            if current == desired_val:
                continue
        changes[attr] = [(MODIFY_REPLACE, [desired_val])]
    return _filter_blocked_update_changes(changes, context or "<unknown>")


def _apply_ldap_modifications(conn, dn: str, changes: dict, conn_factory=None) -> Optional[Connection]:
    """Apply LDAP modifications with basic bind-lost recovery."""
    changes = _filter_blocked_update_changes(changes, dn)
    if not changes:
        return conn
    try:
        if conn.modify(dn, changes):
            return conn
    except Exception as e:
        logging.error(f"Modify raised exception for {dn}: {e}")
        if conn_factory:
            try:
                _safe_unbind(conn, f"modify exception for {dn}")
                conn = conn_factory()
                if conn.modify(dn, changes):
                    return conn
            except Exception as reconnect_error:
                logging.error(f"Reconnect after modify exception failed for {dn}: {reconnect_error}")
        return conn
    result = conn.result or {}
    if _is_bind_lost_result(result):
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
                _safe_unbind(conn, f"modify bind-loss for {dn}")
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
    legal_first, legal_last = get_legal_first_last(person)
    display_name = get_display_name(person)
    if not legal_first or not legal_last:
        logging.error("Skipping user with missing required legal name fields for AD givenName/sn")
        return conn
    if not display_name:
        logging.error("Skipping user with missing display name (preferred and legal both unavailable)")
        return conn
    # CN follows displayName consistently (preferred full name else legal full name).
    full_name = display_name

    emp_id = extract_employee_id(user_data)
    if not emp_id:
        logging.warning(f"Skipping user with missing employee ID: {user_data}")
        return conn
    hire_date = get_hire_date(user_data) or "<no hire date>"

    def find_existing_user_dn(connection, employee_id: str) -> Optional[str]:
        """Return DN for an existing employeeID match, if present."""
        try:
            connection.search(
                ldap_search_base,
                f"(employeeID={employee_id})",
                SUBTREE,
                attributes=["employeeID", "distinguishedName"],
            )
        except Exception as e:
            logging.error(f"Existing-user lookup failed for {employee_id}: {e}")
            return None
        if connection.entries:
            return connection.entries[0].distinguishedName.value
        return None

    existing_dn = find_existing_user_dn(conn, emp_id)
    if existing_dn:
        logging.info(f"User already exists: {emp_id} at {existing_dn}")
        # If user exists, update manager if needed
        manager_id = extract_manager_id(user_data)
        manager_dn = get_manager_dn(conn, ldap_search_base, manager_id)
        if manager_dn:
            conn = _apply_ldap_modifications(
                conn,
                existing_dn,
                {"manager": [(MODIFY_REPLACE, [manager_dn])]},
                conn_factory,
            )
        return conn

    # Build attributes for new user
    base_sam_raw = sanitize_string_for_sam(legal_first[0].lower() + legal_last.lower())
    if not base_sam_raw:
        logging.warning(f"Skipping user with invalid sAMAccountName: {user_data}")
        return conn
    base_alias = sanitize_string_for_sam(legal_first.lower()) + sanitize_string_for_sam(legal_last.lower())
    if not base_alias:
        base_alias = base_sam_raw
    upn_suffix = os.getenv("UPN_SUFFIX", "cfsbrands.com").strip()
    if upn_suffix.startswith("@"):
        upn_suffix = upn_suffix[1:]

    def build_sam(suffix: str) -> str:
        """Build a <=10 char sAMAccountName, preserving collision suffixes."""
        if not suffix:
            return base_sam_raw[:10]
        max_base_len = max(0, 10 - len(suffix))
        return f"{base_sam_raw[:max_base_len]}{suffix}"

    manager_dn = get_manager_dn(conn, ldap_search_base, extract_manager_id(user_data))
    resolved_manager_department = ""
    if manager_dn:
        manager_dept_from_dn = get_department_by_dn(conn, manager_dn)
        if manager_dept_from_dn:
            resolved_manager_department = manager_dept_from_dn

    resolution = resolve_local_ac_department(
        user_data,
        manager_department=resolved_manager_department,
    )
    resolved_department = resolution.get("proposedDepartmentV2")

    if _env_truthy("LOG_DEPARTMENT_MAPPING", False):
        logging.info(
            "Department resolution for %s (create): proposed=%s, evidence=%s, confidence=%s, block=%s",
            emp_id,
            resolved_department or "<none>",
            resolution.get("evidenceUsed") or "<none>",
            resolution.get("confidence") or "<none>",
            resolution.get("blockReason") or "<none>",
        )

    base_attrs = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        ATTR_GIVEN_NAME: legal_first,
        ATTR_SN: legal_last,
        ATTR_EMPLOYEE_ID: emp_id,
        "title": extract_business_title(user_data) or extract_assignment_field(user_data, "jobTitle"),
        "department": resolved_department,
        "l": extract_work_address_field(user_data, "cityName"),
        "postalCode": extract_work_address_field(user_data, "postalCode"),
        "st": extract_state_from_work(user_data),
        "streetAddress": extract_work_address_field(user_data, "lineOne"),
        "co": "United States" if country_code.upper() == "US" else country_code,
        "company": extract_company(user_data),
        "manager": manager_dn,
        "userAccountControl": get_user_account_control(user_data),
    }

    mandatory = {
        "objectClass",
        ATTR_CN,
        ATTR_GIVEN_NAME,
        ATTR_SN,
        ATTR_DISPLAY_NAME,
        ATTR_USER_PRINCIPAL_NAME,
        ATTR_MAIL,
        ATTR_SAM_ACCOUNT_NAME,
        ATTR_EMPLOYEE_ID,
        "userAccountControl",
    }
    def _build_numeric_suffix(index: int) -> str:
        return "" if index == 0 else str(index + 1)

    def _classify_account_id_conflicts(message: str) -> set[str]:
        """Classify which account identifiers collided from LDAP error text."""
        msg_lower = (message or "").lower()
        conflicts = set()
        if "samaccountname" in msg_lower:
            conflicts.add("sam")
        if "userprincipalname" in msg_lower or "mailnickname" in msg_lower or "proxyaddresses" in msg_lower:
            conflicts.add("alias")
        return conflicts

    dn = None
    max_retry_attempts = 50
    retry_count = 0
    cn_index = 0
    sam_index = 0
    alias_index = 0
    while retry_count < max_retry_attempts:
        if hasattr(conn, "bound") and not conn.bound:
            try:
                if not conn.bind():
                    logging.error(f"Bind failed before add attempt: {_format_ldap_error(conn)}")
                    return conn
            except Exception as e:
                logging.error(f"Rebind failed before add attempt: {e}")
                return conn

        cn_suffix = _build_numeric_suffix(cn_index)
        sam_suffix = _build_numeric_suffix(sam_index)
        alias_suffix = _build_numeric_suffix(alias_index)

        cn = full_name if not cn_suffix else f"{full_name} {cn_suffix}"
        sam = build_sam(sam_suffix)
        if not sam:
            logging.warning(f"Skipping user with invalid sAMAccountName: {user_data}")
            return conn
        alias = base_alias if not alias_suffix else f"{base_alias}{alias_suffix}"
        attrs = dict(base_attrs)
        # Email-routing identifiers remain create-time only. Update jobs are
        # blocked from changing these by EMAIL_IDENTIFIER_UPDATE_DENYLIST.
        attrs.update(
            {
                ATTR_CN: cn,
                ATTR_DISPLAY_NAME: cn,
                ATTR_USER_PRINCIPAL_NAME: f"{alias}@{upn_suffix}",
                ATTR_MAIL: f"{alias}@cfsbrands.com",
                ATTR_SAM_ACCOUNT_NAME: sam,
            }
        )
        final_attrs = {k: v for k, v in attrs.items() if v or k in mandatory}
        dn_candidate = f"CN={escape_rdn(cn)},{ldap_create_base}"
        try:
            if conn.add(dn_candidate, attributes=final_attrs):
                dn = dn_candidate
                break
        except Exception as e:
            logging.error(f"Add raised exception for {dn_candidate}: {e}")
            if conn_factory:
                try:
                    _safe_unbind(conn, f"add exception for {dn_candidate}")
                    conn = conn_factory()
                    retry_count += 1
                    continue
                except Exception as reconnect_error:
                    logging.error(f"Reconnect failed after add exception for {dn_candidate}: {reconnect_error}")
            return conn
        result = conn.result or {}
        msg = str(result.get("message") or "")
        if result.get("result") == 68:
            cn_index += 1
            retry_count += 1
            logging.warning(
                f"Add failed for {dn_candidate} (entryAlreadyExists on DN/CN); "
                f"retrying with CN suffix {cn_index + 1}"
            )
            continue
        if result.get("result") == 19:
            conflict_fields = _classify_account_id_conflicts(msg)
            if conflict_fields:
                logging.warning(
                    f"Add failed for {dn_candidate} (constraintViolation on {', '.join(sorted(conflict_fields))}); "
                    "refreshing connection and retrying only conflicting identifiers"
                )
                logging.warning(f"Constraint violation details: {_format_ldap_error(conn)}")
                if conn_factory:
                    try:
                        _safe_unbind(conn, f"account-id constraint for {dn_candidate}")
                        conn = conn_factory()
                        existing_dn = find_existing_user_dn(conn, emp_id)
                        if existing_dn:
                            logging.info(f"User found after reconnect: {emp_id} at {existing_dn}; skipping add")
                            manager_id = extract_manager_id(user_data)
                            manager_dn = get_manager_dn(conn, ldap_search_base, manager_id)
                            if manager_dn:
                                conn.modify(existing_dn, {"manager": [(MODIFY_REPLACE, [manager_dn])]})
                            return conn
                        logging.info(f"Post-reconnect state after account-id constraint: {_format_ldap_error(conn)}")
                    except Exception as e:
                        logging.error(f"Reconnect failed after account-id constraint for {dn_candidate}: {e}")
                        return conn
                if "sam" in conflict_fields:
                    sam_index += 1
                if "alias" in conflict_fields:
                    alias_index += 1
                retry_count += 1
                continue
            logging.error(f"Add failed for {dn_candidate} (constraintViolation): {conn.result}")
            return conn
        if _is_bind_lost_result(result):
            logging.warning(f"Bind lost details: {_format_ldap_error(conn)}")
            if conn_factory:
                logging.warning(f"Add failed for {dn_candidate} (bind lost); reconnecting and skipping current user")
                try:
                    _safe_unbind(conn, f"bind-lost add for {dn_candidate}")
                    conn = conn_factory()
                    existing_dn = find_existing_user_dn(conn, emp_id)
                    if existing_dn:
                        logging.info(f"User found after bind-loss reconnect: {emp_id} at {existing_dn}")
                        manager_id = extract_manager_id(user_data)
                        manager_dn = get_manager_dn(conn, ldap_search_base, manager_id)
                        if manager_dn:
                            conn.modify(existing_dn, {"manager": [(MODIFY_REPLACE, [manager_dn])]})
                    else:
                        logging.error(
                            f"Skipping {emp_id} after bind-lost add; fresh connection ready for next user "
                            f"({_format_ldap_error(conn)})"
                        )
                    return conn
                except Exception as e:
                    logging.error(f"Reconnect failed after bind-lost error for {dn_candidate}: {e}")
                    return conn
            logging.error(f"Add failed for {dn_candidate}: bind lost and no conn_factory available")
            return conn
        logging.error(f"Add failed for {dn_candidate}: {conn.result}")
        return conn
    if not dn:
        logging.error(
            f"Add failed for base CN '{full_name}': exceeded unique add retries "
            f"(cn_index={cn_index}, sam_index={sam_index}, alias_index={alias_index})"
        )
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

# ---- Scheduled new-hire provisioning every 15m ----
@app.schedule(schedule="0 */15 * * * *", arg_name="mytimer", run_on_startup=True)
def scheduled_provision_new_hires(mytimer: func.TimerRequest):
    """Timer-triggered job that provisions recent ADP hires into AD."""
    logging.info("🔄 scheduled_provision_new_hires triggered")
    if mytimer and getattr(mytimer, "past_due", False):
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
    
    hire_lookback_raw = os.getenv("SYNC_HIRE_LOOKBACK_DAYS", "4")
    try:
        hire_lookback_days = max(0, int(hire_lookback_raw))
    except ValueError:
        hire_lookback_days = 4

    today = datetime.now(tz=timezone.utc).date()
    cutoff = today - timedelta(days=hire_lookback_days)
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
    logging.info(
        f"ℹ️  {len(employees_recent)} employees hired since {cutoff.isoformat()} "
        f"(lookback_days={hire_lookback_days})"
    )
    if not employees_recent:
        logging.info("🚫 Nothing to sync; exiting scheduled_provision_new_hires")
        return
    ldap_server = os.getenv("LDAP_SERVER")
    ldap_user = os.getenv("LDAP_USER")
    ldap_password = os.getenv("LDAP_PASSWORD")
    ldap_search_base = os.getenv("LDAP_SEARCH_BASE")
    ldap_create_base = os.getenv("LDAP_CREATE_BASE")
    missing_ldap = _missing_env_vars(
        ["LDAP_SERVER", "LDAP_USER", "LDAP_PASSWORD", "LDAP_SEARCH_BASE", "LDAP_CREATE_BASE"]
    )
    if missing_ldap:
        logging.error(f"Missing LDAP configuration for provisioning: {', '.join(missing_ldap)}")
        return

    ca_bundle = get_ca_bundle()
    logging.info(f"Using CA bundle at '{ca_bundle}' for LDAP")

    if not os.path.isfile(ca_bundle):
        logging.error(f"CA bundle not found at {ca_bundle}")
        return
    _log_ldap_target_details("Provisioning", ldap_server, ca_bundle)

    tls_config = Tls(
        ca_certs_file=ca_bundle,
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLSv1_2,
    )

    server = Server(ldap_server, port=636, use_ssl=True, tls=tls_config, get_info=None)
    try:
        def conn_factory():
            """Create a fresh bound LDAP connection for provisioning retries."""
            connection = Connection(
                server,
                user=ldap_user,
                password=ldap_password,
                authentication=NTLM,
                auto_bind=True,
            )
            logging.info(f"Provisioning LDAP bind established: {_format_ldap_error(connection)}")
            return connection
        conn = conn_factory()
    except Exception as e:
        logging.error(f"❌ Failed to connect to LDAP server: {e}")
        return
    logging.info("🔗 LDAP connection opened")
    try:
        for emp in employees_recent:
            emp_id = extract_employee_id(emp)
            person = emp.get("person", {})
            display_name = get_display_name(person) or "<no display name>"
            legal_first, legal_last = get_legal_first_last(person)
            legal_name = f"{legal_first} {legal_last}".strip() or "<no legal name>"
            logging.info(f"➡️  Processing {emp_id} / display='{display_name}' legal='{legal_name}'")
            try:
                new_conn = provision_user_in_ad(emp, conn, ldap_search_base, ldap_create_base, conn_factory)
                if not new_conn:
                    logging.error("LDAP connection unavailable; aborting scheduled_provision_new_hires")
                    break
                conn = new_conn
            except Exception as e:
                logging.error(f"❌ Exception provisioning {emp_id}: {e}")
    finally:
        _safe_unbind(conn, "scheduled_provision_new_hires completion")
        logging.info("🔒 LDAP connection closed — scheduled_provision_new_hires complete")


# ---- Scheduled existing-user update (dry run by default) ----
@app.schedule(schedule="0 0 * * * *", arg_name="mytimer", run_on_startup=False)
def scheduled_update_existing_users(mytimer: func.TimerRequest):
    """Timer-triggered job that updates existing AD users from ADP."""
    dry_run = _env_truthy("UPDATE_DRY_RUN", True)
    lookback_days_raw = os.getenv("UPDATE_LOOKBACK_DAYS", "7")
    try:
        lookback_days = int(lookback_days_raw)
    except ValueError:
        lookback_days = 7
    include_missing_updates = _env_truthy("UPDATE_INCLUDE_MISSING_LAST_UPDATED", True)
    log_no_changes = _env_truthy("UPDATE_LOG_NO_CHANGES", False)

    logging.info(f"🔁 scheduled_update_existing_users triggered (dry_run={dry_run}, lookback_days={lookback_days})")
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
        logging.info("🚫 Nothing to update; exiting scheduled_update_existing_users")
        return

    ldap_server = os.getenv("LDAP_SERVER")
    ldap_user = os.getenv("LDAP_USER")
    ldap_password = os.getenv("LDAP_PASSWORD")
    ldap_search_base = os.getenv("LDAP_SEARCH_BASE")
    missing_ldap = _missing_env_vars(
        ["LDAP_SERVER", "LDAP_USER", "LDAP_PASSWORD", "LDAP_SEARCH_BASE"]
    )
    if missing_ldap:
        logging.error(f"Missing LDAP configuration for update: {', '.join(missing_ldap)}")
        return

    ca_bundle = get_ca_bundle()
    logging.info(f"Using CA bundle at '{ca_bundle}' for LDAP update")
    if not os.path.isfile(ca_bundle):
        logging.error(f"CA bundle not found at {ca_bundle}")
        return
    _log_ldap_target_details("Update", ldap_server, ca_bundle)

    tls_config = Tls(
        ca_certs_file=ca_bundle,
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLSv1_2,
    )

    server = Server(ldap_server, port=636, use_ssl=True, tls=tls_config, get_info=None)
    try:
        def conn_factory():
            """Create a fresh bound LDAP connection for update retries."""
            connection = Connection(
                server,
                user=ldap_user,
                password=ldap_password,
                authentication=NTLM,
                auto_bind=True,
            )
            logging.info(f"Update LDAP bind established: {_format_ldap_error(connection)}")
            return connection
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
        try:
            found = conn.search(
                ldap_search_base,
                f"(employeeID={emp_id})",
                SUBTREE,
                attributes=AD_UPDATE_SEARCH_ATTRIBUTES,
            )
        except Exception as e:
            logging.error(f"LDAP search exception for {emp_id}: {e}")
            if conn_factory:
                try:
                    _safe_unbind(conn, f"update search exception for {emp_id}")
                    conn = conn_factory()
                except Exception as reconnect_error:
                    logging.error(f"Reconnect failed after search exception for {emp_id}: {reconnect_error}")
            continue
        if not found and _is_bind_lost_result(getattr(conn, "result", None) or {}):
            logging.warning(f"Bind lost during update search for {emp_id}; reconnecting")
            if conn_factory:
                try:
                    _safe_unbind(conn, f"update search bind-loss for {emp_id}")
                    conn = conn_factory()
                except Exception as reconnect_error:
                    logging.error(f"Reconnect failed after bind-loss search for {emp_id}: {reconnect_error}")
                    break
            continue
        if not conn.entries:
            missing_in_ad += 1
            continue
        entry = conn.entries[0]
        dn = _entry_attr_value(entry, "distinguishedName") or "<unknown DN>"
        if is_terminated_employee(emp):
            desired = {"userAccountControl": 514}
        else:
            current_department = (_entry_attr_value(entry, "department") or "").strip()
            current_manager_dn = (_entry_attr_value(entry, "manager") or "").strip()
            current_manager_department = get_department_by_dn(conn, current_manager_dn) if current_manager_dn else ""
            desired = _build_update_attributes(
                emp,
                conn,
                ldap_search_base,
                current_ad_department=current_department,
                manager_department=current_manager_department,
            )
        changes = _diff_update_attributes(entry, desired, context=f"{emp_id} at {dn}")
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
                logging.error("LDAP connection unavailable; aborting scheduled_update_existing_users")
                break

    _safe_unbind(conn, "scheduled_update_existing_users completion")
    logging.info(
        f"🔒 LDAP connection closed — scheduled_update_existing_users complete "
        f"(users_with_changes={updated_users}, total_changes={total_changes}, missing_in_ad={missing_in_ad})"
    )


# ---------------------------
# Simple process endpoint
# ---------------------------
@app.function_name(name="process_request")
@app.route(route="process", methods=["POST"])
def process_request(req: func.HttpRequest) -> func.HttpResponse:
    """HTTP endpoint that returns active users with ADP/HR details."""
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
        try:
            person = emp.get("person", {})
            legal_first, legal_last = get_legal_first_last(person)
            preferred_first, preferred_last = get_preferred_first_last(person)
            display_name = get_display_name(person)
            out.append(
                {
                    "employeeId": extract_employee_id(emp),
                    "givenName": legal_first,
                    "familyName": legal_last,
                    "legalGivenName": legal_first,
                    "legalFamilyName": legal_last,
                    "preferredGivenName": preferred_first,
                    "preferredFamilyName": preferred_last,
                    "displayName": display_name,
                    "jobTitle": extract_business_title(emp) or extract_assignment_field(emp, "jobTitle"),
                    "company": extract_company(emp),
                    "department": extract_department(emp),
                    "hireDate": get_hire_date(emp),
                    "terminationDate": get_termination_date(emp),
                    "workAssignments": emp.get("workAssignments", []),
                }
            )
        except Exception as e:
            # Keep endpoint usable even if one ADP record is malformed.
            logging.warning(f"Skipping malformed process_request worker record: {e}")
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
    if not dept:
        return ""
    return ''.join(c for c in str(dept).lower().strip() if c.isalnum() or c.isspace())


def fetch_ad_data_task() -> Optional[dict]:
    """Fetch all AD users and build a map of employeeID -> department."""
    ldap_server = os.getenv("LDAP_SERVER")
    ldap_user = os.getenv("LDAP_USER")
    ldap_password = os.getenv("LDAP_PASSWORD")
    ldap_search_base = os.getenv("LDAP_SEARCH_BASE")
    missing_ldap = _missing_env_vars(
        ["LDAP_SERVER", "LDAP_USER", "LDAP_PASSWORD", "LDAP_SEARCH_BASE"]
    )
    if missing_ldap:
        logging.error(f"Missing LDAP configuration for export: {', '.join(missing_ldap)}")
        return None

    try:
        ca_bundle = get_ca_bundle()
        logging.info(f"🔐 Using CA bundle for export: {ca_bundle}")
    except Exception as e:
        logging.error(f"❌ Unable to determine CA bundle for export: {e}")
        return None
    if not os.path.isfile(ca_bundle):
        logging.error(f"CA bundle not found for export at {ca_bundle}")
        return None

    tls = Tls(
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLS_CLIENT,
        ca_certs_file=ca_bundle,
    )
    _log_ldap_target_details("Export", ldap_server, ca_bundle)

    server = Server(ldap_server, port=636, use_ssl=True, tls=tls, get_info=None)
    try:
        conn = Connection(
            server,
            user=ldap_user,
            password=ldap_password,
            authentication=NTLM,
            auto_bind=True,
        )
        logging.info(f"🔗 LDAP connection opened for export ({_format_ldap_error(conn)})")
    except Exception as e:
        logging.error(f"Failed to connect to LDAP: {e}")
        return None

    ldap_map: dict[str, str] = {}
    page_size = 500
    cookie = None
    try:
        while True:
            try:
                conn.search(
                    ldap_search_base,
                    "(employeeID=*)",
                    SUBTREE,
                    attributes=["employeeID", "department"],
                    paged_size=page_size,
                    paged_cookie=cookie,
                )
            except Exception as e:
                logging.error(f"LDAP export search failed: {e}")
                return None
            for entry in conn.entries:
                raw_id = entry.employeeID.value
                raw_dept = entry.department.value if entry.department else None
                emp_id = normalize_id(raw_id)
                dept = normalize_dept(raw_dept) if raw_dept else None
                if emp_id and dept:
                    ldap_map[emp_id] = dept

            controls = (conn.result or {}).get("controls", {})
            cookie = (
                controls.get("1.2.840.113556.1.4.319", {})
                .get("value", {})
                .get("cookie")
            )
            if not cookie:
                break
    finally:
        _safe_unbind(conn, "fetch_ad_data_task completion")
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
        try:
            adp_employees = future_adp.result()
            ldap_map = future_ldap.result()
        except Exception as e:
            logging.error(f"Parallel data fetch failed: {e}")
            return func.HttpResponse("Data fetch execution error.", status_code=500)

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
        try:
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
        except Exception as e:
            logging.warning(f"Skipping malformed export worker record: {e}")

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

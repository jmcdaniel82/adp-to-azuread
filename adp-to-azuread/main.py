import os
import json
import logging
import requests
import azure.functions as func
from ldap3 import Server, Connection, ALL, SUBTREE

app = func.FunctionApp()

# Helper Functions
def get_adp_token():
    token_url = os.getenv("ADP_TOKEN_URL")
    client_id = os.getenv("ADP_CLIENT_ID")
    client_secret = os.getenv("ADP_CLIENT_SECRET")
    cert_pem = os.getenv("ADP_CERT_PEM")
    cert_key = os.getenv("ADP_CERT_KEY")

    if not all([token_url, client_id, client_secret, cert_pem, cert_key]):
        logging.error("Missing ADP configuration variables.")
        return None

    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    cert = (cert_pem, cert_key)
    try:
        response = requests.post(token_url, headers=headers, data=payload, cert=cert)
        response.raise_for_status()
        token = response.json().get("access_token")
        return token
    except Exception as e:
        logging.error(f"ADP token retrieval failed: {e}")
        return None

def get_adp_employees(token, employee_id=None):
    employee_url = os.getenv("ADP_EMPLOYEE_URL")
    if not employee_url:
        logging.error("ADP_EMPLOYEE_URL not set!")
        return None

    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(employee_url, headers=headers)
    if response.ok:
        employees = response.json().get('workers', [])
        if employee_id:
            return [emp for emp in employees if emp.get('employeeId') == employee_id]
        return employees
    logging.error(f"Error retrieving employees: {response.text}")
    return None

# Azure Functions
@app.function_name(name="process_request")
@app.route(route="process", methods=["GET"])
def process_request(req: func.HttpRequest) -> func.HttpResponse:
    employee_id = req.params.get('employeeId')
    token = get_adp_token()
    if not token:
        return func.HttpResponse("Failed to retrieve ADP token", status_code=500)

    employees = get_adp_employees(token, employee_id)
    if employees is None or (employee_id and not employees):
        return func.HttpResponse(f"No employee found with ID {employee_id}", status_code=404)

    return func.HttpResponse(json.dumps(employees), mimetype="application/json", status_code=200)

@app.function_name(name="local_user_creation")
@app.route(route="create-local-user", methods=["POST"])
def local_user_creation(req: func.HttpRequest) -> func.HttpResponse:
    user_data = req.get_json()

    ldap_server = os.getenv("LDAP_SERVER")
    ldap_user = os.getenv("LDAP_USER")
    ldap_password = os.getenv("LDAP_PASSWORD")
    ldap_base = "ou=US.Employees,us=corp,dc=corp,dc=corp"

    if not all([ldap_server, ldap_user, ldap_password]):
        logging.error("Missing LDAP configurations.")
        return func.HttpResponse("LDAP config error", status_code=500)

    server = Server(ldap_server, get_info=ALL)
    conn = Connection(server, ldap_user, ldap_password, auto_bind=True)

    first = user_data["firstName"].strip()
    last = user_data.get("lastName", "").strip()
    display_name = f"{first} {last}"

    sam_account_name = (first[0] + last).lower()[:10]

    attributes = {
        "objectClass": ["top", "person", "organizationalPerson", "user"],
        "cn": displayName,
        "givenName": first,
        "sn": last,
        "displayName": displayName,
        "userPrincipalName": f"{first.lower()}.{last.lower()}@corp.cfsbrands.com",
        "mail": f"{first.lower()}.{last.lower()}@cfsbrands.com",
        "sAMAccountName": sAMAccountName,
        "employeeID": user_data["employeeId"],
        "title": user_data.get("title", ""),
        "department": user_data.get("department", ""),
        "l": user_data.get("L", ""),
        "postalCode": user_data.get("postalCode", ""),
        "st": user_data.get("st", ""),
        "streetAddress": user_data.get("streetAddress", ""),
        "co": user_data.get("co", ""),
        "company": user_data.get("company", ""),
        "mail": f"{first.lower()}.{last.lower()}@cfsbrands.com",
        "accountDisabled": False if user_data.get("status", "").lower() == "active" else True,
        "employeeID": user_data["employeeId"]
    }

    # sAMAccountName logic
    if len(last) > 9:
        samAccountName = (first[0] + last[:9]).lower()
    else:
        samAccountName = (first[0] + last).lower()
    attributes["sAMAccountName"] = samAccountName

    # Lookup manager
    manager_name = user_data.get("manager")
    if manager_name:
        conn.search(ldap_search_base, f"(cn={manager_name})", SUBTREE, attributes=["cn"])
        if conn.entries:
            attributes["manager"] = conn.entries[0].entry_dn
        else:
            logging.warning(f"Manager {manager_name} not found.")

    try:
        dn = f"CN={displayName},{ldap_search_base}"
        conn.add(dn, attributes=attributes)
        if conn.result["description"] == "success":
            logging.info(f"User created: {dn}")
            return func.HttpResponse(f"User created with DN: {dn}", status_code=201)
        else:
            logging.error(f"Failed LDAP operation: {conn.result}")
            return func.HttpResponse(f"AD creation error: {conn.result['message']}", status_code=500)
    except Exception as e:
        logging.error(f"LDAP provisioning error: {e}")
        return func.HttpResponse(f"Error provisioning user: {e}", status_code=500)

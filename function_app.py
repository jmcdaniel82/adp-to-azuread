import os
import logging
import requests
import azure.functions as func
from msal import ConfidentialClientApplication
from ldap3 import Server, Connection, ALL

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load configuration from environment variables
ADP_TOKEN_URL       = os.getenv("ADP_TOKEN_URL")            # e.g., "https://accounts.adp.com/auth/oauth/v2/token"
ADP_CERT_PEM        = os.getenv("ADP_CERT_PEM")             # Path to your PEM certificate file
ADP_CERT_KEY        = os.getenv("ADP_CERT_KEY")             # Path to your private key file
ADP_CLIENT_ID       = os.getenv("ADP_CLIENT_ID")
ADP_CLIENT_SECRET   = os.getenv("ADP_CLIENT_SECRET")
ADP_EMPLOYEE_URL    = os.getenv("ADP_EMPLOYEE_URL")         # e.g., "https://api.adp.com/hr/v2/workers"

GRAPH_BULK_UPLOAD_URL      = os.getenv("GRAPH_BULK_UPLOAD_URL")
GRAPH_SERVICE_PRINCIPAL_ID = os.getenv("GRAPH_SERVICE_PRINCIPAL_ID")
GRAPH_JOB_ID               = os.getenv("GRAPH_JOB_ID")
GRAPH_CLIENT_ID            = os.getenv("GRAPH_CLIENT_ID")
GRAPH_TENANT_ID            = os.getenv("GRAPH_TENANT_ID")
GRAPH_CLIENT_SECRET        = os.getenv("GRAPH_CLIENT_SECRET")

LDAP_SERVER       = os.getenv("LDAP_SERVER")
LDAP_USER         = os.getenv("LDAP_USER")
LDAP_PASSWORD     = os.getenv("LDAP_PASSWORD")
LDAP_SEARCH_BASE  = os.getenv("LDAP_SEARCH_BASE")

# Create the Azure Functions app instance
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.function_name(name="test_adp_function")
@app.route(route="test-adp", auth_level=func.AuthLevel.ANONYMOUS)
def test_adp_function(req: func.HttpRequest) -> func.HttpResponse:
    """Test endpoint to verify ADP API connectivity."""
    logging.info("Testing ADP API Connection...")
    try:
        employees = get_adp_employees()
        if not employees:
            return func.HttpResponse("Failed to fetch data from ADP.", status_code=500)
        return func.HttpResponse(str(employees), mimetype="application/json", status_code=200)
    except Exception as e:
        logging.error(f"Error in test_adp_function: {str(e)}")
        return func.HttpResponse(f"Error: {str(e)}", status_code=500)

@app.function_name(name="process_request")
@app.route(route="process", auth_level=func.AuthLevel.ANONYMOUS)
def process_request_function(req: func.HttpRequest) -> func.HttpResponse:
    """Process the request for ADP → Microsoft Entra Provisioning."""
    logging.info("Processing request for ADP → Microsoft Entra Provisioning")
    employees = get_adp_employees()
    if not employees:
        return func.HttpResponse("Error fetching employee data.", status_code=500)

    bulk_payload = generate_bulk_upload_payload(employees)
    if not bulk_payload["values"]:
        return func.HttpResponse("No valid employees to provision.", status_code=200)

    token = get_graph_token()
    if not token:
        return func.HttpResponse("Failed to get Graph API token.", status_code=500)

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    graph_url = GRAPH_BULK_UPLOAD_URL.format(
        servicePrincipalId=GRAPH_SERVICE_PRINCIPAL_ID,
        jobId=GRAPH_JOB_ID
    )
    try:
        response = requests.post(graph_url, headers=headers, json=bulk_payload)
        response.raise_for_status()
        return func.HttpResponse("User provisioning successful.", status_code=200)
    except requests.exceptions.RequestException as e:
        logging.error(f"Graph API Bulk Upload failed: {str(e)}")
        return func.HttpResponse("Provisioning failed.", status_code=500)

def get_adp_token():
    """Retrieve an OAuth token from ADP using mutual TLS and client credentials."""
    if not (ADP_TOKEN_URL and ADP_CERT_PEM and ADP_CERT_KEY and ADP_CLIENT_ID and ADP_CLIENT_SECRET):
        logging.error("One or more ADP configuration values are not set!")
        return None

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = f"grant_type=client_credentials&client_id={ADP_CLIENT_ID}&client_secret={ADP_CLIENT_SECRET}"
    try:
        # Pass the certificate and key as a tuple to enable mutual TLS authentication
        cert_tuple = (ADP_CERT_PEM, ADP_CERT_KEY)
        response = requests.post(ADP_TOKEN_URL, headers=headers, data=data, cert=cert_tuple)
        response.raise_for_status()
        logging.info("Successfully retrieved ADP token.")
        return response.json().get("access_token")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to get ADP token: {str(e)}")
        return None

def get_adp_employees():
    """Fetch employee data from the ADP API."""
    token = get_adp_token()
    if not token:
        return None

    headers = {
        "Accept": "application/json;masked=false",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    try:
        response = requests.get(ADP_EMPLOYEE_URL, headers=headers)
        response.raise_for_status()
        logging.info("Successfully retrieved employee data from ADP.")
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch employees from ADP: {str(e)}")
        return None

def get_graph_token():
    """Authenticate with Microsoft Graph API using client credentials."""
    app_conf = ConfidentialClientApplication(
        GRAPH_CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{GRAPH_TENANT_ID}",
        client_credential=GRAPH_CLIENT_SECRET
    )
    result = app_conf.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" in result:
        logging.info("Successfully retrieved Graph token.")
        return result["access_token"]
    logging.error(f"Failed to get Graph API token: {result.get('error_description')}")
    return None

def get_unique_email(first_name, last_name, domain):
    """Generate a unique email address by checking against LDAP."""
    base_email = f"{first_name.lower()}{last_name.lower()}"
    email = f"{base_email}@{domain}"
    try:
        server = Server(LDAP_SERVER, get_info=ALL)
        conn = Connection(server, LDAP_USER, LDAP_PASSWORD)
        conn.start_tls()  # Start TLS before binding
        if not conn.bind():
            logging.error("LDAP bind failed")
            return f"{base_email}@{domain}"
        counter = 1
        while True:
            conn.search(LDAP_SEARCH_BASE, f"(mail={email})", attributes=["mail"])
            if not conn.entries:
                break  # Found a unique email
            email = f"{base_email}{counter}@{domain}"
            counter += 1
        return email
    except Exception as e:
        logging.error(f"LDAP email lookup failed: {str(e)}")
        return f"{base_email}@{domain}"

def generate_bulk_upload_payload(employees):
    """Format employee data from ADP for Microsoft Entra ID (Azure AD) bulk upload."""
    if not employees or "workers" not in employees:
        logging.warning("No valid employee data received.")
        return {"values": []}
    bulk_data = []
    for emp in employees["workers"]:
        try:
            first_name = emp["legalFirstName"]
            last_name = emp["legalLastName"]
            employee_id = emp["workerID"]["idValue"]
            email = get_unique_email(first_name, last_name, "cfsbrands.com")
            bulk_data.append({
                "id": employee_id,
                "action": "Create",
                "data": {
                    "externalId": employee_id,
                    "displayName": f"{first_name} {last_name}",
                    "givenName": first_name,
                    "sn": last_name,
                    "mail": email,
                    "sAMAccountName": f"{first_name.lower()}{last_name.lower()}",
                    "userPrincipalName": email,
                    "title": emp.get("businessTitle", "Employee")
                }
            })
        except KeyError as e:
            logging.error(f"Error processing employee record: {str(e)}")
    return {"values": bulk_data}

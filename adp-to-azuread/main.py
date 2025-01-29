import os
import json
import requests
import logging
import azure.functions as func
from msal import ConfidentialClientApplication
from azure.identity import DefaultAzureCredential
from ldap3 import Server, Connection, ALL, SUBTREE

# Load Credentials from Azure Key Vault / Environment Variables
ADP_CLIENT_ID = os.getenv("ADP_CLIENT_ID")
ADP_CLIENT_SECRET = os.getenv("ADP_CLIENT_SECRET")
GRAPH_TENANT_ID = os.getenv("GRAPH_TENANT_ID")
GRAPH_CLIENT_ID = os.getenv("GRAPH_CLIENT_ID")
GRAPH_CLIENT_SECRET = os.getenv("GRAPH_CLIENT_SECRET")
LDAP_SERVER = os.getenv("LDAP_SERVER")  # e.g., "ldap://OKCTP-DC01.corp.cfsbrands.com"
LDAP_USER = os.getenv("LDAP_USER")  # e.g., "LDAPS@corp.cfsbrands.com"
LDAP_PASSWORD = os.getenv("LDAP_PASSWORD")  # Securely stored in Key Vault
LDAP_SEARCH_BASE = os.getenv("LDAP_SEARCH_BASE")  # e.g., "dc=corp,dc=cfsbrands,dc=com"

# API URLs
ADP_TOKEN_URL = "https://api.adp.com/auth/oauth/v2/token"
ADP_EMPLOYEE_URL = "https://api.adp.com/hr/v2/workers"
GRAPH_BULK_UPLOAD_URL = "https://graph.microsoft.com/v1.0/servicePrincipals/{servicePrincipalId}/synchronization/jobs/{jobId}/bulkUpload"

# Authenticate with ADP API
def get_adp_token():
    """Retrieve OAuth token from ADP API"""
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {os.getenv('ADP_AUTH_BASE64')}"
    }
    data = {"grant_type": "client_credentials"}

    try:
        response = requests.post(ADP_TOKEN_URL, headers=headers, data=data)
        response.raise_for_status()
        return response.json().get("access_token")
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to get ADP token: {str(e)}")
        return None

# Retrieve employees from ADP
def get_adp_employees():
    """Fetch employee data from ADP API"""
    token = get_adp_token()
    if not token:
        return None

    headers = {"Authorization": f"Bearer {token}"}

    try:
        response = requests.get(ADP_EMPLOYEE_URL, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch employees from ADP: {str(e)}")
        return None

# Generate unique email by checking LDAP (Active Directory)
def get_unique_email(first_name, last_name, domain):
    """Generate a unique email by checking if it already exists in AD"""
    base_email = f"{first_name.lower()}{last_name.lower()}"
    email = f"{base_email}@{domain}"

    try:
        # Connect to LDAP
        server = Server(LDAP_SERVER, get_info=ALL)
        conn = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True)
        conn.start_tls()  # Secure connection

        counter = 1
        while True:
            conn.search(LDAP_SEARCH_BASE, f"(mail={email})", attributes=["mail"])
            if not conn.entries:
                break  # Email is unique, stop loop

            # If email is taken, append a number
            email = f"{base_email}{counter}@{domain}"
            counter += 1

        return email
    except Exception as e:
        logging.error(f"LDAP email lookup failed: {str(e)}")
        return f"{base_email}@{domain}"  # Fallback email

# Get Microsoft Graph Token
def get_graph_token():
    """Authenticate with Microsoft Graph API"""
    app = ConfidentialClientApplication(
        GRAPH_CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{GRAPH_TENANT_ID}",
        client_credential=GRAPH_CLIENT_SECRET
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    
    if "access_token" in result:
        return result["access_token"]
    else:
        logging.error(f"Failed to get Graph API token: {result.get('error_description')}")
        return None

# Format data for Microsoft Entra API
def generate_bulk_upload_payload(employees):
    """Format user data from ADP for Microsoft Entra API"""
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
                    "title": emp.get("businessTitle", "Employee")  # Default title
                }
            })
        except KeyError as e:
            logging.error(f"Error processing employee record: {str(e)}")

    return {"values": bulk_data}

# Azure Function Trigger
def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function Entry Point"""
    logging.info("Starting Azure Function for ADP → Microsoft Entra Provisioning")

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
    service_principal_id = os.getenv("GRAPH_SERVICE_PRINCIPAL_ID")  # Ensure you store this
    job_id = os.getenv("GRAPH_JOB_ID")  # Ensure this is correct

    graph_url = GRAPH_BULK_UPLOAD_URL.format(servicePrincipalId=service_principal_id, jobId=job_id)

    try:
        response = requests.post(graph_url, headers=headers, json=bulk_payload)
        response.raise_for_status()
        return func.HttpResponse("User provisioning successful.", status_code=200)
    except requests.exceptions.RequestException as e:
        logging.error(f"Graph API Bulk Upload failed: {str(e)}")
        return func.HttpResponse("Provisioning failed.", status_code=500)

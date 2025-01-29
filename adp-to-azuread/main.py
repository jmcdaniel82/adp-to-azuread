import os
import json
import requests
import logging
import azure.functions as func
from msal import ConfidentialClientApplication
from azure.identity import DefaultAzureCredential
from ldap3 import Server, Connection, ALL

# Load Credentials from Key Vault
ADP_CLIENT_ID = os.getenv("ADP_CLIENT_ID")
ADP_CLIENT_SECRET = os.getenv("ADP_CLIENT_SECRET")
GRAPH_TENANT_ID = os.getenv("GRAPH_TENANT_ID")
GRAPH_CLIENT_ID = os.getenv("GRAPH_CLIENT_ID")
GRAPH_CLIENT_SECRET = os.getenv("GRAPH_CLIENT_SECRET")

# API URLs
ADP_TOKEN_URL = "https://api.adp.com/auth/oauth/v2/token"
ADP_EMPLOYEE_URL = "https://api.adp.com/hr/v2/workers"
GRAPH_BULK_UPLOAD_URL = "https://graph.microsoft.com/v1.0/servicePrincipals/{servicePrincipalId}/synchronization/jobs/{jobId}/bulkUpload"

# Authenticate with ADP API
def get_adp_token():
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {os.getenv('ADP_AUTH_BASE64')}"
    }
    data = {"grant_type": "client_credentials"}

    response = requests.post(ADP_TOKEN_URL, headers=headers, data=data)
    response.raise_for_status()
    
    return response.json().get("access_token")

# Retrieve employees from ADP
def get_adp_employees():
    token = get_adp_token()
    headers = {"Authorization": f"Bearer {token}"}

    response = requests.get(ADP_EMPLOYEE_URL, headers=headers)
    response.raise_for_status()
    
    return response.json()

# Generate unique email by checking AD
def get_unique_email(first_name, last_name, domain):
    base_email = f"{first_name}{last_name}".lower()
    email = f"{base_email}@{domain}"

    server = Server("ldap://your-ad-server.com", get_info=ALL)
    conn = Connection(server, "ldap_user", "ldap_password", auto_bind=True)

    counter = 1
    while True:
        conn.search("DC=yourdomain,DC=com", f"(mail={email})", attributes=["mail"])
        if not conn.entries:
            break
        email = f"{base_email}{counter}@{domain}"
        counter += 1

    return email

# Get Microsoft Graph Token
def get_graph_token():
    app = ConfidentialClientApplication(
        GRAPH_CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{GRAPH_TENANT_ID}",
        client_credential=GRAPH_CLIENT_SECRET
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    return result.get("access_token")

# Format data for Microsoft Entra API
def generate_bulk_upload_payload(employees):
    bulk_data = []
    for emp in employees["workers"]:
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
                "title": emp["businessTitle"]
            }
        })
    
    return {"values": bulk_data}

# Azure Function Trigger
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Starting Azure Function for ADP → Microsoft Entra Provisioning")

    employees = get_adp_employees()
    if not employees["workers"]:
        return func.HttpResponse("No new employees found.", status_code=200)

    bulk_payload = generate_bulk_upload_payload(employees)
    
    token = get_graph_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    response = requests.post(GRAPH_BULK_UPLOAD_URL, headers=headers, json=bulk_payload)

    if response.status_code == 201:
        return func.HttpResponse("User provisioning successful.", status_code=200)
    else:
        return func.HttpResponse("Provisioning failed.", status_code=500)

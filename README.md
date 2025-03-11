ADP to Azure Active Directory (Local AD via LDAP) Synchronization

Overview

This application automates the provisioning of new employees from ADP Workforce Now (WFN) into your local Active Directory using LDAP (Local Administrator Password Solution - LAPS). It ensures that new employee accounts are created automatically based on real-time HR data from ADP.

Functionality

Retrieves employee data securely from ADP WFN using Mutual TLS.

Filters and identifies new employees hired today.

Creates and provisions new users into your local Active Directory.

ADP Fields Synchronized

employeeId

cn (Common Name)

accountDisabled (based on ADP status)

sAMAccountName (First initial + Last name, max 10 chars)

co (Country)

company

department

displayName

givenName

l (Locality/City)

mail (Email)

manager (DN from LDAP)

postalCode

sn (Surname)

st (State)

streetAddress

title

userPrincipalName (same as mail)

Configuration (Environment Variables)

Set these environment variables in Azure:

ADP API

ADP_TOKEN_URL

ADP_EMPLOYEE_URL

ADP_CLIENT_ID

ADP_CLIENT_SECRET

ADP_CERT_PEM

ADP_CERT_KEY

LDAP (Local AD)

LDAP_SERVER

LDAP_USER

LDAP_PASSWORD

LDAP_SEARCH_BASE

Azure Function Endpoints

Scheduled Sync

Runs automatically to provision users who have a hire date matching today's date.

Manual Testing

Process Request:GET http://localhost:7071/api/process?employeeId=<EMPLOYEE_ID>

Create Local User (Manual)

Provision a local AD user manually for testing:

POST to /api/create-local-user with JSON payload:

{
  "employeeId": "1274578890",
  "firstName": "Johnny",
  "lastName": "Doeray",
  "co": "USA",
  "company": "CFS Brands",
  "department": "Sales",
  "L": "New York",
  "postalCode": "10001",
  "st": "NY",
  "streetAddress": "123 5th Avenue",
  "title": "Sales Manager",
  "manager": "Jane Smith",
  "status": "Active"
}

Troubleshooting

Verify certificates (.pem and .key) are correctly uploaded and paths specified accurately.

Ensure manager lookup base (LDAP_SEARCH_BASE) encompasses all possible sub-OUs.

Check logs in Azure Functions for detailed error messages.

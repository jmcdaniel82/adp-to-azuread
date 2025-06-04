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

LDAP_CREATE_BASE

CA_BUNDLE_PATH

Azure Function Endpoints

Scheduled Sync

Runs automatically to provision users who have a hire date matching today's date.

Troubleshooting

Verify certificates (.pem and .key) are correctly uploaded and paths specified accurately.

Ensure manager lookup base (LDAP_SEARCH_BASE) encompasses all possible sub-OUs.

Check logs in Azure Functions for detailed error messages.

Installation
------------

1. Install Python 3.10+ and [Azure Functions Core Tools](https://learn.microsoft.com/azure/azure-functions/functions-run-local).
2. Create a virtual environment and install dependencies:

   ```bash
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

Configuration
-------------

Set the environment variables listed above either in Azure or in a local `.env` file when running locally. At minimum `ADP_*` variables for the ADP API and `LDAP_*` variables for your directory must be supplied.

Running Locally
---------------

With the environment configured, start the function host:

```bash
func start
```

Deployment
----------

Deploy the function app using the Azure CLI or Azure Functions Core Tools:

```bash
func azure functionapp publish <APP_NAME>
```

This repository also includes a GitHub Actions workflow that builds and deploys the Function App on pushes to the `main` branch.

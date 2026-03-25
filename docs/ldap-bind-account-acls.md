# LDAP Bind Account ACLs

## Scope

This checklist documents the minimum Active Directory rights the ADP sync bind
account should have for the staging write target:

- staging write OU: `OU=US-Staging,OU=US.Employees,DC=US,DC=corp,DC=cfsbrands,DC=com`
- broader read/search base: `DC=US,DC=corp,DC=cfsbrands,DC=com`

The application now also enforces the same write boundary in code through
`LDAP_ALLOWED_WRITE_BASES`, but that is not a substitute for directory ACLs.

## Required Rights

### Read Rights

Grant read access across the configured search base so the app can:

- find existing users by `employeeID`
- resolve manager DNs by `employeeID`
- read manager departments
- inspect naming collisions for `cn`, `displayName`, `mail`, `userPrincipalName`, and `sAMAccountName`

At minimum, the account needs read access to these attributes on relevant user
objects:

- `distinguishedName`
- `employeeID`
- `department`
- `manager`
- `displayName`
- `cn`
- `mail`
- `userPrincipalName`
- `sAMAccountName`
- `title`
- `company`
- `l`
- `st`
- `postalCode`
- `streetAddress`
- `co`
- `c`
- `countryCode`
- `userAccountControl`

If your domain already grants standard authenticated-user read access, do not
add broader read ACLs unless your AD team has removed those defaults.

### Create Rights On The Staging OU

Grant the bind account the right to:

- create child `user` objects under
  `OU=US-Staging,OU=US.Employees,DC=US,DC=corp,DC=cfsbrands,DC=com`

Do not grant:

- delete child objects
- move-tree rights
- rename rights outside the staging OU
- broad write rights on parent OUs or the domain root

### Write Rights On Descendant User Objects In The Staging OU

Grant write-property rights on descendant `user` objects in the staging OU for:

- `givenName`
- `sn`
- `displayName`
- `employeeID`
- `title`
- `department`
- `l`
- `postalCode`
- `st`
- `streetAddress`
- `co`
- `c`
- `countryCode`
- `company`
- `manager`
- `userAccountControl`
- `sAMAccountName`
- `userPrincipalName`
- `mail`
- `cn`
- `pwdLastSet`

Notes:

- `mail`, `userPrincipalName`, and `sAMAccountName` are create-time identifiers.
  The update flow will not modify them after creation, but the create path must
  still be able to set them on the new object.
- The current code does not require post-create write access to
  `proxyAddresses`, `mailNickname`, `targetAddress`, or related routing
  aliases.

### Extended Rights

Grant the bind account this extended right on descendant `user` objects in the
staging OU:

- `Reset Password`

This is required because provisioning creates the object first and then performs
password set and enablement as a second step.

## Recommended Delegation Model

Use a service account dedicated to this app and scope it like this:

1. Read/search at `DC=US,DC=corp,DC=cfsbrands,DC=com`
2. Create child `user` objects only at `OU=US-Staging,OU=US.Employees,...`
3. Write only the listed attributes on descendant `user` objects in that OU
4. Grant `Reset Password` only on descendant `user` objects in that OU
5. Do not grant delete, disable inheritance globally, or broad Account Operators style rights

## Admin Checklist

1. Confirm the bind account is a dedicated service account and not a human admin account.
2. Confirm `LDAP_CREATE_BASE` is set to `OU=US-Staging,OU=US.Employees,DC=US,DC=corp,DC=cfsbrands,DC=com`.
3. Confirm `LDAP_ALLOWED_WRITE_BASES` matches that same OU in Azure App Settings.
4. Delegate domain read/search only as needed for manager lookup and collision inspection.
5. Delegate `Create user objects` on the staging OU only.
6. Delegate write-property rights only for the attribute list in this document.
7. Delegate `Reset Password` on descendant user objects in the staging OU.
8. Do not grant delete, move, or write rights outside the staging OU.
9. Validate with a non-production provisioning test that creates a user in the staging OU.
10. Validate with a non-production update test that changes one allowed attribute, such as `department` or `title`.
11. Confirm an out-of-scope modify attempt is blocked by both AD ACLs and the app-side `LDAP_ALLOWED_WRITE_BASES` guard.
12. Document the owning AD team and the change ticket that applied the delegation.

## Verification Targets

After ACLs are applied, the following behaviors should succeed:

- create a new staging user
- set the initial password
- set `pwdLastSet=0`
- set `userAccountControl=512`
- update allowed mutable attributes on existing staging users

The following behaviors should fail:

- modify a user outside `OU=US-Staging,OU=US.Employees,...`
- delete or move users
- update create-time routing identifiers in the hourly update flow

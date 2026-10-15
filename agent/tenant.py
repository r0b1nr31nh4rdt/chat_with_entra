# tenant.py
# Zentrale Graph-Abfragen – genutzt von fetch_tenant.py (Snapshot) und tools/graph.py (live)

from graph_client import graph_get

# Pfad oder (Pfad, API-Version) – Standard ist v1.0
QUERIES = {
    "users": "/users?$select=id,displayName,userPrincipalName,userType,accountEnabled",
    "role_definitions": "/roleManagement/directory/roleDefinitions?$select=id,displayName,description,isBuiltIn,isEnabled,templateId,rolePermissions",
    "role_assignments": "/roleManagement/directory/roleAssignments?$expand=principal",
    "ca_policies": "/identity/conditionalAccess/policies",
    "mfa_registration": "/reports/authenticationMethods/userRegistrationDetails",
    "security_defaults": "/policies/identitySecurityDefaultsEnforcementPolicy",
    # isPrivileged = Microsofts eigene Einstufung privilegierter Rollen, gibt es nur in beta
    "privileged_roles": ("/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId&$filter=isPrivileged eq true", "beta"),
    "authorization_policy": "/policies/authorizationPolicy",
    "domains": "/domains?$select=id,isVerified,authenticationType,passwordValidityPeriodInDays",
    # signInActivity braucht AuditLog.Read.All + Entra ID P1
    "sign_in_activity": "/users?$select=id,userPrincipalName,signInActivity",
    "applications": "/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials",
    # braucht RoleEligibilitySchedule.Read.Directory (+ Entra ID P2 für PIM)
    "role_eligibility": "/roleManagement/directory/roleEligibilitySchedules",
}

# Graph ignoriert $select innerhalb von $expand=principal und liefert das komplette
# Objekt (60+ Felder) → lokal auf das Nötige kürzen
PRINCIPAL_FIELDS = ("@odata.type", "id", "displayName", "userPrincipalName", "userType", "accountEnabled", "onPremisesSyncEnabled")


GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"  # appId von Microsoft Graph (in jedem Tenant gleich)


def fetch_graph_app_permissions():
    """Alle Application-Permissions auf Microsoft Graph, mit Klarnamen.

    Graph-SP finden → appRoleAssignedTo (wer hat welche Rolle auf Graph)
    → appRoleId über die appRoles des Graph-SPs in Namen wie Directory.ReadWrite.All übersetzen.
    """
    sp = graph_get(f"/servicePrincipals?$filter=appId eq '{GRAPH_APP_ID}'&$select=id,appRoles")[0]
    names = {r["id"]: r["value"] for r in sp["appRoles"]}
    return [
        {
            "principalId": a["principalId"],
            "principalDisplayName": a["principalDisplayName"],
            "principalType": a["principalType"],
            "permission": names.get(a["appRoleId"], a["appRoleId"]),
        }
        for a in graph_get(f"/servicePrincipals/{sp['id']}/appRoleAssignedTo")
    ]


def fetch_service_principal_id(app_id):
    """Objekt-ID des Service Principals zu einer appId (z. B. der eigenen Audit-App)."""
    sps = graph_get(f"/servicePrincipals?$filter=appId eq '{app_id}'&$select=id")
    return sps[0]["id"] if sps else None


def fetch_service_principal_owners(sp_id):
    """Owner eines Service Principals (Benutzer oder andere SPs)."""
    owners = graph_get(f"/servicePrincipals/{sp_id}/owners?$select=id,displayName,userPrincipalName")
    return [{k: v for k, v in o.items() if k in PRINCIPAL_FIELDS} for o in owners]


def fetch(name):
    """Holt einen Datensatz live von Graph."""
    query = QUERIES[name]
    path, version = query if isinstance(query, tuple) else (query, "v1.0")
    data = graph_get(path, version)
    if name == "role_assignments":
        for a in data:
            a["principal"] = {k: v for k, v in a.get("principal", {}).items() if k in PRINCIPAL_FIELDS}
    return data

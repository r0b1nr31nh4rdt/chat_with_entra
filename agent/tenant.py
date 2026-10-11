# tenant.py
# Zentrale Graph-Abfragen – genutzt von fetch_tenant.py (Snapshot) und tools/graph.py (live)

from graph_client import graph_get

QUERIES = {
    "users": "/users?$select=id,displayName,userPrincipalName,userType,accountEnabled",
    "role_definitions": "/roleManagement/directory/roleDefinitions?$select=id,displayName,description,isBuiltIn,isEnabled,templateId,rolePermissions",
    "role_assignments": "/roleManagement/directory/roleAssignments?$expand=principal",
    "ca_policies": "/identity/conditionalAccess/policies",
    "mfa_registration": "/reports/authenticationMethods/userRegistrationDetails",
    "security_defaults": "/policies/identitySecurityDefaultsEnforcementPolicy",
}

# Graph ignoriert $select innerhalb von $expand=principal und liefert das komplette
# Objekt (60+ Felder) → lokal auf das Nötige kürzen
PRINCIPAL_FIELDS = ("@odata.type", "id", "displayName", "userPrincipalName", "userType", "accountEnabled")


def fetch(name):
    """Holt einen Datensatz live von Graph."""
    data = graph_get(QUERIES[name])
    if name == "role_assignments":
        for a in data:
            a["principal"] = {k: v for k, v in a.get("principal", {}).items() if k in PRINCIPAL_FIELDS}
    return data

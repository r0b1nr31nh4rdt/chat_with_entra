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
}

# Graph ignoriert $select innerhalb von $expand=principal und liefert das komplette
# Objekt (60+ Felder) → lokal auf das Nötige kürzen
PRINCIPAL_FIELDS = ("@odata.type", "id", "displayName", "userPrincipalName", "userType", "accountEnabled")


def fetch(name):
    """Holt einen Datensatz live von Graph."""
    query = QUERIES[name]
    path, version = query if isinstance(query, tuple) else (query, "v1.0")
    data = graph_get(path, version)
    if name == "role_assignments":
        for a in data:
            a["principal"] = {k: v for k, v in a.get("principal", {}).items() if k in PRINCIPAL_FIELDS}
    return data

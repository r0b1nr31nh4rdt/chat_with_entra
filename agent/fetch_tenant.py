# fetch_tenant.py

import json
from pathlib import Path

from graph_client import graph_get

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)


def save(name, items):
    (DATA_DIR / f"{name}.json").write_text(
        json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    # Einzelobjekte (dict) haben keine sinnvolle Anzahl Einträge
    print(f"{name}: {len(items)} Einträge" if isinstance(items, list) else f"{name}: Einzelobjekt")


save("users", graph_get("/users?$select=id,displayName,userPrincipalName,userType,accountEnabled"))

save("role_definitions", graph_get("/roleManagement/directory/roleDefinitions?$select=id,displayName,description,isBuiltIn,isEnabled,templateId,rolePermissions"))

# Graph ignoriert $select innerhalb von $expand=principal und liefert das komplette
# Objekt (60+ Felder) → lokal auf das Nötige kürzen
PRINCIPAL_FIELDS = ("@odata.type", "id", "displayName", "userPrincipalName", "userType", "accountEnabled")
role_assignments = graph_get("/roleManagement/directory/roleAssignments?$expand=principal")
for a in role_assignments:
    a["principal"] = {k: v for k, v in a.get("principal", {}).items() if k in PRINCIPAL_FIELDS}
save("role_assignments", role_assignments)

save("ca_policies", graph_get("/identity/conditionalAccess/policies"))

save("mfa_registration", graph_get("/reports/authenticationMethods/userRegistrationDetails"))

save("security_defaults", graph_get("/policies/identitySecurityDefaultsEnforcementPolicy"))
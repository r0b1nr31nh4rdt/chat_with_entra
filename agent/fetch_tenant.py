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
    print(f"{name}: {len(items)} Einträge")


save("users", graph_get("/users?$select=id,displayName,userPrincipalName,userType,accountEnabled"))

# TODO: role_definitions  → /roleManagement/directory/roleDefinitions
# TODO: role_assignments  → /roleManagement/directory/roleAssignments?$expand=principal
# TODO: ca_policies       → /identity/conditionalAccess/policies
# TODO: mfa_registration  → /reports/authenticationMethods/userRegistrationDetails
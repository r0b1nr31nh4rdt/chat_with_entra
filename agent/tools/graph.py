# tools/graph.py
# Entra-Tools: jeder Aufruf holt die Daten live von Graph und wertet sie sofort aus

from collections import Counter
from functools import lru_cache

from tenant import fetch


# Rollendefinitionen ändern sich praktisch nie → nur einmal pro Session laden
_STATIC = {"role_definitions", "privileged_roles"}


def _load(name):
    if name in _STATIC:
        return _cached(name)
    return fetch(name)


@lru_cache(maxsize=None)
def _cached(name):
    return fetch(name)


def _role_names():
    """roleDefinitionId → Rollenname. Assignments verweisen bei Built-in-Rollen auf die templateId."""
    names = {}
    for r in _load("role_definitions"):
        names[r["id"]] = r["displayName"]
        names[r["templateId"]] = r["displayName"]
    return names


def _mfa_by_user():
    return {m["id"]: m for m in _load("mfa_registration")}


def get_role_members(role_name):
    roles = _role_names()
    mfa = _mfa_by_user()
    members = []
    for a in _load("role_assignments"):
        if roles.get(a["roleDefinitionId"], "").lower() != role_name.lower():
            continue
        p = a["principal"]
        is_user = p.get("@odata.type") == "#microsoft.graph.user"
        members.append({
            "displayName": p.get("displayName"),
            "type": "user" if is_user else "servicePrincipal",
            "userPrincipalName": p.get("userPrincipalName"),
            "accountEnabled": p.get("accountEnabled"),
            # MFA gibt es nur für User
            "isMfaRegistered": mfa.get(a["principalId"], {}).get("isMfaRegistered") if is_user else None,
        })
    if not members and role_name.lower() not in {n.lower() for n in roles.values()}:
        raise ValueError(f"Rolle '{role_name}' unbekannt")
    return {"role": role_name, "count": len(members), "by_type": dict(Counter(m["type"] for m in members)), "members": members}


def get_privileged_role_assignments():
    # privilegierte Rollen-IDs (id + templateId, da Assignments auf beide verweisen können)
    privileged = {}
    for r in _load("privileged_roles"):
        privileged[r["id"]] = r["displayName"]
        privileged[r["templateId"]] = r["displayName"]
    mfa = _mfa_by_user()

    roles = {}
    for a in _load("role_assignments"):
        role = privileged.get(a["roleDefinitionId"])
        if not role:
            continue
        p = a["principal"]
        is_user = p.get("@odata.type") == "#microsoft.graph.user"
        roles.setdefault(role, []).append({
            "principalId": a["principalId"],
            "displayName": p.get("displayName"),
            "type": "user" if is_user else "servicePrincipal",
            "userPrincipalName": p.get("userPrincipalName"),
            "accountEnabled": p.get("accountEnabled"),
            "isMfaRegistered": mfa.get(a["principalId"], {}).get("isMfaRegistered") if is_user else None,
        })

    def counts(members):
        return {
            "assignments": len(members),
            "users": sum(m["type"] == "user" for m in members),
            "servicePrincipals": sum(m["type"] == "servicePrincipal" for m in members),
            "usersWithoutMfa": sum(m["isMfaRegistered"] is False for m in members),
        }

    # Gesamtzählung über eindeutige Principals (eine Person mit 2 Rollen zählt einmal)
    unique = {m["principalId"]: m for members in roles.values() for m in members}
    summary = counts(list(unique.values()))
    summary["assignments"] = sum(len(m) for m in roles.values())
    summary["uniquePrincipals"] = len(unique)
    summary["rolesInUse"] = len(roles)

    return {
        "summary": summary,
        "roles": [
            {"role": role, **counts(members), "members": members}
            for role, members in sorted(roles.items(), key=lambda kv: -len(kv[1]))
        ],
    }


def list_users(user_type=None):
    users = _load("users")
    if user_type:
        users = [u for u in users if (u.get("userType") or "").lower() == user_type.lower()]
    return {"count": len(users), "users": users}


def get_mfa_status(only_admins=False):
    entries = _load("mfa_registration")
    if only_admins:
        entries = [m for m in entries if m["isAdmin"]]
    users = [{
        "userPrincipalName": m["userPrincipalName"],
        "isAdmin": m["isAdmin"],
        "isMfaRegistered": m["isMfaRegistered"],
        "methodsRegistered": m["methodsRegistered"],
    } for m in entries]
    return {
        "total": len(users),
        "withoutMfa": sum(not u["isMfaRegistered"] for u in users),
        "users": users,
    }


def get_auth_policies():
    ca = _load("ca_policies")
    sd = _load("security_defaults")
    return {
        "conditionalAccess": {
            "count": len(ca),
            "policies": [{"displayName": p.get("displayName"), "state": p.get("state")} for p in ca],
        },
        "securityDefaultsEnabled": sd.get("isEnabled"),
    }


# Responses-API-Format: name/description/parameters direkt auf oberster Ebene
TOOLS = [
    {
        "type": "function",
        "name": "get_role_members",
        "description": "Listet alle Mitglieder (User und Service Principals) einer Entra-Rolle inkl. MFA-Status, z. B. 'Global Administrator'.",
        "parameters": {
            "type": "object",
            "properties": {"role_name": {"type": "string", "description": "Exakter Rollenname, z. B. Global Administrator"}},
            "required": ["role_name"],
        },
    },
    {
        "type": "function",
        "name": "get_privileged_role_assignments",
        "description": "Alle Mitglieder privilegierter Entra-Rollen (laut Microsoft-Einstufung), gruppiert nach Rolle, mit fertigen Zählungen (User, Service Principals, User ohne MFA) pro Rolle und gesamt.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "type": "function",
        "name": "list_users",
        "description": "Listet Benutzer des Tenants, optional gefiltert nach Typ (Member oder Guest).",
        "parameters": {
            "type": "object",
            "properties": {"user_type": {"type": "string", "enum": ["Member", "Guest"]}},
        },
    },
    {
        "type": "function",
        "name": "get_mfa_status",
        "description": "MFA-Registrierungsstatus der Benutzer inkl. registrierter Methoden; optional nur Admins.",
        "parameters": {
            "type": "object",
            "properties": {"only_admins": {"type": "boolean", "description": "Nur Benutzer mit Admin-Rolle"}},
        },
    },
    {
        "type": "function",
        "name": "get_auth_policies",
        "description": "Conditional-Access-Policies und Status der Security Defaults des Tenants.",
        "parameters": {"type": "object", "properties": {}},
    },
]
FUNCS = {
    "get_role_members": get_role_members,
    "get_privileged_role_assignments": get_privileged_role_assignments,
    "list_users": list_users,
    "get_mfa_status": get_mfa_status,
    "get_auth_policies": get_auth_policies,
}

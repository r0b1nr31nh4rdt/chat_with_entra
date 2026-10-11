# tools/audit.py
# Audit-Checks: jeder Check holt Live-Daten, bewertet deterministisch und liefert Findings
# in einem festen Schema. Severity und Evidence stehen im Code – Erklärung und Fix formuliert das LLM.
#
# Finding-Schema:
#   id, severity (critical/high/medium/low/informational), title, affected (Liste),
#   evidence (Text), reference (CIS/Microsoft), optional note

import os

from tenant import fetch_graph_app_permissions, fetch_service_principal_id

from .graph import _load

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

# Mit jeder dieser Graph-Permissions kann sich eine App selbst oder andere zum Global Admin machen
CRITICAL_GRAPH_PERMISSIONS = {
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
}

GLOBAL_ADMIN_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

REF_ROLES_BEST_PRACTICES = "Microsoft Learn: Best practices for Microsoft Entra roles"


def _finding(id_, severity, title, affected, evidence, reference, note=None):
    f = {
        "id": id_,
        "severity": severity,
        "title": title,
        "affected": affected,
        "evidence": evidence,
        "reference": reference,
    }
    if note:
        f["note"] = note
    return f


def _exclusions(policy):
    """Ausnahmen einer CA-Policy als lesbarer Text (leer, wenn keine)."""
    users = policy.get("conditions", {}).get("users", {})
    parts = []
    for key, label in (("excludeUsers", "Benutzer"), ("excludeGroups", "Gruppen"), ("excludeRoles", "Rollen")):
        if users.get(key):
            parts.append(f"{len(users[key])} {label}")
    return ", ".join(parts)


def _privileged_assignments():
    """Aktive Zuweisungen privilegierter Rollen (laut Microsoft isPrivileged), angereichert mit Rollenname."""
    privileged = {}
    for r in _load("privileged_roles"):
        privileged[r["id"]] = (r["displayName"], r["templateId"])
        privileged[r["templateId"]] = (r["displayName"], r["templateId"])
    result = []
    for a in _load("role_assignments"):
        if a["roleDefinitionId"] in privileged:
            role, template_id = privileged[a["roleDefinitionId"]]
            result.append({**a, "role": role, "templateId": template_id})
    return result


def _is_user(principal):
    return principal.get("@odata.type") == "#microsoft.graph.user"


# ─── Check 1: Legacy Authentication ─────────────────────────────────────────


def _blocks_legacy_auth(policy):
    """Nur aktiv erzwungene Policies zählen – enabledForReportingButNotEnforced blockiert nichts."""
    cond = policy.get("conditions") or {}
    grant = policy.get("grantControls") or {}
    return (
        policy.get("state") == "enabled"
        and {"exchangeActiveSync", "other"} <= set(cond.get("clientAppTypes") or [])
        and "block" in (grant.get("builtInControls") or [])
        and "All" in ((cond.get("users") or {}).get("includeUsers") or [])
    )


def check_legacy_auth():
    note = "Exchange-seitige Einstellungen nicht über Graph prüfbar."
    reference = "CIS M365 5.2.2.3"

    if _load("security_defaults").get("isEnabled"):
        return []  # Security Defaults blockieren Legacy Auth tenant-weit

    policies = _load("ca_policies")
    blocking = [p for p in policies if _blocks_legacy_auth(p)]

    if not blocking:
        report_only = [
            p["displayName"] for p in policies
            if p.get("state") == "enabledForReportingButNotEnforced"
            and {"exchangeActiveSync", "other"} <= set((p.get("conditions") or {}).get("clientAppTypes") or [])
        ]
        evidence = f"Security Defaults: isEnabled=false; {len(policies)} CA-Policies, keine blockiert Legacy Auth für alle Benutzer"
        if report_only:
            evidence += f"; nur im Report-Only-Modus (blockiert nicht): {', '.join(report_only)}"
        return [_finding(
            "LEGACY-AUTH-NOT-BLOCKED", "high",
            "Legacy Authentication wird nicht blockiert",
            ["Alle Benutzer"], evidence, reference, note,
        )]

    # Blockiert – aber Ausnahmen sind ein Restrisiko
    with_exclusions = [(p["displayName"], _exclusions(p)) for p in blocking if _exclusions(p)]
    if len(with_exclusions) == len(blocking):
        details = "; ".join(f"'{name}' schließt aus: {exc}" for name, exc in with_exclusions)
        return [_finding(
            "LEGACY-AUTH-EXCLUSIONS", "low",
            "Legacy Authentication blockiert, aber mit Ausnahmen",
            [name for name, _ in with_exclusions],
            f"Blockierende CA-Policy vorhanden; Hinweis Ausnahmen: {details}", reference, note,
        )]
    return []


# ─── Check 2: Admins ohne MFA / MFA nicht erzwungen ─────────────────────────


def _requires_mfa(policy):
    grant = policy.get("grantControls") or {}
    return policy.get("state") == "enabled" and (
        "mfa" in (grant.get("builtInControls") or []) or grant.get("authenticationStrength")
    )


def _policy_covers(policy, user_id, role_template_ids):
    """Gilt die Policy für diesen Benutzer? (Gruppenmitgliedschaften werden nicht aufgelöst.)"""
    users = (policy.get("conditions") or {}).get("users") or {}
    if user_id in (users.get("excludeUsers") or []):
        return False
    if role_template_ids & set(users.get("excludeRoles") or []):
        return False
    include_users = users.get("includeUsers") or []
    return "All" in include_users or user_id in include_users or bool(role_template_ids & set(users.get("includeRoles") or []))


def check_admin_mfa():
    reference = "CIS M365 5.2.2.1"
    mfa = {m["id"]: m for m in _load("mfa_registration")}

    # Privilegierte Benutzer (keine SPs – die haben kein MFA) mit ihren Rollen
    admins = {}
    for a in _privileged_assignments():
        if not _is_user(a["principal"]):
            continue
        entry = admins.setdefault(a["principalId"], {
            "upn": a["principal"].get("userPrincipalName"),
            "roles": set(), "templateIds": set(),
        })
        entry["roles"].add(a["role"])
        entry["templateIds"].add(a["templateId"])

    if not admins:
        return []

    findings = []

    # Finding A: nicht registriert
    unregistered = [a for uid, a in admins.items() if not mfa.get(uid, {}).get("isMfaRegistered")]
    if unregistered:
        roles = sorted({r for a in unregistered for r in a["roles"]})
        findings.append(_finding(
            "ADMIN-NO-MFA", "critical",
            "Privilegierte Benutzer ohne MFA-Registrierung",
            sorted(a["upn"] for a in unregistered),
            f"{len(unregistered)} von {len(admins)} privilegierten Benutzern: isMfaRegistered=false "
            f"(Rollen: {', '.join(roles)})",
            reference,
        ))

    # Finding B: registriert ≠ erzwungen
    if _load("security_defaults").get("isEnabled"):
        return findings
    mfa_policies = [p for p in _load("ca_policies") if _requires_mfa(p)]
    not_enforced = [
        (uid, a) for uid, a in admins.items()
        if not any(_policy_covers(p, uid, a["templateIds"]) for p in mfa_policies)
    ]
    if not_enforced:
        registered = [a["upn"] for uid, a in not_enforced if mfa.get(uid, {}).get("isMfaRegistered")]
        evidence = (
            f"Security Defaults: isEnabled=false; {len(mfa_policies)} aktive CA-Policies mit MFA-Anforderung; "
            f"{len(not_enforced)} von {len(admins)} privilegierten Benutzern von keiner MFA-Policy erfasst"
        )
        if registered:
            evidence += f" – darunter {len(registered)} mit registrierter MFA, die beim Login trotzdem nicht abgefragt wird: {', '.join(registered)}"
        findings.append(_finding(
            "MFA-NOT-ENFORCED", "critical",
            "MFA wird für privilegierte Benutzer nicht erzwungen",
            sorted(a["upn"] for _, a in not_enforced),
            evidence, reference,
            note="Gruppenbasierte Zuweisungen in CA-Policies werden nicht aufgelöst." if mfa_policies else None,
        ))
    return findings


# ─── Check 3: Überprivilegierte Service Principals ──────────────────────────


def check_service_principals():
    findings = []

    # Quelle 1: SPs in privilegierten Directory-Rollen
    sp_roles = {}
    for a in _privileged_assignments():
        if _is_user(a["principal"]):
            continue
        sp_roles.setdefault(a["principal"].get("displayName"), set()).add(a["role"])
    if sp_roles:
        has_ga = any("Global Administrator" in r for r in sp_roles.values())
        findings.append(_finding(
            "SP-PRIVILEGED-ROLE", "critical" if has_ga else "high",
            "Service Principals in privilegierten Directory-Rollen",
            sorted(sp_roles),
            "; ".join(f"{sp}: {', '.join(sorted(r))}" for sp, r in sorted(sp_roles.items())),
            REF_ROLES_BEST_PRACTICES + " (Service Principals mit privilegierten Rollen = Control Plane)",
        ))

    # Quelle 2: SPs mit kritischen Graph-App-Permissions
    perms = {}
    for p in fetch_graph_app_permissions():
        if p["principalType"] == "ServicePrincipal":
            perms.setdefault((p["principalId"], p["principalDisplayName"]), set()).add(p["permission"])

    critical = {
        name: sorted(granted & CRITICAL_GRAPH_PERMISSIONS)
        for (_, name), granted in perms.items()
        if granted & CRITICAL_GRAPH_PERMISSIONS
    }
    if critical:
        findings.append(_finding(
            "SP-CRITICAL-GRAPH-PERMISSION", "critical",
            "Service Principals mit kritischen Microsoft-Graph-Permissions",
            sorted(critical),
            "; ".join(f"{sp}: {', '.join(p)}" for sp, p in sorted(critical.items()))
            + " – jede dieser Permissions erlaubt die Eskalation bis Global Admin",
            REF_ROLES_BEST_PRACTICES,
        ))

    # Eigene Audit-App: nicht kritisch, aber selbst ein privilegiertes Asset
    own_id = fetch_service_principal_id(os.environ["PEARSON_CLIENT_ID"])
    own = next(((name, granted) for (pid, name), granted in perms.items() if pid == own_id), None)
    if own:
        name, granted = own
        findings.append(_finding(
            "AUDIT-APP-PERMISSIONS", "informational",
            "Berechtigungen der eigenen Audit-App",
            [name],
            f"{name}: {', '.join(sorted(granted))} (nur Leserechte, aber tenant-weiter Lesezugriff)",
            REF_ROLES_BEST_PRACTICES,
            note="Das Audit-Tool ist selbst ein privilegiertes Asset: wer das Client Secret erbeutet, kann den gesamten Tenant auslesen.",
        ))
    return findings


# ─── Check 4: Anzahl Global Admins ──────────────────────────────────────────

GA_MIN, GA_MAX = 2, 4  # CIS: mindestens 2 (Redundanz/Vier-Augen), höchstens 4 (Angriffsfläche)


def check_global_admin_count():
    ga = [a for a in _privileged_assignments() if a["templateId"] == GLOBAL_ADMIN_TEMPLATE_ID]
    # CIS zählt Benutzerkonten; SPs werden separat in check_service_principals bewertet
    users = sorted({a["principal"].get("userPrincipalName") for a in ga if _is_user(a["principal"])})
    sps = sorted({a["principal"].get("displayName") for a in ga if not _is_user(a["principal"])})

    if GA_MIN <= len(users) <= GA_MAX:
        return []
    too_many = len(users) > GA_MAX
    evidence = f"{len(users)} Benutzer mit Global Administrator (Soll: {GA_MIN}–{GA_MAX})"
    if sps:
        evidence += f"; zusätzlich {len(sps)} Service Principals mit Global Administrator: {', '.join(sps)}"
    return [_finding(
        "GA-COUNT-TOO-HIGH" if too_many else "GA-COUNT-TOO-LOW", "medium",
        "Zu viele Global Administrators" if too_many else "Zu wenige Global Administrators",
        users, evidence, "CIS M365 1.1.3",
    )]


# ─── run_audit ──────────────────────────────────────────────────────────────

CHECKS = {
    "legacy_auth": check_legacy_auth,
    "admin_mfa": check_admin_mfa,
    "service_principals": check_service_principals,
    "global_admin_count": check_global_admin_count,
}


def run_audit():
    findings, errors = [], []
    for name, check in CHECKS.items():
        try:
            findings += check()
        except Exception as e:
            # Ein fehlgeschlagener Check soll den Rest des Audits nicht verhindern
            errors.append({"check": name, "error": f"{type(e).__name__}: {e}"})

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    return {
        "checks_run": list(CHECKS),
        "summary": {s: sum(f["severity"] == s for f in findings) for s in SEVERITY_ORDER},
        "findings": findings,
        "errors": errors,
    }


# Responses-API-Format: name/description/parameters direkt auf oberster Ebene
_NO_PARAMS = {"type": "object", "properties": {}}
TOOLS = [
    {
        "type": "function",
        "name": "run_audit",
        "description": "Führt alle Security-Checks (Legacy Auth, Admin-MFA, Service Principals, Anzahl Global Admins) live aus und liefert alle Findings sortiert nach Severity.",
        "parameters": _NO_PARAMS,
    },
    {
        "type": "function",
        "name": "check_legacy_auth",
        "description": "Audit-Check: Wird Legacy Authentication per Security Defaults oder Conditional Access blockiert?",
        "parameters": _NO_PARAMS,
    },
    {
        "type": "function",
        "name": "check_admin_mfa",
        "description": "Audit-Check: Haben privilegierte Benutzer MFA registriert, und wird MFA für sie auch erzwungen?",
        "parameters": _NO_PARAMS,
    },
    {
        "type": "function",
        "name": "check_service_principals",
        "description": "Audit-Check: Service Principals mit privilegierten Directory-Rollen oder kritischen Graph-App-Permissions.",
        "parameters": _NO_PARAMS,
    },
    {
        "type": "function",
        "name": "check_global_admin_count",
        "description": "Audit-Check: Liegt die Anzahl der Global Administrators zwischen 2 und 4 (CIS)?",
        "parameters": _NO_PARAMS,
    },
]
FUNCS = {
    "run_audit": run_audit,
    "check_legacy_auth": check_legacy_auth,
    "check_admin_mfa": check_admin_mfa,
    "check_service_principals": check_service_principals,
    "check_global_admin_count": check_global_admin_count,
}

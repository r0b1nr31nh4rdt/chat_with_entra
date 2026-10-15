# tools/audit.py
# Audit-Checks: jeder Check holt Live-Daten, bewertet deterministisch und liefert Findings
# in einem festen Schema. Severity und Evidence stehen im Code – Erklärung und Fix formuliert das LLM.
#
# Finding-Schema:
#   id, severity (critical/high/medium/low/informational), title, affected (Liste),
#   evidence (Text), reference (CIS/Microsoft), optional note

import os
from datetime import datetime, timedelta, timezone

import requests

from tenant import fetch_graph_app_permissions, fetch_service_principal_id, fetch_service_principal_owners

from .graph import _load
from .history import compare_audits, list_snapshots, save_snapshot

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


# ─── Check 3b: Owner privilegierter Service Principals ──────────────────────


def _privileged_sps():
    """SP-ID → (Name, Gründe): SPs in privilegierten Rollen oder mit kritischen Graph-Permissions (wie Check 3)."""
    sps = {}
    for a in _privileged_assignments():
        if not _is_user(a["principal"]):
            sps.setdefault(a["principalId"], (a["principal"].get("displayName"), set()))[1].add(a["role"])
    for p in fetch_graph_app_permissions():
        if p["principalType"] == "ServicePrincipal" and p["permission"] in CRITICAL_GRAPH_PERMISSIONS:
            sps.setdefault(p["principalId"], (p["principalDisplayName"], set()))[1].add(p["permission"])
    return sps


def check_sp_ownership():
    # Owner eines SP können ihm Credentials hinzufügen und sich dann als SP anmelden –
    # ein Owner ohne eigene Admin-Rolle hat damit einen Eskalationspfad zu den Rechten des SP
    admins = {a["principalId"] for a in _privileged_assignments()}
    paths = []
    for sp_id, (sp_name, reasons) in _privileged_sps().items():
        for owner in fetch_service_principal_owners(sp_id):
            if owner["id"] not in admins:
                name = owner.get("userPrincipalName") or owner.get("displayName")
                paths.append((name, sp_name, sorted(reasons)))
    if not paths:
        return []
    return [_finding(
        "SP-OWNER-NOT-ADMIN", "critical",
        "Owner privilegierter Service Principals ohne eigene Admin-Rolle",
        sorted({owner for owner, _, _ in paths}),
        "; ".join(f"{owner} ist Owner von {sp} ({', '.join(r)})" for owner, sp, r in sorted(paths))
        + " – Owner können dem SP Credentials hinzufügen und sich mit dessen Rechten anmelden",
        "MITRE ATT&CK T1098.001 (Additional Cloud Credentials); Microsoft Learn: Securing service principals in Microsoft Entra ID",
        note="Geprüft werden Owner des Service Principals, nicht Owner der App-Registrierung. "
             "Admin-Rollen zählen nur bei aktiver Zuweisung (PIM-eligible nicht berücksichtigt).",
    )]


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


# ─── Check 5: MFA für alle Benutzer ─────────────────────────────────────────


def check_user_mfa():
    enabled = {u["id"] for u in _load("users") if u.get("accountEnabled")}
    entries = [m for m in _load("mfa_registration") if m["id"] in enabled]
    missing = sorted(m["userPrincipalName"] for m in entries if not m["isMfaRegistered"])
    if not missing:
        return []
    return [_finding(
        "USER-NO-MFA", "high",
        "Benutzer ohne MFA-Registrierung",
        missing,
        f"{len(missing)} von {len(entries)} aktiven Benutzern: isMfaRegistered=false "
        f"({round(100 * len(missing) / len(entries))} %)",
        "CIS M365 5.2.2.2",
    )]


# ─── Check 6: Tenant-Einstellungen (Consent, App-Registrierung, Gäste) ──────

# allowInvitesFrom von restriktiv nach offen; CIS verlangt höchstens adminsAndGuestInviters
INVITE_SEVERITY = {"adminsGuestInvitersAndAllMembers": "low", "everyone": "medium"}


def check_tenant_settings():
    policy = _load("authorization_policy")
    perms = policy.get("defaultUserRolePermissions") or {}
    findings = []

    # User Consent: jede ManagePermissionGrantsForSelf.*-Policy erlaubt Benutzern, Apps Zugriff zu erteilen
    consent = [p for p in perms.get("permissionGrantPoliciesAssigned") or [] if p.startswith("ManagePermissionGrantsForSelf.")]
    if consent:
        legacy = any(p.endswith("microsoft-user-default-legacy") for p in consent)
        findings.append(_finding(
            "USER-CONSENT-ALLOWED", "high" if legacy else "medium",
            "Benutzer dürfen Apps selbst Zugriff auf Unternehmensdaten erteilen",
            ["Alle Benutzer"],
            f"permissionGrantPoliciesAssigned: {', '.join(consent)}"
            + (" (legacy = Consent für alle Apps ohne Einschränkung)" if legacy else ""),
            "CIS M365 5.1.5.1",
        ))

    if perms.get("allowedToCreateApps"):
        findings.append(_finding(
            "USER-APP-REGISTRATION-ALLOWED", "low",
            "Benutzer dürfen Anwendungen registrieren",
            ["Alle Benutzer"],
            "defaultUserRolePermissions.allowedToCreateApps=true",
            "CIS M365 5.1.2.2",
        ))

    invites = policy.get("allowInvitesFrom")
    if invites in INVITE_SEVERITY:
        findings.append(_finding(
            "GUEST-INVITE-UNRESTRICTED", INVITE_SEVERITY[invites],
            "Gast-Einladungen nicht auf Admins/Guest Inviter beschränkt",
            ["Alle Benutzer" if invites == "everyone" else "Alle Mitglieder"],
            f"allowInvitesFrom={invites} (Soll: adminsAndGuestInviters oder none)",
            "CIS M365 5.1.6.3",
        ))
    return findings


# ─── Check 7: Privilegierte Zuweisungen (Anzahl, Cloud-only) ─────────────────

PRIVILEGED_MAX = 10  # Microsoft: weniger als 10 privilegierte Rollenzuweisungen


def check_privileged_assignments():
    assignments = _privileged_assignments()
    findings = []

    if len(assignments) >= PRIVILEGED_MAX:
        findings.append(_finding(
            "PRIVILEGED-ASSIGNMENTS-TOO-MANY", "medium",
            "Zu viele privilegierte Rollenzuweisungen",
            sorted({a["principal"].get("userPrincipalName") or a["principal"].get("displayName") for a in assignments}),
            f"{len(assignments)} privilegierte Rollenzuweisungen (Soll: unter {PRIVILEGED_MAX})",
            REF_ROLES_BEST_PRACTICES + " (#6)",
        ))

    # On-Prem-synchronisierte Admins: eine AD-Kompromittierung reicht bis in die Cloud
    synced = sorted({
        a["principal"].get("userPrincipalName") for a in assignments
        if _is_user(a["principal"]) and a["principal"].get("onPremisesSyncEnabled")
    })
    if synced:
        findings.append(_finding(
            "ADMIN-SYNCED-ACCOUNT", "high",
            "Privilegierte Rollen an On-Premises-synchronisierte Konten vergeben",
            synced,
            f"{len(synced)} privilegierte Benutzer mit onPremisesSyncEnabled=true",
            REF_ROLES_BEST_PRACTICES + " (#9)",
        ))
    return findings


# ─── Check 8: Passwortablauf ────────────────────────────────────────────────

NEVER_EXPIRES = 2147483647  # Graph-Wert für „Passwörter laufen nie ab“


def check_password_expiration():
    expiring = [
        d for d in _load("domains")
        if d.get("isVerified") and d.get("authenticationType") == "Managed"  # föderierte Domains regelt der IdP
        and (d.get("passwordValidityPeriodInDays") or NEVER_EXPIRES) < NEVER_EXPIRES
    ]
    if not expiring:
        return []
    return [_finding(
        "PASSWORD-EXPIRATION-ENABLED", "low",
        "Periodischer Passwortablauf aktiv",
        sorted(d["id"] for d in expiring),
        "; ".join(f"{d['id']}: passwordValidityPeriodInDays={d['passwordValidityPeriodInDays']}" for d in expiring),
        "CIS M365 1.3.1",
    )]


# ─── Check 9: Risk-Policies (Identity Protection) ───────────────────────────


def _risk_policy_exists(policies, field):
    """Aktive CA-Policy für alle Benutzer mit Risk-Bedingung (userRiskLevels / signInRiskLevels)."""
    return any(
        p.get("state") == "enabled"
        and (p.get("conditions") or {}).get(field)
        and "All" in (((p.get("conditions") or {}).get("users") or {}).get("includeUsers") or [])
        for p in policies
    )


def check_risk_policies():
    policies = _load("ca_policies")
    note = "Risk-basierte Conditional-Access-Policies erfordern Microsoft Entra ID P2."
    findings = []
    for field, id_, title, ref in (
        ("userRiskLevels", "NO-USER-RISK-POLICY", "Keine User-Risk-Policy aktiv", "CIS M365 5.2.2.6"),
        ("signInRiskLevels", "NO-SIGNIN-RISK-POLICY", "Keine Sign-in-Risk-Policy aktiv", "CIS M365 5.2.2.7"),
    ):
        if not _risk_policy_exists(policies, field):
            findings.append(_finding(
                id_, "medium", title, ["Alle Benutzer"],
                f"Keine aktive CA-Policy mit conditions.{field} für alle Benutzer ({len(policies)} CA-Policies insgesamt)",
                ref, note,
            ))
    return findings


# ─── Check 10: Inaktive privilegierte Konten ────────────────────────────────

INACTIVE_DAYS = 90


def _last_sign_in(activity):
    """Letzte erfolgreiche Anmeldung (interaktiv oder nicht), None = nie angemeldet."""
    if not activity:
        return None
    stamps = [activity.get(k) for k in ("lastSuccessfulSignInDateTime", "lastSignInDateTime", "lastNonInteractiveSignInDateTime")]
    stamps = [datetime.fromisoformat(s.replace("Z", "+00:00")) for s in stamps if s]
    return max(stamps) if stamps else None


def check_inactive_admins():
    activity = {u["id"]: u.get("signInActivity") for u in _load("sign_in_activity")}
    cutoff = datetime.now(timezone.utc) - timedelta(days=INACTIVE_DAYS)

    admins = {
        a["principalId"]: a["principal"].get("userPrincipalName")
        for a in _privileged_assignments() if _is_user(a["principal"])
    }
    inactive, never = [], []
    for uid, upn in admins.items():
        last = _last_sign_in(activity.get(uid))
        if last is None:
            never.append(upn)
        elif last < cutoff:
            inactive.append(f"{upn} (zuletzt {last:%Y-%m-%d})")
    if not inactive and not never:
        return []

    parts = []
    if inactive:
        parts.append(f"{len(inactive)} seit über {INACTIVE_DAYS} Tagen ohne Anmeldung: {', '.join(inactive)}")
    if never:
        parts.append(f"{len(never)} ohne jede aufgezeichnete Anmeldung")
    return [_finding(
        "ADMIN-INACTIVE", "medium",
        "Inaktive privilegierte Konten",
        sorted(never + [i.split(" (")[0] for i in inactive]),
        f"{len(inactive) + len(never)} von {len(admins)} privilegierten Benutzern: " + "; ".join(parts),
        REF_ROLES_BEST_PRACTICES + " (#4 Access Reviews)",
        note="signInActivity wird erst ab Entra ID P1 erfasst; „nie angemeldet“ kann auch bedeuten, dass die Anmeldung vor Beginn der Aufzeichnung lag.",
    )]


# ─── Check 11: App-Secrets ──────────────────────────────────────────────────

SECRET_MAX_DAYS = 365  # Microsoft empfiehlt kurze Laufzeiten bzw. Zertifikate statt Secrets


def _parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def check_app_credentials():
    now = datetime.now(timezone.utc)
    long_lived, expired = [], []
    for app in _load("applications"):
        for c in app.get("passwordCredentials") or []:
            start, end = _parse(c["startDateTime"]), _parse(c["endDateTime"])
            label = f"{app['displayName']} ({c.get('displayName') or 'Secret'})"
            if end < now:
                expired.append(f"{label}, abgelaufen {end:%Y-%m-%d}")
            elif (end - start).days > SECRET_MAX_DAYS:
                long_lived.append(f"{label}, gültig {(end - start).days} Tage bis {end:%Y-%m-%d}")

    findings = []
    if long_lived:
        findings.append(_finding(
            "APP-SECRET-LONG-LIFETIME", "medium",
            f"App-Secrets mit Laufzeit über {SECRET_MAX_DAYS} Tage",
            sorted({x.split(" (")[0] for x in long_lived}),
            "; ".join(long_lived),
            "Microsoft Learn: Best practices for app registrations (Zertifikate statt Client Secrets)",
        ))
    if expired:
        findings.append(_finding(
            "APP-SECRET-EXPIRED", "low",
            "Abgelaufene App-Secrets nicht entfernt",
            sorted({x.split(" (")[0] for x in expired}),
            "; ".join(expired),
            "Microsoft Learn: Best practices for app registrations",
        ))
    return findings


# ─── Check 12: PIM (Just-in-time statt dauerhafter Zuweisung) ───────────────


def check_pim():
    reference = REF_ROLES_BEST_PRACTICES + " (#2 PIM)"
    try:
        eligible = _load("role_eligibility")
    except requests.HTTPError as e:
        if e.response.status_code != 403:
            raise
        return [_finding(
            "PIM-NOT-CHECKABLE", "informational",
            "PIM-Nutzung nicht prüfbar",
            [], "roleEligibilitySchedules: HTTP 403 – Permission RoleEligibilitySchedule.Read.Directory fehlt",
            reference, note="PIM erfordert außerdem Microsoft Entra ID P2.",
        )]

    eligible_ids = {e["principalId"] for e in eligible}
    standing = sorted({
        a["principal"].get("userPrincipalName") for a in _privileged_assignments()
        if _is_user(a["principal"]) and a["principalId"] not in eligible_ids
    })
    if not standing:
        return []
    return [_finding(
        "PIM-NOT-USED", "medium",
        "Dauerhafte privilegierte Zuweisungen statt PIM",
        standing,
        f"{len(standing)} privilegierte Benutzer mit aktiver Zuweisung ohne PIM-Eligibility "
        f"({len(eligible)} Eligibility-Schedules im Tenant)",
        reference,
        note="Break-Glass-Konten sollen bewusst dauerhaft zugewiesen bleiben.",
    )]


# ─── run_audit ──────────────────────────────────────────────────────────────

# Check-Funktion → Beschreibung für das Modell (Tool-Description)
CHECKS = {
    check_legacy_auth: "Wird Legacy Authentication per Security Defaults oder Conditional Access blockiert?",
    check_admin_mfa: "Haben privilegierte Benutzer MFA registriert, und wird MFA für sie auch erzwungen?",
    check_service_principals: "Service Principals mit privilegierten Directory-Rollen oder kritischen Graph-App-Permissions.",
    check_sp_ownership: "Haben privilegierte Service Principals Owner ohne eigene Admin-Rolle (Eskalationspfad)?",
    check_global_admin_count: "Liegt die Anzahl der Global Administrators zwischen 2 und 4 (CIS)?",
    check_user_mfa: "Haben alle aktiven Benutzer MFA registriert?",
    check_tenant_settings: "Tenant-Einstellungen: User Consent für Apps, App-Registrierung durch Benutzer, Gast-Einladungen.",
    check_privileged_assignments: "Weniger als 10 privilegierte Rollenzuweisungen, und nur Cloud-only-Konten in privilegierten Rollen?",
    check_password_expiration: "Ist periodischer Passwortablauf deaktiviert (CIS-Empfehlung)?",
    check_risk_policies: "Gibt es aktive User-Risk- und Sign-in-Risk-Policies (Identity Protection)?",
    check_inactive_admins: f"Privilegierte Benutzer ohne Anmeldung seit über {INACTIVE_DAYS} Tagen.",
    check_app_credentials: f"App-Secrets mit Laufzeit über {SECRET_MAX_DAYS} Tage oder abgelaufene, nicht entfernte Secrets.",
    check_pim: "Werden privilegierte Rollen just-in-time über PIM vergeben statt dauerhaft?",
}


def _snapshot():
    """Zustandsaufnahme: alle Checks ausführen, Findings mit auslösendem Check und Zeitstempel."""
    findings, errors, passed = [], [], []
    for check in CHECKS:
        try:
            result = check()
        except Exception as e:
            # Ein fehlgeschlagener Check soll den Rest des Audits nicht verhindern
            errors.append({"check": check.__name__, "error": f"{type(e).__name__}: {e}"})
            continue
        findings += [{**f, "check": check.__name__} for f in result]
        if not result:
            passed.append(check.__name__)

    findings.sort(key=lambda f: SEVERITY_ORDER.index(f["severity"]))
    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "checks_run": [c.__name__ for c in CHECKS],
        "checks_passed": passed,  # bestandene Prüfungen gehören auch in einen Audit-Report
        "summary": {s: sum(f["severity"] == s for f in findings) for s in SEVERITY_ORDER},
        "findings": findings,
        "errors": errors,
    }


def run_audit():
    """Snapshot speichern, danach als eigener Schritt mit dem vorherigen Snapshot vergleichen."""
    audit = _snapshot()
    snapshot_id = save_snapshot(audit)
    changes = compare_audits(new=snapshot_id) if len(list_snapshots()) > 1 else None
    return {"snapshot": snapshot_id, "audit": audit, "changes": changes}


# Responses-API-Format: name/description/parameters direkt auf oberster Ebene
_NO_PARAMS = {"type": "object", "properties": {}}
TOOLS = [
    {
        "type": "function",
        "name": "run_audit",
        "description": f"Führt alle {len(CHECKS)} Security-Checks live aus und liefert alle Findings sortiert nach Severity, plus Liste der bestandenen Checks. "
                       "Speichert das Ergebnis als Snapshot und vergleicht es danach mit dem vorherigen (changes: Score und Veränderungen).",
        "parameters": _NO_PARAMS,
    },
] + [
    {"type": "function", "name": check.__name__, "description": f"Audit-Check: {desc}", "parameters": _NO_PARAMS}
    for check, desc in CHECKS.items()
]
FUNCS = {"run_audit": run_audit} | {check.__name__: check for check in CHECKS}

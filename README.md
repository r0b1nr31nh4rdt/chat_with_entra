# chat_with_entra

Chat-basiertes Audit-Tool für Microsoft Entra ID. Ein LLM (Azure OpenAI) beantwortet Fragen zum Tenant und führt Security-Checks aus. Die Daten kommen **live** über Microsoft Graph. Die Tools laufen über einen lokalen MCP-Server.

**Arbeitsteilung:** Die Checks bewerten deterministisch im Code (Severity, Evidence). Das LLM erklärt nur Risiko und Behebung – es erfindet keine Findings.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Benötigte Variablen in `.env` (Projekt-Root):

```
END_POINT=https://<resource>.openai.azure.com/openai/v1
API_KEY=...
DEPLOYMENT_NAME=gpt-5.4-mini

PEARSON_TENANT_ID=...
PEARSON_CLIENT_ID=...
PEARSON_CLIENT_SECRET=...
```

Die App-Registration braucht diese **Application-Permissions** auf Microsoft Graph (Admin-Consent erforderlich):
`AuditLog.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `User.Read.All`.

## Starten

Alle Befehle aus dem Ordner `agent/` bei aktiver venv:

```bash
cd agent
python main.py           # Chat starten (beenden mit "exit" oder leerer Eingabe)
python fetch_tenant.py   # Tenant-Daten per Graph nach agent/data/ laden
python compare_audits.py # die letzten beiden gespeicherten Audits vergleichen (siehe Audit-Verlauf)
```

`main.py` startet `mcp_server.py` automatisch als Unterprozess. Die Tools im Chat fragen Graph bei jedem Aufruf **live** ab. `fetch_tenant.py` wird dafür nicht gebraucht – es speichert nur einen Snapshot für die `jq`-Auswertungen unten.

Beispielfragen im Chat:

- „Führe ein vollständiges Audit durch.“
- „Wer ist Global Admin und hat davon jemand kein MFA?“
- „Wird Legacy Authentication blockiert?“
- „Was hat sich seit dem letzten Audit verändert?“

## Projektstruktur

```
agent/
├── main.py            Chat-Schleife, MCP-Client, Tool-Calling
├── mcp_server.py      MCP-Server: stellt alle Tools aus tools/ bereit
├── llm.py             Azure-OpenAI-Client (Konfiguration aus .env)
├── graph_client.py    Graph-Login (Client Credentials) + graph_get mit Paging
├── tenant.py          Zentrale Graph-Abfragen (von Tools und fetch_tenant.py genutzt)
├── fetch_tenant.py    Snapshot aller Tenant-Daten nach data/
├── compare_audits.py  CLI: zwei Audit-Snapshots vergleichen
├── logger.py          JSONL-Log pro Session nach logs/
├── prompts/system.md  System-Prompt (Auditor-Rolle, Regeln für Findings)
├── tools/
│   ├── basic.py       get_current_time
│   ├── weather.py     get_weather (Open-Meteo)
│   ├── graph.py       Abfrage-Tools: Rollen, Benutzer, MFA, Policies
│   ├── audit.py       Audit-Checks + run_audit
│   └── history.py     Audit-Snapshots speichern und vergleichen (Score)
├── data/              Snapshot (gitignored)
└── logs/              Session-Logs (gitignored)
reports/               Audit-Snapshots audit_<YYYYMMDD_HHMMSS>.json (gitignored)
history/               Vergleiche <alt>__<neu>.json (gitignored)
```

## Audit-Checks

Jeder Check holt Live-Daten, bewertet deterministisch und gibt Findings in einem festen Schema zurück. `run_audit()` führt alle 12 Checks aus, sortiert die Findings nach Severity und listet zusätzlich die **bestandenen** Checks (`checks_passed`). Das Ergebnis wird als Snapshot gespeichert und mit dem vorherigen verglichen (siehe [Audit-Verlauf](#audit-verlauf)). Jeder Check ist zusätzlich einzeln als Tool aufrufbar.

| Tool | Prüft | Mögliche Findings | Referenz |
|---|---|---|---|
| `check_legacy_auth` | Wird Legacy Auth blockiert? Ja, wenn Security Defaults an **oder** eine CA-Policy mit `state=enabled` (Report-Only zählt nicht), `clientAppTypes` ⊇ `exchangeActiveSync`+`other`, `block`, Benutzer = `All` | `LEGACY-AUTH-NOT-BLOCKED` (high), `LEGACY-AUTH-EXCLUSIONS` (low) | CIS M365 5.2.2.3 |
| `check_admin_mfa` | Haben privilegierte Benutzer MFA **registriert** – und wird MFA für sie auch **erzwungen**? | `ADMIN-NO-MFA` (critical), `MFA-NOT-ENFORCED` (critical) | CIS M365 5.2.2.1 |
| `check_service_principals` | SPs in privilegierten Directory-Rollen und SPs mit kritischen Graph-Permissions | `SP-PRIVILEGED-ROLE` (critical/high), `SP-CRITICAL-GRAPH-PERMISSION` (critical), `AUDIT-APP-PERMISSIONS` (informational) | Microsoft Learn: Best practices for Entra roles |
| `check_global_admin_count` | Liegt die Zahl der Global Admins (Benutzer) zwischen 2 und 4? | `GA-COUNT-TOO-HIGH` / `GA-COUNT-TOO-LOW` (medium) | CIS M365 1.1.3 |
| `check_user_mfa` | Haben alle aktiven Benutzer MFA registriert? | `USER-NO-MFA` (high) | CIS M365 5.2.2.2 |
| `check_tenant_settings` | User Consent für Apps, App-Registrierung durch Benutzer, Gast-Einladungen (`authorizationPolicy`) | `USER-CONSENT-ALLOWED` (high bei legacy, sonst medium), `USER-APP-REGISTRATION-ALLOWED` (low), `GUEST-INVITE-UNRESTRICTED` (medium/low) | CIS M365 5.1.5.1, 5.1.2.2, 5.1.6.3 |
| `check_privileged_assignments` | Unter 10 privilegierte Zuweisungen? Nur Cloud-only-Konten in privilegierten Rollen? | `PRIVILEGED-ASSIGNMENTS-TOO-MANY` (medium), `ADMIN-SYNCED-ACCOUNT` (high) | Microsoft Learn: Best practices for Entra roles (#6, #9) |
| `check_password_expiration` | Periodischer Passwortablauf deaktiviert? (nur verwaltete Domains) | `PASSWORD-EXPIRATION-ENABLED` (low) | CIS M365 1.3.1 |
| `check_risk_policies` | Aktive CA-Policies mit User-Risk bzw. Sign-in-Risk für alle Benutzer? | `NO-USER-RISK-POLICY`, `NO-SIGNIN-RISK-POLICY` (medium) | CIS M365 5.2.2.6, 5.2.2.7 |
| `check_inactive_admins` | Privilegierte Benutzer seit über 90 Tagen oder noch nie angemeldet? | `ADMIN-INACTIVE` (medium) | Microsoft Learn: Best practices for Entra roles (#4) |
| `check_app_credentials` | App-Secrets mit über 365 Tagen Laufzeit oder abgelaufen und nicht entfernt? | `APP-SECRET-LONG-LIFETIME` (medium), `APP-SECRET-EXPIRED` (low) | Microsoft Learn: Best practices for app registrations |
| `check_pim` | Privilegierte Rollen über PIM (eligible) statt dauerhaft zugewiesen? | `PIM-NOT-USED` (medium), `PIM-NOT-CHECKABLE` (informational, bei fehlender Permission) | Microsoft Learn: Best practices for Entra roles (#2) |

**Finding-Schema:**

```json
{
  "id": "ADMIN-NO-MFA",
  "severity": "critical",
  "title": "Privilegierte Benutzer ohne MFA-Registrierung",
  "affected": ["..."],
  "evidence": "5 von 6 privilegierten Benutzern: isMfaRegistered=false (Rollen: Global Administrator)",
  "reference": "CIS M365 5.2.2.1",
  "note": "optional"
}
```

Severity-Stufen: `critical` · `high` · `medium` · `low` · `informational`

**Fachliche Details:**

- **Privilegierte Rollen** = Microsofts eigene Einstufung (`isPrivileged`, derzeit 35 Rollen). Das Feld gibt es nur in der Graph-Beta.
- **Kritische Graph-Permissions:** `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, `Directory.ReadWrite.All`. Mit jeder davon kann sich eine App selbst oder andere zum Global Admin machen.
- **Registriert ≠ erzwungen:** Ohne CA-Policy und ohne Security Defaults wird MFA auch für Admins mit registrierter MFA beim Login nicht verlangt. Deshalb gibt es zwei getrennte Findings.

**Bekannte Grenzen:**

- Exchange-seitige Einstellungen (z. B. Basic Auth pro Protokoll) sind über Graph nicht prüfbar.
- Gruppenbasierte Zuweisungen in CA-Policies werden nicht aufgelöst. Erfasst eine MFA-Policy Admins nur über eine Gruppe, meldet `check_admin_mfa` sie als „nicht erzwungen“.
- *Eligible* PIM-Zuweisungen sind nur mit zusätzlicher Permission `RoleEligibilitySchedule.Read.Directory` (und Entra ID P2) sichtbar. Ohne sie meldet `check_pim` „nicht prüfbar“, die übrigen Checks berücksichtigen nur aktive Zuweisungen.
- `signInActivity` (für `check_inactive_admins`) wird erst ab Entra ID P1 erfasst.
- Nicht automatisiert prüfbar: Break-Glass-Konten (nicht eindeutig erkennbar), Access Reviews (Governance-Lizenz), On-Prem-Empfehlungen des Secure Score (Kerberos, LAPS, Entra Connect).
- Die Logik für CA-Policies, PIM, synchronisierte Konten, Passwortablauf und abgelaufene Secrets ist mit synthetischen Daten getestet, weil der Lab-Tenant diese Fälle nicht enthält.
- CIS-Nummern sind laut Benchmark-Mappings über v4–v6 stabil (5.1.6.3 erst ab v6 belegt), können sich in künftigen Versionen aber verschieben.

## Audit-Verlauf

Zwei getrennte Schritte – wie Commit und `git diff`:

1. **Zustandsaufnahme:** Jeder `run_audit()` speichert sein Ergebnis unverändert als Snapshot `reports/audit_<YYYYMMDD_HHMMSS>.json` (Zeitstempel, ausgeführte/bestandene Checks, Summary, Findings, Errors). Jedes Finding enthält zusätzlich `check` – den Check, der es geliefert hat.
2. **Vergleich:** `compare_audits` vergleicht zwei Snapshots und legt das Ergebnis in `history/<alt>__<neu>.json` ab. Nach jedem `run_audit()` läuft er automatisch gegen den vorherigen Snapshot; das Tool liefert `{snapshot, audit, changes}` (`changes` ist beim ersten Audit `null`).

Vergleich ohne neues Audit – im Chat („Was hat sich seit dem letzten Audit verändert?“, Tools `compare_audits` und `list_snapshots`) oder im Terminal:

```bash
python compare_audits.py                     # die letzten beiden Snapshots
python compare_audits.py <alt> <neu>         # bestimmte Snapshots, z. B. 20261011_181500 20261014_153000
python compare_audits.py --list              # vorhandene Snapshots
```

**Inhalt eines Vergleichs:**

| Feld | Bedeutung |
|---|---|
| `score` | Risiko-Score alt → neu, Differenz und Bewertung (`verbessert` / `verschlechtert` / `unverändert`) |
| `summary_delta` | Veränderung der Anzahl Findings pro Severity |
| `new_findings` | Neu aufgetretene Findings (Verschlechterung) |
| `resolved_findings` | Nicht mehr vorhandene Findings (Verbesserung) |
| `changed_findings` | Gleiche ID, aber andere Severity oder hinzugekommene/entfernte betroffene Objekte |
| `not_checked` | Findings, deren Check im neueren Audit fehlgeschlagen ist – **nicht** behoben |

**Risiko-Score:** Summe der Risikopunkte aller Findings nach Severity – critical 10, high 5, medium 3, low 1, informational 0. Niedriger ist besser. Die Anzahl betroffener Objekte zählt bewusst nicht (sonst würde z. B. „30 Benutzer ohne MFA“ alles andere überdecken); Veränderungen dort zeigt `changed_findings`. In den Score fließen nur Checks ein, die in **beiden** Audits erfolgreich liefen – ein fehlgeschlagener Check soll den Score nicht scheinbar verbessern. Ausgeschlossene Checks stehen in `score.checks_excluded`.

## Testen

```bash
python graph_test.py     # Graph-Login prüfen: zeigt Tenant, App und Rollen (roles) aus dem Token
```

## Research („think like an attacker“)

Auswertung der geladenen Daten mit `jq` aus `agent/` heraus (Ausgabe enthält echte Benutzernamen – nicht ins Repo kopieren):

```bash
# Alle Admins und ob sie MFA registriert haben
jq '.[] | select(.isAdmin) | {userPrincipalName, isMfaRegistered}' data/mfa_registration.json

# Wer hat die Rolle Global Administrator? (62e90394-… = Template-ID von Global Administrator)
jq '.[] | select(.roleDefinitionId=="62e90394-69f5-4237-9190-012177145e10") | .principal.displayName' data/role_assignments.json

# Welche Gäste gibt es?
jq '.[] | select(.userType=="Guest") | {displayName, userPrincipalName, accountEnabled}' data/users.json

# Hat ein Gast eine Rolle? (verknüpft role_assignments mit role_definitions für den Rollennamen)
jq -n --slurpfile ra data/role_assignments.json --slurpfile rd data/role_definitions.json '
  ($rd[0] | map({(.templateId): .displayName}) | add) as $roles
  | $ra[0][] | select(.principal.userType=="Guest")
  | {guest: .principal.userPrincipalName, role: ($roles[.roleDefinitionId] // .roleDefinitionId)}'

# Keine CA-Policies – sind wenigstens die Security Defaults an?
jq 'length' data/ca_policies.json
jq '{displayName, isEnabled}' data/security_defaults.json
```

## Befunde Tenant-Audit (Stand: 2026-10-11)

Datengrundlage: `run_audit()` (live über Microsoft Graph) sowie die `jq`-Auswertungen oben.
Hier stehen bewusst nur aggregierte Werte – keine Namen, UPNs oder IDs.

### Überblick

| Bereich | Wert |
|---|---|
| Benutzer | 33 (alle aktiv, keine Gäste) |
| Rollendefinitionen | 145 (davon 35 privilegiert) |
| Aktive Rollenzuweisungen | 13 (alle tenant-weit, Scope `/`) |
| Conditional-Access-Policies | 0 |
| Security Defaults | deaktiviert |
| **Audit-Ergebnis** | **4 critical · 2 high · 5 medium · 1 low · 2 informational** (12 Checks, 4 bestanden) |

### 🔴 Critical

| ID | Befund |
|---|---|
| `ADMIN-NO-MFA` | 5 von 6 privilegierten Benutzern (alle Global Administrator) haben keine MFA registriert. |
| `MFA-NOT-ENFORCED` | 6 von 6 privilegierten Benutzern werden von keiner MFA-Policy erfasst – auch der eine Admin mit registrierter MFA wird beim Login nicht nach dem zweiten Faktor gefragt. |
| `SP-PRIVILEGED-ROLE` | 2 Service Principals haben die Rolle Global Administrator. |
| `SP-CRITICAL-GRAPH-PERMISSION` | Dieselben 2 Service Principals haben zusätzlich `Directory.ReadWrite.All` und `RoleManagement.ReadWrite.Directory`. |

### 🟠 High

| ID | Befund |
|---|---|
| `LEGACY-AUTH-NOT-BLOCKED` | Weder Security Defaults noch eine CA-Policy blockieren Legacy Authentication. Exchange-seitige Einstellungen sind nicht über Graph prüfbar. |
| `USER-NO-MFA` | 30 von 33 aktiven Benutzern (91 %) haben keine MFA registriert. |

### 🟡 Medium

| ID | Befund |
|---|---|
| `GA-COUNT-TOO-HIGH` | 6 Benutzer mit Global Administrator (Soll laut CIS: 2–4), zusätzlich 2 Service Principals. |
| `USER-CONSENT-ALLOWED` | Benutzer dürfen Apps selbst Zugriff auf Unternehmensdaten erteilen (Microsoft-Standardrichtlinien für User Consent aktiv). |
| `GUEST-INVITE-UNRESTRICTED` | Jeder – auch Gäste – darf Gäste einladen (`allowInvitesFrom=everyone`). |
| `NO-USER-RISK-POLICY` | Keine aktive User-Risk-Policy (erfordert Entra ID P2). |
| `NO-SIGNIN-RISK-POLICY` | Keine aktive Sign-in-Risk-Policy (erfordert Entra ID P2). |

### 🔵 Low

| ID | Befund |
|---|---|
| `USER-APP-REGISTRATION-ALLOWED` | Alle Benutzer dürfen Anwendungen registrieren. |

### ⚪ Informational

| ID | Befund |
|---|---|
| `AUDIT-APP-PERMISSIONS` | Die eigene Audit-App hat 4 Read-Permissions (`AuditLog.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `User.Read.All`). Nicht kritisch, aber tenant-weiter Lesezugriff. |
| `PIM-NOT-CHECKABLE` | PIM-Nutzung nicht prüfbar – Permission `RoleEligibilitySchedule.Read.Directory` fehlt. |

### ✅ Bestanden

| Check | Ergebnis |
|---|---|
| `check_privileged_assignments` | 8 privilegierte Zuweisungen (unter 10), keine On-Prem-synchronisierten Admins. |
| `check_password_expiration` | Passwörter laufen nicht ab. |
| `check_inactive_admins` | Alle privilegierten Benutzer haben sich in den letzten 90 Tagen angemeldet. |
| `check_app_credentials` | Ein App-Secret mit 90 Tagen Laufzeit, keine abgelaufenen Secrets. |

### Weitere Beobachtungen (nicht automatisiert geprüft)

- **MFA-Methoden:** Registriert sind Software-OTP (3), Authenticator-Push (2), E-Mail (1).
- **Weitere SP-Rollen:** Neben den 2 Global-Admin-Zuweisungen gibt es 3 weitere Rollenzuweisungen an Service Principals (1× Exchange Administrator, 2× Rollen-IDs ohne passende Rollendefinition – vermutlich versteckte Systemrollen). Microsoft stuft diese nicht als privilegiert ein.
- **Admin ohne aktive Zuweisung:** Der MFA-Report markiert 7 Benutzer als Admin (`isAdmin`), aktive privilegierte Zuweisungen haben aber nur 6. Vermutlich eine *eligible* PIM-Zuweisung – mit der PIM-Permission ließe sich das klären.
- **SSPR:** Nur 3 Benutzer für Self-Service-Password-Reset registriert.

### Empfehlungen

1. **Sofort:** MFA für alle privilegierten Rollen per Conditional Access erzwingen (oder übergangsweise Security Defaults aktivieren). Vorher ein Break-Glass-Konto anlegen und ausnehmen.
2. Global-Admin-Rolle und kritische Graph-Permissions der beiden Service Principals prüfen und entziehen, wo nicht zwingend nötig.
3. Legacy Authentication per CA-Policy für alle Benutzer blockieren.
4. Anzahl Global Admins auf 2–4 reduzieren. Übrige Konten auf weniger privilegierte Rollen umstellen.
5. MFA-Registrierung für alle Benutzer durchsetzen (Registrierungskampagne). E-Mail als Methode vermeiden.
6. User Consent abschalten (Admin-Consent-Workflow stattdessen), Gast-Einladungen auf Admins/Guest Inviter und App-Registrierung auf Admins beschränken.
7. Permission `RoleEligibilitySchedule.Read.Directory` ergänzen, damit der PIM-Check greift.

### Reflexion

Das Audit-Tool ist selbst ein privilegiertes Asset: Wer das Client Secret aus der `.env` erbeutet, kann den gesamten Tenant auslesen – genau die Informationen, die ein Angreifer für die Planung braucht (wer ist Admin, wer hat kein MFA, welche Policies fehlen). Absicherung: Secret nur lokal und gitignored (pre-commit mit gitleaks), regelmäßig rotieren oder durch ein Zertifikat ersetzen, nur Read-Permissions vergeben.

## Quellen

Die CIS-Referenzen stammen aus öffentlichen Benchmark-Mappings (Tenable, Powerpipe/Steampipe), nicht aus dem offiziellen CIS-PDF. Für einen verbindlichen Report die Nummern gegen die aktuelle Version in der CIS WorkBench prüfen.

### Microsoft Learn

- [Best practices for Microsoft Entra roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices) – Least Privilege, PIM (#2), MFA für Admins (#3), Access Reviews (#4), < 5 Global Admins (#5), < 10 privilegierte Zuweisungen (#6), Cloud-only-Konten (#9); Service Principals mit privilegierten Rollen als Control Plane
- [What is the Identity Secure Score?](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-identity-secure-score) – Empfehlungsliste (MFA für alle, Legacy Auth, User Consent, Passwortablauf, Risk-Policies, SSPR u. a.)
- [Identity Secure Score (ältere URL)](https://learn.microsoft.com/azure/active-directory/fundamentals/identity-secure-score)

### CIS Microsoft 365 Foundations Benchmark

| Control | Thema | Check | Quelle |
|---|---|---|---|
| 1.1.3 | Zwei bis vier Global Admins | `check_global_admin_count` | [Tenable (v6.0.1)](https://www.tenable.com/audits/items/CIS_Microsoft_365_Foundations_v6.0.1_L1_E3.audit:b00615853b821c12d798039097dce35a) |
| 1.3.1 | Passwörter laufen nicht ab | `check_password_expiration` | [Tenable (v6.0.1)](https://www.tenable.com/audits/items/CIS_Microsoft_365_Foundations_v6.0.1_L1_E3.audit:6dbe2160c93a3ca645c77f1dec83b123) |
| 5.1.2.2 | Keine App-Registrierung durch Benutzer | `check_tenant_settings` | [Powerpipe (v6)](https://hub.powerpipe.io/mods/turbot/steampipe-mod-microsoft365-compliance/controls/control.cis_v600_5_1_2_2) |
| 5.1.5.1 | Kein User Consent für Apps | `check_tenant_settings` | [Powerpipe (v6)](https://hub.powerpipe.io/mods/turbot/steampipe-mod-microsoft365-compliance/controls/control.cis_v600_5_1_5_1) |
| 5.1.6.3 | Gast-Einladungen nur durch Guest Inviter | `check_tenant_settings` | [PowerShell Gallery (v6.0.1)](https://www.powershellgallery.com/packages/ROOTM365/1.0.1/Content/SHELL%5C5.1.6.3.ps1) |
| 5.2.2.1 | MFA für administrative Rollen | `check_admin_mfa` | [Tenable (v6.0.0)](https://www.tenable.com/audits/items/CIS_Microsoft_365_Foundations_v6.0.0_L1_E3.audit:dec4ac010f858723a9b67fc7c04f8262) |
| 5.2.2.2 | MFA für alle Benutzer | `check_user_mfa` | [Tenable (v6.0.0)](https://www.tenable.com/audits/items/CIS_Microsoft_365_Foundations_v6.0.0_L1_E5.audit:63ffc9b1065e47b999c9dfeb0c360261) |
| 5.2.2.3 | Legacy Auth per CA blockieren | `check_legacy_auth` | [Powerpipe (v5)](https://hub.powerpipe.io/mods/turbot/steampipe-mod-microsoft365-compliance/controls/benchmark.cis_v500_5_2_2), [Powerpipe (v6)](https://hub.powerpipe.io/mods/turbot/steampipe-mod-microsoft365-compliance/controls/benchmark.cis_v600_5_2_2) |
| 5.2.2.6 | User-Risk-Policy | `check_risk_policies` | [Tenable (v5.0.0)](https://www.tenable.com/audits/items/CIS_Microsoft_365_Foundations_v5.0.0_L1_E5.audit:95d841342c810e5e7b46982a3a712508) |
| 5.2.2.7 | Sign-in-Risk-Policy | `check_risk_policies` | [Tenable (v6.0.0)](https://www.tenable.com/audits/items/CIS_Microsoft_365_Foundations_v6.0.0_L1_E5.audit:686911ddcacd957cf55790a14d32b68c) |

### Microsoft Graph

- Graph-Endpunkte und Permissions laut [Microsoft Graph REST API v1.0](https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0); `isPrivileged` an Rollendefinitionen nur in der [Beta-API](https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-beta).
- Wetterdaten: [Open-Meteo](https://open-meteo.com/en/docs) (Geocoding + Forecast, kein API-Key).

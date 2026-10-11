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
```

`main.py` startet `mcp_server.py` automatisch als Unterprozess. Die Tools im Chat fragen Graph bei jedem Aufruf **live** ab. `fetch_tenant.py` wird dafür nicht gebraucht – es speichert nur einen Snapshot für die `jq`-Auswertungen unten.

Beispielfragen im Chat:

- „Führe ein vollständiges Audit durch.“
- „Wer ist Global Admin und hat davon jemand kein MFA?“
- „Wird Legacy Authentication blockiert?“

## Projektstruktur

```
agent/
├── main.py            Chat-Schleife, MCP-Client, Tool-Calling
├── mcp_server.py      MCP-Server: stellt alle Tools aus tools/ bereit
├── llm.py             Azure-OpenAI-Client (Konfiguration aus .env)
├── graph_client.py    Graph-Login (Client Credentials) + graph_get mit Paging
├── tenant.py          Zentrale Graph-Abfragen (von Tools und fetch_tenant.py genutzt)
├── fetch_tenant.py    Snapshot aller Tenant-Daten nach data/
├── logger.py          JSONL-Log pro Session nach logs/
├── prompts/system.md  System-Prompt (Auditor-Rolle, Regeln für Findings)
├── tools/
│   ├── basic.py       get_current_time
│   ├── weather.py     get_weather (Open-Meteo)
│   ├── graph.py       Abfrage-Tools: Rollen, Benutzer, MFA, Policies
│   └── audit.py       Audit-Checks + run_audit
├── data/              Snapshot (gitignored)
└── logs/              Session-Logs (gitignored)
```

## Audit-Checks

Jeder Check holt Live-Daten, bewertet deterministisch und gibt Findings in einem festen Schema zurück. `run_audit()` führt alle Checks aus und sortiert die Findings nach Severity. Jeder Check ist zusätzlich einzeln als Tool aufrufbar.

| Tool | Prüft | Mögliche Findings | Referenz |
|---|---|---|---|
| `check_legacy_auth` | Wird Legacy Auth blockiert? Ja, wenn Security Defaults an **oder** eine CA-Policy mit `state=enabled` (Report-Only zählt nicht), `clientAppTypes` ⊇ `exchangeActiveSync`+`other`, `block`, Benutzer = `All` | `LEGACY-AUTH-NOT-BLOCKED` (high), `LEGACY-AUTH-EXCLUSIONS` (low) | CIS M365 5.2.2.3 |
| `check_admin_mfa` | Haben privilegierte Benutzer MFA **registriert** – und wird MFA für sie auch **erzwungen**? | `ADMIN-NO-MFA` (critical), `MFA-NOT-ENFORCED` (critical) | CIS M365 5.2.2.1 |
| `check_service_principals` | SPs in privilegierten Directory-Rollen und SPs mit kritischen Graph-Permissions | `SP-PRIVILEGED-ROLE` (critical/high), `SP-CRITICAL-GRAPH-PERMISSION` (critical), `AUDIT-APP-PERMISSIONS` (informational) | Microsoft Learn: Best practices for Entra roles |
| `check_global_admin_count` | Liegt die Zahl der Global Admins (Benutzer) zwischen 2 und 4? | `GA-COUNT-TOO-HIGH` / `GA-COUNT-TOO-LOW` (medium) | CIS M365 1.1.3 |

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
- Nur **aktive** Rollenzuweisungen. *Eligible* PIM-Zuweisungen fehlen.
- Die CA-Logik ist mit synthetischen Policies getestet. Der Lab-Tenant hat keine CA-Policies.
- CIS-Nummern sind über v4–v6 stabil, können sich in künftigen Versionen aber verschieben.

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
| **Audit-Ergebnis** | **4 critical · 1 high · 1 medium · 1 informational** |

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

### 🟡 Medium

| ID | Befund |
|---|---|
| `GA-COUNT-TOO-HIGH` | 6 Benutzer mit Global Administrator (Soll laut CIS: 2–4), zusätzlich 2 Service Principals. |

### ⚪ Informational

| ID | Befund |
|---|---|
| `AUDIT-APP-PERMISSIONS` | Die eigene Audit-App hat 4 Read-Permissions (`AuditLog.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `User.Read.All`). Nicht kritisch, aber tenant-weiter Lesezugriff. |

### Weitere Beobachtungen (nicht automatisiert geprüft)

- **MFA-Registrierung insgesamt:** Nur 3 von 33 Benutzern (9 %) haben MFA registriert. Registrierte Methoden: Software-OTP (3), Authenticator-Push (2), E-Mail (1).
- **Weitere SP-Rollen:** Neben den 2 Global-Admin-Zuweisungen gibt es 3 weitere Rollenzuweisungen an Service Principals (1× Exchange Administrator, 2× Rollen-IDs ohne passende Rollendefinition – vermutlich versteckte Systemrollen). Microsoft stuft diese nicht als privilegiert ein.
- **Admin ohne aktive Zuweisung:** Der MFA-Report markiert 7 Benutzer als Admin (`isAdmin`), aktive privilegierte Zuweisungen haben aber nur 6. Vermutlich eine *eligible* PIM-Zuweisung.
- **SSPR:** Nur 3 Benutzer für Self-Service-Password-Reset registriert.

### Empfehlungen

1. **Sofort:** MFA für alle privilegierten Rollen per Conditional Access erzwingen (oder übergangsweise Security Defaults aktivieren). Vorher ein Break-Glass-Konto anlegen und ausnehmen.
2. Global-Admin-Rolle und kritische Graph-Permissions der beiden Service Principals prüfen und entziehen, wo nicht zwingend nötig.
3. Legacy Authentication per CA-Policy für alle Benutzer blockieren.
4. Anzahl Global Admins auf 2–4 reduzieren. Übrige Konten auf weniger privilegierte Rollen umstellen.
5. MFA-Registrierung für alle Benutzer durchsetzen (Registrierungskampagne). E-Mail als Methode vermeiden.

### Reflexion

Das Audit-Tool ist selbst ein privilegiertes Asset: Wer das Client Secret aus der `.env` erbeutet, kann den gesamten Tenant auslesen – genau die Informationen, die ein Angreifer für die Planung braucht (wer ist Admin, wer hat kein MFA, welche Policies fehlen). Absicherung: Secret nur lokal und gitignored (pre-commit mit gitleaks), regelmäßig rotieren oder durch ein Zertifikat ersetzen, nur Read-Permissions vergeben.

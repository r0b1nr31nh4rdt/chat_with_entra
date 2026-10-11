# chat_with_entra

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

## Starten

Alle Befehle aus dem Ordner `agent/` bei aktiver venv:

```bash
cd agent
python main.py           # Chat starten (beenden mit "exit" oder leerer Eingabe)
python fetch_tenant.py   # Tenant-Daten per Graph nach agent/data/ laden
```

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
```

## Befunde Tenant-Audit (Stand: 2026-10-11)

Datengrundlage: `agent/fetch_tenant.py` (Microsoft Graph, App-Registration mit Leserechten).
Rohdaten liegen lokal in `agent/data/` (gitignored). Hier stehen bewusst nur aggregierte Werte – keine Namen, UPNs oder IDs.

### Überblick

| Bereich | Wert |
|---|---|
| Benutzer | 33 (alle aktiv, keine Gäste) |
| Rollendefinitionen | 145 |
| Aktive Rollenzuweisungen | 13 (alle tenant-weit, Scope `/`) |
| Conditional-Access-Policies | 0 |
| Security Defaults | deaktiviert |

### 🔴 Kritisch

**1. MFA wird nirgends erzwungen**
Security Defaults sind deaktiviert (`isEnabled: false`) und es existiert keine einzige Conditional-Access-Policy. Damit gibt es keinen Mechanismus, der MFA für Anmeldungen verlangt.

**2. 5 von 6 Global Administrators ohne MFA**
6 Benutzer haben die Rolle *Global Administrator*, nur 1 davon hat MFA registriert. Ein kompromittiertes Passwort reicht hier für die vollständige Übernahme des Tenants.

**3. Nur 3 von 33 Benutzern (9 %) haben MFA registriert**
30 Konten sind allein durch ein Passwort geschützt. Registrierte Methoden: Software-OTP (3), Authenticator-Push (2), E-Mail (1).

### 🟠 Hoch

**4. Zu viele Global Administrators**
8 Global-Admin-Zuweisungen insgesamt: 6 Benutzer + 2 Service Principals. Microsoft empfiehlt weniger als 5 Global Admins; Service Principals mit Global Admin sind besonders heikel, weil ihre Credentials (Secrets/Zertifikate) oft schlechter überwacht werden.

**5. Weitere privilegierte Service Principals**
Insgesamt 5 Rollenzuweisungen an Service Principals (2× Global Administrator, 1× Exchange Administrator, 2× Rollen, deren ID nicht in den Rollendefinitionen auftaucht – vermutlich Custom- oder versteckte Systemrollen, noch zu klären).

### 🟡 Zu prüfen

- **Admin ohne aktive Zuweisung:** Der MFA-Report markiert 7 Benutzer als Admin (`isAdmin`), aktive Zuweisungen haben aber nur 6. Mögliche Ursache: eine *eligible* PIM-Zuweisung, die `roleAssignments` nicht liefert.
- **SSPR:** Nur 3 Benutzer für Self-Service-Password-Reset registriert.

### Empfehlungen

1. Sofort: MFA für alle Admin-Rollen erzwingen (Conditional Access oder zumindest Security Defaults aktivieren).
2. Anzahl Global Admins auf 2–4 reduzieren, inkl. Break-Glass-Konto; übrige auf weniger privilegierte Rollen umstellen.
3. Global-Admin-Rechte der Service Principals prüfen und entziehen, wo nicht zwingend nötig.
4. MFA-Registrierung für alle Benutzer durchsetzen (Registrierungskampagne), E-Mail als Methode vermeiden.
5. Unbekannte Rollen-IDs und die PIM-Eligibility nachrecherchieren.

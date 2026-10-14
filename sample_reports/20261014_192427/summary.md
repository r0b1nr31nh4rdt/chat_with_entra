# Audit-Zusammenfassung 20261014_192427

> Vom LLM erstellt (gpt-5.4-mini) am 2026-10-14 20:55. Maßgeblich sind die Fakten in `snapshot.json` und `changes.json` – dieser Text ist ihre Auswertung.
>
> Frage: erstelle eine zusammenfassung zu dem audit 20261014_192427

---

Hier ist die Zusammenfassung für das Audit `20261014_192427`.

## Kurzfazit
- **Risiko-Score:** `66 → 72` (**+6**, **verschlechtert**)
- **Vergleich zum vorherigen Audit:** Es sind **2 neue Medium-Findings** hinzugekommen, keine Findings wurden behoben.
- **Gesamtbewertung:** Der Tenant bleibt stark gefährdet, vor allem durch **fehlende MFA-Erzwingung**, **kritisch privilegierte Service Principals** und **zu viele privilegierte Zuweisungen**.

## Verteilung der Findings
- **critical:** 4
- **high:** 2
- **medium:** 7
- **low:** 1
- **informational:** 2

## Wichtigste Veränderungen seit dem letzten Audit
### Neu hinzugekommen
- **`ADMIN-INACTIVE`** – inaktive privilegierte Konten
- **`PRIVILEGED-ASSIGNMENTS-TOO-MANY`** – zu viele privilegierte Rollenzuweisungen

### Verschärft
- **`ADMIN-NO-MFA`**: zusätzlich `user16@contoso.onmicrosoft.com`
- **`MFA-NOT-ENFORCED`**: zusätzlich `user16@contoso.onmicrosoft.com`
- **`GA-COUNT-TOO-HIGH`**: zusätzlich `user16@contoso.onmicrosoft.com`
- **`SP-PRIVILEGED-ROLE`**: zusätzlich `ServicePrincipal-A`

## Kritische Findings

### 1) `ADMIN-NO-MFA` – Privilegierte Benutzer ohne MFA-Registrierung
- **Affected:**  
  `user05@contoso.onmicrosoft.com`, `user16@contoso.onmicrosoft.com`, `user21@contoso.onmicrosoft.com`, `user25@contoso.onmicrosoft.com`, `user27@contoso.onmicrosoft.com`, `user29@contoso.onmicrosoft.com`
- **Evidence:** `6 von 7 privilegierten Benutzern: isMfaRegistered=false (Rollen: Global Administrator)`
- **Reference:** `CIS M365 5.2.2.1`

**Risiko:** Ein Angreifer mit gestohlenem Passwort kann sich ohne zweiten Faktor anmelden und als Global Admin agieren.

**Behebung:**  
Entra Admin Center → **Protection** → **Conditional Access** → MFA für privilegierte Rollen erzwingen; vorher Break-Glass-Konto ausnehmen; anschließend betroffene Konten unter **Users** → **Authentication methods** zur MFA-Registrierung bringen.

---

### 2) `MFA-NOT-ENFORCED` – MFA wird für privilegierte Benutzer nicht erzwungen
- **Affected:**  
  `user05@contoso.onmicrosoft.com`, `user16@contoso.onmicrosoft.com`, `user21@contoso.onmicrosoft.com`, `user25@contoso.onmicrosoft.com`, `user27@contoso.onmicrosoft.com`, `user29@contoso.onmicrosoft.com`, `user03@contoso.onmicrosoft.com`
- **Evidence:** `Security Defaults: isEnabled=false; 0 aktive CA-Policies mit MFA-Anforderung; 7 von 7 privilegierten Benutzern von keiner MFA-Policy erfasst – darunter 1 mit registrierter MFA, die beim Login trotzdem nicht abgefragt wird: user03@contoso.onmicrosoft.com`
- **Reference:** `CIS M365 5.2.2.1`

**Risiko:** Selbst registrierte MFA schützt nicht, wenn keine Policy MFA tatsächlich verlangt.

**Behebung:**  
Entra Admin Center → **Protection** → **Conditional Access** → Policy für Admins erstellen, **Require multi-factor authentication** aktivieren; optional Security Defaults nutzen; Break-Glass-Konto ausnehmen.

---

### 3) `SP-PRIVILEGED-ROLE` – Service Principals in privilegierten Directory-Rollen
- **Affected:**  
  `ServicePrincipal-A`, `ServicePrincipal-C`, `ServicePrincipal-B`
- **Evidence:** `ServicePrincipal-A: Privileged Authentication Administrator; ServicePrincipal-C: Global Administrator; ServicePrincipal-B: Global Administrator`
- **Reference:** `Microsoft Learn: Best practices for Microsoft Entra roles (Service Principals mit privilegierten Rollen = Control Plane)`

**Risiko:** Wird das Secret oder Zertifikat einer App kompromittiert, kann ein Angreifer direkt administrative Kontrolle übernehmen.

**Behebung:**  
Entra Admin Center → **Roles and administrators** → Rollen-Zuordnung prüfen und auf Minimum reduzieren; wo möglich keine Service Principals dauerhaft in privilegierten Rollen belassen; Secrets/Zertifikate rotieren.

---

### 4) `SP-CRITICAL-GRAPH-PERMISSION` – Kritische Microsoft-Graph-Permissions
- **Affected:**  
  `ServicePrincipal-C`, `ServicePrincipal-B`
- **Evidence:** `Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory`
- **Reference:** `Microsoft Learn: Best practices for Microsoft Entra roles`

**Risiko:** Eine kompromittierte App kann Verzeichnisobjekte und Rollen manipulieren und sich bis zum Global Admin eskalieren.

**Behebung:**  
Entra Admin Center → **App registrations** → **API permissions** prüfen, kritische Permissions entfernen, wo nicht zwingend nötig; danach Secrets/Zertifikate rotieren.

---

## High

### 5) `LEGACY-AUTH-NOT-BLOCKED`
- **Affected:** `Alle Benutzer`
- **Evidence:** `Security Defaults: isEnabled=false; 0 CA-Policies, keine blockiert Legacy Auth für alle Benutzer`
- **Reference:** `CIS M365 5.2.2.3`
- **Note:** Exchange-seitige Einstellungen nicht über Graph prüfbar.

**Risiko:** Legacy Protokolle erleichtern Password-Spraying und umgehen oft MFA.

**Behebung:**  
Entra Admin Center → **Protection** → **Conditional Access** → **Block legacy authentication** erstellen.

---

### 6) `USER-NO-MFA`
- **Affected:** 30 aktive Benutzer, u. a.  
  `user01@contoso.onmicrosoft.com`, `user04@contoso.onmicrosoft.com`, `user05@contoso.onmicrosoft.com`, …, `user34@contoso.onmicrosoft.com`
- **Evidence:** `30 von 33 aktiven Benutzern: isMfaRegistered=false (91 %)`
- **Reference:** `CIS M365 5.2.2.2`

**Risiko:** Der Großteil der Benutzer ist bei Phishing oder Credential Stuffing ohne zweite Schutzbarriere angreifbar.

**Behebung:**  
Entra Admin Center → **Users** → **Authentication methods** → MFA-Registrierung erzwingen; zusätzlich Conditional Access für MFA.

---

## Medium

### 7) `GA-COUNT-TOO-HIGH`
- **Affected:**  
  `user05@contoso.onmicrosoft.com`, `user16@contoso.onmicrosoft.com`, `user21@contoso.onmicrosoft.com`, `user25@contoso.onmicrosoft.com`, `user27@contoso.onmicrosoft.com`, `user29@contoso.onmicrosoft.com`, `user03@contoso.onmicrosoft.com`
- **Evidence:** `7 Benutzer mit Global Administrator (Soll: 2–4); zusätzlich 2 Service Principals mit Global Administrator: ServicePrincipal-C, ServicePrincipal-B`
- **Reference:** `CIS M365 1.1.3`

**Risiko:** Zu viele Global Admins erhöhen die Chance auf Kontoübernahme und Fehlbedienung.

**Behebung:**  
Entra Admin Center → **Roles and administrators** → Global Admin-Anzahl reduzieren und Aufgaben auf geringere Rollen verteilen.

---

### 8) `USER-CONSENT-ALLOWED`
- **Affected:** `Alle Benutzer`
- **Evidence:** `permissionGrantPoliciesAssigned: ManagePermissionGrantsForSelf.microsoft-user-default-recommended, ManagePermissionGrantsForSelf.microsoft-user-default-allow-consent-apps`
- **Reference:** `CIS M365 5.1.5.1`

**Risiko:** Benutzer können täuschend echte Apps autorisieren und so Datenzugriff freigeben.

**Behebung:**  
Entra Admin Center → **Enterprise applications** → **Consent and permissions** → User Consent einschränken oder deaktivieren; Admin Consent Workflow aktivieren.

---

### 9) `GUEST-INVITE-UNRESTRICTED`
- **Affected:** `Alle Benutzer`
- **Evidence:** `allowInvitesFrom=everyone (Soll: adminsAndGuestInviters oder none)`
- **Reference:** `CIS M365 5.1.6.3`

**Risiko:** Unkontrollierte externe Einladungen erhöhen Datenexposition und Schattenzugänge.

**Behebung:**  
Entra Admin Center → **External Identities** → **External collaboration settings** → Einladungen auf Admins/Guest Inviter beschränken.

---

### 10) `PRIVILEGED-ASSIGNMENTS-TOO-MANY`
- **Affected:**  
  `user05@contoso.onmicrosoft.com`, `user16@contoso.onmicrosoft.com`, `ServicePrincipal-A`, `user21@contoso.onmicrosoft.com`, `user25@contoso.onmicrosoft.com`, `user27@contoso.onmicrosoft.com`, `user29@contoso.onmicrosoft.com`, `ServicePrincipal-C`, `user03@contoso.onmicrosoft.com`, `ServicePrincipal-B`
- **Evidence:** `10 privilegierte Rollenzuweisungen (Soll: unter 10)`
- **Reference:** `Microsoft Learn: Best practices for Microsoft Entra roles (#6)`

**Risiko:** Mehr privilegierte Zuweisungen bedeuten mehr Angriffsfläche und mehr Möglichkeiten zur Eskalation.

**Behebung:**  
Entra Admin Center → **Roles and administrators** → Zuweisungen auf das Minimum reduzieren; möglichst PIM statt Dauerzuweisung verwenden.

---

### 11) `NO-USER-RISK-POLICY`
- **Affected:** `Alle Benutzer`
- **Evidence:** `Keine aktive CA-Policy mit conditions.userRiskLevels für alle Benutzer (0 CA-Policies insgesamt)`
- **Reference:** `CIS M365 5.2.2.6`
- **Note:** Risk-basierte Conditional-Access-Policies erfordern Microsoft Entra ID P2.

**Risiko:** Riskante Konten werden nicht automatisch isoliert oder zur Passwortänderung gezwungen.

**Behebung:**  
Entra Admin Center → **Protection** → **Conditional Access** → User-Risk-Policy aktivieren; Voraussetzung: **Entra ID P2**.

---

### 12) `NO-SIGNIN-RISK-POLICY`
- **Affected:** `Alle Benutzer`
- **Evidence:** `Keine aktive CA-Policy mit conditions.signInRiskLevels für alle Benutzer (0 CA-Policies insgesamt)`
- **Reference:** `CIS M365 5.2.2.7`
- **Note:** Risk-basierte Conditional-Access-Policies erfordern Microsoft Entra ID P2.

**Risiko:** Verdächtige Anmeldungen werden nicht automatisch erkannt und abgefangen.

**Behebung:**  
Entra Admin Center → **Protection** → **Conditional Access** → Sign-in-Risk-Policy aktivieren; bei Risiko MFA oder Block erzwingen.

---

### 13) `ADMIN-INACTIVE`
- **Affected:** `user16@contoso.onmicrosoft.com`
- **Evidence:** `1 von 7 privilegierten Benutzern: 1 ohne jede aufgezeichnete Anmeldung`
- **Reference:** `Microsoft Learn: Best practices for Microsoft Entra roles (#4 Access Reviews)`
- **Note:** `signInActivity wird erst ab Entra ID P1 erfasst; „nie angemeldet“ kann auch bedeuten, dass die Anmeldung vor Beginn der Aufzeichnung lag.`

**Risiko:** Unklare oder ungenutzte privilegierte Konten können später missbraucht werden.

**Behebung:**  
Entra Admin Center → **Users** / **Privileged Identity Management** → Konten prüfen, deaktivieren oder entfernen, falls nicht benötigt.

---

## Low

### 14) `USER-APP-REGISTRATION-ALLOWED`
- **Affected:** `Alle Benutzer`
- **Evidence:** `defaultUserRolePermissions.allowedToCreateApps=true`
- **Reference:** `CIS M365 5.1.2.2`

**Risiko:** Benutzer können Apps registrieren, was Schatten-IT und missbrauchte App-Identitäten begünstigt.

**Behebung:**  
Entra Admin Center → **User settings** → **Users can register applications** deaktivieren.

---

## Informational

### 15) `AUDIT-APP-PERMISSIONS`
- **Affected:** `chat_with_entra`
- **Evidence:** `AuditLog.Read.All, Directory.Read.All, Policy.Read.All, User.Read.All`
- **Reference:** `Microsoft Learn: Best practices for Microsoft Entra roles`
- **Note:** Das Audit-Tool ist selbst ein privilegiertes Asset; kompromittiertes Secret würde Tenant-Lesezugriff ermöglichen.

### 16) `PIM-NOT-CHECKABLE`
- **Affected:** leer
- **Evidence:** `roleEligibilitySchedules: HTTP 403 – Permission RoleEligibilitySchedule.Read.Directory fehlt`
- **Reference:** `Microsoft Learn: Best practices for Microsoft Entra roles (#2 PIM)`
- **Note:** PIM erfordert außerdem Microsoft Entra ID P2.

**Wichtig:** Das bedeutet **nicht**, dass PIM korrekt umgesetzt ist, sondern nur, dass es mit der aktuellen Berechtigung **nicht prüfbar** war.

---

## Fazit
Der Audit-Lauf `20261014_192427` zeigt eine **Verschlechterung** gegenüber dem vorherigen Lauf: mehr privilegierte Zuweisungen, ein zusätzlicher inaktiver Admin, und weiterhin keine wirksame MFA-Erzwingung. Der größte Handlungsdruck liegt bei:
1. **MFA für Admins sofort erzwingen**
2. **Service Principals aus privilegierten Rollen entfernen**
3. **Global Admins und privilegierte Zuweisungen reduzieren**
4. **Legacy Auth blockieren**
5. **User Consent und Guest Invites einschränken**

Wenn du möchtest, kann ich dir daraus auch eine **priorisierte To-do-Liste für die nächsten 24 Stunden** erstellen.

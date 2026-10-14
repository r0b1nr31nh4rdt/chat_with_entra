# Audit-Zusammenfassung 20261014_191558

> Vom LLM erstellt (gpt-5.4-mini) am 2026-10-14 20:52. Maßgeblich sind die Fakten in `snapshot.json` und `changes.json` – dieser Text ist ihre Auswertung.
>
> Frage: erstelle eine zusammenfassung von dem audit 20261014_191558

---

Hier ist die Zusammenfassung für das Audit `20261014_191558`.

## Kurzfazit
- **Risiko-Score-Vergleich:** nicht verfügbar, weil `changes = null` — das ist der **erste gespeicherte Audit-Lauf**.
- **Gesamtbefund:** Der Tenant hat mehrere **kritische Schwachstellen** rund um **MFA**, **privilegierte Rollen** und **Service Principals**.
- **Ergebnis nach Severity:**
  - **critical:** 4
  - **high:** 2
  - **medium:** 5
  - **low:** 1
  - **informational:** 2

## Wichtigste Risiken
1. **Privilegierte Benutzer ohne MFA** und **MFA wird nicht erzwungen**  
2. **Service Principals in Global-Administrator-Rollen** sowie mit **kritischen Graph-Berechtigungen**
3. **Legacy Authentication nicht blockiert**
4. **Sehr viele Benutzer ohne MFA-Registrierung**
5. **Zu viele Global Administratoren**
6. **Unsichere Tenant-Einstellungen**: User Consent erlaubt, Gast-Einladungen offen, Benutzer dürfen Apps registrieren
7. **Keine Risiko-Policies** für User-Risk und Sign-in-Risk
8. **PIM-Nutzung nicht prüfbar** wegen fehlender Berechtigung im Audit-Tool

---

## Findings im Detail

### Critical

#### 1) `ADMIN-NO-MFA` – Privilegierte Benutzer ohne MFA-Registrierung
- **Affected:**  
  `user05@contoso.onmicrosoft.com`, `user21@contoso.onmicrosoft.com`, `user25@contoso.onmicrosoft.com`, `user27@contoso.onmicrosoft.com`, `user29@contoso.onmicrosoft.com`
- **Evidence:** `5 von 6 privilegierten Benutzern: isMfaRegistered=false (Rollen: Global Administrator)`
- **Reference:** `CIS M365 5.2.2.1`

**Warum ist das ein Risiko?**  
Wenn ein Angreifer ein Passwort per Phishing oder Password-Spraying erbeutet, kann er sich bei diesen Konten ohne zweite Faktor-Hürde anmelden und direkt privilegierte Änderungen im Tenant durchführen.

**Wie beheben?**  
- Entra Admin Center → **Protection** → **Conditional Access** → neue Policy für **Admins**
- MFA für privilegierte Konten erzwingen
- Vorher ein **Break-Glass-Konto** ausnehmen
- Zusätzlich die betroffenen Konten unter **Users** → **Authentication methods** zur MFA-Registrierung bringen

---

#### 2) `MFA-NOT-ENFORCED` – MFA wird für privilegierte Benutzer nicht erzwungen
- **Affected:**  
  `user05@contoso.onmicrosoft.com`, `user21@contoso.onmicrosoft.com`, `user25@contoso.onmicrosoft.com`, `user27@contoso.onmicrosoft.com`, `user29@contoso.onmicrosoft.com`, `user03@contoso.onmicrosoft.com`
- **Evidence:** `Security Defaults: isEnabled=false; 0 aktive CA-Policies mit MFA-Anforderung; 6 von 6 privilegierten Benutzern von keiner MFA-Policy erfasst – darunter 1 mit registrierter MFA, die beim Login trotzdem nicht abgefragt wird: user03@contoso.onmicrosoft.com`
- **Reference:** `CIS M365 5.2.2.1`

**Warum ist das ein Risiko?**  
Selbst ein korrekt registrierter MFA-Faktor schützt nicht, wenn keine Policy die MFA wirklich verlangt. Ein Angreifer mit gestohlenem Passwort kann sich dann ohne zweite Prüfung anmelden.

**Wie beheben?**  
- Entra Admin Center → **Protection** → **Conditional Access**
- Policy für **privileged roles / admins** erstellen
- Zugriff auf **All cloud apps** oder relevante Admin-Apps nur mit **Require multi-factor authentication**
- Security Defaults alternativ aktivieren, wenn CA nicht genutzt wird
- Break-Glass-Konto vorher sauber ausnehmen

---

#### 3) `SP-PRIVILEGED-ROLE` – Service Principals in privilegierten Directory-Rollen
- **Affected:** `ServicePrincipal-C`, `ServicePrincipal-B`
- **Evidence:** `ServicePrincipal-C: Global Administrator; ServicePrincipal-B: Global Administrator`
- **Reference:** `Microsoft Learn: Best practices for Microsoft Entra roles (Service Principals mit privilegierten Rollen = Control Plane)`

**Warum ist das ein Risiko?**  
Wenn ein Angreifer das zugehörige Secret, Zertifikat oder eine Identität dieser App kompromittiert, kann er direkt Control-Plane-Zugriff erlangen und den Tenant administrieren.

**Wie beheben?**  
- Entra Admin Center → **Roles and administrators**
- Prüfen, ob die App-Rollen wirklich nötig sind
- Service Principals möglichst **nicht** dauerhaft in Global Admin belassen
- Falls unvermeidbar: streng absichern, Secret/Zertifikate rotieren, Zugriff minimieren
- Wo möglich stattdessen **least privilege** und geeignete App-Rollen verwenden

---

#### 4) `SP-CRITICAL-GRAPH-PERMISSION` – Service Principals mit kritischen Microsoft-Graph-Permissions
- **Affected:** `ServicePrincipal-C`, `ServicePrincipal-B`
- **Evidence:** `ServicePrincipal-C: Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory; ServicePrincipal-B: Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory – jede dieser Permissions erlaubt die Eskalation bis Global Admin`
- **Reference:** `Microsoft Learn: Best practices for Microsoft Entra roles`

**Warum ist das ein Risiko?**  
Mit diesen Berechtigungen kann ein kompromittierter App-Zugang Verzeichnisobjekte ändern und Rollen manipulieren — bis hin zur vollständigen Eskalation.

**Wie beheben?**  
- Entra Admin Center → **App registrations** → betroffene App
- Unter **API permissions** die Berechtigungen prüfen und auf das Minimum reduzieren
- `Directory.ReadWrite.All` und `RoleManagement.ReadWrite.Directory` entfernen, wenn fachlich möglich
- Danach Secret/Zertifikat rotieren und Nutzung überwachen

---

### High

#### 5) `LEGACY-AUTH-NOT-BLOCKED` – Legacy Authentication wird nicht blockiert
- **Affected:** `Alle Benutzer`
- **Evidence:** `Security Defaults: isEnabled=false; 0 CA-Policies, keine blockiert Legacy Auth für alle Benutzer`
- **Reference:** `CIS M365 5.2.2.3`
- **Note:** `Exchange-seitige Einstellungen nicht über Graph prüfbar.`

**Warum ist das ein Risiko?**  
Legacy Protokolle unterstützen oft kein modernes MFA und sind anfälliger für Password-Spraying und andere Auth-Angriffe.

**Wie beheben?**  
- Entra Admin Center → **Protection** → **Conditional Access**
- Policy erstellen: **Block legacy authentication**
- Vorher betroffene Alt-Clients identifizieren, damit nichts Ungewolltes ausfällt
- Falls genutzt, Exchange-/SMTP-Altlasten separat prüfen

---

#### 6) `USER-NO-MFA` – Benutzer ohne MFA-Registrierung
- **Affected:** 30 Benutzer, u. a.  
  `user01@contoso.onmicrosoft.com`, `user04@contoso.onmicrosoft.com`, `user05@contoso.onmicrosoft.com`, …, `user34@contoso.onmicrosoft.com`
- **Evidence:** `30 von 33 aktiven Benutzern: isMfaRegistered=false (91 %)`
- **Reference:** `CIS M365 5.2.2.2`

**Warum ist das ein Risiko?**  
Ohne MFA-Registrierung ist der Tenant bei Passwortdiebstahl, Phishing und Credential Stuffing deutlich gefährdeter.

**Wie beheben?**  
- Entra Admin Center → **Users** → **Authentication methods**
- MFA-Registrierung forcieren
- Conditional Access für Benutzer mit **Require multi-factor authentication**
- Für besonders kritische Konten zuerst Admins und Break-Glass sauber trennen

---

### Medium

#### 7) `GA-COUNT-TOO-HIGH` – Zu viele Global Administrators
- **Affected:**  
  `user05@contoso.onmicrosoft.com`, `user21@contoso.onmicrosoft.com`, `user25@contoso.onmicrosoft.com`, `user27@contoso.onmicrosoft.com`, `user29@contoso.onmicrosoft.com`, `user03@contoso.onmicrosoft.com`
- **Evidence:** `6 Benutzer mit Global Administrator (Soll: 2–4); zusätzlich 2 Service Principals mit Global Administrator: ServicePrincipal-C, ServicePrincipal-B`
- **Reference:** `CIS M365 1.1.3`

**Warum ist das ein Risiko?**  
Je mehr Global Admins existieren, desto größer ist die Angriffsfläche für Kontoübernahmen und Fehlkonfigurationen.

**Wie beheben?**  
- Entra Admin Center → **Roles and administrators** → **Global Administrator**
- Anzahl auf das Minimum reduzieren
- Admin-Aufgaben auf passendere Rollen verteilen
- Falls möglich PIM einsetzen

---

#### 8) `USER-CONSENT-ALLOWED` – Benutzer dürfen Apps selbst Zugriff auf Unternehmensdaten erteilen
- **Affected:** `Alle Benutzer`
- **Evidence:** `permissionGrantPoliciesAssigned: ManagePermissionGrantsForSelf.microsoft-user-default-recommended, ManagePermissionGrantsForSelf.microsoft-user-default-allow-consent-apps`
- **Reference:** `CIS M365 5.1.5.1`

**Warum ist das ein Risiko?**  
Angreifer können über eine täuschend echte App Zustimmung erschleichen und so auf Daten zugreifen, ohne ein Passwort direkt zu stehlen.

**Wie beheben?**  
- Entra Admin Center → **Enterprise applications** → **Consent and permissions**
- User Consent einschränken oder deaktivieren
- Admin Consent Workflow aktivieren
- Nur vertrauenswürdige Publisher zulassen

---

#### 9) `GUEST-INVITE-UNRESTRICTED` – Gast-Einladungen nicht beschränkt
- **Affected:** `Alle Benutzer`
- **Evidence:** `allowInvitesFrom=everyone (Soll: adminsAndGuestInviters oder none)`
- **Reference:** `CIS M365 5.1.6.3`

**Warum ist das ein Risiko?**  
Jeder Benutzer kann externe Gäste einladen, was unkontrollierte externe Zusammenarbeit und Datenexposition begünstigt.

**Wie beheben?**  
- Entra Admin Center → **External Identities** → **External collaboration settings**
- `Allow invitations from` auf **Admins and guest inviters** oder **Only admins**
- Zusätzlich Gastzugriffe regelmäßig prüfen

---

#### 10) `NO-USER-RISK-POLICY` – Keine User-Risk-Policy aktiv
- **Affected:** `Alle Benutzer`
- **Evidence:** `Keine aktive CA-Policy mit conditions.userRiskLevels für alle Benutzer (0 CA-Policies insgesamt)`
- **Reference:** `CIS M365 5.2.2.6`
- **Note:** `Risk-basierte Conditional-Access-Policies erfordern Microsoft Entra ID P2.`

**Warum ist das ein Risiko?**  
Kompromittierte Konten werden bei auffälligem Risiko nicht automatisch extra abgesichert oder blockiert.

**Wie beheben?**  
- Entra Admin Center → **Protection** → **Conditional Access**
- User-Risk-Policy für hohe Risiken aktivieren
- Aktion typischerweise: **Require password change** oder Zugriff blockieren
- Voraussetzung: **Entra ID P2**

---

#### 11) `NO-SIGNIN-RISK-POLICY` – Keine Sign-in-Risk-Policy aktiv
- **Affected:** `Alle Benutzer`
- **Evidence:** `Keine aktive CA-Policy mit conditions.signInRiskLevels für alle Benutzer (0 CA-Policies insgesamt)`
- **Reference:** `CIS M365 5.2.2.7`
- **Note:** `Risk-basierte Conditional-Access-Policies erfordern Microsoft Entra ID P2.`

**Warum ist das ein Risiko?**  
Verdächtige Anmeldungen, z. B. aus ungewöhnlichen Ländern oder mit gestohlenen Sessions, werden nicht automatisch abgefangen.

**Wie beheben?**  
- Entra Admin Center → **Protection** → **Conditional Access**
- Sign-in-Risk-Policy aktivieren
- Für mittlere/hohe Risiken MFA oder Block erzwingen
- Voraussetzung: **Entra ID P2**

---

### Low

#### 12) `USER-APP-REGISTRATION-ALLOWED` – Benutzer dürfen Anwendungen registrieren
- **Affected:** `Alle Benutzer`
- **Evidence:** `defaultUserRolePermissions.allowedToCreateApps=true`
- **Reference:** `CIS M365 5.1.2.2`

**Warum ist das ein Risiko?**  
Benutzer können eigene Apps registrieren, was für Schatten-IT, Fehlkonfigurationen oder missbrauchte App-Identitäten genutzt werden kann.

**Wie beheben?**  
- Entra Admin Center → **User settings**
- **Users can register applications** deaktivieren
- Stattdessen zentrale App-Registrierung über Admins oder kontrollierte Gruppen

---

### Informational

#### 13) `AUDIT-APP-PERMISSIONS` – Berechtigungen der eigenen Audit-App
- **Affected:** `chat_with_entra`
- **Evidence:** `chat_with_entra: AuditLog.Read.All, Directory.Read.All, Policy.Read.All, User.Read.All (nur Leserechte, aber tenant-weiter Lesezugriff)`
- **Reference:** `Microsoft Learn: Best practices for Microsoft Entra roles`
- **Note:** `Das Audit-Tool ist selbst ein privilegiertes Asset: wer das Client Secret erbeutet, kann den gesamten Tenant auslesen.`

**Warum ist das ein Risiko?**  
Wenn das Client Secret der Audit-App gestohlen wird, kann ein Angreifer Tenant-Daten auslesen und damit Aufklärung und Folgeangriffe erleichtern.

**Wie beheben?**  
- App-Secret sicher verwalten und regelmäßig rotieren
- Möglichkeit auf **Zertifikatsauthentifizierung** prüfen
- Berechtigungen auf das Minimum prüfen

---

#### 14) `PIM-NOT-CHECKABLE` – PIM-Nutzung nicht prüfbar
- **Affected:** leer
- **Evidence:** `roleEligibilitySchedules: HTTP 403 – Permission RoleEligibilitySchedule.Read.Directory fehlt`
- **Reference:** `Microsoft Learn: Best practices for Microsoft Entra roles (#2 PIM)`
- **Note:** `PIM erfordert außerdem Microsoft Entra ID P2.`

**Bedeutung**  
Der Audit konnte nicht verifizieren, ob PIM korrekt genutzt wird. Das ist **kein Beleg für gutes PIM**, sondern ein **Prüflimit durch fehlende Berechtigung**.

**Wie beheben?**  
- Der Audit-App die nötige Leseberechtigung für PIM geben
- Danach PIM-Status erneut prüfen
- Falls gewünscht, PIM in Entra Admin Center unter **Privileged Identity Management** konfigurieren

---

## Zusammenfassung in einem Satz
Der Tenant ist aktuell vor allem wegen **fehlender MFA-Erzwingung**, **zu vieler privilegierter Konten** und **kritisch privilegierter Service Principals** stark gefährdet.

Wenn du möchtest, kann ich dir daraus als Nächstes auch eine **Management-Zusammenfassung in 5 Stichpunkten** oder eine **priorisierte Remediation-Liste nach Reihenfolge** erstellen.

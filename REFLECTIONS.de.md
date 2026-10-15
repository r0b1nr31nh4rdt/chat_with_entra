# Reflexion: Ein KI-Agent für Identity Security

## Was ich gebaut habe

Ich habe einen Python-Agenten gebaut, der Fragen zu einem Entra-ID-Tenant beantwortet und ihn auf typische Fehlkonfigurationen prüft. Das Modell (gpt-5.4-mini) läuft in Azure AI Foundry im Cybersteps-Tenant. Die Daten kommen live per Microsoft Graph aus dem Pearson-Lab-Tenant. Mein lokales Skript ist die einzige Verbindung zwischen beiden: Die Tenants sprechen nie direkt miteinander, und das Modell sieht nie die Graph-Zugangsdaten, sondern nur die Ergebnisse, die mein Code zurückgibt. Die Graph-Abfragen stelle ich über einen eigenen MCP-Server als Tools bereit. Die Audit-Checks sind deterministische Python-Funktionen. Das Modell wählt Tools aus, erklärt die Findings und schlägt Maßnahmen vor.

## 1. Das Modell sollte nicht zählen

Die deutlichste Erkenntnis kam früh. Auf die Frage „Wie viele Admins gibt es?“ kam: „8 Global-Administrator-Mitglieder – davon 7 Benutzer und 2 Service Principals.“ 7 + 2 ergibt aber nicht 8. Das Log zeigte, dass mein Tool genau 8 Einträge geliefert hatte (6 Benutzer, 2 Service Principals) und dazu `count: 8`. Die Gesamtzahl hat das Modell richtig übernommen. Die Aufteilung nach Typ hat es selbst gezählt und sich dabei verzählt. Vermutlich hat es die Zahl 7 aus einem zweiten Tool übernommen, dem MFA-Report, wo „Admin“ etwas anderes bedeutet.

**Lösung:** Alle Aggregationen passieren jetzt im Code (`count`, `by_type`). Das Modell liest die Zahlen nur noch vor.
**Erkenntnis:** In einem Audit ist eine falsche Zahl schlimmer als keine. Was sich deterministisch berechnen lässt, sollte auch so berechnet werden.

## 2. „Admin“ ist kein eindeutiger Begriff

Zwei Tools haben zwei verschiedene Definitionen verwendet. `get_role_members` hat Global Administrators gezählt, inklusive Service Principals. Das Feld `isAdmin` im MFA-Report zählt dagegen Benutzer mit *irgendeiner* privilegierten Rolle und lässt Service Principals weg. Beide Antworten waren richtig, aber sie haben unterschiedliche Fragen beantwortet, und das Modell hat sie vermischt, ohne das zu sagen.

Mit niedrigerer Reasoning-Stufe (`effort: low`) verhielt sich das Modell anders: Statt zu raten, fragte es nach, ob ich Global Administrators oder alle Admin-Rollen meine. Das ist eigentlich das sauberere Verhalten, für ein Audit-Tool aber unpraktisch. Statt die Reasoning-Stufe zu erhöhen, habe ich es an zwei Stellen gelöst:
- Der System Prompt legt jetzt fest, was „Admin“ standardmäßig bedeutet, und weist das Modell an, seine Annahme zu nennen und weiterzumachen.
- Ein eigenes Tool (`get_privileged_role_assignments`) beantwortet die Frage direkt, mit Zählung pro Rolle.

**Erkenntnis:** Mehrdeutigkeit löst man zuverlässiger über Tool-Design und klare Definitionen als über ein „klügeres“ Modell. Ich bin bei `low` geblieben: Bei eindeutigen Fragen ist die Qualität gleich, und die Antworten kommen spürbar schneller.

## 3. „Registriert“ heißt nicht „erzwungen“

Der Tenant hat keine Conditional-Access-Policies, und die Security Defaults sind deaktiviert. 5 von 6 menschlichen Global Administrators haben keine MFA-Methode registriert. Aber auch der eine Admin, der MFA registriert *hat*, ist nicht wirklich geschützt, denn nichts verlangt MFA bei der Anmeldung. Ein naiver Check („ist MFA registriert?“) würde dieses Konto als in Ordnung einstufen. Ich habe das deshalb in zwei getrennte Findings aufgeteilt: MFA nicht registriert und MFA nicht erzwungen.

Ähnlich ist es bei Legacy Authentication. Aus Sicht von Entra ist sie nicht blockiert. Sie könnte aber auf Exchange-Online-Seite deaktiviert sein, und das sieht Graph nicht. Das ehrliche Finding lautet deshalb „in Entra nicht blockiert; Exchange-Einstellungen nicht prüfbar“ und nicht einfach „erlaubt“.

**Erkenntnis:** Das Schwierige beim Identity-Audit ist nicht das Abrufen der Daten, sondern zu wissen, was die Daten *nicht* belegen.

## 4. Einzelchecks vs. Angriffspfade (EntraGoat Szenario 1)

**Vorgehen:** Ich habe zuerst ein Baseline-Audit gemacht, dann EntraGoat-Szenario 1 deployt, ein zweites Audit laufen lassen und beide automatisch verglichen (`compare_audits`). Die Ground Truth habe ich aus der offiziellen EntraGoat-Lösung genommen und nicht selbst erarbeitet.

**Die Fehlkonfiguration:** Der Finance-Mitarbeiter `david.martinez`, ein normaler Benutzer ohne Admin-Rolle, ist Owner des Service Principals „Finance Analytics Dashboard“. Dieser SP hat die Rolle *Privileged Authentication Administrator* (PAA), eine der am höchsten privilegierten Rollen in Entra, die auch Konten von Global Administrators beeinflussen kann. Wer einen Service Principal besitzt, kontrolliert faktisch auch dessen Rechte. Das Risiko entsteht also aus der **Kombination** zweier Einstellungen, die einzeln harmlos wirken können: Ownership durch einen normalen Benutzer und eine privilegierte Rolle am SP.

**Was der Agent gefunden hat:** die privilegierte Rolle. `SP-PRIVILEGED-ROLE` listet im zweiten Audit neu „Finance Analytics Dashboard: Privileged Authentication Administrator“. Der Vorher/Nachher-Vergleich (`changed_findings`) hat diese Änderung in Sekunden isoliert. Manuell hätte ich dafür alle Rollen und ihre Mitglieder im Portal durchgehen müssen.

**Was der Agent übersehen hat:**
- **Die Ownership, also die eigentliche Schwachstelle.** Kein Check fragt, *wer* einen privilegierten Service Principal kontrolliert. Dass ein normaler Finance-Benutzer über den SP faktisch an hochprivilegierte Rechte kommt, steht nirgends im Report.
- **Die Einordnung der Rolle.** Meine Severity-Logik stuft nur Global Administrator als *critical* ein. Das Finding ist nur deshalb critical, weil im selben Finding zwei SPs mit Global Admin stehen. Für sich allein wäre der neue SP nur als *high* eingestuft worden, obwohl PAA in der Wirkung nahe an Global Admin liegt.
- **Credentials am Service Principal.** `check_app_credentials` prüft nur Secrets an *Application*-Objekten. Credentials, die direkt am Service Principal hinterlegt sind, sieht der Check nicht. Ein solches zusätzliches Secret an einem privilegierten SP würde mein Audit also nicht melden.

**Rauschen:** Die beiden *neuen* Findings (`PRIVILEGED-ASSIGNMENTS-TOO-MANY`, `ADMIN-INACTIVE`) und die Erweiterungen bei `ADMIN-NO-MFA`, `MFA-NOT-ENFORCED` und `GA-COUNT-TOO-HIGH` gehen alle auf den Flag-Admin `EntraGoat-admin-s1` zurück bzw. auf das Überschreiten eines Schwellwerts (8 → 10 privilegierte Zuweisungen). Der Risiko-Score stieg von 66 auf 72, und zwar **ausschließlich durch diese Nebeneffekte**. Die eigentlich relevante Änderung, der neue SP mit PAA, hat den Score überhaupt nicht verändert, weil sie nur als weiterer Eintrag in einem bestehenden Finding auftauchte. Ein aggregierter Score ist für Angriffspfade also ein schlechter Indikator.

**Das LLM:** Die Zusammenfassung hat Zahlen und Namen korrekt wiedergegeben. Da sie aus dem Code kamen, gab es hier keine Halluzination. Die Risikoerklärung für den neuen SP blieb aber generisch („wenn das Secret kompromittiert wird …“). Die Verbindung „normaler Benutzer besitzt hochprivilegierten SP“ hat das Modell nicht hergestellt, weil die Ownership in den Daten gar nicht vorkam. Den Flag-Admin hat es als „zusätzlichen inaktiven Admin“ gemeldet, ohne zu erkennen, dass er zum Szenario gehört. Das Modell kann nur verknüpfen, was die Tools liefern.

**Verbesserung:** Ich habe einen neuen Check `check_sp_ownership` ergänzt. Er fragt für jeden Service Principal mit privilegierter Rolle die Owner ab und meldet Owner ohne eigene Admin-Rolle als *critical*. Das dritte Audit (15.10.) zeigt das Ergebnis: Das neue Finding `SP-OWNER-NOT-ADMIN` nennt genau `david.martinez` als Owner von „Finance Analytics Dashboard (Privileged Authentication Administrator)“. Damit stehen beide Glieder der Kette im Report. Auch die LLM-Erklärung wurde dadurch konkret: Behebung über *Enterprise applications → Owners*, Owner-Liste reduzieren, Credentials des SP rotieren. Das Modell konnte die Verbindung herstellen, sobald die Daten dafür vorlagen.

Bemerkenswert: Der Score blieb trotz neuem *critical*-Finding bei 72 („unverändert“). Das ist gewollt, denn neue Checks werden beim Vergleich aus dem Score ausgeschlossen, damit alter und neuer Lauf vergleichbar bleiben. Es zeigt aber noch einmal, dass ein einzelner Score ohne Kontext in die Irre führen kann.

**Noch offen:** Owner der zugehörigen *App-Registrierung* werden noch nicht geprüft, ebenso wenig Credentials direkt am Service Principal. PAA wird in der Severity-Logik noch nicht als Global-Admin-gleichwertig behandelt.

## 5. MCP: eine Architekturentscheidung

Die Aufgabe schlug vor, einen MCP-Server für Entra zu verwenden. Microsofts MCP Server for Enterprise unterstützt nur delegierte Berechtigungen, läuft also als angemeldeter Benutzer. Mein Agent arbeitet dagegen mit App-only-Zugriff. Ich habe deshalb meine vorhandenen Tools in einen eigenen MCP-Server (Python SDK) verpackt. Weil die Tools schon von der Chat-Schleife getrennt waren, bestand der Server nur aus wenigen Zeilen. Praktische Stolperfallen:
- Im Python-MCP-SDK 2.x heißt `FastMCP` jetzt `MCPServer`. Die meisten Tutorials im Netz funktionieren deshalb nicht mehr wie beschrieben.
- Parameter-Schemas werden aus Type Hints erzeugt. Ohne sie wurde ein `bool`-Parameter zu einem `string`.
- Beim stdio-Transport ist stdout der Protokollkanal. Ein einziges `print()` in einem Tool bricht die Verbindung.
- Das Standard-Logging des Servers auf INFO-Level, inklusive der HTTP-Logs des Azure SDK, hat das Terminal geflutet und musste umgeleitet werden.

MCP selbst hat keine spürbare Verzögerung verursacht. Die Wartezeit entsteht durch die LLM-Runden, mindestens zwei pro Frage mit Tool-Nutzung.

## 6. Das Audit-Tool ist selbst ein privilegiertes Asset

Meine App-Registrierung hat Anwendungsberechtigungen wie `Directory.Read.All` und `AuditLog.Read.All`. Wer das Client Secret besitzt, kann den gesamten Tenant lesen, ohne Benutzer, ohne MFA und ohne Conditional Access. Genau diese Art Service Principal soll der Agent eigentlich melden. Praktisch heißt das:
- Secrets nur in `.env`, nie im Repo oder in den Logs.
- Nur lesende Berechtigungen. So kann selbst ein vollständig manipuliertes Modell nur lesen und nie etwas ändern.
- Die Sicherheitsgrenze liegt im Code und in den Graph-Berechtigungen, nicht im Prompt.

## 7. Kleinere Beobachtungen

- **Logging war unverzichtbar.** Ohne das JSONL-Log aller Requests, Tool-Aufrufe und Ergebnisse hätte ich den Zählfehler nicht gefunden. Das Log ist auch der Beleg für diese Reflexion.
- **Erst die Ground Truth.** Bevor ich das Modell angebunden habe, habe ich die Rohdaten abgerufen und die erwarteten Antworten notiert (`notes.md`). Ohne das wären mir die falschen Zahlen gar nicht aufgefallen.
- **Report-Daten können verzögert sein.** Der MFA-Registrierungsreport ist nicht zwingend in Echtzeit aktuell. Neue Änderungen tauchen deshalb eventuell nicht sofort auf.
- **Modell-Lebenszyklus.** gpt-4o war in Azure Foundry schon ausgemustert, als das Projekt begann. Die Modellwahl ist eine betriebliche Abhängigkeit und keine einmalige Entscheidung.

## Fazit

Ein LLM ist eine gute Schnittstelle zu Identitätsdaten: Es übersetzt Fragen in die richtigen Abfragen und erklärt Risiken verständlich. Die Erkennung selbst muss aber deterministisch und überprüfbar im Code passieren, denn das Modell zählt unzuverlässig und kann nur verknüpfen, was die Tools ihm liefern. EntraGoat hat gezeigt, wo die eigentliche Grenze liegt: Mein Agent hat zunächst nur die privilegierte Rolle gefunden, aber nicht die Ownership, die daraus erst ein Risiko macht. Erst ein zusätzlicher Check für diese Beziehung hat den Pfad sichtbar gemacht. Gefährlich wird es meist nicht durch eine einzelne Fehlkonfiguration, sondern durch die Beziehung zwischen Objekten. Ein brauchbarer Identity-Security-Agent muss deshalb Beziehungen abfragen können, nicht nur Eigenschaften, und der Mensch muss weiterhin wissen, was die Daten *nicht* zeigen.
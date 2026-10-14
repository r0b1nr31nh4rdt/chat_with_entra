# Reflexion: Ein KI-Agent für Identity Security

**Deutsch** · [English](REFLECTIONS.md)

*Entwurf. Die mit **[TODO]** markierten Abschnitte brauchen noch meine eigenen Beobachtungen aus dem EntraGoat-Durchlauf.*

## Was ich gebaut habe

Ich habe einen Python-Agenten gebaut, der Fragen zu einem Entra-ID-Tenant beantwortet und ihn auf typische Fehlkonfigurationen prüft. Das Modell (gpt-5-mini) läuft in Azure AI Foundry im Cybersteps-Tenant. Die Daten kommen live per Microsoft Graph aus dem Pearson-Lab-Tenant. Mein lokales Skript ist die einzige Verbindung zwischen beiden: Die Tenants sprechen nie direkt miteinander, und das Modell sieht nie die Graph-Zugangsdaten, sondern nur die Ergebnisse, die mein Code zurückgibt. Die Graph-Abfragen stelle ich über einen eigenen MCP-Server als Tools bereit. Die Audit-Checks sind deterministische Python-Funktionen. Das Modell wählt Tools aus, erklärt die Findings und schlägt Maßnahmen vor.

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

## 4. Einzelchecks vs. Angriffspfade

**[TODO – nach Szenario 1 ausfüllen]**
- Was hat der Agent mit den vorhandenen Checks gefunden?
- Was hat er übersehen, und warum? Meine Erwartung: EntraGoat-Pfade sind *Ketten* (z. B. ein normaler Benutzer ist Owner eines Service Principals, der eine gefährliche Berechtigung hat). Checks, die immer nur ein Objekt betrachten, sehen die gefährliche Berechtigung, aber nicht, wer sie kontrolliert.
- Welches Tool habe ich ergänzt, um die Lücke zu schließen (z. B. Owner privilegierter Service Principals), und hat es funktioniert?
- Ein konkretes Beispiel, wo der Agent schneller war als eine manuelle Suche, und eines, wo er falsch lag oder halluziniert hat (mit Logauszug).

Hinweis für den Vergleich: Jedes EntraGoat-Szenario legt einen eigenen Global Administrator ohne MFA an, der die Flag enthält. Der Agent meldet diese sofort als „mehr Global Admins ohne MFA“. Sie sind aber das *Ziel* des Angriffs, nicht die Schwachstelle. Mehr Findings heißen nicht, dass der Agent den eigentlichen Angriffspfad gefunden hat.

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

**[TODO – 3–4 Sätze in meinen eigenen Worten]** Vorschlag für die Richtung: Ein LLM ist nützlich als Schnittstelle zu Identitätsdaten und um Risiken verständlich zu erklären. Die Erkennung selbst muss deterministisch und überprüfbar sein, und der Mensch muss weiterhin wissen, was die Daten *nicht* zeigen.
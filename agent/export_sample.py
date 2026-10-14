# export_sample.py
# Exportiert Audit-Läufe anonymisiert nach sample_reports/ (Beispiel fürs Repo)
#   python export_sample.py <id> [<id> ...]
#
# Echte Namen werden deterministisch durch Pseudonyme ersetzt – über alle Dateien und Läufe gleich,
# damit Snapshot, Vergleich und Summary zusammenpassen. Danach prüft ein Leak-Check, ob noch
# ein Originalwert im Export steht; dann wird abgebrochen und nichts geschrieben.

import json
import re
import sys
from pathlib import Path

from tools.history import AUDITS_DIR, list_snapshots

SAMPLE_DIR = AUDITS_DIR.parent / "sample_reports"
DATA_DIR = Path(__file__).parent / "data"
FILES = ("snapshot.json", "changes.json", "summary.md")

DOMAIN = "contoso.onmicrosoft.com"
KEEP = {"Alle Benutzer", "Alle Mitglieder", "chat_with_entra"}  # generisch bzw. eigene App (= Repo-Name)
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.onmicrosoft\.com", re.IGNORECASE)
TENANT_DOMAIN = re.compile(r"\b([\w-]+)\.onmicrosoft\.com\b", re.IGNORECASE)
GUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)


def _letters(n):
    return chr(ord("A") + n) if n < 26 else f"{n + 1:02d}"


def _build_mapping(runs):
    """Original → Pseudonym, aus Tenant-Daten (falls geladen) und den Findings der Läufe."""
    emails, names, sps, apps = set(), {}, set(), set()

    users = DATA_DIR / "users.json"
    if users.exists():
        for u in json.loads(users.read_text(encoding="utf-8")):
            if u.get("userPrincipalName"):
                emails.add(u["userPrincipalName"].lower())
                if u.get("displayName"):
                    names[u["userPrincipalName"].lower()] = u["displayName"]
    apps_file = DATA_DIR / "applications.json"
    if apps_file.exists():
        apps |= {a["displayName"] for a in json.loads(apps_file.read_text(encoding="utf-8"))}

    texts = []
    for run in runs:
        for name in FILES:
            path = AUDITS_DIR / run / name
            if path.exists():
                texts.append(path.read_text(encoding="utf-8"))
        for f in json.loads((AUDITS_DIR / run / "snapshot.json").read_text(encoding="utf-8"))["findings"]:
            for a in f["affected"]:
                if EMAIL.fullmatch(a):
                    emails.add(a.lower())
                elif a in KEEP:
                    continue
                elif f["id"].startswith("APP-SECRET"):
                    apps.add(a)
                else:
                    sps.add(a)  # SP-*, PRIVILEGED-ASSIGNMENTS-TOO-MANY: nicht-Benutzer = Service Principals
    for t in texts:
        emails |= {m.lower() for m in EMAIL.findall(t)}

    mapping = {}
    for i, e in enumerate(sorted(emails), 1):
        mapping[e] = f"user{i:02d}@{DOMAIN}"
        if e in names and names[e] not in KEEP:
            mapping[names[e]] = f"User {i:02d}"
    for i, sp in enumerate(sorted(sps - KEEP, key=str.lower)):
        mapping[sp] = f"ServicePrincipal-{_letters(i)}"
    for i, app in enumerate(sorted(apps - KEEP - sps, key=str.lower)):
        mapping[app] = f"App-{_letters(i)}"
    tenants = {m.lower() for t in texts for m in TENANT_DOMAIN.findall(t)} - {"contoso"}
    return mapping, tenants


def anonymize(text, mapping, tenants):
    # Längste Werte zuerst, damit z. B. eine UPN nicht teilweise durch einen kürzeren Namen ersetzt wird
    for original in sorted(mapping, key=len, reverse=True):
        text = re.sub(re.escape(original), mapping[original], text, flags=re.IGNORECASE)
    text = TENANT_DOMAIN.sub(DOMAIN, text)
    for t in tenants:
        text = re.sub(re.escape(t), "contoso", text, flags=re.IGNORECASE)
    return GUID.sub("00000000-0000-0000-0000-000000000000", text)


def _leaks(text, mapping, tenants):
    lower = text.lower()
    found = [o for o in list(mapping) + list(tenants) if o.lower() in lower]
    found += [e for e in EMAIL.findall(text) if not e.lower().endswith("@" + DOMAIN)]
    return found


def main(runs):
    unknown = [r for r in runs if r not in list_snapshots()]
    if not runs or unknown:
        sys.exit(f"Unbekannte Läufe: {unknown}. Vorhanden: {', '.join(list_snapshots())}" if unknown else __doc__ or "Läufe angeben.")

    mapping, tenants = _build_mapping(runs)
    out = {}
    for run in runs:
        for name in FILES:
            path = AUDITS_DIR / run / name
            if not path.exists():
                continue
            text = anonymize(path.read_text(encoding="utf-8"), mapping, tenants)
            if leaks := _leaks(text, mapping, tenants):
                sys.exit(f"Abbruch – {run}/{name} enthält noch Originalwerte: {sorted(set(leaks))}")
            out[SAMPLE_DIR / run / name] = text

    for path, text in out.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"{path.relative_to(SAMPLE_DIR.parent)}")
    print(f"{len(mapping)} Namen pseudonymisiert, Tenant-Domain → {DOMAIN}, Leak-Check bestanden.")


if __name__ == "__main__":
    main(sys.argv[1:])

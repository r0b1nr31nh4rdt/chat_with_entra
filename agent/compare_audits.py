# compare_audits.py
# Vergleicht zwei gespeicherte Audit-Snapshots und legt das Ergebnis in history/ ab
#   python compare_audits.py                  → die letzten beiden Snapshots
#   python compare_audits.py <alt> <neu>      → bestimmte Snapshots (IDs: YYYYMMDD_HHMMSS)
#   python compare_audits.py --list           → vorhandene Snapshots

import sys

from tools.history import compare_audits, list_snapshots

args = sys.argv[1:]
if args == ["--list"]:
    print("\n".join(list_snapshots()) or "Keine Snapshots vorhanden.")
    sys.exit()

r = compare_audits(*args)
if "error" in r:
    sys.exit(r["error"])

s = r["score"]
print(f"{r['old']} → {r['new']}")
print(f"Risiko-Score: {s['old']} → {s['new']} ({s['delta']:+d}) – {s['verdict']}")
if s["checks_excluded"]:
    print(f"  (nicht im Score, da nicht in beiden Audits erfolgreich: {', '.join(s['checks_excluded'])})")
print("Pro Severity:", ", ".join(f"{k} {v:+d}" for k, v in r["summary_delta"].items() if v))
for label, key in (("Neu", "new_findings"), ("Behoben", "resolved_findings")):
    for f in r[key]:
        print(f"  {label}: [{f['severity']}] {f['id']} – {f['title']}")
for f in r["not_checked"]:
    print(f"  Nicht geprüft (Check fehlgeschlagen): {f['id']} ({f['check']})")
for c in r["changed_findings"]:
    details = [c.get("severity") and f"Severity {c['severity']}",
               c.get("affected_added") and f"+ {', '.join(c['affected_added'])}",
               c.get("affected_removed") and f"− {', '.join(c['affected_removed'])}"]
    print(f"  Verändert: {c['id']}: {'; '.join(d for d in details if d)}")

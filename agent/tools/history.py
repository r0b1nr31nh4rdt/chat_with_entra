# tools/history.py
# Audit-Verlauf: Snapshots in reports/ sind reine Zustandsaufnahmen.
# Der Vergleich zweier Snapshots ist ein eigener Vorgang und landet in history/ (wie ein git diff).

import json
from pathlib import Path

ROOT = Path(__file__).parents[2]
REPORTS_DIR = ROOT / "reports"
HISTORY_DIR = ROOT / "history"

# Risikopunkte pro Finding nach Severity – die Anzahl betroffener Objekte zählt bewusst nicht,
# sonst überdeckt z. B. „40 Benutzer ohne MFA“ alle anderen Findings
SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 3, "low": 1, "informational": 0}


def _path(snapshot_id):
    return REPORTS_DIR / f"audit_{snapshot_id}.json"


def list_snapshots():
    """Snapshot-IDs (Zeitstempel YYYYMMDD_HHMMSS), älteste zuerst."""
    return sorted(p.stem.removeprefix("audit_") for p in REPORTS_DIR.glob("audit_*.json"))


def save_snapshot(audit):
    """Speichert ein Audit-Ergebnis unverändert als Snapshot und liefert die Snapshot-ID."""
    snapshot_id = audit["timestamp"].replace("-", "").replace(":", "").replace("T", "_")
    REPORTS_DIR.mkdir(exist_ok=True)
    _path(snapshot_id).write_text(json.dumps(audit, indent=2, ensure_ascii=False), encoding="utf-8")
    return snapshot_id


def _load_snapshot(snapshot_id):
    return json.loads(_path(snapshot_id).read_text(encoding="utf-8"))


def _ok_checks(audit):
    return set(audit["checks_run"]) - {e["check"] for e in audit["errors"]}


def risk_score(audit, checks=None):
    """Summe der Severity-Gewichte; mit checks nur Findings dieser Checks."""
    return sum(SEVERITY_WEIGHTS[f["severity"]] for f in audit["findings"] if checks is None or f["check"] in checks)


def _diff(old, new):
    before = {f["id"]: f for f in old["findings"]}
    after = {f["id"]: f for f in new["findings"]}
    # Findings eines im neuen Lauf fehlgeschlagenen Checks gelten nicht als behoben – der Check hat nur nichts geliefert
    failed = {e["check"] for e in new["errors"]}
    gone = before.keys() - after.keys()

    changed = []
    for id_ in sorted(before.keys() & after.keys()):
        b, a = before[id_], after[id_]
        entry = {"id": id_}
        if b["severity"] != a["severity"]:
            entry["severity"] = f"{b['severity']} → {a['severity']}"
        if added := sorted(set(a["affected"]) - set(b["affected"])):
            entry["affected_added"] = added
        if removed := sorted(set(b["affected"]) - set(a["affected"])):
            entry["affected_removed"] = removed
        if len(entry) > 1:
            changed.append(entry)

    return {
        "new_findings": [{"id": i, "severity": after[i]["severity"], "title": after[i]["title"]} for i in sorted(after.keys() - before.keys())],
        "resolved_findings": [
            {"id": i, "severity": before[i]["severity"], "title": before[i]["title"]}
            for i in sorted(gone) if before[i]["check"] not in failed
        ],
        "not_checked": [
            {"id": i, "check": before[i]["check"]} for i in sorted(gone) if before[i]["check"] in failed
        ],
        "changed_findings": changed,
    }


def compare_audits(old=None, new=None):
    """Vergleicht zwei Snapshots (Standard: die letzten beiden) und speichert das Ergebnis in history/."""
    snapshots = list_snapshots()
    new = new or (snapshots[-1] if snapshots else None)
    if old is None:
        older = [s for s in snapshots if s < new] if new else []
        old = older[-1] if older else None
    if old is None or new is None:
        return {"error": "Für einen Vergleich werden mindestens zwei gespeicherte Audits benötigt.", "snapshots": snapshots}
    for s in (old, new):
        if s not in snapshots:
            return {"error": f"Snapshot {s} nicht gefunden.", "snapshots": snapshots}

    a, b = _load_snapshot(old), _load_snapshot(new)
    # Nur Checks, die in beiden Läufen erfolgreich waren – sonst „verbessert“ sich der Score durch einen fehlgeschlagenen Check
    comparable = _ok_checks(a) & _ok_checks(b)
    score_old, score_new = risk_score(a, comparable), risk_score(b, comparable)
    delta = score_new - score_old
    result = {
        "old": old,
        "new": new,
        "score": {
            "old": score_old,
            "new": score_new,
            "delta": delta,
            "verdict": "verbessert" if delta < 0 else "verschlechtert" if delta > 0 else "unverändert",
            "weights": SEVERITY_WEIGHTS,
            "checks_excluded": sorted((set(a["checks_run"]) | set(b["checks_run"])) - comparable),
        },
        "summary_delta": {s: b["summary"][s] - a["summary"][s] for s in SEVERITY_WEIGHTS},
        **_diff(a, b),
    }
    HISTORY_DIR.mkdir(exist_ok=True)
    (HISTORY_DIR / f"{old}__{new}.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result


TOOLS = [
    {
        "type": "function",
        "name": "compare_audits",
        "description": "Vergleicht zwei gespeicherte Audit-Snapshots (ohne Angabe: die letzten beiden) – ohne neues Audit. "
                       "Liefert Risiko-Score alt/neu mit Bewertung, neue, behobene und veränderte Findings.",
        "parameters": {
            "type": "object",
            "properties": {
                "old": {"type": "string", "description": "Snapshot-ID (YYYYMMDD_HHMMSS) des älteren Audits"},
                "new": {"type": "string", "description": "Snapshot-ID (YYYYMMDD_HHMMSS) des neueren Audits"},
            },
        },
    },
    {
        "type": "function",
        "name": "list_snapshots",
        "description": "Listet alle gespeicherten Audit-Snapshots (IDs = Zeitstempel), älteste zuerst.",
        "parameters": {"type": "object", "properties": {}},
    },
]
FUNCS = {"compare_audits": compare_audits, "list_snapshots": list_snapshots}

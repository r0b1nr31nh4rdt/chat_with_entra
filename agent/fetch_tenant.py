# fetch_tenant.py
# Speichert einen Snapshot aller Tenant-Daten nach data/ (z. B. für die jq-Auswertungen)

import json
from pathlib import Path

import requests

from tenant import QUERIES, fetch

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)


def save(name, items):
    (DATA_DIR / f"{name}.json").write_text(
        json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    # Einzelobjekte (dict) haben keine sinnvolle Anzahl Einträge
    print(f"{name}: {len(items)} Einträge" if isinstance(items, list) else f"{name}: Einzelobjekt")


for name in QUERIES:
    try:
        save(name, fetch(name))
    except requests.HTTPError as e:
        # z. B. 403 bei fehlender Permission – restliche Abfragen trotzdem speichern
        print(f"{name}: übersprungen ({e.response.status_code})")

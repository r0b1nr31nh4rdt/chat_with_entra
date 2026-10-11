# logger.py

import json

from datetime import datetime
from pathlib import Path

LOG_DIR = Path(__file__).parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / f"session_{datetime.now():%Y%m%d_%H%M%S}.jsonl"


def log(type_, **data):
    """Hängt eine Zeile (ein JSON-Objekt) an die Session-Logdatei an."""
    entry = {"ts": datetime.now().isoformat(), "type": type_, **data}
    with LOG_FILE.open("a", encoding="utf-8") as f:
        # default=str nur als Sicherheitsnetz, falls doch mal ein Objekt durchrutscht
        f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
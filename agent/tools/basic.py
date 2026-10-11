# tools/basic.py

from datetime import datetime
from zoneinfo import ZoneInfo

def get_current_time(timezone="Europe/Berlin"):
    return {"time": datetime.now(ZoneInfo(timezone)).isoformat()}

# Responses-API-Format: name/description/parameters direkt auf oberster Ebene
TOOLS = [{
    "type": "function",
    "name": "get_current_time",
    "description": "Aktuelle Uhrzeit für eine IANA-Zeitzone, z. B. Europe/Berlin.",
    "parameters": {"type": "object", "properties": {"timezone": {"type": "string"}}},
}]
FUNCS = {"get_current_time": get_current_time}
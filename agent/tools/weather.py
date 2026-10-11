# tools/weather.py
# Wetterdaten von Open-Meteo (kostenlos, kein API-Key nötig)

import requests

GEO_URL = "https://geocoding-api.open-meteo.com/v1/search"
FORECAST_URL = "https://api.open-meteo.com/v1/forecast"
TIMEOUT = 10  # Sekunden

# WMO-Wettercodes → Klartext (https://open-meteo.com/en/docs)
WEATHER_CODES = {
    0: "klar", 1: "überwiegend klar", 2: "teilweise bewölkt", 3: "bedeckt",
    45: "Nebel", 48: "Nebel mit Reif",
    51: "leichter Nieselregen", 53: "Nieselregen", 55: "starker Nieselregen",
    56: "gefrierender Nieselregen", 57: "starker gefrierender Nieselregen",
    61: "leichter Regen", 63: "Regen", 65: "starker Regen",
    66: "gefrierender Regen", 67: "starker gefrierender Regen",
    71: "leichter Schneefall", 73: "Schneefall", 75: "starker Schneefall", 77: "Schneegriesel",
    80: "leichte Regenschauer", 81: "Regenschauer", 82: "heftige Regenschauer",
    85: "leichte Schneeschauer", 86: "starke Schneeschauer",
    95: "Gewitter", 96: "Gewitter mit Hagel", 99: "Gewitter mit starkem Hagel",
}


def _geocode(city):
    """Stadtname → Koordinaten. Wirft ValueError, wenn nichts gefunden wird."""
    r = requests.get(GEO_URL, params={"name": city, "count": 1, "language": "de"}, timeout=TIMEOUT)
    r.raise_for_status()
    results = r.json().get("results")
    if not results:
        raise ValueError(f"Ort '{city}' nicht gefunden")
    return results[0]


def get_weather(city, days=1):
    days = max(1, min(int(days), 7))
    place = _geocode(city)

    r = requests.get(FORECAST_URL, params={
        "latitude": place["latitude"],
        "longitude": place["longitude"],
        "current": "temperature_2m,apparent_temperature,relative_humidity_2m,wind_speed_10m,weather_code",
        "daily": "temperature_2m_min,temperature_2m_max,precipitation_probability_max,weather_code",
        "timezone": "auto",
        "forecast_days": days,
    }, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()

    current = data["current"]
    daily = data["daily"]
    return {
        "location": f"{place['name']}, {place.get('country', '')}".strip(", "),
        "current": {
            "time": current["time"],
            "temperature_c": current["temperature_2m"],
            "feels_like_c": current["apparent_temperature"],
            "humidity_percent": current["relative_humidity_2m"],
            "wind_kmh": current["wind_speed_10m"],
            "conditions": WEATHER_CODES.get(current["weather_code"], "unbekannt"),
        },
        "forecast": [
            {
                "date": daily["time"][i],
                "min_c": daily["temperature_2m_min"][i],
                "max_c": daily["temperature_2m_max"][i],
                "rain_probability_percent": daily["precipitation_probability_max"][i],
                "conditions": WEATHER_CODES.get(daily["weather_code"][i], "unbekannt"),
            }
            for i in range(len(daily["time"]))
        ],
    }


# Responses-API-Format: name/description/parameters direkt auf oberster Ebene
TOOLS = [{
    "type": "function",
    "name": "get_weather",
    "description": "Aktuelles Wetter und Vorhersage (bis 7 Tage) für eine Stadt.",
    "parameters": {
        "type": "object",
        "properties": {
            "city": {"type": "string", "description": "Stadtname, z. B. Berlin"},
            "days": {"type": "integer", "description": "Anzahl Vorhersagetage (1-7), Standard 1"},
        },
        "required": ["city"],
    },
}]
FUNCS = {"get_weather": get_weather}

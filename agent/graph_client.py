# graph_client.py

import os
import requests
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential

load_dotenv()

_cred = ClientSecretCredential(
    os.environ["PEARSON_TENANT_ID"],
    os.environ["PEARSON_CLIENT_ID"],
    os.environ["PEARSON_CLIENT_SECRET"],
)

GRAPH = "https://graph.microsoft.com"


def graph_get(path, version="v1.0"):
    """GET gegen Graph, folgt automatisch allen Seiten (@odata.nextLink).
    Bei Endpoints ohne "value" (Einzelobjekt) wird das Objekt direkt zurückgegeben.
    version="beta" nur für Felder, die es in v1.0 (noch) nicht gibt."""
    token = _cred.get_token("https://graph.microsoft.com/.default").token
    url = f"{GRAPH}/{version}{path}"
    items = []
    while url:
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        data = r.json()
        if "value" not in data:      # Einzelobjekt statt Liste
            return data
        items += data["value"]
        url = data.get("@odata.nextLink")
    return items

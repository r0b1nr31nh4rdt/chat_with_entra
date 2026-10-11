# graph_test.py

import os, json, base64

from dotenv import load_dotenv
from azure.identity import ClientSecretCredential

load_dotenv()

cred = ClientSecretCredential(
    os.environ["PEARSON_TENANT_ID"],
    os.environ["PEARSON_CLIENT_ID"],
    os.environ["PEARSON_CLIENT_SECRET"],
)

token = cred.get_token("https://graph.microsoft.com/.default").token

# Payload (mittlerer Teil des JWT) lokal dekodieren, statt das Token irgendwo einzufügen
payload = token.split(".")[1]
payload += "=" * (-len(payload) % 4)  # Base64-Padding auffüllen
claims = json.loads(base64.urlsafe_b64decode(payload))

print("Tenant:", claims.get("tid"))
print("App:   ", claims.get("app_displayname"))
print("Roles: ", claims.get("roles"))
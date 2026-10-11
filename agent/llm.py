# llm.py

import os

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()  # lädt die .env in os.environ

# os.environ[...] statt os.getenv: fehlt ein Wert, bricht das Skript sofort
# mit klarer Meldung ab statt später mit einem kryptischen API-Fehler.
DEPLOYMENT = os.environ["DEPLOYMENT_NAME"]

client = OpenAI(
    base_url=os.environ["END_POINT"],
    api_key=os.environ["API_KEY"],
)
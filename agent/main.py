# main.py

import json

from llm import client, DEPLOYMENT
from logger import log
from tools import TOOLS, FUNCS
from pathlib import Path

SYSTEM_PROMPT = (Path(__file__).parent / "prompts" / "system.md").read_text(encoding="utf-8")
MAX_ROUNDS = 10  # Schutz gegen Endlosschleifen beim Tool-Calling


def run_tool(name, arguments):
    """Führt ein Tool lokal aus und gibt das Ergebnis als String zurück."""
    args = None
    try:
        args = json.loads(arguments or "{}")
        result = FUNCS[name](**args)
    except Exception as e:
        # Fehler ans Modell zurückgeben statt den Chat abstürzen zu lassen
        result = {"error": f"{type(e).__name__}: {e}"}
    log("tool_result", tool=name, args=args if args is not None else arguments, result=result)
    return result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)


def ask(history):
    """Eine Nutzerfrage abarbeiten, inkl. beliebig vieler Tool-Runden."""
    for round_ in range(1, MAX_ROUNDS + 1):
        log("request", round=round_, input=history)

        response = client.responses.create(
            model=DEPLOYMENT,
            instructions=SYSTEM_PROMPT,
            input=history,
            tools=TOOLS
        )

        # SDK-Objekte sofort in Dicts umwandeln → history bleibt komplett JSON-fähig
        output = [item.model_dump(exclude_none=True) for item in response.output]
        log("response", round=round_, output=output, usage=response.usage.model_dump())

        history += output

        calls = [item for item in output if item["type"] == "function_call"]
        if not calls:
            return response.output_text

        for call in calls:
            history.append({
                "type": "function_call_output",
                "call_id": call["call_id"],
                "output": run_tool(call["name"], call.get("arguments")),
            })

    return "Abbruch: maximale Rundenzahl erreicht."


def main():
    print("Chat gestartet. Mit 'exit' oder leerer Eingabe beenden.")
    history = []  # gesamter Verlauf über alle Fragen hinweg

    while True:
        user_input = input("\nyou: ").strip()
        if user_input in ("", "exit", "quit"):
            break

        history.append({"role": "user", "content": user_input})
        print(f"answer: {ask(history)}")


if __name__ == "__main__":
    main()
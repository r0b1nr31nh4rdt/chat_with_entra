"""Chat-Schleife als MCP-Client.

Startet mcp_server.py als Unterprozess (stdio), holt sich dort die Tool-Liste
und führt Tool-Calls des Modells über MCP aus statt direkt über FUNCS.
"""

import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from llm import client, DEPLOYMENT
from logger import log

BASE_DIR = Path(__file__).parent
LOG_DIR = BASE_DIR / "logs"
SYSTEM_PROMPT = (BASE_DIR / "prompts" / "system.md").read_text(encoding="utf-8")
MAX_ROUNDS = 10  # Schutz gegen Endlosschleifen beim Tool-Calling

# Der Server wird mit demselben Python-Interpreter (.venv) gestartet wie der Client.
SERVER = StdioServerParameters(
    command=sys.executable,
    args=[str(BASE_DIR / "mcp_server.py")],
    cwd=str(BASE_DIR),
)


def to_openai_tool(tool):
    """MCP-Tool-Beschreibung → Tool-Format der Responses API."""
    return {
        "type": "function",
        "name": tool.name,
        "description": tool.description or "",
        "parameters": tool.input_schema,
    }


async def run_tool(session, name, arguments):
    """Tool über MCP ausführen, Ergebnis als Text zurückgeben."""
    args = json.loads(arguments or "{}")
    result = await session.call_tool(name, args)
    # Ein Ergebnis kann aus mehreren Content-Blöcken bestehen → Textteile zusammenfügen
    text = "\n".join(getattr(c, "text", "") for c in result.content)
    log("tool_result", tool=name, args=args, result=text, is_error=result.is_error)
    return text


async def ask(session, tools, history):
    """Eine Nutzerfrage abarbeiten, inkl. beliebig vieler Tool-Runden."""
    for round_ in range(1, MAX_ROUNDS + 1):
        log("request", round=round_, input=history)

        # Der OpenAI-Client ist synchron → in einen Thread auslagern,
        # damit die MCP-Verbindung im Hintergrund nicht blockiert wird.
        response = await asyncio.to_thread(
            client.responses.create,
            model=DEPLOYMENT,
            instructions=SYSTEM_PROMPT,
            input=history,
            tools=tools,
            reasoning={"effort": "low"}
        )

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
                "output": await run_tool(session, call["name"], call.get("arguments")),
            })

    return "Abbruch: maximale Rundenzahl erreicht."


async def main():
    with open(LOG_DIR / "mcp_server.log", "a", encoding="utf-8") as errlog:
        async with stdio_client(SERVER, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = [to_openai_tool(t) for t in (await session.list_tools()).tools]

                log("session_start", system_prompt=SYSTEM_PROMPT, tools=[t["name"] for t in tools])
                print(f"Chat gestartet – {len(tools)} Tools über MCP: {', '.join(t['name'] for t in tools)}")
                print("Mit 'exit' oder leerer Eingabe beenden.")

                history = []
                while True:
                    user_input = (await asyncio.to_thread(input, "\nyou: ")).strip()
                    if user_input in ("", "exit", "quit"):
                        break
                    history.append({"role": "user", "content": user_input})
                    print(f"answer: {await ask(session, tools, history)}")


if __name__ == "__main__":
    asyncio.run(main())
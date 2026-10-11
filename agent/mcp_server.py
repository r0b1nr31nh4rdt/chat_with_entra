# mcp_server.py
from mcp.server.mcpserver import MCPServer
from tools import TOOLS, FUNCS

mcp = MCPServer("entra-audit", log_level="WARNING")

for t in TOOLS:
    mcp.add_tool(FUNCS[t["name"]], name=t["name"], description=t["description"])

if __name__ == "__main__":
    mcp.run()  # Standard: stdio
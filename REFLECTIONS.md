# Reflections: Building an AI Agent for Identity Security

[Deutsch](REFLECTIONS.de.md) · **English**

*Draft. Sections marked **[TODO]** still need my own observations from the EntraGoat run.*

## What I built

A Python agent that answers questions about an Entra ID tenant and audits it for common misconfigurations. The model (gpt-5-mini) runs in Azure AI Foundry in the Cybersteps tenant. The data comes live from Microsoft Graph in the Pearson lab tenant. My local script is the only bridge between the two: the tenants never talk to each other, and the model never sees the Graph credentials, only the results my code sends back. The Graph queries are exposed as tools through my own MCP server, and the audit checks are deterministic Python functions. The model's job is to choose tools, explain findings and suggest fixes.

## 1. The model should not count

The clearest lesson came early. I asked "How many admins are there?" and got: "8 Global Administrator members – 7 users and 2 service principals." 7 + 2 is not 8. The log showed my tool had returned exactly 8 entries (6 users, 2 service principals) with `count: 8`. The model read the total correctly but counted the types itself and got it wrong. It probably mixed in the number 7 from a second tool, the MFA report, where "admin" means something different.

**Fix:** every aggregation now happens in code (`count`, `by_type`). The model only reads the numbers out.
**Takeaway:** in an audit, a wrong number is worse than no number. Anything that can be computed deterministically should be.

## 2. "Admin" is not a well-defined word

Two tools used two different definitions. `get_role_members` counted Global Administrators, including service principals. The MFA report's `isAdmin` flag counts users with *any* privileged role and excludes service principals. Both answers were correct, but they answered different questions, and the model blended them without saying so.

With a lower reasoning setting (`effort: low`) the model behaved differently: it asked whether I meant Global Administrators or all admin roles instead of guessing. That is arguably the better behaviour, but it is impractical for an audit tool. I fixed it in two places instead of raising the reasoning level:
- the system prompt now defines what "admin" means by default and tells the model to state its assumption and continue;
- a dedicated tool (`get_privileged_role_assignments`) answers the question directly, with counts per role.

**Takeaway:** ambiguity is solved more reliably by tool design and clear definitions than by a "smarter" model. `low` stayed: same quality on clear questions, noticeably faster.

## 3. "Registered" is not "enforced"

The tenant has no Conditional Access policies and Security Defaults are disabled. 5 of 6 human Global Administrators have no MFA method registered. The one admin who *has* registered MFA is not actually protected either, because nothing requires MFA at sign-in. A naive check ("is MFA registered?") would mark that account as fine. I split this into two separate findings: MFA not registered, and MFA not enforced.

The same applies to legacy authentication. From Entra's point of view it is not blocked, but it could still be disabled on the Exchange Online side, which Graph cannot see. The honest finding is "not blocked in Entra; Exchange settings not verifiable", not simply "allowed".

**Takeaway:** the hard part of identity auditing is not fetching data. It is knowing what the data does *not* prove.

## 4. Single checks vs. attack paths

**[TODO – fill in after Scenario 1]**
- What did the agent find with the existing checks?
- What did it miss, and why? My expectation: EntraGoat paths are *chains* (e.g. a low-privileged user owns a service principal that holds a dangerous permission). Checks that look at one object at a time see the dangerous permission but not who controls it.
- Which tool did I add to close the gap (e.g. owners of privileged service principals), and did it work?
- One concrete example where the agent was faster than a manual search, and one where it was wrong or hallucinated (with log excerpt).

Side note for the comparison: every EntraGoat scenario creates its own Global Administrator without MFA, who holds the flag. The agent reports these immediately as "more Global Admins without MFA", but they are the *target* of the attack, not the vulnerability. A rising number of findings does not mean the agent found the actual path.

## 5. MCP: architecture decision

The task suggested using an MCP server for Entra. Microsoft's MCP Server for Enterprise supports only delegated permissions, so it runs as a signed-in user, while my agent uses app-only access. Instead I wrapped my existing tools in my own MCP server (Python SDK). Because the tools were already separated from the chat loop, the server was only a few lines. Practical issues I hit:
- the Python MCP SDK 2.x renamed `FastMCP` to `MCPServer`, so most online tutorials no longer work as written;
- parameter schemas are generated from type hints, and without them a `bool` parameter became a `string`;
- with stdio transport, stdout is the protocol channel, so a single `print()` in a tool breaks the connection;
- the server's default INFO logging, including Azure SDK HTTP logs, flooded the terminal and had to be redirected.

MCP itself added no noticeable latency. The waiting time comes from the LLM rounds (at least two per tool-using question).

## 6. The audit tool is itself a privileged asset

My app registration has application permissions like `Directory.Read.All` and `AuditLog.Read.All`. Anyone holding the client secret can read the entire tenant without a user, without MFA and without Conditional Access. That is exactly the kind of service principal the agent is supposed to flag. In practice this means:
- secrets only in `.env`, never in the repo or the logs;
- read-only permissions only, so even a fully manipulated model can only read and never change anything;
- the safety boundary lives in the code and the Graph permissions, not in the prompt.

## 7. Smaller observations

- **Logging was essential.** Without the JSONL log of every request, tool call and result, I could not have found the counting error. The log is also the evidence for this reflection.
- **Ground truth first.** Before connecting the model, I pulled the raw data and wrote down the expected answers (`notes.md`). Without that, I would not have noticed the wrong numbers at all.
- **Report data may lag.** The MFA registration report is not necessarily real-time, so recent changes may not show up immediately.
- **Model lifecycle.** gpt-4o had already been retired in Azure Foundry when the project started. Model choice is an operational dependency, not a one-time decision.

## Conclusion

**[TODO – 3–4 sentences in my own words]** Suggested direction: an LLM is useful as an interface to identity data and for explaining risks in plain language. Detection itself has to be deterministic and verifiable, and the human still needs to know what the data does *not* show.
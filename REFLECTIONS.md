# Reflections: Building an AI Agent for Identity Security

## What I built

A Python agent that answers questions about an Entra ID tenant and audits it for common misconfigurations. The model (gpt-5.4-mini) runs in Azure AI Foundry in the Cybersteps tenant. The data comes live from Microsoft Graph in the Pearson lab tenant. My local script is the only bridge between the two: the tenants never talk to each other, and the model never sees the Graph credentials, only the results my code sends back. The Graph queries are exposed as tools through my own MCP server, and the audit checks are deterministic Python functions. The model's job is to choose tools, explain findings and suggest fixes.

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

## 4. Single checks vs. attack paths (EntraGoat Scenario 1)

**Approach:** I ran a baseline audit, deployed EntraGoat Scenario 1, ran a second audit and compared both automatically (`compare_audits`). The ground truth comes from the official EntraGoat solution; I did not work it out myself.

**The misconfiguration:** `david.martinez`, a regular finance user without any admin role, owns the service principal "Finance Analytics Dashboard". That SP holds the *Privileged Authentication Administrator* (PAA) role, one of the most privileged roles in Entra, which can also affect Global Administrator accounts. Whoever owns a service principal effectively controls its permissions. The risk comes from the **combination** of two settings that can each look harmless on their own: ownership by a regular user and a privileged role on the SP.

**What the agent found:** the privileged role. In the second audit, `SP-PRIVILEGED-ROLE` newly lists "Finance Analytics Dashboard: Privileged Authentication Administrator". The before/after comparison (`changed_findings`) isolated this change within seconds. Doing it manually would have meant clicking through every role and its members in the portal.

**What the agent missed:**
- **The ownership, which is the actual vulnerability.** No check asks *who* controls a privileged service principal. Nothing in the report says that a regular finance user effectively has access to highly privileged rights through the SP.
- **How serious the role is.** My severity logic only rates Global Administrator as *critical*. The finding is critical only because two SPs with Global Admin sit in the same finding. On its own, the new SP would have been rated *high*, although PAA is close to Global Admin in impact.
- **Credentials on the service principal.** `check_app_credentials` only inspects secrets on *application* objects. Credentials stored directly on the service principal are not checked, so an additional secret on a privileged SP would go unreported.

**Noise:** Both *new* findings (`PRIVILEGED-ASSIGNMENTS-TOO-MANY`, `ADMIN-INACTIVE`) and the additions to `ADMIN-NO-MFA`, `MFA-NOT-ENFORCED` and `GA-COUNT-TOO-HIGH` come from the flag holder `EntraGoat-admin-s1` or from crossing a threshold (8 → 10 privileged assignments). The risk score rose from 66 to 72, **entirely because of these side effects**. The change that actually matters, the new SP with PAA, did not move the score at all, because it was only added as another entry to an existing finding. An aggregated score is a poor indicator for attack paths.

**The LLM:** The summary reproduced numbers and names correctly. They came from code, so there were no hallucinations there. But the risk explanation for the new SP stayed generic ("if the secret is compromised…"). The model did not make the connection "a regular user owns a highly privileged SP", because ownership never appeared in the data. It reported the flag holder as "an additional inactive admin" without recognising it as part of the scenario. The model can only connect what the tools give it.

**Improvement:** I added a new check, `check_sp_ownership`. For every service principal with a privileged role it queries the owners and reports owners without their own admin role as *critical*. The third audit (15 Oct) shows the result: the new finding `SP-OWNER-NOT-ADMIN` names exactly `david.martinez` as owner of "Finance Analytics Dashboard (Privileged Authentication Administrator)". Both links of the chain are now in the report. The LLM's explanation also became specific: fix it via *Enterprise applications → Owners*, reduce the owner list, rotate the SP's credentials. Once the data was there, the model could make the connection.

Worth noting: despite the new *critical* finding, the score stayed at 72 ("unchanged"). That is intentional: new checks are excluded from the score comparison so old and new runs stay comparable. But it shows again that a single score without context can be misleading.

**Still open:** owners of the associated *app registration* are not checked yet, nor are credentials stored directly on the service principal. The severity logic does not yet treat PAA as equivalent to Global Admin.

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

An LLM is a good interface to identity data. It turns questions into the right queries and explains risks in plain language. Detection, however, has to happen deterministically and verifiably in code: the model counts unreliably and can only connect what the tools give it. EntraGoat showed where the real limit is. At first my agent found only the privileged role, not the ownership that turns it into a risk. Only an additional check for that relationship made the path visible. Danger rarely comes from a single misconfiguration; it comes from the relationships between objects. A useful identity security agent therefore needs to query relationships, not just properties, and the human still needs to know what the data does *not* show.
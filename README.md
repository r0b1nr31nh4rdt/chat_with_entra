# chat_with_entra

[Deutsch](README.de.md) · **English**

Chat-based audit tool for Microsoft Entra ID. An LLM (Azure OpenAI) answers questions about the tenant and runs security checks. Data is fetched **live** via Microsoft Graph. The tools are served by a local MCP server.

**Division of labour:** The checks evaluate deterministically in code (severity, evidence). The LLM only explains risk and remediation – it does not invent findings.

> **Language:** The tool itself works in German – system prompt, finding titles, evidence texts, score verdicts and the chat answers.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Required variables in `.env` (project root):

```
END_POINT=https://<resource>.openai.azure.com/openai/v1
API_KEY=...
DEPLOYMENT_NAME=gpt-5.4-mini

PEARSON_TENANT_ID=...
PEARSON_CLIENT_ID=...
PEARSON_CLIENT_SECRET=...
```

The app registration needs these **application permissions** on Microsoft Graph (admin consent required):
`AuditLog.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `User.Read.All`.

## Running

All commands from the `agent/` folder with the venv activated:

```bash
cd agent
python main.py           # start the chat (quit with "exit" or empty input)
python fetch_tenant.py   # load tenant data via Graph into agent/data/
python compare_audits.py # compare the last two saved audits (see Audit history)
```

`main.py` starts `mcp_server.py` automatically as a subprocess. The tools in the chat query Graph **live** on every call. `fetch_tenant.py` is not needed for that – it only stores a snapshot for the `jq` analyses below.

Example questions in the chat (German):

- „Führe ein vollständiges Audit durch.“ – *Run a full audit.*
- „Wer ist Global Admin und hat davon jemand kein MFA?“ – *Who is Global Admin, and does any of them lack MFA?*
- „Wird Legacy Authentication blockiert?“ – *Is legacy authentication blocked?*
- „Was hat sich seit dem letzten Audit verändert?“ – *What has changed since the last audit?*

## Project structure

```
agent/
├── main.py            Chat loop, MCP client, tool calling
├── mcp_server.py      MCP server: exposes all tools from tools/
├── llm.py             Azure OpenAI client (configuration from .env)
├── graph_client.py    Graph login (client credentials) + graph_get with paging
├── tenant.py          Central Graph queries (used by tools and fetch_tenant.py)
├── fetch_tenant.py    Snapshot of all tenant data into data/
├── compare_audits.py  CLI: compare two audit snapshots
├── export_sample.py   CLI: export audit runs anonymised into sample_reports/
├── logger.py          JSONL log per session into logs/
├── prompts/system.md  System prompt (auditor role, rules for findings)
├── tools/
│   ├── basic.py       get_current_time
│   ├── weather.py     get_weather (Open-Meteo)
│   ├── graph.py       Query tools: roles, users, MFA, policies
│   ├── audit.py       Audit checks + run_audit
│   └── history.py     Save and compare audit runs (score)
├── data/              Snapshot (gitignored)
└── logs/              Session logs (gitignored)
audits/                One folder per audit run (gitignored, see Audit history)
sample_reports/        Anonymised example runs (in the repo)
```

## Audit checks

Each check fetches live data, evaluates deterministically and returns findings in a fixed schema. `run_audit()` runs all 12 checks, sorts the findings by severity and additionally lists the **passed** checks (`checks_passed`). The result is saved as a snapshot and compared with the previous one (see [Audit history](#audit-history)). Each check can also be called individually as a tool.

| Tool | Checks | Possible findings | Reference |
|---|---|---|---|
| `check_legacy_auth` | Is legacy auth blocked? Yes if Security Defaults are on **or** a CA policy with `state=enabled` (report-only does not count), `clientAppTypes` ⊇ `exchangeActiveSync`+`other`, `block`, users = `All` | `LEGACY-AUTH-NOT-BLOCKED` (high), `LEGACY-AUTH-EXCLUSIONS` (low) | CIS M365 5.2.2.3 |
| `check_admin_mfa` | Have privileged users **registered** MFA – and is MFA actually **enforced** for them? | `ADMIN-NO-MFA` (critical), `MFA-NOT-ENFORCED` (critical) | CIS M365 5.2.2.1 |
| `check_service_principals` | SPs in privileged directory roles and SPs with critical Graph permissions | `SP-PRIVILEGED-ROLE` (critical/high), `SP-CRITICAL-GRAPH-PERMISSION` (critical), `AUDIT-APP-PERMISSIONS` (informational) | Microsoft Learn: Best practices for Entra roles |
| `check_global_admin_count` | Is the number of Global Admins (users) between 2 and 4? | `GA-COUNT-TOO-HIGH` / `GA-COUNT-TOO-LOW` (medium) | CIS M365 1.1.3 |
| `check_user_mfa` | Have all active users registered MFA? | `USER-NO-MFA` (high) | CIS M365 5.2.2.2 |
| `check_tenant_settings` | User consent for apps, app registration by users, guest invitations (`authorizationPolicy`) | `USER-CONSENT-ALLOWED` (high if legacy, otherwise medium), `USER-APP-REGISTRATION-ALLOWED` (low), `GUEST-INVITE-UNRESTRICTED` (medium/low) | CIS M365 5.1.5.1, 5.1.2.2, 5.1.6.3 |
| `check_privileged_assignments` | Fewer than 10 privileged assignments? Only cloud-only accounts in privileged roles? | `PRIVILEGED-ASSIGNMENTS-TOO-MANY` (medium), `ADMIN-SYNCED-ACCOUNT` (high) | Microsoft Learn: Best practices for Entra roles (#6, #9) |
| `check_password_expiration` | Periodic password expiration disabled? (managed domains only) | `PASSWORD-EXPIRATION-ENABLED` (low) | CIS M365 1.3.1 |
| `check_risk_policies` | Active CA policies with user risk and sign-in risk for all users? | `NO-USER-RISK-POLICY`, `NO-SIGNIN-RISK-POLICY` (medium) | CIS M365 5.2.2.6, 5.2.2.7 |
| `check_inactive_admins` | Privileged users not signed in for over 90 days, or never? | `ADMIN-INACTIVE` (medium) | Microsoft Learn: Best practices for Entra roles (#4) |
| `check_app_credentials` | App secrets with a lifetime over 365 days, or expired and not removed? | `APP-SECRET-LONG-LIFETIME` (medium), `APP-SECRET-EXPIRED` (low) | Microsoft Learn: Best practices for app registrations |
| `check_pim` | Privileged roles assigned via PIM (eligible) instead of permanently? | `PIM-NOT-USED` (medium), `PIM-NOT-CHECKABLE` (informational, if the permission is missing) | Microsoft Learn: Best practices for Entra roles (#2) |

**Finding schema** (texts are German):

```json
{
  "id": "ADMIN-NO-MFA",
  "severity": "critical",
  "title": "Privilegierte Benutzer ohne MFA-Registrierung",
  "affected": ["..."],
  "evidence": "5 von 6 privilegierten Benutzern: isMfaRegistered=false (Rollen: Global Administrator)",
  "reference": "CIS M365 5.2.2.1",
  "note": "optional"
}
```

Severity levels: `critical` · `high` · `medium` · `low` · `informational`

**Technical details:**

- **Privileged roles** = Microsoft's own classification (`isPrivileged`, currently 35 roles). The field only exists in the Graph beta.
- **Critical Graph permissions:** `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, `Directory.ReadWrite.All`. With any of them an app can make itself or others Global Admin.
- **Registered ≠ enforced:** Without a CA policy and without Security Defaults, MFA is not required at sign-in – even for admins who have registered MFA. That is why there are two separate findings.

**Known limitations:**

- Exchange-side settings (e.g. basic auth per protocol) cannot be checked via Graph.
- Group-based assignments in CA policies are not resolved. If an MFA policy covers admins only through a group, `check_admin_mfa` reports them as "not enforced".
- *Eligible* PIM assignments are only visible with the additional permission `RoleEligibilitySchedule.Read.Directory` (and Entra ID P2). Without it, `check_pim` reports "not checkable" and the other checks only consider active assignments.
- `signInActivity` (for `check_inactive_admins`) is only recorded from Entra ID P1 onwards.
- Not automatically checkable: break-glass accounts (not reliably identifiable), access reviews (governance licence), on-prem recommendations of the Secure Score (Kerberos, LAPS, Entra Connect).
- The logic for CA policies, PIM, synced accounts, password expiration and expired secrets is tested with synthetic data, because the lab tenant does not contain these cases.
- According to benchmark mappings, the CIS numbers are stable across v4–v6 (5.1.6.3 only from v6), but may shift in future versions.

## Audit history

Every audit run gets its own folder – everything that belongs to a run is kept together:

```
audits/
├── 20261014_191558/
│   ├── snapshot.json     State capture (facts)
│   ├── changes.json      Comparison with the previous run
│   └── summary.md        Summary and assessment from the chat
├── 20261014_192427/
│   └── …
└── comparisons/          Ad-hoc comparisons of non-consecutive runs
    └── <old>__<new>.json
```

1. **State capture:** `run_audit()` saves its result unchanged as `snapshot.json` (timestamp, checks run/passed, summary, findings, errors). Each finding additionally contains `check` – the check that produced it.
2. **Comparison:** Afterwards, as a separate step, `compare_audits` compares it with the previous run → `changes.json`. The tool returns `{snapshot, audit, changes}` (`changes` is `null` for the first audit).
3. **Assessment:** The answer the LLM gives in the chat for an audit is saved by `main.py` as `summary.md` – unchanged and deterministically, not via a tool of the LLM. For an already saved run, the `load_audit` tool loads snapshot and comparison without a new audit – e.g. „Erstelle eine Zusammenfassung zum Audit 20261014_191558“ (*create a summary for audit …*); the answer is then also saved as that run's `summary.md` (an existing one is overwritten). The header states model, time and question. The text is LLM-generated and may be worded differently each time; `snapshot.json` and `changes.json` are authoritative.

Comparison without a new audit – in the chat („Was hat sich seit dem letzten Audit verändert?“, tools `compare_audits` and `list_snapshots`) or in the terminal:

```bash
python compare_audits.py                     # the last two snapshots
python compare_audits.py <old> <new>         # specific snapshots, e.g. 20261011_181500 20261014_153000
python compare_audits.py --list              # available snapshots
```

**Example:** [`sample_reports/`](sample_reports/) contains the first two runs of the lab tenant, anonymised – including the `summary.md` as produced in the chat. Generated with:

```bash
python export_sample.py 20261014_191558 20261014_192427
```

The script deterministically replaces UPNs, display names, service principal and app names with pseudonyms (`user01@contoso.onmicrosoft.com`, `ServicePrincipal-A`, `App-A`) – consistent across all files and runs –, replaces the tenant domain and GUIDs, and aborts if any original value is still present in the export.

**Contents of a comparison:**

| Field | Meaning |
|---|---|
| `score` | Risk score old → new, difference and verdict (`verbessert` = improved / `verschlechtert` = worsened / `unverändert` = unchanged) |
| `summary_delta` | Change in the number of findings per severity |
| `new_findings` | Newly appeared findings (deterioration) |
| `resolved_findings` | Findings no longer present (improvement) |
| `changed_findings` | Same ID, but different severity or added/removed affected objects |
| `not_checked` | Findings whose check failed in the newer audit – **not** resolved |

**Risk score:** Sum of the risk points of all findings by severity – critical 10, high 5, medium 3, low 1, informational 0. Lower is better. The number of affected objects deliberately does not count (otherwise e.g. "30 users without MFA" would outweigh everything else); changes there are shown in `changed_findings`. Only checks that ran successfully in **both** audits are included in the score – a failed check must not seemingly improve the score. Excluded checks are listed in `score.checks_excluded`.

## Testing

```bash
python graph_test.py     # check Graph login: shows tenant, app and roles from the token
```

## Research ("think like an attacker")

Analysis of the loaded data with `jq` from within `agent/` (output contains real user names – do not copy into the repo):

```bash
# All admins and whether they have registered MFA
jq '.[] | select(.isAdmin) | {userPrincipalName, isMfaRegistered}' data/mfa_registration.json

# Who has the Global Administrator role? (62e90394-… = template ID of Global Administrator)
jq '.[] | select(.roleDefinitionId=="62e90394-69f5-4237-9190-012177145e10") | .principal.displayName' data/role_assignments.json

# Which guests exist?
jq '.[] | select(.userType=="Guest") | {displayName, userPrincipalName, accountEnabled}' data/users.json

# Does a guest have a role? (joins role_assignments with role_definitions for the role name)
jq -n --slurpfile ra data/role_assignments.json --slurpfile rd data/role_definitions.json '
  ($rd[0] | map({(.templateId): .displayName}) | add) as $roles
  | $ra[0][] | select(.principal.userType=="Guest")
  | {guest: .principal.userPrincipalName, role: ($roles[.roleDefinitionId] // .roleDefinitionId)}'

# No CA policies – are at least the Security Defaults enabled?
jq 'length' data/ca_policies.json
jq '{displayName, isEnabled}' data/security_defaults.json
```

## Tenant audit findings (as of 2026-10-11)

Data basis: `run_audit()` (live via Microsoft Graph) and the `jq` analyses above.
Only aggregated values are shown here on purpose – no names, UPNs or IDs.

### Overview

| Area | Value |
|---|---|
| Users | 33 (all active, no guests) |
| Role definitions | 145 (35 of them privileged) |
| Active role assignments | 13 (all tenant-wide, scope `/`) |
| Conditional Access policies | 0 |
| Security Defaults | disabled |
| **Audit result** | **4 critical · 2 high · 5 medium · 1 low · 2 informational** (12 checks, 4 passed) |

### 🔴 Critical

| ID | Finding |
|---|---|
| `ADMIN-NO-MFA` | 5 of 6 privileged users (all Global Administrator) have not registered MFA. |
| `MFA-NOT-ENFORCED` | 6 of 6 privileged users are not covered by any MFA policy – even the one admin with registered MFA is not asked for a second factor at sign-in. |
| `SP-PRIVILEGED-ROLE` | 2 service principals hold the Global Administrator role. |
| `SP-CRITICAL-GRAPH-PERMISSION` | The same 2 service principals additionally have `Directory.ReadWrite.All` and `RoleManagement.ReadWrite.Directory`. |

### 🟠 High

| ID | Finding |
|---|---|
| `LEGACY-AUTH-NOT-BLOCKED` | Neither Security Defaults nor a CA policy block legacy authentication. Exchange-side settings cannot be checked via Graph. |
| `USER-NO-MFA` | 30 of 33 active users (91 %) have not registered MFA. |

### 🟡 Medium

| ID | Finding |
|---|---|
| `GA-COUNT-TOO-HIGH` | 6 users with Global Administrator (CIS target: 2–4), plus 2 service principals. |
| `USER-CONSENT-ALLOWED` | Users may grant apps access to company data themselves (Microsoft default user consent policies active). |
| `GUEST-INVITE-UNRESTRICTED` | Everyone – including guests – may invite guests (`allowInvitesFrom=everyone`). |
| `NO-USER-RISK-POLICY` | No active user risk policy (requires Entra ID P2). |
| `NO-SIGNIN-RISK-POLICY` | No active sign-in risk policy (requires Entra ID P2). |

### 🔵 Low

| ID | Finding |
|---|---|
| `USER-APP-REGISTRATION-ALLOWED` | All users may register applications. |

### ⚪ Informational

| ID | Finding |
|---|---|
| `AUDIT-APP-PERMISSIONS` | The audit app itself has 4 read permissions (`AuditLog.Read.All`, `Directory.Read.All`, `Policy.Read.All`, `User.Read.All`). Not critical, but tenant-wide read access. |
| `PIM-NOT-CHECKABLE` | PIM usage not checkable – permission `RoleEligibilitySchedule.Read.Directory` is missing. |

### ✅ Passed

| Check | Result |
|---|---|
| `check_privileged_assignments` | 8 privileged assignments (below 10), no on-prem synced admins. |
| `check_password_expiration` | Passwords do not expire. |
| `check_inactive_admins` | All privileged users have signed in within the last 90 days. |
| `check_app_credentials` | One app secret with a 90-day lifetime, no expired secrets. |

### Further observations (not checked automatically)

- **MFA methods:** Registered are software OTP (3), Authenticator push (2), email (1).
- **Further SP roles:** Besides the 2 Global Admin assignments there are 3 more role assignments to service principals (1× Exchange Administrator, 2× role IDs without a matching role definition – probably hidden system roles). Microsoft does not classify these as privileged.
- **Admin without active assignment:** The MFA report flags 7 users as admin (`isAdmin`), but only 6 have active privileged assignments. Probably an *eligible* PIM assignment – the PIM permission would clarify this.
- **SSPR:** Only 3 users registered for self-service password reset.

### Recommendations

1. **Immediately:** Enforce MFA for all privileged roles via Conditional Access (or enable Security Defaults as an interim measure). Create and exclude a break-glass account first.
2. Review the Global Admin role and critical Graph permissions of the two service principals and revoke them where not strictly required.
3. Block legacy authentication for all users via a CA policy.
4. Reduce the number of Global Admins to 2–4. Move the remaining accounts to less privileged roles.
5. Enforce MFA registration for all users (registration campaign). Avoid email as a method.
6. Disable user consent (use the admin consent workflow instead), restrict guest invitations to admins/guest inviters and app registration to admins.
7. Add the permission `RoleEligibilitySchedule.Read.Directory` so that the PIM check works.

### Reflection

The audit tool is itself a privileged asset: whoever obtains the client secret from `.env` can read the entire tenant – exactly the information an attacker needs for planning (who is admin, who has no MFA, which policies are missing). Mitigation: keep the secret local and gitignored (pre-commit with gitleaks), rotate it regularly or replace it with a certificate, grant read permissions only.

## Sources

The CIS references come from public benchmark mappings (Tenable, Powerpipe/Steampipe), not from the official CIS PDF. For a binding report, verify the numbers against the current version in the CIS WorkBench.

### Microsoft Learn

- [Best practices for Microsoft Entra roles](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices) – least privilege, PIM (#2), MFA for admins (#3), access reviews (#4), < 5 Global Admins (#5), < 10 privileged assignments (#6), cloud-only accounts (#9); service principals with privileged roles as control plane
- [What is the Identity Secure Score?](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-identity-secure-score) – list of recommendations (MFA for everyone, legacy auth, user consent, password expiration, risk policies, SSPR and more)
- [Identity Secure Score (older URL)](https://learn.microsoft.com/azure/active-directory/fundamentals/identity-secure-score)

### CIS Microsoft 365 Foundations Benchmark

| Control | Topic | Check | Source |
|---|---|---|---|
| 1.1.3 | Two to four Global Admins | `check_global_admin_count` | [Tenable (v6.0.1)](https://www.tenable.com/audits/items/CIS_Microsoft_365_Foundations_v6.0.1_L1_E3.audit:b00615853b821c12d798039097dce35a) |
| 1.3.1 | Passwords never expire | `check_password_expiration` | [Tenable (v6.0.1)](https://www.tenable.com/audits/items/CIS_Microsoft_365_Foundations_v6.0.1_L1_E3.audit:6dbe2160c93a3ca645c77f1dec83b123) |
| 5.1.2.2 | No app registration by users | `check_tenant_settings` | [Powerpipe (v6)](https://hub.powerpipe.io/mods/turbot/steampipe-mod-microsoft365-compliance/controls/control.cis_v600_5_1_2_2) |
| 5.1.5.1 | No user consent for apps | `check_tenant_settings` | [Powerpipe (v6)](https://hub.powerpipe.io/mods/turbot/steampipe-mod-microsoft365-compliance/controls/control.cis_v600_5_1_5_1) |
| 5.1.6.3 | Guest invitations only by guest inviters | `check_tenant_settings` | [PowerShell Gallery (v6.0.1)](https://www.powershellgallery.com/packages/ROOTM365/1.0.1/Content/SHELL%5C5.1.6.3.ps1) |
| 5.2.2.1 | MFA for administrative roles | `check_admin_mfa` | [Tenable (v6.0.0)](https://www.tenable.com/audits/items/CIS_Microsoft_365_Foundations_v6.0.0_L1_E3.audit:dec4ac010f858723a9b67fc7c04f8262) |
| 5.2.2.2 | MFA for all users | `check_user_mfa` | [Tenable (v6.0.0)](https://www.tenable.com/audits/items/CIS_Microsoft_365_Foundations_v6.0.0_L1_E5.audit:63ffc9b1065e47b999c9dfeb0c360261) |
| 5.2.2.3 | Block legacy auth via CA | `check_legacy_auth` | [Powerpipe (v5)](https://hub.powerpipe.io/mods/turbot/steampipe-mod-microsoft365-compliance/controls/benchmark.cis_v500_5_2_2), [Powerpipe (v6)](https://hub.powerpipe.io/mods/turbot/steampipe-mod-microsoft365-compliance/controls/benchmark.cis_v600_5_2_2) |
| 5.2.2.6 | User risk policy | `check_risk_policies` | [Tenable (v5.0.0)](https://www.tenable.com/audits/items/CIS_Microsoft_365_Foundations_v5.0.0_L1_E5.audit:95d841342c810e5e7b46982a3a712508) |
| 5.2.2.7 | Sign-in risk policy | `check_risk_policies` | [Tenable (v6.0.0)](https://www.tenable.com/audits/items/CIS_Microsoft_365_Foundations_v6.0.0_L1_E5.audit:686911ddcacd957cf55790a14d32b68c) |

### Microsoft Graph

- Graph endpoints and permissions according to the [Microsoft Graph REST API v1.0](https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0); `isPrivileged` on role definitions only in the [beta API](https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-beta).
- Weather data: [Open-Meteo](https://open-meteo.com/en/docs) (geocoding + forecast, no API key).

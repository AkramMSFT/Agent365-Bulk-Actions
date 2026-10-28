# Agent365-Bulk-Actions

A single PowerShell tool for Microsoft Agent 365 and Microsoft 365 Copilot administrators. It lists, inspects, contains and governs the agents in the organization catalog in bulk, from the command line or from a desktop console.

> [!IMPORTANT]
> Block, unblock and reassign, and the Entra agent-identity and agent-risk calls, use Microsoft Graph **`/beta`** endpoints, which Microsoft does not recommend for production automation. Try it in a lab tenant first. Every write previews first, asks for confirmation and writes a log that can be undone.

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Permissions](#permissions)
  - [Use your own app registration](#use-your-own-app-registration)
- [Safety model](#safety-model)
- [How it works](#how-it-works)
- [Guides](#guides)
  - [Find and inspect agents](#find-and-inspect-agents)
  - [Block, unblock and undo](#block-unblock-and-undo)
  - [Find stale agents](#find-stale-agents)
  - [Find risky agents](#find-risky-agents)
  - [Ownership](#ownership)
  - [Entra accountability](#entra-accountability)
  - [Restrict who can use an agent](#restrict-who-can-use-an-agent)
  - [AI activity from Purview](#ai-activity-from-purview)
  - [Endpoint AI: local agents and shadow AI](#endpoint-ai-local-agents-and-shadow-ai)
  - [Contain and clean up](#contain-and-clean-up)
  - [Respond to a compromised agent](#respond-to-a-compromised-agent)
  - [Check Conditional Access for agents](#check-conditional-access-for-agents)
  - [Agent users and licenses](#agent-users-and-licenses)
  - [Purview policy hits on agents](#purview-policy-hits-on-agents)
  - [MCP access and per-agent MCP blocks](#mcp-access-and-per-agent-mcp-blocks)
  - [Revoke an agent's sessions](#revoke-an-agents-sessions)
  - [Policy file](#policy-file)
  - [Snapshots and change reports](#snapshots-and-change-reports)
  - [Graphical console](#graphical-console)
- [Parameter reference](#parameter-reference)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Appendix: hunting queries](#appendix-hunting-queries)
- [Development](#development)
  - [Graph API watch](#graph-api-watch)
- [Disclaimer](#disclaimer)

## Features

| Area | What it does | Main parameters |
| --- | --- | --- |
| Inventory | List every agent, show the full record of one, export one row per agent with tools, MCP servers, sharing and permissions | `-List`, `-Detail`, `-Inventory` |
| Block and unblock | Block or unblock agents by name or id, from a picker, or from a CSV; reverse any run from its log | `-Block`, `-Unblock`, `-Select`, `-FromCsv`, `-Undo` |
| Stale agents | Find agents with no usage telemetry, or an old manifest, and block them | `-Stale` |
| Risky agents | Find agents with Defender AI-security alerts or detections, ranked by severity, and block them | `-Risky` |
| Ownership | Propose an owner for shared agents whose owner is missing, or assign one by hand | `-Ownerless`, `-Reassign` |
| Accountability | Give Entra agent identities a sponsor (and optionally an owner), proposed from the owner chain | `-Accountability`, `-AddSponsor` |
| Access scope | Restrict who can use an agent (nobody, owner only, named users and groups) as a softer step than blocking | `-Restrict` |
| AI activity | Risky AI activity per agent from the Purview audit log, with per-event detail | `-AiActivity` |
| Agent users | Which users interacted with which agent in the last 7, 14 or 30 days, and whether each has an Agent 365 or E7 license | `-AgentUsers` |
| Policy hits | Which Purview policies fired on which agents: DLP rule matches and DLP or Insider Risk alerts over the last 7, 14 or 30 days | `-AgentPolicyHits` |
| MCP access | Which MCP servers and tools each agent may reach, sets up and calls; a Conditional Access block for chosen agents and one server; and removing, granting or allowing only chosen MCP servers in the agents' Entra permissions | `-McpAccess`, `-BlockMcp`, `-UnblockMcp`, `-Via Permission` |
| Endpoint AI | Discover local AI agents and shadow AI on Defender-onboarded devices, with their telemetry and risk, and block one on a device | `-EndpointAi`, `-BlockLocalAgent`, `-UnblockLocalAgent` |
| Containment | Verify the Entra identity is disabled with a block, preview who would lose an agent, list long-blocked agents | `-DisableIdentity`, `-Impact`, `-DeleteCandidates` |
| Compromise response | Confirm an agent's Entra identity as compromised in Entra ID Protection, or dismiss the risk, and end the sessions of its user accounts | `-ConfirmCompromised`, `-DismissRisk`, `-RevokeSessions` |
| Conditional Access | Check whether a Conditional Access policy blocks each risky agent, or every agent, at High agent risk, and which policies apply | `-CheckConditionalAccess` |
| Policy | Declare rules once, review the plan, apply it | `-Policy`, `-Apply` |
| Snapshots | Save the inventory and report what changed since an earlier one | `-Snapshot`, `-CompareTo` |
| Console | A desktop app laid out like the Agent 365 portal: Home, All agents, Shadow AI, Tools, Users, and Security pages for alerts with response actions, built-in hunting queries, Purview audit, policy hits and Conditional Access | `-Gui` |

## Requirements

- An **Agent 365 license** on the tenant (the catalog API returns packages only with it).
- **PowerShell 7 or later** is recommended. When `Microsoft.Graph.Authentication` is missing, the first run installs the tested version (2.39.0) from the PowerShell Gallery for the current user; PowerShellGet asks first if the gallery is not trusted.
- An administrator who can consent to the permissions listed below, for example an AI Administrator or Global Administrator.
- Stale-by-activity, risky agents, inventory details and policies also read **Defender Advanced Hunting**: a Microsoft Defender or Microsoft 365 E5 license with Security for AI onboarded.
- Endpoint AI needs devices onboarded to **Microsoft Defender for Endpoint** (Windows or macOS). Defender's own local agent discovery needs Plan 2.
- The console needs Windows.

## Quick start

```powershell
# 1. Save Agent365-Bulk-Actions.ps1 to a folder and open PowerShell 7 there
cd C:\Path\To\Scripts

# 2. Sign in once from the terminal (every permission the tool can use; later runs reuse it without a prompt)
.\Agent365-Bulk-Actions.ps1 -SignIn

# 3. List the Copilot agents
.\Agent365-Bulk-Actions.ps1 -List -AgentsOnly

# 4. Preview a change before making it
.\Agent365-Bulk-Actions.ps1 -Block "Contoso HR Agent" -WhatIf

# 5. Or open the console
pwsh -STA -File .\Agent365-Bulk-Actions.ps1 -Gui
```

**Signing in.** `-SignIn` starts the sign-in from the terminal and keeps the session for your Windows account. Microsoft Entra offers no way to type an administrator's password into a terminal (accounts with multi-factor authentication cannot use it, and this tool never handles a password), so the sign-in itself is completed in the Microsoft sign-in window that opens. After that, every mode, scheduled runs included, reuses the saved session silently until it expires or is revoked. The **Microsoft sign-in window always comes first**. Only when it cannot be shown (an SSH or Cloud Shell session, a Linux machine with no desktop, a window that fails to open) and you are at the terminal, the tool falls back to a **device code**: it prints a short code, you open https://microsoft.com/devicelogin on any device, enter the code and finish the sign-in. A code works for about two minutes, and the tool asks for a new one up to three times. `-DeviceCode` uses a code from the start. If you cancel the window, the tool says so and does not switch to a code on its own.

**A session made with a code can only be reused with a code.** The Graph module keeps the two kinds apart, so the tool notes how you signed in (a small file, `a365.signin-method`, next to the saved session). An unattended run or a remote shell that finds a code session reuses it the same way and asks for a new code only when the session has expired. At a terminal with a desktop the window is tried first and replaces it; once a session is made with a window, every later run reuses it silently. A run nobody can answer, such as a scheduled task, cannot enter a code: for scheduled runs sign in once with a window (`-SignIn` on a machine with a desktop), and without a saved session it stops with a message that tells you to do that.

Add `-TenantId <guid-or-domain>` to target a specific tenant. Everything that changes something prints what it will do, asks once (use `-Force` to skip the question) and can write a log with `-OutFile`.

## Permissions

The tool signs in with delegated permissions and requests only what the chosen mode needs.

| Permission | Needed for |
| --- | --- |
| `CopilotPackages.Read.All` | Read-only modes (`-List`, `-Detail`, `-Inventory`, `-Snapshot`, and any mode with `-Action list`) |
| `CopilotPackages.ReadWrite.All` | Blocking, unblocking, reassigning and restricting agents |
| `ThreatHunting.Read.All` | Activity-based staleness, risky agents, inventory details, delete candidates, policies, Endpoint AI |
| `User.Read.All`, `AgentIdentity.Read.All` | Ownership, accountability, inventory and the console |
| `AgentIdentity.EnableDisable.All` | `-DisableIdentity` when the tool has to disable an identity itself, and the console |
| `AgentIdentity.ReadWrite.All` | Adding sponsors or owners to agent identities. Needs the Agent ID Administrator role. The console asks for it only when you use that action. |
| `IdentityRiskyAgent.ReadWrite.All` | Reading an agent identity's Entra risk and confirming it compromised or dismissing the risk. Needs the Security Administrator role. The console asks for it only when you use that action. |
| `CustomDetection.ReadWrite.All` | Blocking a local AI agent on a device (a Defender custom detection rule) and reading which are blocked. Needs a Defender role that manages custom detections and can remediate files. The console asks for it only when you use that action. |
| `Policy.Read.All` | Reading Conditional Access policies (`-CheckConditionalAccess`, `-McpAccess`). The console asks for it only when you use that action. |
| `Policy.ReadWrite.ConditionalAccess` | Blocking an MCP server for chosen agents (`-BlockMcp`, `-UnblockMcp`, the console's MCP access window). Needs the Conditional Access Administrator role. The console asks for it only when you use that action. |
| `DelegatedPermissionGrant.ReadWrite.All` | Removing, granting and allowing only chosen MCP servers in agents' delegated permission grants (`-BlockMcp` and `-UnblockMcp` with `-Via Permission`, the console's **Remove permission...** and **Set servers...**, and undoing them). Needs the Cloud Application Administrator, Application Administrator or Privileged Role Administrator role. The console asks for it only after you confirm such a change. It can grant any delegated permission, so the tool only ever adds or removes MCP scopes. |
| `IdentityRiskyAgent.Read.All` | Reading an agent identity's Entra risk without changing it (`-CheckConditionalAccess`). `IdentityRiskyAgent.ReadWrite.All` also satisfies it. |
| `SecurityAlert.Read.All` | Reading DLP and Insider Risk alerts (`-AgentPolicyHits`). |
| `User.RevokeSessions.All` | Ending the sessions of agents' user accounts (`-RevokeSessions`, the console's **Revoke sessions...**). Needs an Entra role that can manage those accounts. The console asks for it only when you use that action. |
| `Group.Read.All` | Naming a group in `-AllowGroups`, a policy rule, or the console's group picker |
| `Application.Read.All`, `DelegatedPermissionGrant.Read.All` | Reading the permissions an agent identity holds (`-Detail`, `-Inventory -WithPermissions`, `-McpAccess`). The console shows the same data when these permissions have been consented for your account. |
| `AuditLogsQuery.Read.All` | AI activity (`-AiActivity`, the console's AI activity tab, `aiActivity` policy rules). Needs admin consent and a Purview audit role such as Audit Reader. |

### Use your own app registration

By default the tool signs in through the shared **Microsoft Graph Command Line Tools** app. Entra puts every permission consented to that app into each token it issues, so after `-SignIn` every run, and any other Graph PowerShell script you run, carries the write permissions too. An app registration of your own keeps the tool's rights separate and limited to what you grant it. You can register two: a read-only app for reporting, and one with write permissions for the administrators who make changes.

1. In the Microsoft Entra admin center, open **App registrations > New registration**. Choose **Accounts in this organizational directory only**.
2. Under **Authentication**, add the platform **Mobile and desktop applications** with the redirect URI `http://localhost`. To sign in with `-DeviceCode`, also turn on **Allow public client flows**.
3. Under **API permissions**, add the **Microsoft Graph** delegated permissions from the table above that the app should have, then **Grant admin consent**.
4. Run the tool with the app:

```powershell
.\Agent365-Bulk-Actions.ps1 -SignIn -ClientId <application-id> -TenantId <tenant-id>

# Or set both once for every run, scheduled runs included
$env:A365_BULK_ACTIONS_CLIENT_ID = '<application-id>'
$env:A365_BULK_ACTIONS_TENANT_ID = '<tenant-id>'
```

With your own app, `-SignIn` asks only for what the app was granted. A mode that needs a permission the app lacks fails at sign-in with a message naming the missing setup.

## Safety model

- **Preview first.** `-WhatIf` shows what would happen. `-Action list` shows the matched set without acting.
- **One confirmation per batch.** Each write mode lists its targets and asks once. `-Force` skips the question. A selection made in a picker counts as confirmation.
- **A log you can undo.** `-OutFile run.csv` (or `.json`) records every agent with the state it had before the change. `-Undo run.csv` restores block state, owners and access scope, removes sponsors or owners the run added, dismisses a compromised flag the run set, removes local AI agent block rules, puts MCP blocks back the way they were, and adds back MCP permissions a run removed (creating a deleted grant again) or removes those it granted. All changes of one run go into one log, even when the run writes it more than once.
- **An edited log cannot widen an undo.** Before a log drives any write, every row is checked: the agent must be in the catalog, Entra ids must be ids, an identity must be that agent's own, and values must be ones the tool writes. MCP rows are confirmed in Entra (an agent identity or blueprint, agent user accounts only, an MCP server), and block rules must be ones the tool made. Rows that fail are named and left out, and agents are shown with their names from the catalog.
- **MCP permission changes touch MCP scopes only.** A change adds or removes one MCP scope (`Tools.ListInvoke.All` or `McpServers.<Name>.All`) and keeps every other scope in the grant. An undo row must name exactly one MCP scope, its client must be an agent identity or blueprint principal, its resource an MCP server that publishes that scope, and its logged scopes may hold nothing but MCP scopes and what the grant holds now, so an edited log cannot add a permission such as `Directory.ReadWrite.All`.
- **Exports are safe to open in Excel.** A cell that starts with `=`, `+`, `-` or `@` is written with a leading apostrophe, so an agent name or page title from the tenant cannot run as a formula.
- **Revoking sessions is the exception.** It cannot be undone and needs nothing undone: the agent signs in again, subject to any block in place. It writes a log of its own (`name-revoke.csv` beside `-OutFile`) so the log of the block it follows stays usable by `-Undo`.
- **Agents already in the target state are skipped.**
- **Throttling is handled.** HTTP 429 and transient 5xx responses are retried with the service's delay; large reads are batched and writes are paced.
- **Errors say why.** A failed call shows the service's own error code and message and the request that failed.

## How it works

| API | Used for |
| --- | --- |
| Graph `v1.0` `/copilot/admin/catalog/packages` | Listing agents, details and the availability scope (PATCH) |
| Graph beta `/copilot/admin/catalog/packages` | Block, unblock and reassign, which `v1.0` does not offer |
| Graph `/security/runHuntingQuery` (Defender Advanced Hunting) | Usage telemetry, alerts, detections, the per-agent records (tools, MCP servers, sharing) and the endpoint telemetry behind Endpoint AI |
| Graph Entra endpoints (agent identities, users, groups, permission grants) | Identity state, owners, sponsors, permissions, managers |
| Graph beta `/security/rules/detectionRules` | Blocking a local AI agent on a device (a Defender custom detection rule that stops and quarantines its files) |
| Graph beta `/identityProtection/riskyAgents` | Reading an agent identity's risk, confirming it compromised or dismissing the risk |
| Graph beta `/identity/conditionalAccess/policies` | Reading Conditional Access policies; creating, updating and deleting this tool's MCP block policies |
| Graph `v1.0` `/oauth2PermissionGrants` | Reading delegated permission grants; removing or adding an MCP scope (PATCH), deleting a grant left with nothing (DELETE) and granting an MCP server to an agent identity (POST) |
| Graph `v1.0` `/users/{id}/revokeSignInSessions` | Ending the sessions of an agent's user accounts |
| Graph `/security/auditLog/queries` (Purview audit search) | AI activity |

On each run the tool ensures the `Microsoft.Graph.Authentication` module is present, signs in requesting only the permissions the chosen mode needs, reads the catalog, resolves your targets, applies the action and prints an `OK` or `FAIL` line per agent.

## Guides

### Find and inspect agents

```powershell
.\Agent365-Bulk-Actions.ps1 -List -AgentsOnly                         # catalog with blocked state
.\Agent365-Bulk-Actions.ps1 -Detail "Contoso HR Agent"                # everything about one agent
.\Agent365-Bulk-Actions.ps1 -Detail "T_<guid>" -OutFile .\agent.json  # save it as JSON
.\Agent365-Bulk-Actions.ps1 -Inventory -OutFile .\inventory.csv       # one row per agent
.\Agent365-Bulk-Actions.ps1 -Inventory -Deep -WithPermissions -OutFile .\inventory-full.csv
```

The picture is assembled from four places, because no single API holds all of it:

| Source | What it provides |
| --- | --- |
| Catalog package | Kind (shared by a creator, org-published, Microsoft, partner), platform, publisher, version, dates, owner, who can use it, deployment, usage |
| Defender `AgentsInfo` | Declared tools (type, authentication, approval mode), MCP servers, data sources, capabilities, channels, model, sharing, publish and lifecycle status |
| Entra | The agent identity, its owners and sponsors, and the permissions held by the identity and inherited from its blueprint |
| Defender alerts and detections | The agent's risk signals for the last 30 days |

`-Inventory` makes one catalog call and one Defender query. `-Deep` adds one call per agent for usage and availability, and `-WithPermissions` adds the identity's permissions, so both take longer on a large catalog. Fields a tenant does not populate are left blank.

The **Platform** column shows the catalog's platform when it names one (Copilot Studio, Foundry, Microsoft 365 Copilot Agent Builder, Amazon Bedrock, SharePoint). Agents onboarded through the Agent 365 SDK are reported as `Not Available` by the catalog and `Other` by Defender, so they are recognised by their Entra agent identity and shown as **A365 SDK agent**; remaining store packages show as **Microsoft 365 app**.

### Block, unblock and undo

```powershell
.\Agent365-Bulk-Actions.ps1 -Block "Contoso HR Agent","Northwind Sales Agent"   # by name or package id (P_ or T_)
.\Agent365-Bulk-Actions.ps1 -Block "Contoso HR Agent" -WhatIf                   # preview only
.\Agent365-Bulk-Actions.ps1 -Block "Contoso HR Agent" -Force -OutFile .\blocked.csv
.\Agent365-Bulk-Actions.ps1 -Unblock "Contoso HR Agent"
.\Agent365-Bulk-Actions.ps1 -Select -AgentsOnly                                 # pick from a list, then block
.\Agent365-Bulk-Actions.ps1 -Select -Action unblock -AgentsOnly                 # pick from a list, then unblock
.\Agent365-Bulk-Actions.ps1 -FromCsv .\agents.csv -OutFile .\run.csv            # every agent in a CSV (Id or DisplayName column)
.\Agent365-Bulk-Actions.ps1 -Undo .\run.csv                                     # reverse a whole run from its log
.\Agent365-Bulk-Actions.ps1 -Block "Contoso HR Agent" -RevokeSessions          # block, then end its user accounts' sessions
```

Blocking is fully reversible with `-Unblock`. Add `-RevokeSessions` to apply it at once; see [Revoke an agent's sessions](#revoke-an-agents-sessions).

### Find stale agents

```powershell
.\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 14 -Action list         # preview
.\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 14 -AgentsOnly          # block (preview, then confirm)
.\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 14 -Pick                # choose which matches to block
.\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 30 -IncludeNeverSeen -Action list
.\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 90 -By modified -AgentsOnly   # manifest age, no Defender needed
```

| `-By` | Needs Defender | What stale means |
| --- | --- | --- |
| `activity` (default) | Yes | The agent reported telemetry in the last 30 days but has been idle for `-StaleDays`. |
| `modified` | No | The package manifest has not changed for `-StaleDays`. |

Advanced Hunting keeps about 30 days of data, so `-By activity` can only prove idleness inside that window. With `-StaleDays` of 30 or more the tool stops with an explanation unless you add `-IncludeNeverSeen`, which then means "no activity in the last 30 days"; use `-By modified` for longer horizons. By default, agents that never reported telemetry (built-ins and add-ins) are not treated as stale.

Telemetry is matched to catalog packages through `AgentsInfo`: a package id equals the agent's `titleId`, and the agent id, Entra agent id, observability id, source id and bot id seen in events all resolve to it. Display names are never used for matching.

### Find risky agents

```powershell
.\Agent365-Bulk-Actions.ps1 -Risky -Action list                        # severity, signal count and why
.\Agent365-Bulk-Actions.ps1 -Risky -MinSeverity High -Action list
.\Agent365-Bulk-Actions.ps1 -Risky -MinAlerts 2 -MinSeverity Medium -AgentsOnly
.\Agent365-Bulk-Actions.ps1 -Risky -Pick                               # choose which to block
.\Agent365-Bulk-Actions.ps1 -Risky -RiskSource Detections -Action list
```

Results carry **severity**, **alerts**, **detections**, **why** (alert titles and detection types), **categories** and the date of the last signal, worst first. Two kinds of signal are read from Advanced Hunting, because Defender can detect something without raising an alert:

| Signal | Source | Tied to an agent by | Severity |
| --- | --- | --- | --- |
| Alert | `AlertInfo` with `AlertEvidence` (entity `AIAgent`) | The agent id in the evidence | The alert's own severity |
| Real-time protection detection | `BehaviorEntities` (entity `AIAgent`) for `BehaviorAgentRTPAudit` and `BehaviorAgentRTPBlock`, with the block reason from `BehaviorInfo` | The Entra agent id in the entity | Block: High. Audit: Medium |
| Prompt Shield detection | `BehaviorInfo` for `BehaviorPromptShieldJailbreakBlock` and `BehaviorPromptShieldJailbreakDetect` | The agent name, only when it is unique in `AgentsInfo` | Block: High. Detect: Medium |

Behaviors carry no severity of their own, so the table is the mapping the tool applies: a block means an attack was stopped, an audit or detect means it was seen but not stopped. `-RiskSource Both|Alerts|Detections` chooses the signals.

Not every signal can be attributed to a catalog agent. Defender for AI Services alerts name an Azure AI account rather than an agent, real-time block records can lack an agent identity, and a Prompt Shield record whose agent name is missing or duplicated is skipped. Run `-Risky -Action list` first, and override the default query with `-HuntingQuery` if it does not fit your tenant (return `Key, AlertCount, DetectionCount, Severity, LastAlert`, with `Key` set to the package id).

### Ownership

```powershell
.\Agent365-Bulk-Actions.ps1 -Ownerless                                            # preview proposals, changes nothing
.\Agent365-Bulk-Actions.ps1 -Ownerless -Action reassign -OutFile .\owners.csv     # apply the proposals
.\Agent365-Bulk-Actions.ps1 -Reassign "Contoso HR Agent" -To alex@contoso.com     # by hand
```

For each shared agent the tool decides, in this order:

1. **Keep** the current owner when the account exists and is enabled.
2. **Agent identity owner**: the person registered as owner of the agent's Entra identity, the closest available record of who created it.
3. **Manager** of that person, or of the former owner while the account still exists.
4. **Flag for review.** Nothing is guessed or defaulted; assign these by hand.

The package API exposes no creator field, so step 2 is the creator substitute and applies only to agents with an Entra identity. Only Copilot Studio shared agents that already have an owner are sent to the reassign API; everything else is skipped with the reason. There is no call that clears an owner: reassigning to a different, valid user is the only operation. Reassignment is delegated-only: it needs a signed-in administrator and has no app-only option.

See [Limitations](#limitations) for a service-side failure that can affect Copilot Studio reassignment, and [Entra accountability](#entra-accountability) for an alternative that works on the agent identity.

### Entra accountability

Every agent that has an Entra identity can carry a **sponsor** (the person accountable for why the agent exists and whether it is still needed; Microsoft requires at least one) and **owners** (technical administrators). These relationships live on the identity, so they can be filled in even when the package reassign API cannot help.

```powershell
.\Agent365-Bulk-Actions.ps1 -Accountability                       # identities with no valid sponsor, and who would be added
.\Agent365-Bulk-Actions.ps1 -Accountability -IncludeOwners        # also identities with no owner
.\Agent365-Bulk-Actions.ps1 -Accountability -Action assign        # add the proposed people (one confirmation)
.\Agent365-Bulk-Actions.ps1 -AddSponsor "Contoso HR Agent" -To someone@contoso.com
.\Agent365-Bulk-Actions.ps1 -AddSponsor "Contoso HR Agent" -To someone@contoso.com -AsOwner
```

The proposal follows the ownership order: the agent's own owner, an owner of its identity, then the manager of either. If none can be found the agent is flagged for review. Sponsors are the default because they carry no technical privilege; owners can change credentials and re-enable the identity, so they are added only with `-IncludeOwners` or `-AsOwner`. Each addition is logged and `-Undo` removes it.

- Agent user accounts (the accounts agents get) are not people. They are never offered in the pickers and never proposed, because the API rejects them as sponsors.
- Groups can be sponsors (dynamic or Microsoft 365 groups only) and count as a valid sponsor when scanning.
- An identity that cannot be read is reported separately instead of being counted as having no sponsor.
- Owners are optional in Entra, so most identities have none; the owner scan is off by default for that reason.
- Microsoft documents adding a sponsor for application permissions and an owner for delegated sign-in. If your tenant refuses the sponsor call, the log says so; add an owner instead or use the Entra admin center.

### Restrict who can use an agent

Every agent has an availability scope: everyone, some users and groups, or nobody. Narrowing it is a softer containment than a block: the agent stays in the catalog and keeps working for the people you leave. The scope it had is read first and logged, so `-Undo` puts it back.

```powershell
.\Agent365-Bulk-Actions.ps1 -Restrict "Contoso HR Agent"                                          # nobody
.\Agent365-Bulk-Actions.ps1 -Restrict "Contoso HR Agent" -AvailableTo Some -OwnerOnly             # its owner only
.\Agent365-Bulk-Actions.ps1 -Restrict "Contoso HR Agent" -AvailableTo Some -AllowUsers a@contoso.com -AllowGroups "HR team"
.\Agent365-Bulk-Actions.ps1 -Restrict "Contoso HR Agent" -AvailableTo All                         # reopen
.\Agent365-Bulk-Actions.ps1 -Undo .\restrict-log.csv                                              # restore a logged run
```

Add `-IncludeDeployment` to change who the agent is deployed to as well, `-WhatIf` to preview and `-OutFile` to keep the log. An agent that already has the target scope is skipped. With `-OwnerOnly`, an agent whose owner is missing or disabled is reported as failed rather than locked out of everyone. `-AllowUsers` and `-AllowGroups` are checked against Entra before anything changes.

Restricting changes who may use the agent. It does not end a running session or touch the agent's Entra identity; use `-DisableIdentity` with a block for that.

### AI activity from Purview

DSPM's Activity Explorer has no API of its own. It is a view over the Microsoft Purview unified audit log, which Graph exposes as asynchronous searches. `-AiActivity` runs them, ties each record to a catalog agent and flags the risky events.

```powershell
.\Agent365-Bulk-Actions.ps1 -AiActivity                                  # every agent with activity, worst first
.\Agent365-Bulk-Actions.ps1 -AiActivity -AiDays 7 -RiskyOnly             # only agents with a risk signal in the last week
.\Agent365-Bulk-Actions.ps1 -AiActivity -ForAgent "Contoso HR Agent"     # the events of one agent
.\Agent365-Bulk-Actions.ps1 -AiActivity -OutFile .\ai-activity.csv       # export the summary (or, with -ForAgent, the events)
```

| Signal | Where it comes from in the audit record | Risk |
| --- | --- | --- |
| Jailbreak attempt | A `JailBreak` entry in the accessed resources, or a message flagged `JailbreakDetected` | High |
| Indirect prompt injection | An `IndirectAttack` entry, with the tool it came through | High |
| Runtime protection blocked | A `SecurityWebhook` verdict of `Block`, with the detection rule and the tool | High |
| Protection check failed | A `SecurityWebhook` verdict of `Fail` (the call was not evaluated, for example a timeout) | Medium |
| Labeled file accessed | An accessed file that carries a sensitivity label | Medium |

The tool reads `CopilotInteraction` records (the interactions), `AISpanOutputs` records (the agent's responses) and the Agent 365 operations `AIInvokeAgent`, `AIExecuteTool`, `AIInferenceCall` and `AIGuardrail`. A record is tied to an agent through Defender's identifiers for it (agent id, bot id, Entra id, observability id, source id). Events of agents that are not in the catalog, such as Microsoft 365 Copilot's own agents, are counted but not listed.

**In the console:** select an agent and press **AI activity...** (or open **Details...** and use the **AI activity** tab). Pick a period, press **Load from Purview audit**, and the events appear with the risk coloured. The search covers the whole tenant and is reused by every agent you open afterwards. **Risky only** hides routine events, and **Whole conversation** lists every event of the highlighted event's conversation, oldest first.

Each event reads as one line under **What happened**, for example *Tools: a365outlookmailmcp, UniversalSearchTool; Files: 1; Web pages: 3* or *Handed to Email communication agent*. Select an event for the detail pane:

- **Event**: time, user, app, conversation and thread ids, client address and region.
- **Model**: the model and provider, any built-in plugin and the licence.
- **Tools and MCP**: each connector or MCP server called, with the action.
- **Files**: SharePoint and OneDrive files read, with their address and whether they carry a sensitivity label.
- **Web**: pages cited or read, and whether the agent searched the web.
- **Protection**: the verdict for every tool call (Allow, Block or Fail) with the rule, the tool and the duration, plus the text of any flagged jailbreak or injected instruction.
- **Messages and Response**: how many prompts and responses the turn had; for a response, the channel, the step and any error.

Things to know:

- The audit log keeps **message ids only, not the prompt and response text** (apart from the text of a flagged jailbreak or injection, shown as the first 160 characters). Microsoft's Interaction Export API returns the text but excludes agents built in Copilot Studio; for the conversation itself, open it in Purview using the conversation id.
- Risk levels come from the audit signals above, not from Insider Risk Management. The portal's risk level and sensitive-information classification are computed inside Purview and have no API. Insider Risk, DLP and Security for AI alerts do reach Defender, so `-Risky` covers those.
- A search takes about a minute for 7 days and about ten minutes for 30. Ranges longer than 30 days are split into windows that run side by side. The audit retention of your licence bounds `-AiDays` (maximum 180).
- Each run creates audit searches named `Agent365-Bulk-Actions AI activity ...`. The service does not allow deleting them through the API, so they stay in the Purview audit search history until you remove them there.

### Endpoint AI: local agents and shadow AI

Agents are not only in the cloud. People install coding agents, desktop assistants, agentic IDEs and local model runtimes on their own devices, often without anyone reviewing them. `-EndpointAi` finds them on devices onboarded to Microsoft Defender for Endpoint and shows what each one did and which risks it carries. It only reads.

```powershell
.\Agent365-Bulk-Actions.ps1 -EndpointAi                                   # every AI tool found, worst first
.\Agent365-Bulk-Actions.ps1 -EndpointAi -RiskyOnly -EndpointDays 14       # high and medium risk, last two weeks
.\Agent365-Bulk-Actions.ps1 -EndpointAi -ForDevice "lab-*"                # the full evidence for the tools on matching devices
.\Agent365-Bulk-Actions.ps1 -EndpointAi -Sanctioned "GitHub","Microsoft" -OutFile .\endpoint-ai.csv
```

In the console, **Agents > Shadow AI** shows the same view: a grid of tools, with the evidence for the selected one underneath.

**What it reads.**

| Source | What it adds |
| --- | --- |
| Defender's local agent discovery (`AgentsInfo`, platform `LocalAgents`) | The agent, its vendor and version, the account it runs under, whether its host process is trusted, whether it approves its own actions, and its MCP servers. Needs Defender for Endpoint Plan 2. |
| Process telemetry | Which tools ran, when, started by what, from where, and with which flags. Also finds tools Defender's discovery does not list, such as LM Studio, GPT4All or a local MCP server started with `npx`. |
| Network telemetry | The services each tool connected to, and every port it listens on, including whether it is reachable from other machines. |
| Software inventory and vulnerabilities | The installed version, and its known vulnerabilities. |
| File telemetry | Model files and MCP configuration files written to disk. |
| Alerts and device details | Alerts on the device, and the device's exposure level and asset value. |

**Risk.** Each tool gets the highest level of the rules it triggers, and every reason is shown.

| Level | Rule |
| --- | --- |
| High | It approves its own actions (Defender's flag), or was started with a flag that skips approvals (`--dangerously-skip-permissions`, `--yolo`, `--full-auto`, `--allow-all-tools`). |
| High | It listens on an address other than loopback, so other machines can reach it (for example a model server on `0.0.0.0:11434`). |
| High | The installed version has a critical vulnerability. |
| High or Medium | AI-related alerts fired within 15 minutes of the tool running: High when any is High or Critical, otherwise Medium. |
| Medium | The installed version has a high-severity vulnerability. |
| Medium | Its host process is not trusted, or a local MCP server is fetched by a package runner (`npx`, `uvx`) every time it starts. |
| Medium | It runs on a device Defender rates as high value. |
| Low | The device has a High exposure level, MCP servers are configured, model or MCP configuration files were written, or (when you pass `-Sanctioned`) the tool is not on your list. |

`-Sanctioned` takes tool or vendor names (substring match) that you have approved. A tool then shows as Sanctioned or Unsanctioned; without the list every tool is Unreviewed and the list rule does not apply.

Things to know:

- **Only onboarded devices are visible.** The summary says how many devices are onboarded. A tool on a device that is not onboarded is not listed.
- **Prompts and credentials are hidden.** Command lines are shown with the text after `-p`, `--prompt` or `--message`, API keys, bearer tokens and `sk-` keys replaced.
- **Alerts name the device, not the process.** An alert is counted against a tool only when it fired within 15 minutes of that tool running, so the match is by timing. Other alerts on the device are listed in the evidence without affecting the level.
- **Defender keeps about 30 days** of endpoint telemetry. The software inventory and Defender's discovery record are current.
- **The portal's own risk level needs a different licence.** Microsoft 365 E7, or Agent 365 with Defender for Endpoint Plan 2, adds a risk level, risk indicators and recommendations in the Defender portal's AI agent inventory. They are not available through Advanced Hunting, so this tool computes its own from the rules above.
- **Removed agents are left out.** An agent Defender marks as deleted or uninstalled is not listed. An older version of an agent that was reinstalled is counted once.


#### Block a local AI agent on a device

```powershell
.\Agent365-Bulk-Actions.ps1 -BlockLocalAgent "Ollama" -ForDevice "lab-pc-01" -WhatIf      # show the files, change nothing
.\Agent365-Bulk-Actions.ps1 -BlockLocalAgent "Ollama" -ForDevice "lab-pc-01" -OutFile .\block.csv
.\Agent365-Bulk-Actions.ps1 -UnblockLocalAgent "Ollama" -ForDevice "lab-pc-01"           # delete the rule
.\Agent365-Bulk-Actions.ps1 -Undo .\block.csv                                           # the same, from the log
```

In the console, select a tool on the Shadow AI page and press **Block on this device...** (or **Remove block**). A **Blocked** column shows what is blocked.

- **What it does.** It creates a Microsoft Defender custom detection rule named `Agent365 Bulk Actions: block <tool> on <device>`. The rule matches only that device and only the program files the tool was seen running from, and its action is *stop and quarantine file*. A version folder in the path (for example `Claude_1.52.3.0`) matches any version, so an update is covered. Other devices are not affected.
- **Why not Microsoft's own block.** The Shadow AI page in the Microsoft 365 admin center blocks only OpenClaw, Node.js-based agents (blocking one blocks them all, and Node.js with them) and VS Code extensions, through an Intune policy on managed Windows devices. Ollama, Claude, GitHub Copilot CLI and ChatGPT Desktop are listed as not blockable there.
- **Timing.** Defender runs the rule when it is created and then every hour. The files are stopped and quarantined each time it finds them, so the effect is not instant.
- **What cannot be blocked.** MCP server and model-file rows (they are not programs of their own), files in the Windows folder, and Microsoft's own app packages. A tool installed from the Microsoft Store is allowed, with a warning: Defender may not be able to quarantine files in that protected folder.
- **Undo.** Deleting the rule (`-UnblockLocalAgent`, `-Undo`, **Remove block**) stops further quarantines. Files already quarantined stay quarantined until you restore them in Microsoft Defender. The service accepts the delete at once, but its rule list can keep showing the rule for several minutes.
- **Requirements.** The `CustomDetection.ReadWrite.All` permission, and a Defender role that manages custom detections and can remediate files, such as Security Administrator. The device must be onboarded to Defender for Endpoint. The API is beta.


### Contain and clean up

```powershell
.\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 14 -DisableIdentity -OutFile .\run.csv         # block, then verify the identity is disabled
.\Agent365-Bulk-Actions.ps1 -Risky -MinSeverity High -Impact -Action list                    # who would lose each agent
.\Agent365-Bulk-Actions.ps1 -DeleteCandidates -MinDaysBlocked 30 -OutFile .\delete-candidates.csv
```

- **`-DisableIdentity`** checks the agent's Entra identity after the block. Blocking a package that has an Agent ID normally makes the platform disable the identity within about ten seconds, and unblocking re-enables it. The tool waits up to 30 seconds, records `Disabled (by platform)` or `Enabled (by platform)` in the log, and calls the identity API itself only if the platform left it in the wrong state (`Disabled (by tool)`, or `Failed` with the error). Only agents that have an identity and that the run blocked or unblocked are checked; an agent already in the target state is left as it is, so `-WhatIf` changes nothing. The forced path needs `AgentIdentity.EnableDisable.All` and the Agent ID Administrator role.
- **`-Impact`** reads each target's detail record (`activeUsers`, `totalSessions`, `lastUsedDateTime`). These figures are not in the list call, so the tool fetches them only for the agents you are about to act on.
- **`-DeleteCandidates`** deletes nothing: the catalog API has no delete, and a block lasts until someone reverses it. It lists blocked agents that have stayed blocked at least `-MinDaysBlocked` days. The block date comes from this tool's own logs (`-OutFile` files and the console's logs under `%LOCALAPPDATA%\Agent365-Bulk-Actions\logs`; add others with `-History`) and from the `BlockedAgent` audit events Defender keeps for about 30 days. Agents whose block date is unknown are skipped unless you add `-IncludeUnknown`. Delete them in the admin center (Agents > All agents > Delete, then Deleted > Permanently delete), or through the Power Platform API for Copilot Studio agents.

### Respond to a compromised agent

```powershell
.\Agent365-Bulk-Actions.ps1 -ConfirmCompromised "Contoso HR Agent" -WhatIf       # show each agent's current Entra risk, change nothing
.\Agent365-Bulk-Actions.ps1 -ConfirmCompromised "Contoso HR Agent" -OutFile .\compromised.csv
.\Agent365-Bulk-Actions.ps1 -ConfirmCompromised "Contoso HR Agent" -RevokeSessions   # and end the sessions of its user accounts
.\Agent365-Bulk-Actions.ps1 -Undo .\compromised.csv                               # dismiss the flag again
.\Agent365-Bulk-Actions.ps1 -DismissRisk "Contoso HR Agent"                       # dismiss an active risk, with or without a log
```

- **What it does.** It marks the agent's Entra identity as compromised in Microsoft Entra ID Protection. Entra sets the risk level to High and records an admin-confirmed detection. A Conditional Access policy that blocks high agent risk then blocks the agent; without such a policy the flag alone blocks nothing. To stop the package as well, block it (`-Block`, or **Block selected** in the console).
- **Preview.** The tool shows each agent's current Entra risk (not flagged, at risk, dismissed, confirmed compromised) before it asks once. An identity that is already confirmed is skipped. An agent with no Entra agent identity is left out with a warning.
- **Entra applies it with a delay.** Entra accepts the request at once and shows the new state a minute or two later. The tool reads it back for up to `-WaitSeconds` (default 240; 0 does not wait). An agent that has not shown the state by then is logged as accepted but not verified (`Verified` is `False`), and the console does not wait at all. Check the Risky agents report in Microsoft Entra, or run the command again, to see it.
- **Undo dismisses the risk.** Entra has no call that returns an agent to the state before, so `-Undo` and **Undo last run** dismiss the risk: the agent ends up *dismissed*, and the admin-confirmed detection stays in Entra's detection history (kept for 90 days). If Entra had already flagged the agent before you confirmed it, dismissing clears that earlier risk too, and the tool warns about it. A confirmation Entra had not shown yet when the log was written may still appear after an undo; dismiss it again then. To clear a flag without a log, use `-DismissRisk` or, in the console, **Entra risk > Clear the compromised flag...**; dismissing cannot itself be undone.
- **Requirements.** The Security Administrator role and the `IdentityRiskyAgent.ReadWrite.All` permission. The call is beta only.

### Check Conditional Access for agents

```powershell
.\Agent365-Bulk-Actions.ps1 -CheckConditionalAccess                                # the agents Defender or Entra rate as risky
.\Agent365-Bulk-Actions.ps1 -CheckConditionalAccess -MinSeverity Medium            # only Defender alerts of Medium or higher
.\Agent365-Bulk-Actions.ps1 -CheckConditionalAccess -ForAgent "Contoso HR Agent" -OutFile .\ca.csv
.\Agent365-Bulk-Actions.ps1 -CheckConditionalAccess -AllAgents -OutFile .\ca-all.csv     # every agent in the catalog, summarised by covering policy
```

Read-only. For each agent it answers one question: would Microsoft Entra Conditional Access block this agent if its risk were High? Without `-ForAgent` or `-AllAgents` the tool checks the agents Defender flags as risky (last 30 days, optionally limited by `-MinSeverity`) together with the agents Entra ID Protection currently rates at risk or confirmed compromised.

**All agents.** `-AllAgents` checks every agent in the catalog (add `-AgentsOnly` for Copilot agents only). It first prints a *By coverage* table that counts agents with the same verdict and the same covering policies, then one line per agent, worst verdict first; the covering policy column appears only when agents differ. Agents with no Entra agent identity cannot be covered by Conditional Access for agents and are counted in one warning instead of one row each. `-OutFile` writes every agent with its verdict, `CoveredBy` and `PoliciesThatApply`.

| Verdict | Meaning |
| --- | --- |
| **Protected** | An enabled policy that blocks at High agent risk targets this agent identity and the resources it signs in to. The detail says whether it is blocked now. |
| **Report-only** | Only a report-only policy targets it. Entra logs what it would have blocked and blocks nothing. |
| **No effect** | An enabled policy targets the agent but protects no resources (its target resources are *None*), so it never applies. |
| **Possible** | The policy selects agents by a custom security attribute rule. The rule is shown, not evaluated; check it in Entra. |
| **Unprotected** | No enforced policy blocks the agent at High agent risk. A policy that only covers lower risk levels leaves it here. |

- **Blocked now needs Entra to rate the agent.** Agent risk comes from Entra's own detections or from confirming the agent compromised. Defender alerts do not change it, so a Defender-risky agent that Entra has not flagged is *Protected* but *not blocked now*. Confirming it as compromised (see [Respond to a compromised agent](#respond-to-a-compromised-agent)) raises its risk to High, which the policy then enforces.
- **Enabled does not mean effective.** An enabled policy whose target resources are *None* never applies; the tool lists these by name.
- **Agents without an Entra agent identity** (for example declarative agents) cannot be covered by Conditional Access for agents and are listed separately.
- **MCP blocks are not protection.** A policy that names specific resources, such as one made by `-BlockMcp`, blocks the agent there only, so it is listed but not counted as protection at High risk.
- **What is not evaluated.** Policies for the on-behalf-of flow (they target users), policies for agent user accounts, and attribute rules. Resources that accept an API key instead of a token are outside Conditional Access.
- **Requirements.** `Policy.Read.All`, `IdentityRiskyAgent.Read.All` (or the ReadWrite permission) and `Application.Read.All`. The policy call is beta only. `-OutFile` writes agent, identity, Entra risk, verdict, detail and the policies that apply.
- **In the console**, **Security > Conditional Access** shows the same result for the ticked agents, or every agent that has an Entra identity when none is ticked, with the policies behind the selected agent below. **Entra risk > Check Conditional Access...** opens it too.

### Agent users and licenses

```powershell
.\Agent365-Bulk-Actions.ps1 -AgentUsers                                  # last 30 days, every agent
.\Agent365-Bulk-Actions.ps1 -AgentUsers -UserDays 7                      # last 7 days (7, 14 or 30)
.\Agent365-Bulk-Actions.ps1 -AgentUsers -UserDays 14 -Unlicensed         # only users with neither an Agent 365 nor an E7 license
.\Agent365-Bulk-Actions.ps1 -AgentUsers -ForAgent "Contoso HR Agent" -OutFile .\agent-users.csv
```

Read-only. It answers who interacts with which agent in the last 7, 14 or 30 days, and whether each of those users holds an Agent 365 or a Microsoft 365 E7 license.

- **Interactions.** They come from Defender Advanced Hunting: the user-attributed `InvokeAgent`, `CopilotInteraction` and `ConnectedAIAppInteraction` events, matched to a catalog agent through every id the agent appears under (registry id, Entra agent id, observability id, source id, bot id, blueprint). One read covers all three periods. Defender keeps about 30 days, so 30 is the longest period.
- **Output.** A summary line with the whole-tenant context (how many hits there are in all, how many are tied to an agent), a *By agent* table, and under *What fired* each hit as a few lines: the policy and rule, what the policy did (raised an alert, blocked access, notified the user), where it happened, the item, the person and the count. With `-ForAgent` it also says which of the chosen agents had no hits. With `-IncludeUnattributed` the hits that name only a person follow, with the item and, when the event carries one, the application id. `-OutFile` writes one row per policy, rule, agent and account with the counts for 7, 14 and 30 days.
- **License.** Read from each user's license details, which include licenses assigned through groups. A user counts as licensed when they hold the `AGENT_365` plan (the standalone Agent 365 SKUs, or a bundle that contains the plan) or a SKU whose name contains E7, unless the Agent 365 plan is turned off for that user. The column says which: `Agent 365`, `E7`, `Agent 365 (in <SKU>)`, `Agent 365 plan turned off` or `None`.
- **Accounts that are not users.** An id that is not a directory user (an agent identity, or an account since deleted) is listed by the name on the event, marked *Not applicable*, and never counted as unlicensed.
- **Requirements.** `ThreatHunting.Read.All`, `User.Read.All` and `CopilotPackages.Read.All`, all already part of `-SignIn`. Reading license details also needs an Entra role such as License Administrator, User Administrator or Global Reader.
- **In the console**, the **Users** page shows the same data, with a 7, 14 or 30 day selector, a *No Agent 365 or E7 license only* filter, a search box and export. It covers the ticked agents, or every agent when none is ticked.

### Purview policy hits on agents

```powershell
.\Agent365-Bulk-Actions.ps1 -AgentPolicyHits                                   # last 30 days, every agent
.\Agent365-Bulk-Actions.ps1 -AgentPolicyHits -HitDays 7 -IncludeUnattributed   # 7, 14 or 30; also the hits that name only a person
.\Agent365-Bulk-Actions.ps1 -AgentPolicyHits -ForAgent "Contoso HR Agent" -OutFile .\policy-hits.csv
```

Read-only. It shows which Purview policies **fired** on which agents. It is evidence of what happened, not a list of the policies configured for agents; the policy definitions are only available from Security & Compliance PowerShell and the Purview portal.

| Source | What it holds | Where it comes from |
| --- | --- | --- |
| DLP match | The policy, rule, actions and severity of each Data Loss Prevention rule that matched, with who triggered it | Defender Advanced Hunting, `CloudAppEvents` events of type `DLPRuleMatch` |
| DLP alert | An alert a DLP policy raised, with the policy it names | Microsoft Graph alerts API, source `dataLossPrevention` |
| Insider Risk alert | An alert an Insider Risk Management policy raised, for example from the Risky agents template | Microsoft Graph alerts API, source `microsoftInsiderRiskManagement` |

- **How a hit is tied to an agent.** A DLP match can carry the application id of the agent, which Defender's inventory maps to a catalog agent. A hit on an agent's own user account is tied through that account's parent identity, and from there through the identity's application id or blueprint. An id shared by several agents (a blueprint they have in common) is treated as ambiguous and not used. A hit that names only a person, such as the human who typed a sensitive prompt, cannot be tied to an agent: it is counted, listed with `-IncludeUnattributed` and shown with the application id it carries, if any, so that an agent missing from Defender's inventory can be spotted.
- **Output.** A summary line, a *By agent* table (hits by source, policies, last hit), a *By policy* table, and with `-IncludeUnattributed` the hits that name only a person. `-OutFile` writes one row per policy, rule, agent and account with the counts for 7, 14 and 30 days.
- **Not covered.** Communication Compliance has no alert or event source here. Insider Risk risk levels per agent are shown in the Purview portal's DSPM AI observability page, which has no API this tool uses. Advanced Hunting keeps about 30 days.
- **Requirements.** `ThreatHunting.Read.All`, `SecurityAlert.Read.All`, `User.Read.All`, `CopilotPackages.Read.All`, `AgentIdentity.Read.All` and `Application.Read.All`, all part of `-SignIn`.
- **In the console**, **Security > Policy hits** shows the same data, with a 7, 14 or 30 day selector, a switch for hits not tied to an agent, a search box and export. It covers the ticked agents, or every agent when none is ticked; when you tick agents it says which of them had no hits. Select a row for the detail pane: how the hit was tied to the agent, what the policy did, the item with its path, the counts for 7, 14 and 30 days and where to look in Purview. **Defender alerts...** on that page opens the Alerts page (below).

#### Defender alerts on agents

**Security > Alerts** in the console lists the Defender alerts that concern agents, one row per alert, for the ticked agents or all agents and a 7, 14 or 30 day period: when it was raised, the agent, the alert, its severity and category, the Defender source, and how it was tied. Pick a severity and a period, search, export, or select an alert for the detail pane and press **Open in Defender** to open it in the Microsoft Defender portal. **Respond** acts on the agent the alert names; see [Graphical console](#graphical-console).

- **What is listed.** An alert is listed when it carries the agent as an entity (Security for AI alerts, for example) or names the Azure AI resource a Foundry agent runs on. An alert naming an agent that Defender's inventory does not list is kept and named as the alert names it.
- **What is not.** Defender for AI Services alerts about model deployments (jailbreak attempts against a model, LLM reconnaissance) name no agent, so they are not listed; they are in the Defender portal under Incidents and alerts.
- **Source.** Defender Advanced Hunting (`AlertInfo` and `AlertEvidence`), so about 30 days.

### MCP access and per-agent MCP blocks

```powershell
.\Agent365-Bulk-Actions.ps1 -McpAccess                                              # every agent, last 30 days
.\Agent365-Bulk-Actions.ps1 -McpAccess -McpDays 7 -Unused                           # permissions with no call in 7 days
.\Agent365-Bulk-Actions.ps1 -McpAccess -ForAgent "Contoso HR Agent" -OutFile .\mcp.csv
.\Agent365-Bulk-Actions.ps1 -BlockMcp "Mail" -ForAgent "Contoso HR Agent" -ReportOnly   # report-only first
.\Agent365-Bulk-Actions.ps1 -BlockMcp "Mail","Teams" -ForAgent "Contoso HR Agent","Northwind Agent" -OutFile .\mcp-block.csv
.\Agent365-Bulk-Actions.ps1 -UnblockMcp "Mail" -ForAgent "Contoso HR Agent"
```

Agent 365's Tools registry (**Agents > Tools** in the Microsoft 365 admin center) and its Block switch act on every agent at once and have no public API. `-McpAccess` answers the same questions per agent from three sources the tool can read, `-BlockMcp` blocks one server for chosen agents with Conditional Access, and with `-Via Permission` it removes, grants or allows only chosen servers in the agents' Entra permissions instead (see [Manage MCP permissions](#manage-mcp-permissions)).

| Column | What it shows | Where it comes from |
| --- | --- | --- |
| Permission | Whether the agent may call the server | Entra delegated permission grants. Each Microsoft MCP server is its own application with the scope `Tools.ListInvoke.All` (*Own*). Agents set up earlier hold shared scopes, `McpServers.<Name>.All`, on the one *Agent Tools* application (*Shared*). A grant to a blueprint reaches its agent identities only when the blueprint lists the server as inheritable (*Blueprint only* when it does not). |
| Set up | The MCP servers the agent declares | Defender Advanced Hunting, `AgentsInfo` |
| Calls | The tool calls the agent made: how many in the period, when, which tools and how (Agent 365 gateway, SDK or Power Platform connector) | Defender Advanced Hunting, `CloudAppEvents` events `ExecuteToolByGateway` and `ExecuteToolBySDK` |
| Block | Whether a Conditional Access policy that names the server blocks the agent: *Blocked*, *Partly blocked* (its identity or its agent user account only), *Report-only* | Microsoft Entra Conditional Access |

- **Output.** A summary line, a *By server* table (agents with a permission, agents that set it up, agents that called it, calls, blocks) and one row per agent and server with a note such as *Has the permission but no call in 30 days*. `-Unused` lists only permissions with no call in the period, the candidates to remove. `-OutFile` writes every row with the permission detail, the tools called and the block policies.
- **One name per server.** A server goes by several names, for example `Work IQ Mail MCP`, `McpServers.Mail.All`, `mcp_MailTools` and `a365outlookmailmcp`; the tool counts them as one.
- **Not only agents.** Without `-ForAgent`, blueprints with no catalog entry and applications that are not agents (the Agent 365 CLI, for example) are listed with their kind when they hold MCP permissions.
- **Blueprint entries.** A catalog entry that stands for a whole blueprint (an A365 SDK agent registered as a template) has no agent identity of its own. The tool counts the identities made from it under that entry and blocks through the blueprint, which covers all of them.

**Blocking a server for chosen agents.** `-BlockMcp` puts the agents in a Conditional Access policy whose only resource is that server's Entra application, so Entra refuses them a token for it and nothing else changes. Entra does not accept agent identities and agent user accounts in one policy, so the tool keeps one policy for each per server and mode, named `Agent365 Bulk Actions: block MCP server <server> for agent identities` and `... for agent user accounts` (with `(report-only)` in report-only mode), and adds or removes agents in them. A policy left with nobody in it is deleted. Policies made by hand are read, never changed.

- **Report-only first.** With `-ReportOnly` nothing is blocked; Entra's sign-in logs record what would have been. Running `-BlockMcp` again without it moves the agents to the enforced policy.
- **The shared permission.** An agent that reaches a server only through a shared scope cannot be blocked from that server alone. Block *Agent Tools* (`-BlockMcp "Agent Tools"`), which stops every server the shared permission covers for that agent.
- **What it does not cover.** An agent acting on behalf of a signed-in person (user policies apply there), Copilot Studio agents (they reach MCP servers through Power Platform connectors: use a Power Platform data policy, or remove the tool from the agent) and agents with no Entra agent identity. The block applies at the agent's next token request; a token already issued stays valid for up to an hour.
- **Apply it at once.** Add `-RevokeSessions` to end the sessions of the blocked agents' user accounts straight after an enforced block; the console offers the same after **Block...**. See [Revoke an agent's sessions](#revoke-an-agents-sessions).
- **Undo.** `-UnblockMcp` removes the block. `-Undo <log>` and **Undo last run** put each agent and server back the way it was: blocked, report-only or not blocked.
- **Requirements.** To read: `DelegatedPermissionGrant.Read.All`, `Application.Read.All`, `Policy.Read.All`, `AgentIdentity.Read.All`, `User.Read.All`, `ThreatHunting.Read.All` and `CopilotPackages.Read.All`. To block: `Policy.ReadWrite.ConditionalAccess` and the Conditional Access Administrator role. All are part of `-SignIn`. Conditional Access for agents needs Microsoft 365 E7, or Agent 365 with at least Microsoft Entra ID P1. The policy calls are beta.
- **In the console**, **Agents > Tools** shows the same view for the ticked agents, or every agent when none is ticked, with a period, a filter (everything, permission but not used, used, blocked or report-only), a search box, export and a detail pane. Select one or more rows and press **Block...**, **Block in report-only...** or **Remove block**; a row that cannot be blocked says why.

#### Manage MCP permissions

```powershell
.\Agent365-Bulk-Actions.ps1 -BlockMcp "Mail" -ForAgent "Contoso HR Agent" -Via Permission -WhatIf        # remove one server's permission
.\Agent365-Bulk-Actions.ps1 -BlockMcp "Agent Tools" -ForAgent "Contoso HR Agent" -Via Permission         # every shared McpServers.* scope it holds
.\Agent365-Bulk-Actions.ps1 -UnblockMcp "Teams" -ForAgent "Contoso HR Agent" -Via Permission             # grant one server
.\Agent365-Bulk-Actions.ps1 -BlockMcp All -ExceptMcp "Mail","Calendar" -ForAgent "Contoso HR Agent" -Via Permission -GrantMissing -OutFile .\mcp-permissions.csv
.\Agent365-Bulk-Actions.ps1 -BlockMcp "Mail" -ForAgent "Northwind Agent" -Via Permission -IncludeSharedBlueprint
.\Agent365-Bulk-Actions.ps1 -Undo .\mcp-permissions.csv
```

A Conditional Access block leaves the permission in place and refuses the token. `-Via Permission` changes the permission itself, in the delegated permission grants Entra keeps for the agent. An agent holds an MCP server's scope through its own agent identity's grant, or through its blueprint's grant when the blueprint passes it on (its inheritable permissions). For each agent and server the tool takes the narrowest lever that reaches the agent:

| Where the agent gets the scope | What `-BlockMcp -Via Permission` does | Who it affects |
| --- | --- | --- |
| Its agent identity's own grant, for every user or for one agent user | Removes the scope from that grant, and deletes the grant only when nothing else is left in it | This agent |
| Its blueprint's grant, when every agent identity of the blueprint belongs to this catalog agent (a blueprint catalog entry, or a blueprint with this one agent) | Removes the scope from the blueprint's grant | This agent |
| Its blueprint's grant, when the blueprint also serves other catalog agents | Leaves the grant alone and blocks this agent from the server with Conditional Access instead, naming the other agents | This agent |
| The same, with `-IncludeSharedBlueprint` (in the console, the check box in the confirmation) | Removes the scope from the blueprint's grant | Every agent of that blueprint, named in the preview |

- **The shared permission.** For a server reached through the legacy shared permission (*Agent Tools*), removing the server removes only its `McpServers.<Name>.All` scope. The *Agent Tools (shared permission)* row stands for every `McpServers.*` scope the agent holds there. A shared scope inherited from a blueprint that other agents use cannot be blocked for one server with Conditional Access: remove the *Agent Tools* row instead, which is blocked for this agent alone, or use `-IncludeSharedBlueprint`.
- **Granting.** `-UnblockMcp <server> -Via Permission` adds `Tools.ListInvoke.All` of the server's own application to each agent identity of the agent: to its grant for that server, or in a new grant for every user. A blueprint catalog entry gets it on each of its agent identities, never on the blueprint. Only a server with an application of its own that publishes `Tools.ListInvoke.All` is granted; shared scopes never are. The permission is not enough on its own: the agent's code or manifest must also declare the server. A Conditional Access block of the server still applies; `-UnblockMcp` without `-Via Permission` removes it.
- **Allow only.** `-BlockMcp All -ExceptMcp <servers> -Via Permission` removes every MCP permission the agent holds except those servers, and `-GrantMissing` also grants the allowed servers it lacks. With `"Agent Tools"` in `-ExceptMcp` the shared scopes stay. With `-Via ConditionalAccess`, `All` means every known MCP server application, and the agent gets the Conditional Access block on each; an allowed server it reaches only through the shared permission is blocked with *Agent Tools* too, and the tool warns.
- **Preview.** The preview lists, per agent, server and scope, the lever, the agent identity or blueprint that holds the grant, and what happens to the grant: the scopes it keeps, deleted, or a new grant. A scope that is not an MCP scope is never removed or added. `-WhatIf` changes nothing, and each grant is read again just before it is written.
- **Timing.** A change applies at the agent's next token request; a token already issued keeps its permissions for up to an hour. `-RevokeSessions` ends the sessions of the changed agents' user accounts straight after.
- **Log and undo.** Each changed scope is one log record, `revokemcpscope` or `grantmcpscope`, with the grant, its client and resource, the consent type and user, the scope, and the grant's scopes before and after. `-Undo` and **Undo last run** add a removed scope back, creating a deleted grant again with the same consent type, user and scopes, and remove an added one, deleting the grant once nothing else is in it. A Conditional Access fallback is logged and undone as an MCP block.
- **Requirements.** `DelegatedPermissionGrant.ReadWrite.All` and the Cloud Application Administrator, Application Administrator or Privileged Role Administrator role, plus `Policy.ReadWrite.ConditionalAccess` and the Conditional Access Administrator role for the fallback. `-ReportOnly` applies only to the fallback.
- **In the console**, on **Agents > Tools**, **Remove permission...** works on the selected rows and **Set servers...** on the agent of the highlighted row. Set servers lists every known MCP server, ticked where the agent holds a permission, with whether the agent sets it up and its calls in 30 days; tick to grant, untick to remove. One confirmation lists each change with its lever, with the check box for a shared blueprint, and the console asks for `DelegatedPermissionGrant.ReadWrite.All` only after you confirm. The page then reads its data again.

### Revoke an agent's sessions

```powershell
.\Agent365-Bulk-Actions.ps1 -Block "Contoso HR Agent" -RevokeSessions
.\Agent365-Bulk-Actions.ps1 -BlockMcp "Mail" -ForAgent "Contoso HR Agent" -RevokeSessions
.\Agent365-Bulk-Actions.ps1 -ConfirmCompromised "Contoso HR Agent" -RevokeSessions -OutFile .\compromised.csv   # the revocation logs to compromised-revoke.csv
```

A block or a Conditional Access change applies when the agent next asks for a token, so a token it already holds keeps working until it expires, about an hour. `-RevokeSessions` closes that gap: straight after the block or the confirmation, it ends the sessions of the agents' user accounts (`revokeSignInSessions`).

- **What it does.** Entra invalidates the accounts' refresh tokens and, within a few minutes, tells the resources that support continuous access evaluation (Exchange, SharePoint, Teams and Microsoft Graph) to refuse the access tokens already issued. Other resources accept an access token until it expires. The agent signs in again on its own, which a block then refuses.
- **What it cannot do.** An agent identity's own tokens, used when the agent acts as itself, cannot be revoked; Entra has no such call. They expire on their own, and a block, a disabled identity (`-DisableIdentity`) or a Conditional Access policy stops new ones. An agent with no agent user account is skipped and says so.
- **Which accounts.** The agent user accounts of the agent's identity, or, for a catalog entry that stands for a whole blueprint, of every identity made from it. Only the agents the action changed are revoked: an agent already blocked, skipped or failed is left alone.
- **Undo.** Nothing to undo: the revocation only forces a new sign-in. `-Undo` on the action's log reverses the block or the confirmation as usual.
- **Requirements.** `User.RevokeSessions.All` (part of `-SignIn`) and an Entra role that can manage the accounts. `-RevokeSessions` works with `-Block`, `-BlockMcp` (enforced blocks only) and `-ConfirmCompromised`.
- **In the console**, **Entra risk > Revoke sessions...** ends the sessions of the ticked agents' user accounts on its own, the Tools page offers it after an enforced **Block...**, and **Respond > Revoke sessions...** on Security > Alerts does it for the agent an alert names.

### Policy file

Declare governance rules once, review the plan, then apply it. See [policy.example.json](policy.example.json).

```powershell
.\Agent365-Bulk-Actions.ps1 -Policy .\policy.example.json                                     # show the plan, change nothing
.\Agent365-Bulk-Actions.ps1 -Policy .\policy.example.json -Apply -OutFile .\policy-run.csv    # run it (one confirmation)
```

```json
{
  "name": "Agent governance baseline",
  "exclude": { "publishers": ["Microsoft Corporation"], "types": ["firstParty"], "names": [], "ids": [] },
  "rules": [
    { "name": "Contain high-risk agents",
      "when": { "risky": { "minSeverity": "High", "source": "Both" } },
      "then": { "action": "block", "disableIdentity": true } },
    { "name": "Pull back agents that keep tripping runtime protection",
      "when": { "aiActivity": { "days": 7, "minHigh": 3, "signals": ["Runtime protection blocked", "Jailbreak attempt"] } },
      "then": { "action": "restrict", "availableTo": "owner" } }
  ]
}
```

| Part | Values |
| --- | --- |
| `when` | `stale` (`by`: activity or modified, `days`, optional `includeNeverSeen`), `risky` (`minSeverity`, `minSignals`, `source`), `aiActivity` (below), `blockedDays`, `ownerless` (true), `state` (blocked or active) |
| `match` | `all` (default: every condition must hold) or `any` |
| `then.action` | `block`, `unblock`, `reassign` (applies the proposed owners), `restrict`, or `report` (list only, the default) |
| `then` for `restrict` | `availableTo`: `none` (default), `owner`, `some` (with `users` and/or `groups`) or `all`; optional `includeDeployment` |
| `then.disableIdentity` | With `block`: also disable the agent's Entra identity |
| `exclude` | Agents to leave alone, by `ids`, `names`, `publishers` or `types` |

The `aiActivity` condition matches agents with enough risky events in the window. `days` defaults to 7, `minHigh` to 1 and `minMedium` to 0; at least one minimum must be 1 or more, so a rule cannot match every agent that has any activity. `signals` optionally limits which signals count. The plan shows why each agent matched (for example *3 high, 0 medium in 7 days: Runtime protection blocked x2*), and the audit search runs once per plan however many rules use it.

A rule must have at least one condition, so a typo can never match the whole catalog. Rules that would change nothing (an agent already blocked) are shown but not counted. Write actions need a signed-in administrator; there is no app-only option.

### Snapshots and change reports

```powershell
.\Agent365-Bulk-Actions.ps1 -Snapshot .\inventory-2026-10-01.json
.\Agent365-Bulk-Actions.ps1 -Snapshot .\inventory-2026-10-08.json -CompareTo .\inventory-2026-10-01.json -OutFile .\changes.csv
```

The report lists agents that are new or removed, newly blocked or unblocked, and those whose owner or version changed.

### Graphical console

```powershell
pwsh -STA -File .\Agent365-Bulk-Actions.ps1 -Gui
```

A Windows desktop app over the same catalog, laid out like the Agent 365 portal: navigation on the left and one page at a time on the right. It opens on **All agents** with no filter applied. The top bar shows the signed-in account, which agents the other pages cover, and **Refresh catalog**.

| Page | What it shows | What you can do there |
| --- | --- | --- |
| Home | Catalog counts (total, blocked, shared agents without an owner, agents with an Entra identity) and, once their pages have been opened, the security findings: Defender alerts in 30 days, agents not protected by Conditional Access, unused MCP permissions and users without a license | Select a card to open the page behind it, already filtered |
| Agents > All agents | The registry: every agent, with count cards, search, filters and a funnel on every column | Everything in the action bar under the table (below) |
| Agents > Shadow AI | Local AI agents and shadow AI on Defender-onboarded devices, with the evidence for the selected one | **Block on this device...** and **Remove block** for the selected tool |
| Agents > Tools | Which MCP servers each agent may reach, sets up and calls | **Block...**, **Block in report-only...**, **Remove block** and **Remove permission...** for the selected rows; **Set servers...** for the highlighted agent; revoke sessions after a block |
| Users | Who used which agent in the last 7, 14 or 30 days, and whether each user has an Agent 365 or E7 license | Filter to users without a license, search, export |
| Security > Alerts | Defender XDR alerts that concern agents, with severity, category and source | **Respond** on the agent an alert names; **Open in Defender** |
| Security > Hunting | 18 built-in Advanced Hunting queries from the Agent365-Hunting library, grouped by area | Run one, change it first if you like, export the results, or copy it and open Advanced hunting in Defender |
| Security > Purview audit | AI activity per agent from the Purview audit log, and the events of the selected agent | Search the last 1, 7, 14 or 30 days, show risky events only, export |
| Security > Policy hits | DLP rule matches and DLP or Insider Risk alerts on agents | Open the Alerts page, export |
| Security > Conditional Access | Whether a Conditional Access policy blocks each agent at High agent risk, and the policies behind it | **Refresh** |

**Which agents a page covers.** Tick agents on All agents and the other pages cover only those; with nothing ticked they cover every agent, and the top bar says which. A page reads its data the first time it opens. Tools, Users, Alerts, Purview audit and Policy hits read it for every agent, so a change of ticked agents only filters what they hold; Conditional Access reads again. A page's **Refresh** button reads it again on demand. **Refresh catalog** reads the catalog again, and each page then reads its data again when you next open it.

**All agents.** The action bar under the table has two rows: selection, **Details...**, **AI activity...**, **Export** and **Undo last run** on top; **Apply suggested**, **Restrict access...**, **Assign owner...**, **Entra risk**, **Verify identity state**, **Unblock selected** and **Block selected** below.

| To do this | Use |
| --- | --- |
| Find agents | Search by name, publisher, platform or id. Filter All, Active or Blocked, and optionally Copilot agents only. **Reset filters** clears everything. |
| Filter by analysis | *Stale*, *Risk* (from alerts, detections or both), *Ownership*, *Blocked*, *Tools*, *Permissions* and *Access* dropdowns. Each defaults to **None**. The matching columns fill in. *Match All* needs every active Stale and Risk filter; *Any* accepts either. Stale, Risk and Blocked reuse their Defender query for ten minutes, so another threshold shows at once; **Refresh catalog** reads it again. |
| Filter any column | Every column header has a small funnel beside its name. It opens a box with a text search (matches part of a value, in any case) and the values the column holds, with how many agents have each; tick some to show only those. Text and ticked values work together. A filtered column's funnel turns blue and filled, the filters of different columns add up, and they combine with the filters above. **Reset filters** clears them all, and a filter ends when its column leaves the screen. Click the column name, not the funnel, to sort. |
| Block or unblock | Tick rows (or **Select visible**), then **Block selected** or **Unblock selected**. A confirmation lists the agents with their active users and last use. **Verify identity state** adds a check that the Entra identity ends up disabled (or enabled again after an unblock). |
| Fix ownership | *Ownership > Needs an owner* lists shared agents with no usable owner and a suggestion; tick the rows and press **Apply suggested** (enabled once a ticked row has a suggestion). **Assign owner...** opens a searchable Entra directory picker. |
| Add accountability | *Ownership > Missing an Entra sponsor* (or *sponsor or owner*) lists identities with a gap; **Apply suggested** adds the proposed person after a confirmation. |
| Restrict access | Tick rows and press **Restrict access...** to choose nobody, the owner only, named users and groups (searchable picker, Users or Groups) or everyone. Tick **Also apply this choice to deployment** to make who the agent is installed for follow the same choice (nobody, the same users and groups, or everyone); there is no separate deployment list. The *Access* filter lists agents open to everyone, restricted or closed. |
| Inspect an agent | **Details...** (or double-click a row): Overview, Sharing, Tools and MCP, Data, Permissions, Identity, Usage, Risk and AI activity tabs, with **Export JSON**. **AI activity...** opens it on that tab. The **Tools and sharing columns** checkbox adds tool count, MCP servers, shared-with count and channels. |
| Entra risk | Tick agents and open **Entra risk**: **Confirm as compromised...** sets the risk level of their Entra identities to High, and **Clear the compromised flag...** dismisses the risk again. The console does not wait for Entra to show the new state, which takes a few minutes. **Check Conditional Access...** opens the Conditional Access page for the ticked agents. **Revoke sessions...** ends the sessions of the ticked agents' user accounts, so a block applies at once. |
| Undo | **Undo last run** reverses the previous block, unblock, access change, sponsor addition, compromised flag (it dismisses the risk), MCP block change or MCP permission change, including one made on the Tools page or from an alert. |
| Export | **Export** saves the grid as CSV or JSON. |

**Respond from an alert.** On Security > Alerts, select an alert and open **Respond**: **Block the agent...**, **Confirm as compromised...**, **Revoke sessions...**, **Block an MCP server for it...** (opens the Tools page on that agent) or **Show it in All agents**. The actions use the same confirmations and logs as on All agents, and **Undo last run** reverses a block or a compromised flag made this way. They need the alert to name an agent in the catalog.

**Hunting.** The built-in queries come from the Agent365-Hunting library and were validated against Defender Advanced Hunting. They cover inventory and governance gaps, telemetry health, agents at risk, runtime protection, permissions and posture, sign-ins and risky users, MCP servers and tools, sensitive data with external reach, and blocked agentic network traffic. Each reads about the last 30 days unless its first lines say otherwise. Select one to see what it does and its text; change the text if you like (Reset puts the built-in text back) and press **Run**. The results show every column the query returns, with objects and lists as JSON; **Export** saves them as CSV or JSON, and **Copy and open Defender** copies the query and opens Advanced hunting in the Defender portal. A query that reads data your tenant does not collect (Global Secure Access traffic, for example) returns nothing. Running a query needs `ThreatHunting.Read.All`.

**Purview audit.** The same AI activity as `-AiActivity`, for every agent at once: pick a period and press **Read audit log** (a search takes a few minutes), then select an agent for its events, newest first. **Risky only** counts only events with a risk signal. The search covers the whole tenant and is shared with the AI activity tab of the details window. It needs `AuditLogsQuery.Read.All` and a Purview audit role.

Each write action saves a result log under `%LOCALAPPDATA%\Agent365-Bulk-Actions\logs`.

## Parameter reference

Use one primary mode per run. Options marked "with ..." only apply to that mode.

### Modes

| Parameter | Values | What it does |
| --- | --- | --- |
| `-List` | switch | List catalog packages. |
| `-Block` | names and/or ids | Block packages by display name or `P_`/`T_` id. |
| `-Unblock` | names and/or ids | Unblock packages. |
| `-Select` | switch | Pick agents from a grid or numbered menu, then apply `-Action`. |
| `-FromCsv` | path | Apply `-Action` (block, unblock or list) to every agent in a CSV with an `Id` or `DisplayName` column. |
| `-Undo` | path | Reverse a run from its `-OutFile` log (block state, owners, access scope, added sponsors and owners, compromised flags, local AI agent block rules, MCP blocks, MCP permissions). Every row is checked first. |
| `-Stale` | switch | Act on agents stale beyond `-StaleDays`. |
| `-Risky` | switch | Act on agents with Defender AI-security alerts or detections. |
| `-Ownerless` | switch | Propose owners for shared agents whose owner is missing. Add `-Action reassign` to apply. |
| `-Reassign` | names and/or ids | Assign these agents to the user in `-To`. |
| `-Accountability` | switch | List Entra identities with no valid sponsor; `-Action assign` adds the proposals. |
| `-AddSponsor` | names and/or ids | Add `-To` as sponsor (or owner with `-AsOwner`) of these agents' identities. |
| `-SignIn` | none | Sign in once with every permission the tool can use; later runs reuse the saved session. |
| `-ConfirmCompromised` | names and/or ids | Confirm these agents' Entra identities as compromised (risk level High). |
| `-DismissRisk` | names and/or ids | Dismiss the Entra risk of these agents' identities. |
| `-CheckConditionalAccess` | switch | Check whether Conditional Access blocks risky agents (or the agents in `-ForAgent` or `-AllAgents`) at High agent risk. Read-only. |
| `-Restrict` | names and/or ids | Change who can use these agents. |
| `-BlockLocalAgent` | tool names (wildcards allowed) | Have Defender stop and quarantine these local AI agents on the devices in `-ForDevice`. |
| `-UnblockLocalAgent` | tool names (wildcards allowed) | Remove the block rule of these local AI agents on the devices in `-ForDevice`. |
| `-EndpointAi` | switch | Local AI agents and shadow AI on Defender-onboarded devices, with telemetry and risk. |
| `-AiActivity` | switch | Risky AI activity per agent from the Purview audit log. |
| `-AgentUsers` | switch | Which users interacted with which agent, and whether each has an Agent 365 or E7 license. Read-only. |
| `-AgentPolicyHits` | switch | Which DLP rules matched and which DLP or Insider Risk alerts were raised on which agent. Read-only. |
| `-McpAccess` | switch | Which MCP servers each agent may reach, sets up and calls, and whether Conditional Access blocks it. Read-only. |
| `-BlockMcp` | server names, or `All` | Block these MCP servers (Mail, Calendar, a BYO server, or Agent Tools for the shared permission) for the agents in `-ForAgent` with Conditional Access, or with `-Via Permission` remove the agents' permission for them. `All` with `-ExceptMcp` allows only the servers named there. |
| `-UnblockMcp` | server names | Remove this tool's block of these MCP servers for the agents in `-ForAgent`, or with `-Via Permission` grant the agents these servers. |
| `-DeleteCandidates` | switch | List agents blocked at least `-MinDaysBlocked` days (default 30). Deletes nothing. |
| `-Policy` | path | Evaluate a JSON policy and print the plan. |
| `-Snapshot` | path | Save the inventory to a JSON file. |
| `-Detail` | name or id | Print the full record of one agent. |
| `-Inventory` | switch | One row per agent. |
| `-Gui` | switch | Open the console. |

### Options

| Parameter | Used with | Values and default | What it does |
| --- | --- | --- | --- |
| `-Action` | select, stale, risky, FromCsv, ownerless, accountability | `block` (default), `unblock`, `list`; `reassign` with `-Ownerless`; `assign` with `-Accountability` | What to do with the matched set. `list` previews. |
| `-AgentsOnly` | list, select, stale, risky, inventory, CheckConditionalAccess | switch | Limit to Copilot agents (`supportedHosts` contains `Copilot`). |
| `-Pick` | stale, risky | switch | Choose which matches to act on in the picker. |
| `-Force` | any write | switch | Skip the confirmation. |
| `-WhatIf` | any write | switch | Show what would change; change nothing. |
| `-OutFile` | most modes | path (.csv or .json) | Write a result log, or export the result. |
| `-TenantId` | all | GUID or domain | Target a specific tenant. |
| `-ClientId` | all | GUID | Sign in with your own app registration instead of the shared Graph PowerShell app; needs `-TenantId`. See [Use your own app registration](#use-your-own-app-registration). |
| `-DeviceCode` | all | switch | Sign in with a device code from the start, instead of a sign-in window. Without it the window comes first and the tool falls back to a code only where it cannot be shown. A code works for about two minutes; the tool asks for a new one up to three times. A session made with a code is reused with a code, which the tool does by itself. |
| `-DisableIdentity` | block, unblock | switch | Verify the Entra identity is disabled (enabled after unblock); force it only if the platform did not. |
| `-Impact` | block, unblock, stale, risky | switch | Show active users, sessions and last use before acting. |
| `-StaleDays` | `-Stale` | 1 to 3650 | Age threshold in days. |
| `-By` | `-Stale` | `activity` (default), `modified` | Telemetry or manifest age. |
| `-IncludeNeverSeen` | `-Stale` | switch | Also treat agents with no telemetry as stale. |
| `-RiskDays` | `-Risky` | 1 to 3650, default 30 | Lookback window (Advanced Hunting keeps about 30 days). |
| `-RiskSource` | `-Risky` | `Both` (default), `Alerts`, `Detections` | Which signals count. |
| `-MinAlerts` | `-Risky` | integer, default 1 | Minimum signals for an agent to count. |
| `-MinSeverity` | `-Risky`, `-CheckConditionalAccess` | Informational, Low, Medium, High | Minimum severity. |
| `-HuntingQuery` | stale, risky | KQL | Custom query. Stale returns `Key, LastActivity`; risky returns `Key, AlertCount, DetectionCount, Severity, LastAlert`. |
| `-To` | reassign, AddSponsor | UPN or object id | The person to assign. |
| `-AsOwner` | `-AddSponsor` | switch | Add as owner instead of sponsor. |
| `-IncludeOwners` | `-Accountability` | switch | Also look for identities with no owner. |
| `-WaitSeconds` | `-ConfirmCompromised`, `-DismissRisk` | integer 0 to 900, default 240 | How long to wait for Entra to show the new state. 0 does not wait. |
| `-AvailableTo` | `-Restrict` | `None` (default), `Some`, `All` | Nobody, named users and groups (or the owner), or everyone. |
| `-AllowUsers`, `-AllowGroups` | `-Restrict` | UPNs or ids; names or ids | Who the agents stay available to (with `-AvailableTo Some`). |
| `-OwnerOnly` | `-Restrict` | switch | Keep each agent available to its own owner (with `-AvailableTo Some`). |
| `-IncludeDeployment` | `-Restrict` | switch | Also change who the agent is deployed to. |
| `-AllAgents` | `-CheckConditionalAccess` | switch | Check every agent in the catalog instead of the risky ones. Not with `-ForAgent`. |
| `-ForAgent` | `-AiActivity`, `-CheckConditionalAccess`, `-AgentUsers`, `-AgentPolicyHits`, `-McpAccess`, `-BlockMcp`, `-UnblockMcp` | names and/or ids | List the individual events of these agents, check these agents instead of the risky ones, show only these agents, or the agents to block or unblock (required with `-BlockMcp` and `-UnblockMcp`). |
| `-UserDays` | `-AgentUsers` | 7, 14 or 30, default 30 | The period for interactions. |
| `-Unlicensed` | `-AgentUsers` | switch | Only users who have neither an Agent 365 nor an E7 license. |
| `-HitDays` | `-AgentPolicyHits` | 7, 14 or 30, default 30 | The period for policy hits. |
| `-IncludeUnattributed` | `-AgentPolicyHits` | switch | Also list the hits that name only a person, so no agent can be named. |
| `-McpDays` | `-McpAccess` | 7, 14 or 30, default 30 | The period for calls and for "not used". |
| `-Unused` | `-McpAccess` | switch | Only permissions with no call in the period. |
| `-RevokeSessions` | `-Block`, `-BlockMcp`, `-ConfirmCompromised` | switch | Straight after the change, end the sessions of the changed agents' user accounts so it applies at once. Logged beside `-OutFile` as `name-revoke.csv`. |
| `-ReportOnly` | `-BlockMcp` | switch | Block in report-only mode: nothing is blocked, and Entra's sign-in logs record what would have been. With `-Via Permission` it applies only to the Conditional Access fallback. |
| `-Via` | `-BlockMcp`, `-UnblockMcp` | `ConditionalAccess` (default), `Permission` | `ConditionalAccess` blocks with a Conditional Access policy. `Permission` removes (`-BlockMcp`) or grants (`-UnblockMcp`) the Entra permission itself, through the narrowest grant that reaches each agent. See [Manage MCP permissions](#manage-mcp-permissions). |
| `-ExceptMcp` | `-BlockMcp All` | server names | The MCP servers to leave allowed. |
| `-IncludeSharedBlueprint` | `-BlockMcp -Via Permission` | switch | Remove a permission from a blueprint's grant even when other catalog agents use the blueprint; they lose it too and are named in the preview. Without it the tool blocks the agent with Conditional Access instead. |
| `-GrantMissing` | `-BlockMcp All -Via Permission` | switch | Also grant the servers in `-ExceptMcp` that the agent does not hold. |
| `-AiDays` | `-AiActivity` | 1 to 180, default 30 | How far back to search. |
| `-RiskyOnly` | `-AiActivity`, `-EndpointAi` | switch | Only events with a risk signal, or only tools rated High or Medium. |
| `-EndpointDays` | `-EndpointAi`, `-BlockLocalAgent` | 1 to 30, default 30 | Days of endpoint telemetry to read. |
| `-ForDevice` | `-EndpointAi`, `-BlockLocalAgent`, `-UnblockLocalAgent` | device names (wildcards allowed) | Show the full evidence for the tools on these devices, or the devices to block or unblock on. |
| `-Sanctioned` | `-EndpointAi` | tool or vendor names | Names you have approved (substring match). Others show as Unsanctioned. |
| `-MinDaysBlocked` | `-DeleteCandidates` | integer, default 30 | Minimum days blocked. |
| `-History` | `-DeleteCandidates` | paths | Extra logs or folders that record when agents were blocked. |
| `-IncludeUnknown` | `-DeleteCandidates` | switch | Also list agents whose block date is unknown. |
| `-Apply` | `-Policy` | switch | Run the plan. |
| `-CompareTo` | `-Snapshot` | path | List changes since an earlier snapshot. |
| `-Deep` | `-Inventory` | switch | Add usage and availability per agent (one call each). |
| `-WithPermissions` | `-Inventory` | switch | Add the Entra permissions of each identity. |

## Limitations

- **Agent users counts what the audit trail can attribute.** An interaction appears only when Defender ties it to a user and the event carries an id that maps to a catalog agent. Agents that emit no user-attributed events, and events with no agent id, are not counted. Retention is about 30 days.
- **Policy hits are evidence, not configuration.** `-AgentPolicyHits` shows what fired. A hit is tied to an agent only through the application id it names or an agent user account; a hit that names only a person stays unattributed, which can be most of them (117 of 121 in the tenant this was built against). Insider Risk alerts and Communication Compliance depend on the policies you have created, and Communication Compliance has no source at all.
- **MCP access shows what Entra and Defender can see.** Registry status, tool switches and calls older than about 30 days are not shown. A Copilot Studio agent's MCP servers come through Power Platform connectors and carry no Entra permission, so they show as set up and called, never as granted.
- **An agent identity's own tokens cannot be revoked.** `-RevokeSessions` ends the sessions of agent user accounts only, and only Exchange, SharePoint, Teams and Microsoft Graph refuse tokens already issued; elsewhere a token lasts until it expires, about an hour.
- **E7 is recognised by name or by its Agent 365 plan.** The Learn licensing reference lists no E7 SKU yet, so a user counts as E7-licensed when a SKU name contains E7, and as Agent 365-licensed when a SKU carries the `AGENT_365` plan.
- **Beta APIs.** Block, unblock, reassign, the Entra agent-identity calls, the Entra agent-risk calls, the Conditional Access policy calls and the Defender custom detection rules used to block a local AI agent target `/beta` and can change without notice. Listing, details and the availability scope use `v1.0`.
- **Reassigning Copilot Studio agents can fail at the service.** The package reassign call can answer HTTP 424 with "An error occurred while reassigning the agent" or "The agent could not be reassigned in Power Platform". It was observed for every Copilot Studio agent in one tenant, including agents with a valid owner and a reassignment to the current owner, and the Microsoft 365 admin center's Assign new owner failed the same way, so the cause is on the service side. For a support case use the `request-id` and `client-request-id` from the response. Setting the owner in Copilot Studio, or adding a sponsor or owner on the Entra identity, are the alternatives.
- **No delete and no clear.** The catalog API cannot delete an agent or clear an owner. The Agent 365 Tools registry (its list of MCP servers, its Block and its tool switches) has no public API either: `-McpAccess` reads permissions, set-up servers and calls instead, and `-BlockMcp` blocks per agent with Conditional Access or, with `-Via Permission`, removes the agent's permission.
- **Write calls are delegated-only.** Block, unblock, reassign, restrict and sponsor changes need a signed-in administrator and have no app-only option. A scheduled task can reuse a saved administrator sign-in (create it with `-SignIn`, as the account that runs the task) until it expires; the run then fails with a message to run `-SignIn` again.
- **Entra applies risk changes with a delay.** Confirming an agent as compromised, or dismissing its risk, shows up a minute or two after Entra accepts it. See [Respond to a compromised agent](#respond-to-a-compromised-agent).
- **Retention.** Advanced Hunting keeps about 30 days. The Purview audit log keeps what your licence allows (180 days or one year).
- **Audit searches are slow and permanent.** See [AI activity from Purview](#ai-activity-from-purview).

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| No packages returned | Confirm the tenant has an Agent 365 license and that you consented to `CopilotPackages.Read.All`. |
| "No package named 'X'" | Run `-List` for the exact display name or id. |
| "Multiple packages named 'X'" | Two packages share the name; pass the exact `P_` or `T_` id. |
| Advanced Hunting query failed | Check `ThreatHunting.Read.All` consent, an E5 or Defender license and Security for AI onboarding, or use `-By modified`. |
| "No saved sign-in ... cannot show a sign-in window" | This appears only in a session nobody can answer, such as a scheduled task. Run `.\Agent365-Bulk-Actions.ps1 -SignIn` in a terminal, as the same Windows account that runs the tool. |
| The sign-in window does not appear | When the tool can tell the window failed it switches to a device code by itself. If it just waits and nothing opens, look behind other windows, then press Ctrl+C and run again with `-DeviceCode`. |
| Every run asks for a new device code | A session made with a code is reused only by a code run. Sign in once with a window (`-SignIn` on a machine with a desktop) and later runs reuse it silently, scheduled ones included. Do not delete `a365.signin-method` from the `.mg` folder next to the saved session unless you also sign in again. |
| `-StaleDays` of 30 or more seems to under-report | Expected: telemetry covers about 30 days. Use `-By modified` or `-IncludeNeverSeen`. |
| Audit search is refused | Grant `AuditLogsQuery.Read.All` (admin consent) and hold a Purview audit role. |
| Confirm compromised says "accepted" but the state is not visible | Entra applies it a minute or two after accepting it. Check the Risky agents report in Microsoft Entra, or raise `-WaitSeconds`. The Security Administrator role and `IdentityRiskyAgent.ReadWrite.All` are required. |
| Conditional Access check says a Defender-risky agent is not blocked now | Expected. Conditional Access reads the agent risk Entra holds, which comes from Entra's own detections or from confirming the agent compromised; Defender alerts do not change it. |
| Conditional Access check is refused | Grant `Policy.Read.All` and `IdentityRiskyAgent.Read.All` (or `IdentityRiskyAgent.ReadWrite.All`). Reading policies needs a role such as Security Reader or Conditional Access Administrator. |
| Agent users shows nothing | The feed may be stale or the agents may not emit user-attributed events. Check the latest CloudAppEvents rows with ActionType InvokeAgent in Advanced Hunting, and widen the period. |
| Agent users says license details could not be read | The signed-in account needs an Entra role that can read license details (License Administrator, User Administrator, Global Reader). |
| Policy hits ties nothing to an agent | Many DLP events name the person who typed the prompt, not the agent. Run with `-IncludeUnattributed` to see them with the application id they carry. A per-agent policy ties its hits to the agent; a tenant-wide one cannot. |
| Policy hits shows no Insider Risk alert | No Insider Risk policy raised one in the period, or none exists. Insider Risk alerts come from the Graph alerts API (source `microsoftInsiderRiskManagement`); the Risky agents risk levels are visible only in the Purview portal. |
| Blocking an MCP server is refused | Grant `Policy.ReadWrite.ConditionalAccess` (run `-SignIn` again) and hold the Conditional Access Administrator role. Conditional Access for agents also needs Microsoft 365 E7, or Agent 365 with Microsoft Entra ID P1. |
| Removing or granting an MCP permission is refused | Grant `DelegatedPermissionGrant.ReadWrite.All` (run `-SignIn` again) and hold the Cloud Application Administrator, Application Administrator or Privileged Role Administrator role. |
| An agent still reaches an MCP server after a block | A token issued before the block stays valid for up to an hour. Check that the block is not report-only, that the agent does not reach the server through the shared permission (block *Agent Tools*), and that it is not acting on behalf of a signed-in person or running in Copilot Studio, which Conditional Access for agents does not cover. |
| Revoking sessions is refused | Grant `User.RevokeSessions.All` (run `-SignIn` again) and use an Entra role that can manage agent user accounts, such as Agent ID Administrator. |
| Adding a sponsor is refused | Add an owner instead (`-AsOwner`) or use the Entra admin center; the Agent ID Administrator role is required either way. |

## Appendix: hunting queries

Both built-in queries start with the same inventory block, which maps every identifier an agent appears under to its catalog id. A stale override must return `Key` (catalog id, lowercase) and `LastActivity`.

```kql
let inv = AgentsInfo
    | summarize arg_max(Timestamp, *) by AgentId
    | extend r = todynamic(RawAgentInfo)
    | project CatalogId = tolower(tostring(r.titleId)),
              Keys = pack_array(tolower(tostring(AgentId)), tolower(tostring(EntraAgentID)),
                                tolower(tostring(ObservabilityID)), tolower(tostring(SourceAgentId)),
                                tolower(tostring(r.botId)))
    | mv-expand Key = Keys to typeof(string)
    | where isnotempty(Key) and isnotempty(CatalogId)
    | distinct CatalogId, Key;
```

Activity (`-By activity`), always over the full 30 days:

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("InvokeAgent", "InferenceCall", "ExecuteToolBySDK", "ConnectedAIAppInteraction",
                       "CopilotInteraction", "AISpanOutput")
| extend d = todynamic(RawEventData)
| extend Keys = pack_array(tolower(tostring(coalesce(d.AgentId, d.agentId))),
                           tolower(tostring(d.TargetAgentId)), tolower(tostring(d.PlatformTargetAgentId)))
| mv-expand Key = Keys to typeof(string)
| where isnotempty(Key)
| summarize LastActivity = max(Timestamp) by Key
| join kind=leftouter inv on Key
| summarize LastActivity = max(LastActivity) by Key = coalesce(CatalogId, Key)
```

Risky (`-Risky`), after the same inventory block. `-RiskSource` selects which of the `alerts`, `rtp` and `shield` legs are included:

```kql
let win = 30d;
let alerts = AlertInfo
    | where Timestamp > ago(win)
    | where DetectionSource in ("Security for AI", "Microsoft Security for AI")
         or ServiceSource in ("Security for AI", "Microsoft Security for AI")
    | join kind=inner (
        AlertEvidence
        | where EntityType == "AIAgent"
        | extend af = todynamic(AdditionalFields)
        | project AlertId, AgentKey = tolower(tostring(coalesce(af.AgentId, af.agentId)))
        | where isnotempty(AgentKey)
        | distinct AlertId, AgentKey ) on AlertId
    | join kind=leftouter inv on $left.AgentKey == $right.Key
    | project Key = coalesce(CatalogId, AgentKey), Kind = "Alert", SignalId = AlertId, Timestamp,
              Rank = case(Severity == "High", 4, Severity == "Medium", 3, Severity == "Low", 2, Severity == "Informational", 1, 0),
              Reason = Title, Category;
let names = AgentsInfo
    | summarize arg_max(Timestamp, *) by AgentId
    | extend r = todynamic(RawAgentInfo)
    | summarize cnt = count(), CatalogId = take_any(tolower(tostring(r.titleId))) by NameKey = tolower(Name)
    | where cnt == 1 and isnotempty(CatalogId);
let rtp = BehaviorEntities
    | where Timestamp > ago(win)
    | where EntityType == "AIAgent" and ActionType in ("BehaviorAgentRTPAudit", "BehaviorAgentRTPBlock")
    | extend af = todynamic(AdditionalFields)
    | project BehaviorId, ActionType, Timestamp, AgentKey = tolower(tostring(af.AgentId))
    | where isnotempty(AgentKey)
    | join kind=leftouter inv on $left.AgentKey == $right.Key
    | join kind=leftouter (BehaviorInfo | project BehaviorId, Categories, BlockReason = tostring(todynamic(AdditionalFields).BlockReason)) on BehaviorId
    | project Key = coalesce(CatalogId, AgentKey), Kind = "Detection", SignalId = BehaviorId, Timestamp,
              Rank = iff(ActionType == "BehaviorAgentRTPBlock", 4, 3),
              Reason = iff(ActionType == "BehaviorAgentRTPBlock", strcat("Real-time protection blocked: ", coalesce(BlockReason, "interaction")), "Real-time protection detection (audit)"),
              Category = tostring(todynamic(Categories)[0]);
let shield = BehaviorInfo
    | where Timestamp > ago(win) and ActionType startswith "BehaviorPromptShield"
    | extend NameKey = tolower(tostring(todynamic(AdditionalFields).AgentName))
    | join kind=inner names on NameKey
    | project Key = CatalogId, Kind = "Detection", SignalId = BehaviorId, Timestamp,
              Rank = iff(ActionType endswith "Block", 4, 3),
              Reason = iff(ActionType endswith "Block", "Prompt Shield blocked a jailbreak attempt", "Prompt Shield detected a jailbreak attempt"),
              Category = "Jailbreak";
union alerts, rtp, shield
| summarize AlertCount = dcountif(SignalId, Kind == "Alert"), DetectionCount = dcountif(SignalId, Kind == "Detection"),
            SevRank = max(Rank), LastAlert = max(Timestamp),
            Reasons = make_set(Reason, 8), Categories = make_set(Category, 6) by Key
| extend Severity = case(SevRank == 4, "High", SevRank == 3, "Medium", SevRank == 2, "Low", SevRank == 1, "Informational", "-")
```

## Development

```powershell
# Tests (Pester 5 or later) and lint (PSScriptAnalyzer); CI runs the same on every pull request
Invoke-Pester -Path .\tests
Invoke-ScriptAnalyzer -Path .\Agent365-Bulk-Actions.ps1 -Settings .\PSScriptAnalyzerSettings.psd1
Invoke-ScriptAnalyzer -Path .\tools\Watch-GraphApi.ps1 -Settings .\PSScriptAnalyzerSettings.psd1
```

Dot-sourcing the script (`. .\Agent365-Bulk-Actions.ps1`) loads its functions without signing in or running anything, which is how the tests exercise them with mocked Graph calls.

### Graph API watch

Part of the tool runs on Graph beta, and Microsoft adds, promotes and retires Graph APIs regularly. `tools/Watch-GraphApi.ps1` checks the kit against the published API without signing in:

| Check | What it reports |
| --- | --- |
| Endpoints | Each endpoint in `tools/graph-endpoints.json`, resolved against the live `$metadata` of its version: not found, or marked deprecated with the removal date |
| Beta endpoints in v1.0 | Beta endpoints the kit calls that also exist in v1.0, with the beta properties v1.0 still lacks, nested ones included (such as `conditions.agents` on Conditional Access policies). Changes since the baseline are flagged |
| Endpoint list | Graph calls in the script that `graph-endpoints.json` does not list. The tests fail on these too |
| Agent, Copilot and MCP surface | Types, properties, relationships, actions, functions and enum members added or removed since `tools/graph-api-baseline.json` |
| Changelog | Entries from the [Graph changelog](https://developer.microsoft.com/graph/changelog) about agents, Copilot, MCP and the APIs the kit calls |

```powershell
# Report, reading the last 30 days of the changelog
./tools/Watch-GraphApi.ps1 -OutFile graph-api-watch.md

# After acting on a report, record the current state as the new baseline and commit it
./tools/Watch-GraphApi.ps1 -UpdateBaseline
```

The [Graph API watch workflow](.github/workflows/graph-api-watch.yml) runs it every Monday and, when there is something to review, keeps one open issue named **Microsoft Graph API watch** up to date. It can also be started from the Actions tab. GitHub pauses scheduled workflows in a public repository after 60 days without activity.

When adding a Graph call to the script, add its endpoint to `tools/graph-endpoints.json`.

## Disclaimer

Provided as-is, without warranty of any kind. Part of it targets `/beta` Microsoft Graph APIs that can change without notice. Not an official Microsoft product. Test in a non-production tenant first. See [LICENSE](LICENSE).

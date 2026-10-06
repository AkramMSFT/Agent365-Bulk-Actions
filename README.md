# Agent365-Bulk-Actions

A single PowerShell tool for Microsoft Agent 365 and Microsoft 365 Copilot administrators. It lists, inspects, contains and governs the agents in the organization catalog in bulk, from the command line or from a desktop console.

> [!IMPORTANT]
> Block, unblock and reassign, and the Entra agent-identity and agent-risk calls, use Microsoft Graph **`/beta`** endpoints, which Microsoft does not recommend for production automation. Try it in a lab tenant first. Every write previews first, asks for confirmation and writes a log that can be undone.

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Permissions](#permissions)
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
  - [Policy file](#policy-file)
  - [Snapshots and change reports](#snapshots-and-change-reports)
  - [Graphical console](#graphical-console)
- [Parameter reference](#parameter-reference)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Appendix: hunting queries](#appendix-hunting-queries)
- [Development](#development)
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
| Endpoint AI | Discover local AI agents and shadow AI on Defender-onboarded devices, with their telemetry and risk, and block one on a device | `-EndpointAi`, `-BlockLocalAgent`, `-UnblockLocalAgent` |
| Containment | Verify the Entra identity is disabled with a block, preview who would lose an agent, list long-blocked agents | `-DisableIdentity`, `-Impact`, `-DeleteCandidates` |
| Compromise response | Confirm an agent's Entra identity as compromised in Entra ID Protection, or dismiss the risk | `-ConfirmCompromised`, `-DismissRisk` |
| Conditional Access | Check whether a Conditional Access policy blocks each risky agent, or every agent, at High agent risk, and which policies apply | `-CheckConditionalAccess` |
| Policy | Declare rules once, review the plan, apply it | `-Policy`, `-Apply` |
| Snapshots | Save the inventory and report what changed since an earlier one | `-Snapshot`, `-CompareTo` |
| Console | A desktop window with filters, a details window and buttons for all of the above | `-Gui` |

## Requirements

- An **Agent 365 license** on the tenant (the catalog API returns packages only with it).
- **PowerShell 7 or later** is recommended. The `Microsoft.Graph.Authentication` module installs itself on first run.
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

**Signing in.** `-SignIn` starts the sign-in from the terminal and keeps the session for your Windows account. Microsoft Entra offers no way to type an administrator's password into a terminal (accounts with multi-factor authentication cannot use it, and this tool never handles a password), so the sign-in itself is completed in the Microsoft sign-in window that opens. After that, every mode, scheduled runs included, reuses the saved session silently until it expires or is revoked. A run that cannot show a window and has no saved session stops with a message that tells you to run `-SignIn`. `-DeviceCode` prints a code instead of opening a window, but the code must be entered within two minutes.

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
| `Policy.Read.All` | Reading Conditional Access policies (`-CheckConditionalAccess`). The console asks for it only when you use that action. |
| `IdentityRiskyAgent.Read.All` | Reading an agent identity's Entra risk without changing it (`-CheckConditionalAccess`). `IdentityRiskyAgent.ReadWrite.All` also satisfies it. |
| `Group.Read.All` | Naming a group in `-AllowGroups`, a policy rule, or the console's group picker |
| `Application.Read.All`, `DelegatedPermissionGrant.Read.All` | Reading the permissions an agent identity holds (`-Detail`, `-Inventory -WithPermissions`). The console shows the same data when these permissions have been consented for your account. |
| `AuditLogsQuery.Read.All` | AI activity (`-AiActivity`, the console's AI activity tab, `aiActivity` policy rules). Needs admin consent and a Purview audit role such as Audit Reader. |

## Safety model

- **Preview first.** `-WhatIf` shows what would happen. `-Action list` shows the matched set without acting.
- **One confirmation per batch.** Each write mode lists its targets and asks once. `-Force` skips the question. A selection made in a picker counts as confirmation.
- **A log you can undo.** `-OutFile run.csv` (or `.json`) records every agent with the state it had before the change. `-Undo run.csv` restores block state, owners and access scope, removes sponsors or owners the run added, and dismisses a compromised flag the run set.
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
```

Blocking is fully reversible with `-Unblock`.

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

In the console, **Endpoint AI...** (top row) opens the same view: a grid of tools, with the evidence for the selected one underneath.

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

In the console, select a tool in the Endpoint AI window and press **Block on this device...** (or **Remove block**). A **Blocked** column shows what is blocked.

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

- **`-DisableIdentity`** checks the agent's Entra identity after the block. Blocking a package that has an Agent ID normally makes the platform disable the identity within about ten seconds, and unblocking re-enables it. The tool waits up to 30 seconds, records `Disabled (by platform)` or `Enabled (by platform)` in the log, and calls the identity API itself only if the platform left it in the wrong state (`Disabled (by tool)`, or `Failed` with the error). Only agents that have an identity are checked. The forced path needs `AgentIdentity.EnableDisable.All` and the Agent ID Administrator role.
- **`-Impact`** reads each target's detail record (`activeUsers`, `totalSessions`, `lastUsedDateTime`). These figures are not in the list call, so the tool fetches them only for the agents you are about to act on.
- **`-DeleteCandidates`** deletes nothing: the catalog API has no delete, and a block lasts until someone reverses it. It lists blocked agents that have stayed blocked at least `-MinDaysBlocked` days. The block date comes from this tool's own logs (`-OutFile` files and the console's logs under `%LOCALAPPDATA%\Agent365-Bulk-Actions\logs`; add others with `-History`) and from the `BlockedAgent` audit events Defender keeps for about 30 days. Agents whose block date is unknown are skipped unless you add `-IncludeUnknown`. Delete them in the admin center (Agents > All agents > Delete, then Deleted > Permanently delete), or through the Power Platform API for Copilot Studio agents.

### Respond to a compromised agent

```powershell
.\Agent365-Bulk-Actions.ps1 -ConfirmCompromised "Contoso HR Agent" -WhatIf       # show each agent's current Entra risk, change nothing
.\Agent365-Bulk-Actions.ps1 -ConfirmCompromised "Contoso HR Agent" -OutFile .\compromised.csv
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
- **What is not evaluated.** Policies for the on-behalf-of flow (they target users), policies for agent user accounts, and attribute rules. Resources that accept an API key instead of a token are outside Conditional Access.
- **Requirements.** `Policy.Read.All`, `IdentityRiskyAgent.Read.All` (or the ReadWrite permission) and `Application.Read.All`. The policy call is beta only. `-OutFile` writes agent, identity, Entra risk, verdict, detail and the policies that apply.
- **In the console**, tick agents and open **Entra risk > Check Conditional Access...** for the same result in a window, with the policies behind the selected agent below. With nothing ticked it checks every agent that has an Entra identity.

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

A Windows desktop window over the same catalog. It opens on every agent with no filter applied. The action bar has two rows: selection, **Details...**, **AI activity...**, **Export** and **Undo last run** on top; **Apply suggested**, **Restrict access...**, **Assign owner...**, **Verify identity state**, **Unblock selected** and **Block selected** below.

| To do this | Use |
| --- | --- |
| Find agents | Search by name, publisher, platform or id. Filter All, Active or Blocked, and optionally Copilot agents only. **Reset filters** clears everything. |
| Filter by analysis | *Stale*, *Risk* (from alerts, detections or both), *Ownership*, *Blocked*, *Tools*, *Permissions* and *Access* dropdowns. Each defaults to **None**. The matching columns fill in. *Match All* needs every active Stale and Risk filter; *Any* accepts either. |
| Block or unblock | Tick rows (or **Select visible**), then **Block selected** or **Unblock selected**. A confirmation lists the agents with their active users and last use. **Verify identity state** adds a check that the Entra identity ends up disabled (or enabled again after an unblock). |
| Fix ownership | *Ownership > Needs an owner* lists shared agents with no usable owner and a suggestion; tick the rows and press **Apply suggested** (always on the action bar, enabled once a ticked row has a suggestion). **Assign owner...** opens a searchable Entra directory picker. |
| Add accountability | *Ownership > Missing an Entra sponsor* (or *sponsor or owner*) lists identities with a gap; **Apply suggested** adds the proposed person after a confirmation. |
| Restrict access | Tick rows and press **Restrict access...** to choose nobody, the owner only, named users and groups (searchable picker, Users or Groups) or everyone. Tick **Also apply this choice to deployment** to make who the agent is installed for follow the same choice (nobody, the same users and groups, or everyone); there is no separate deployment list. The *Access* filter lists agents open to everyone, restricted or closed. |
| Inspect an agent | **Details...** (or double-click a row): Overview, Sharing, Tools and MCP, Data, Permissions, Identity, Usage, Risk and AI activity tabs, with **Export JSON**. The **Tools and sharing columns** checkbox adds tool count, MCP servers, shared-with count and channels. |
| Find local AI agents | **Endpoint AI...** opens a window of the AI tools found on Defender-onboarded devices, with their risk and, for the selected one, the evidence behind it. It loads when it opens and has a refresh button, a period selector, a risky-only filter and export. **Block on this device...** and **Remove block** act on the selected tool. |
| Review AI activity | **AI activity...** opens the details window on that tab. |
| Entra risk | Tick agents and open **Entra risk**: **Confirm as compromised...** sets the risk level of their Entra identities to High, and **Clear the compromised flag...** dismisses the risk again. The console does not wait for Entra to show the new state, which takes a few minutes. **Check Conditional Access...** shows whether a policy blocks each ticked agent (every agent with an Entra identity when none is ticked) at High agent risk, with the policies behind the selected one. |
| Undo | **Undo last run** reverses the previous block, unblock, access change, sponsor addition or compromised flag (it dismisses the risk). |
| Export | **Export** saves the grid as CSV or JSON. |

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
| `-Undo` | path | Reverse a run from its `-OutFile` log (block state, owners, access scope, added sponsors and owners, compromised flags). |
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
| `-DeviceCode` | all | switch | Print a device code instead of opening a sign-in window. The code expires after two minutes; `-SignIn` is the more reliable route. |
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
| `-ForAgent` | `-AiActivity`, `-CheckConditionalAccess` | names and/or ids | List the individual events of these agents, or check these agents instead of the risky ones. |
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

- **Beta APIs.** Block, unblock, reassign, the Entra agent-identity calls, the Entra agent-risk calls, the Conditional Access policy read and the Defender custom detection rules used to block a local AI agent target `/beta` and can change without notice. Listing, details and the availability scope use `v1.0`.
- **Reassigning Copilot Studio agents can fail at the service.** The package reassign call can answer HTTP 424 with "An error occurred while reassigning the agent" or "The agent could not be reassigned in Power Platform". It was observed for every Copilot Studio agent in one tenant, including agents with a valid owner and a reassignment to the current owner, and the Microsoft 365 admin center's Assign new owner failed the same way, so the cause is on the service side. For a support case use the `request-id` and `client-request-id` from the response. Setting the owner in Copilot Studio, or adding a sponsor or owner on the Entra identity, are the alternatives.
- **No delete and no clear.** The catalog API cannot delete an agent or clear an owner. There is no supported API to list, block or delete MCP servers either (most are readable by id only).
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
| "No saved sign-in ... cannot show a sign-in window" | Run `.\Agent365-Bulk-Actions.ps1 -SignIn` in a terminal, as the same Windows account that runs the tool. |
| The sign-in window does not appear | Look behind other windows. If it still does not open, `-DeviceCode` prints a code instead; enter it within two minutes. |
| `-StaleDays` of 30 or more seems to under-report | Expected: telemetry covers about 30 days. Use `-By modified` or `-IncludeNeverSeen`. |
| Audit search is refused | Grant `AuditLogsQuery.Read.All` (admin consent) and hold a Purview audit role. |
| Confirm compromised says "accepted" but the state is not visible | Entra applies it a minute or two after accepting it. Check the Risky agents report in Microsoft Entra, or raise `-WaitSeconds`. The Security Administrator role and `IdentityRiskyAgent.ReadWrite.All` are required. |
| Conditional Access check says a Defender-risky agent is not blocked now | Expected. Conditional Access reads the agent risk Entra holds, which comes from Entra's own detections or from confirming the agent compromised; Defender alerts do not change it. |
| Conditional Access check is refused | Grant `Policy.Read.All` and `IdentityRiskyAgent.Read.All` (or `IdentityRiskyAgent.ReadWrite.All`). Reading policies needs a role such as Security Reader or Conditional Access Administrator. |
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
```

Dot-sourcing the script (`. .\Agent365-Bulk-Actions.ps1`) loads its functions without signing in or running anything, which is how the tests exercise them with mocked Graph calls.

## Disclaimer

Provided as-is, without warranty of any kind. Part of it targets `/beta` Microsoft Graph APIs that can change without notice. Not an official Microsoft product. Test in a non-production tenant first. See [LICENSE](LICENSE).

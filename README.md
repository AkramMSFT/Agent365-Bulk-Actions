# Agent365-Bulk-Actions

A single PowerShell tool for **Agent 365 / Microsoft 365 Copilot** administrators to **list, block, unblock, and bulk‑retire stale agents** in the organization catalog, through the Microsoft Graph **Copilot Package Management API**.

Beyond one‑off actions, it can bulk‑block **stale** agents — those that have stopped sending usage telemetry, or whose package manifest hasn't been updated in a set number of days.

> [!IMPORTANT]
> This tool targets the Microsoft Graph **`/beta`** endpoint, which Microsoft does not recommend for production automation. Validate in a lab tenant before using it against production.

---

## What you can do with it

- **List** every agent and see which are already blocked.
- **Block / unblock** one or many agents by display name and/or `P_` id in a single command.
- **Pick** agents interactively from a grid or numbered menu — no need to type names.
- Find and **block stale agents** by inactivity (Defender telemetry) or by manifest age.
- **Preview everything first** with a dry run (`-WhatIf` or `-Action list`) before changing anything.
- Find **risky** agents from alerts and from Defender detections that never raised an alert.
- Fix **ownership** gaps: propose an owner for orphaned shared agents, or assign one by hand.
- **Contain** agents by also disabling their Entra identity, and see each agent's blast radius first.
- Track **delete candidates** (agents that stayed blocked) for clean-up in the admin center.
- Run a repeatable **policy file**, keep **snapshots**, and **undo** a run from its log.
- Use the **graphical console** (`-Gui`) for all of the above.

> Blocking is fully reversible — the same tool re‑enables an agent with `-Unblock`.

## How it works

The script wraps three Graph beta endpoints:

```
GET  /beta/copilot/admin/catalog/packages              (list)
POST /beta/copilot/admin/catalog/packages/{id}/block   (block)
POST /beta/copilot/admin/catalog/packages/{id}/unblock (unblock)
```

`block` / `unblock` are **delegated‑only** (there is no app‑only permission), so the script signs an administrator in interactively and requests `CopilotPackages.ReadWrite.All`. Read‑only actions use `CopilotPackages.Read.All`. Activity‑based staleness additionally queries **Defender Advanced Hunting** (`/security/runHuntingQuery`), which needs `ThreatHunting.Read.All`.

On each run the script: ensures the `Microsoft.Graph.Authentication` module is installed → signs you in requesting only the scopes the chosen action needs → retrieves the catalog → resolves your targets → applies the action and prints an `OK`/`FAIL` summary.

## Prerequisites

- **Agent 365 license** on the tenant (required for the catalog API to return packages).
- For activity‑based staleness: a **Microsoft Defender / Microsoft 365 E5** license with **Security for AI** onboarded.
- **PowerShell 7+** recommended. The `Microsoft.Graph.Authentication` module installs automatically on first run.
- An account able to consent to the scopes below (e.g. **AI Administrator**).

### Permissions (delegated scopes)

| Scope | When it is requested |
| --- | --- |
| `CopilotPackages.Read.All` | Read‑only actions (`-List`, or any mode with `-Action list`) |
| `CopilotPackages.ReadWrite.All` | Blocking or unblocking agents |
| `ThreatHunting.Read.All` | Activity‑based staleness (`-Stale -By activity`) |

## Getting started

```powershell
# 1. Save Agent365-Bulk-Actions.ps1 to a folder and cd into it
cd C:\Path\To\Scripts

# 2. Run any command below. On first run it installs the Graph auth module
#    (if needed) and opens a sign-in prompt. Sign in and consent to the scopes.
.\Agent365-Bulk-Actions.ps1 -List -AgentsOnly
```

Pass `-TenantId <guid-or-domain>` to target a specific tenant (otherwise your account's home tenant is used). On a machine where interactive/WAM sign‑in misbehaves, add `-DeviceCode`.

## What "stale" means

Two ways to measure staleness, chosen with `-By`:

| `-By` | Needs Defender? | What "stale" means |
| --- | --- | --- |
| `activity` *(default)* | Yes | Reported telemetry before, but idle beyond the cutoff (max provable window ~30 days). |
| `modified` | No | Package manifest (`lastModifiedDateTime`) not updated within the cutoff. |

By default, activity mode only treats agents that **have** reported telemetry but gone idle as stale — built‑ins/add‑ins that never emit telemetry are skipped. Add `-IncludeNeverSeen` to also flag agents with zero telemetry.

> [!IMPORTANT]
> Advanced Hunting keeps only about **30 days** of data, so `-By activity` can only detect agents that reported within the last 30 days and then went quiet. Use `-StaleDays` below 30 for that. With `-StaleDays` of 30 or more, the script stops with an explanation unless you add `-IncludeNeverSeen`, in which case "stale" means "no activity in the last 30 days". Use `-By modified` for longer horizons.

Telemetry is matched to catalog packages through `AgentsInfo`: a package `id` equals the agent's `titleId`, and the registry id, Entra agent id, observability id, source id and bot id seen in events all resolve to that `titleId`. Display names are never used for matching.

## Scenarios

```powershell
# List all Copilot agents and their blocked state
.\Agent365-Bulk-Actions.ps1 -List -AgentsOnly

# Block specific agents by name and/or package id (P_ or T_), comma-separated
.\Agent365-Bulk-Actions.ps1 -Block "Contoso HR Agent","Northwind Sales Agent","P_19ae1zz1-..."
.\Agent365-Bulk-Actions.ps1 -Block "Contoso HR Agent" -WhatIf                   # preview, changes nothing
.\Agent365-Bulk-Actions.ps1 -Block "Contoso HR Agent" -Force -OutFile .\blocked.csv   # no prompt, keep a log

# Pick agents from a list (grid or numbered menu). Default action = block.
.\Agent365-Bulk-Actions.ps1 -Select -AgentsOnly
.\Agent365-Bulk-Actions.ps1 -Select -Action unblock -AgentsOnly

# Preview stale agents (safe dry run — changes nothing)
.\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 30 -Action list

# Block stale agents by inactivity (preview + confirm; -Force skips the prompt)
.\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 30 -AgentsOnly
.\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 30 -Force

# Compute the stale set, then hand-pick which to block
.\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 30 -Pick -AgentsOnly

# Also treat agents that never reported telemetry as stale (sweeps the whole catalog)
.\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 30 -IncludeNeverSeen -Action list

# Stale by manifest age instead of telemetry (no Defender needed)
.\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 30 -By modified -AgentsOnly

# List RISKY agents (those with Defender AI-security alerts), then block them
.\Agent365-Bulk-Actions.ps1 -Risky -Action list                 # dry run: severity, alert count, and WHY
.\Agent365-Bulk-Actions.ps1 -Risky -MinSeverity High -Action list   # only High-severity agents
.\Agent365-Bulk-Actions.ps1 -Risky -RiskDays 30 -MinAlerts 2 -MinSeverity Medium -AgentsOnly
.\Agent365-Bulk-Actions.ps1 -Risky -Pick                        # pick which risky agents to block

# Undo
.\Agent365-Bulk-Actions.ps1 -Unblock "Contoso HR Agent","Northwind Sales Agent"

# Block every agent listed in a CSV (Id or DisplayName column), keeping a log
.\Agent365-Bulk-Actions.ps1 -FromCsv .\agents.csv -OutFile .\run.csv

# Reverse that whole run later, using its log
.\Agent365-Bulk-Actions.ps1 -Undo .\run.csv
```

### Graphical console

```powershell
pwsh -STA -File .\Agent365-Bulk-Actions.ps1 -Gui
```

Opens a Windows desktop window over the same catalog. It needs Windows and PowerShell 7 (or Windows PowerShell 5.1) in single-threaded mode, which `pwsh` uses by default.

- **Browse**: the window opens on every agent in the catalog with no filter applied. Search by name, publisher, platform or id; filter All / Active / Blocked; optionally limit to Copilot agents.
- **Filter**: the *Stale* and *Risk* dropdowns default to **None**. Pick a value to narrow the grid (no activity for 7 to 29 days, not modified for 30 to 365 days, or risk severity from Informational up to High, taken from alerts, detections or both); the matching columns fill in. The *Match* toggle controls how Stale and Risk combine: **All** (the default) needs both, **Any** accepts either. Search, status and Copilot-only always narrow on top. **Reset filters** returns everything to the unfiltered view.
- **Act**: tick rows (or *Select visible*), then **Block selected** or **Unblock selected**. A "Confirm the action" dialog lists the agents and offers Cancel (the default) or the matching Block or Unblock button. Each action writes a result log under `%LOCALAPPDATA%\Agent365-Bulk-Actions\logs`.
- **Ownership and blocked-for filters**: *Ownership > Needs an owner* lists shared agents with no usable owner, with a suggested replacement. Select rows and use **Apply suggested** or **Assign owner...**. *Blocked* shows how long agents have stayed blocked (delete candidates). The grid shows only the columns relevant to the filters you turned on.
- **Also disable identity** next to Block and Unblock adds the Entra identity step. The confirmation dialog shows each agent's active users and last use.
- **Undo last run** reverses the previous block or unblock in the window. **Export** saves what the grid shows as CSV or JSON.

### Ownership: ownerless and orphaned agents

```powershell
# Preview shared agents whose owner is missing or gone, with a proposed replacement (changes nothing)
.\Agent365-Bulk-Actions.ps1 -Ownerless

# Apply the proposals (asks first; -WhatIf previews, -OutFile keeps a log)
.\Agent365-Bulk-Actions.ps1 -Ownerless -Action reassign -OutFile .\owners.csv

# Manual assignment for agents the tool flagged for review
.\Agent365-Bulk-Actions.ps1 -Reassign "HR Policy Assistant","Hesham-TEST" -To alex@contoso.com
```

For each shared agent the tool decides, in this order:

1. **Keep** the current owner when the account exists and is enabled.
2. **Agent identity owner**: the person registered as owner of the agent's Entra identity, the closest available record of who created it.
3. **Manager** of that person, or of the former owner while the account still exists.
4. **Flag for review.** Nothing is guessed or defaulted; assign these yourself with `-Reassign ... -To ...`.

Notes:

- The package API exposes no creator field, so step 2 is the creator substitute. It only applies to agents that have an Entra identity.
- Only **shared** agents are considered. Microsoft documents reassignment for shared Agent Builder and Copilot Studio agents; org-published (line-of-business) agents without an owner are counted but not acted on.
- Reassign is **delegated-only** (the API has no application permission), so it cannot run unattended.
- The mode needs `User.Read.All` and `AgentIdentity.Read.All` in addition to `CopilotPackages.ReadWrite.All`.

### Containment, impact and clean-up

```powershell
# Block and also disable the agent's Entra identity (unblock re-enables it). Only agents that have an identity are affected.
.\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 14 -DisableIdentity -OutFile .\run.csv

# See who would lose each agent before acting: active users, sessions and last use
.\Agent365-Bulk-Actions.ps1 -Risky -MinSeverity High -Impact -Action list

# Blocked agents that have stayed blocked 30+ days (candidates for deletion)
.\Agent365-Bulk-Actions.ps1 -DeleteCandidates -MinDaysBlocked 30 -OutFile .\delete-candidates.csv
```

- **`-DisableIdentity`** blocks the package and also disables the agent's Entra identity, so the agent cannot sign in at runtime as well as disappearing from the catalog. Unblock re-enables it. It needs `AgentIdentity.EnableDisable.All` and the Agent ID Administrator role. The result log records the identity outcome per agent.
- **`-Impact`** reads each target's detail record (`activeUsers`, `totalSessions`, `lastUsedDateTime`). These figures are not in the list call, so the tool fetches them only for the agents you are about to act on.
- **`-DeleteCandidates`** does not delete anything. The catalog API has no delete, and nothing deletes blocked agents automatically; a block lasts until someone reverses it. The report lists blocked agents that have been blocked at least `-MinDaysBlocked` days. The block date comes from this tool's own logs (`-OutFile` files, plus the GUI's logs under `%LOCALAPPDATA%\Agent365-Bulk-Actions\logs`; add other log files or folders with `-History`) and from the `BlockedAgent` audit events, which Defender keeps for about 30 days. Agents whose block date cannot be determined are skipped unless you add `-IncludeUnknown`. Delete the listed agents in the admin center (**Agents > All agents > Delete**, then **Deleted > Permanently delete**), or for Copilot Studio agents through the Power Platform API.

### Policy file

Declare your governance rules once, review the plan, then apply it. See [policy.example.json](policy.example.json).

```powershell
# Show what the policy would do (changes nothing)
.\Agent365-Bulk-Actions.ps1 -Policy .\policy.example.json

# Run it (one confirmation for the whole plan; -WhatIf previews, -OutFile keeps a log)
.\Agent365-Bulk-Actions.ps1 -Policy .\policy.example.json -Apply -OutFile .\policy-run.csv
```

```json
{
  "name": "Agent governance baseline",
  "exclude": { "publishers": ["Microsoft Corporation"], "types": ["firstParty"], "names": [], "ids": [] },
  "rules": [
    { "name": "Contain high-risk agents",
      "when": { "risky": { "minSeverity": "High", "source": "Both" } },
      "then": { "action": "block", "disableIdentity": true } }
  ]
}
```

| Part | Values |
| --- | --- |
| `when` conditions | `stale` (`by`: activity or modified, `days`, optional `includeNeverSeen`), `risky` (`minSeverity`, `minSignals`, `source`), `blockedDays`, `ownerless` (true), `state` (blocked or active) |
| `match` | `all` (default, every condition must hold) or `any` |
| `then.action` | `block`, `unblock`, `reassign` (applies the proposed owners), or `report` (list only, the default) |
| `then.disableIdentity` | With `block`: also disable the agent's Entra identity |
| `exclude` | Agents to leave alone, by `ids`, `names`, `publishers` or `types` |

A rule must have at least one condition, so a typo can never match the whole catalog. Rules that would change nothing (an agent already blocked) are shown but not counted. Reassignment, like the other write modes, needs a signed-in administrator and cannot run unattended.

### Snapshots and change reports

```powershell
# Save today's inventory
.\Agent365-Bulk-Actions.ps1 -Snapshot .\inventory-2026-10-01.json

# Later: save a new one and list what changed since the old one
.\Agent365-Bulk-Actions.ps1 -Snapshot .\inventory-2026-10-08.json -CompareTo .\inventory-2026-10-01.json -OutFile .\changes.csv
```

The report lists agents that are new or removed, newly blocked or unblocked, and those whose owner or version changed.

### Risky agents

`-Risky` finds agents with Defender **Security for AI** signals and enriches each with **`severity`**, **`alerts`**, **`detections`**, **`why`** (alert titles and detection types), **`categories`** and the date of the last signal. Results are sorted worst-severity-first. Use `-MinSeverity` and `-MinAlerts` to narrow them, then block with the same preview and confirm/pick flow.

Two kinds of signal are read from Advanced Hunting, because Defender can detect something without raising an alert:

| Signal | Source | How it is tied to an agent | Severity |
| --- | --- | --- | --- |
| Alert | `AlertInfo` with `AlertEvidence` (entity `AIAgent`) | The agent id in the evidence | The alert's own severity |
| Real-time protection detection | `BehaviorEntities` (entity `AIAgent`) for `BehaviorAgentRTPAudit` and `BehaviorAgentRTPBlock`, with the block reason from `BehaviorInfo` | The Entra agent id in the entity | Block: High. Audit: Medium |
| Prompt Shield detection | `BehaviorInfo` for `BehaviorPromptShieldJailbreakBlock` and `BehaviorPromptShieldJailbreakDetect` | The agent name only, matched when the name is unique in `AgentsInfo` | Block: High. Detect: Medium |

Behaviors carry no severity of their own, so the table above is the mapping the script applies (a block means an attack was stopped; an audit or detect means it was seen but not stopped). Choose the signals with `-RiskSource Both|Alerts|Detections`; in the console use the *from* dropdown next to *Risk*.

> [!NOTE]
> Not every signal can be attributed to a catalog agent. "Defender for AI Services" alerts name an Azure AI account rather than an agent, `BehaviorAIAgentsRealTimeBlock` records carry no agent identity, and a Prompt Shield record whose agent name is missing or duplicated in `AgentsInfo` is skipped. **Always run `-Risky -Action list` first**, and if the default query doesn't match your tenant's schema, override it with `-HuntingQuery` (return `Key, AlertCount, DetectionCount, Severity, LastAlert`, with `Key` set to the package id). Advanced Hunting retains ~30 days, so `-RiskDays` is effectively capped there.

## Parameter reference

Only one primary mode (`List`, `Block`, `Unblock`, `Select`, `Stale`, or `Risky`) is used per run.

| Parameter | Values / default | What it does |
| --- | --- | --- |
| `-List` | switch | List catalog packages. |
| `-Block` | names and/or ids | Block one or more packages by display name and/or `P_` id. |
| `-Unblock` | names and/or ids | Unblock (undo) one or more packages. |
| `-Select` | switch | Interactive multi‑select picker over the catalog. |
| `-Gui` | switch | Open the graphical console. |
| `-FromCsv` | path | Apply `-Action` (block, unblock or list) to every agent named in a CSV with an `Id` or `DisplayName` column. |
| `-Undo` | path | Reverse a previous run using its `-OutFile` log: every agent changed in that run returns to its earlier state. |
| `-Ownerless` | switch | Find shared agents whose owner is missing or gone and propose a replacement. Default is a preview; add `-Action reassign` to apply. |
| `-Reassign` | names and/or ids | Manually assign the listed agents to the user given by `-To`. |
| `-To` | UPN or object id | The new owner for `-Reassign`. |
| `-DisableIdentity` | switch | Block also disables the agent's Entra identity; unblock re-enables it. |
| `-Impact` | switch | Show active users, sessions and last use for each target before acting. |
| `-DeleteCandidates` | switch | List agents that have stayed blocked at least `-MinDaysBlocked` days (default 30). Reports only; nothing is deleted. |
| `-History` | paths | Extra result logs or folders that record when agents were blocked. |
| `-IncludeUnknown` | switch | With `-DeleteCandidates`, also list blocked agents whose block date is unknown. |
| `-Policy` | path | Evaluate a JSON policy file and print the plan. Nothing changes without `-Apply`. |
| `-Apply` | switch | With `-Policy`, run the plan. |
| `-Snapshot` | path | Save the inventory to a JSON file. |
| `-CompareTo` | path | With `-Snapshot`, list changes since an earlier snapshot. |
| `-Stale` | switch | Act on agents stale beyond `-StaleDays`. |
| `-StaleDays` | 1–3650 (30/60/90) | Age threshold in days. Required with `-Stale`. |
| `-By` | `activity` / `modified` | `activity` = no usage telemetry (Defender); `modified` = manifest age. |
| `-Risky` | switch | Act on agents with Defender AI‑security alerts (Advanced Hunting). |
| `-RiskDays` | 1–3650 (default 30) | Alert lookback window (Advanced Hunting retains ~30 days). |
| `-RiskSource` | Both (default) / Alerts / Detections | Which signals make an agent risky: Security for AI alerts, BehaviorInfo detections that raised no alert, or both. |
| `-MinAlerts` | int (default 1) | Minimum number of signals (alerts plus detections) for an agent to count as risky. |
| `-MinSeverity` | Informational/Low/Medium/High | Only act on agents at/above this alert severity. |
| `-HuntingQuery` | KQL (optional) | Custom KQL. Stale: returns `Key,LastActivity`. Risky: returns `Key,AlertCount,Severity,LastAlert`. |
| `-IncludeNeverSeen` | switch | Activity mode: also treat agents with zero telemetry as stale. |
| `-Action` | `block` / `unblock` / `list` | What to do with the matched set. `list` = preview only (dry run). |
| `-AgentsOnly` | switch | Limit to Copilot agents (`supportedHosts` contains `Copilot`). |
| `-Force` | switch | Skip the "proceed?" confirmation for any write mode. |
| `-WhatIf` | switch | Show what would be blocked or unblocked without changing anything. |
| `-OutFile` | path (.csv or .json) | Write a per-agent result log: timestamp, operator, action, id, name, state before the run, result, error. |
| `-Pick` | switch | Choose which stale or risky matches to act on via the picker (the selection counts as confirmation). |
| `-TenantId` | GUID/domain (optional) | Target a specific tenant (default = your home tenant). |
| `-DeviceCode` | switch | Use device‑code sign‑in when interactive/WAM auth misbehaves. |

## Safety & good practice

- **Dry run first.** Add `-Action list` or `-WhatIf` to preview before any bulk change.
- **Every write asks once.** `-Block`, `-Unblock`, `-Stale` and `-Risky` show the target set and ask before acting; `-Force` skips the prompt. Agents already in the target state are skipped.
- **Keep a record.** `-OutFile ./run.csv` logs each agent with the state it had before the run, which is what you need to reverse a batch.
- **Throttling is handled.** Graph 429 and transient 5xx responses are retried with the `Retry-After` delay.
- **Everything is reversible.** `-Unblock` restores anything you block.
- **Start narrow.** Use `-AgentsOnly` and a specific `-StaleDays`; widen only once the preview looks right.
- **Mind the retention window.** With `-By activity` you can only prove ~30 days of inactivity.
- **Keep a human in the loop.** Prefer `-Pick`, or omit `-Force`, when you want to confirm before blocking.
- **Beta endpoint.** `/beta` is not recommended for production automation — validate in a lab first.

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| No packages returned | Confirm the tenant has an Agent 365 license and that you consented to `CopilotPackages.Read.All`. |
| "No package named 'X'" | Run `-List` to confirm the exact display name or `P_` id. |
| "Multiple packages named 'X'" | Two packages share that name — pass the exact `P_` id instead. |
| Advanced Hunting query failed | Check `ThreatHunting.Read.All` consent, an E5/Defender license, and that Security for AI is onboarded — or use `-By modified`. |
| Sign‑in / WAM prompt misbehaves | Re‑run with `-DeviceCode`. |
| `-StaleDays > 30` seems to under‑report | Expected: Advanced Hunting retains ~30 days, so activity can only prove 30 days of inactivity. |

## Appendix: the built-in hunting queries

Both queries start with the same inventory block, which maps every identifier an agent appears under to its catalog id. Override either query with `-HuntingQuery`. A stale override must return `Key` (catalog id, lowercase) and `LastActivity`.

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
# Tests (Pester 5+) and lint (PSScriptAnalyzer); CI runs the same on every pull request
Invoke-Pester -Path .\tests
Invoke-ScriptAnalyzer -Path .\Agent365-Bulk-Actions.ps1 -Settings .\PSScriptAnalyzerSettings.psd1
```

Dot-sourcing the script (`. .\Agent365-Bulk-Actions.ps1`) loads its functions without signing in or running anything, which is how the tests exercise them with mocked Graph calls.
## Disclaimer

Provided as‑is, without warranty of any kind. It targets a `/beta` Microsoft Graph API that can change without notice. Not an official Microsoft product. Test in a non‑production tenant first. See [LICENSE](LICENSE).

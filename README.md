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
- **Preview everything first** with a dry run before changing anything.

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
- **Filter**: the *Stale* and *Risk* dropdowns default to **None**. Pick a value to narrow the grid (no activity for 7 to 29 days, not modified for 30 to 365 days, or alert severity from Informational up to High); the matching columns fill in. The *Match* toggle controls how Stale and Risk combine: **All** (the default) needs both, **Any** accepts either. Search, status and Copilot-only always narrow on top. **Reset filters** returns everything to the unfiltered view.
- **Act**: tick rows (or *Select visible*), then **Block selected** or **Unblock selected**. A confirmation lists the agents first. Each action writes a result log under `%LOCALAPPDATA%\Agent365-Bulk-Actions\logs`.
- **Undo last run** reverses the previous action in the window. **Export list** saves what the grid shows as CSV or JSON.

### Risky agents

`-Risky` finds agents that have **Microsoft Defender "Security for AI" alerts** (jailbreak, prompt injection, credential/secret access, etc.) via Advanced Hunting (`runHuntingQuery`), and enriches each with **`severity` (Informational/Low/Medium/High)**, **`alerts`** (count), **`why`** (the alert titles), **`categories`**, and `lastAlert` — so you can decide by severity what to block. Use `-MinSeverity High` (or Medium/Low) to act only on the worst, and `-MinAlerts` for a count threshold; results are sorted worst-severity-first. Then block with the same preview → confirm/pick flow. Needs `ThreatHunting.Read.All` plus a Defender/E5 license with **Security for AI** onboarded (same prerequisite as `-Stale -By activity`).

> [!NOTE]
> Alerts are attributed to a package through the `AIAgent` entity in `AlertEvidence`, whose agent id is the package `id`. Only "Security for AI" alerts that carry an agent entity are counted. "Defender for AI Services" alerts name an Azure AI account rather than an agent and are not attributed. **Always run `-Risky -Action list` first**, and if the default query doesn't match your tenant's schema, override it with `-HuntingQuery` (return columns `Key, AlertCount, Severity, LastAlert`, with `Key` set to the package id). Advanced Hunting retains ~30 days, so `-RiskDays` is effectively capped there.

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
| `-Stale` | switch | Act on agents stale beyond `-StaleDays`. |
| `-StaleDays` | 1–3650 (30/60/90) | Age threshold in days. Required with `-Stale`. |
| `-By` | `activity` / `modified` | `activity` = no usage telemetry (Defender); `modified` = manifest age. |
| `-Risky` | switch | Act on agents with Defender AI‑security alerts (Advanced Hunting). |
| `-RiskDays` | 1–3650 (default 30) | Alert lookback window (Advanced Hunting retains ~30 days). |
| `-MinAlerts` | int (default 1) | Minimum alert count for an agent to count as risky. |
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
| where ActionType in ("InvokeAgent", "InferenceCall", "ExecuteToolBySDK", "ConnectedAIAppInteraction")
| extend d = todynamic(RawEventData)
| extend Keys = pack_array(tolower(tostring(coalesce(d.AgentId, d.agentId))),
                           tolower(tostring(d.TargetAgentId)), tolower(tostring(d.PlatformTargetAgentId)))
| mv-expand Key = Keys to typeof(string)
| where isnotempty(Key)
| summarize LastActivity = max(Timestamp) by Key
| join kind=leftouter inv on Key
| summarize LastActivity = max(LastActivity) by Key = coalesce(CatalogId, Key)
```

Risky (`-Risky`), after the same inventory block:

```kql
AlertInfo
| where Timestamp > ago(30d)
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
| extend Key = coalesce(CatalogId, AgentKey)
| extend sev = case(Severity == "High", 4, Severity == "Medium", 3, Severity == "Low", 2, Severity == "Informational", 1, 0)
| summarize AlertCount = dcount(AlertId), SevRank = max(sev), LastAlert = max(Timestamp),
            Reasons = make_set(Title, 8), Categories = make_set(Category, 6) by Key
| extend Severity = case(SevRank == 4, "High", SevRank == 3, "Medium", SevRank == 2, "Low", SevRank == 1, "Informational", "-")
```

## Disclaimer

Provided as‑is, without warranty of any kind. It targets a `/beta` Microsoft Graph API that can change without notice. Not an official Microsoft product. Test in a non‑production tenant first. See [LICENSE](LICENSE).

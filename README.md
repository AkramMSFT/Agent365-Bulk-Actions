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
> Advanced Hunting keeps only about **30 days** of data, so `-By activity` can prove inactivity for at most 30 days. If you set `-StaleDays` greater than 30, "stale" effectively means "no activity in the last 30 days," and the script warns you.

## Scenarios

```powershell
# List all Copilot agents and their blocked state
.\Agent365-Bulk-Actions.ps1 -List -AgentsOnly

# Block specific agents by name and/or P_ id (comma-separated)
.\Agent365-Bulk-Actions.ps1 -Block "Contoso HR Agent","Northwind Sales Agent","P_19ae1zz1-..."

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

# Undo
.\Agent365-Bulk-Actions.ps1 -Unblock "Contoso HR Agent","Northwind Sales Agent"
```

## Parameter reference

Only one primary mode (`List`, `Block`, `Unblock`, `Select`, or `Stale`) is used per run.

| Parameter | Values / default | What it does |
| --- | --- | --- |
| `-List` | switch | List catalog packages. |
| `-Block` | names and/or ids | Block one or more packages by display name and/or `P_` id. |
| `-Unblock` | names and/or ids | Unblock (undo) one or more packages. |
| `-Select` | switch | Interactive multi‑select picker over the catalog. |
| `-Stale` | switch | Act on agents stale beyond `-StaleDays`. |
| `-StaleDays` | 1–3650 (30/60/90) | Age threshold in days. Required with `-Stale`. |
| `-By` | `activity` / `modified` | `activity` = no usage telemetry (Defender); `modified` = manifest age. |
| `-HuntingQuery` | KQL (optional) | Custom KQL returning columns `Key`, `LastActivity`; overrides the built‑in query. |
| `-IncludeNeverSeen` | switch | Activity mode: also treat agents with zero telemetry as stale. |
| `-Action` | `block` / `unblock` / `list` | What to do with the matched set. `list` = preview only (dry run). |
| `-AgentsOnly` | switch | Limit to Copilot agents (`supportedHosts` contains `Copilot`). |
| `-Force` | switch | Skip the "proceed?" confirmation (Stale mode). |
| `-Pick` | switch | Choose which stale matches to act on via the picker. |
| `-TenantId` | GUID/domain (optional) | Target a specific tenant (default = your home tenant). |
| `-DeviceCode` | switch | Use device‑code sign‑in when interactive/WAM auth misbehaves. |

## Safety & good practice

- **Dry run first.** Add `-Action list` to preview before any bulk change.
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

## Appendix — the built‑in hunting query

When `-By activity` is used, the script runs this KQL against Defender Advanced Hunting to build each agent's last‑activity timestamp. Override it with `-HuntingQuery`, as long as your query returns the columns `Key` and `LastActivity`.

```kql
let win = 30d;
let ev = CloudAppEvents
    | where Timestamp > ago(win)
    | extend d = todynamic(RawEventData);
ev
| extend Key = tolower(tostring(coalesce(d.AgentId, d.agentId)))
| where isnotempty(Key)
| summarize LastActivity = max(Timestamp) by Key
| union (
    ev
    | extend Key = tolower(tostring(coalesce(d.AgentName, d.agentName)))
    | where isnotempty(Key)
    | summarize LastActivity = max(Timestamp) by Key )
| summarize LastActivity = max(LastActivity) by Key
```

## Disclaimer

Provided as‑is, without warranty of any kind. It targets a `/beta` Microsoft Graph API that can change without notice. Not an official Microsoft product. Test in a non‑production tenant first. See [LICENSE](LICENSE).

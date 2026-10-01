<#
.SYNOPSIS
  List / block / unblock Agent 365 (Copilot) catalog packages via Microsoft Graph beta,
  including bulk-blocking STALE agents (no activity/usage) or unmaintained (unmodified) ones.

.DESCRIPTION
  Wraps the Copilot Package Management API:
    GET  /beta/copilot/admin/catalog/packages              (list)
    POST /beta/copilot/admin/catalog/packages/{id}/block   (block)
    POST /beta/copilot/admin/catalog/packages/{id}/unblock (unblock)

  block/unblock are DELEGATED-ONLY (no app-only permission exists), so this
  script signs in an interactive admin and requests CopilotPackages.ReadWrite.All.
  Requires an Agent 365 license on the tenant. /beta = not for production.

  STALENESS by activity uses Defender Advanced Hunting (Graph /security/runHuntingQuery)
  to find each agent's last telemetry event in CloudAppEvents, and needs
  ThreatHunting.Read.All + a Defender / Microsoft 365 E5 license + "Security for AI" onboarded.

.PARAMETER TenantId
  Optional. Target a specific tenant (GUID or domain). If omitted, sign-in uses your
  account's home tenant.

.EXAMPLE
  # List agents only (supportedHosts contains Copilot), showing blocked state
  .\Agent365-Bulk-Actions.ps1 -List -AgentsOnly

.EXAMPLE
  # Block one or MANY by display name and/or P_ id (comma-separated)
  .\Agent365-Bulk-Actions.ps1 -Block "Contoso HR Agent","Northwind Sales Agent","P_19ae1zz1-..."

.EXAMPLE
  # Interactive multi-select picker over the whole catalog (grid if available, else numbered menu)
  .\Agent365-Bulk-Actions.ps1 -Select -AgentsOnly              # default action = block

.EXAMPLE
  # Compute stale agents, then PICK which of them to block from the list (no typing names)
  .\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 90 -Pick -AgentsOnly

.EXAMPLE
  # Block STALE agents = reported to Defender before but IDLE > 30/60/90 days. Preview + confirm.
  # (default only considers agents that HAVE emitted telemetry, so built-ins/add-ins are skipped)
  .\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 90 -AgentsOnly
  .\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 30 -Action list      # dry run, change nothing
  .\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 30 -Force            # skip confirmation

.EXAMPLE
  # Treat agents that have never reported any telemetry as stale (sweeps the whole catalog).
  .\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 90 -IncludeNeverSeen -Action list

.EXAMPLE
  # Old behavior: stale = agent package not MODIFIED in > N days (manifest age, no Defender needed)
  .\Agent365-Bulk-Actions.ps1 -Stale -StaleDays 90 -By modified -AgentsOnly

.EXAMPLE
  # List RISKY agents (Defender AI-security alerts and detections), then block them
  .\Agent365-Bulk-Actions.ps1 -Risky -Action list                    # dry run, shows alert count/severity
  .\Agent365-Bulk-Actions.ps1 -Risky -RiskDays 30 -MinAlerts 2 -AgentsOnly
  .\Agent365-Bulk-Actions.ps1 -Risky -Pick                           # choose which risky agents to block

.EXAMPLE
  # Undo
  .\Agent365-Bulk-Actions.ps1 -Unblock "Contoso HR Agent","Northwind Sales Agent"

.NOTES
  Add -DeviceCode if interactive/WAM sign-in misbehaves (for example on an unmanaged machine).
  Advanced Hunting retains only ~30 days, so -By activity can PROVE inactivity for at most
  30 days; StaleDays > 30 with -By activity means "no activity in the last 30 days".

  Project home / license: see the repository README and LICENSE.
#>
[CmdletBinding(DefaultParameterSetName = 'List', SupportsShouldProcess)]
param(
    [Parameter(ParameterSetName = 'List')]
    [switch]$List,

    [Parameter(ParameterSetName = 'Block', Mandatory, Position = 0)]
    [string[]]$Block,                         # one or more P_ ids OR displayNames

    [Parameter(ParameterSetName = 'Unblock', Mandatory, Position = 0)]
    [string[]]$Unblock,                       # one or more P_ ids OR displayNames

    [Parameter(ParameterSetName = 'Select', Mandatory)]
    [switch]$Select,                          # interactive multi-select picker

    [Parameter(ParameterSetName = 'Undo', Mandatory)]
    [string]$Undo,                            # reverse a previous run using its -OutFile log (.csv or .json)

    [Parameter(ParameterSetName = 'FromCsv', Mandatory)]
    [string]$FromCsv,                         # CSV with an Id and/or DisplayName column; apply -Action to every row

    [Parameter(ParameterSetName = 'Gui', Mandatory)]
    [switch]$Gui,                             # open the graphical console

    [Parameter(ParameterSetName = 'Stale', Mandatory)]
    [switch]$Stale,                           # act on agents stale > StaleDays

    [Parameter(ParameterSetName = 'Stale', Mandatory)]
    [ValidateRange(1, 3650)]
    [int]$StaleDays,                          # 30 / 60 / 90 are the usual presets

    [Parameter(ParameterSetName = 'Stale')]
    [ValidateSet('activity', 'modified')]
    [string]$By = 'activity',                 # activity = no usage telemetry; modified = manifest age

    [Parameter(ParameterSetName = 'Stale')]
    [Parameter(ParameterSetName = 'Risky')]
    [string]$HuntingQuery,                    # optional KQL override. Stale: return Key,LastActivity.
                                              # Risky: return Key,AlertCount,Severity,LastAlert

    [Parameter(ParameterSetName = 'Stale')]
    [switch]$IncludeNeverSeen,                # activity mode: ALSO treat agents with zero telemetry as
                                              # stale (default = only agents that HAVE reported, but idle)

    [Parameter(ParameterSetName = 'Risky', Mandatory)]
    [switch]$Risky,                           # act on agents with Defender AI-security alerts

    [Parameter(ParameterSetName = 'Risky')]
    [ValidateRange(1, 3650)]
    [int]$RiskDays = 30,                       # alert lookback window (Advanced Hunting retains ~30 days)

    [Parameter(ParameterSetName = 'Risky')]
    [ValidateRange(1, 10000)]
    [int]$MinAlerts = 1,                       # minimum alert count for an agent to count as risky

    [Parameter(ParameterSetName = 'Risky')]
    [ValidateSet('Both', 'Alerts', 'Detections')]
    [string]$RiskSource = 'Both',             # Alerts = Security for AI alerts; Detections = BehaviorInfo detections that raised no alert

    [Parameter(ParameterSetName = 'Risky')]
    [ValidateSet('Informational', 'Low', 'Medium', 'High')]
    [string]$MinSeverity = 'Informational',    # only act on agents at/above this alert severity

    [Parameter(ParameterSetName = 'Select')]
    [Parameter(ParameterSetName = 'Stale')]
    [Parameter(ParameterSetName = 'Risky')]
    [Parameter(ParameterSetName = 'FromCsv')]
    [ValidateSet('block', 'unblock', 'list')]
    [string]$Action = 'block',                # what to do with the matched set ('list' = preview only)

    [Parameter(ParameterSetName = 'List')]
    [Parameter(ParameterSetName = 'Select')]
    [Parameter(ParameterSetName = 'Stale')]
    [Parameter(ParameterSetName = 'Risky')]
    [switch]$AgentsOnly,                       # filter supportedHosts eq 'Copilot'

    [switch]$Force,                           # skip the "proceed?" confirmation for any write

    [string]$OutFile,                         # write a per-agent result log (.csv or .json)

    [Parameter(ParameterSetName = 'Stale')]
    [Parameter(ParameterSetName = 'Risky')]
    [switch]$Pick,                            # choose WHICH stale/risky agents to act on via the picker

    [string]$TenantId,                        # optional: target a specific tenant (default = home tenant)

    [switch]$DeviceCode
)

$ErrorActionPreference = 'Stop'
$Base = 'https://graph.microsoft.com/beta/copilot/admin/catalog/packages'

# Advanced Hunting keeps ~30 days, so an agent last seen before the cutoff can only be found when
# the cutoff is inside that window. At 30+ days only "no activity at all in the window" is provable.
if ($PSCmdlet.ParameterSetName -eq 'Stale' -and $By -eq 'activity' -and $StaleDays -ge 30 -and
    -not $IncludeNeverSeen -and -not $HuntingQuery) {
    throw (("-StaleDays {0} with -By activity cannot find agents that reported before: telemetry is retained ~30 days. " -f $StaleDays) +
           'Use a value below 30, add -IncludeNeverSeen to flag agents with no activity in the last 30 days, or use -By modified.')
}

# --- ensure the Graph auth module (no full SDK needed) ---
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host 'Installing Microsoft.Graph.Authentication (CurrentUser)...' -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# --- sign in (delegated). Read-only paths need .Read.All; writes need .ReadWrite.All;
#     activity-based staleness also needs ThreatHunting.Read.All for Advanced Hunting ---
$readOnly = ($PSCmdlet.ParameterSetName -eq 'List') -or
            ($PSCmdlet.ParameterSetName -in @('Select', 'Stale', 'Risky', 'FromCsv') -and $Action -eq 'list')
$scopes = @(if ($readOnly) { 'CopilotPackages.Read.All' } else { 'CopilotPackages.ReadWrite.All' })
if (($PSCmdlet.ParameterSetName -eq 'Stale' -and $By -eq 'activity') -or
    $PSCmdlet.ParameterSetName -in @('Risky', 'Gui')) { $scopes += 'ThreatHunting.Read.All' }
$connect = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId)   { $connect['TenantId'] = $TenantId }
if ($DeviceCode) { $connect['UseDeviceCode'] = $true }
Connect-MgGraph @connect

# Graph call with retry on throttling (429) and transient 5xx, honouring Retry-After.
function Invoke-Graph {
    param([string]$Method = 'GET', [string]$Uri, [string]$Body, [string]$ContentType)
    $call = @{ Method = $Method; Uri = $Uri }
    if ($Body) { $call['Body'] = $Body; $call['ContentType'] = $ContentType }
    for ($attempt = 1; ; $attempt++) {
        try { return Invoke-MgGraphRequest @call }
        catch {
            $resp = $_.Exception.Response
            $code = if ($resp -and $resp.StatusCode) { [int]$resp.StatusCode } else { 0 }
            if ($code -notin 429, 502, 503, 504 -or $attempt -ge 5) { throw }
            $wait = [Math]::Pow(2, $attempt)
            try { if ($resp.Headers.RetryAfter.Delta) { $wait = [Math]::Max($wait, $resp.Headers.RetryAfter.Delta.TotalSeconds) } } catch { $null = $_ }
            Write-Warning ("HTTP {0}; retrying in {1:N0}s (attempt {2}/5)." -f $code, $wait, $attempt)
            Start-Sleep -Seconds $wait
        }
    }
}

function Get-Packages {
    param([switch]$AgentsOnly)
    $uri = if ($AgentsOnly) {
        "$Base`?`$filter=supportedHosts/any(h:h eq 'Copilot')"
    } else { $Base }
    $all = @()
    do {
        $resp = Invoke-Graph -Uri $uri
        # Invoke-MgGraphRequest returns each item as a Hashtable; cast to PSCustomObject so
        # Select-Object / Format-Table can resolve displayName, id, isBlocked as real properties.
        foreach ($v in $resp.value) { $all += [pscustomobject]$v }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
    # The service does not apply the supportedHosts filter, so enforce it here.
    if ($AgentsOnly) { $all = @($all | Where-Object { @($_.supportedHosts) -contains 'Copilot' }) }
    $all
}

# Resolve a mix of package ids (P_ or T_) and display names to concrete catalog objects, so every
# target is validated and carries its current isBlocked state.
function Resolve-Packages {
    param([string[]]$Names)
    $catalog = @(Get-Packages)
    $resolved = foreach ($n in $Names) {
        $hit = if ($n -match '^[PT]_') { @($catalog | Where-Object { $_.id -eq $n }) }
               else { @($catalog | Where-Object { $_.displayName -eq $n }) }
        if ($hit.Count -eq 0) { throw "No package matching '$n'. Run -List to see names/ids." }
        if ($hit.Count -gt 1) { throw "Multiple packages named '$n'. Use the exact package id instead." }
        $hit[0]
    }
    @($resolved | Sort-Object id -Unique)
}

# Maps every identifier an agent can appear under in telemetry (registry id, Entra agent id,
# observability id, platform source id, bot id) to its catalog id. Package ids equal AgentsInfo titleId.
$InventoryKql = @'
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

'@

# Identifiers a catalog package can be matched on. Display names are excluded: they are not unique.
function Get-PackageKeys {
    param([object]$Package)
    @($Package.id, $Package.appId, $Package.manifestId, $Package.agentIdentityId) |
        Where-Object { $_ } | ForEach-Object { $_.ToString().ToLower() } | Select-Object -Unique
}

function Invoke-HuntingQuery {
    param([string]$Query, [string]$Hint)
    try {
        $resp = Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
            -Body (@{ Query = $Query } | ConvertTo-Json) -ContentType 'application/json'
    } catch {
        throw ("Advanced Hunting query failed ({0}). {1}" -f $_.Exception.Message, $Hint)
    }
    @($resp.results)
}

# Build a lookup of  catalog id (lowercased)  ->  last telemetry timestamp, from Defender
# Advanced Hunting over the retained window (Defender keeps ~30 days).
function Get-ActivityIndex {
    param()
    $win = 30   # full retention: the index must reach back past the stale cutoff
    $kql = if ($HuntingQuery) { $HuntingQuery } else { $InventoryKql + @"
CloudAppEvents
| where Timestamp > ago(${win}d)
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
"@ }

    $rows = Invoke-HuntingQuery -Query $kql -Hint "Check ThreatHunting.Read.All consent, an E5/Defender license, and that 'Security for AI' is onboarded. Use -By modified to fall back to manifest age."
    $idx = @{}
    foreach ($row in $rows) {
        $k = [string]$row.Key
        if ([string]::IsNullOrWhiteSpace($k)) { continue }
        $k = $k.ToLower()
        $ts = [datetimeoffset]$row.LastActivity
        if (-not $idx.ContainsKey($k) -or $ts -gt $idx[$k]) { $idx[$k] = $ts }
    }
    $idx
}

# Return agent packages annotated with a StaleSince datetimeoffset ($null = never/unknown),
# filtered to those stale beyond the cutoff. $By selects the signal.
function Get-StalePackages {
    param([int]$Days, [ValidateSet('activity', 'modified')][string]$By, [switch]$AgentsOnly,
          [switch]$IncludeNeverSeen)
    $cutoff = [datetimeoffset]((Get-Date).ToUniversalTime().AddDays(-$Days))
    $pkgs = @(Get-Packages -AgentsOnly:$AgentsOnly)

    if ($By -eq 'modified') {
        $out = foreach ($p in $pkgs) {
            $since = $null
            if ($p.lastModifiedDateTime) { try { $since = [datetimeoffset]$p.lastModifiedDateTime } catch {} }
            if ($null -ne $since -and $since -lt $cutoff) {
                $p | Add-Member -NotePropertyName StaleSince -NotePropertyValue $since -Force -PassThru
            }
        }
        return @($out | Sort-Object StaleSince)
    }

    # activity
    $idx = Get-ActivityIndex
    $out = foreach ($p in $pkgs) {
        $last = $null
        foreach ($k in (Get-PackageKeys $p)) {
            if ($idx.ContainsKey($k) -and ($null -eq $last -or $idx[$k] -gt $last)) { $last = $idx[$k] }
        }
        # Default: stale only if the agent HAS reported telemetry but its last event predates the
        # cutoff. -IncludeNeverSeen also flags agents that never appear in telemetry at all.
        $isStale = if ($null -eq $last) { [bool]$IncludeNeverSeen } else { $last -lt $cutoff }
        if ($isStale) {
            $p | Add-Member -NotePropertyName StaleSince -NotePropertyValue $last -Force -PassThru
        }
    }
    # nulls (never seen) first, then oldest activity
    return @($out | Sort-Object @{ e = { $null -ne $_.StaleSince } }, StaleSince)
}

# Interactive multi-select over ANY set of package objects (full catalog or a stale subset).
# Uses Out-GridView -PassThru when available, else a numbered menu that accepts comma lists
# and ranges, e.g.  1,3,5-7  or  all. Returns the chosen subset (objects carry id + displayName).
function Invoke-Picker {
    param([object[]]$Packages, [string]$Title = 'Select agents (Ctrl/Shift for multiple), then OK')
    $pkgs = @($Packages | Sort-Object displayName)
    if ($pkgs.Count -eq 0) { return @() }
    $hasStale = $pkgs[0].PSObject.Properties.Name -contains 'StaleSince'

    # Flat view rows that keep id + displayName so the action step works on the picked objects.
    $view = $pkgs | ForEach-Object {
        $o = [ordered]@{ displayName = $_.displayName; isBlocked = $_.isBlocked }
        if ($hasStale) {
            $o.lastSeen = if ($_.StaleSince) { $_.StaleSince.ToString('yyyy-MM-dd') } else { 'never/none' }
            $o.idleDays = if ($_.StaleSince) { [int]([datetimeoffset]::UtcNow - $_.StaleSince).TotalDays } else { $null }
        } else {
            $o.hosts = ($_.supportedHosts) -join ','
        }
        $o.id = $_.id
        [pscustomobject]$o
    }

    if (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
        return @($view | Out-GridView -Title $Title -PassThru)
    }

    Write-Host "`n$Title`n" -ForegroundColor Cyan
    for ($i = 0; $i -lt $view.Count; $i++) {
        $flag  = if ($view[$i].isBlocked) { '[blocked]' } else { '         ' }
        $extra = if ($hasStale) { '  (idle {0}d, seen {1})' -f $view[$i].idleDays, $view[$i].lastSeen } else { '' }
        '{0,3}) {1} {2}{3}' -f ($i + 1), $flag, $view[$i].displayName, $extra | Write-Host
    }
    $entry = Read-Host "`nSelect (e.g. 1,3,5-7 or 'all', blank to cancel)"
    if ([string]::IsNullOrWhiteSpace($entry)) { return @() }

    $idx = New-Object System.Collections.Generic.HashSet[int]
    if ($entry.Trim() -eq 'all') {
        0..($view.Count - 1) | ForEach-Object { [void]$idx.Add($_) }
    } else {
        foreach ($tok in $entry -split ',') {
            $tok = $tok.Trim()
            if ($tok -match '^\d+$') {
                [void]$idx.Add([int]$tok - 1)
            } elseif ($tok -match '^(\d+)\s*-\s*(\d+)$') {
                ([int]$Matches[1] - 1)..([int]$Matches[2] - 1) | ForEach-Object { [void]$idx.Add($_) }
            } elseif ($tok) {
                Write-Warning "Ignoring unrecognized selection '$tok'."
            }
        }
    }
    @($idx | Where-Object { $_ -ge 0 -and $_ -lt $view.Count } | Sort-Object | ForEach-Object { $view[$_] })
}

# Preview table for a stale set: shows when each agent was last seen and how many days idle.
function Show-StalePreview {
    param([object[]]$Packages, [string]$Basis)
    $label = if ($Basis -eq 'activity') { 'lastActivity' } else { 'lastModified' }
    $Packages | Select-Object displayName, id,
        @{ n = $label;   e = { if ($_.StaleSince) { $_.StaleSince.ToString('yyyy-MM-dd') } else { 'never/none' } } },
        @{ n = 'idleDays'; e = { if ($_.StaleSince) { [int]([datetimeoffset]::UtcNow - $_.StaleSince).TotalDays } else { $null } } },
        isBlocked |
        Format-Table -AutoSize | Out-Host
}

# Query Defender Advanced Hunting for risk signals per agent and return Key -> risk info.
# Signals are Security for AI alerts and, because Defender can detect without alerting, the
# agent-attributed behaviors in BehaviorInfo/BehaviorEntities. Behaviors carry no severity, so one
# is assigned: a block (an attack was stopped) ranks High, an audit/detect (seen, not stopped) Medium.
function Get-RiskyIndex {
    param([int]$Days, [ValidateSet('Both', 'Alerts', 'Detections')][string]$Source = 'Both')
    $alertLeg = @"
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
    | join kind=leftouter inv on `$left.AgentKey == `$right.Key
    | project Key = coalesce(CatalogId, AgentKey), Kind = "Alert", SignalId = AlertId, Timestamp,
              Rank = case(Severity == "High", 4, Severity == "Medium", 3, Severity == "Low", 2, Severity == "Informational", 1, 0),
              Reason = Title, Category;

"@
    $detectionLeg = @"
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
    | join kind=leftouter inv on `$left.AgentKey == `$right.Key
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

"@
    $legs = switch ($Source) { 'Alerts' { 'alerts' } 'Detections' { 'rtp, shield' } default { 'alerts, rtp, shield' } }
    $prefix = $InventoryKql + "let win = ${Days}d;`n" +
              $(if ($Source -ne 'Detections') { $alertLeg }) + $(if ($Source -ne 'Alerts') { $detectionLeg })
    $kql = if ($HuntingQuery) { $HuntingQuery } else { $prefix + @"
union $legs
| summarize AlertCount = dcountif(SignalId, Kind == "Alert"), DetectionCount = dcountif(SignalId, Kind == "Detection"),
            SevRank = max(Rank), LastAlert = max(Timestamp),
            Reasons = make_set(Reason, 8), Categories = make_set(Category, 6) by Key
| extend Severity = case(SevRank == 4, "High", SevRank == 3, "Medium", SevRank == 2, "Low", SevRank == 1, "Informational", "-")
"@ }
    $rows = Invoke-HuntingQuery -Query $kql -Hint "Check ThreatHunting.Read.All consent, an E5/Defender license, and that 'Security for AI' is onboarded."
    # make_set columns come back as arrays (or a JSON string); normalize to a "; "-joined string.
    $joinSet = {
        param($v)
        if ($v -is [string]) { try { $v = $v | ConvertFrom-Json } catch { $null = $_ } }
        (@($v) | ForEach-Object { [string]$_ } | Where-Object { $_ }) -join '; '
    }
    $idx = @{}
    foreach ($row in $rows) {
        $k = [string]$row.Key
        if ([string]::IsNullOrWhiteSpace($k)) { continue }
        $idx[$k.ToLower()] = [pscustomobject]@{
            AlertCount     = [int]$row.AlertCount
            DetectionCount = [int]$row.DetectionCount
            Severity       = [string]$row.Severity
            LastAlert      = if ($row.LastAlert) { [datetimeoffset]$row.LastAlert } else { $null }
            Reasons        = (& $joinSet $row.Reasons)
            Categories     = (& $joinSet $row.Categories)
        }
    }
    $idx
}

# Rank a severity string so we can filter/sort (higher = worse).
function Get-SevRank { param([string]$S)
    switch ($S) { 'High' { 4 } 'Medium' { 3 } 'Low' { 2 } 'Informational' { 1 } default { 0 } } }

# Return agent packages with >= MinAlerts alerts at/above MinSeverity, annotated with risk info.
function Get-RiskyPackages {
    param([int]$Days, [int]$MinAlerts, [string]$MinSeverity, [switch]$AgentsOnly,
          [ValidateSet('Both', 'Alerts', 'Detections')][string]$Source = 'Both')
    $idx = Get-RiskyIndex -Days $Days -Source $Source
    $minRank = Get-SevRank $MinSeverity
    $out = foreach ($p in (Get-Packages -AgentsOnly:$AgentsOnly)) {
        $hit = $null
        foreach ($k in (Get-PackageKeys $p)) { if ($idx.ContainsKey($k)) { $hit = $idx[$k]; break } }
        if ($hit -and ($hit.AlertCount + $hit.DetectionCount) -ge $MinAlerts -and (Get-SevRank $hit.Severity) -ge $minRank) {
            $p | Add-Member -NotePropertyName RiskAlerts     -NotePropertyValue $hit.AlertCount     -Force
            $p | Add-Member -NotePropertyName RiskDetections -NotePropertyValue $hit.DetectionCount -Force
            $p | Add-Member -NotePropertyName RiskSeverity   -NotePropertyValue $hit.Severity       -Force
            $p | Add-Member -NotePropertyName RiskReasons    -NotePropertyValue $hit.Reasons        -Force
            $p | Add-Member -NotePropertyName RiskCategories -NotePropertyValue $hit.Categories     -Force
            $p | Add-Member -NotePropertyName RiskLastAlert  -NotePropertyValue $hit.LastAlert      -Force -PassThru
        }
    }
    # worst first: by severity, then total signals
    @($out | Sort-Object -Property @{ e = { Get-SevRank $_.RiskSeverity } ; Descending = $true },
                                   @{ e = { $_.RiskAlerts + $_.RiskDetections } ; Descending = $true })
}

# Preview table for a risky set (severity, signal counts, and WHY / reasons).
function Show-RiskyPreview {
    param([object[]]$Packages)
    $Packages | Select-Object `
        @{ n = 'severity';   e = { $_.RiskSeverity } },
        @{ n = 'alerts';     e = { $_.RiskAlerts } },
        @{ n = 'detections'; e = { $_.RiskDetections } },
        displayName,
        @{ n = 'why'; e = { $_.RiskReasons } },
        @{ n = 'categories'; e = { $_.RiskCategories } },
        @{ n = 'lastSignal'; e = { if ($_.RiskLastAlert) { $_.RiskLastAlert.ToString('yyyy-MM-dd') } else { '-' } } },
        isBlocked, id |
        Format-Table -AutoSize -Wrap | Out-Host
}

# Single seam over ShouldProcess so -WhatIf applies to every write.
function Test-Proceed { param([string]$Target, [string]$Verb) $PSCmdlet.ShouldProcess($Target, $Verb) }

# Ask once before a batch write. -Force and -WhatIf skip the prompt; a picker selection counts as consent.
function Confirm-Batch {
    param([int]$Count, [string]$Action, [switch]$Implied)
    if ($Implied -or $Force -or $WhatIfPreference) { return $true }
    (Read-Host ("Proceed to {0} {1} package(s)? [y/N]" -f $Action, $Count)) -match '^(y|yes)$'
}

# Save the per-agent results (and the state each agent had before the run) as CSV or JSON.
function Export-ActionLog {
    param([object[]]$Records)
    if (-not $OutFile -or $Records.Count -eq 0) { return }
    if ($OutFile -match '\.json$') { $Records | ConvertTo-Json -Depth 3 | Set-Content -Path $OutFile -Encoding utf8 }
    else { $Records | Export-Csv -Path $OutFile -NoTypeInformation -Encoding utf8 }
    Write-Host "Result log: $OutFile" -ForegroundColor Cyan
}

# Apply block/unblock to each package; skip ones already in the target state, keep going on
# error, then summarize. Honours -WhatIf and records the outcome per package.
function Invoke-PackageAction {
    param([object[]]$Packages, [ValidateSet('block', 'unblock')][string]$Action, [switch]$PassThru)
    if (-not $Packages -or $Packages.Count -eq 0) { Write-Host 'Nothing selected.'; return }

    $want = ($Action -eq 'block')
    $who = (Get-MgContext).Account
    $verb = $Action.Substring(0,1).ToUpper() + $Action.Substring(1)
    Write-Host ("`n{0} {1} package(s):" -f $verb, $Packages.Count) -ForegroundColor Cyan
    $log = @(); $ok = 0; $skip = 0; $fail = 0
    foreach ($p in $Packages) {
        $rec = [ordered]@{
            Timestamp = (Get-Date).ToUniversalTime().ToString('o'); Operator = $who; Action = $Action
            Id = $p.id; DisplayName = $p.displayName; WasBlocked = $p.isBlocked; Result = ''; Error = ''
        }
        if ($null -ne $p.isBlocked -and [bool]$p.isBlocked -eq $want) {
            Write-Host ("  SKIP {0}  ({1}) already {2}ed" -f $p.displayName, $p.id, $Action) -ForegroundColor DarkGray
            $rec.Result = 'Skipped'; $skip++
        } elseif (-not (Test-Proceed ("{0} ({1})" -f $p.displayName, $p.id) $verb)) {
            $rec.Result = 'WhatIf'
        } else {
            try {
                Invoke-Graph -Method POST -Uri "$Base/$($p.id)/$Action" | Out-Null   # 204
                Write-Host ("  OK   {0}  ({1})" -f $p.displayName, $p.id) -ForegroundColor Green
                $rec.Result = 'Done'; $ok++
            } catch {
                Write-Host ("  FAIL {0}  ({1}) -> {2}" -f $p.displayName, $p.id, $_.Exception.Message) -ForegroundColor Red
                $rec.Result = 'Failed'; $rec.Error = $_.Exception.Message; $fail++
            }
        }
        $log += [pscustomobject]$rec
    }
    Write-Host ("Done: {0} {1}ed, {2} skipped, {3} failed." -f $ok, $Action, $skip, $fail) -ForegroundColor Cyan
    Export-ActionLog -Records $log
    if ($PassThru) { $log }
}

# ---------------------------------------------------------------------------------------------
# Graphical console (-Gui): WPF window over the same catalog, stale, risky, block and unblock logic.
# ---------------------------------------------------------------------------------------------
$GuiXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Agent 365 Bulk Actions" Width="1280" Height="780" MinWidth="1000" MinHeight="560"
        WindowStartupLocation="CenterScreen" Background="#F3F4F6" FontFamily="Segoe UI" FontSize="13"
        UseLayoutRounding="True" SnapsToDevicePixels="True">
  <Window.Resources>
    <SolidColorBrush x:Key="Accent" Color="#0F6CBD"/>
    <SolidColorBrush x:Key="Ink" Color="#1F2937"/>
    <SolidColorBrush x:Key="Muted" Color="#6B7280"/>
    <SolidColorBrush x:Key="Line" Color="#E5E7EB"/>

    <Style x:Key="Btn" TargetType="Button">
      <Setter Property="Foreground" Value="{StaticResource Ink}"/>
      <Setter Property="Background" Value="White"/>
      <Setter Property="BorderBrush" Value="#D1D5DB"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="16,8"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Opacity" Value="0.88"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="bd" Property="Opacity" Value="0.72"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="bd" Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="BtnDanger" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="#C42B1C"/><Setter Property="BorderBrush" Value="#C42B1C"/><Setter Property="Foreground" Value="White"/>
    </Style>
    <Style x:Key="BtnGood" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="#107C41"/><Setter Property="BorderBrush" Value="#107C41"/><Setter Property="Foreground" Value="White"/>
    </Style>
    <Style x:Key="BtnAccent" TargetType="Button" BasedOn="{StaticResource Btn}">
      <Setter Property="Background" Value="#0F6CBD"/><Setter Property="BorderBrush" Value="#0F6CBD"/><Setter Property="Foreground" Value="White"/>
    </Style>
    <Style x:Key="BtnLink" TargetType="Button">
      <Setter Property="Foreground" Value="#0F6CBD"/><Setter Property="Cursor" Value="Hand"/><Setter Property="Background" Value="Transparent"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <TextBlock x:Name="t" Text="{TemplateBinding Content}" Foreground="{TemplateBinding Foreground}" Padding="4,2"/>
            <ControlTemplate.Triggers><Trigger Property="IsMouseOver" Value="True"><Setter TargetName="t" Property="TextDecorations" Value="Underline"/></Trigger></ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="Seg" TargetType="RadioButton">
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="bd" Background="Transparent" CornerRadius="5" Padding="14,6" Margin="2">
              <TextBlock x:Name="tx" Text="{TemplateBinding Content}" Foreground="#4B5563" FontWeight="SemiBold"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="bd" Property="Background" Value="White"/>
                <Setter TargetName="tx" Property="Foreground" Value="#0F6CBD"/>
              </Trigger>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#ECEEF1"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="TextBox">
      <Setter Property="Padding" Value="10,7"/><Setter Property="BorderBrush" Value="#D1D5DB"/><Setter Property="VerticalContentAlignment" Value="Center"/>
    </Style>
    <Style TargetType="ComboBox"><Setter Property="Padding" Value="8,5"/><Setter Property="VerticalContentAlignment" Value="Center"/></Style>

    <Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="#F9FAFB"/><Setter Property="Foreground" Value="#4B5563"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Padding" Value="12,10"/><Setter Property="BorderBrush" Value="#E5E7EB"/><Setter Property="BorderThickness" Value="0,0,0,1"/>
    </Style>
    <Style TargetType="DataGridCell">
      <Setter Property="BorderThickness" Value="0"/><Setter Property="Padding" Value="12,0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="DataGridCell">
            <Border Background="{TemplateBinding Background}" Padding="{TemplateBinding Padding}">
              <ContentPresenter VerticalAlignment="Center"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="DataGridRow">
      <Setter Property="Background" Value="White"/><Setter Property="MinHeight" Value="40"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="#F3F8FD"/></Trigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="#E6F0FA"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="Cell" TargetType="TextBlock"><Setter Property="TextTrimming" Value="CharacterEllipsis"/></Style>
    <Style x:Key="Pill" TargetType="Border">
      <Setter Property="CornerRadius" Value="10"/><Setter Property="Padding" Value="10,2"/><Setter Property="HorizontalAlignment" Value="Left"/>
    </Style>
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- header -->
    <Border Grid.Row="0" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="0,0,0,1" Padding="24,16">
      <Grid>
        <StackPanel>
          <TextBlock Text="Agent 365 Bulk Actions" FontSize="20" FontWeight="SemiBold" Foreground="{StaticResource Ink}"/>
          <TextBlock x:Name="Account" Foreground="{StaticResource Muted}" Margin="0,2,0,0"/>
        </StackPanel>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center">
          <Border Background="#F3F4F6" CornerRadius="8" Padding="14,6" Margin="0,0,10,0">
            <StackPanel Orientation="Horizontal">
              <TextBlock Text="Total " Foreground="{StaticResource Muted}"/><TextBlock x:Name="CountTotal" FontWeight="SemiBold" Margin="0,0,16,0"/>
              <TextBlock Text="Blocked " Foreground="{StaticResource Muted}"/><TextBlock x:Name="CountBlocked" FontWeight="SemiBold" Foreground="#C42B1C" Margin="0,0,16,0"/>
              <TextBlock Text="Showing " Foreground="{StaticResource Muted}"/><TextBlock x:Name="CountShown" FontWeight="SemiBold"/>
            </StackPanel>
          </Border>
          <Button x:Name="BtnRefresh" Content="Refresh" Style="{StaticResource Btn}"/>
        </StackPanel>
      </Grid>
    </Border>

    <!-- toolbar -->
    <Border Grid.Row="1" Padding="24,14,24,6">
      <Grid>
        <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
        <Grid Grid.Row="0">
          <Grid.ColumnDefinitions><ColumnDefinition Width="320"/><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
          <TextBox x:Name="Search" Grid.Column="0" ToolTip="Search by name, publisher, platform or id"/>
          <TextBlock Grid.Column="0" Text="Search agents" Foreground="#9CA3AF" IsHitTestVisible="False" Margin="12,0,0,0" VerticalAlignment="Center">
            <TextBlock.Style>
              <Style TargetType="TextBlock">
                <Setter Property="Visibility" Value="Collapsed"/>
                <Style.Triggers><DataTrigger Binding="{Binding Text, ElementName=Search}" Value=""><Setter Property="Visibility" Value="Visible"/></DataTrigger></Style.Triggers>
              </Style>
            </TextBlock.Style>
          </TextBlock>
          <Border Grid.Column="1" Background="#E5E7EB" CornerRadius="7" Margin="14,0,0,0" Padding="1">
            <StackPanel Orientation="Horizontal">
              <RadioButton x:Name="FltAll" Content="All" GroupName="f" IsChecked="True" Style="{StaticResource Seg}"/>
              <RadioButton x:Name="FltActive" Content="Active" GroupName="f" Style="{StaticResource Seg}"/>
              <RadioButton x:Name="FltBlocked" Content="Blocked" GroupName="f" Style="{StaticResource Seg}"/>
            </StackPanel>
          </Border>
          <Button x:Name="BtnReset" Grid.Column="2" Content="Reset filters" Style="{StaticResource Btn}" Padding="14,6" Margin="16,0,0,0" HorizontalAlignment="Left" IsEnabled="False"/>
          <CheckBox x:Name="AgentsOnlyBox" Grid.Column="3" Content="Copilot agents only" VerticalAlignment="Center"/>
        </Grid>
        <Border Grid.Row="1" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="8" Padding="14,10" Margin="0,12,0,0">
          <WrapPanel VerticalAlignment="Center">
            <TextBlock Text="FILTER BY" FontWeight="SemiBold" Foreground="{StaticResource Muted}" VerticalAlignment="Center" Margin="0,0,14,0"/>
            <TextBlock Text="Stale" VerticalAlignment="Center" Margin="0,0,8,0"/>
            <ComboBox x:Name="StaleBox" Width="205" SelectedIndex="0">
              <ComboBoxItem Content="None" Tag=""/>
              <ComboBoxItem Content="No activity for 7+ days" Tag="activity:7"/>
              <ComboBoxItem Content="No activity for 14+ days" Tag="activity:14"/>
              <ComboBoxItem Content="No activity for 21+ days" Tag="activity:21"/>
              <ComboBoxItem Content="No activity for 29+ days" Tag="activity:29"/>
              <ComboBoxItem Content="Not modified for 30+ days" Tag="modified:30"/>
              <ComboBoxItem Content="Not modified for 60+ days" Tag="modified:60"/>
              <ComboBoxItem Content="Not modified for 90+ days" Tag="modified:90"/>
              <ComboBoxItem Content="Not modified for 180+ days" Tag="modified:180"/>
              <ComboBoxItem Content="Not modified for 365+ days" Tag="modified:365"/>
            </ComboBox>
            <CheckBox x:Name="NeverSeenBox" Content="include never seen" VerticalAlignment="Center" Margin="12,0,0,0" IsEnabled="False" ToolTip="Activity filters only: also match agents with no telemetry in the last 30 days"/>
            <Rectangle Width="1" Fill="{StaticResource Line}" Margin="22,2,22,2"/>
            <TextBlock Text="Risk" VerticalAlignment="Center" Margin="0,0,8,0"/>
            <ComboBox x:Name="RiskBox" Width="175" SelectedIndex="0">
              <ComboBoxItem Content="None" Tag=""/>
              <ComboBoxItem Content="Informational or above" Tag="Informational"/>
              <ComboBoxItem Content="Low or above" Tag="Low"/>
              <ComboBoxItem Content="Medium or above" Tag="Medium"/>
              <ComboBoxItem Content="High only" Tag="High"/>
            </ComboBox>
            <TextBlock Text="from" VerticalAlignment="Center" Margin="10,0,8,0"/>
            <ComboBox x:Name="SignalBox" Width="155" SelectedIndex="0" ToolTip="Alerts come from Security for AI. Detections are BehaviorInfo records (real-time protection, Prompt Shield) that may never raise an alert.">
              <ComboBoxItem Content="Alerts + detections" Tag="Both"/>
              <ComboBoxItem Content="Alerts only" Tag="Alerts"/>
              <ComboBoxItem Content="Detections only" Tag="Detections"/>
            </ComboBox>
            <Rectangle Width="1" Fill="{StaticResource Line}" Margin="22,2,22,2"/>
            <TextBlock Text="Match" VerticalAlignment="Center" Margin="0,0,8,0"/>
            <Border Background="#E5E7EB" CornerRadius="7" Padding="1" VerticalAlignment="Center">
              <StackPanel Orientation="Horizontal">
                <RadioButton x:Name="MatchAll" Content="All" GroupName="m" IsChecked="True" Style="{StaticResource Seg}" ToolTip="An agent must match every active Stale and Risk filter (default)"/>
                <RadioButton x:Name="MatchAny" Content="Any" GroupName="m" Style="{StaticResource Seg}" ToolTip="An agent may match any one of the active Stale and Risk filters"/>
              </StackPanel>
            </Border>
            <TextBlock x:Name="MatchNote" Visibility="Collapsed"/>
          </WrapPanel>
        </Border>
      </Grid>
    </Border>

    <!-- grid -->
    <Border Grid.Row="2" Margin="24,8,24,0" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="8">
      <Grid>
        <DataGrid x:Name="Grid" AutoGenerateColumns="False" CanUserAddRows="False" CanUserDeleteRows="False" CanUserResizeRows="False"
                  HeadersVisibility="Column" GridLinesVisibility="Horizontal" HorizontalGridLinesBrush="#F0F1F3" BorderThickness="0"
                  Background="White" SelectionMode="Single" RowHeaderWidth="0" IsReadOnly="False" SelectionUnit="FullRow">
          <DataGrid.Columns>
            <DataGridTemplateColumn Width="46" SortMemberPath="Checked">
              <DataGridTemplateColumn.Header><CheckBox x:Name="HeaderCheck" HorizontalAlignment="Center" ToolTip="Select or clear every visible row"/></DataGridTemplateColumn.Header>
              <DataGridTemplateColumn.CellTemplate><DataTemplate>
                <CheckBox IsChecked="{Binding Checked, UpdateSourceTrigger=PropertyChanged}" HorizontalAlignment="Center" VerticalAlignment="Center"/>
              </DataTemplate></DataGridTemplateColumn.CellTemplate>
            </DataGridTemplateColumn>
            <DataGridTextColumn Header="Agent" Binding="{Binding Name}" Width="2*" IsReadOnly="True" ElementStyle="{StaticResource Cell}"/>
            <DataGridTemplateColumn Header="Status" Width="100" SortMemberPath="Status" IsReadOnly="True">
              <DataGridTemplateColumn.CellTemplate><DataTemplate>
                <Border>
                  <Border.Style>
                    <Style TargetType="Border" BasedOn="{StaticResource Pill}">
                      <Setter Property="Background" Value="#DFF6DD"/>
                      <Style.Triggers><DataTrigger Binding="{Binding IsBlocked}" Value="True"><Setter Property="Background" Value="#FDE7E9"/></DataTrigger></Style.Triggers>
                    </Style>
                  </Border.Style>
                  <TextBlock Text="{Binding Status}" FontWeight="SemiBold" FontSize="12">
                    <TextBlock.Style>
                      <Style TargetType="TextBlock">
                        <Setter Property="Foreground" Value="#0B6A0B"/>
                        <Style.Triggers><DataTrigger Binding="{Binding IsBlocked}" Value="True"><Setter Property="Foreground" Value="#A4262C"/></DataTrigger></Style.Triggers>
                      </Style>
                    </TextBlock.Style>
                  </TextBlock>
                </Border>
              </DataTemplate></DataGridTemplateColumn.CellTemplate>
            </DataGridTemplateColumn>
            <DataGridTextColumn Header="Platform" Binding="{Binding Platform}" Width="1.2*" IsReadOnly="True" ElementStyle="{StaticResource Cell}"/>
            <DataGridTextColumn Header="Publisher" Binding="{Binding Publisher}" Width="1.2*" IsReadOnly="True" ElementStyle="{StaticResource Cell}"/>
            <DataGridTextColumn Header="Modified" Binding="{Binding Modified}" Width="95" IsReadOnly="True"/>
            <DataGridTextColumn Header="Last activity" Binding="{Binding LastActivity}" Width="105" SortMemberPath="LastActivity" IsReadOnly="True"/>
            <DataGridTextColumn Header="Idle days" Binding="{Binding Idle}" Width="80" SortMemberPath="IdleSort" IsReadOnly="True"/>
            <DataGridTemplateColumn Header="Risk" Width="110" SortMemberPath="RiskSort" IsReadOnly="True">
              <DataGridTemplateColumn.CellTemplate><DataTemplate>
                <TextBlock Text="{Binding Risk}" FontWeight="SemiBold">
                  <TextBlock.Style>
                    <Style TargetType="TextBlock">
                      <Setter Property="Foreground" Value="#1F2937"/>
                      <Style.Triggers>
                        <DataTrigger Binding="{Binding Risk}" Value="High"><Setter Property="Foreground" Value="#A4262C"/></DataTrigger>
                        <DataTrigger Binding="{Binding Risk}" Value="Medium"><Setter Property="Foreground" Value="#B45309"/></DataTrigger>
                      </Style.Triggers>
                    </Style>
                  </TextBlock.Style>
                </TextBlock>
              </DataTemplate></DataGridTemplateColumn.CellTemplate>
            </DataGridTemplateColumn>
            <DataGridTextColumn Header="Alerts" Binding="{Binding Alerts}" Width="62" SortMemberPath="AlertsSort" IsReadOnly="True"/>
            <DataGridTextColumn Header="Detections" Binding="{Binding Detections}" Width="90" SortMemberPath="DetectionsSort" IsReadOnly="True"/>
            <DataGridTextColumn Header="Why" Binding="{Binding Why}" Width="2*" IsReadOnly="True" ElementStyle="{StaticResource Cell}"/>
          </DataGrid.Columns>
        </DataGrid>
        <StackPanel x:Name="EmptyNote" HorizontalAlignment="Center" VerticalAlignment="Center" Visibility="Collapsed">
          <TextBlock x:Name="EmptyText" Foreground="{StaticResource Muted}" FontSize="14" HorizontalAlignment="Center"/>
        </StackPanel>
      </Grid>
    </Border>

    <!-- action bar -->
    <Border Grid.Row="3" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="0,1,0,0" Padding="24,14" Margin="0,12,0,0">
      <Grid>
        <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
          <TextBlock x:Name="SelectedText" FontWeight="SemiBold" VerticalAlignment="Center" MinWidth="110"/>
          <Button x:Name="BtnSelectVisible" Content="Select visible" Style="{StaticResource BtnLink}" Margin="12,0,0,0"/>
          <Button x:Name="BtnClearSel" Content="Clear selection" Style="{StaticResource BtnLink}" Margin="6,0,0,0"/>
        </StackPanel>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
          <Button x:Name="BtnExport" Content="Export list" Style="{StaticResource Btn}" Margin="0,0,8,0"/>
          <Button x:Name="BtnUndo" Content="Undo last run" Style="{StaticResource Btn}" Margin="0,0,22,0" IsEnabled="False"/>
          <Button x:Name="BtnUnblock" Content="Unblock selected" Style="{StaticResource BtnGood}" Margin="0,0,10,0" MinWidth="150" IsEnabled="False"/>
          <Button x:Name="BtnBlock" Content="Block selected" Style="{StaticResource BtnDanger}" MinWidth="150" IsEnabled="False"/>
        </StackPanel>
      </Grid>
    </Border>

    <!-- status -->
    <Border Grid.Row="4" Background="#F9FAFB" BorderBrush="{StaticResource Line}" BorderThickness="0,1,0,0" Padding="24,7">
      <TextBlock x:Name="Status" Foreground="{StaticResource Muted}" FontSize="12" TextTrimming="CharacterEllipsis"/>
    </Border>
  </Grid>
</Window>
'@

# Row model with change notification so checkboxes, status pills and analysis columns update live.
if (-not ('AgentRow' -as [type])) {
    $notifyProps = 'Checked:bool', 'IsBlocked:bool', 'LastActivity:string', 'Idle:string', 'IdleSort:int',
                   'Risk:string', 'RiskSort:int', 'Alerts:string', 'AlertsSort:int', 'Detections:string', 'DetectionsSort:int', 'Why:string'
    $props = foreach ($np in $notifyProps) {
        $n, $t = $np -split ':'
        "private $t _$n; public $t $n { get { return _$n; } set { _$n = value; Notify(`"$n`"); $(if ($n -eq 'IsBlocked') { 'Notify("Status");' }) } }"
    }
    Add-Type -ReferencedAssemblies System.ObjectModel -TypeDefinition @"
using System.ComponentModel;
public class AgentRow : INotifyPropertyChanged {
    public event PropertyChangedEventHandler PropertyChanged;
    private void Notify(string p) { if (PropertyChanged != null) PropertyChanged(this, new PropertyChangedEventArgs(p)); }
    public string Status { get { return IsBlocked ? "Blocked" : "Active"; } }
    public string Id { get; set; }
    public string Name { get; set; }
    public string Platform { get; set; }
    public string Publisher { get; set; }
    public string Hosts { get; set; }
    public string Modified { get; set; }
    public object Package { get; set; }
    $($props -join "`n    ")
}
"@
}

$ConfirmXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Confirm the action" Width="500" SizeToContent="Height" ResizeMode="NoResize" ShowInTaskbar="False"
        WindowStartupLocation="CenterOwner" Background="White" FontFamily="Segoe UI" FontSize="13" UseLayoutRounding="True">
  <Grid Margin="28,24,28,22">
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <StackPanel Orientation="Horizontal">
      <Border x:Name="Badge" Width="40" Height="40" CornerRadius="20" Background="#FDE7E9">
        <TextBlock x:Name="BadgeText" Text="!" FontSize="22" FontWeight="Bold" Foreground="#C42B1C" HorizontalAlignment="Center" VerticalAlignment="Center"/>
      </Border>
      <StackPanel Margin="14,0,0,0" VerticalAlignment="Center">
        <TextBlock Text="Confirm the action" FontSize="18" FontWeight="SemiBold" Foreground="#1F2937"/>
        <TextBlock x:Name="Message" Foreground="#4B5563" Margin="0,2,0,0" TextWrapping="Wrap"/>
      </StackPanel>
    </StackPanel>
    <Border Grid.Row="1" Margin="0,18,0,0" BorderBrush="#E5E7EB" BorderThickness="1" CornerRadius="8" Background="#F9FAFB">
      <ListBox x:Name="Names" MaxHeight="190" BorderThickness="0" Background="Transparent" Padding="6,4"/>
    </Border>
    <TextBlock Grid.Row="2" Text="You can reverse this with the opposite action or Undo last run." Foreground="#6B7280" FontSize="12" Margin="0,12,0,0"/>
    <StackPanel Grid.Row="3" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,22,0,0">
      <Button x:Name="BtnCancel" Content="Cancel" Style="{DynamicResource Btn}" IsCancel="True" IsDefault="True" MinWidth="100" Margin="0,0,10,0"/>
      <Button x:Name="BtnOk" Style="{DynamicResource BtnDanger}" MinWidth="160"/>
    </StackPanel>
  </Grid>
</Window>
'@

function New-ConfirmDialog {
    param([object[]]$Rows, [string]$Verb, [System.Windows.Window]$Owner)
    $d = [Windows.Markup.XamlReader]::Parse($ConfirmXaml)
    if ($Owner) { $d.Owner = $Owner; $d.Resources.MergedDictionaries.Add($Owner.Resources) }
    $count = @($Rows).Count
    $noun = if ($count -eq 1) { 'agent' } else { 'agents' }
    $d.FindName('Message').Text = "You are about to $($Verb.ToLower()) $count $noun."
    $names = $d.FindName('Names')
    foreach ($r in @($Rows) | Select-Object -First 50) { [void]$names.Items.Add($r.Name) }
    if ($count -gt 50) { [void]$names.Items.Add("... and $($count - 50) more") }
    $ok = $d.FindName('BtnOk'); $ok.Content = "$Verb $count $noun"
    if ($Verb -eq 'Unblock') {
        $ok.SetResourceReference([Windows.Controls.Control]::StyleProperty, 'BtnGood')
        $d.FindName('Badge').Background = '#DFF6DD'; $d.FindName('BadgeText').Foreground = '#0B6A0B'; $d.FindName('BadgeText').Text = 'i'
    }
    $script:confirmDialog = $d
    $ok.Add_Click({ $script:confirmDialog.DialogResult = $true })
    $d
}

function New-ConsoleWindow {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $script:w = [Windows.Markup.XamlReader]::Parse($GuiXaml)
    $script:ui = @{}
    foreach ($n in 'Account', 'CountTotal', 'CountBlocked', 'CountShown', 'BtnRefresh', 'Search', 'FltAll', 'FltActive', 'FltBlocked',
                   'AgentsOnlyBox', 'StaleBox', 'NeverSeenBox', 'RiskBox', 'SignalBox', 'BtnReset', 'MatchAll', 'MatchAny', 'MatchNote',
                    'Grid', 'HeaderCheck', 'EmptyNote', 'EmptyText', 'SelectedText', 'BtnSelectVisible', 'BtnClearSel',
                   'BtnExport', 'BtnUndo', 'BtnUnblock', 'BtnBlock', 'Status') { $script:ui[$n] = $script:w.FindName($n) }

    $script:ctx = @{ Window = $script:w; UI = $script:ui; Rows = $null; View = $null; StaleSet = $null; RiskSet = $null; LastRun = @() }
    $script:ctx.Rows = New-Object 'System.Collections.ObjectModel.ObservableCollection[AgentRow]'
    $script:ctx.View = [Windows.Data.CollectionViewSource]::GetDefaultView($script:ctx.Rows)
    $script:ui.Grid.ItemsSource = $script:ctx.View

    $script:ctx.Pump = { $script:w.Dispatcher.Invoke([Action]{}, [Windows.Threading.DispatcherPriority]::Background) }
    $script:ctx.Busy = { param($msg) $script:ui.Status.Text = $msg; $script:w.Cursor = [Windows.Input.Cursors]::Wait; & $script:ctx.Pump }
    $script:ctx.Idle = { param($msg) $script:ui.Status.Text = $msg; $script:w.Cursor = $null }

    $script:ctx.Summary = {
        $rows = @($script:ctx.Rows)
        $checked = @($rows | Where-Object { $_.Checked })
        $script:ui.CountTotal.Text = $rows.Count
        $script:ui.CountBlocked.Text = @($rows | Where-Object { $_.IsBlocked }).Count
        $script:ui.CountShown.Text = @($script:ctx.View).Count
        $script:ui.SelectedText.Text = if ($checked.Count) { "$($checked.Count) selected" } else { 'None selected' }
        $script:ui.BtnBlock.IsEnabled   = @($checked | Where-Object { -not $_.IsBlocked }).Count -gt 0
        $script:ui.BtnUnblock.IsEnabled = @($checked | Where-Object { $_.IsBlocked }).Count -gt 0
        $script:ui.BtnUndo.IsEnabled    = @($script:ctx.LastRun | Where-Object { $_.Result -eq 'Done' }).Count -gt 0
        $shown = [int]$script:ui.CountShown.Text
        $script:ui.EmptyNote.Visibility = if ($shown -eq 0) { 'Visible' } else { 'Collapsed' }
        $script:ui.EmptyText.Text = if ($rows.Count -eq 0) { 'No agents loaded.' } else { 'No agents match the current filters.' }
    }

    $script:ctx.Filter = {
        param($o)
        if ($script:ui.FltActive.IsChecked  -and $o.IsBlocked)       { return $false }
        if ($script:ui.FltBlocked.IsChecked -and -not $o.IsBlocked)  { return $false }
        if ($script:ui.AgentsOnlyBox.IsChecked -and $o.Hosts -notmatch 'Copilot') { return $false }
        $sets = @(); foreach ($s in $script:ctx.StaleSet, $script:ctx.RiskSet) { if ($null -ne $s) { $sets += , $s } }
        if ($sets.Count) {
            $hits = @($sets | Where-Object { $_.Contains($o.Id) }).Count
            if ($script:ui.MatchAny.IsChecked) { if ($hits -eq 0) { return $false } }
            elseif ($hits -ne $sets.Count) { return $false }
        }
        $q = $script:ui.Search.Text.Trim()
        if ($q -and -not (($o.Name, $o.Publisher, $o.Platform, $o.Id) -join ' ').ToLower().Contains($q.ToLower())) { return $false }
        $true
    }
    $script:ctx.View.Filter = [Predicate[object]]$script:ctx.Filter

    $script:ctx.FilterActive = {
        [bool]($script:ui.Search.Text.Trim() -or $script:ui.FltActive.IsChecked -or $script:ui.FltBlocked.IsChecked -or
               $script:ui.AgentsOnlyBox.IsChecked -or $null -ne $script:ctx.StaleSet -or $null -ne $script:ctx.RiskSet)
    }
    $script:ctx.MatchNoteText = {
        $n = 0; foreach ($s in $script:ctx.StaleSet, $script:ctx.RiskSet) { if ($null -ne $s) { $n++ } }
        $script:ui.MatchNote.Text = if ($n -lt 2) { 'applies when both Stale and Risk are set' }
                                    elseif ($script:ui.MatchAny.IsChecked) { 'agents matching either Stale or Risk' } else { 'agents matching both Stale and Risk' }
    }
    $script:ctx.Refilter = { & $script:ctx.MatchNoteText; $script:ctx.View.Refresh(); & $script:ctx.Summary; $script:ui.BtnReset.IsEnabled = (& $script:ctx.FilterActive) }

    $script:ctx.Load = {
        & $script:ctx.Busy 'Loading the catalog...'
        try {
            $pkgs = @(Get-Packages)
            $script:ctx.Rows.Clear(); & $script:ctx.ResetFilters
            foreach ($p in ($pkgs | Sort-Object displayName)) {
                $r = New-Object AgentRow
                $r.Id = $p.id; $r.Name = $p.displayName; $r.Publisher = $p.publisher
                $r.Platform = if ($p.platform -and $p.platform -ne 'Not Available') { $p.platform } else { [string]$p.type }
                $r.Hosts = ($p.supportedHosts) -join ','
                $r.IsBlocked = [bool]$p.isBlocked
                $r.Modified = if ($p.lastModifiedDateTime) { ([datetimeoffset]$p.lastModifiedDateTime).ToString('yyyy-MM-dd') } else { '' }
                $r.Package = $p
                $r.IdleSort = -1; $r.RiskSort = 0; $r.AlertsSort = 0
                $r.add_PropertyChanged({ param($s, $e) if ($e.PropertyName -eq 'Checked' -or $e.PropertyName -eq 'IsBlocked') { & $script:ctx.Summary } })
                $script:ctx.Rows.Add($r)
            }
            & $script:ctx.Refilter
            & $script:ctx.Idle ("Loaded {0} packages at {1}." -f $pkgs.Count, (Get-Date).ToString('HH:mm:ss'))
        } catch { & $script:ctx.Idle ('Load failed: ' + $_.Exception.Message); [void][Windows.MessageBox]::Show($_.Exception.Message, 'Could not load the catalog', 'OK', 'Error') }
    }

    $script:ctx.ClearStale = { foreach ($r in $script:ctx.Rows) { $r.LastActivity = ''; $r.Idle = ''; $r.IdleSort = -1 }; $script:ctx.StaleSet = $null }
    $script:ctx.ClearRisk  = { foreach ($r in $script:ctx.Rows) { $r.Risk = ''; $r.RiskSort = 0; $r.Alerts = ''; $r.AlertsSort = 0; $r.Detections = ''; $r.DetectionsSort = 0; $r.Why = '' }; $script:ctx.RiskSet = $null }

    # Return every filter control to its neutral value: all agents, nothing narrowed.
    $script:ctx.ResetFilters = {
        $script:ctx.Resetting = $true
        $script:ui.Search.Text = ''; $script:ui.FltAll.IsChecked = $true; $script:ui.AgentsOnlyBox.IsChecked = $false
        $script:ui.StaleBox.SelectedIndex = 0; $script:ui.RiskBox.SelectedIndex = 0; $script:ui.SignalBox.SelectedIndex = 0; $script:ui.NeverSeenBox.IsChecked = $false; $script:ui.MatchAll.IsChecked = $true
        & $script:ctx.ClearStale; & $script:ctx.ClearRisk
        $script:ctx.Resetting = $false
    }

    # Run the stale finder for the current dropdown value (or clear it for "None").
    $script:ctx.RunStale = {
        $tag = [string]$script:ui.StaleBox.SelectedItem.Tag
        $script:ui.NeverSeenBox.IsEnabled = $tag.StartsWith('activity')
        & $script:ctx.ClearStale
        if (-not $tag) { & $script:ctx.Refilter; & $script:ctx.Idle 'Stale filter cleared.'; return }
        $by, $days = $tag -split ':'; $days = [int]$days
        & $script:ctx.Busy ("Finding agents with no {0} for {1}+ days..." -f $(if ($by -eq 'activity') { 'activity' } else { 'manifest change' }), $days)
        try {
            $never = [bool]$script:ui.NeverSeenBox.IsChecked -and $by -eq 'activity'
            $found = @(Get-StalePackages -Days $days -By $by -IncludeNeverSeen:$never)
            $set = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($m in $found) {
                [void]$set.Add($m.id)
                $row = $script:ctx.Rows | Where-Object { $_.Id -eq $m.id } | Select-Object -First 1
                if (-not $row) { continue }
                if ($m.StaleSince) {
                    $row.LastActivity = $m.StaleSince.ToString('yyyy-MM-dd')
                    $row.Idle = [string][int]([datetimeoffset]::UtcNow - $m.StaleSince).TotalDays
                    $row.IdleSort = [int]$row.Idle
                } else { $row.LastActivity = 'never seen'; $row.Idle = ''; $row.IdleSort = 99999 }
            }
            $script:ctx.StaleSet = $set
            & $script:ctx.Refilter
            & $script:ctx.Idle ("{0} agent(s) match the stale filter." -f $found.Count)
        } catch {
            $script:ui.StaleBox.SelectedIndex = 0; & $script:ctx.Refilter
            & $script:ctx.Idle 'Stale filter failed.'; [void][Windows.MessageBox]::Show($_.Exception.Message, 'Stale filter', 'OK', 'Error')
        }
    }

    # Run the risky finder for the current dropdown value (or clear it for "None").
    $script:ctx.RunRisk = {
        $sev = [string]$script:ui.RiskBox.SelectedItem.Tag
        & $script:ctx.ClearRisk
        if (-not $sev) { & $script:ctx.Refilter; & $script:ctx.Idle 'Risk filter cleared.'; return }
        & $script:ctx.Busy "Finding agents with risk signals at $sev or above..."
        try {
            $found = @(Get-RiskyPackages -Days 30 -MinAlerts 1 -MinSeverity $sev -Source ([string]$script:ui.SignalBox.SelectedItem.Tag))
            $set = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($m in $found) {
                [void]$set.Add($m.id)
                $row = $script:ctx.Rows | Where-Object { $_.Id -eq $m.id } | Select-Object -First 1
                if (-not $row) { continue }
                $row.Risk = $m.RiskSeverity; $row.RiskSort = Get-SevRank $m.RiskSeverity
                $row.Alerts = [string]$m.RiskAlerts; $row.AlertsSort = [int]$m.RiskAlerts
                $row.Detections = [string]$m.RiskDetections; $row.DetectionsSort = [int]$m.RiskDetections
                $row.Why = $m.RiskReasons
            }
            $script:ctx.RiskSet = $set
            & $script:ctx.Refilter
            & $script:ctx.Idle ("{0} agent(s) flagged by {1} at {2} or above (last 30 days)." -f $found.Count, $script:ui.SignalBox.SelectedItem.Content.ToLower(), $sev)
        } catch {
            $script:ui.RiskBox.SelectedIndex = 0; & $script:ctx.Refilter
            & $script:ctx.Idle 'Risk filter failed.'; [void][Windows.MessageBox]::Show($_.Exception.Message, 'Risk filter', 'OK', 'Error')
        }
    }
    $script:ctx.Confirm = {
        param([object[]]$Rows, [string]$Verb)
        [bool](New-ConfirmDialog -Rows $Rows -Verb $Verb -Owner $script:w).ShowDialog()
    }

    $script:ctx.Apply = {
        param([string]$Verb, [object[]]$Rows)
        if (-not (& $script:ctx.Confirm $Rows $Verb)) { return }
        $dir = Join-Path $env:LOCALAPPDATA 'Agent365-Bulk-Actions\logs'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $script:OutFile = Join-Path $dir ('run-{0:yyyyMMdd-HHmmss}.csv' -f (Get-Date))
        & $script:ctx.Busy ("{0}ing {1} agent(s)..." -f $Verb.TrimEnd('e'), $Rows.Count)
        $recs = @(Invoke-PackageAction -Packages @($Rows | ForEach-Object { $_.Package | Add-Member -NotePropertyName isBlocked -NotePropertyValue $_.IsBlocked -Force -PassThru }) -Action $Verb.ToLower() -PassThru)
        foreach ($rec in $recs) {
            if ($rec.Result -eq 'Done') {
                $row = $script:ctx.Rows | Where-Object { $_.Id -eq $rec.Id } | Select-Object -First 1
                if ($row) { $row.IsBlocked = ($Verb -eq 'Block'); $row.Package.isBlocked = $row.IsBlocked; $row.Checked = $false }
            }
        }
        $script:ctx.LastRun = $recs
        $done = @($recs | Where-Object { $_.Result -eq 'Done' }).Count; $failed = @($recs | Where-Object { $_.Result -eq 'Failed' }).Count
        & $script:ctx.Refilter
        & $script:ctx.Idle ("{0}: {1} done, {2} failed. Log: {3}" -f $Verb, $done, $failed, $script:OutFile)
        if ($failed) {
            $why = ($recs | Where-Object { $_.Result -eq 'Failed' } | Select-Object -First 5 | ForEach-Object { "$($_.DisplayName): $($_.Error)" }) -join "`n"
            [void][Windows.MessageBox]::Show("$failed agent(s) failed:`n`n$why", 'Some actions failed', 'OK', 'Warning')
        }
    }

    # ---- wiring ----

    $script:ui.BtnRefresh.Add_Click({ & $script:ctx.Load })
    $script:ui.Search.Add_TextChanged({ & $script:ctx.Refilter })
    foreach ($b in 'FltAll', 'FltActive', 'FltBlocked') { $script:ui[$b].Add_Click({ & $script:ctx.Refilter }) }
    $script:ui.AgentsOnlyBox.Add_Click({ & $script:ctx.Refilter })
    foreach ($b in 'MatchAll', 'MatchAny') { $script:ui[$b].Add_Click({ & $script:ctx.Refilter }) }
    $script:ui.StaleBox.Add_SelectionChanged({ if (-not $script:ctx.Resetting) { & $script:ctx.RunStale } })
    $script:ui.NeverSeenBox.Add_Click({ if ($script:ui.StaleBox.SelectedIndex -gt 0) { & $script:ctx.RunStale } })
    $script:ui.RiskBox.Add_SelectionChanged({ if (-not $script:ctx.Resetting) { & $script:ctx.RunRisk } })
    $script:ui.SignalBox.Add_SelectionChanged({ if (-not $script:ctx.Resetting -and $script:ui.RiskBox.SelectedIndex -gt 0) { & $script:ctx.RunRisk } })
    $script:ui.BtnReset.Add_Click({ & $script:ctx.ResetFilters; & $script:ctx.Refilter; & $script:ctx.Idle 'Filters reset. Showing all agents.' })
    $script:ui.BtnSelectVisible.Add_Click({ foreach ($r in $script:ctx.View) { $r.Checked = $true }; & $script:ctx.Summary })
    $script:ui.BtnClearSel.Add_Click({ foreach ($r in $script:ctx.Rows) { $r.Checked = $false }; & $script:ctx.Summary })
    $script:ui.HeaderCheck.Add_Click({
        $on = [bool]$script:ui.HeaderCheck.IsChecked
        foreach ($r in $script:ctx.View) { $r.Checked = $on }; & $script:ctx.Summary
    })


    $script:ui.BtnBlock.Add_Click({   & $script:ctx.Apply 'Block'   @($script:ctx.Rows | Where-Object { $_.Checked -and -not $_.IsBlocked }) })
    $script:ui.BtnUnblock.Add_Click({ & $script:ctx.Apply 'Unblock' @($script:ctx.Rows | Where-Object { $_.Checked -and $_.IsBlocked }) })

    $script:ui.BtnUndo.Add_Click({
        $done = @($script:ctx.LastRun | Where-Object { $_.Result -eq 'Done' })
        $back = @($done | ForEach-Object { $id = $_.Id; $script:ctx.Rows | Where-Object { $_.Id -eq $id } } | Where-Object { $_ })
        if ($back.Count -eq 0) { return }
        $verb = if ($done[0].Action -eq 'block') { 'Unblock' } else { 'Block' }
        & $script:ctx.Apply $verb $back
    })

    $script:ui.BtnExport.Add_Click({
        $dlg = New-Object Microsoft.Win32.SaveFileDialog
        $dlg.Filter = 'CSV (*.csv)|*.csv|JSON (*.json)|*.json'; $dlg.FileName = 'agents.csv'
        if (-not $dlg.ShowDialog()) { return }
        $out = @($script:ctx.View | Select-Object Name, Status, Platform, Publisher, Modified, LastActivity, Idle, Risk, Alerts, Detections, Why, Id)
        if ($dlg.FileName -match '\.json$') { $out | ConvertTo-Json | Set-Content -Path $dlg.FileName -Encoding utf8 }
        else { $out | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding utf8 }
        & $script:ctx.Idle "Exported $($out.Count) rows to $($dlg.FileName)"
    })

    $script:ctx.Account = { $c = Get-MgContext; $script:ui.Account.Text = if ($c) { "$($c.Account)   |   tenant $($c.TenantId)" } else { '' } }
    & $script:ctx.Account
    $script:ctx
}

function Show-Console {
    if (($null -ne $IsWindows -and -not $IsWindows) -or [Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
        throw '-Gui needs Windows and a single-threaded apartment. Start it with: pwsh -STA -File .\Agent365-Bulk-Actions.ps1 -Gui'
    }
    $script:ctx = New-ConsoleWindow
    $script:ctx.Window.Add_ContentRendered({ if (-not $script:ctx.Loaded) { $script:ctx.Loaded = $true; & $script:ctx.Load } })
    [void]$script:ctx.Window.ShowDialog()
}

switch ($PSCmdlet.ParameterSetName) {
    'Gui' { Show-Console }
    'List' {
        Get-Packages -AgentsOnly:$AgentsOnly |
            Select-Object displayName, id, isBlocked,
                          @{ n = 'hosts'; e = { ($_.supportedHosts) -join ',' } }, type |
            Sort-Object isBlocked, displayName |
            Format-Table -AutoSize
    }
    'Undo' {
        if (-not (Test-Path -LiteralPath $Undo)) { throw "Log not found: $Undo" }
        $rows = if ($Undo -match '\.json$') { @(Get-Content -Raw -LiteralPath $Undo | ConvertFrom-Json) }
                else { @(Import-Csv -LiteralPath $Undo) }
        $changed = @($rows | Where-Object { $_.Result -eq 'Done' })
        if ($changed.Count -eq 0) { Write-Host 'The log has no changes to undo.'; break }
        $catalog = @(Get-Packages)
        $restore = @{ block = @(); unblock = @() }
        foreach ($r in $changed) {
            $pkg = $catalog | Where-Object { $_.id -eq $r.Id } | Select-Object -First 1
            if (-not $pkg) { Write-Warning "Package $($r.Id) no longer exists; skipped."; continue }
            $wasBlocked = [string]$r.WasBlocked -eq 'True'
            $restore[$(if ($wasBlocked) { 'block' } else { 'unblock' })] += $pkg
        }
        Write-Host ("Undo restores {0} package(s) to their state before the logged run." -f ($restore.block.Count + $restore.unblock.Count)) -ForegroundColor Cyan
        foreach ($verb in 'block', 'unblock') {
            if ($restore[$verb].Count -eq 0) { continue }
            $restore[$verb] | Select-Object displayName, id, isBlocked | Format-Table -AutoSize | Out-Host
            if (-not (Confirm-Batch -Count $restore[$verb].Count -Action $verb)) { Write-Host 'Cancelled.'; continue }
            Invoke-PackageAction -Packages $restore[$verb] -Action $verb
        }
    }
    'FromCsv' {
        if (-not (Test-Path -LiteralPath $FromCsv)) { throw "File not found: $FromCsv" }
        $names = foreach ($row in Import-Csv -LiteralPath $FromCsv) {
            $v = foreach ($c in 'Id', 'DisplayName', 'Name', 'Package') { if ($row.$c) { $row.$c; break } }
            if ($v) { $v.Trim() }
        }
        if (-not $names) { throw "No Id or DisplayName values found in $FromCsv." }
        $targets = @(Resolve-Packages @($names))
        $pending = @($targets | Where-Object { [bool]$_.isBlocked -ne ($Action -eq 'block') })
        Write-Host ("{0} package(s) from the file{1}." -f $targets.Count,
            $(if ($Action -ne 'list') { "; $($pending.Count) need $Action" } else { '' })) -ForegroundColor Cyan
        $targets | Select-Object displayName, id, isBlocked | Format-Table -AutoSize | Out-Host
        if ($Action -eq 'list') { break }
        if (-not (Confirm-Batch -Count $pending.Count -Action $Action)) { Write-Host 'Cancelled.'; break }
        Invoke-PackageAction -Packages $targets -Action $Action
    }
    { $_ -in 'Block', 'Unblock' } {
        $verb = $_.ToLower()
        $targets = @(Resolve-Packages $(if ($verb -eq 'block') { $Block } else { $Unblock }))
        $pending = @($targets | Where-Object { [bool]$_.isBlocked -ne ($verb -eq 'block') })
        Write-Host ("{0} of {1} target(s) need {2}." -f $pending.Count, $targets.Count, $verb) -ForegroundColor Cyan
        $targets | Select-Object displayName, id, isBlocked | Format-Table -AutoSize | Out-Host
        if (-not (Confirm-Batch -Count $pending.Count -Action $verb)) { Write-Host 'Cancelled.'; break }
        Invoke-PackageAction -Packages $targets -Action $verb
    }
    'Select'  {
        $catalog = @(Get-Packages -AgentsOnly:$AgentsOnly)
        if ($catalog.Count -eq 0) { throw 'No packages returned (check the Agent 365 license / permissions).' }
        $picked = Invoke-Picker -Packages $catalog -Title "Select agents to $Action (Ctrl/Shift for multiple), then OK"
        if ($Action -eq 'list') { $picked | Format-Table displayName, id, isBlocked -AutoSize }
        else { Invoke-PackageAction -Packages $picked -Action $Action }
    }
    'Stale'   {
        $matched = @(Get-StalePackages -Days $StaleDays -By $By -AgentsOnly:$AgentsOnly -IncludeNeverSeen:$IncludeNeverSeen)
        # When blocking, drop ones already blocked; when unblocking, only the blocked ones.
        if     ($Action -eq 'block')   { $matched = @($matched | Where-Object { -not $_.isBlocked }) }
        elseif ($Action -eq 'unblock') { $matched = @($matched | Where-Object { $_.isBlocked }) }

        $basisText = if ($By -eq 'activity') {
            if ($IncludeNeverSeen) { 'no activity (incl. never-seen)' } else { 'reported but idle' }
        } else { 'not modified' }
        Write-Host ("`nAgents with {0} > {1} days: {2} match(es){3}." -f
            $basisText, $StaleDays, $matched.Count,
            $(if ($Action -ne 'list') { " needing $Action" } else { '' })) -ForegroundColor Cyan
        if ($matched.Count -eq 0) { break }
        Show-StalePreview -Packages $matched -Basis $By

        if ($Action -eq 'list') { break }        # preview only

        # -Pick lets you choose WHICH of the stale matches to act on (else act on all).
        if ($Pick) {
            $matched = @(Invoke-Picker -Packages $matched -Title "Stale agents to $Action - select which (Ctrl/Shift), then OK")
            if ($matched.Count -eq 0) { Write-Host 'Nothing selected.'; break }
        }

        if (-not (Confirm-Batch -Count $matched.Count -Action $Action -Implied:$Pick)) { Write-Host 'Cancelled.'; break }
        Invoke-PackageAction -Packages $matched -Action $Action
    }
    'Risky'   {
        $matched = @(Get-RiskyPackages -Days $RiskDays -MinAlerts $MinAlerts -MinSeverity $MinSeverity -AgentsOnly:$AgentsOnly -Source $RiskSource)
        if     ($Action -eq 'block')   { $matched = @($matched | Where-Object { -not $_.isBlocked }) }
        elseif ($Action -eq 'unblock') { $matched = @($matched | Where-Object { $_.isBlocked }) }

        Write-Host ("`nAgents with >= {0} risk signal(s) (source: {5}) at/above {1} severity in {2} days: {3} match(es){4}." -f
            $MinAlerts, $MinSeverity, $RiskDays, $matched.Count,
            $(if ($Action -ne 'list') { " needing $Action" } else { '' }), $RiskSource.ToLower()) -ForegroundColor Cyan
        if ($matched.Count -eq 0) { break }
        Show-RiskyPreview -Packages $matched

        if ($Action -eq 'list') { break }

        if ($Pick) {
            $matched = @(Invoke-Picker -Packages $matched -Title "Risky agents to $Action - select which (Ctrl/Shift), then OK")
            if ($matched.Count -eq 0) { Write-Host 'Nothing selected.'; break }
        }
        if (-not (Confirm-Batch -Count $matched.Count -Action $Action -Implied:$Pick)) { Write-Host 'Cancelled.'; break }
        Invoke-PackageAction -Packages $matched -Action $Action
    }
}

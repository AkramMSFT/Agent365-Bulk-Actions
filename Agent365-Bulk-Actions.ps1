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
  # List RISKY agents (those with Defender AI-security alerts), then block them
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
[CmdletBinding(DefaultParameterSetName = 'List')]
param(
    [Parameter(ParameterSetName = 'List')]
    [switch]$List,

    [Parameter(ParameterSetName = 'Block', Mandatory, Position = 0)]
    [string[]]$Block,                         # one or more P_ ids OR displayNames

    [Parameter(ParameterSetName = 'Unblock', Mandatory, Position = 0)]
    [string[]]$Unblock,                       # one or more P_ ids OR displayNames

    [Parameter(ParameterSetName = 'Select', Mandatory)]
    [switch]$Select,                          # interactive multi-select picker

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
    [ValidateSet('Informational', 'Low', 'Medium', 'High')]
    [string]$MinSeverity = 'Informational',    # only act on agents at/above this alert severity

    [Parameter(ParameterSetName = 'Select')]
    [Parameter(ParameterSetName = 'Stale')]
    [Parameter(ParameterSetName = 'Risky')]
    [ValidateSet('block', 'unblock', 'list')]
    [string]$Action = 'block',                # what to do with the matched set ('list' = preview only)

    [Parameter(ParameterSetName = 'List')]
    [Parameter(ParameterSetName = 'Select')]
    [Parameter(ParameterSetName = 'Stale')]
    [Parameter(ParameterSetName = 'Risky')]
    [switch]$AgentsOnly,                       # filter supportedHosts eq 'Copilot'

    [Parameter(ParameterSetName = 'Stale')]
    [Parameter(ParameterSetName = 'Risky')]
    [switch]$Force,                           # skip the "proceed?" confirmation

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
            ($PSCmdlet.ParameterSetName -in @('Select', 'Stale', 'Risky') -and $Action -eq 'list')
$scopes = @(if ($readOnly) { 'CopilotPackages.Read.All' } else { 'CopilotPackages.ReadWrite.All' })
if (($PSCmdlet.ParameterSetName -eq 'Stale' -and $By -eq 'activity') -or
    $PSCmdlet.ParameterSetName -eq 'Risky') { $scopes += 'ThreatHunting.Read.All' }
$connect = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId)   { $connect['TenantId'] = $TenantId }
if ($DeviceCode) { $connect['UseDeviceCode'] = $true }
Connect-MgGraph @connect

function Get-Packages {
    param([switch]$AgentsOnly)
    $uri = if ($AgentsOnly) {
        "$Base`?`$filter=supportedHosts/any(h:h eq 'Copilot')"
    } else { $Base }
    $all = @()
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
        # Invoke-MgGraphRequest returns each item as a Hashtable; cast to PSCustomObject so
        # Select-Object / Format-Table can resolve displayName, id, isBlocked as real properties.
        foreach ($v in $resp.value) { $all += [pscustomobject]$v }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
    $all
}

# Resolve a mix of P_ ids and display names to concrete package objects (fetches list once).
function Resolve-Packages {
    param([string[]]$Names)
    $catalog = $null
    $resolved = @()
    foreach ($n in $Names) {
        if ($n -like 'P_*') {
            $resolved += [pscustomobject]@{ id = $n; displayName = $n }
            continue
        }
        if (-not $catalog) { $catalog = Get-Packages }        # lazy: only if a name is used
        $hit = @($catalog | Where-Object { $_.displayName -eq $n })
        if ($hit.Count -eq 0) { throw "No package named '$n'. Run -List to see names/ids." }
        if ($hit.Count -gt 1) { throw "Multiple packages named '$n'. Use the exact P_ id instead." }
        $resolved += $hit[0]
    }
    $resolved
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
        $resp = Invoke-MgGraphRequest -Method POST `
            -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
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
| where ActionType in ("InvokeAgent", "InferenceCall", "ExecuteToolBySDK", "ConnectedAIAppInteraction")
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

# Query Defender Advanced Hunting for agents with AI-security alerts; return Key -> risk info.
function Get-RiskyIndex {
    param([int]$Days)
    $kql = if ($HuntingQuery) { $HuntingQuery } else { $InventoryKql + @"
let win = ${Days}d;
AlertInfo
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
| extend Key = coalesce(CatalogId, AgentKey)
| extend sev = case(Severity == "High", 4, Severity == "Medium", 3, Severity == "Low", 2, Severity == "Informational", 1, 0)
| summarize AlertCount = dcount(AlertId), SevRank = max(sev), LastAlert = max(Timestamp),
            Reasons = make_set(Title, 8), Categories = make_set(Category, 6) by Key
| extend Severity = case(SevRank == 4, "High", SevRank == 3, "Medium", SevRank == 2, "Low", SevRank == 1, "Informational", "-")
"@ }
    $rows = Invoke-HuntingQuery -Query $kql -Hint "Check ThreatHunting.Read.All consent, an E5/Defender license, and that 'Security for AI' is onboarded."
    # make_set columns come back as arrays (or a JSON string); normalize to a "; "-joined string.
    $joinSet = {
        param($v)
        if ($v -is [string]) { try { $v = $v | ConvertFrom-Json } catch {} }
        (@($v) | ForEach-Object { [string]$_ } | Where-Object { $_ }) -join '; '
    }
    $idx = @{}
    foreach ($row in $rows) {
        $k = [string]$row.Key
        if ([string]::IsNullOrWhiteSpace($k)) { continue }
        $idx[$k.ToLower()] = [pscustomobject]@{
            AlertCount = [int]$row.AlertCount
            Severity   = [string]$row.Severity
            LastAlert  = if ($row.LastAlert) { [datetimeoffset]$row.LastAlert } else { $null }
            Reasons    = (& $joinSet $row.Reasons)
            Categories = (& $joinSet $row.Categories)
        }
    }
    $idx
}

# Rank a severity string so we can filter/sort (higher = worse).
function Get-SevRank { param([string]$S)
    switch ($S) { 'High' { 4 } 'Medium' { 3 } 'Low' { 2 } 'Informational' { 1 } default { 0 } } }

# Return agent packages with >= MinAlerts alerts at/above MinSeverity, annotated with risk info.
function Get-RiskyPackages {
    param([int]$Days, [int]$MinAlerts, [string]$MinSeverity, [switch]$AgentsOnly)
    $idx = Get-RiskyIndex -Days $Days
    $minRank = Get-SevRank $MinSeverity
    $out = foreach ($p in (Get-Packages -AgentsOnly:$AgentsOnly)) {
        $hit = $null
        foreach ($k in (Get-PackageKeys $p)) { if ($idx.ContainsKey($k)) { $hit = $idx[$k]; break } }
        if ($hit -and $hit.AlertCount -ge $MinAlerts -and (Get-SevRank $hit.Severity) -ge $minRank) {
            $p | Add-Member -NotePropertyName RiskAlerts     -NotePropertyValue $hit.AlertCount -Force
            $p | Add-Member -NotePropertyName RiskSeverity   -NotePropertyValue $hit.Severity   -Force
            $p | Add-Member -NotePropertyName RiskReasons    -NotePropertyValue $hit.Reasons    -Force
            $p | Add-Member -NotePropertyName RiskCategories -NotePropertyValue $hit.Categories -Force
            $p | Add-Member -NotePropertyName RiskLastAlert  -NotePropertyValue $hit.LastAlert  -Force -PassThru
        }
    }
    # worst first: by severity, then alert count
    @($out | Sort-Object -Property @{ e = { Get-SevRank $_.RiskSeverity } ; Descending = $true },
                                   @{ e = { $_.RiskAlerts } ; Descending = $true })
}

# Preview table for a risky set (severity, alert count, and WHY / reasons).
function Show-RiskyPreview {
    param([object[]]$Packages)
    $Packages | Select-Object `
        @{ n = 'severity';  e = { $_.RiskSeverity } },
        @{ n = 'alerts';    e = { $_.RiskAlerts } },
        displayName,
        @{ n = 'why (alert titles)'; e = { $_.RiskReasons } },
        @{ n = 'categories'; e = { $_.RiskCategories } },
        @{ n = 'lastAlert'; e = { if ($_.RiskLastAlert) { $_.RiskLastAlert.ToString('yyyy-MM-dd') } else { '-' } } },
        isBlocked, id |
        Format-Table -AutoSize -Wrap | Out-Host
}

# Apply block/unblock to each package; keep going on error, then summarize.
function Invoke-PackageAction {
    param([object[]]$Packages, [ValidateSet('block', 'unblock')][string]$Action)
    if (-not $Packages -or $Packages.Count -eq 0) { Write-Host 'Nothing selected.'; return }

    $verb = $Action.Substring(0,1).ToUpper() + $Action.Substring(1)
    Write-Host ("`n{0} {1} package(s):" -f $verb, $Packages.Count) -ForegroundColor Cyan
    $ok = 0; $fail = 0
    foreach ($p in $Packages) {
        try {
            Invoke-MgGraphRequest -Method POST -Uri "$Base/$($p.id)/$Action" | Out-Null   # 204
            Write-Host ("  OK   {0}  ({1})" -f $p.displayName, $p.id) -ForegroundColor Green
            $ok++
        } catch {
            Write-Host ("  FAIL {0}  ({1}) -> {2}" -f $p.displayName, $p.id, $_.Exception.Message) -ForegroundColor Red
            $fail++
        }
    }
    Write-Host ("Done: {0} {1}ed, {2} failed." -f $ok, $Action, $fail) -ForegroundColor Cyan
}

switch ($PSCmdlet.ParameterSetName) {
    'List' {
        Get-Packages -AgentsOnly:$AgentsOnly |
            Select-Object displayName, id, isBlocked,
                          @{ n = 'hosts'; e = { ($_.supportedHosts) -join ',' } }, type |
            Sort-Object isBlocked, displayName |
            Format-Table -AutoSize
    }
    'Block'   { Invoke-PackageAction -Packages (Resolve-Packages $Block)   -Action 'block' }
    'Unblock' { Invoke-PackageAction -Packages (Resolve-Packages $Unblock) -Action 'unblock' }
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

        if (-not $Force -and -not $Pick) {
            $ans = Read-Host ("Proceed to {0} these {1} agent(s)? [y/N]" -f $Action, $matched.Count)
            if ($ans -notmatch '^(y|yes)$') { Write-Host 'Cancelled.'; break }
        }
        Invoke-PackageAction -Packages $matched -Action $Action
    }
    'Risky'   {
        $matched = @(Get-RiskyPackages -Days $RiskDays -MinAlerts $MinAlerts -MinSeverity $MinSeverity -AgentsOnly:$AgentsOnly)
        if     ($Action -eq 'block')   { $matched = @($matched | Where-Object { -not $_.isBlocked }) }
        elseif ($Action -eq 'unblock') { $matched = @($matched | Where-Object { $_.isBlocked }) }

        Write-Host ("`nAgents with >= {0} AI-security alert(s) at/above {1} severity in {2} days: {3} match(es){4}." -f
            $MinAlerts, $MinSeverity, $RiskDays, $matched.Count,
            $(if ($Action -ne 'list') { " needing $Action" } else { '' })) -ForegroundColor Cyan
        if ($matched.Count -eq 0) { break }
        Show-RiskyPreview -Packages $matched

        if ($Action -eq 'list') { break }

        if ($Pick) {
            $matched = @(Invoke-Picker -Packages $matched -Title "Risky agents to $Action - select which (Ctrl/Shift), then OK")
            if ($matched.Count -eq 0) { Write-Host 'Nothing selected.'; break }
        }
        if (-not $Force -and -not $Pick) {
            $ans = Read-Host ("Proceed to {0} these {1} agent(s)? [y/N]" -f $Action, $matched.Count)
            if ($ans -notmatch '^(y|yes)$') { Write-Host 'Cancelled.'; break }
        }
        Invoke-PackageAction -Packages $matched -Action $Action
    }
}

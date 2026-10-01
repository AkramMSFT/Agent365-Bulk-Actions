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

    [Parameter(ParameterSetName = 'Ownerless', Mandatory)]
    [switch]$Ownerless,                      # find shared agents whose owner is missing or gone and propose a replacement

    [Parameter(ParameterSetName = 'Reassign', Mandatory)]
    [string[]]$Reassign,                     # manual assignment: agents (names or ids) to give to -To

    [Parameter(ParameterSetName = 'Reassign', Mandatory)]
    [string]$To,                             # UPN or object id of the new owner

    [Parameter(ParameterSetName = 'Detail', Mandatory)]
    [string]$Detail,                         # full picture of one agent (name or id): sharing, tools, MCP, permissions, identity, usage

    [Parameter(ParameterSetName = 'Inventory', Mandatory)]
    [switch]$Inventory,                      # one row per agent with kind, owner, tools, MCP servers, sharing (use -OutFile for csv/json)

    [Parameter(ParameterSetName = 'Inventory')]
    [switch]$Deep,                           # inventory: also read usage and availability per agent (one call each)

    [Parameter(ParameterSetName = 'Inventory')]
    [switch]$WithPermissions,                # inventory: also list each agent identity's Entra permissions

    [Parameter(ParameterSetName = 'Policy', Mandatory)]
    [string]$Policy,                         # path to a JSON policy file; prints the plan (no changes without -Apply)

    [Parameter(ParameterSetName = 'Policy')]
    [switch]$Apply,                          # run the policy plan

    [Parameter(ParameterSetName = 'Snapshot', Mandatory)]
    [string]$Snapshot,                       # save the inventory to this JSON file

    [Parameter(ParameterSetName = 'Snapshot')]
    [string]$CompareTo,                      # earlier snapshot to compare with (new, removed, blocked, owner, version changes)

    [Parameter(ParameterSetName = 'DeleteCandidates', Mandatory)]
    [switch]$DeleteCandidates,               # list blocked agents that have stayed blocked long enough to delete

    [Parameter(ParameterSetName = 'DeleteCandidates')]
    [ValidateRange(0, 3650)]
    [int]$MinDaysBlocked = 30,                # delete-candidate threshold

    [Parameter(ParameterSetName = 'DeleteCandidates')]
    [string[]]$History,                       # extra -OutFile logs or folders that record when agents were blocked

    [Parameter(ParameterSetName = 'DeleteCandidates')]
    [switch]$IncludeUnknown,                  # also list blocked agents whose block date cannot be determined

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
    [Parameter(ParameterSetName = 'Ownerless')]
    [ValidateSet('block', 'unblock', 'list', 'reassign')]
    [string]$Action = 'block',                # what to do with the matched set ('list' = preview only)

    [Parameter(ParameterSetName = 'List')]
    [Parameter(ParameterSetName = 'Select')]
    [Parameter(ParameterSetName = 'Stale')]
    [Parameter(ParameterSetName = 'Risky')]
    [Parameter(ParameterSetName = 'Inventory')]
    [switch]$AgentsOnly,                       # filter supportedHosts eq 'Copilot'

    [switch]$Force,                           # skip the "proceed?" confirmation for any write

    [switch]$DisableIdentity,                 # make sure the agent's Entra identity ends up disabled on block (enabled on unblock): verified, forced only if the platform did not

    [switch]$Impact,                          # show active users, sessions and last use for each target before acting

    [string]$OutFile,                         # write a per-agent result log (.csv or .json)

    [Parameter(ParameterSetName = 'Stale')]
    [Parameter(ParameterSetName = 'Risky')]
    [switch]$Pick,                            # choose WHICH stale/risky agents to act on via the picker

    [string]$TenantId,                        # optional: target a specific tenant (default = home tenant)

    [switch]$DeviceCode
)

$ErrorActionPreference = 'Stop'
# Dot-sourcing (. .\Agent365-Bulk-Actions.ps1) loads the functions only: no sign-in, no action. Used by the tests.
$script:LoadOnly = ($MyInvocation.InvocationName -eq '.')
if ($PSCmdlet.ParameterSetName -eq 'Ownerless' -and -not $PSBoundParameters.ContainsKey('Action')) { $Action = 'list' }
if ($Action -eq 'reassign' -and $PSCmdlet.ParameterSetName -ne 'Ownerless') { throw '-Action reassign is only valid with -Ownerless. Use -Reassign <agents> -To <user> for manual assignment.' }
$Base = 'https://graph.microsoft.com/beta/copilot/admin/catalog/packages'

# Advanced Hunting keeps ~30 days, so an agent last seen before the cutoff can only be found when
# the cutoff is inside that window. At 30+ days only "no activity at all in the window" is provable.
if ($PSCmdlet.ParameterSetName -eq 'Stale' -and $By -eq 'activity' -and $StaleDays -ge 30 -and
    -not $IncludeNeverSeen -and -not $HuntingQuery) {
    throw (("-StaleDays {0} with -By activity cannot find agents that reported before: telemetry is retained ~30 days. " -f $StaleDays) +
           'Use a value below 30, add -IncludeNeverSeen to flag agents with no activity in the last 30 days, or use -By modified.')
}

# --- ensure the Graph auth module (no full SDK needed) ---
if (-not $script:LoadOnly -and -not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host 'Installing Microsoft.Graph.Authentication (CurrentUser)...' -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
}
if (-not $script:LoadOnly) { Import-Module Microsoft.Graph.Authentication -ErrorAction Stop }

# --- sign in (delegated). Read-only paths need .Read.All; writes need .ReadWrite.All;
#     activity-based staleness also needs ThreatHunting.Read.All for Advanced Hunting ---
$readOnly = ($PSCmdlet.ParameterSetName -in @('List', 'Snapshot', 'Detail', 'Inventory')) -or
            ($PSCmdlet.ParameterSetName -eq 'Policy' -and -not $Apply) -or
            ($PSCmdlet.ParameterSetName -in @('Select', 'Stale', 'Risky', 'FromCsv', 'Ownerless') -and $Action -eq 'list')
$scopes = @(if ($readOnly) { 'CopilotPackages.Read.All' } else { 'CopilotPackages.ReadWrite.All' })
if (($PSCmdlet.ParameterSetName -eq 'Stale' -and $By -eq 'activity') -or
    $PSCmdlet.ParameterSetName -in @('Risky', 'Gui')) { $scopes += 'ThreatHunting.Read.All' }
if ($PSCmdlet.ParameterSetName -in @('Ownerless', 'Reassign', 'Gui')) { $scopes += 'User.Read.All', 'AgentIdentity.Read.All' }
if ($DisableIdentity -or $PSCmdlet.ParameterSetName -eq 'Gui') { $scopes += 'AgentIdentity.Read.All', 'AgentIdentity.EnableDisable.All' }
if ($PSCmdlet.ParameterSetName -in @('DeleteCandidates', 'Policy', 'Detail', 'Inventory')) { $scopes += 'ThreatHunting.Read.All' }
if ($PSCmdlet.ParameterSetName -in @('Detail', 'Inventory')) { $scopes += 'User.Read.All', 'AgentIdentity.Read.All', 'Application.Read.All', 'DelegatedPermissionGrant.Read.All' }
if ($PSCmdlet.ParameterSetName -eq 'Policy') { $scopes += 'User.Read.All', 'AgentIdentity.Read.All'; if ($Apply) { $scopes += 'AgentIdentity.EnableDisable.All' } }
$connect = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId)   { $connect['TenantId'] = $TenantId }
if ($DeviceCode) { $connect['UseDeviceCode'] = $true }
if (-not $script:LoadOnly) { Connect-MgGraph @connect }

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
            # The package service throttles with 424 "Too Many Requests" instead of 429.
            if ($code -notin 424, 429, 502, 503, 504 -or $attempt -ge 5) { throw }
            $wait = if ($code -eq 424) { [Math]::Max(10, 5 * $attempt) } else { [Math]::Pow(2, $attempt) }
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
    $all = New-Object 'System.Collections.Generic.List[object]'
    $pages = 0
    do {
        $resp = Invoke-Graph -Uri $uri
        $pages++
        # Invoke-MgGraphRequest returns each item as a Hashtable; cast to PSCustomObject so
        # Select-Object / Format-Table can resolve displayName, id, isBlocked as real properties.
        foreach ($v in $resp.value) { $all.Add([pscustomobject]$v) }
        $uri = $resp.'@odata.nextLink'
        if ($uri -and $pages % 5 -eq 0) { Write-Progress -Activity 'Reading the agent catalog' -Status ("{0} packages so far" -f $all.Count) }
    } while ($uri)
    if ($pages -ge 5) { Write-Progress -Activity 'Reading the agent catalog' -Completed }
    # The service does not apply the supportedHosts filter, so enforce it here.
    if ($AgentsOnly) { return @($all | Where-Object { @($_.supportedHosts) -contains 'Copilot' }) }
    $all.ToArray()
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

# ---------------------------------------------------------------------------------------------
# Ownership: find agents whose owner is missing or gone, propose a replacement, reassign.
# ---------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------
# Scale: Graph JSON batching. Per-agent lookups are sent 20 at a time instead of one call each.
# ---------------------------------------------------------------------------------------------
$script:GuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

# Send requests through $batch in groups of 20. Throttled or transiently failed sub-requests are retried with
# back-off. Returns a hashtable: request id -> { Status, Body }. Requests are { id; method; url [; body; headers] }.
function Invoke-GraphBatch {
    param([object[]]$Requests, [ValidateSet('v1.0', 'beta')][string]$Version = 'v1.0', [string]$Activity,
          [ValidateRange(1, 20)][int]$ChunkSize = 20, [double]$PaceSeconds = 0)
    $results = @{}
    $pending = @($Requests)
    $total = $pending.Count
    $pace = $PaceSeconds
    for ($attempt = 1; $pending.Count -gt 0 -and $attempt -le 5; $attempt++) {
        $retry = @(); $wait = 0
        for ($i = 0; $i -lt $pending.Count; $i += $ChunkSize) {
            $chunk = @($pending[$i..([Math]::Min($i + $ChunkSize - 1, $pending.Count - 1))])
            $started = Get-Date
            $chunkThrottled = $false
            if ($Activity -and $total -gt 40) {
                Write-Progress -Activity $Activity -Status ("{0} of {1}" -f [Math]::Min($results.Count + $i, $total), $total) -PercentComplete ([Math]::Min(100, 100 * ($results.Count + $i) / [Math]::Max(1, $total)))
            }
            $resp = Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/$Version/`$batch" -ContentType 'application/json' `
                -Body (@{ requests = $chunk } | ConvertTo-Json -Depth 8 -Compress)
            foreach ($r in @($resp.responses)) {
                $status = [int]$r.status
                # The package service throttles with 424 "Too Many Requests" rather than 429.
                $throttled = $status -in 429, 502, 503, 504 -or ($status -eq 424 -and (($r.body | ConvertTo-Json -Compress -Depth 5) -match 'Too Many Requests'))
                if ($throttled -and $attempt -lt 5) {
                    $retry += @($chunk | Where-Object { [string]$_.id -eq [string]$r.id } | Select-Object -First 1)
                    $ra = 0
                    if ($r.headers) { [void][int]::TryParse([string]$r.headers.'Retry-After', [ref]$ra) }
                    $backoff = if ($status -eq 424) { 5 * $attempt + 5 } else { [Math]::Pow(2, $attempt) }
                    $wait = [Math]::Max($wait, [Math]::Max($ra, $backoff))
                    $chunkThrottled = $true
                } else {
                    $results[[string]$r.id] = [pscustomobject]@{ Status = $status; Body = $r.body }
                }
            }
            # Slow down once per throttled chunk (not once per failed request), never beyond two seconds per request.
            if ($chunkThrottled) { $pace = [Math]::Min([Math]::Max($pace * 1.5, 0.3), 2) }
            elseif ($pace -gt $PaceSeconds) { $pace = [Math]::Max($PaceSeconds, $pace * 0.9) }   # ease back once clean
            if ($pace -gt 0) {
                $target = $pace * $chunk.Count
                $spent = ((Get-Date) - $started).TotalSeconds
                if ($spent -lt $target) { Start-Sleep -Milliseconds ([int](($target - $spent) * 1000)) }
            }
        }
        $pending = @($retry)
        if ($pending.Count -gt 0) { Write-Warning ("{0} request(s) throttled; retrying in {1:N0}s." -f $pending.Count, $wait); Start-Sleep -Seconds $wait }
    }
    foreach ($p in $pending) { if (-not $results.ContainsKey([string]$p.id)) { $results[[string]$p.id] = [pscustomobject]@{ Status = 429; Body = $null } } }
    if ($Activity -and $total -gt 40) { Write-Progress -Activity $Activity -Completed }
    $results
}

# Look up many users in a few calls and cache them (404 is cached as "does not exist"; other errors are not cached).
function Initialize-UserCache {
    param([string[]]$Ids)
    $need = @($Ids | Where-Object { $_ -match $script:GuidPattern -and $_ -ne '00000000-0000-0000-0000-000000000000' } |
              ForEach-Object { $_.ToLower() } | Select-Object -Unique | Where-Object { -not $script:UserCache.ContainsKey($_) })
    if ($need.Count -eq 0) { return }
    $reqs = @($need | ForEach-Object { @{ id = $_; method = 'GET'; url = "/users/$_`?`$select=id,displayName,userPrincipalName,accountEnabled" } })
    $res = Invoke-GraphBatch -Requests $reqs -Activity 'Resolving users'
    foreach ($id in $need) {
        $r = $res[$id]
        if ($r -and $r.Status -eq 200 -and $r.Body.id) {
            $script:UserCache[$id] = [pscustomobject]@{ Id = $r.Body.id; Upn = $r.Body.userPrincipalName; Name = $r.Body.displayName; Exists = $true; Enabled = [bool]$r.Body.accountEnabled }
        } elseif ($r -and $r.Status -eq 404) {
            $script:UserCache[$id] = [pscustomobject]@{ Id = $id; Upn = ''; Name = ''; Exists = $false; Enabled = $false }
        }
    }
}

# Owners of many agent identities in a few calls; their user records are cached too.
$script:IdentityOwnerCache = @{}
function Initialize-IdentityOwnerCache {
    param([string[]]$AgentIdentityIds)
    $need = @($AgentIdentityIds | Where-Object { $_ } | Select-Object -Unique | Where-Object { -not $script:IdentityOwnerCache.ContainsKey($_) })
    if ($need.Count -eq 0) { return }
    $reqs = @($need | ForEach-Object { @{ id = $_; method = 'GET'; url = "/servicePrincipals/$_/microsoft.graph.agentIdentity/owners?`$select=id" } })
    $res = Invoke-GraphBatch -Requests $reqs -Version beta -Activity 'Reading agent identity owners'
    foreach ($id in $need) {
        $r = $res[$id]
        if ($r -and $r.Status -eq 200) { $script:IdentityOwnerCache[$id] = @(@($r.Body.value) | Where-Object { $_.'@odata.type' -match 'user$' } | ForEach-Object { [string]$_.id }) }
        elseif ($r -and $r.Status -in 403, 404) { $script:IdentityOwnerCache[$id] = @() }
    }
    Initialize-UserCache -Ids @($need | ForEach-Object { $script:IdentityOwnerCache[$_] } | ForEach-Object { $_ })
}

# Managers of many users in a few calls (404 = no manager).
$script:ManagerCache = @{}
function Initialize-ManagerCache {
    param([string[]]$UserIds)
    $need = @($UserIds | Where-Object { $_ -match $script:GuidPattern } | ForEach-Object { $_.ToLower() } | Select-Object -Unique | Where-Object { -not $script:ManagerCache.ContainsKey($_) })
    if ($need.Count -eq 0) { return }
    $reqs = @($need | ForEach-Object { @{ id = $_; method = 'GET'; url = "/users/$_/manager?`$select=id" } })
    $res = Invoke-GraphBatch -Requests $reqs -Activity 'Reading managers'
    foreach ($id in $need) {
        $r = $res[$id]
        if ($r -and $r.Status -eq 200 -and $r.Body.id) { $script:ManagerCache[$id] = [string]$r.Body.id } elseif ($r -and $r.Status -eq 404) { $script:ManagerCache[$id] = '' }
    }
    Initialize-UserCache -Ids @($need | ForEach-Object { $script:ManagerCache[$_] } | Where-Object { $_ })
}

$script:UserCache = @{}

# Look up a user by object id or UPN. Returns an object with Exists/Enabled, cached per run.
function Get-UserInfo {
    param([string]$IdOrUpn)
    if ([string]::IsNullOrWhiteSpace($IdOrUpn) -or $IdOrUpn -eq '00000000-0000-0000-0000-000000000000') {
        return [pscustomobject]@{ Id = $IdOrUpn; Upn = ''; Name = ''; Exists = $false; Enabled = $false }
    }
    $key = $IdOrUpn.ToLower()
    if ($script:UserCache.ContainsKey($key)) { return $script:UserCache[$key] }
    try {
        $u = Invoke-Graph -Uri ("https://graph.microsoft.com/v1.0/users/{0}?`$select=id,displayName,userPrincipalName,accountEnabled" -f [uri]::EscapeDataString($IdOrUpn))
        $info = [pscustomobject]@{ Id = $u.id; Upn = $u.userPrincipalName; Name = $u.displayName; Exists = $true; Enabled = [bool]$u.accountEnabled }
    } catch {
        $info = [pscustomobject]@{ Id = $IdOrUpn; Upn = ''; Name = ''; Exists = $false; Enabled = $false }
    }
    $script:UserCache[$key] = $info
    if ($info.Exists) { $script:UserCache[$info.Id.ToLower()] = $info }
    $info
}

# The manager of a user, as a user object, or $null when none is set.
function Get-ManagerInfo {
    param([string]$UserId)
    $key = "$UserId".ToLower()
    if ($script:ManagerCache.ContainsKey($key)) { if ($script:ManagerCache[$key]) { return Get-UserInfo $script:ManagerCache[$key] } else { return $null } }
    try {
        $m = Invoke-Graph -Uri ("https://graph.microsoft.com/v1.0/users/{0}/manager?`$select=id" -f $UserId)
        if ($m.id) { return Get-UserInfo $m.id }
    } catch { $null = $_ }
    $null
}

# People registered as owners of the agent's Entra identity, the nearest thing to a creator.
function Get-IdentityOwners {
    param([string]$AgentIdentityId)
    if (-not $AgentIdentityId) { return @() }
    if ($script:IdentityOwnerCache.ContainsKey($AgentIdentityId)) { return @($script:IdentityOwnerCache[$AgentIdentityId] | ForEach-Object { Get-UserInfo $_ }) }
    try {
        $r = Invoke-Graph -Uri ("https://graph.microsoft.com/beta/servicePrincipals/{0}/microsoft.graph.agentIdentity/owners?`$select=id" -f $AgentIdentityId)
        @($r.value | Where-Object { $_.'@odata.type' -match 'user$' } | ForEach-Object { Get-UserInfo $_.id })
    } catch { @() }
}

# The reassign API only works for shared agents. Anything else (store apps, org-published packages)
# makes it answer 500, so those are never sent.
function Test-Reassignable {
    param([object]$Package)
    $Package.type -eq 'shared'
}

# Decide what to do about one shared agent's ownership. Order of preference:
#   1. keep a valid current owner, 2. the Entra agent identity owner, 3. that person's manager
#   (or the former owner's), 4. nobody: flag for a manual decision. Never guesses.
function Resolve-AgentOwner {
    param([object]$Package)
    $current = Get-UserInfo $Package.ownerId
    $result = [ordered]@{
        Id = $Package.id; DisplayName = $Package.displayName; Platform = $Package.platform
        CurrentOwnerId = $Package.ownerId; CurrentOwner = ''; State = ''; ProposedId = ''; Proposed = ''; Source = ''; Reason = ''
    }
    if ($current.Exists) { $result.CurrentOwner = $current.Upn }
    if ($current.Exists -and $current.Enabled) { $result.State = 'OK'; return [pscustomobject]$result }

    $result.Reason = if (-not $Package.ownerId -or $Package.ownerId -eq '00000000-0000-0000-0000-000000000000') { 'no owner' }
                     elseif (-not $current.Exists) { 'owner account no longer exists' } else { 'owner account is disabled' }

    $identityOwners = @(Get-IdentityOwners $Package.agentIdentityId)
    $pick = $identityOwners | Where-Object { $_.Enabled } | Select-Object -First 1
    if ($pick) {
        $result.State = 'Proposed'; $result.ProposedId = $pick.Id; $result.Proposed = $pick.Upn; $result.Source = 'Agent identity owner'
        return [pscustomobject]$result
    }
    # Manager chain: the identity owner if there is one, else the former owner (only possible while the account exists).
    foreach ($who in @($identityOwners | Select-Object -First 1) + @($current | Where-Object { $_.Exists })) {
        $mgr = Get-ManagerInfo $who.Id
        if ($mgr -and $mgr.Enabled) {
            $result.State = 'Proposed'; $result.ProposedId = $mgr.Id; $result.Proposed = $mgr.Upn; $result.Source = "Manager of $($who.Upn)"
            return [pscustomobject]$result
        }
    }
    $result.State = 'Needs review'
    [pscustomobject]$result
}

# Scan the catalog. Only shared agents are reassignable through the API; org-published (lob) agents are counted, not acted on.
function Get-OwnerReport {
    param([object[]]$Packages)
    $shared = @($Packages | Where-Object { $_.type -eq 'shared' })
    Initialize-UserCache -Ids @($shared | ForEach-Object { $_.ownerId })
    $needsOwner = @($shared | Where-Object { $u = Get-UserInfo $_.ownerId; -not ($u.Exists -and $u.Enabled) })
    Initialize-IdentityOwnerCache -AgentIdentityIds @($needsOwner | ForEach-Object { $_.agentIdentityId })
    $managerFor = @($needsOwner | ForEach-Object {
        $io = @(Get-IdentityOwners $_.agentIdentityId | Select-Object -First 1)
        if ($io.Count -and -not ($io[0].Enabled)) { $io[0].Id } elseif (-not $io.Count) { $_.ownerId }
    })
    Initialize-ManagerCache -UserIds @($managerFor | Where-Object { $_ })
    $report = foreach ($p in $shared) { Resolve-AgentOwner $p }
    [pscustomobject]@{
        Items         = @($report | Where-Object { $_.State -ne 'OK' })
        OkCount       = @($report | Where-Object { $_.State -eq 'OK' }).Count
        OrgPublished  = @($Packages | Where-Object { $_.type -eq 'lob' -and -not $_.ownerId }).Count
    }
}

function Show-OwnerPreview {
    param([object[]]$Items)
    $Items | Select-Object @{ n = 'agent'; e = { $_.DisplayName } }, @{ n = 'platform'; e = { $_.Platform } },
        @{ n = 'why'; e = { $_.Reason } }, @{ n = 'currentOwner'; e = { $_.CurrentOwner } },
        @{ n = 'status'; e = { $_.State } }, @{ n = 'proposedOwner'; e = { $_.Proposed } }, @{ n = 'basis'; e = { $_.Source } }, Id |
        Format-Table -AutoSize -Wrap | Out-Host
}

# Reassign each item to its NewOwnerId; honours -WhatIf, keeps going on error, and logs the previous owner so it can be undone.
function Invoke-OwnerReassign {
    param([object[]]$Items, [switch]$PassThru)
    if (-not $Items -or $Items.Count -eq 0) { Write-Host 'Nothing to reassign.'; return }
    $who = (Get-MgContext).Account
    Write-Host ("`nReassign {0} agent(s):" -f $Items.Count) -ForegroundColor Cyan
    $log = @(); $ok = 0; $fail = 0
    foreach ($i in $Items) {
        $rec = [ordered]@{
            Timestamp = (Get-Date).ToUniversalTime().ToString('o'); Operator = $who; Action = 'reassign'
            Id = $i.Id; DisplayName = $i.DisplayName; WasOwner = $i.CurrentOwnerId; NewOwner = $i.NewOwnerId; Basis = $i.Source; Result = ''; Error = ''
        }
        if (-not (Test-Proceed ("{0} -> {1}" -f $i.DisplayName, $i.NewOwnerUpn) 'Reassign')) { $rec.Result = 'WhatIf' }
        else {
            try {
                Invoke-Graph -Method POST -Uri "$Base/$($i.Id)/reassign" -Body (@{ userId = $i.NewOwnerId } | ConvertTo-Json) -ContentType 'application/json' | Out-Null
                Write-Host ("  OK   {0}  ->  {1}" -f $i.DisplayName, $i.NewOwnerUpn) -ForegroundColor Green
                $rec.Result = 'Done'; $ok++
            } catch {
                Write-Host ("  FAIL {0}  -> {1}" -f $i.DisplayName, $_.Exception.Message) -ForegroundColor Red
                $rec.Result = 'Failed'; $rec.Error = $_.Exception.Message; $fail++
            }
        }
        $log += [pscustomobject]$rec
    }
    Write-Host ("Done: {0} reassigned, {1} failed." -f $ok, $fail) -ForegroundColor Cyan
    Export-ActionLog -Records $log
    if ($PassThru) { $log }
}

# ---------------------------------------------------------------------------------------------
# Policy file: declare rules once, review the plan, apply it. Conditions inside a rule combine
# with AND (or OR when "match": "any"). Without -Apply nothing is changed.
# ---------------------------------------------------------------------------------------------

# Drop catalog packages the policy excludes (by id, name, publisher or type).
function Test-PolicyExcluded {
    param([object]$Package, [object]$Exclude)
    if (-not $Exclude) { return $false }
    if (@($Exclude.ids) -contains $Package.id) { return $true }
    if (@($Exclude.names) -contains $Package.displayName) { return $true }
    if ($Package.publisher -and @($Exclude.publishers) -contains $Package.publisher) { return $true }
    if (@($Exclude.types) -contains $Package.type) { return $true }
    $false
}

# Evaluate every rule against the live tenant and return the plan (no changes made).
function Get-PolicyPlan {
    param([object]$PolicyDoc)
    $catalog = @(Get-Packages)
    $byId = @{}; foreach ($p in $catalog) { $byId[$p.id] = $p }
    $ownerReport = $null
    foreach ($rule in @($PolicyDoc.rules)) {
        if (-not $rule.when) { throw "Rule '$($rule.name)' has no conditions; a rule without 'when' would match everything." }
        $sets = @(); $proposals = @{}
        $w = $rule.when
        if ($w.stale) {
            $by = if ($w.stale.by) { [string]$w.stale.by } else { 'activity' }
            if ($by -eq 'activity' -and [int]$w.stale.days -ge 30 -and -not $w.stale.includeNeverSeen) {
                throw "Rule '$($rule.name)': activity staleness of 30+ days needs includeNeverSeen (telemetry is kept ~30 days)."
            }
            $sets += , @(Get-StalePackages -Days ([int]$w.stale.days) -By $by -IncludeNeverSeen:([bool]$w.stale.includeNeverSeen) | ForEach-Object { $_.id })
        }
        if ($w.risky) {
            $sev = if ($w.risky.minSeverity) { [string]$w.risky.minSeverity } else { 'Informational' }
            $src = if ($w.risky.source) { [string]$w.risky.source } else { 'Both' }
            $sets += , @(Get-RiskyPackages -Days 30 -MinAlerts ([Math]::Max(1, [int]$w.risky.minSignals)) -MinSeverity $sev -Source $src | ForEach-Object { $_.id })
        }
        if ($null -ne $w.blockedDays) {
            $sets += , @(Get-DeleteCandidates -MinDays ([int]$w.blockedDays) | ForEach-Object { $_.Id })
        }
        if ($w.ownerless) {
            if (-not $ownerReport) { $ownerReport = Get-OwnerReport -Packages $catalog }
            foreach ($i in $ownerReport.Items) { $proposals[$i.Id] = $i }
            $sets += , @($ownerReport.Items | ForEach-Object { $_.Id })
        }
        if ($w.state) {
            $wantBlocked = ([string]$w.state -eq 'blocked')
            $sets += , @($catalog | Where-Object { [bool]$_.isBlocked -eq $wantBlocked } | ForEach-Object { $_.id })
        }
        if ($sets.Count -eq 0) { throw "Rule '$($rule.name)' uses no recognised condition (stale, risky, blockedDays, ownerless, state)." }

        $ids = New-Object 'System.Collections.Generic.HashSet[string]'
        if ($rule.match -eq 'any') { foreach ($s in $sets) { foreach ($i in $s) { [void]$ids.Add([string]$i) } } }
        else {
            foreach ($i in $sets[0]) { [void]$ids.Add([string]$i) }
            for ($k = 1; $k -lt $sets.Count; $k++) {
                $other = New-Object 'System.Collections.Generic.HashSet[string]'
                foreach ($i in $sets[$k]) { [void]$other.Add([string]$i) }
                $ids.IntersectWith($other)
            }
        }
        $action = if ($rule.then.action) { ([string]$rule.then.action).ToLower() } else { 'report' }
        if ($action -notin 'block', 'unblock', 'reassign', 'report') { throw "Rule '$($rule.name)': unknown action '$action'." }

        $matched = @($ids | ForEach-Object { $byId[$_] } | Where-Object { $_ -and -not (Test-PolicyExcluded $_ $PolicyDoc.exclude) })
        $actionable = switch ($action) {
            'block'    { @($matched | Where-Object { -not $_.isBlocked }) }
            'unblock'  { @($matched | Where-Object { $_.isBlocked }) }
            'reassign' { @($matched | Where-Object { $proposals.ContainsKey($_.id) -and $proposals[$_.id].State -eq 'Proposed' }) }
            default    { @($matched) }
        }
        [pscustomobject]@{
            Rule = [string]$rule.name; Action = $action; DisableIdentity = [bool]$rule.then.disableIdentity
            Matched = $matched; Actionable = $actionable; Proposals = $proposals
        }
    }
}

# Show the plan, then apply it when asked. One confirmation covers the whole plan.
function Invoke-PolicyPlan {
    param([object[]]$Plan, [switch]$Apply)
    Write-Host ''
    $Plan | Select-Object Rule, Action, @{ n = 'matched'; e = { $_.Matched.Count } }, @{ n = 'would change'; e = { $_.Actionable.Count } } | Format-Table -AutoSize | Out-Host
    foreach ($step in $Plan) {
        if ($step.Matched.Count -gt 0) {
            Write-Host ("Rule '{0}' ({1}):" -f $step.Rule, $step.Action) -ForegroundColor Cyan
            $step.Matched | Select-Object displayName, id, isBlocked, type | Format-Table -AutoSize | Out-Host
        }
    }
    $total = ($Plan | Where-Object { $_.Action -ne 'report' } | ForEach-Object { $_.Actionable.Count } | Measure-Object -Sum).Sum
    if (-not $Apply) { Write-Host ("Plan only: {0} change(s) pending. Add -Apply to run it." -f [int]$total) -ForegroundColor Yellow; return }
    if (-not $total) { Write-Host 'Nothing to change.'; return }
    if (-not (Confirm-Batch -Count $total -Action 'apply')) { Write-Host 'Cancelled.'; return }
    $identityBefore = $script:DisableIdentity
    foreach ($step in $Plan) {
        if ($step.Action -eq 'report' -or $step.Actionable.Count -eq 0) { continue }
        Write-Host ("`nApplying rule '{0}'" -f $step.Rule) -ForegroundColor Cyan
        if ($step.Action -in 'block', 'unblock') {
            $script:DisableIdentity = $step.DisableIdentity
            Invoke-PackageAction -Packages $step.Actionable -Action $step.Action
        } else {
            $items = @($step.Actionable | ForEach-Object { $s = $step.Proposals[$_.id]
                [pscustomobject]@{ Id = $_.id; DisplayName = $_.displayName; CurrentOwnerId = $_.ownerId; NewOwnerId = $s.ProposedId; NewOwnerUpn = $s.Proposed; Source = $s.Source } })
            Invoke-OwnerReassign -Items $items
        }
    }
    $script:DisableIdentity = $identityBefore
}

# ---------------------------------------------------------------------------------------------
# Snapshots: record the inventory, and report what changed since an earlier snapshot.
# ---------------------------------------------------------------------------------------------
function Save-Snapshot {
    param([string]$Path, [object[]]$Packages)
    $items = $Packages | Select-Object id, displayName, type, platform, publisher, ownerId, isBlocked, version, lastModifiedDateTime, agentIdentityId
    [pscustomobject]@{ takenAt = (Get-Date).ToUniversalTime().ToString('o'); count = @($items).Count; items = @($items) } |
        ConvertTo-Json -Depth 4 | Set-Content -Path $Path -Encoding utf8
}

function Compare-Snapshot {
    param([object]$Old, [object[]]$Current)
    $oldById = @{}; foreach ($o in @($Old.items)) { $oldById[[string]$o.id] = $o }
    $curById = @{}; foreach ($c in $Current) { $curById[[string]$c.id] = $c }
    $out = @()
    foreach ($c in $Current) {
        $o = $oldById[[string]$c.id]
        if (-not $o) { $out += [pscustomobject]@{ Change = 'New'; Agent = $c.displayName; Id = $c.id; Detail = "$($c.type), $($c.platform)" }; continue }
        if ([bool]$o.isBlocked -ne [bool]$c.isBlocked) { $out += [pscustomobject]@{ Change = $(if ($c.isBlocked) { 'Blocked' } else { 'Unblocked' }); Agent = $c.displayName; Id = $c.id; Detail = '' } }
        if ([string]$o.ownerId -ne [string]$c.ownerId) { $out += [pscustomobject]@{ Change = 'Owner changed'; Agent = $c.displayName; Id = $c.id; Detail = "$($o.ownerId) -> $($c.ownerId)" } }
        if ([string]$o.version -ne [string]$c.version) { $out += [pscustomobject]@{ Change = 'Version changed'; Agent = $c.displayName; Id = $c.id; Detail = "$($o.version) -> $($c.version)" } }
    }
    foreach ($o in @($Old.items)) {
        if (-not $curById.ContainsKey([string]$o.id)) { $out += [pscustomobject]@{ Change = 'Removed'; Agent = $o.displayName; Id = $o.id; Detail = "$($o.type)" } }
    }
    $out
}

# ---------------------------------------------------------------------------------------------
# Agent detail: one model that joins the catalog record, Defender's AgentsInfo and Entra, used by
# -Detail, -Inventory and the console's details window.
# ---------------------------------------------------------------------------------------------
$script:ResourceCache = @{}

# Hunting results arrive as arrays, JSON text, or single objects; normalise to a list of objects.
function ConvertTo-ObjectList {
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) {
        $s = $Value.Trim()
        if (-not $s -or $s -eq 'null') { return @() }
        if ($s.StartsWith('[') -or $s.StartsWith('{')) { try { return @(ConvertFrom-Json $s) } catch { return @($s) } }
        return @($s)
    }
    # Each array element can itself be a JSON document held as text.
    foreach ($item in @($Value)) {
        if ($item -is [string] -and ($item.TrimStart().StartsWith('{') -or $item.TrimStart().StartsWith('['))) { try { ConvertFrom-Json $item } catch { $item } }
        else { $item }
    }
}

# Items as an array with no nulls. (In PowerShell, @($null).Count is 1: agents with no Defender record must count as zero tools.)
function Get-ItemList {
    param($Items)
    @(@($Items) | Where-Object { $null -ne $_ })
}

# A short text for a list of tools, servers or data sources: their names, one per entry.
function Get-NameText {
    param($Items, [string]$Property = 'name')
    $names = foreach ($i in (ConvertTo-ObjectList $Items)) {
        if ($i -is [string]) { $i } elseif ($i.$Property) { [string]$i.$Property } elseif ($i.Name) { [string]$i.Name } else { ($i | ConvertTo-Json -Compress -Depth 2) }
    }
    (@($names | Where-Object { $_ }) -join '; ')
}

function Get-TypeLabel {
    param([string]$Type)
    switch ($Type) { 'firstParty' { 'Microsoft' } 'thirdParty' { 'Partner or store app' } 'lob' { 'Org-published' } 'shared' { 'Shared by a creator' } default { $Type } }
}

# One query for every agent's declared tools, MCP servers, data sources, channels and sharing, keyed by catalog id.
function Get-AgentInfoTable {
    param([string]$TitleId)
    $where = if ($TitleId) { "| where tolower(tostring(r.titleId)) == '$($TitleId.ToLower().Replace("'", ''))'" } else { '' }
    $kql = 'AgentsInfo | summarize arg_max(Timestamp, *) by AgentId | extend r = todynamic(RawAgentInfo) ' + $where +
           ' | project TitleId = tolower(tostring(r.titleId)), Name, Platform, Channels, Model, PublishedStatus, LifecycleStatus,' +
           ' EntraAgentID = tostring(EntraAgentID), EntraBlueprintID = tostring(EntraBlueprintID), Owners, SharedWith, DeclaredTools, McpServers,' +
           ' DeclaredDataSources, Capabilities, ConnectedAgents, Endpoints, Triggers, Instructions = substring(tostring(Instructions), 0, 1500)'
    $rows = Invoke-HuntingQuery -Query $kql -Hint 'Detail columns need Defender Advanced Hunting (ThreatHunting.Read.All).'
    $table = @{}
    foreach ($row in $rows) {
        if (-not $row.TitleId) { continue }
        $table[[string]$row.TitleId] = [pscustomobject]@{
            Platform = $row.Platform; BlueprintId = [string]$row.EntraBlueprintID; Model = $row.Model; PublishedStatus = $row.PublishedStatus; LifecycleStatus = $row.LifecycleStatus
            Channels = @(ConvertTo-ObjectList $row.Channels | ForEach-Object { "$_".Split(' ') } | Where-Object { $_ })
            Tools = @(ConvertTo-ObjectList $row.DeclaredTools | ForEach-Object {
                [pscustomobject]@{ Name = $_.name; Type = $_.type; Authentication = $_.authenticationUsed.type; Approval = $_.approvalModeKind; Connection = $_.connectionName; Description = $_.description } })
            McpServers = @(ConvertTo-ObjectList $row.McpServers | ForEach-Object {
                [pscustomobject]@{ Name = $_.name; Type = $_.type; Authentication = $_.authenticationUsed.type; Approval = $_.approvalModeKind; Connection = $_.connectionName; Description = $_.description } })
            DataSources = @(ConvertTo-ObjectList $row.DeclaredDataSources | ForEach-Object { "$_" } | Where-Object { $_ })
            Capabilities = @(ConvertTo-ObjectList $row.Capabilities | ForEach-Object { "$_" } | Where-Object { $_ })
            ConnectedAgents = @(ConvertTo-ObjectList $row.ConnectedAgents | ForEach-Object { "$_" } | Where-Object { $_ })
            SharedWith = @(ConvertTo-ObjectList $row.SharedWith | ForEach-Object { "$_" } | Where-Object { $_ })
            Owners = @(ConvertTo-ObjectList $row.Owners | ForEach-Object { "$_" } | Where-Object { $_ })
            Endpoints = @(ConvertTo-ObjectList $row.Endpoints | ForEach-Object { if ($_.endpointUrl) { "$($_.endpointType): $($_.endpointUrl)" } else { "$_" } })
            Triggers = @(ConvertTo-ObjectList $row.Triggers | ForEach-Object { "$_" } | Where-Object { $_ })
            Instructions = [string]$row.Instructions
        }
    }
    $table
}

# Display name and application roles of a resource service principal, cached for the run.
function Get-ResourceInfo {
    param([string]$ResourceId)
    if ($script:ResourceCache.ContainsKey($ResourceId)) { return $script:ResourceCache[$ResourceId] }
    try {
        $sp = Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ResourceId`?`$select=id,displayName,appRoles"
        $roles = @{}; foreach ($r in @($sp.appRoles)) { $roles[[string]$r.id] = [string]$r.value }
        $info = [pscustomobject]@{ Name = $sp.displayName; Roles = $roles }
    } catch { $info = [pscustomobject]@{ Name = $ResourceId; Roles = @{} } }
    $script:ResourceCache[$ResourceId] = $info
    $info
}

# Turn grant and role-assignment responses into permission rows (resource name resolved from the cache).
function ConvertTo-PermissionRows {
    param($Grants, $Roles, [string]$Source)
    $out = @()
    foreach ($grant in (Get-ItemList $Grants)) {
        $res = Get-ResourceInfo $grant.resourceId
        foreach ($s in ([string]$grant.scope).Split(' ', [StringSplitOptions]::RemoveEmptyEntries)) {
            $out += [pscustomobject]@{ Source = $Source; Kind = 'Delegated'; Resource = $res.Name; Permission = $s; Consent = $grant.consentType }
        }
    }
    foreach ($ra in (Get-ItemList $Roles)) {
        $res = Get-ResourceInfo $ra.resourceId
        $name = if ($res.Roles.ContainsKey([string]$ra.appRoleId)) { $res.Roles[[string]$ra.appRoleId] } else { [string]$ra.appRoleId }
        $out += [pscustomobject]@{ Source = $Source; Kind = 'Application'; Resource = $res.Name; Permission = $name; Consent = 'Admin' }
    }
    $out
}

# What one identity may do: delegated grants and application roles.
function Get-IdentityPermissions {
    param([string]$ServicePrincipalId, [string]$Source)
    $grants = @(); $roles = @()
    try { $grants = @((Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=clientId eq '$ServicePrincipalId'").value) } catch { $null = $_ }
    try { $roles = @((Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/appRoleAssignments?`$top=100").value) } catch { $null = $_ }
    # resolve every resource in one pass before building rows
    Initialize-ResourceCache -Ids @(@($grants) + @($roles) | ForEach-Object { $_.resourceId })
    ConvertTo-PermissionRows -Grants $grants -Roles $roles -Source $Source
}

# Resource service principals (name and application roles) for many ids in a few calls.
function Initialize-ResourceCache {
    param([string[]]$Ids)
    $need = @($Ids | Where-Object { $_ } | Select-Object -Unique | Where-Object { -not $script:ResourceCache.ContainsKey($_) })
    if ($need.Count -eq 0) { return }
    $reqs = @($need | ForEach-Object { @{ id = $_; method = 'GET'; url = "/servicePrincipals/$_`?`$select=id,displayName,appRoles" } })
    $res = Invoke-GraphBatch -Requests $reqs -Activity 'Reading permission resources'
    foreach ($id in $need) {
        $r = $res[$id]
        if ($r -and $r.Status -eq 200) {
            $roles = @{}; foreach ($x in @($r.Body.appRoles)) { $roles[[string]$x.id] = [string]$x.value }
            $script:ResourceCache[$id] = [pscustomobject]@{ Name = $r.Body.displayName; Roles = $roles }
        }
    }
}

# Permissions of many agents at once. Items are { Key; ServicePrincipalId; BlueprintAppId }. Returns Key -> permission rows
# (the identity's own plus those inherited from its blueprint). Costs a handful of batched calls, not two per agent.
function Get-PermissionsBulk {
    param([object[]]$Items)
    $out = @{}
    $Items = @($Items | Where-Object { $_ -and $_.ServicePrincipalId })
    if ($Items.Count -eq 0) { return $out }

    # blueprint service principals, once per blueprint
    $bpApps = @($Items | ForEach-Object { $_.BlueprintAppId } | Where-Object { $_ } | Select-Object -Unique | Where-Object { -not $script:BlueprintPermCache.ContainsKey($_) })
    $bpSp = @{}
    if ($bpApps.Count) {
        $res = Invoke-GraphBatch -Requests @($bpApps | ForEach-Object { @{ id = $_; method = 'GET'; url = "/servicePrincipals?`$filter=appId eq '$_'&`$select=id" } }) -Activity 'Reading agent blueprints'
        foreach ($a in $bpApps) { $r = $res[$a]; if ($r -and $r.Status -eq 200 -and @(Get-ItemList $r.Body.value).Count) { $bpSp[$a] = [string]@(Get-ItemList $r.Body.value)[0].id } else { $script:BlueprintPermCache[$a] = @() } }
    }

    # grants and role assignments for every identity and blueprint, two requests each
    $sps = @(@($Items | ForEach-Object { $_.ServicePrincipalId }) + @($bpSp.Values) | Select-Object -Unique)
    $reqs = @($sps | ForEach-Object { @{ id = "g:$_"; method = 'GET'; url = "/oauth2PermissionGrants?`$filter=clientId eq '$_'" }; @{ id = "r:$_"; method = 'GET'; url = "/servicePrincipals/$_/appRoleAssignments?`$top=100" } })
    $res = Invoke-GraphBatch -Requests $reqs -Activity 'Reading agent permissions'
    $grants = @{}; $roles = @{}
    foreach ($sp in $sps) {
        $grants[$sp] = if ($res["g:$sp"] -and $res["g:$sp"].Status -eq 200) { ,@(Get-ItemList $res["g:$sp"].Body.value) } else { ,@() }
        $roles[$sp]  = if ($res["r:$sp"] -and $res["r:$sp"].Status -eq 200) { ,@(Get-ItemList $res["r:$sp"].Body.value) } else { ,@() }
    }
    Initialize-ResourceCache -Ids @(@($grants.Values + $roles.Values) | ForEach-Object { $_ } | ForEach-Object { $_.resourceId })

    foreach ($a in $bpSp.Keys) { $script:BlueprintPermCache[$a] = @(ConvertTo-PermissionRows -Grants $grants[$bpSp[$a]] -Roles $roles[$bpSp[$a]] -Source 'Blueprint (inherited)') }
    foreach ($item in $Items) {
        $own = @(ConvertTo-PermissionRows -Grants $grants[$item.ServicePrincipalId] -Roles $roles[$item.ServicePrincipalId] -Source 'Agent identity')
        $inherited = if ($item.BlueprintAppId -and $script:BlueprintPermCache.ContainsKey($item.BlueprintAppId)) { @($script:BlueprintPermCache[$item.BlueprintAppId]) } else { @() }
        $out[[string]$item.Key] = @($own + $inherited)
    }
    $out
}

# Catalog detail records (usage, availability, sharing) for many packages in a few calls. Returns id -> record.
function Get-PackageDetailMap {
    param([string[]]$Ids)
    $map = @{}
    $ids = @($Ids | Where-Object { $_ } | Select-Object -Unique)
    if ($ids.Count -eq 0) { return $map }
    # The package service sustains roughly 1.5 to 2 requests per second (bursts of ~40); faster than that it answers 424.
    $res = Invoke-GraphBatch -Requests @($ids | ForEach-Object { @{ id = $_; method = 'GET'; url = "/copilot/admin/catalog/packages/$_" } }) -Version beta -Activity 'Reading agent details' -ChunkSize 10 -PaceSeconds 0.5
    foreach ($id in $ids) { if ($res[$id] -and $res[$id].Status -eq 200) { $map[$id] = $res[$id].Body } }
    $map
}

# accountEnabled of many agent identities in a few calls. Returns identity id -> $true / $false ($null when unreadable).
function Get-AgentIdentityStateMap {
    param([string[]]$AgentIdentityIds)
    $map = @{}
    $ids = @($AgentIdentityIds | Where-Object { $_ } | Select-Object -Unique)
    if ($ids.Count -eq 0) { return $map }
    $res = Invoke-GraphBatch -Requests @($ids | ForEach-Object { @{ id = $_; method = 'GET'; url = "/servicePrincipals/$_/microsoft.graph.agentIdentity?`$select=id,accountEnabled" } }) -Version beta
    foreach ($id in $ids) { $map[$id] = if ($res[$id] -and $res[$id].Status -eq 200) { [bool]$res[$id].Body.accountEnabled } else { $null } }
    $map
}

# The full picture of one agent. Entra lookups run only when the agent has an identity.
function Get-AgentDetail {
    param([object]$Package, [hashtable]$InfoTable, [switch]$SkipEntra, [switch]$SkipRisk)
    $d = Invoke-Graph -Uri "$Base/$($Package.id)"
    $info = if ($InfoTable) { $InfoTable[$Package.id.ToLower()] } else { (Get-AgentInfoTable -TitleId $Package.id)[$Package.id.ToLower()] }
    $owner = Get-UserInfo $d.ownerId
    $identity = $null; $perms = @(); $owners = @(); $sponsors = @()
    if ($d.agentIdentityId -and -not $SkipEntra) {
        try { $identity = Invoke-Graph -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($d.agentIdentityId)/microsoft.graph.agentIdentity?`$select=id,displayName,accountEnabled,agentIdentityBlueprintId,createdDateTime" } catch { $null = $_ }
        $owners = @(Get-IdentityOwners $d.agentIdentityId | ForEach-Object { $_.Upn })
        try { $sp = Invoke-Graph -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($d.agentIdentityId)/microsoft.graph.agentIdentity/sponsors?`$select=id"; $sponsors = @($sp.value | ForEach-Object { (Get-UserInfo $_.id).Upn }) } catch { $null = $_ }
        $perms = @(Get-AgentPermissionList -AgentIdentityId $d.agentIdentityId -BlueprintAppId $(if ($identity) { $identity.agentIdentityBlueprintId }))
    }
    $count = { param($x) @(Get-ItemList $x).Count }
    $riskEntry = if ($SkipRisk) { $null } else { try { Get-AgentRisk $Package } catch { $null } }
    $riskInfo = [ordered]@{}
    if ($riskEntry) {
        $riskInfo['Severity'] = $riskEntry.Severity; $riskInfo['Alerts (30 days)'] = $riskEntry.AlertCount; $riskInfo['Detections (30 days)'] = $riskEntry.DetectionCount
        $riskInfo['Last signal'] = $(if ($riskEntry.LastAlert) { $riskEntry.LastAlert.ToString('yyyy-MM-dd') })
        $n = 0; foreach ($s in ([string]$riskEntry.Reasons -split '; ')) { if ($s) { $n++; $riskInfo["Signal $n"] = $s } }
    } else { $riskInfo['Security signals (30 days)'] = $(if ($SkipRisk) { 'not checked' } else { 'none found' }) }
    [pscustomobject]@{
        Id = $d.id; Name = $d.displayName
        Overview = [ordered]@{
            Name = $d.displayName; 'Catalog id' = $d.id; Kind = Get-TypeLabel $d.type; Platform = $(if ($info.Platform) { $info.Platform } else { $d.platform })
            Publisher = $d.publisher; Version = $d.version; Status = $(if ($d.isBlocked) { 'Blocked' } else { 'Active' })
            Published = $info.PublishedStatus; Lifecycle = $info.LifecycleStatus; Model = $info.Model
            Created = $(if ($d.createdDateTime) { ([datetimeoffset]$d.createdDateTime).ToString('yyyy-MM-dd') }); Modified = $(if ($d.lastModifiedDateTime) { ([datetimeoffset]$d.lastModifiedDateTime).ToString('yyyy-MM-dd') })
            Description = $(if ($d.longDescription) { $d.longDescription } else { $d.shortDescription }); Categories = (@($d.categories) -join ', ')
        }
        Sharing = [ordered]@{
            'Who can use it' = $d.availableTo; 'Deployed to' = $d.deployedTo
            'Allowed users and groups' = (& $count $d.allowedUsersAndGroups); 'Users and groups it can be installed by' = (& $count $d.acquireUsersAndGroups)
            'Shared with (catalog)' = (& $count $d.sharedWithUsersAndGroups); 'Shared with (agent record)' = $(if ($info) { (& $count $info.SharedWith) } else { 0 })
            Channels = $(if ($info) { $info.Channels -join ', ' } else { '' })
        }
        Tools = @(Get-ItemList $info.Tools); McpServers = @(Get-ItemList $info.McpServers)
        DataSources = @(Get-ItemList $info.DataSources); Capabilities = @(Get-ItemList $info.Capabilities); ConnectedAgents = @(Get-ItemList $info.ConnectedAgents); Endpoints = @(Get-ItemList $info.Endpoints)
        Permissions = @($perms)
        Identity = [ordered]@{
            Owner = $(if ($owner.Exists) { $owner.Upn } elseif ($d.ownerId) { '(account no longer exists)' } else { '(none)' })
            'Owners recorded on the agent' = $(if ($info) { $info.Owners -join ', ' } else { '' })
            'Agent identity' = $d.agentIdentityId; 'Identity enabled' = $(if ($identity) { $identity.accountEnabled } else { '' })
            'Blueprint id' = $(if ($identity) { $identity.agentIdentityBlueprintId } else { '' })
            'Identity owners' = ($owners -join ', '); Sponsors = ($sponsors -join ', ')
        }
        Usage = [ordered]@{
            'Active users' = $d.activeUsers; Sessions = $d.totalSessions; 'Last used' = $(if ($d.lastUsedDateTime) { ([datetimeoffset]$d.lastUsedDateTime).ToString('yyyy-MM-dd') } else { 'never' })
            'Exception rate' = $d.exceptionRate; 'Run time (hours)' = $d.totalRunTimeInHours
        }
        Risk = $riskInfo
        Instructions = $(if ($info) { $info.Instructions } else { '' })
    }
}

# Risk signals per agent come from one hunting run, cached for ten minutes so the details window is quick.
$script:RiskCache = $null
$script:RiskCacheAt = [datetime]::MinValue
function Get-RiskCached {
    if (-not $script:RiskCache -or ((Get-Date) - $script:RiskCacheAt).TotalMinutes -gt 10) {
        $script:RiskCache = Get-RiskyIndex -Days 30
        $script:RiskCacheAt = Get-Date
    }
    $script:RiskCache
}

# The risk entry for one package (severity, alert and detection counts, reasons), or $null when it has none.
function Get-AgentRisk {
    param([object]$Package)
    $idx = Get-RiskCached
    foreach ($k in (Get-PackageKeys $Package)) { if ($idx.ContainsKey($k)) { return $idx[$k] } }
    $null
}

# Permissions of an agent identity plus what it inherits from its blueprint. Blueprint lookups are cached per run.
$script:BlueprintPermCache = @{}
function Get-AgentPermissionList {
    param([string]$AgentIdentityId, [string]$BlueprintAppId)
    $perms = @(Get-IdentityPermissions -ServicePrincipalId $AgentIdentityId -Source 'Agent identity')
    if ($BlueprintAppId) {
        if (-not $script:BlueprintPermCache.ContainsKey($BlueprintAppId)) {
            $inherited = @()
            try {
                $bp = Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$BlueprintAppId'&`$select=id,displayName"
                foreach ($b in @($bp.value | Select-Object -First 1)) { $inherited = @(Get-IdentityPermissions -ServicePrincipalId $b.id -Source 'Blueprint (inherited)') }
            } catch { $null = $_ }
            $script:BlueprintPermCache[$BlueprintAppId] = $inherited
        }
        $perms += $script:BlueprintPermCache[$BlueprintAppId]
    }
    $perms
}

# Does a permission list satisfy the filter: any permission, a Microsoft Graph application permission, or an MCP server permission?
function Test-PermissionMatch {
    param([object[]]$Perms, [string]$Mode)
    $p = @($Perms)
    switch ($Mode) {
        'any'      { $p.Count -gt 0 }
        'graphapp' { @($p | Where-Object { $_.Kind -eq 'Application' -and $_.Resource -eq 'Microsoft Graph' }).Count -gt 0 }
        'mcp'      { @($p | Where-Object { $_.Permission -like 'McpServers.*' -or $_.Resource -like '*MCP*' -or $_.Resource -eq 'Agent Tools' }).Count -gt 0 }
        default    { $true }
    }
}

# Text rendering of the detail object for the console.
function Show-AgentDetail {
    param([object]$Detail)
    $section = { param($title, $dict) Write-Host "`n$title" -ForegroundColor Cyan; foreach ($k in $dict.Keys) { if ($null -ne $dict[$k] -and "$($dict[$k])" -ne '') { Write-Host ('  {0,-34} {1}' -f $k, $dict[$k]) } } }
    & $section 'OVERVIEW' $Detail.Overview
    & $section 'SHARING AND AVAILABILITY' $Detail.Sharing
    Write-Host "`nTOOLS ($($Detail.Tools.Count)) AND MCP SERVERS ($($Detail.McpServers.Count))" -ForegroundColor Cyan
    if ($Detail.Tools.Count -or $Detail.McpServers.Count) { @($Detail.McpServers | Select-Object @{ n = 'kind'; e = { 'MCP server' } }, Name, Type, Authentication, Approval) + @($Detail.Tools | Select-Object @{ n = 'kind'; e = { 'tool' } }, Name, Type, Authentication, Approval) | Format-Table -AutoSize | Out-Host }
    else { Write-Host '  (none declared)' }
    if ($Detail.DataSources.Count) { Write-Host "`nDATA SOURCES" -ForegroundColor Cyan; $Detail.DataSources | ForEach-Object { Write-Host "  $_" } }
    if ($Detail.Capabilities.Count) { Write-Host "`nCAPABILITIES: $($Detail.Capabilities -join ', ')" -ForegroundColor Cyan }
    Write-Host "`nPERMISSIONS ($($Detail.Permissions.Count))" -ForegroundColor Cyan
    if ($Detail.Permissions.Count) { $Detail.Permissions | Format-Table -AutoSize | Out-Host } else { Write-Host '  (none found for the agent identity or its blueprint)' }
    & $section 'RISK SIGNALS' $Detail.Risk
    & $section 'IDENTITY AND OWNERSHIP' $Detail.Identity
    & $section 'USAGE' $Detail.Usage
}

# One row per agent for -Inventory: the catalog record plus the Defender columns; -Deep adds usage and sharing per agent.
function Get-InventoryRows {
    param([object[]]$Packages, [hashtable]$InfoTable, [switch]$Deep, [switch]$WithPermissions)
    Initialize-UserCache -Ids @($Packages | ForEach-Object { $_.ownerId })
    $detailMap = if ($Deep) { Get-PackageDetailMap -Ids @($Packages | ForEach-Object { $_.id }) } else { @{} }
    $permMap = if ($WithPermissions) {
        Get-PermissionsBulk -Items @($Packages | Where-Object { $_.agentIdentityId } | ForEach-Object {
            @{ Key = $_.id; ServicePrincipalId = $_.agentIdentityId; BlueprintAppId = $InfoTable[$_.id.ToLower()].BlueprintId } })
    } else { @{} }
    $i = 0
    foreach ($p in $Packages) {
        $i++
        $info = $InfoTable[$p.id.ToLower()]
        $owner = Get-UserInfo $p.ownerId
        $row = [ordered]@{
            Name = $p.displayName; Id = $p.id; Kind = Get-TypeLabel $p.type; Platform = $(if ($info.Platform) { $info.Platform } else { $p.platform })
            Publisher = $p.publisher; Status = $(if ($p.isBlocked) { 'Blocked' } else { 'Active' })
            Owner = $(if ($owner.Exists) { $owner.Upn } elseif ($p.ownerId -and $p.ownerId -ne '00000000-0000-0000-0000-000000000000') { '(account no longer exists)' } else { '' })
            Version = $p.version; Created = $(if ($p.createdDateTime) { ([datetimeoffset]$p.createdDateTime).ToString('yyyy-MM-dd') }); Modified = $(if ($p.lastModifiedDateTime) { ([datetimeoffset]$p.lastModifiedDateTime).ToString('yyyy-MM-dd') })
            Published = $info.PublishedStatus; Channels = ($info.Channels -join ', '); Model = $info.Model
            ToolCount = @(Get-ItemList $info.Tools).Count; Tools = (Get-NameText $info.Tools); McpServers = (Get-NameText $info.McpServers)
            DataSources = ($info.DataSources -join '; '); Capabilities = ($info.Capabilities -join '; ')
            SharedWithCount = @(Get-ItemList $info.SharedWith).Count; AgentIdentity = $p.agentIdentityId
        }
        if ($Deep) {
            foreach ($c in 'AvailableTo', 'DeployedTo', 'CatalogSharedWith', 'ActiveUsers', 'Sessions', 'LastUsed') { $row[$c] = '' }
            $d = $detailMap[$p.id]
            if ($d) {
                $row.AvailableTo = $d.availableTo; $row.DeployedTo = $d.deployedTo
                $row.CatalogSharedWith = @(Get-ItemList $d.sharedWithUsersAndGroups).Count
                $row.ActiveUsers = $d.activeUsers; $row.Sessions = $d.totalSessions
                $row.LastUsed = if ($d.lastUsedDateTime) { ([datetimeoffset]$d.lastUsedDateTime).ToString('yyyy-MM-dd') } else { 'never' }
            } else { $row.AvailableTo = 'error' }
        }
        if ($WithPermissions) {
            $perms = @(Get-ItemList $permMap[[string]$p.id])
            $row.PermissionCount = $perms.Count
            $row.Permissions = (($perms | ForEach-Object { "$($_.Resource):$($_.Permission)" }) -join '; ')
        }        [pscustomobject]$row
    }
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
            if ($p.lastModifiedDateTime) { try { $since = [datetimeoffset]$p.lastModifiedDateTime } catch { $null = $_ } }
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
function Test-Proceed {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '', Justification = 'Delegates to the script-level ShouldProcess so -WhatIf covers every write.')]
    param([string]$Target, [string]$Verb)
    $PSCmdlet.ShouldProcess($Target, $Verb)
}

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

# Enable or disable the Entra agent identity behind a package (containment that also stops runtime sign-in).
function Set-AgentIdentityState {
    param([string]$AgentIdentityId, [bool]$Enabled)
    Invoke-Graph -Method PATCH -Uri "https://graph.microsoft.com/beta/servicePrincipals/$AgentIdentityId/microsoft.graph.agentIdentity" `
        -Body (@{ accountEnabled = $Enabled } | ConvertTo-Json) -ContentType 'application/json' | Out-Null
}

# Blocking a package that has an Agent ID makes the platform disable that identity a few seconds later
# (and unblock re-enables it). Wait for that, record what happened, and only call the identity API
# ourselves for agents the platform left in the wrong state.
function Confirm-AgentIdentityState {
    param([object[]]$Records, [hashtable]$PackageById, [bool]$WantDisabled, [int]$WaitSeconds = 30)
    $pending = @($Records | Where-Object { $_.Result -in 'Done', 'Skipped' -and $PackageById[$_.Id].agentIdentityId })
    if ($pending.Count -eq 0) { return }
    $wantEnabled = -not $WantDisabled
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while ($pending.Count -gt 0) {
        $still = @()
        $states = Get-AgentIdentityStateMap -AgentIdentityIds @($pending | ForEach-Object { $PackageById[$_.Id].agentIdentityId })
        foreach ($rec in $pending) {
            $state = $states[[string]$PackageById[$rec.Id].agentIdentityId]
            if ($state -eq $wantEnabled) { $rec.Identity = if ($WantDisabled) { 'Disabled (by platform)' } else { 'Enabled (by platform)' } }
            elseif ($null -eq $state) { $rec.Identity = 'Unreadable' }
            else { $still += $rec }
        }
        $pending = $still
        if ($pending.Count -eq 0 -or (Get-Date) -ge $deadline) { break }
        Start-Sleep -Seconds 3
    }
    foreach ($rec in $pending) {
        try {
            Set-AgentIdentityState -AgentIdentityId $PackageById[$rec.Id].agentIdentityId -Enabled $wantEnabled
            $rec.Identity = if ($WantDisabled) { 'Disabled (by tool)' } else { 'Enabled (by tool)' }
        } catch {
            $rec.Identity = 'Failed'; $rec.Error = ($rec.Error + ' identity: ' + $_.Exception.Message).Trim()
        }
    }
}

# Apply block/unblock to each package; skip ones already in the target state, keep going on
# error, then summarize. Honours -WhatIf and records the outcome per package. With
# -DisableIdentity the agent's Entra identity is disabled on block and re-enabled on unblock.
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
            Id = $p.id; DisplayName = $p.displayName; WasBlocked = $p.isBlocked; Result = ''; Identity = ''; Error = ''
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
    if ($DisableIdentity) {
        $byId = @{}; foreach ($p in $Packages) { $byId[$p.id] = $p }
        Confirm-AgentIdentityState -Records $log -PackageById $byId -WantDisabled $want
        foreach ($r in ($log | Where-Object { $_.Identity })) { Write-Host ("  identity {0}: {1}" -f $r.Identity.ToLower(), $r.DisplayName) -ForegroundColor DarkGreen }
    }
    Write-Host ("Done: {0} {1}ed, {2} skipped, {3} failed." -f $ok, $Action, $skip, $fail) -ForegroundColor Cyan
    Export-ActionLog -Records $log
    if ($PassThru) { $log }
}

# Usage figures live only on the per-package detail call, so fetch them for the targets, not the whole catalog.
function Add-PackageUsage {
    param([object[]]$Packages)
    $map = Get-PackageDetailMap -Ids @($Packages | ForEach-Object { $_.id })
    foreach ($p in $Packages) {
        $d = $map[$p.id]
        if (-not $d) { continue }
        $p | Add-Member -NotePropertyName ActiveUsers -NotePropertyValue $d.activeUsers -Force
        $p | Add-Member -NotePropertyName Sessions    -NotePropertyValue $d.totalSessions -Force
        $p | Add-Member -NotePropertyName LastUsed    -NotePropertyValue $(if ($d.lastUsedDateTime) { ([datetimeoffset]$d.lastUsedDateTime).ToString('yyyy-MM-dd') } else { 'never' }) -Force
    }
    $Packages
}
# Preview of the targets with their blast radius (who would lose the agent).
function Show-ImpactPreview {
    param([object[]]$Packages)
    Add-PackageUsage $Packages | Out-Null
    $Packages | Select-Object displayName, id, isBlocked, ActiveUsers, Sessions, LastUsed | Format-Table -AutoSize | Out-Host
}

# Blocked agents that have stayed blocked at least MinDaysBlocked. The block date comes from this
# tool's own logs and, for the last ~30 days, from the BlockedAgent/UnblockedAgent audit events.
function Get-DeleteCandidates {
    param([int]$MinDays, [string[]]$HistoryPaths, [switch]$IncludeUnknown,
          [string]$LogDir = (Join-Path $env:LOCALAPPDATA 'Agent365-Bulk-Actions\logs'))
    $logDir = $LogDir
    $files = @()
    foreach ($p in @($logDir) + @($HistoryPaths)) {
        if (-not $p -or -not (Test-Path -LiteralPath $p)) { continue }
        $item = Get-Item -LiteralPath $p
        $files += if ($item.PSIsContainer) { @(Get-ChildItem -LiteralPath $p -File | Where-Object { $_.Extension -in '.csv', '.json' }) } else { $item }
    }
    $events = @()
    foreach ($file in ($files | Sort-Object FullName -Unique)) {
        $rows = if ($file.Extension -eq '.json') { @(Get-Content -Raw -LiteralPath $file.FullName | ConvertFrom-Json) } else { @(Import-Csv -LiteralPath $file.FullName) }
        foreach ($r in $rows) {
            if ($r.Result -eq 'Done' -and $r.Action -in 'block', 'unblock' -and $r.Id -and $r.Timestamp) {
                $events += [pscustomobject]@{ Id = $r.Id; At = [datetimeoffset]$r.Timestamp; Action = $r.Action; Source = 'kit log' }
            }
        }
    }
    try {
        $audit = Invoke-HuntingQuery -Hint 'Audit events unavailable; relying on kit logs.' -Query ('CloudAppEvents | where Timestamp > ago(30d) and ActionType in ("BlockedAgent", "UnblockedAgent")' +
            ' | extend d = todynamic(RawEventData) | project Timestamp, ActionType, AgentId = tostring(d.AgentId)')
        foreach ($a in $audit) {
            $events += [pscustomobject]@{ Id = [string]$a.AgentId; At = [datetimeoffset]$a.Timestamp; Action = $(if ($a.ActionType -eq 'BlockedAgent') { 'block' } else { 'unblock' }); Source = 'audit' }
        }
    } catch { Write-Warning $_.Exception.Message }

    $latest = @{}
    foreach ($e in ($events | Sort-Object At)) { $latest[$e.Id.ToLower()] = $e }
    $now = [datetimeoffset]::UtcNow
    $out = foreach ($p in (Get-Packages | Where-Object { $_.isBlocked })) {
        $e = $latest[$p.id.ToLower()]
        $since = if ($e -and $e.Action -eq 'block') { $e.At } else { $null }
        $days = if ($since) { [int]($now - $since).TotalDays } else { $null }
        if (($null -ne $days -and $days -ge $MinDays) -or ($null -eq $days -and $IncludeUnknown)) {
            [pscustomobject]@{
                Agent = $p.displayName; Id = $p.id; Platform = $(if ($p.platform -and $p.platform -ne 'Not Available') { $p.platform } else { $p.type })
                BlockedSince = $(if ($since) { $since.ToString('yyyy-MM-dd') } else { 'unknown' }); DaysBlocked = $days
                Evidence = $(if ($e) { $e.Source } else { 'none' })
                DeleteVia = $(if ($p.platform -match 'Copilot Studio') { 'Admin center, or Power Platform API' } else { 'Admin center' })
            }
        }
    }
    @($out | Sort-Object @{ e = { $null -eq $_.DaysBlocked } }, @{ e = { $_.DaysBlocked }; Descending = $true })
}
# ---------------------------------------------------------------------------------------------
# Graphical console (-Gui): WPF window over the same catalog, stale, risky, block and unblock logic.
# ---------------------------------------------------------------------------------------------
$GuiXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Agent 365 Bulk Actions" Width="1380" Height="780" MinWidth="1100" MinHeight="560"
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
          <StackPanel Grid.Column="3" Orientation="Horizontal" VerticalAlignment="Center">
            <CheckBox x:Name="DetailColsBox" Content="Tools and sharing columns" Margin="0,0,18,0" ToolTip="Adds tools, MCP servers, sharing and channels to the grid (reads Defender agent records once)."/>
            <CheckBox x:Name="AgentsOnlyBox" Content="Copilot agents only"/>
          </StackPanel>
        </Grid>
        <Border Grid.Row="1" Background="White" BorderBrush="{StaticResource Line}" BorderThickness="1" CornerRadius="8" Padding="14,10" Margin="0,12,0,0">
          <StackPanel>
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
          </WrapPanel>
          <WrapPanel VerticalAlignment="Center" Margin="0,10,0,0">
            <TextBlock Text="" Width="84"/>
            <TextBlock Text="Ownership" VerticalAlignment="Center" Margin="0,0,8,0"/>
            <ComboBox x:Name="OwnerBox" Width="190" SelectedIndex="0" ToolTip="Shared agents whose owner is missing, deleted or disabled, with a suggested replacement">
              <ComboBoxItem Content="None" Tag=""/>
              <ComboBoxItem Content="Needs an owner" Tag="needs"/>
            </ComboBox>
            <TextBlock Text="Blocked" VerticalAlignment="Center" Margin="14,0,8,0"/>
            <ComboBox x:Name="BlockedBox" Width="165" SelectedIndex="0" ToolTip="How long an agent has stayed blocked, from this tool's logs and the 30-day audit trail">
              <ComboBoxItem Content="None" Tag=""/>
              <ComboBoxItem Content="Any time" Tag="0"/>
              <ComboBoxItem Content="7+ days" Tag="7"/>
              <ComboBoxItem Content="30+ days" Tag="30"/>
              <ComboBoxItem Content="60+ days" Tag="60"/>
              <ComboBoxItem Content="90+ days" Tag="90"/>
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
          <WrapPanel VerticalAlignment="Center" Margin="0,10,0,0">
            <TextBlock Text="" Width="84"/>
            <TextBlock Text="Tools" VerticalAlignment="Center" Margin="0,0,8,0" Width="64" TextAlignment="Right"/>
            <ComboBox x:Name="ToolsBox" Width="190" SelectedIndex="0" ToolTip="Reads Defender's declared tools and MCP servers for each agent">
              <ComboBoxItem Content="None" Tag=""/>
              <ComboBoxItem Content="Uses an MCP server" Tag="mcp"/>
              <ComboBoxItem Content="Has declared tools" Tag="tools"/>
              <ComboBoxItem Content="Has no declared tools" Tag="none"/>
            </ComboBox>
            <TextBlock Text="Permissions" VerticalAlignment="Center" Margin="22,0,8,0"/>
            <ComboBox x:Name="PermBox" Width="250" SelectedIndex="0" ToolTip="Scans the Entra permissions of every agent that has an identity (a few minutes the first time)">
              <ComboBoxItem Content="None" Tag=""/>
              <ComboBoxItem Content="Holds any Entra permission" Tag="any"/>
              <ComboBoxItem Content="Holds a Microsoft Graph application permission" Tag="graphapp"/>
              <ComboBoxItem Content="Holds an MCP server permission" Tag="mcp"/>
            </ComboBox>
          </WrapPanel>
          </StackPanel>
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
            <DataGridTextColumn Header="Kind" Binding="{Binding Kind}" Width="1.5*" IsReadOnly="True" ElementStyle="{StaticResource Cell}"/>
            <DataGridTextColumn Header="Platform" Binding="{Binding Platform}" Width="1.2*" IsReadOnly="True" ElementStyle="{StaticResource Cell}"/>
            <DataGridTextColumn Header="Publisher" Binding="{Binding Publisher}" Width="1.2*" IsReadOnly="True" ElementStyle="{StaticResource Cell}"/>
            <DataGridTextColumn Header="Owner" Binding="{Binding Owner}" Width="1.4*" IsReadOnly="True" ElementStyle="{StaticResource Cell}"/>
            <DataGridTextColumn Header="Tools" Binding="{Binding ToolCount}" Width="62" SortMemberPath="ToolCountSort" IsReadOnly="True" Visibility="Collapsed"/>
            <DataGridTextColumn Header="MCP servers" Binding="{Binding Mcp}" Width="1.3*" IsReadOnly="True" ElementStyle="{StaticResource Cell}" Visibility="Collapsed"/>
            <DataGridTextColumn Header="Shared with" Binding="{Binding SharedCount}" Width="105" IsReadOnly="True" Visibility="Collapsed"/>
            <DataGridTextColumn Header="Channels" Binding="{Binding Channels}" Width="1.2*" IsReadOnly="True" ElementStyle="{StaticResource Cell}" Visibility="Collapsed"/>
            <DataGridTextColumn Header="Permissions held" Binding="{Binding PermNote}" Width="2*" IsReadOnly="True" ElementStyle="{StaticResource Cell}" Visibility="Collapsed"/>
            <DataGridTextColumn Header="Modified" Binding="{Binding Modified}" Width="95" IsReadOnly="True"/>
            <DataGridTextColumn Header="Blocked for" Binding="{Binding BlockedFor}" Width="95" SortMemberPath="BlockedForSort" IsReadOnly="True"/>
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
            <DataGridTextColumn Header="Suggested owner" Binding="{Binding Suggested}" Width="1.5*" IsReadOnly="True" ElementStyle="{StaticResource Cell}"/>
            <DataGridTextColumn Header="Ownership note" Binding="{Binding OwnerNote}" Width="1.5*" IsReadOnly="True" ElementStyle="{StaticResource Cell}"/>
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
          <Button x:Name="BtnDetails" Content="Details..." Style="{StaticResource Btn}" Margin="0,0,8,0" IsEnabled="False" ToolTip="Full record of the highlighted agent: sharing, tools, MCP servers, permissions, identity and usage. Double-click a row does the same."/>
          <Button x:Name="BtnApplyOwner" Content="Apply suggested" Style="{StaticResource Btn}" Margin="0,0,8,0" IsEnabled="False" Visibility="Collapsed"/>
          <Button x:Name="BtnAssign" Content="Assign owner..." Style="{StaticResource Btn}" Margin="0,0,8,0" IsEnabled="False" ToolTip="Pick a new owner for the selected agents. Only shared agents can be reassigned; the button stays off until one is selected."/>
          <Button x:Name="BtnExport" Content="Export" Style="{StaticResource Btn}" Margin="0,0,8,0"/>
          <Button x:Name="BtnUndo" Content="Undo last run" Style="{StaticResource Btn}" Margin="0,0,18,0" IsEnabled="False"/>
          <CheckBox x:Name="IdentityBox" Content="Verify identity state" VerticalAlignment="Center" Margin="0,0,14,0" ToolTip="Checks that the agent's Entra identity ends up disabled after a block (enabled after an unblock). The platform normally does this itself within seconds; the tool only forces it if that did not happen."/>
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
                   'Risk:string', 'RiskSort:int', 'Alerts:string', 'AlertsSort:int', 'Detections:string', 'DetectionsSort:int', 'Why:string', 'PermNote:string', 'Kind:string', 'ToolCount:string', 'ToolCountSort:int', 'Mcp:string', 'ToolsText:string', 'SharedCount:string', 'Channels:string', 'Owner:string', 'Suggested:string', 'OwnerNote:string', 'BlockedFor:string', 'BlockedForSort:int'
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
    $usage = @{}
    if ($count -le 25) {
        try { $pk = @($Rows | ForEach-Object { $_.Package }); Add-PackageUsage $pk | Out-Null; foreach ($q in $pk) { $usage[$q.id] = $q } } catch { $null = $_ }
    }
    foreach ($r in @($Rows) | Select-Object -First 50) {
        $x = $usage[$r.Id]
        $label = if ($x -and $null -ne $x.ActiveUsers) { "{0}    ({1} active users, last used {2})" -f $r.Name, $x.ActiveUsers, $x.LastUsed } else { $r.Name }
        [void]$names.Items.Add($label)
    }
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

$OwnerPromptXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Assign owner" Width="540" SizeToContent="Height" ResizeMode="NoResize" ShowInTaskbar="False"
        WindowStartupLocation="CenterOwner" Background="White" FontFamily="Segoe UI" FontSize="13" UseLayoutRounding="True">
  <StackPanel Margin="28,24,28,22">
    <TextBlock Text="Assign owner" FontSize="18" FontWeight="SemiBold" Foreground="#1F2937"/>
    <TextBlock x:Name="Info" Foreground="#4B5563" Margin="0,4,0,14" TextWrapping="Wrap"/>
    <Grid>
      <TextBox x:Name="Search" Padding="10,8" BorderBrush="#D1D5DB" FontSize="14"/>
      <TextBlock Text="Search by name or email" Foreground="#9CA3AF" IsHitTestVisible="False" Margin="12,0,0,0" VerticalAlignment="Center" FontSize="14">
        <TextBlock.Style>
          <Style TargetType="TextBlock">
            <Setter Property="Visibility" Value="Collapsed"/>
            <Style.Triggers><DataTrigger Binding="{Binding Text, ElementName=Search}" Value=""><Setter Property="Visibility" Value="Visible"/></DataTrigger></Style.Triggers>
          </Style>
        </TextBlock.Style>
      </TextBlock>
    </Grid>
    <Border BorderBrush="#E5E7EB" BorderThickness="1" CornerRadius="8" Margin="0,10,0,0" Background="#F9FAFB">
      <ListBox x:Name="Users" Height="230" BorderThickness="0" Background="Transparent" Padding="4" HorizontalContentAlignment="Stretch"/>
    </Border>
    <TextBlock x:Name="Note" Foreground="#6B7280" FontSize="12" Margin="0,8,0,0" TextWrapping="Wrap"/>
    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,16,0,0">
      <Button x:Name="BtnCancel" Content="Cancel" Style="{DynamicResource Btn}" IsCancel="True" MinWidth="100" Margin="0,0,10,0"/>
      <Button x:Name="BtnOk" Content="Assign" Style="{DynamicResource BtnAccent}" IsDefault="True" MinWidth="120" IsEnabled="False"/>
    </StackPanel>
  </StackPanel>
</Window>
'@

# Enabled users from Entra whose name, sign-in name or email starts with the text (all users, first page, when empty).
function Find-DirectoryUsers {
    param([string]$Text, [int]$Top = 40)
    $uri = "https://graph.microsoft.com/v1.0/users?`$top=$Top&`$select=id,displayName,userPrincipalName,mail,accountEnabled"
    $q = $Text.Trim()
    if ($q) {
        $e = $q.Replace("'", "''")
        $uri += "&`$filter=" + [uri]::EscapeDataString("startswith(displayName,'$e') or startswith(userPrincipalName,'$e') or startswith(mail,'$e')")
    }
    $r = Invoke-Graph -Uri $uri
    @($r.value | Where-Object { $_.accountEnabled } | Sort-Object displayName |
        ForEach-Object { [pscustomobject]@{ Id = $_.id; Name = $_.displayName; Upn = $_.userPrincipalName; Enabled = $true } })
}

# Build the owner picker window: type to search Entra, pick a person, Assign.
function New-OwnerPicker {
    param([int]$Count, [System.Windows.Window]$Owner)
    $d = [Windows.Markup.XamlReader]::Parse($OwnerPromptXaml)
    if ($Owner) { $d.Owner = $Owner; $d.Resources.MergedDictionaries.Add($Owner.Resources) }
    $d.FindName('Info').Text = "The selected $Count agent(s) will be assigned to the person you pick."
    $script:picker = @{ Window = $d; Search = $d.FindName('Search'); List = $d.FindName('Users'); Ok = $d.FindName('BtnOk'); Note = $d.FindName('Note'); Chosen = $null }
    $script:picker.Run = {
        $script:picker.Note.Text = 'Searching...'
        try {
            $found = @(Find-DirectoryUsers -Text $script:picker.Search.Text)
            $script:picker.List.Items.Clear()
            foreach ($u in $found) {
                $item = New-Object Windows.Controls.ListBoxItem
                $item.Content = ('{0}    ({1})' -f $u.Name, $u.Upn); $item.Tag = $u; $item.Padding = '8,6'
                [void]$script:picker.List.Items.Add($item)
            }
            $script:picker.Note.Text = if ($found.Count -eq 0) { 'No matching enabled users.' }
                                       elseif ($found.Count -ge 40) { 'Showing the first 40. Type more to narrow the list.' }
                                       else { "$($found.Count) user(s). Select one." }
        } catch { $script:picker.Note.Text = 'Could not read the directory: ' + $_.Exception.Message }
    }
    $timer = New-Object Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(350)
    $script:picker.Timer = $timer
    $timer.Add_Tick({ $script:picker.Timer.Stop(); & $script:picker.Run })
    $script:picker.Search.Add_TextChanged({ $script:picker.Timer.Stop(); $script:picker.Timer.Start() })
    $script:picker.List.Add_SelectionChanged({
        $sel = $script:picker.List.SelectedItem
        $script:picker.Chosen = if ($sel) { $sel.Tag } else { $null }
        $script:picker.Ok.IsEnabled = [bool]$script:picker.Chosen
    })
    $script:picker.List.Add_MouseDoubleClick({ if ($script:picker.Chosen) { $script:picker.Window.DialogResult = $true } })
    $script:picker.Ok.Add_Click({ $script:picker.Window.DialogResult = $true })
    $d.Add_ContentRendered({ $script:picker.Search.Focus(); if ($script:picker.List.Items.Count -eq 0) { & $script:picker.Run } })
    $d
}

# Ask who should own the selected agents. Returns the chosen user ({ Id, Name, Upn }) or $null when cancelled.
function Read-OwnerPrompt {
    param([int]$Count, [System.Windows.Window]$Owner)
    $d = New-OwnerPicker -Count $Count -Owner $Owner
    if ($d.ShowDialog() -and $script:picker.Chosen) { return $script:picker.Chosen }
    $null
}

# Owner as shown in the grid: the UPN, a marker when the account is gone, blank when there is no owner.
function Get-OwnerLabel {
    param([object]$Package)
    if (-not $Package.ownerId -or $Package.ownerId -eq '00000000-0000-0000-0000-000000000000') { return '' }
    $u = Get-UserInfo $Package.ownerId
    if ($u.Exists) { if ($u.Enabled) { $u.Upn } else { "$($u.Upn) (disabled)" } } else { '(account no longer exists)' }
}

$DetailXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Agent details" Width="1040" Height="700" MinWidth="760" MinHeight="480" ShowInTaskbar="False"
        WindowStartupLocation="CenterOwner" Background="#F3F4F6" FontFamily="Segoe UI" FontSize="13" UseLayoutRounding="True">
  <Window.Resources>
    <Style TargetType="TabItem">
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="bd" Padding="12,9" Margin="0,0,2,0" Background="Transparent" BorderBrush="Transparent" BorderThickness="0,0,0,2" Cursor="Hand" TextElement.Foreground="#4B5563" TextElement.FontWeight="SemiBold">
              <ContentPresenter ContentSource="Header" HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Background" Value="#EEF2F7"/></Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="bd" Property="BorderBrush" Value="#0F6CBD"/>
                <Setter TargetName="bd" Property="TextElement.Foreground" Value="#0F6CBD"/>
                <Setter TargetName="bd" Property="Background" Value="White"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Wrap" TargetType="TextBlock"><Setter Property="TextWrapping" Value="Wrap"/><Setter Property="Padding" Value="0,6"/></Style>
    <Style x:Key="Grid" TargetType="DataGrid">
      <Setter Property="AutoGenerateColumns" Value="False"/><Setter Property="IsReadOnly" Value="True"/><Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="GridLinesVisibility" Value="Horizontal"/><Setter Property="HorizontalGridLinesBrush" Value="#F0F1F3"/><Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Background" Value="White"/><Setter Property="RowHeaderWidth" Value="0"/><Setter Property="CanUserAddRows" Value="False"/>
    </Style>
  </Window.Resources>
  <Grid>
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <Border Background="White" BorderBrush="#E5E7EB" BorderThickness="0,0,0,1" Padding="24,16">
      <StackPanel>
        <TextBlock x:Name="Title" FontSize="20" FontWeight="SemiBold" Foreground="#1F2937" Text="Loading..."/>
        <TextBlock x:Name="Subtitle" Foreground="#6B7280" Margin="0,2,0,0"/>
      </StackPanel>
    </Border>
    <TabControl x:Name="Tabs" Grid.Row="1" Margin="16,12,16,0" Background="White" BorderBrush="#E5E7EB">
      <TabItem x:Name="TabOverview" Header="Overview">
        <DataGrid x:Name="OvGrid" Style="{StaticResource Grid}">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Field" Binding="{Binding Field}" Width="220" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="*" ElementStyle="{StaticResource Wrap}"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>
      <TabItem x:Name="TabSharing" Header="Sharing">
        <DataGrid x:Name="ShGrid" Style="{StaticResource Grid}">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Field" Binding="{Binding Field}" Width="280" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="*" ElementStyle="{StaticResource Wrap}"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>
      <TabItem x:Name="TabTools" Header="Tools and MCP">
        <DataGrid x:Name="ToolGrid" Style="{StaticResource Grid}">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Kind" Binding="{Binding Kind}" Width="100" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="1.3*" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="110" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Authentication" Binding="{Binding Authentication}" Width="120" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Approval" Binding="{Binding Approval}" Width="90" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="2*" ElementStyle="{StaticResource Wrap}"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>
      <TabItem x:Name="TabData" Header="Data">
        <DataGrid x:Name="DataGrid2" Style="{StaticResource Grid}">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Kind" Binding="{Binding Kind}" Width="160" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="*" ElementStyle="{StaticResource Wrap}"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>
      <TabItem x:Name="TabPerms" Header="Permissions">
        <DataGrid x:Name="PermGrid" Style="{StaticResource Grid}">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Held by" Binding="{Binding Source}" Width="170" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Kind" Binding="{Binding Kind}" Width="100" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Resource" Binding="{Binding Resource}" Width="1.3*" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Permission" Binding="{Binding Permission}" Width="1.6*" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Consent" Binding="{Binding Consent}" Width="110" ElementStyle="{StaticResource Wrap}"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>
      <TabItem x:Name="TabIdentity" Header="Identity">
        <DataGrid x:Name="IdGrid" Style="{StaticResource Grid}">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Field" Binding="{Binding Field}" Width="260" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="*" ElementStyle="{StaticResource Wrap}"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>
      <TabItem x:Name="TabUsage" Header="Usage">
        <DataGrid x:Name="UsGrid" Style="{StaticResource Grid}">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Field" Binding="{Binding Field}" Width="260" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="*" ElementStyle="{StaticResource Wrap}"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>
      <TabItem x:Name="TabRisk" Header="Risk">
        <DataGrid x:Name="RiskGrid" Style="{StaticResource Grid}">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Field" Binding="{Binding Field}" Width="260" ElementStyle="{StaticResource Wrap}"/>
            <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="*" ElementStyle="{StaticResource Wrap}"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>
    </TabControl>
    <Border Grid.Row="2" Padding="16,12" Margin="0,8,0,0">
      <Grid>
        <TextBlock x:Name="Note" Foreground="#6B7280" VerticalAlignment="Center" FontSize="12"/>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
          <Button x:Name="BtnExport" Content="Export JSON" Style="{DynamicResource Btn}" Margin="0,0,8,0"/>
          <Button x:Name="BtnClose" Content="Close" Style="{DynamicResource BtnAccent}" IsCancel="True" MinWidth="100"/>
        </StackPanel>
      </Grid>
    </Border>
  </Grid>
</Window>
'@

function ConvertTo-FieldRows {
    param($Dictionary)
    @($Dictionary.Keys | ForEach-Object { [pscustomobject]@{ Field = $_; Value = [string]$Dictionary[$_] } } | Where-Object { $_.Value -ne '' })
}

# Fill the details window from a detail object.
function Set-DetailWindowContent {
    param([System.Windows.Window]$Window, [object]$Detail)
    $f = { param($n) $Window.FindName($n) }
    (& $f 'Title').Text = $Detail.Name
    (& $f 'Subtitle').Text = ('{0}   |   {1}   |   {2}' -f $Detail.Overview.Kind, $Detail.Overview.Platform, $Detail.Overview.Status)
    (& $f 'OvGrid').ItemsSource = ConvertTo-FieldRows $Detail.Overview
    (& $f 'ShGrid').ItemsSource = ConvertTo-FieldRows $Detail.Sharing
    $tools = @($Detail.McpServers | ForEach-Object { [pscustomobject]@{ Kind = 'MCP server'; Name = $_.Name; Type = $_.Type; Authentication = $_.Authentication; Approval = $_.Approval; Description = $_.Description } }) +
             @($Detail.Tools | ForEach-Object { [pscustomobject]@{ Kind = 'Tool'; Name = $_.Name; Type = $_.Type; Authentication = $_.Authentication; Approval = $_.Approval; Description = $_.Description } })
    (& $f 'ToolGrid').ItemsSource = $tools
    (& $f 'TabTools').Header = "Tools and MCP ($($tools.Count))"
    $data = @($Detail.DataSources | ForEach-Object { [pscustomobject]@{ Kind = 'Data source'; Value = $_ } }) +
            @($Detail.Capabilities | ForEach-Object { [pscustomobject]@{ Kind = 'Capability'; Value = $_ } }) +
            @($Detail.ConnectedAgents | ForEach-Object { [pscustomobject]@{ Kind = 'Connected agent'; Value = $_ } }) +
            @($Detail.Endpoints | ForEach-Object { [pscustomobject]@{ Kind = 'Endpoint'; Value = $_ } })
    (& $f 'DataGrid2').ItemsSource = $data
    (& $f 'TabData').Header = "Data ($($data.Count))"
    (& $f 'PermGrid').ItemsSource = @($Detail.Permissions)
    (& $f 'TabPerms').Header = "Permissions ($(@($Detail.Permissions).Count))"
    (& $f 'IdGrid').ItemsSource = ConvertTo-FieldRows $Detail.Identity
    (& $f 'UsGrid').ItemsSource = ConvertTo-FieldRows $Detail.Usage
    (& $f 'RiskGrid').ItemsSource = ConvertTo-FieldRows $Detail.Risk
    $riskSeverity = $Detail.Risk['Severity']
    (& $f 'TabRisk').Header = if ($riskSeverity) { "Risk ($riskSeverity)" } else { 'Risk' }
    $noPerms = if (@($Detail.Permissions).Count -eq 0) { 'No permissions found for the agent identity or its blueprint.' } else { '' }
    (& $f 'Note').Text = $noPerms
}

# Build the details window (not yet shown) for one grid row.
function New-DetailWindow {
    param([object]$Row, [System.Windows.Window]$Owner)
    $d = [Windows.Markup.XamlReader]::Parse($DetailXaml)
    if ($Owner) { $d.Owner = $Owner; $d.Resources.MergedDictionaries.Add($Owner.Resources) }
    $d.FindName('Title').Text = $Row.Name
    $d.FindName('Subtitle').Text = 'Loading the full record...'
    $script:detailState = @{ Window = $d; Row = $Row; Detail = $null }
    $d.FindName('BtnExport').Add_Click({
        if (-not $script:detailState.Detail) { return }
        $dlg = New-Object Microsoft.Win32.SaveFileDialog
        $dlg.Filter = 'JSON (*.json)|*.json'; $dlg.FileName = ('{0}.json' -f ($script:detailState.Detail.Name -replace '[^\w\-. ]', '_'))
        if ($dlg.ShowDialog()) { $script:detailState.Detail | ConvertTo-Json -Depth 8 | Set-Content -Path $dlg.FileName -Encoding utf8 }
    })
    $d.Add_ContentRendered({
        if ($script:detailState.Detail) { return }
        $w = $script:detailState.Window
        try {
            $w.Cursor = [Windows.Input.Cursors]::Wait
            $table = $script:ctx.InfoTable
            $script:detailState.Detail = Get-AgentDetail -Package $script:detailState.Row.Package -InfoTable $table
            Set-DetailWindowContent -Window $w -Detail $script:detailState.Detail
        } catch {
            $w.FindName('Subtitle').Text = 'Could not read the record: ' + $_.Exception.Message
        } finally { $w.Cursor = $null }
    })
    $d
}

function New-ConsoleWindow {
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
    $script:w = [Windows.Markup.XamlReader]::Parse($GuiXaml)
    $script:ui = @{}
    foreach ($n in 'Account', 'CountTotal', 'CountBlocked', 'CountShown', 'BtnRefresh', 'Search', 'FltAll', 'FltActive', 'FltBlocked',
                   'AgentsOnlyBox', 'StaleBox', 'NeverSeenBox', 'RiskBox', 'SignalBox', 'BtnReset', 'OwnerBox', 'BlockedBox', 'IdentityBox', 'BtnAssign', 'BtnApplyOwner', 'DetailColsBox', 'BtnDetails', 'ToolsBox', 'PermBox', 'MatchAll', 'MatchAny', 'MatchNote',
                    'Grid', 'HeaderCheck', 'EmptyNote', 'EmptyText', 'SelectedText', 'BtnSelectVisible', 'BtnClearSel',
                   'BtnExport', 'BtnUndo', 'BtnUnblock', 'BtnBlock', 'Status') { $script:ui[$n] = $script:w.FindName($n) }

    $script:ctx = @{ Window = $script:w; UI = $script:ui; Rows = $null; View = $null; InfoTable = $null; ToolsSet = $null; PermSet = $null; PermCache = @{}; StaleSet = $null; RiskSet = $null; OwnerSet = $null; BlockedSet = $null; Suggest = @{}; LastRun = @() }
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
        $script:ui.BtnAssign.IsEnabled  = @($checked | Where-Object { Test-Reassignable $_.Package }).Count -gt 0
        $script:ui.BtnApplyOwner.IsEnabled = @($checked | Where-Object { $script:ctx.Suggest.ContainsKey($_.Id) }).Count -gt 0
        $shown = [int]$script:ui.CountShown.Text
        $script:ui.EmptyNote.Visibility = if ($shown -eq 0) { 'Visible' } else { 'Collapsed' }
        $script:ui.EmptyText.Text = if ($rows.Count -eq 0) { 'No agents loaded.' } else { 'No agents match the current filters.' }
    }

    $script:ctx.Filter = {
        param($o)
        if ($script:ui.FltActive.IsChecked  -and $o.IsBlocked)       { return $false }
        if ($script:ui.FltBlocked.IsChecked -and -not $o.IsBlocked)  { return $false }
        if ($script:ui.AgentsOnlyBox.IsChecked -and $o.Hosts -notmatch 'Copilot') { return $false }
        if ($script:ctx.OwnerSet   -and -not $script:ctx.OwnerSet.Contains($o.Id))   { return $false }
        if ($script:ctx.BlockedSet -and -not $script:ctx.BlockedSet.Contains($o.Id)) { return $false }
        if ($null -ne $script:ctx.ToolsSet -and -not $script:ctx.ToolsSet.Contains($o.Id)) { return $false }
        if ($null -ne $script:ctx.PermSet  -and -not $script:ctx.PermSet.Contains($o.Id))  { return $false }
        if ($null -ne $script:ctx.OwnerSet   -and $script:ctx.OwnerSet.Count -eq 0)   { return $false }
        if ($null -ne $script:ctx.BlockedSet -and $script:ctx.BlockedSet.Count -eq 0) { return $false }
        $sets = @(); foreach ($s in $script:ctx.StaleSet, $script:ctx.RiskSet) { if ($null -ne $s) { $sets += , $s } }
        if ($sets.Count) {
            $hits = @($sets | Where-Object { $_.Contains($o.Id) }).Count
            if ($script:ui.MatchAny.IsChecked) { if ($hits -eq 0) { return $false } }
            elseif ($hits -ne $sets.Count) { return $false }
        }
        $q = $script:ui.Search.Text.Trim()
        if ($q -and -not (($o.Name, $o.Publisher, $o.Platform, $o.Kind, $o.ToolsText, $o.Mcp, $o.Id) -join ' ').ToLower().Contains($q.ToLower())) { return $false }
        $true
    }
    $script:ctx.View.Filter = [Predicate[object]]$script:ctx.Filter

    $script:ctx.FilterActive = {
        [bool]($script:ui.Search.Text.Trim() -or $script:ui.FltActive.IsChecked -or $script:ui.FltBlocked.IsChecked -or
               $script:ui.AgentsOnlyBox.IsChecked -or $null -ne $script:ctx.StaleSet -or $null -ne $script:ctx.RiskSet -or
               $null -ne $script:ctx.OwnerSet -or $null -ne $script:ctx.BlockedSet -or $null -ne $script:ctx.ToolsSet -or $null -ne $script:ctx.PermSet)
    }
    $script:ctx.MatchNoteText = {
        $n = 0; foreach ($s in $script:ctx.StaleSet, $script:ctx.RiskSet) { if ($null -ne $s) { $n++ } }
        $script:ui.MatchNote.Text = if ($n -lt 2) { 'applies when both Stale and Risk are set' }
                                    elseif ($script:ui.MatchAny.IsChecked) { 'agents matching either Stale or Risk' } else { 'agents matching both Stale and Risk' }
    }
    $script:ctx.Refilter = { & $script:ctx.MatchNoteText; $script:ctx.View.Refresh(); & $script:ctx.Summary; & $script:ctx.Columns; $script:ui.BtnReset.IsEnabled = (& $script:ctx.FilterActive) }

    $script:ctx.Load = {
        & $script:ctx.Busy 'Loading the catalog...'
        try {
            $pkgs = @(Get-Packages)
            & $script:ctx.Busy ("Resolving owners of {0} agents..." -f $pkgs.Count)
            Initialize-UserCache -Ids @($pkgs | ForEach-Object { $_.ownerId })
            $script:ctx.Rows.Clear(); & $script:ctx.ResetFilters
            foreach ($p in ($pkgs | Sort-Object displayName)) {
                $r = New-Object AgentRow
                $r.Id = $p.id; $r.Name = $p.displayName; $r.Publisher = $p.publisher
                $r.Platform = if ($p.platform -and $p.platform -ne 'Not Available') { $p.platform } else { [string]$p.type }
                $r.Hosts = ($p.supportedHosts) -join ','
                $r.Owner = Get-OwnerLabel $p
                $r.Kind = Get-TypeLabel $p.type
                $r.IsBlocked = [bool]$p.isBlocked
                $r.Modified = if ($p.lastModifiedDateTime) { ([datetimeoffset]$p.lastModifiedDateTime).ToString('yyyy-MM-dd') } else { '' }
                $r.Package = $p
                $r.IdleSort = -1; $r.RiskSort = 0; $r.AlertsSort = 0
                $r.add_PropertyChanged({ param($s, $e) if ($e.PropertyName -eq 'Checked' -or $e.PropertyName -eq 'IsBlocked') { & $script:ctx.Summary } })
                $script:ctx.Rows.Add($r)
            }
            & $script:ctx.FillInfo
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
        $script:ui.OwnerBox.SelectedIndex = 0; $script:ui.BlockedBox.SelectedIndex = 0; $script:ui.ToolsBox.SelectedIndex = 0; $script:ui.PermBox.SelectedIndex = 0
        & $script:ctx.ClearStale; & $script:ctx.ClearRisk; & $script:ctx.ClearOwner; & $script:ctx.ClearBlocked; & $script:ctx.ClearTools; & $script:ctx.ClearPerm
        $script:ctx.Resetting = $false
    }

    $script:ctx.ClearTools = { $script:ctx.ToolsSet = $null }
    $script:ctx.ClearPerm  = { foreach ($r in $script:ctx.Rows) { $r.PermNote = '' }; $script:ctx.PermSet = $null }

    # Make sure Defender's per-agent tool records are loaded (once per refresh).
    $script:ctx.EnsureInfo = {
        if ($script:ctx.InfoTable) { return $true }
        & $script:ctx.Busy 'Reading Defender agent records...'
        try { $script:ctx.InfoTable = Get-AgentInfoTable; & $script:ctx.FillInfo; return $true }
        catch { & $script:ctx.Idle 'Could not read agent records.'; [void][Windows.MessageBox]::Show($_.Exception.Message, 'Agent records', 'OK', 'Error'); return $false }
    }

    # Agents by what they declare: an MCP server, any tools, or none.
    $script:ctx.RunTools = {
        & $script:ctx.ClearTools
        $mode = [string]$script:ui.ToolsBox.SelectedItem.Tag
        if (-not $mode) { & $script:ctx.Refilter; & $script:ctx.Idle 'Tools filter cleared.'; return }
        if (-not (& $script:ctx.EnsureInfo)) { $script:ui.ToolsBox.SelectedIndex = 0; return }
        $set = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($r in $script:ctx.Rows) {
            $i = $script:ctx.InfoTable[$r.Id.ToLower()]
            $tools = @(Get-ItemList $i.Tools).Count; $mcp = @(Get-ItemList $i.McpServers).Count
            $hit = switch ($mode) { 'mcp' { $mcp -gt 0 } 'tools' { $tools -gt 0 -or $mcp -gt 0 } 'none' { $tools -eq 0 -and $mcp -eq 0 } }
            if ($hit) { [void]$set.Add($r.Id) }
        }
        $script:ctx.ToolsSet = $set
        & $script:ctx.Refilter
        & $script:ctx.Idle ("{0} agent(s) match: {1}." -f $set.Count, $script:ui.ToolsBox.SelectedItem.Content.ToLower())
    }

    # Agents by the Entra permissions their identity holds. Scans every agent that has an identity; results are cached.
    $script:ctx.RunPerm = {
        & $script:ctx.ClearPerm
        $mode = [string]$script:ui.PermBox.SelectedItem.Tag
        if (-not $mode) { & $script:ctx.Refilter; & $script:ctx.Idle 'Permissions filter cleared.'; return }
        if (-not (& $script:ctx.EnsureInfo)) { $script:ui.PermBox.SelectedIndex = 0; return }
        try {
            $withIdentity = @($script:ctx.Rows | Where-Object { $_.Package.agentIdentityId })
            $todo = @($withIdentity | Where-Object { -not $script:ctx.PermCache.ContainsKey($_.Id) })
            if ($todo.Count) {
                & $script:ctx.Busy ("Reading Entra permissions for {0} agents..." -f $todo.Count)
                $items = @($todo | ForEach-Object { @{ Key = $_.Id; ServicePrincipalId = $_.Package.agentIdentityId; BlueprintAppId = $script:ctx.InfoTable[$_.Id.ToLower()].BlueprintId } })
                $got = Get-PermissionsBulk -Items $items
                foreach ($k in $got.Keys) { $script:ctx.PermCache[$k] = $got[$k] }
            }            $set = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($r in $withIdentity) {
                $p = @($script:ctx.PermCache[$r.Id])
                if (Test-PermissionMatch -Perms $p -Mode $mode) {
                    [void]$set.Add($r.Id)
                    $r.PermNote = (($p | Select-Object -First 4 | ForEach-Object { "$($_.Resource): $($_.Permission)" }) -join '; ') + $(if ($p.Count -gt 4) { " (+$($p.Count - 4) more)" } else { '' })
                }
            }
            $script:ctx.PermSet = $set
            & $script:ctx.Refilter
            & $script:ctx.Idle ("{0} agent(s): {1}. Only agents with an Entra identity were checked ({2})." -f $set.Count, $script:ui.PermBox.SelectedItem.Content.ToLower(), $withIdentity.Count)
        } catch {
            $script:ui.PermBox.SelectedIndex = 0; & $script:ctx.Refilter
            & $script:ctx.Idle 'Permissions scan failed.'; [void][Windows.MessageBox]::Show($_.Exception.Message, 'Permissions', 'OK', 'Error')
        }
    }
    # Copy Defender's declared tools, MCP servers, sharing and channels onto the grid rows.
    $script:ctx.FillInfo = {
        if (-not $script:ctx.InfoTable) { return }
        foreach ($r in $script:ctx.Rows) {
            $i = $script:ctx.InfoTable[$r.Id.ToLower()]
            if (-not $i) { $r.ToolCount = '0'; $r.ToolCountSort = 0; continue }
            $toolCount = @(Get-ItemList $i.Tools).Count
            $r.ToolCount = [string]$toolCount; $r.ToolCountSort = $toolCount
            $r.ToolsText = Get-NameText $i.Tools; $r.Mcp = Get-NameText $i.McpServers
            $r.SharedCount = [string]@(Get-ItemList $i.SharedWith).Count; $r.Channels = ($i.Channels -join ', ')
        }
    }

    # Show only the columns that matter for the filters that are on.
    $script:ctx.Columns = {
        $on = @{
            'Last activity' = ($null -ne $script:ctx.StaleSet); 'Idle days' = ($null -ne $script:ctx.StaleSet)
            'Risk' = ($null -ne $script:ctx.RiskSet); 'Alerts' = ($null -ne $script:ctx.RiskSet); 'Detections' = ($null -ne $script:ctx.RiskSet); 'Why' = ($null -ne $script:ctx.RiskSet)
            'Suggested owner' = ($null -ne $script:ctx.OwnerSet); 'Ownership note' = ($null -ne $script:ctx.OwnerSet)
            'Blocked for' = ($null -ne $script:ctx.BlockedSet)
            'Tools' = ([bool]$script:ui.DetailColsBox.IsChecked -or $null -ne $script:ctx.ToolsSet); 'MCP servers' = ([bool]$script:ui.DetailColsBox.IsChecked -or $null -ne $script:ctx.ToolsSet)
            'Shared with' = [bool]$script:ui.DetailColsBox.IsChecked; 'Channels' = [bool]$script:ui.DetailColsBox.IsChecked
            'Permissions held' = ($null -ne $script:ctx.PermSet)
        }
        $script:ui.BtnApplyOwner.Visibility = if ($null -ne $script:ctx.OwnerSet) { 'Visible' } else { 'Collapsed' }
        foreach ($c in $script:ui.Grid.Columns) {
            if ($c.Header -is [string] -and $on.ContainsKey($c.Header)) { $c.Visibility = if ($on[$c.Header]) { 'Visible' } else { 'Collapsed' } }
        }
    }

    $script:ctx.ClearOwner = {
        foreach ($r in $script:ctx.Rows) { $r.Suggested = ''; $r.OwnerNote = '' }
        $script:ctx.OwnerSet = $null; $script:ctx.Suggest = @{}
    }
    $script:ctx.ClearBlocked = {
        foreach ($r in $script:ctx.Rows) { $r.BlockedFor = ''; $r.BlockedForSort = -1 }
        $script:ctx.BlockedSet = $null
    }

    # Shared agents without a usable owner, each with the replacement the resolver would pick.
    $script:ctx.RunOwner = {
        & $script:ctx.ClearOwner
        if (-not [string]$script:ui.OwnerBox.SelectedItem.Tag) { & $script:ctx.Refilter; & $script:ctx.Idle 'Ownership filter cleared.'; return }
        & $script:ctx.Busy 'Checking owners of shared agents...'
        try {
            $report = Get-OwnerReport -Packages @($script:ctx.Rows | ForEach-Object { $_.Package })
            $set = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($i in $report.Items) {
                [void]$set.Add($i.Id)
                $row = $script:ctx.Rows | Where-Object { $_.Id -eq $i.Id } | Select-Object -First 1
                if (-not $row) { continue }
                $row.OwnerNote = $i.Reason
                if ($i.State -eq 'Proposed') { $row.Suggested = "$($i.Proposed)  ($($i.Source))"; $script:ctx.Suggest[$i.Id] = $i } else { $row.Suggested = 'Needs review' }
            }
            $script:ctx.OwnerSet = $set
            & $script:ctx.Refilter
            & $script:ctx.Idle ("{0} shared agent(s) need an owner: {1} with a suggestion, {2} to assign manually. {3} org-published agent(s) have no owner but cannot be reassigned through the API." -f
                $report.Items.Count, $script:ctx.Suggest.Count, ($report.Items.Count - $script:ctx.Suggest.Count), $report.OrgPublished)
        } catch {
            $script:ui.OwnerBox.SelectedIndex = 0; & $script:ctx.Refilter
            & $script:ctx.Idle 'Ownership check failed.'; [void][Windows.MessageBox]::Show($_.Exception.Message, 'Ownership', 'OK', 'Error')
        }
    }

    # Agents that have stayed blocked for the chosen number of days.
    $script:ctx.RunBlocked = {
        & $script:ctx.ClearBlocked
        $tag = [string]$script:ui.BlockedBox.SelectedItem.Tag
        if (-not $tag) { & $script:ctx.Refilter; & $script:ctx.Idle 'Blocked filter cleared.'; return }
        & $script:ctx.Busy 'Looking up when agents were blocked...'
        try {
            $days = [int]$tag
            $found = @(Get-DeleteCandidates -MinDays $days -IncludeUnknown:($days -eq 0))
            $set = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($c in $found) {
                [void]$set.Add($c.Id)
                $row = $script:ctx.Rows | Where-Object { $_.Id -eq $c.Id } | Select-Object -First 1
                if (-not $row) { continue }
                $row.BlockedFor = if ($null -ne $c.DaysBlocked) { "$($c.DaysBlocked) days" } else { 'unknown' }
                $row.BlockedForSort = if ($null -ne $c.DaysBlocked) { [int]$c.DaysBlocked } else { -1 }
            }
            $script:ctx.BlockedSet = $set
            & $script:ctx.Refilter
            & $script:ctx.Idle ("{0} agent(s) blocked {1}. Delete them in the admin center (Agents > All agents > Delete); the catalog API has no delete." -f $found.Count, $(if ($days -eq 0) { 'for any time' } else { "$days+ days" }))
        } catch {
            $script:ui.BlockedBox.SelectedIndex = 0; & $script:ctx.Refilter
            & $script:ctx.Idle 'Blocked filter failed.'; [void][Windows.MessageBox]::Show($_.Exception.Message, 'Blocked filter', 'OK', 'Error')
        }
    }

    # Reassign the given rows through the shared reassign routine and refresh the Owner column.
    $script:ctx.ReassignRows = {
        param([object[]]$Items, [string]$Label)
        $dir = Join-Path $env:LOCALAPPDATA 'Agent365-Bulk-Actions\logs'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $script:OutFile = Join-Path $dir ('owners-{0:yyyyMMdd-HHmmss}.csv' -f (Get-Date))
        & $script:ctx.Busy ("Reassigning {0} agent(s)..." -f $Items.Count)
        $recs = @(Invoke-OwnerReassign -Items $Items -PassThru)
        foreach ($rec in $recs) {
            if ($rec.Result -ne 'Done') { continue }
            $row = $script:ctx.Rows | Where-Object { $_.Id -eq $rec.Id } | Select-Object -First 1
            if ($row) { $row.Package.ownerId = $rec.NewOwner; $row.Owner = Get-OwnerLabel $row.Package; $row.Checked = $false }
        }
        $done = @($recs | Where-Object { $_.Result -eq 'Done' }).Count; $failed = @($recs | Where-Object { $_.Result -eq 'Failed' }).Count
        & $script:ctx.Refilter
        & $script:ctx.Idle ("{0}: {1} reassigned, {2} failed. Log: {3}" -f $Label, $done, $failed, $script:OutFile)
        if ($failed) {
            $why = ($recs | Where-Object { $_.Result -eq 'Failed' } | Select-Object -First 5 | ForEach-Object { "$($_.DisplayName): $($_.Error)" }) -join "`n"
            [void][Windows.MessageBox]::Show("$failed agent(s) failed:`n`n$why", 'Some reassignments failed', 'OK', 'Warning')
        }
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
        $script:DisableIdentity = [bool]$script:ui.IdentityBox.IsChecked
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
    $script:ui.DetailColsBox.Add_Click({
        if ($script:ui.DetailColsBox.IsChecked -and -not $script:ctx.InfoTable) {
            & $script:ctx.Busy 'Reading Defender agent records...'
            try { $script:ctx.InfoTable = Get-AgentInfoTable; & $script:ctx.FillInfo; & $script:ctx.Idle 'Tools and sharing columns loaded.' }
            catch { $script:ui.DetailColsBox.IsChecked = $false; & $script:ctx.Idle 'Could not read agent records.'; [void][Windows.MessageBox]::Show($_.Exception.Message, 'Tools and sharing columns', 'OK', 'Error') }
        }
        & $script:ctx.Refilter
    })
    $script:ctx.ShowDetails = {
        $row = $script:ui.Grid.SelectedItem
        if (-not $row) { return }
        (New-DetailWindow -Row $row -Owner $script:w).ShowDialog() | Out-Null
    }
    $script:ui.BtnDetails.Add_Click({ & $script:ctx.ShowDetails })
    $script:ui.Grid.Add_MouseDoubleClick({ param($s, $e) if ($e.OriginalSource -is [Windows.Controls.TextBlock] -or $e.OriginalSource -is [Windows.Controls.Border]) { & $script:ctx.ShowDetails } })
    $script:ui.Grid.Add_SelectionChanged({ $script:ui.BtnDetails.IsEnabled = ($null -ne $script:ui.Grid.SelectedItem) })
    $script:ui.ToolsBox.Add_SelectionChanged({ if (-not $script:ctx.Resetting) { & $script:ctx.RunTools } })
    $script:ui.PermBox.Add_SelectionChanged({ if (-not $script:ctx.Resetting) { & $script:ctx.RunPerm } })
    $script:ui.OwnerBox.Add_SelectionChanged({ if (-not $script:ctx.Resetting) { & $script:ctx.RunOwner } })
    $script:ui.BlockedBox.Add_SelectionChanged({ if (-not $script:ctx.Resetting) { & $script:ctx.RunBlocked } })

    $script:ui.BtnApplyOwner.Add_Click({
        $rows = @($script:ctx.Rows | Where-Object { $_.Checked -and $script:ctx.Suggest.ContainsKey($_.Id) })
        if ($rows.Count -eq 0) { return }
        $items = @($rows | ForEach-Object { $s = $script:ctx.Suggest[$_.Id]
            [pscustomobject]@{ Id = $_.Id; DisplayName = $_.Name; CurrentOwnerId = $_.Package.ownerId; NewOwnerId = $s.ProposedId; NewOwnerUpn = $s.Proposed; Source = $s.Source } })
        $names = ($items | Select-Object -First 12 | ForEach-Object { "  - $($_.DisplayName)  ->  $($_.NewOwnerUpn)" }) -join "`n"
        if ([Windows.MessageBox]::Show("Assign the suggested owner to $($items.Count) agent(s)?`n`n$names", 'Confirm the action', 'YesNo', 'Question', 'No') -ne 'Yes') { return }
        & $script:ctx.ReassignRows $items 'Apply suggested owners'
    })

    $script:ui.BtnAssign.Add_Click({
        $checked = @($script:ctx.Rows | Where-Object { $_.Checked })
        $rows = @($checked | Where-Object { Test-Reassignable $_.Package })
        if ($rows.Count -eq 0) { return }
        $owner = Read-OwnerPrompt -Count $rows.Count -Owner $script:w
        if (-not $owner) { return }
        $items = @($rows | Where-Object { $_.Package.ownerId -ne $owner.Id } | ForEach-Object {
            [pscustomobject]@{ Id = $_.Id; DisplayName = $_.Name; CurrentOwnerId = $_.Package.ownerId; NewOwnerId = $owner.Id; NewOwnerUpn = $owner.Upn; Source = 'Manual' } })
        if ($items.Count -eq 0) { & $script:ctx.Idle 'Those agents already belong to that user.'; return }
        if ($checked.Count -gt $rows.Count) {
            [void][Windows.MessageBox]::Show(("{0} of the {1} selected agents are not shared agents and were left out: only shared agents can be reassigned." -f ($checked.Count - $rows.Count), $checked.Count), 'Assign owner', 'OK', 'Information')
        }
        & $script:ctx.ReassignRows $items 'Assign owner'
    })
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
        $out = @($script:ctx.View | Select-Object Name, Status, Kind, Platform, Publisher, Owner, ToolCount, Mcp, SharedCount, Channels, Modified, LastActivity, Idle, Risk, Alerts, Detections, Why, Id)
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

if ($script:LoadOnly) { return }

switch ($PSCmdlet.ParameterSetName) {
    'Gui' { Show-Console }
    'List' {
        Get-Packages -AgentsOnly:$AgentsOnly |
            Select-Object displayName, id, isBlocked,
                          @{ n = 'hosts'; e = { ($_.supportedHosts) -join ',' } }, type |
            Sort-Object isBlocked, displayName |
            Format-Table -AutoSize
    }
    'Detail' {
        $pkg = @(Resolve-Packages $Detail)[0]
        Write-Host ("Reading {0}..." -f $pkg.displayName) -ForegroundColor DarkGray
        $det = Get-AgentDetail -Package $pkg
        Show-AgentDetail -Detail $det
        if ($OutFile) { $det | ConvertTo-Json -Depth 8 | Set-Content -Path $OutFile -Encoding utf8; Write-Host "Saved: $OutFile" -ForegroundColor Cyan }
    }
    'Inventory' {
        $pk = @(Get-Packages -AgentsOnly:$AgentsOnly)
        Write-Host ("Reading Defender agent records for {0} package(s)..." -f $pk.Count) -ForegroundColor DarkGray
        $rows = @(Get-InventoryRows -Packages $pk -InfoTable (Get-AgentInfoTable) -Deep:$Deep -WithPermissions:$WithPermissions)
        Write-Host ("`n{0} agent(s): {1} shared by a creator, {2} org-published, {3} with declared tools, {4} using MCP servers, {5} blocked." -f
            $rows.Count, @($rows | Where-Object { $_.Kind -eq 'Shared by a creator' }).Count, @($rows | Where-Object { $_.Kind -eq 'Org-published' }).Count,
            @($rows | Where-Object { $_.ToolCount -gt 0 }).Count, @($rows | Where-Object { $_.McpServers }).Count, @($rows | Where-Object { $_.Status -eq 'Blocked' }).Count) -ForegroundColor Cyan
        $rows | Select-Object Name, Kind, Platform, Status, Owner, ToolCount, McpServers | Format-Table -AutoSize | Out-Host
        Export-ActionLog -Records $rows
    }
    'Policy' {
        if (-not (Test-Path -LiteralPath $Policy)) { throw "Policy file not found: $Policy" }
        $doc = Get-Content -Raw -LiteralPath $Policy | ConvertFrom-Json
        Write-Host ("Policy: {0} ({1} rule(s))" -f $(if ($doc.name) { $doc.name } else { $Policy }), @($doc.rules).Count) -ForegroundColor Cyan
        Invoke-PolicyPlan -Plan @(Get-PolicyPlan -PolicyDoc $doc) -Apply:$Apply
    }
    'Snapshot' {
        $catalog = @(Get-Packages)
        if ($CompareTo) {
            if (-not (Test-Path -LiteralPath $CompareTo)) { throw "Snapshot not found: $CompareTo" }
            $old = Get-Content -Raw -LiteralPath $CompareTo | ConvertFrom-Json
            $changes = @(Compare-Snapshot -Old $old -Current $catalog)
            Write-Host ("`nChanges since {0}: {1}" -f $old.takenAt, $changes.Count) -ForegroundColor Cyan
            if ($changes.Count) { $changes | Sort-Object Change, Agent | Format-Table -AutoSize -Wrap | Out-Host }
            if ($OutFile) { Export-ActionLog -Records $changes }
        }
        Save-Snapshot -Path $Snapshot -Packages $catalog
        Write-Host ("Snapshot of {0} package(s) saved to {1}" -f $catalog.Count, $Snapshot) -ForegroundColor Cyan
    }
    'DeleteCandidates' {
        $c = @(Get-DeleteCandidates -MinDays $MinDaysBlocked -HistoryPaths $History -IncludeUnknown:$IncludeUnknown)
        Write-Host ("`n{0} blocked agent(s) have been blocked {1}+ days{2}." -f $c.Count, $MinDaysBlocked, $(if ($IncludeUnknown) { ' (or for an unknown time)' } else { '' })) -ForegroundColor Cyan
        if ($c.Count -eq 0) { break }
        $c | Format-Table -AutoSize | Out-Host
        Export-ActionLog -Records $c
        Write-Host 'This tool does not delete agents: the catalog API has no delete. Delete them in the admin center (Agents > All agents > Delete, then Deleted > Permanently delete).' -ForegroundColor Yellow
    }
    'Ownerless' {
        $report = Get-OwnerReport -Packages @(Get-Packages)
        Write-Host ("`nShared agents: {0} have a valid owner, {1} need attention. {2} org-published agent(s) have no owner but cannot be reassigned through the API." -f
            $report.OkCount, $report.Items.Count, $report.OrgPublished) -ForegroundColor Cyan
        if ($report.Items.Count -eq 0) { break }
        Show-OwnerPreview -Items $report.Items
        $proposed = @($report.Items | Where-Object { $_.State -eq 'Proposed' })
        $review = @($report.Items | Where-Object { $_.State -eq 'Needs review' })
        Write-Host ("{0} proposed, {1} flagged for review (no owner could be derived; assign manually with -Reassign <agent> -To <user>)." -f $proposed.Count, $review.Count) -ForegroundColor Cyan
        if ($Action -ne 'reassign' -or $proposed.Count -eq 0) { break }
        $items = @($proposed | ForEach-Object { $_ | Add-Member -NotePropertyName NewOwnerId -NotePropertyValue $_.ProposedId -Force -PassThru |
                                                   Add-Member -NotePropertyName NewOwnerUpn -NotePropertyValue $_.Proposed -Force -PassThru })
        if (-not (Confirm-Batch -Count $items.Count -Action 'reassign')) { Write-Host 'Cancelled.'; break }
        Invoke-OwnerReassign -Items $items
    }
    'Reassign' {
        $owner = Get-UserInfo $To
        if (-not $owner.Exists -or -not $owner.Enabled) { throw "'$To' is not an existing, enabled user." }
        $targets = @(Resolve-Packages $Reassign)
        $skipped = @($targets | Where-Object { -not (Test-Reassignable $_) })
        if ($skipped.Count) {
            Write-Warning ("Only shared agents can be reassigned through the API. Skipped: {0}" -f (($skipped | ForEach-Object { "$($_.displayName) [$($_.type)]" }) -join '; '))
        }
        $items = @($targets | Where-Object { (Test-Reassignable $_) -and $_.ownerId -ne $owner.Id } | ForEach-Object {
            [pscustomobject]@{ Id = $_.id; DisplayName = $_.displayName; Platform = $_.platform; CurrentOwnerId = $_.ownerId; CurrentOwner = ''
                               State = 'Manual'; Reason = ''; Proposed = $owner.Upn; Source = 'Manual'; NewOwnerId = $owner.Id; NewOwnerUpn = $owner.Upn } })
        Write-Host ("{0} agent(s) will be assigned to {1}." -f $items.Count, $owner.Upn) -ForegroundColor Cyan
        if ($items.Count -eq 0) { break }
        Show-OwnerPreview -Items $items
        if (-not (Confirm-Batch -Count $items.Count -Action 'reassign')) { Write-Host 'Cancelled.'; break }
        Invoke-OwnerReassign -Items $items
    }
    'Undo' {
        if (-not (Test-Path -LiteralPath $Undo)) { throw "Log not found: $Undo" }
        $rows = if ($Undo -match '\.json$') { @(Get-Content -Raw -LiteralPath $Undo | ConvertFrom-Json) }
                else { @(Import-Csv -LiteralPath $Undo) }
        $changed = @($rows | Where-Object { $_.Result -eq 'Done' -and $_.Action -in 'block', 'unblock' })
        $ownerChanges = @($rows | Where-Object { $_.Result -eq 'Done' -and $_.Action -eq 'reassign' })
        if ($ownerChanges.Count -gt 0) {
            $back = foreach ($r in $ownerChanges) {
                $prev = Get-UserInfo $r.WasOwner
                if (-not $prev.Exists -or -not $prev.Enabled) { Write-Warning ('Cannot restore the owner of {0}: the previous owner no longer exists or is disabled.' -f $r.DisplayName); continue }
                [pscustomobject]@{ Id = $r.Id; DisplayName = $r.DisplayName; CurrentOwnerId = $r.NewOwner; NewOwnerId = $prev.Id; NewOwnerUpn = $prev.Upn; Source = 'Undo' }
            }
            $back = @($back)
            if ($back.Count -gt 0 -and (Confirm-Batch -Count $back.Count -Action 'reassign')) { Invoke-OwnerReassign -Items $back }
        }
        if ($changed.Count -eq 0) { if ($ownerChanges.Count -eq 0) { Write-Host 'The log has no changes to undo.' }; break }
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
        if ($Impact) { Show-ImpactPreview $targets } else { $targets | Select-Object displayName, id, isBlocked | Format-Table -AutoSize | Out-Host }
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
        if ($Impact) { Show-ImpactPreview $matched }

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
        if ($Impact) { Show-ImpactPreview $matched }

        if ($Action -eq 'list') { break }

        if ($Pick) {
            $matched = @(Invoke-Picker -Packages $matched -Title "Risky agents to $Action - select which (Ctrl/Shift), then OK")
            if ($matched.Count -eq 0) { Write-Host 'Nothing selected.'; break }
        }
        if (-not (Confirm-Batch -Count $matched.Count -Action $Action -Implied:$Pick)) { Write-Host 'Cancelled.'; break }
        Invoke-PackageAction -Packages $matched -Action $Action
    }
}

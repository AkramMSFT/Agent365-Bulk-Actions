<#
.SYNOPSIS
  List, approve, or reject pending agent/app REVIEW submissions in bulk via the Microsoft
  Graph Teams App Submission API.

.DESCRIPTION
  When a member submits a custom agent/app for admin approval (custom-engine agents,
  declarative agents built with Agents Toolkit, or apps submitted via the Teams App
  Submission API), it appears in the tenant app catalog with publishingState = 'submitted'.
  This tool wraps:
    GET   /beta/appCatalogs/teamsApps?$filter=appDefinitions/any(a:a/publishingState eq 'submitted')&$expand=appDefinitions   (list pending)
    PATCH /beta/appCatalogs/teamsApps/{teamsAppId}/appDefinitions/{appDefinitionId}                                            (approve/reject)
  Approve sets publishingState = 'published'; reject sets it = 'rejected'.

  Requires the DELEGATED scope AppCatalog.ReadWrite.All (approve/reject) or AppCatalog.Read.All
  (list only), and the caller must be a Teams Service Administrator or higher. App-only is not
  supported. /beta = not for production.

  SCOPE NOTE: this acts ONLY on apps submitted to the TEAMS APP CATALOG for review
  (publishingState = 'submitted'). It does NOT cover the Microsoft 365 admin center
  "Agents > Requests" queue for agents built with Copilot Studio / Azure AI Foundry /
  Agent 365 (shown as "Pending review" / internal state "Staged"), nor blueprint
  "Pending activate" requests. Those are served by an internal admin-center API
  (admin.cloud.microsoft/fd/addins/api/actionableApps) with no documented Graph
  equivalent, so approve/reject for them remains a Microsoft 365 admin center action.
  If -List returns 0 but the admin center Requests tab shows pending agents, they are
  in that registry queue, not the Teams app catalog.

.PARAMETER TenantId
  Optional. Target a specific tenant (GUID or domain). Default = your account's home tenant.

.EXAMPLE
  # List everything awaiting review
  .\Agent365-Review-Requests.ps1 -List

.EXAMPLE
  # Approve (publish) one or many by display name and/or teamsAppId
  .\Agent365-Review-Requests.ps1 -Approve "Contoso HR Agent","06805b9e-77e3-4b93-ac81-525eb87513b8"

.EXAMPLE
  # Reject one or many
  .\Agent365-Review-Requests.ps1 -Reject "Northwind Sales Agent"

.EXAMPLE
  # Pick from the pending queue and approve (or -Action reject / -Action list)
  .\Agent365-Review-Requests.ps1 -Select
  .\Agent365-Review-Requests.ps1 -Select -Action reject

.EXAMPLE
  # Dry run (change nothing) and skip-confirmation variants
  .\Agent365-Review-Requests.ps1 -Approve "Contoso HR Agent" -Preview
  .\Agent365-Review-Requests.ps1 -Approve "Contoso HR Agent" -Force

.NOTES
  Add -DeviceCode if interactive/WAM sign-in misbehaves (for example on an unmanaged machine).
  Approving publishes the agent/app to your org catalog for the audience set by policy; review
  with -List or -Preview first.
#>
[CmdletBinding(DefaultParameterSetName = 'List')]
param(
    [Parameter(ParameterSetName = 'List')]
    [switch]$List,

    [Parameter(ParameterSetName = 'Approve', Mandatory, Position = 0)]
    [string[]]$Approve,                       # display names and/or teamsAppIds to approve (publish)

    [Parameter(ParameterSetName = 'Reject', Mandatory, Position = 0)]
    [string[]]$Reject,                        # display names and/or teamsAppIds to reject

    [Parameter(ParameterSetName = 'Select', Mandatory)]
    [switch]$Select,                          # interactive multi-select over the pending queue

    [Parameter(ParameterSetName = 'Select')]
    [ValidateSet('approve', 'reject', 'list')]
    [string]$Action = 'approve',              # what to do with the picked set ('list' = preview only)

    [Parameter(ParameterSetName = 'Approve')]
    [Parameter(ParameterSetName = 'Reject')]
    [Parameter(ParameterSetName = 'Select')]
    [switch]$Preview,                         # show the plan, change nothing

    [Parameter(ParameterSetName = 'Approve')]
    [Parameter(ParameterSetName = 'Reject')]
    [Parameter(ParameterSetName = 'Select')]
    [switch]$Force,                           # skip the confirmation prompt

    [string]$TenantId,                        # optional: target a specific tenant (default = home tenant)

    [switch]$DeviceCode
)

$ErrorActionPreference = 'Stop'
$Base = 'https://graph.microsoft.com/beta/appCatalogs/teamsApps'

# --- ensure the Graph auth module ---
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host 'Installing Microsoft.Graph.Authentication (CurrentUser)...' -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
}
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# --- sign in (delegated). List/preview need Read.All; approve/reject need ReadWrite.All ---
$readOnly = ($PSCmdlet.ParameterSetName -eq 'List') -or
            ($PSCmdlet.ParameterSetName -eq 'Select' -and $Action -eq 'list')
$scope = if ($readOnly) { 'AppCatalog.Read.All' } else { 'AppCatalog.ReadWrite.All' }
$connect = @{ Scopes = $scope; NoWelcome = $true }
if ($TenantId)   { $connect['TenantId'] = $TenantId }
if ($DeviceCode) { $connect['UseDeviceCode'] = $true }
Connect-MgGraph @connect

# Return one row per submitted app definition (carries the ids needed for the PATCH).
function Get-PendingSubmissions {
    $uri = "$Base`?`$filter=appDefinitions/any(a:a/publishingState eq 'submitted')&`$expand=appDefinitions"
    $out = @()
    do {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
        foreach ($app in $resp.value) {
            foreach ($d in @($app.appDefinitions)) {
                if ($d.publishingState -ne 'submitted') { continue }   # app may also have published defs
                $out += [pscustomobject]@{
                    displayName          = $d.displayName
                    version              = $d.version
                    teamsAppId           = $app.id
                    appDefinitionId      = $d.id
                    publishingState      = $d.publishingState
                    lastModifiedDateTime = $d.lastModifiedDateTime
                }
            }
        }
        $uri = $resp.'@odata.nextLink'
    } while ($uri)
    $out
}

# Resolve display names / teamsAppIds to pending-submission rows (fetches the queue once).
function Resolve-Submissions {
    param([string[]]$Names)
    $pending = @(Get-PendingSubmissions)
    $out = @()
    foreach ($n in $Names) {
        $hit = @($pending | Where-Object { $_.displayName -eq $n -or $_.teamsAppId -eq $n })
        if ($hit.Count -eq 0) { throw "No pending submission matches '$n'. Run -List to see the queue." }
        if ($hit.Count -gt 1) { throw "Multiple pending submissions match '$n'. Use the exact teamsAppId." }
        $out += $hit[0]
    }
    $out
}

# Interactive multi-select over the pending queue. Out-GridView if available, else numbered menu.
function Select-Submissions {
    param([object[]]$Items, [string]$Title = 'Select submissions (Ctrl/Shift for multiple), then OK')
    $items = @($Items | Sort-Object displayName)
    if ($items.Count -eq 0) { return @() }
    if (Get-Command Out-GridView -ErrorAction SilentlyContinue) {
        return @($items | Select-Object displayName, version, teamsAppId, appDefinitionId |
            Out-GridView -Title $Title -PassThru)
    }
    Write-Host "`n$Title`n" -ForegroundColor Cyan
    for ($i = 0; $i -lt $items.Count; $i++) {
        '{0,3}) {1}  (v{2}, {3})' -f ($i + 1), $items[$i].displayName, $items[$i].version, $items[$i].teamsAppId | Write-Host
    }
    $entry = Read-Host "`nSelect (e.g. 1,3,5-7 or 'all', blank to cancel)"
    if ([string]::IsNullOrWhiteSpace($entry)) { return @() }
    $idx = New-Object System.Collections.Generic.HashSet[int]
    if ($entry.Trim() -eq 'all') { 0..($items.Count - 1) | ForEach-Object { [void]$idx.Add($_) } }
    else {
        foreach ($tok in $entry -split ',') {
            $tok = $tok.Trim()
            if ($tok -match '^\d+$') { [void]$idx.Add([int]$tok - 1) }
            elseif ($tok -match '^(\d+)\s*-\s*(\d+)$') { ([int]$Matches[1]-1)..([int]$Matches[2]-1) | ForEach-Object { [void]$idx.Add($_) } }
            elseif ($tok) { Write-Warning "Ignoring '$tok'." }
        }
    }
    @($idx | Where-Object { $_ -ge 0 -and $_ -lt $items.Count } | Sort-Object | ForEach-Object { $items[$_] })
}

# Approve (publishingState=published) or reject (=rejected) each item; keep going on error.
function Invoke-ReviewAction {
    param([object[]]$Items, [ValidateSet('approve', 'reject')][string]$Action)
    if (-not $Items -or $Items.Count -eq 0) { Write-Host 'Nothing selected.'; return }
    $state = if ($Action -eq 'approve') { 'published' } else { 'rejected' }

    Write-Host ("`n{0} {1} submission(s):" -f (($Action.Substring(0,1).ToUpper()) + $Action.Substring(1)), $Items.Count) -ForegroundColor Cyan
    $Items | ForEach-Object { Write-Host ("  {0}  (v{1}, {2})" -f $_.displayName, $_.version, $_.teamsAppId) }

    if ($Preview) { Write-Host "`n(Preview only - no changes made.)" -ForegroundColor Yellow; return }
    if (-not $Force) {
        $ans = Read-Host ("`n{0} these {1} submission(s)? [y/N]" -f $Action, $Items.Count)
        if ($ans -notmatch '^(y|yes)$') { Write-Host 'Cancelled.'; return }
    }

    $ok = 0; $fail = 0
    foreach ($it in $Items) {
        try {
            Invoke-MgGraphRequest -Method PATCH `
                -Uri "$Base/$($it.teamsAppId)/appDefinitions/$($it.appDefinitionId)" `
                -Body (@{ publishingState = $state } | ConvertTo-Json) -ContentType 'application/json' | Out-Null
            Write-Host ("  OK   {0}" -f $it.displayName) -ForegroundColor Green; $ok++
        } catch {
            Write-Host ("  FAIL {0} -> {1}" -f $it.displayName, $_.Exception.Message) -ForegroundColor Red; $fail++
        }
    }
    Write-Host ("Done: {0} {1}d, {2} failed." -f $ok, $Action, $fail) -ForegroundColor Cyan
}

switch ($PSCmdlet.ParameterSetName) {
    'List' {
        $pending = @(Get-PendingSubmissions)
        Write-Host ("{0} submission(s) awaiting review." -f $pending.Count) -ForegroundColor Cyan
        $pending | Sort-Object displayName |
            Format-Table displayName, version, teamsAppId, lastModifiedDateTime -AutoSize
    }
    'Approve' { Invoke-ReviewAction -Items (Resolve-Submissions $Approve) -Action 'approve' }
    'Reject'  { Invoke-ReviewAction -Items (Resolve-Submissions $Reject)  -Action 'reject' }
    'Select'  {
        $pending = @(Get-PendingSubmissions)
        if ($pending.Count -eq 0) { Write-Host 'No submissions awaiting review.'; break }
        $picked = Select-Submissions -Items $pending -Title "Select submissions to $Action (Ctrl/Shift), then OK"
        if ($Action -eq 'list') { $picked | Format-Table displayName, version, teamsAppId -AutoSize }
        else { Invoke-ReviewAction -Items $picked -Action $Action }
    }
}

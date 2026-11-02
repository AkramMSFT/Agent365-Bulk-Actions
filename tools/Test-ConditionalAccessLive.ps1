<#
.SYNOPSIS
    Proves what Conditional Access really does to an agent, with real token requests from a throwaway agent.

.DESCRIPTION
    What If and sign-in logs show what happened or would happen. This shows it directly. It creates a throwaway agent, requests real
    tokens each way an agent can sign in, applies policies one round at a time, records when each token starts or stops being refused,
    and removes everything it made.

    It WRITES to the tenant, so run it on purpose, as an administrator:
    - An agent identity blueprint with a secret that expires in four hours, its principal, an agent identity, an agent user account,
      and delegated grants for that identity only.
    - Conditional Access policies that name only those objects, or you together with a test resource. No policy targets all users or all
      agents. Nothing outside the test is affected, with one exception: one round blocks you from Azure Resource Manager for agent-assisted
      flows, and if Entra ignored that condition you could not reach Azure Resource Manager until the round ends.
    - The last round confirms the throwaway agent as compromised, and only runs when an enforced policy blocks High agent risk.

    You sign in once with a device code as yourself, to act as the person an agent works for. A policy change can take more than 15 minutes
    to reach every sign-in, so allow over an hour. Press Ctrl+C at any time: the cleanup still runs. If a run is killed outright, -CleanupOnly
    removes whatever it left. Deleted objects stay in the directory's recycle bin for 30 days.

    Each result is PASS, FAIL or NOT SETTLED. NOT SETTLED means tokens were both issued and denied until the round ended: the policy is
    having an effect that has not reached every sign-in yet. Raise -RoundMinutes to wait longer.

    Needs a role that can create agents and manage Conditional Access, such as Global Administrator.

.PARAMETER RoundMinutes
    How long to wait for one round to settle.

.PARAMETER ResultFile
    Where to save the results as JSON. Tokens and the secret are never written anywhere.

.PARAMETER CleanupOnly
    Remove everything an earlier run left behind, found by name, and stop.

.EXAMPLE
    ./tools/Test-ConditionalAccessLive.ps1 -ResultFile ./ca-live.json
#>
param(
    [ValidateRange(5, 60)][int]$RoundMinutes = 15,
    [string]$ResultFile,
    [switch]$CleanupOnly
)
$ErrorActionPreference = 'Stop'
$kitFile = Join-Path $PSScriptRoot '..\Agent365-Bulk-Actions.ps1'
if (-not (Test-Path -LiteralPath $kitFile)) { throw "Agent365-Bulk-Actions.ps1 was not found at $kitFile" }
. $kitFile
$ErrorActionPreference = 'Stop'

$script:LivePrefix = 'A365 CA live test'
$script:AzureCliApp = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
$script:ArmApp = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
$script:OData = @{ 'OData-Version' = '4.0' }

# Every policy this script writes passes through here, so a mistake cannot reach anyone outside the test.
function Assert-LivePolicyIsNarrow {
    param([hashtable]$Body)
    $c = $Body.conditions
    if (@($c.users.includeUsers) -contains 'All' -or @($c.clientApplications.includeAgentIdServicePrincipals) -contains 'All' -or @($c.agents.includeAgentUsers) -contains 'All') { throw "Refusing to create a policy that targets everyone: $($Body.displayName)" }
    if (-not ([string]$Body.displayName).StartsWith($script:LivePrefix)) { throw "Refusing to create a policy without the test prefix: $($Body.displayName)" }
}

function New-LivePolicy {
    param([string]$Name, [hashtable]$Conditions)
    $body = @{ displayName = "$($script:LivePrefix): $Name"; state = 'enabled'; conditions = $Conditions; grantControls = @{ operator = 'OR'; builtInControls = @('block') } }
    Assert-LivePolicyIsNarrow $body
    Invoke-Graph -Method POST -Uri $script:CaPolicyBase -Body ($body | ConvertTo-Json -Depth 8) -ContentType 'application/json'
}

# One request to the token endpoint. Only the outcome is kept, never what was sent.
function Request-LiveToken {
    param([string]$Tenant, [hashtable]$Form)
    try {
        $r = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token" -Body $Form -ContentType 'application/x-www-form-urlencoded'
        [pscustomobject]@{ Ok = $true; Code = 0; Token = $r.access_token; Refresh = $r.refresh_token; Text = '' }
    } catch {
        $detail = $null
        try { $detail = $_.ErrorDetails.Message | ConvertFrom-Json } catch { Write-Verbose 'The token endpoint did not return JSON.' }
        [pscustomobject]@{ Ok = $false; Code = $(if ($detail.error_codes) { [int]@($detail.error_codes)[0] } else { -1 }); Token = ''; Refresh = ''
                           Text = $(if ($detail.error_description) { ([string]$detail.error_description).Split("`n")[0].Trim() } else { $_.Exception.Message }) }
    }
}

function Get-LiveOutcome {
    param([object]$Result)
    if ($Result.Ok) { return 'Issued' }
    if ($Result.Code -eq 53003) { return 'Denied' }
    "Error $($Result.Code)"
}

# Each probe is one real way of getting a token. The blueprint's exchange token is exempt from Conditional Access, so a fresh one each time
# changes nothing about what is being tested.
function Get-LiveExchange {
    param([object]$Ctx)
    Request-LiveToken $Ctx.Tenant @{ client_id = $Ctx.BlueprintApp; client_secret = $Ctx.Secret; scope = 'api://AzureADTokenExchange/.default'; fmi_path = $Ctx.IdentityApp; grant_type = 'client_credentials' }
}

function Invoke-LiveProbe {
    param([object]$Ctx, [string]$Probe)
    $assertion = @{ client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' }
    switch ($Probe) {
        { $_ -in 'UserToAgent', 'UserToArm' } {
            $scope = if ($Probe -eq 'UserToAgent') { "api://$($Ctx.BlueprintApp)/access_agent" } else { 'https://management.azure.com/.default' }
            return (Get-LiveOutcome (Request-LiveToken $Ctx.Tenant @{ client_id = $script:AzureCliApp; grant_type = 'refresh_token'; refresh_token = $Ctx.UserRefresh; scope = $scope }))
        }
    }
    $t1 = Get-LiveExchange $Ctx
    if (-not $t1.Ok) { return "Exchange error $($t1.Code)" }
    $assertion['client_assertion'] = $t1.Token
    $assertion['client_id'] = $Ctx.IdentityApp
    switch ($Probe) {
        'AsItself' { $form = $assertion + @{ scope = 'https://graph.microsoft.com/.default'; grant_type = 'client_credentials' } }
        'OwnAccount' {
            $t2 = Request-LiveToken $Ctx.Tenant ($assertion + @{ scope = 'api://AzureADTokenExchange/.default'; grant_type = 'client_credentials' })
            if (-not $t2.Ok) { return "Exchange error $($t2.Code)" }
            $form = $assertion + @{ scope = 'https://graph.microsoft.com/User.Read'; grant_type = 'user_fic'; user_federated_identity_credential = $t2.Token; username = $Ctx.AgentUserUpn; requested_token_use = 'on_behalf_of' }
        }
        'ForUserGraph' { $form = $assertion + @{ scope = 'https://graph.microsoft.com/User.Read'; grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer'; assertion = $Ctx.UserToken; requested_token_use = 'on_behalf_of' } }
        'ForUserArm' { $form = $assertion + @{ scope = 'https://management.azure.com/user_impersonation'; grant_type = 'urn:ietf:params:oauth:grant-type:jwt-bearer'; assertion = $Ctx.UserToken; requested_token_use = 'on_behalf_of' } }
        default { throw "Unknown probe $Probe" }
    }
    $result = Request-LiveToken $Ctx.Tenant $form
    if (-not $result.Ok -and $result.Code -ne 53003) { $Ctx.LastErrors[$Probe] = $result.Text }
    Get-LiveOutcome $result
}

# A person's token for the agent lasts about an hour, longer than a run can rely on. A refused refresh keeps the last good one.
function Update-LiveUserToken {
    param([object]$Ctx)
    if (-not $Ctx.UserRefresh) { return }
    $r = Request-LiveToken $Ctx.Tenant @{ client_id = $script:AzureCliApp; grant_type = 'refresh_token'; refresh_token = $Ctx.UserRefresh; scope = "api://$($Ctx.BlueprintApp)/access_agent offline_access" }
    if ($r.Ok) { $Ctx.UserToken = $r.Token; if ($r.Refresh) { $Ctx.UserRefresh = $r.Refresh } }
}

# Whether the last few tries of a probe all had the expected outcome.
function Test-LiveSettled {
    param([string[]]$History, [string]$Expected, [int]$Needed = 5)
    $history = @($History)
    if ($history.Count -lt $Needed) { return $false }
    @($history | Select-Object -Last $Needed | Where-Object { $_ -ne $Expected }).Count -eq 0
}

# What one round found for one probe: when it first and last went each way, and whether it ended as expected.
function Get-LiveRoundLine {
    param([string]$Probe, [string]$Expected, [object[]]$Tries)
    $mine = @($Tries | Where-Object { $_.Probe -eq $Probe })
    $firstDenied = @($mine | Where-Object { $_.Outcome -eq 'Denied' })[0]
    $lastIssued = @($mine | Where-Object { $_.Outcome -eq 'Issued' })[-1]
    $otherTries = @($mine | Where-Object { $_.Outcome -notin 'Denied', 'Issued' })
    $issued = @($mine | Where-Object { $_.Outcome -eq 'Issued' }).Count
    $denied = @($mine | Where-Object { $_.Outcome -eq 'Denied' }).Count
    $passed = Test-LiveSettled -History @($mine | ForEach-Object { $_.Outcome }) -Expected $Expected
    [pscustomobject]@{
        Probe = $Probe; Expected = $Expected; Tries = $mine.Count; Issued = $issued; Denied = $denied
        Verdict = $(if ($passed) { 'PASS' } elseif ($issued -and $denied) { 'NOT SETTLED' } else { 'FAIL' })
        Other = $(if ($otherTries.Count) { ($otherTries | Group-Object Outcome | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', ' } else { '' })
        FirstDeniedMin = $(if ($firstDenied) { $firstDenied.Minutes } else { $null }); LastIssuedMin = $(if ($lastIssued) { $lastIssued.Minutes } else { $null })
    }
}

function Format-LiveLine {
    param([object]$Line)
    '{0}: {1}. Expected {2}. Issued {3}, denied {4}{5}{6}{7}' -f $Line.Verdict, $Line.Probe, $Line.Expected, $Line.Issued, $Line.Denied,
        $(if ($Line.Other) { ", other: $($Line.Other)" } else { '' }), $(if ($null -ne $Line.FirstDeniedMin) { ", first denied at $($Line.FirstDeniedMin) min" } else { '' }), $(if ($null -ne $Line.LastIssuedMin) { ", last issued at $($Line.LastIssuedMin) min" } else { '' })
}

# Apply a change, then try every probe every 20 seconds until each one holds its expected outcome, and a little longer so a late change shows.
function Invoke-LiveRound {
    param([object]$Ctx, [string]$Name, [hashtable]$Expect, [int]$Minutes, [scriptblock]$Change)
    Write-Host "`n=== $Name" -ForegroundColor Cyan
    $probes = @($Expect.Keys | Where-Object { $Ctx.Usable -contains $_ })
    foreach ($p in @($Expect.Keys | Where-Object { $Ctx.Usable -notcontains $_ })) { Write-Host "  $p cannot be tested: it never got a token at the start." -ForegroundColor Yellow }
    Update-LiveUserToken $Ctx
    if ((& $Change) -eq $false) {
        Write-Host '  Skipped: Entra refused the policy, so this cannot be tested here.' -ForegroundColor Yellow
        return [pscustomobject]@{ Round = $Name; Refused = $true; Results = @(); Tries = @() }
    }
    $started = Get-Date
    $deadline = $started.AddMinutes($Minutes)
    $tries = New-Object 'System.Collections.Generic.List[object]'
    $settledAt = $null
    while ((Get-Date) -lt $deadline) {
        $at = [math]::Round(((Get-Date) - $started).TotalMinutes, 1)
        $now = foreach ($p in $probes) { $o = Invoke-LiveProbe -Ctx $Ctx -Probe $p; $tries.Add([pscustomobject]@{ Probe = $p; Minutes = $at; Outcome = $o }); "$p=$o" }
        Write-Host ('  {0,5:N1} min  {1}' -f $at, (@($now) -join '  '))
        $held = @($probes | Where-Object { -not (Test-LiveSettled -History @($tries | Where-Object Probe -eq $_ | ForEach-Object { $_.Outcome }) -Expected $Expect[$_]) }).Count -eq 0
        if ($held -and -not $settledAt) { $settledAt = Get-Date }
        if (-not $held) { $settledAt = $null }
        # A probe expected to stay issued settles at once, so it needs time to show it would not change: at least six minutes, and two after the rest.
        if ($settledAt -and ((Get-Date) - $started).TotalMinutes -ge 6 -and ((Get-Date) - $settledAt).TotalMinutes -ge 2) { break }
        Start-Sleep -Seconds 20
    }
    $lines = @($probes | ForEach-Object { Get-LiveRoundLine -Probe $_ -Expected $Expect[$_] -Tries $tries.ToArray() })
    foreach ($l in $lines) {
        Write-Host ('  {0}' -f (Format-LiveLine $l)) -ForegroundColor $(switch ($l.Verdict) { 'PASS' { 'Green' } 'NOT SETTLED' { 'Yellow' } default { 'Red' } })
    }
    [pscustomobject]@{ Round = $Name; Refused = $false; Results = $lines; Tries = $tries.ToArray() }
}

function Remove-LivePolicies {
    param([object]$Ctx)
    foreach ($id in $Ctx.Policies.ToArray()) {
        try { Invoke-Graph -Method DELETE -Uri "$($script:CaPolicyBase)/$id" | Out-Null } catch { Write-Warning "Could not remove policy $id`: $($_.Exception.Message)" }
    }
    $Ctx.Policies.Clear()
}

# Remove everything a run made, found by the name prefix so this also clears up after a run that was killed, and by the ids a run knows so a
# listing that fails or lags leaves nothing behind. No step may stop the ones after it, and what could not be removed is named.
function Remove-LiveObjects {
    param([object]$Ctx)
    Write-Host "`nRemoving everything the test made..." -ForegroundColor Cyan
    $name = "startswith(displayName,'$($script:LivePrefix)')"
    $list = { param([string]$Uri) try { @(Get-GraphAll -Uri $Uri | ForEach-Object { [string]$_.id }) } catch { Write-Warning "Could not list what to remove: $($_.Exception.Message)"; @() } }
    $failures = New-Object 'System.Collections.Generic.List[string]'
    $remove = {
        param([string]$What, [string]$Uri, [hashtable]$Headers)
        try { Invoke-Graph -Method DELETE -Uri $Uri -Headers $Headers | Out-Null; Write-Host "  Removed $What" }
        catch { if ("$($_.Exception.Message)" -notmatch 'NotFound|does not exist|404') { $failures.Add($What); Write-Warning "Could not remove $What`: $($_.Exception.Message)" } }
    }
    $policies = @(try { @(Get-CaPoliciesRaw | Where-Object { ([string]$_.displayName).StartsWith($script:LivePrefix) } | ForEach-Object { [string]$_.id }) } catch { Write-Warning "Could not list policies: $($_.Exception.Message)" })
    foreach ($id in @($policies + @(if ($Ctx) { $Ctx.Policies.ToArray() }) | Where-Object { $_ } | Select-Object -Unique)) { & $remove "policy $id" "$($script:CaPolicyBase)/$id" $null }
    $identities = @(@(& $list "https://graph.microsoft.com/beta/servicePrincipals/microsoft.graph.agentIdentity?`$filter=$name&`$select=id") + @(if ($Ctx) { $Ctx.IdentityId }) | Where-Object { $_ } | Select-Object -Unique)
    if ($identities.Count) {
        try { Invoke-Graph -Method POST -Uri "$($script:RiskBase)/dismiss" -Body (@{ agentIds = $identities } | ConvertTo-Json) -ContentType 'application/json' | Out-Null } catch { Write-Verbose $_.Exception.Message }
    }
    $agentUsers = @(@(& $list "https://graph.microsoft.com/beta/users/microsoft.graph.agentUser?`$filter=$name&`$select=id") + @(if ($Ctx) { $Ctx.AgentUserId }) | Where-Object { $_ } | Select-Object -Unique)
    foreach ($id in $agentUsers) { & $remove "agent user $id" "https://graph.microsoft.com/v1.0/users/$id" $null }
    foreach ($id in $identities) { & $remove "agent identity $id" "https://graph.microsoft.com/beta/servicePrincipals/$id" $script:OData }
    foreach ($id in @(& $list "https://graph.microsoft.com/beta/servicePrincipals?`$filter=$name&`$select=id") | Where-Object { $identities -notcontains $_ }) { & $remove "blueprint principal $id" "https://graph.microsoft.com/beta/servicePrincipals/$id" $script:OData }
    $blueprints = @(@(& $list "https://graph.microsoft.com/beta/applications?`$filter=$name&`$select=id") + @(if ($Ctx) { $Ctx.BlueprintObject }) | Where-Object { $_ } | Select-Object -Unique)
    foreach ($id in $blueprints) { & $remove "blueprint $id" "https://graph.microsoft.com/beta/applications/$id" $null }
    if ($failures.Count) { Write-Warning "$($failures.Count) object(s) could not be removed. Run this script again with -CleanupOnly." } else { Write-Host '  Nothing left behind.' -ForegroundColor Green }
}

# A newly made object can take a while to be usable everywhere, so writes that depend on one are retried.
function Invoke-LiveRetry {
    param([string]$What, [scriptblock]$Do, [int]$Tries = 12)
    for ($i = 1; ; $i++) {
        try { return (& $Do) }
        catch {
            if ($i -ge $Tries) { throw "$What failed: $($_.Exception.Message)" }
            Write-Host "  $What not ready yet, retrying..." -ForegroundColor DarkGray
            Start-Sleep -Seconds 15
        }
    }
}

function New-LiveAgent {
    param([string]$Stamp)
    $me = Invoke-Graph -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName'
    $tenant = (Get-MgContext).TenantId
    $domain = ([string]$me.userPrincipalName).Split('@')[1]
    $label = "$($script:LivePrefix) $Stamp"
    $sponsor = "https://graph.microsoft.com/v1.0/users/$($me.id)"
    Write-Host "Creating $label..." -ForegroundColor Cyan
    $bp = Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/v1.0/applications/microsoft.graph.agentIdentityBlueprint' -Headers $script:OData -ContentType 'application/json' -Body (@{ displayName = $label; 'sponsors@odata.bind' = @($sponsor); 'owners@odata.bind' = @($sponsor) } | ConvertTo-Json)
    $scopeId = [guid]::NewGuid().ToString()
    $scope = @{ adminConsentDescription = 'Throwaway agent for a Conditional Access test.'; adminConsentDisplayName = 'Access agent'; id = $scopeId; isEnabled = $true; type = 'User'; value = 'access_agent' }
    Invoke-LiveRetry 'Adding the blueprint scope' { Invoke-Graph -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($bp.id)" -Headers $script:OData -ContentType 'application/json' -Body (@{ identifierUris = @("api://$($bp.appId)"); api = @{ requestedAccessTokenVersion = 2; oauth2PermissionScopes = @($scope) } } | ConvertTo-Json -Depth 6) | Out-Null }
    Invoke-LiveRetry 'Pre-authorizing the sign-in client' { Invoke-Graph -Method PATCH -Uri "https://graph.microsoft.com/v1.0/applications/$($bp.id)" -Headers $script:OData -ContentType 'application/json' -Body (@{ api = @{ preAuthorizedApplications = @(@{ appId = $script:AzureCliApp; delegatedPermissionIds = @($scopeId) }) } } | ConvertTo-Json -Depth 6) | Out-Null }
    Invoke-LiveRetry 'Creating the blueprint principal' { Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/v1.0/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal' -Headers $script:OData -ContentType 'application/json' -Body (@{ appId = $bp.appId } | ConvertTo-Json) | Out-Null }
    $secret = Invoke-LiveRetry 'Adding the short-lived secret' { Invoke-Graph -Method POST -Uri "https://graph.microsoft.com/v1.0/applications/$($bp.id)/addPassword" -ContentType 'application/json' -Body (@{ passwordCredential = @{ displayName = 'Conditional Access test'; endDateTime = (Get-Date).ToUniversalTime().AddHours(4).ToString('yyyy-MM-ddTHH:mm:ssZ') } } | ConvertTo-Json) }
    $identity = Invoke-LiveRetry 'Creating the agent identity' { Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/beta/servicePrincipals/microsoft.graph.agentIdentity' -Headers $script:OData -ContentType 'application/json' -Body (@{ displayName = $label; agentIdentityBlueprintId = $bp.appId; 'sponsors@odata.bind' = @($sponsor) } | ConvertTo-Json) }
    $nick = 'a365catest' + ($Stamp -replace '\D', '')
    $agentUser = Invoke-LiveRetry 'Creating the agent user' { Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/v1.0/users/microsoft.graph.agentUser' -ContentType 'application/json' -Body (@{ accountEnabled = $true; displayName = $label; mailNickname = $nick; userPrincipalName = "$nick@$domain"; identityParentId = $identity.id } | ConvertTo-Json) }
    $graphSp = (Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$($script:GraphAppId)')?`$select=id").id
    $armSp = (Invoke-Graph -Uri "https://graph.microsoft.com/v1.0/servicePrincipals(appId='$($script:ArmApp)')?`$select=id").id
    foreach ($grant in @(@{ Resource = $graphSp; Scope = 'User.Read' }, @{ Resource = $armSp; Scope = 'user_impersonation' })) {
        Invoke-LiveRetry "Granting $($grant.Scope)" { Invoke-Graph -Method POST -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants' -ContentType 'application/json' -Body (@{ clientId = $identity.id; consentType = 'AllPrincipals'; resourceId = $grant.Resource; scope = $grant.Scope } | ConvertTo-Json) | Out-Null }
    }
    [pscustomobject]@{ Tenant = $tenant; MeId = [string]$me.id; Me = [string]$me.userPrincipalName; BlueprintObject = [string]$bp.id; BlueprintApp = [string]$bp.appId; Secret = [string]$secret.secretText
                       IdentityId = [string]$identity.id; IdentityApp = [string]$identity.appId; AgentUserId = [string]$agentUser.id; AgentUserUpn = [string]$agentUser.userPrincipalName
                       UserToken = ''; UserRefresh = ''; Usable = @(); LastErrors = @{}; Policies = (New-Object 'System.Collections.Generic.List[string]') }
}

# You sign in once, as the person the agent works for. The device code flow is the only part that needs you.
function Connect-LiveUser {
    param([object]$Ctx)
    $scope = "api://$($Ctx.BlueprintApp)/access_agent offline_access"
    for ($attempt = 1; $attempt -le 6; $attempt++) {
        try {
            $code = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$($Ctx.Tenant)/oauth2/v2.0/devicecode" -ContentType 'application/x-www-form-urlencoded' -Body @{ client_id = $script:AzureCliApp; scope = $scope }
            break
        } catch {
            if ($attempt -eq 6) { throw }
            Write-Host '  The new agent is not ready to sign in to yet, retrying...' -ForegroundColor DarkGray
            Start-Sleep -Seconds 20
        }
    }
    Write-Host "`nSign in as $($Ctx.Me), the person this agent will act for:" -ForegroundColor Cyan
    Write-Host "  Open $($code.verification_uri) and enter $($code.user_code)" -ForegroundColor Yellow
    $until = (Get-Date).AddSeconds([int]$code.expires_in)
    while ((Get-Date) -lt $until) {
        Start-Sleep -Seconds ([Math]::Max(5, [int]$code.interval))
        $r = Request-LiveToken $Ctx.Tenant @{ client_id = $script:AzureCliApp; grant_type = 'urn:ietf:params:oauth:grant-type:device_code'; device_code = $code.device_code }
        if ($r.Ok) { $Ctx.UserToken = $r.Token; $Ctx.UserRefresh = $r.Refresh; Write-Host '  Signed in.' -ForegroundColor Green; return $true }
        if ($r.Code -notin 70016, 70020) { Write-Warning "Sign-in failed: $($r.Text)"; return $false }
    }
    Write-Warning 'The code expired before it was used. The flows that act for a person will be skipped.'
    $false
}

# Tokens can take minutes to work after the objects are made. Whatever never works cannot be tested, and the run says so.
function Wait-LiveBaseline {
    param([object]$Ctx, [string[]]$Probes, [int]$Minutes = 8)
    Write-Host "`n=== Baseline: with no test policy, every way of signing in should get a token" -ForegroundColor Cyan
    $until = (Get-Date).AddMinutes($Minutes)
    $good = New-Object 'System.Collections.Generic.HashSet[string]'
    do {
        $line = foreach ($p in $Probes) { if ($good.Contains($p)) { continue }; $o = Invoke-LiveProbe -Ctx $Ctx -Probe $p; if ($o -eq 'Issued') { [void]$good.Add($p) }; "$p=$o" }
        if ($line) { Write-Host ('  ' + (@($line) -join '  ')) }
        if ($good.Count -eq $Probes.Count) { break }
        Start-Sleep -Seconds 20
    } while ((Get-Date) -lt $until)
    $Ctx.Usable = @($good | ForEach-Object { $_ })
    foreach ($p in @($Probes | Where-Object { -not $good.Contains($_) })) { Write-Warning ("{0} never got a token: {1}" -f $p, $Ctx.LastErrors[$p]) }
}

function Invoke-LiveTest {
    param([int]$Minutes, [string]$SaveTo)
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmm')
    $rounds = New-Object 'System.Collections.Generic.List[object]'
    $ctx = $null
    $startedAt = Get-Date
    try {
        $ctx = New-LiveAgent -Stamp $stamp
        $signedIn = Connect-LiveUser -Ctx $ctx
        Wait-LiveBaseline -Ctx $ctx -Probes @(@('AsItself', 'OwnAccount') + @(if ($signedIn) { 'ForUserGraph', 'ForUserArm', 'UserToAgent', 'UserToArm' }))
        $add = { param([string]$Name, [hashtable]$Conditions) try { $ctx.Policies.Add([string](New-LivePolicy -Name $Name -Conditions $Conditions).id); $true } catch { Write-Warning "Entra refused the policy '$Name': $($_.Exception.Message)"; $false } }

        $rounds.Add((Invoke-LiveRound -Ctx $ctx -Minutes $Minutes -Name 'A policy on the agent identity, and one naming its user account under Users' `
            -Expect @{ AsItself = 'Denied'; OwnAccount = 'Issued'; ForUserGraph = 'Issued' } -Change {
                $null = & $add 'identity' @{ users = @{ includeUsers = @('None') }; clientApplications = @{ includeAgentIdServicePrincipals = @($ctx.IdentityId) }; applications = @{ includeApplications = @('All') } }
                $null = & $add 'named under users' @{ users = @{ includeUsers = @($ctx.AgentUserId) }; applications = @{ includeApplications = @('All') } } }))
        $rounds.Add((Invoke-LiveRound -Ctx $ctx -Minutes $Minutes -Name 'A policy targeting agent users' `
            -Expect @{ AsItself = 'Issued'; OwnAccount = 'Denied'; ForUserGraph = 'Issued' } -Change {
                Remove-LivePolicies $ctx
                $null = & $add 'agent user' @{ users = @{ includeUsers = @('None') }; agents = @{ includeAgentUsers = @($ctx.AgentUserId) }; applications = @{ includeApplications = @('All') } } }))
        if ($signedIn) {
            $rounds.Add((Invoke-LiveRound -Ctx $ctx -Minutes $Minutes -Name 'A user policy naming the agent as the resource' `
                -Expect @{ UserToAgent = 'Denied'; AsItself = 'Issued'; OwnAccount = 'Issued'; ForUserGraph = 'Issued' } -Change {
                    Remove-LivePolicies $ctx
                    $null = & $add 'agent as resource' @{ users = @{ includeUsers = @($ctx.MeId) }; applications = @{ includeApplications = @($ctx.BlueprintApp) } } }))
            $rounds.Add((Invoke-LiveRound -Ctx $ctx -Minutes $Minutes -Name 'A user policy for agent-assisted flows only' `
                -Expect @{ ForUserArm = 'Denied'; UserToArm = 'Issued'; ForUserGraph = 'Issued' } -Change {
                    Remove-LivePolicies $ctx
                    & $add 'agent assisted' @{ users = @{ includeUsers = @($ctx.MeId) }; applications = @{ includeApplications = @($script:ArmApp) }; clientAppTypes = @('all'); agentContext = @{ includeAgentContexts = @('allAgentAssistedFlows') } } }))
        }
        Remove-LivePolicies $ctx
        $highBlock = @(Get-AgentCaPolicies | Where-Object { $_.State -eq 'enabled' -and $_.Blocks -and $_.AllAgents -and $_.ResourceScope -eq 'All resources' -and $_.RiskLevels -contains 'high' })
        if ($highBlock.Count) {
            $rounds.Add((Invoke-LiveRound -Ctx $ctx -Minutes ($Minutes + 10) -Name "Confirming the agent compromised, under $($highBlock[0].Name)" `
                -Expect @{ AsItself = 'Denied'; ForUserGraph = 'Issued' } -Change {
                    Invoke-Graph -Method POST -Uri "$($script:RiskBase)/confirmCompromised" -Body (@{ agentIds = @($ctx.IdentityId) } | ConvertTo-Json) -ContentType 'application/json' | Out-Null }))
        } else { Write-Host "`nSkipped the compromised round: no enforced policy blocks High agent risk on all resources." -ForegroundColor Yellow }
    }
    finally {
        Remove-LiveObjects -Ctx $ctx
        if ($ctx) { $ctx.Secret = ''; $ctx.UserToken = ''; $ctx.UserRefresh = '' }
        $summary = @($rounds | ForEach-Object { $r = $_; $r.Results | ForEach-Object { [pscustomobject]@{ Round = $r.Round; Probe = $_.Probe; Expected = $_.Expected; Verdict = $_.Verdict; Issued = $_.Issued; Denied = $_.Denied; Other = $_.Other; FirstDeniedMin = $_.FirstDeniedMin; LastIssuedMin = $_.LastIssuedMin } } })
        Write-Host "`n=== Results" -ForegroundColor Cyan
        foreach ($r in $rounds) {
            Write-Host $r.Round
            foreach ($l in @($r.Results)) { Write-Host ('  {0}' -f (Format-LiveLine $l)) -ForegroundColor $(switch ($l.Verdict) { 'PASS' { 'Green' } 'NOT SETTLED' { 'Yellow' } default { 'Red' } }) }
            if ($r.Refused) { Write-Host '  NOT TESTED: Entra refused the policy.' -ForegroundColor Yellow }
        }
        if ($SaveTo) {
            [pscustomobject]@{ Started = $startedAt.ToUniversalTime().ToString('o'); Finished = (Get-Date).ToUniversalTime().ToString('o'); Stamp = $stamp; IdentityApp = $(if ($ctx) { $ctx.IdentityApp }); BlueprintApp = $(if ($ctx) { $ctx.BlueprintApp }); AgentUser = $(if ($ctx) { $ctx.AgentUserUpn }); Usable = $(if ($ctx) { $ctx.Usable }); Errors = $(if ($ctx) { $ctx.LastErrors }); NotTested = @($rounds | Where-Object { $_.Refused } | ForEach-Object { $_.Round }); Summary = $summary; Tries = @($rounds | ForEach-Object { [pscustomobject]@{ Round = $_.Round; Tries = $_.Tries } }) } |
                ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $SaveTo -Encoding utf8
            Write-Host "Saved: $SaveTo" -ForegroundColor Cyan
        }
    }
}

if ($MyInvocation.InvocationName -eq '.') { return }

Connect-GraphSession -DeviceCode -Connect @{ Scopes = @('AgentIdentityBlueprint.Create', 'AgentIdentityBlueprint.ReadWrite.All', 'AgentIdentityBlueprintPrincipal.Create', 'AgentIdentity.Create.All', 'AgentIdUser.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All', 'Application.Read.All', 'Policy.Read.All', 'Policy.ReadWrite.ConditionalAccess', 'IdentityRiskyAgent.ReadWrite.All', 'User.Read'); NoWelcome = $true }
Write-Host "Signed in as $((Get-MgContext).Account)." -ForegroundColor Green
if ($CleanupOnly) { Remove-LiveObjects -Ctx $null; return }
Invoke-LiveTest -Minutes $RoundMinutes -SaveTo $ResultFile

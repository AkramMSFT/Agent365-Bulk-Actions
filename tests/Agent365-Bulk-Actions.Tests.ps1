BeforeAll {
    # Stand-ins so the tests run without the Microsoft Graph module or a tenant.
    function Get-MgContext { [pscustomobject]@{ Account = 'tester@contoso.com' } }
    function Invoke-MgGraphRequest { throw 'Tests must mock Graph calls.' }

    . (Join-Path $PSScriptRoot '..\Agent365-Bulk-Actions.ps1')

    function New-Pkg {
        param([string]$Id, [string]$Name, [bool]$Blocked = $false, [string]$OwnerId = '', [string]$IdentityId = '', [string]$Type = 'shared')
        [pscustomobject]@{ id = $Id; displayName = $Name; isBlocked = $Blocked; ownerId = $OwnerId; agentIdentityId = $IdentityId; type = $Type
                           appId = "app-$Id"; manifestId = "man-$Id"; platform = 'Copilot Studio'; supportedHosts = @('Copilot') }
    }
}

Describe 'Package keys and severity' {
    It 'matches on ids, never on display name, in lower case' {
        $keys = Get-PackageKeys (New-Pkg 'T_ABC' 'Same Name' -IdentityId 'AGENT-1')
        $keys | Should -Contain 't_abc'
        $keys | Should -Contain 'agent-1'
        $keys | Should -Not -Contain 'same name'
    }
    It 'ranks severities from Informational to High' {
        (Get-SevRank 'High') | Should -BeGreaterThan (Get-SevRank 'Medium')
        (Get-SevRank 'Medium') | Should -BeGreaterThan (Get-SevRank 'Low')
        (Get-SevRank 'Low') | Should -BeGreaterThan (Get-SevRank 'Informational')
        (Get-SevRank 'nonsense') | Should -Be 0
    }
}

Describe 'Resolve-Packages' {
    BeforeEach {
        Mock Get-Packages { @((New-Pkg 'P_1' 'Alpha'), (New-Pkg 'T_2' 'Beta'), (New-Pkg 'P_3' 'Dup'), (New-Pkg 'P_4' 'Dup')) }
    }
    It 'resolves both P_ and T_ ids and names' {
        $r = Resolve-Packages 'P_1', 'T_2', 'Alpha'
        $r.id | Should -Be @('P_1', 'T_2')   # the repeated target collapses to one
    }
    It 'fails on an unknown id or name' {
        { Resolve-Packages 'P_missing' } | Should -Throw '*No package matching*'
        { Resolve-Packages 'Nope' } | Should -Throw '*No package matching*'
    }
    It 'refuses an ambiguous display name' {
        { Resolve-Packages 'Dup' } | Should -Throw '*Multiple packages*'
    }
}

Describe 'Confirm-Batch' {
    It 'skips the prompt with -Force and for implied consent' {
        $Force = $true
        Confirm-Batch -Count 3 -Action block | Should -BeTrue
        $Force = $false
        Confirm-Batch -Count 3 -Action block -Implied | Should -BeTrue
    }
    It 'asks otherwise, and only a yes proceeds' {
        $Force = $false
        Mock Read-Host { 'y' }
        Confirm-Batch -Count 1 -Action block | Should -BeTrue
        Mock Read-Host { 'n' }
        Confirm-Batch -Count 1 -Action block | Should -BeFalse
    }
}

Describe 'Invoke-PackageAction' {
    BeforeEach {
        Mock Invoke-Graph { }
        Mock Test-Proceed { $true }
        Mock Write-Host { }
        $OutFile = $null
        $DisableIdentity = $false
    }
    It 'blocks an active agent and logs the previous state' {
        $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha') -Action block -PassThru
        $log.Result | Should -Be 'Done'
        $log.WasBlocked | Should -BeFalse
        Should -Invoke Invoke-Graph -Times 1 -ParameterFilter { $Method -eq 'POST' -and $Uri -like '*/P_1/block' }
    }
    It 'skips an agent already in the target state without calling Graph' {
        $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -Blocked $true) -Action block -PassThru
        $log.Result | Should -Be 'Skipped'
        Should -Invoke Invoke-Graph -Times 0
    }
    It 'changes nothing when the proceed check says no (-WhatIf)' {
        Mock Test-Proceed { $false }
        $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha') -Action block -PassThru
        $log.Result | Should -Be 'WhatIf'
        Should -Invoke Invoke-Graph -Times 0
    }
    It 'keeps going after a failure and records the error' {
        Mock Invoke-Graph { if ($Uri -like '*P_1*') { throw 'boom' } }
        $log = Invoke-PackageAction -Packages @((New-Pkg 'P_1' 'Alpha'), (New-Pkg 'P_2' 'Beta')) -Action block -PassThru
        ($log | Where-Object Id -eq 'P_1').Result | Should -Be 'Failed'
        ($log | Where-Object Id -eq 'P_1').Error | Should -Match 'boom'
        ($log | Where-Object Id -eq 'P_2').Result | Should -Be 'Done'
    }
    It 'disables the agent identity on block and re-enables it on unblock when asked' {
        $DisableIdentity = $true
        $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -IdentityId 'ID-1') -Action block -PassThru
        $log.Identity | Should -Be 'Disabled'
        Should -Invoke Invoke-Graph -ParameterFilter { $Method -eq 'PATCH' -and $Uri -like '*ID-1*' -and $Body -match 'false' }
        $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -Blocked $true -IdentityId 'ID-1') -Action unblock -PassThru
        $log.Identity | Should -Be 'Enabled'
    }
    It 'leaves identities alone without -DisableIdentity' {
        Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -IdentityId 'ID-1') -Action block | Out-Null
        Should -Invoke Invoke-Graph -Times 0 -ParameterFilter { $Method -eq 'PATCH' }
    }
}

Describe 'Export-ActionLog' {
    BeforeEach { Mock Write-Host { } }
    It 'writes CSV or JSON by extension' {
        $rec = [pscustomobject]@{ Id = 'P_1'; Result = 'Done' }
        $OutFile = Join-Path $TestDrive 'log.csv'
        Export-ActionLog -Records @($rec)
        (Import-Csv $OutFile).Id | Should -Be 'P_1'
        $OutFile = Join-Path $TestDrive 'log.json'
        Export-ActionLog -Records @($rec)
        (Get-Content -Raw $OutFile | ConvertFrom-Json).Result | Should -Be 'Done'
    }
}

Describe 'Resolve-AgentOwner' {
    BeforeEach {
        $live = [pscustomobject]@{ Id = 'u-live'; Upn = 'live@contoso.com'; Name = 'Live'; Exists = $true; Enabled = $true }
        $gone = [pscustomobject]@{ Id = 'u-gone'; Upn = ''; Name = ''; Exists = $false; Enabled = $false }
        Mock Get-UserInfo { param($IdOrUpn) if ($IdOrUpn -eq 'u-live') { $live } else { $gone } }
        Mock Get-IdentityOwners { @() }
        Mock Get-ManagerInfo { $null }
    }
    It 'keeps a valid current owner' {
        (Resolve-AgentOwner (New-Pkg 'P_1' 'A' -OwnerId 'u-live')).State | Should -Be 'OK'
    }
    It 'proposes the Entra agent identity owner when the owner is gone' {
        Mock Get-IdentityOwners { @($live) }
        $r = Resolve-AgentOwner (New-Pkg 'P_1' 'A' -OwnerId 'u-gone' -IdentityId 'ID-1')
        $r.State | Should -Be 'Proposed'
        $r.Proposed | Should -Be 'live@contoso.com'
        $r.Source | Should -Be 'Agent identity owner'
        $r.Reason | Should -Match 'no longer exists'
    }
    It 'falls back to the manager of the identity owner' {
        $disabled = [pscustomobject]@{ Id = 'u-off'; Upn = 'off@contoso.com'; Name = 'Off'; Exists = $true; Enabled = $false }
        Mock Get-IdentityOwners { @($disabled) }
        Mock Get-ManagerInfo { $live }
        $r = Resolve-AgentOwner (New-Pkg 'P_1' 'A' -OwnerId 'u-gone' -IdentityId 'ID-1')
        $r.State | Should -Be 'Proposed'
        $r.Source | Should -Match 'Manager of off@contoso.com'
    }
    It 'flags for review instead of guessing when nothing can be derived' {
        $r = Resolve-AgentOwner (New-Pkg 'P_1' 'A' -OwnerId '')
        $r.State | Should -Be 'Needs review'
        $r.Proposed | Should -BeNullOrEmpty
        $r.Reason | Should -Be 'no owner'
    }
    It 'treats the all-zeros owner id as no owner' {
        (Resolve-AgentOwner (New-Pkg 'P_1' 'A' -OwnerId '00000000-0000-0000-0000-000000000000')).Reason | Should -Be 'no owner'
    }
}

Describe 'Get-OwnerReport' {
    It 'only considers shared agents and counts org-published ones separately' {
        Mock Resolve-AgentOwner { [pscustomobject]@{ Id = $Package.id; State = $(if ($Package.id -eq 'P_ok') { 'OK' } else { 'Needs review' }) } }
        $pk = @((New-Pkg 'P_ok' 'a'), (New-Pkg 'P_bad' 'b'), (New-Pkg 'P_lob' 'c' -Type 'lob'), (New-Pkg 'P_3p' 'd' -Type 'thirdParty'))
        $rep = Get-OwnerReport -Packages $pk
        $rep.OkCount | Should -Be 1
        $rep.Items.Count | Should -Be 1
        $rep.OrgPublished | Should -Be 1
        Should -Invoke Resolve-AgentOwner -Times 2
    }
}

Describe 'Risk query' {
    BeforeEach {
        $script:captured = ''
        Mock Invoke-HuntingQuery { $script:captured = $Query; @() }
        $HuntingQuery = $null
    }
    It 'reads alerts and detections by default' {
        Get-RiskyIndex -Days 30 | Out-Null
        $script:captured | Should -Match 'union alerts, rtp, shield'
        $script:captured | Should -Match 'BehaviorAgentRTPAudit'
        $script:captured | Should -Match 'Security for AI'
    }
    It 'limits the legs when asked' {
        Get-RiskyIndex -Days 30 -Source Alerts | Out-Null
        $script:captured | Should -Match 'union alerts\r?\n'
        $script:captured | Should -Not -Match 'BehaviorEntities'
        Get-RiskyIndex -Days 30 -Source Detections | Out-Null
        $script:captured | Should -Match 'union rtp, shield'
        $script:captured | Should -Not -Match 'AlertInfo'
    }
    It 'maps hunting rows to lower-case keys with counts and severity' {
        Mock Invoke-HuntingQuery { @([pscustomobject]@{ Key = 'T_ABC'; AlertCount = 2; DetectionCount = 5; Severity = 'High'; LastAlert = '2026-09-30T10:00:00Z'; Reasons = @('x', 'y'); Categories = '[]' }) }
        $idx = Get-RiskyIndex -Days 30
        $idx['t_abc'].AlertCount | Should -Be 2
        $idx['t_abc'].DetectionCount | Should -Be 5
        $idx['t_abc'].Reasons | Should -Be 'x; y'
    }
}

Describe 'Get-RiskyPackages' {
    It 'filters on total signals and minimum severity, worst first' {
        Mock Get-Packages { @((New-Pkg 'T_hi' 'Hi'), (New-Pkg 'T_lo' 'Lo'), (New-Pkg 'T_none' 'None')) }
        Mock Get-RiskyIndex { @{
            't_hi' = [pscustomobject]@{ AlertCount = 1; DetectionCount = 3; Severity = 'High'; LastAlert = $null; Reasons = ''; Categories = '' }
            't_lo' = [pscustomobject]@{ AlertCount = 1; DetectionCount = 0; Severity = 'Low'; LastAlert = $null; Reasons = ''; Categories = '' } } }
        $r = @(Get-RiskyPackages -Days 30 -MinAlerts 1 -MinSeverity Informational)
        $r.displayName | Should -Be @('Hi', 'Lo')
        @(Get-RiskyPackages -Days 30 -MinAlerts 1 -MinSeverity Medium).displayName | Should -Be @('Hi')
        @(Get-RiskyPackages -Days 30 -MinAlerts 5 -MinSeverity Informational).Count | Should -Be 0
    }
}

Describe 'Get-DeleteCandidates' {
    BeforeEach {
        Mock Write-Warning { }
        $now = [datetimeoffset]::UtcNow
        $script:old = $now.AddDays(-45).ToString('o')
        Mock Get-Packages { @((New-Pkg 'P_old' 'Old' -Blocked $true), (New-Pkg 'P_new' 'New' -Blocked $true), (New-Pkg 'P_unk' 'Unknown' -Blocked $true), (New-Pkg 'P_ok' 'Active')) }
        Mock Invoke-HuntingQuery { @([pscustomobject]@{ Timestamp = $now.AddDays(-2).ToString('o'); ActionType = 'BlockedAgent'; AgentId = 'P_new' }) }
        $empty = Join-Path $TestDrive 'empty'; New-Item -ItemType Directory -Force $empty | Out-Null
        $script:empty = $empty
        $script:logFile = Join-Path $TestDrive 'history.csv'
        [pscustomobject]@{ Timestamp = $script:old; Action = 'block'; Id = 'P_old'; Result = 'Done' } | Export-Csv $script:logFile -NoTypeInformation
    }
    It 'lists agents blocked long enough, using logs and audit events' {
        $c = @(Get-DeleteCandidates -MinDays 30 -HistoryPaths $script:logFile -LogDir $script:empty)
        $c.Id | Should -Be @('P_old')
        $c[0].DaysBlocked | Should -BeGreaterOrEqual 45
        $c[0].Evidence | Should -Be 'kit log'
    }
    It 'uses audit events for recent blocks' {
        $c = @(Get-DeleteCandidates -MinDays 0 -HistoryPaths $script:logFile -LogDir $script:empty)
        $c.Id | Should -Contain 'P_new'
        ($c | Where-Object Id -eq 'P_new').Evidence | Should -Be 'audit'
    }
    It 'omits agents with no known block date unless asked' {
        (Get-DeleteCandidates -MinDays 0 -HistoryPaths $script:logFile -LogDir $script:empty).Id | Should -Not -Contain 'P_unk'
        (Get-DeleteCandidates -MinDays 0 -HistoryPaths $script:logFile -LogDir $script:empty -IncludeUnknown).Id | Should -Contain 'P_unk'
    }
    It 'never reports an agent that was unblocked afterwards' {
        $later = [datetimeoffset]::UtcNow.AddDays(-10).ToString('o')
        [pscustomobject]@{ Timestamp = $later; Action = 'unblock'; Id = 'P_old'; Result = 'Done' } | Export-Csv $script:logFile -NoTypeInformation -Append
        (Get-DeleteCandidates -MinDays 0 -HistoryPaths $script:logFile -LogDir $script:empty -IncludeUnknown | Where-Object Id -eq 'P_old').BlockedSince | Should -Be 'unknown'
    }
}

Describe 'Graph retry' {
    It 'retries a throttled call and then succeeds' {
        $script:calls = 0
        Mock Start-Sleep { }
        Mock Write-Warning { }
        Mock Invoke-MgGraphRequest {
            $script:calls++
            if ($script:calls -lt 3) {
                $ex = [System.Net.Http.HttpRequestException]::new('throttled')
                $resp = [pscustomobject]@{ StatusCode = 429; Headers = [pscustomobject]@{ RetryAfter = $null } }
                $ex | Add-Member -NotePropertyName Response -NotePropertyValue $resp -Force
                throw $ex
            }
            'ok'
        }
        Invoke-Graph -Uri 'https://graph.microsoft.com/beta/x' | Should -Be 'ok'
        $script:calls | Should -Be 3
    }
}

Describe 'Policy plan' {
    BeforeEach {
        $script:catalog = @((New-Pkg 'T_a' 'Alpha'), (New-Pkg 'T_b' 'Beta' -Blocked $true), (New-Pkg 'T_c' 'Gamma'), (New-Pkg 'T_ms' 'Microsoft thing' -Type 'firstParty'))
        $script:catalog[3] | Add-Member -NotePropertyName publisher -NotePropertyValue 'Microsoft Corporation' -Force
        Mock Get-Packages { $script:catalog }
        Mock Get-StalePackages { @($script:catalog[0], $script:catalog[1], $script:catalog[3]) }
        Mock Get-RiskyPackages { @($script:catalog[0], $script:catalog[2]) }
        Mock Get-OwnerReport { [pscustomobject]@{ Items = @([pscustomobject]@{ Id = 'T_c'; State = 'Proposed'; ProposedId = 'u1'; Proposed = 'u1@contoso.com'; Source = 'Agent identity owner' }); OkCount = 0; OrgPublished = 0 } }
        Mock Get-DeleteCandidates { @([pscustomobject]@{ Id = 'T_b' }) }
        function Doc($json) { $json | ConvertFrom-Json }
    }
    It 'combines conditions with AND by default and OR on request' {
        $and = Doc '{ "rules": [ { "name": "r", "when": { "stale": { "days": 14 }, "risky": { "minSeverity": "High" } }, "then": { "action": "report" } } ] }'
        (Get-PolicyPlan $and).Matched.id | Should -Be @('T_a')
        $any = Doc '{ "rules": [ { "name": "r", "match": "any", "when": { "stale": { "days": 14 }, "risky": { } }, "then": { "action": "report" } } ] }'
        (Get-PolicyPlan $any).Matched.id | Should -Contain 'T_c'
        (Get-PolicyPlan $any).Matched.id | Should -Contain 'T_b'
    }
    It 'applies exclusions by publisher, type, name and id' {
        $d = Doc '{ "exclude": { "publishers": ["Microsoft Corporation"], "names": ["Beta"] }, "rules": [ { "name": "r", "when": { "stale": { "days": 14 } }, "then": { "action": "report" } } ] }'
        (Get-PolicyPlan $d).Matched.id | Should -Be @('T_a')
    }
    It 'only plans changes that would actually change state' {
        $d = Doc '{ "rules": [ { "name": "r", "when": { "stale": { "days": 14 } }, "then": { "action": "block" } } ] }'
        $p = Get-PolicyPlan $d
        $p.Matched.Count | Should -Be 3
        $p.Actionable.id | Should -Not -Contain 'T_b'   # already blocked
    }
    It 'plans reassignment only where an owner was proposed' {
        $d = Doc '{ "rules": [ { "name": "r", "when": { "ownerless": true }, "then": { "action": "reassign" } } ] }'
        (Get-PolicyPlan $d).Actionable.id | Should -Be @('T_c')
    }
    It 'rejects a rule without conditions, an unknown action, and unprovable activity windows' {
        { Get-PolicyPlan (Doc '{ "rules": [ { "name": "x", "then": { "action": "block" } } ] }') } | Should -Throw '*no conditions*'
        { Get-PolicyPlan (Doc '{ "rules": [ { "name": "x", "when": { "state": "blocked" }, "then": { "action": "explode" } } ] }') } | Should -Throw '*unknown action*'
        { Get-PolicyPlan (Doc '{ "rules": [ { "name": "x", "when": { "stale": { "days": 60 } }, "then": { "action": "block" } } ] }') } | Should -Throw '*includeNeverSeen*'
    }
}

Describe 'Invoke-PolicyPlan' {
    BeforeEach {
        Mock Write-Host { }
        Mock Invoke-PackageAction { }
        Mock Invoke-OwnerReassign { }
        Mock Out-Host { }
        $pk = New-Pkg 'T_a' 'Alpha'
        $script:plan = @(
            [pscustomobject]@{ Rule = 'b'; Action = 'block'; DisableIdentity = $true; Matched = @($pk); Actionable = @($pk); Proposals = @{} },
            [pscustomobject]@{ Rule = 'r'; Action = 'report'; DisableIdentity = $false; Matched = @($pk); Actionable = @($pk); Proposals = @{} })
    }
    It 'changes nothing without -Apply' {
        Invoke-PolicyPlan -Plan $script:plan
        Should -Invoke Invoke-PackageAction -Times 0
    }
    It 'applies block rules once confirmed and skips report rules' {
        Mock Confirm-Batch { $true }
        Invoke-PolicyPlan -Plan $script:plan -Apply
        Should -Invoke Invoke-PackageAction -Times 1 -ParameterFilter { $Action -eq 'block' }
    }
    It 'applies nothing when the confirmation is declined' {
        Mock Confirm-Batch { $false }
        Invoke-PolicyPlan -Plan $script:plan -Apply
        Should -Invoke Invoke-PackageAction -Times 0
    }
}

Describe 'Snapshots' {
    It 'reports new, removed, blocked and owner changes between snapshots' {
        $path = Join-Path $TestDrive 'snap.json'
        Save-Snapshot -Path $path -Packages @((New-Pkg 'T_a' 'Alpha' -OwnerId 'u1'), (New-Pkg 'T_b' 'Beta'), (New-Pkg 'T_gone' 'Gone'))
        $old = Get-Content -Raw $path | ConvertFrom-Json
        $now = @((New-Pkg 'T_a' 'Alpha' -OwnerId 'u2'), (New-Pkg 'T_b' 'Beta' -Blocked $true), (New-Pkg 'T_new' 'Newcomer'))
        $c = @(Compare-Snapshot -Old $old -Current $now)
        ($c | Where-Object Change -eq 'New').Id | Should -Be 'T_new'
        ($c | Where-Object Change -eq 'Removed').Id | Should -Be 'T_gone'
        ($c | Where-Object Change -eq 'Blocked').Id | Should -Be 'T_b'
        ($c | Where-Object Change -eq 'Owner changed').Id | Should -Be 'T_a'
    }
}

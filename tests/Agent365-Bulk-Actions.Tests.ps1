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
    Context 'identity check with -DisableIdentity' {
        BeforeEach {
            Mock Start-Sleep { }
            Mock Set-AgentIdentityState { }
            $DisableIdentity = $true
        }
        It 'records that the platform disabled the identity and does not call the identity API' {
            Mock Get-AgentIdentityStateMap { @{ 'ID-1' = $false } }
            $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -IdentityId 'ID-1') -Action block -PassThru
            $log.Identity | Should -Be 'Disabled (by platform)'
            Should -Invoke Set-AgentIdentityState -Times 0
        }
        It 'waits for the platform and then records an unblock re-enabling the identity' {
            $script:reads = 0
            Mock Get-AgentIdentityStateMap { $script:reads++; @{ 'ID-1' = ($script:reads -ge 2) } }
            $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -Blocked $true -IdentityId 'ID-1') -Action unblock -PassThru
            $log.Identity | Should -Be 'Enabled (by platform)'
            $script:reads | Should -BeGreaterOrEqual 2
        }
        It 'forces the change itself only when the platform left the identity in the wrong state' {
            Mock Get-AgentIdentityStateMap { @{ 'ID-1' = $true } }
            $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -IdentityId 'ID-1') -Action block -PassThru
            $log.Identity | Should -Be 'Disabled (by tool)'
            Should -Invoke Set-AgentIdentityState -Times 1 -ParameterFilter { $AgentIdentityId -eq 'ID-1' -and $Enabled -eq $false }
        }
        It 'reports a failed forced change without failing the block' {
            Mock Get-AgentIdentityStateMap { @{ 'ID-1' = $true } }
            Mock Set-AgentIdentityState { throw 'Forbidden' }
            $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -IdentityId 'ID-1') -Action block -PassThru
            $log.Result | Should -Be 'Done'
            $log.Identity | Should -Be 'Failed'
            $log.Error | Should -Match 'Forbidden'
        }
        It 'reports an unreadable identity without changing it' {
            Mock Get-AgentIdentityStateMap { @{ 'ID-1' = $null } }
            $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -IdentityId 'ID-1') -Action block -PassThru
            $log.Identity | Should -Be 'Unreadable'
            Should -Invoke Set-AgentIdentityState -Times 0
        }
        It 'does nothing for identities without -DisableIdentity' {
            $DisableIdentity = $false
            Mock Get-AgentIdentityStateMap { @{ 'ID-1' = $true } }
            Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -IdentityId 'ID-1') -Action block | Out-Null
            Should -Invoke Get-AgentIdentityStateMap -Times 0
            Should -Invoke Set-AgentIdentityState -Times 0
        }
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
        $pk = @((New-Pkg 'P_ok' 'a' -OwnerId 'u1'), (New-Pkg 'P_bad' 'b' -OwnerId 'u2'), (New-Pkg 'P_lob' 'c' -Type 'lob'), (New-Pkg 'P_3p' 'd' -Type 'thirdParty'), (New-Pkg 'P_none' 'e'))
        $rep = Get-OwnerReport -Packages $pk
        $rep.OkCount | Should -Be 1
        $rep.Items.Count | Should -Be 1
        $rep.OrgPublished | Should -Be 1
        $rep.NoOwner | Should -Be 1
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

Describe 'Find-DirectoryUsers' {
    BeforeEach {
        $script:uri = ''
        Mock Invoke-Graph {
            $script:uri = $Uri
            [pscustomobject]@{ value = @(
                [pscustomobject]@{ id = 'u1'; displayName = 'Zed'; userPrincipalName = 'zed@contoso.com'; accountEnabled = $true },
                [pscustomobject]@{ id = 'u2'; displayName = 'Ann'; userPrincipalName = 'ann@contoso.com'; accountEnabled = $true },
                [pscustomobject]@{ id = 'u3'; displayName = 'Off'; userPrincipalName = 'off@contoso.com'; accountEnabled = $false }) }
        }
    }
    It 'returns enabled users only, sorted by name' {
        (Find-DirectoryUsers -Text '').Name | Should -Be @('Ann', 'Zed')
    }
    It 'sends no filter for an empty search and a startswith filter otherwise' {
        Find-DirectoryUsers -Text '' | Out-Null
        $script:uri | Should -Not -Match 'filter'
        Find-DirectoryUsers -Text 'ak' | Out-Null
        [uri]::UnescapeDataString($script:uri) | Should -Match "startswith\(displayName,'ak'\) or startswith\(userPrincipalName,'ak'\) or startswith\(mail,'ak'\)"
    }
    It 'escapes single quotes in the search text' {
        Find-DirectoryUsers -Text "o'brien" | Out-Null
        [uri]::UnescapeDataString($script:uri) | Should -Match "'o''brien'"
    }
}

Describe 'Test-Reassignable' {
    It 'allows only Copilot Studio shared agents that already have an owner' {
        Test-Reassignable (New-Pkg 'P_1' 'a' -Type 'shared' -OwnerId 'u1') | Should -BeTrue
        Test-Reassignable (New-Pkg 'P_2' 'b' -Type 'thirdParty' -OwnerId 'u1') | Should -BeFalse
        Test-Reassignable (New-Pkg 'P_3' 'c' -Type 'lob' -OwnerId 'u1') | Should -BeFalse
        Test-Reassignable (New-Pkg 'P_4' 'd' -Type 'firstParty' -OwnerId 'u1') | Should -BeFalse
    }
    It 'refuses an ownerless agent and an agent from another platform, with the reason' {
        Get-ReassignBlock (New-Pkg 'P_5' 'e') | Should -BeLike 'no current owner*'
        Get-ReassignBlock (New-Pkg 'P_6' 'f' -OwnerId '00000000-0000-0000-0000-000000000000') | Should -BeLike 'no current owner*'
        $sdk = New-Pkg 'P_7' 'fabrikam' -OwnerId 'u1'; $sdk.platform = 'Not Available'
        Get-ReassignBlock $sdk | Should -Be 'not created by Copilot Studio'
    }
}
Describe 'Agent detail helpers' {
    It 'parses array elements that are JSON text, as Defender returns declared tools' {
        $raw = @('{"name":"search_web","type":"capability"}', '{"name":"Send mail","type":"api_action"}')
        $items = @(ConvertTo-ObjectList $raw)
        $items.Count | Should -Be 2
        $items[0].name | Should -Be 'search_web'
        (Get-NameText $raw) | Should -Be 'search_web; Send mail'
    }
    It 'accepts a JSON array in one string, plain strings, and empty values' {
        @(ConvertTo-ObjectList '[{"name":"a"},{"name":"b"}]').name | Should -Be @('a', 'b')
        @(ConvertTo-ObjectList 'MsTeams').Count | Should -Be 1
        @(ConvertTo-ObjectList $null).Count | Should -Be 0
        @(ConvertTo-ObjectList '[]').Count | Should -Be 0
    }
    It 'labels agent kinds in plain words' {
        Get-TypeLabel 'shared' | Should -Be 'Shared by a creator'
        Get-TypeLabel 'lob' | Should -Be 'Org-published'
        Get-TypeLabel 'firstParty' | Should -Be 'Microsoft'
        Get-TypeLabel 'thirdParty' | Should -Be 'Partner or store app'
    }
}

Describe 'Get-AgentInfoTable' {
    It 'turns Defender rows into per-agent tools, MCP servers, sharing and channels' {
        Mock Invoke-HuntingQuery { @([pscustomobject]@{
            TitleId = 't_abc'; Platform = 'Copilot Studio'; Model = 'M'; PublishedStatus = 'Published'; LifecycleStatus = 'Active'
            Channels = 'MsTeams Microsoft365Copilot'
            DeclaredTools = @('{"type":"capability","name":"search_web","authenticationUsed":{"type":"Invoker"}}')
            McpServers = @('{"name":"Work IQ Mail","type":"api_action","approvalModeKind":"never"}')
            DeclaredDataSources = @('https://example.com'); Capabilities = @('Public sites'); SharedWith = @('grp'); Owners = @('u1')
            ConnectedAgents = $null; Endpoints = $null; Triggers = $null; Instructions = 'be helpful' }) }
        $i = (Get-AgentInfoTable -TitleId 't_abc')['t_abc']
        $i.Tools[0].Name | Should -Be 'search_web'
        $i.Tools[0].Authentication | Should -Be 'Invoker'
        $i.McpServers[0].Name | Should -Be 'Work IQ Mail'
        $i.Channels | Should -Be @('MsTeams', 'Microsoft365Copilot')
        $i.SharedWith.Count | Should -Be 1
        $i.SharedCount | Should -Be 1
    }
}

Describe 'Permission and risk helpers' {
    BeforeEach {
        $script:perms = @(
            [pscustomobject]@{ Source = 'Agent identity'; Kind = 'Delegated'; Resource = 'Azure API Connections'; Permission = 'Runtime.All'; Consent = 'AllPrincipals' },
            [pscustomobject]@{ Source = 'Blueprint (inherited)'; Kind = 'Application'; Resource = 'Microsoft Graph'; Permission = 'AgentIdentity.CreateAsManager'; Consent = 'Admin' },
            [pscustomobject]@{ Source = 'Agent identity'; Kind = 'Delegated'; Resource = 'Agent Tools'; Permission = 'McpServers.Mail.All'; Consent = 'AllPrincipals' })
    }
    It 'matches any permission, Graph application permissions and MCP permissions' {
        Test-PermissionMatch -Perms $script:perms -Mode 'any' | Should -BeTrue
        Test-PermissionMatch -Perms @() -Mode 'any' | Should -BeFalse
        Test-PermissionMatch -Perms $script:perms -Mode 'graphapp' | Should -BeTrue
        Test-PermissionMatch -Perms @($script:perms[0]) -Mode 'graphapp' | Should -BeFalse
        Test-PermissionMatch -Perms $script:perms -Mode 'mcp' | Should -BeTrue
        Test-PermissionMatch -Perms @($script:perms[0], $script:perms[1]) -Mode 'mcp' | Should -BeFalse
    }
    It 'combines identity and blueprint permissions and looks the blueprint up once' {
        $script:script_bpCalls = 0
        $script:BlueprintPermCache = @{}
        Mock Get-IdentityPermissions { param($ServicePrincipalId, $Source) @([pscustomobject]@{ Source = $Source; Kind = 'Delegated'; Resource = 'R'; Permission = "p-$ServicePrincipalId"; Consent = 'x' }) }
        Mock Invoke-Graph { $script:script_bpCalls++; [pscustomobject]@{ value = @([pscustomobject]@{ id = 'bp-sp'; displayName = 'BP' }) } }
        $first = @(Get-AgentPermissionList -AgentIdentityId 'id1' -BlueprintAppId 'bp-app')
        $second = @(Get-AgentPermissionList -AgentIdentityId 'id2' -BlueprintAppId 'bp-app')
        $first.Source | Should -Be @('Agent identity', 'Blueprint (inherited)')
        $second.Count | Should -Be 2
        $script:script_bpCalls | Should -Be 1
    }
    It 'finds an agent''s risk entry by any of its identifiers' {
        Mock Get-RiskCached { @{ 't_abc' = [pscustomobject]@{ Severity = 'High'; AlertCount = 2; DetectionCount = 1 } } }
        (Get-AgentRisk (New-Pkg 'T_ABC' 'x')).Severity | Should -Be 'High'
        Get-AgentRisk (New-Pkg 'T_other' 'y') | Should -BeNullOrEmpty
    }
}

Describe 'Agents with no Defender record count as having nothing' {
    It 'Get-ItemList drops nulls so an empty value counts as zero' {
        @(Get-ItemList $null).Count | Should -Be 0
        @(Get-ItemList @()).Count | Should -Be 0
        @(Get-ItemList @($null, 'a')).Count | Should -Be 1
    }
    It 'reports zero tools, MCP servers and sharing for an agent missing from the table' {
        $row = Get-InventoryRows -Packages @(New-Pkg 'P_none' 'Store app' -Type 'thirdParty') -InfoTable @{}
        $row.ToolCount | Should -Be 0
        $row.SharedWithCount | Should -Be 0
        $row.McpServers | Should -BeNullOrEmpty
    }
    It 'counts real tools and MCP servers for an agent that has them' {
        $info = [pscustomobject]@{ Platform = 'Copilot Studio'; Channels = @(); Model = ''; PublishedStatus = ''
            Tools = @([pscustomobject]@{ Name = 'a' }, [pscustomobject]@{ Name = 'b' }); McpServers = @([pscustomobject]@{ Name = 'Work IQ Mail' })
            DataSources = @(); Capabilities = @(); SharedWith = @('g1'); SharedCount = 1 }
        $row = Get-InventoryRows -Packages @(New-Pkg 'P_has' 'Agent') -InfoTable @{ 'p_has' = $info }
        $row.ToolCount | Should -Be 2
        $row.McpServers | Should -Be 'Work IQ Mail'
        $row.SharedWithCount | Should -Be 1
    }
}

Describe 'Graph batching' {
    BeforeEach {
        Mock Write-Progress { }
        Mock Write-Warning { }
        Mock Start-Sleep { }
        $script:batchCalls = @()
    }
    It 'sends requests 20 at a time and returns every result by id' {
        Mock Invoke-Graph {
            $reqs = @(($Body | ConvertFrom-Json).requests)
            $script:batchCalls += , $reqs.Count
            [pscustomobject]@{ responses = @($reqs | ForEach-Object { [pscustomobject]@{ id = $_.id; status = 200; body = [pscustomobject]@{ echo = $_.url } } }) }
        }
        $reqs = 1..45 | ForEach-Object { @{ id = "r$_"; method = 'GET'; url = "/x/$_" } }
        $res = Invoke-GraphBatch -Requests $reqs
        $script:batchCalls | Should -Be @(20, 20, 5)
        $res.Count | Should -Be 45
        $res['r33'].Body.echo | Should -Be '/x/33'
    }
    It 'retries only the throttled sub-requests and then completes' {
        $script:seen = @{}
        Mock Invoke-Graph {
            $reqs = @(($Body | ConvertFrom-Json).requests)
            [pscustomobject]@{ responses = @($reqs | ForEach-Object {
                $n = 1 + [int]$script:seen[$_.id]; $script:seen[$_.id] = $n
                if ($_.id -eq 'r2' -and $n -lt 3) { [pscustomobject]@{ id = $_.id; status = 429; headers = [pscustomobject]@{ 'Retry-After' = '1' }; body = $null } }
                else { [pscustomobject]@{ id = $_.id; status = 200; body = [pscustomobject]@{ ok = $true } } } }) }
        }
        $res = Invoke-GraphBatch -Requests @(@{ id = 'r1'; method = 'GET'; url = '/a' }, @{ id = 'r2'; method = 'GET'; url = '/b' })
        $res['r2'].Status | Should -Be 200
        $script:seen['r1'] | Should -Be 1
        $script:seen['r2'] | Should -Be 3
    }
    It 'gives up after repeated throttling and reports 429' {
        Mock Invoke-Graph { $reqs = @(($Body | ConvertFrom-Json).requests); [pscustomobject]@{ responses = @($reqs | ForEach-Object { [pscustomobject]@{ id = $_.id; status = 429; body = $null } }) } }
        (Invoke-GraphBatch -Requests @(@{ id = 'r1'; method = 'GET'; url = '/a' }))['r1'].Status | Should -Be 429
    }
    It 'handles a thousand requests without per-request cost growing' {
        Mock Invoke-Graph { $reqs = @(($Body | ConvertFrom-Json).requests); [pscustomobject]@{ responses = @($reqs | ForEach-Object { [pscustomobject]@{ id = $_.id; status = 200; body = $null } }) } }
        $reqs = 1..1000 | ForEach-Object { @{ id = "r$_"; method = 'GET'; url = "/x/$_" } }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        (Invoke-GraphBatch -Requests $reqs).Count | Should -Be 1000
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 15
    }
}

Describe 'Bulk prefetch caches' {
    BeforeEach {
        Mock Write-Progress { }
        Mock Start-Sleep { }
        $script:UserCache = @{}; $script:ManagerCache = @{}; $script:IdentityOwnerCache = @{}
        $script:g1 = '11111111-1111-1111-1111-111111111111'; $script:g2 = '22222222-2222-2222-2222-222222222222'; $script:g3 = '33333333-3333-3333-3333-333333333333'
    }
    It 'caches found and missing users, skips non-ids and already cached ones' {
        $script:asked = @()
        Mock Invoke-GraphBatch {
            $script:asked = @($Requests | ForEach-Object { $_.id })
            $h = @{}
            $h[$script:g1] = [pscustomobject]@{ Status = 200; Body = [pscustomobject]@{ id = $script:g1; userPrincipalName = 'a@contoso.com'; displayName = 'A'; accountEnabled = $true } }
            $h[$script:g2] = [pscustomobject]@{ Status = 404; Body = $null }
            $h
        }
        Initialize-UserCache -Ids @($script:g1, $script:g2, 'not-a-guid', '00000000-0000-0000-0000-000000000000', $script:g1.ToUpper())
        $script:asked.Count | Should -Be 2
        $script:UserCache[$script:g1].Upn | Should -Be 'a@contoso.com'
        $script:UserCache[$script:g2].Exists | Should -BeFalse
        Initialize-UserCache -Ids @($script:g1, $script:g2)
        Should -Invoke Invoke-GraphBatch -Times 1
    }
    It 'does not cache a user whose lookup failed for another reason' {
        Mock Invoke-GraphBatch { @{ $script:g3 = [pscustomobject]@{ Status = 500; Body = $null } } }
        Initialize-UserCache -Ids @($script:g3)
        $script:UserCache.ContainsKey($script:g3) | Should -BeFalse
    }
    It 'reads identity owners in bulk and makes Get-IdentityOwners use the cache' {
        Mock Invoke-GraphBatch {
            if ($Version -eq 'beta') { @{ 'idn1' = [pscustomobject]@{ Status = 200; Body = [pscustomobject]@{ value = @([pscustomobject]@{ id = $script:g1; '@odata.type' = '#microsoft.graph.user' }) } } } }
            else { @{ $script:g1 = [pscustomobject]@{ Status = 200; Body = [pscustomobject]@{ id = $script:g1; userPrincipalName = 'o@contoso.com'; displayName = 'O'; accountEnabled = $true } } } }
        }
        Mock Invoke-Graph { throw 'Should not call Graph one by one' }
        Initialize-IdentityOwnerCache -AgentIdentityIds @('idn1')
        (Get-IdentityOwners 'idn1').Upn | Should -Be 'o@contoso.com'
    }
    It 'records managers and uses them without another call' {
        Mock Invoke-GraphBatch {
            if ($Requests[0].url -like '*/manager*') { @{ $script:g1 = [pscustomobject]@{ Status = 200; Body = [pscustomobject]@{ id = $script:g2 } }; $script:g3 = [pscustomobject]@{ Status = 404; Body = $null } } }
            else { @{ $script:g2 = [pscustomobject]@{ Status = 200; Body = [pscustomobject]@{ id = $script:g2; userPrincipalName = 'boss@contoso.com'; displayName = 'Boss'; accountEnabled = $true } } } }
        }
        Mock Invoke-Graph { throw 'Should not call Graph one by one' }
        Initialize-ManagerCache -UserIds @($script:g1, $script:g3)
        (Get-ManagerInfo $script:g1).Upn | Should -Be 'boss@contoso.com'
        Get-ManagerInfo $script:g3 | Should -BeNullOrEmpty
    }
}

Describe 'Get-Packages paging' {
    It 'follows nextLink to the end and keeps every package' {
        $script:page = 0
        Mock Write-Progress { }
        Mock Invoke-Graph {
            $script:page++
            $items = 1..1000 | ForEach-Object { @{ id = "P_$($script:page)_$_"; displayName = "n$_"; supportedHosts = @('Copilot') } }
            $r = @{ value = $items }
            if ($script:page -lt 12) { $r['@odata.nextLink'] = "https://graph.microsoft.com/next$($script:page)" }
            $r
        }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $all = @(Get-Packages)
        $all.Count | Should -Be 12000
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 20
        $script:page = 0
        @(Get-Packages -AgentsOnly).Count | Should -Be 12000
    }
}

Describe 'Bulk permission, detail and identity-state reads' {
    BeforeEach {
        Mock Write-Progress { }
        Mock Start-Sleep { }
        $script:ResourceCache = @{}; $script:BlueprintPermCache = @{}
    }
    It 'reads permissions for many agents in batched calls and adds blueprint permissions once' {
        $script:batchRequests = 0
        Mock Invoke-GraphBatch {
            $script:batchRequests += @($Requests).Count
            $h = @{}
            foreach ($r in $Requests) {
                if ($r.id -like 'g:*') { $h[$r.id] = [pscustomobject]@{ Status = 200; Body = [pscustomobject]@{ value = @([pscustomobject]@{ resourceId = 'res1'; scope = ' Runtime.All'; consentType = 'AllPrincipals' }) } } }
                elseif ($r.id -like 'r:*') { $h[$r.id] = [pscustomobject]@{ Status = 200; Body = [pscustomobject]@{ value = @() } } }
                elseif ($r.url -like '/servicePrincipals/res1*') { $h[$r.id] = [pscustomobject]@{ Status = 200; Body = [pscustomobject]@{ displayName = 'Azure API Connections'; appRoles = @() } } }
                elseif ($r.url.StartsWith('/servicePrincipals?')) { $h[$r.id] = [pscustomobject]@{ Status = 200; Body = [pscustomobject]@{ value = @([pscustomobject]@{ id = 'bp-sp' }) } } }
            }
            $h
        }
        $items = 1..30 | ForEach-Object { @{ Key = "k$_"; ServicePrincipalId = "sp$_"; BlueprintAppId = 'bp-app' } }
        $got = Get-PermissionsBulk -Items $items
        $got.Count | Should -Be 30
        $got['k7'].Source | Should -Be @('Agent identity', 'Blueprint (inherited)')
        $got['k7'][0].Resource | Should -Be 'Azure API Connections'
        $got['k7'][0].Permission | Should -Be 'Runtime.All'
        # 1 blueprint lookup + 2 per identity + 2 for the blueprint SP + 1 resource lookup
        $script:batchRequests | Should -Be (1 + 60 + 2 + 1)
    }
    It 'maps package details and identity states by id' {
        Mock Invoke-GraphBatch {
            $h = @{}
            foreach ($r in $Requests) { $h[$r.id] = if ($r.id -eq 'bad') { [pscustomobject]@{ Status = 404; Body = $null } } else { [pscustomobject]@{ Status = 200; Body = [pscustomobject]@{ id = $r.id; activeUsers = 4; accountEnabled = $false } } } }
            $h
        }
        $d = Get-PackageDetailMap -Ids @('a', 'b', 'bad')
        $d['a'].activeUsers | Should -Be 4
        $d.ContainsKey('bad') | Should -BeFalse
        $s = Get-AgentIdentityStateMap -AgentIdentityIds @('i1', 'bad')
        $s['i1'] | Should -BeFalse
        $s['bad'] | Should -BeNullOrEmpty
    }
}

Describe 'Throttling signalled as 424' {
    BeforeEach {
        Mock Write-Progress { }
        Mock Write-Warning { }
        $script:sleeps = @()
        Mock Start-Sleep { $script:sleeps += [double]$(if ($Seconds) { $Seconds } else { $Milliseconds / 1000 }) }
    }
    It 'retries batch sub-requests that fail with 424 Too Many Requests, and waits longer than for 429' {
        $script:n = @{}
        Mock Invoke-Graph {
            $reqs = @(($Body | ConvertFrom-Json).requests)
            [pscustomobject]@{ responses = @($reqs | ForEach-Object {
                $c = 1 + [int]$script:n[$_.id]; $script:n[$_.id] = $c
                if ($c -lt 2) { [pscustomobject]@{ id = $_.id; status = 424; body = [pscustomobject]@{ error = [pscustomobject]@{ message = '{"StatusCode":424,"Message":"Too Many Requests"}' } } } }
                else { [pscustomobject]@{ id = $_.id; status = 200; body = [pscustomobject]@{ ok = 1 } } } }) }
        }
        $res = Invoke-GraphBatch -Requests @(@{ id = 'a'; method = 'GET'; url = '/x' }, @{ id = 'b'; method = 'GET'; url = '/y' }) -Version beta
        $res['a'].Status | Should -Be 200
        $res['b'].Status | Should -Be 200
        ($script:sleeps | Measure-Object -Maximum).Maximum | Should -BeGreaterOrEqual 10
    }
    It 'does not treat a 424 without the throttling message as retryable' {
        Mock Invoke-Graph {
            $reqs = @(($Body | ConvertFrom-Json).requests)
            [pscustomobject]@{ responses = @($reqs | ForEach-Object { [pscustomobject]@{ id = $_.id; status = 424; body = [pscustomobject]@{ error = [pscustomobject]@{ message = 'dependency failed' } } } }) }
        }
        $res = Invoke-GraphBatch -Requests @(@{ id = 'a'; method = 'GET'; url = '/x' })
        $res['a'].Status | Should -Be 424
        Should -Invoke Invoke-Graph -Times 1
    }
    It 'paces chunks when a pace is given' {
        Mock Invoke-Graph { $reqs = @(($Body | ConvertFrom-Json).requests); [pscustomobject]@{ responses = @($reqs | ForEach-Object { [pscustomobject]@{ id = $_.id; status = 200; body = $null } }) } }
        $reqs = 1..30 | ForEach-Object { @{ id = "r$_"; method = 'GET'; url = "/x/$_" } }
        Invoke-GraphBatch -Requests $reqs -ChunkSize 10 -PaceSeconds 0.3 | Out-Null
        Should -Invoke Invoke-Graph -Times 3
        @($script:sleeps | Where-Object { $_ -gt 2 }).Count | Should -Be 3
    }
    It 'retries a single Graph call that answers 424' {
        $script:calls = 0
        Mock Invoke-MgGraphRequest {
            $script:calls++
            if ($script:calls -lt 2) {
                $ex = [System.Net.Http.HttpRequestException]::new('424'); $ex | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{ StatusCode = 424; Headers = [pscustomobject]@{ RetryAfter = $null } }) -Force; throw $ex
            }
            'ok'
        }
        Invoke-Graph -Uri 'https://graph.microsoft.com/beta/x' | Should -Be 'ok'
        $script:calls | Should -Be 2
    }
}

Describe 'Batch pacing stays bounded under heavy throttling' {
    It 'never sleeps more than a few seconds per request even when many sub-requests are throttled' {
        Mock Write-Progress { }
        Mock Write-Warning { }
        $script:sleepMs = @()
        Mock Start-Sleep { if ($Milliseconds) { $script:sleepMs += [double]$Milliseconds } }
        Mock Invoke-Graph {
            $reqs = @(($Body | ConvertFrom-Json).requests)
            [pscustomobject]@{ responses = @($reqs | ForEach-Object { [pscustomobject]@{ id = $_.id; status = 424; body = [pscustomobject]@{ error = [pscustomobject]@{ message = 'Too Many Requests' } } } }) }
        }
        $reqs = 1..200 | ForEach-Object { @{ id = "r$_"; method = 'GET'; url = "/x/$_" } }
        Invoke-GraphBatch -Requests $reqs -ChunkSize 10 -PaceSeconds 0.3 | Out-Null
        $perRequest = ($script:sleepMs | Measure-Object -Maximum).Maximum / 10
        $perRequest | Should -BeLessOrEqual 2100   # ms per request, capped at 2 seconds
    }
}

Describe 'Write loop pacing and scale' {
    BeforeEach {
        Mock Write-Host { }
        Mock Write-Progress { }
        Mock Test-Proceed { $true }
        $OutFile = $null
        $DisableIdentity = $false
    }
    It 'slows down after a throttled call and eases off when calls are clean' {
        $script:sleepsMs = @(); $script:calls = 0
        Mock Start-Sleep { if ($Milliseconds) { $script:sleepsMs += [double]$Milliseconds } }
        Mock Invoke-Graph { $script:calls++; if ($script:calls -eq 3) { Add-ThrottleHit } }
        $pk = 1..12 | ForEach-Object { New-Pkg "P_$_" "A$_" }
        Invoke-PackageAction -Packages $pk -Action block | Out-Null
        $script:calls | Should -Be 12
        ($script:sleepsMs | Measure-Object -Maximum).Maximum | Should -BeGreaterOrEqual 500     # backed off after the throttle
        ($script:sleepsMs | Measure-Object -Maximum).Maximum | Should -BeLessOrEqual 3000
        $script:sleepsMs[-1] | Should -BeLessThan 500                                          # and eased back
    }
    It 'handles a large batch of blocks without slowing per item' {
        Mock Invoke-Graph { }
        $pk = 1..3000 | ForEach-Object { New-Pkg "P_$_" "A$_" }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $log = @(Invoke-PackageAction -Packages $pk -Action block -PassThru)
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 30
        $log.Count | Should -Be 3000
        @($log | Where-Object Result -eq 'Done').Count | Should -Be 3000
    }
}

Describe 'Large inputs stay linear' {
    It 'compares snapshots of 20,000 agents quickly' {
        $old = [pscustomobject]@{ items = @(1..20000 | ForEach-Object { [pscustomobject]@{ id = "T_$_"; displayName = "a$_"; isBlocked = $false; ownerId = 'o'; version = '1' } }) }
        $now = @(1..20000 | ForEach-Object { New-Pkg "T_$_" "a$_" -Blocked ($_ % 1000 -eq 0) -OwnerId 'o' })
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $c = @(Compare-Snapshot -Old $old -Current $now)
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 30
        @($c | Where-Object Change -eq 'Blocked').Count | Should -Be 20
    }
    It 'plans a policy over 10,000 agents quickly' {
        $cat = @(1..10000 | ForEach-Object { New-Pkg "T_$_" "a$_" -Blocked ($_ % 50 -eq 0) })
        Mock Get-Packages { $cat }
        Mock Get-StalePackages { @($cat | Select-Object -First 4000) }
        $doc = '{ "rules": [ { "name": "r", "when": { "stale": { "days": 14 } }, "then": { "action": "block" } } ] }' | ConvertFrom-Json
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $plan = @(Get-PolicyPlan $doc)
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 30
        $plan[0].Matched.Count | Should -Be 4000
    }
    It 'builds inventory rows for 10,000 agents quickly' {
        Mock Initialize-UserCache { }
        Mock Get-UserInfo { [pscustomobject]@{ Exists = $true; Enabled = $true; Upn = 'o@contoso.com' } }
        $pk = @(1..10000 | ForEach-Object { New-Pkg "T_$_" "a$_" -OwnerId 'o' })
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $rows = @(Get-InventoryRows -Packages $pk -InfoTable @{})
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 60
        $rows.Count | Should -Be 10000
    }
    It 'resolves owners for 5,000 shared agents quickly when lookups are cached' {
        Mock Initialize-UserCache { }; Mock Initialize-IdentityOwnerCache { }; Mock Initialize-ManagerCache { }
        Mock Get-UserInfo { [pscustomobject]@{ Id = 'o'; Exists = $true; Enabled = $true; Upn = 'o@contoso.com' } }
        $pk = @(1..5000 | ForEach-Object { New-Pkg "T_$_" "a$_" -OwnerId 'o' })
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $rep = Get-OwnerReport -Packages $pk
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 60
        $rep.OkCount | Should -Be 5000
    }
}

Describe 'Lean Defender read for many agents' {
    BeforeEach { Mock Write-Progress { } }
    It 'reads tool and MCP server names and counts without descriptions or instructions' {
        $script:queries = @()
        Mock Invoke-HuntingQuery {
            $script:queries += $Query
            if ($Query -like '*summarize n = dcount*') { return @([pscustomobject]@{ n = 2 }) }
            @([pscustomobject]@{ TitleId = 't_a'; Platform = 'Copilot Studio'; EntraBlueprintID = 'bp1'; ToolNames = @('search_web', 'Send mail'); McpNames = @('Work IQ Mail')
                Channels = 'MsTeams'; DeclaredDataSources = @('https://x.com'); Capabilities = @(); SharedCount = 3 },
              [pscustomobject]@{ TitleId = 't_b'; Platform = 'Foundry'; EntraBlueprintID = ''; ToolNames = $null; McpNames = $null; Channels = $null; DeclaredDataSources = $null; Capabilities = $null; SharedCount = 0 })
        }
        $t = Get-AgentInfoTable
        $t['t_a'].Tools.Name | Should -Be @('search_web', 'Send mail')
        $t['t_a'].McpServers.Name | Should -Be 'Work IQ Mail'
        $t['t_a'].SharedCount | Should -Be 3
        $t['t_a'].BlueprintId | Should -Be 'bp1'
        @($t['t_b'].Tools).Count | Should -Be 0
        @($t['t_b'].McpServers).Count | Should -Be 0
        ($script:queries -join ' ') | Should -Not -Match 'Instructions'
        ($script:queries -join ' ') | Should -Not -Match 'where hash'
    }
    It 'splits a very large tenant into chunks' {
        $script:queries = @()
        Mock Invoke-HuntingQuery {
            $script:queries += $Query
            if ($Query -like '*summarize n = dcount*') { return @([pscustomobject]@{ n = 6000 }) }
            @()
        }
        Get-AgentInfoTable | Out-Null
        $script:queries.Count | Should -Be 4                       # one count plus three chunks of up to 2,500
        @($script:queries | Where-Object { $_ -match 'hash\(tostring\(AgentId\), 3\) == [012]' }).Count | Should -Be 3
    }
}
Describe 'Lean read keeps exact counts' {
    It 'pads unnamed entries so the count matches array_length' {
        $e = @(New-NamedEntries -Names @('a', 'b') -Count 5)
        $e.Count | Should -Be 5
        @($e | Where-Object Name).Count | Should -Be 2
        @(New-NamedEntries -Names $null -Count 0).Count | Should -Be 0
        @(New-NamedEntries -Names @('a', 'b', 'c') -Count 2).Count | Should -Be 3   # never fewer than the names found
    }
    It 'asks Defender for exact counts and a quote-tolerant name match' {
        $script:q = ''
        Mock Write-Progress { }
        Mock Invoke-HuntingQuery { if ($Query -like '*summarize n = dcount*') { return @([pscustomobject]@{ n = 1 }) }; $script:q = $Query; @() }
        Get-AgentInfoTable | Out-Null
        $script:q | Should -Match 'ToolCount = array_length'
        $script:q | Should -Match 'McpCount = array_length'
        $script:q | Should -Match 'extract_all'
    }
    It 'names listing skips unnamed entries' {
        (Get-NameText @([pscustomobject]@{ Name = 'x' }, [pscustomobject]@{ Name = '' })) | Should -Be 'x'
    }
}

Describe 'Get-PlatformLabel' {
    It 'uses the catalog platform when it names one, with readable names' {
        (Get-PlatformLabel (New-Pkg 'P_1' 'a') $null) | Should -Be 'Copilot Studio'
        $b = New-Pkg 'P_2' 'b'; $b.platform = 'AmazonBedrock'
        (Get-PlatformLabel $b $null) | Should -Be 'Amazon Bedrock'
    }
    It 'falls back to a specific Defender platform, ignoring Other' {
        $p = New-Pkg 'P_3' 'c'; $p.platform = 'Not Available'
        (Get-PlatformLabel $p ([pscustomobject]@{ Platform = 'Microsoft Foundry' })) | Should -Be 'Foundry'
        (Get-PlatformLabel $p ([pscustomobject]@{ Platform = 'Other' })) | Should -Be 'Microsoft 365 app'
    }
    It 'recognises SDK-onboarded agents by their agent identity or blueprint' {
        $sdk = New-Pkg 'P_4' 'fabrikam' -IdentityId 'identity-1'; $sdk.platform = 'Not Available'
        (Get-PlatformLabel $sdk $null) | Should -Be 'A365 SDK agent'
        $bp = New-Pkg 'P_5' 'x'; $bp.platform = 'Not Available'
        (Get-PlatformLabel $bp ([pscustomobject]@{ Platform = 'Other'; BlueprintId = 'bp-1' })) | Should -Be 'A365 SDK agent'
    }
}

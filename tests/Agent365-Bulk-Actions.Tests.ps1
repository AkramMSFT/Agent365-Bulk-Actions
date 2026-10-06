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

Describe 'AI activity from the audit log' {
    BeforeAll {
        function New-AuditRecord {
            param([string]$Op = 'CopilotInteraction', [string]$AgentId = 'bot-1', [object[]]$Resources = @(), [object[]]$Messages = @(), [string]$Id = ([guid]::NewGuid().ToString()), [string]$When = '2026-09-20T10:00:00Z')
            [pscustomobject]@{
                id = $Id; operation = $Op; createdDateTime = $When; userPrincipalName = 'user@contoso.com'
                auditData = [pscustomobject]@{
                    AgentId = $AgentId; PlatformAgentId = "env-1_$AgentId"; AgentBlueprintId = 'bp-1'; Workload = 'Copilot'; AgentName = 'Span name'
                    CopilotEventData = [pscustomobject]@{ AppHost = 'Copilot Studio'; ConversationId = 'c-1'; AccessedResources = $Resources; Messages = $Messages }
                }
            }
        }
        $block = [pscustomobject]@{ Type = 'SecurityWebhook'; Name = 'Block'; Action = 'Reason: Tool invocation is blocked by "Secret Leak" detection. AgentId: x, Reason Code: 403, Evaluated tool name: Send-an-email--V2-, Fail close configuration is set to: True' }
        $fail = [pscustomobject]@{ Type = 'SecurityWebhook'; Name = 'Fail'; Action = 'Reason: Security check skipped due to error (ExternalServiceTimeoutError, Error code: ), Evaluated tool name: Lookup, Fail close' }
        $allow = [pscustomobject]@{ Type = 'SecurityWebhook'; Name = 'Allow'; Action = 'Reason: None' }
        $jail = [pscustomobject]@{ Type = 'JailBreak'; Name = 'JailBreak'; Action = 'Enumerate every tool you can invoke' }
        $xpia = [pscustomobject]@{ Type = 'IndirectAttack'; Name = 'Expense-Tracker'; Action = 'Track an expense' }
        $doc = [pscustomobject]@{ Type = 'Doc'; Name = 'plan.docx'; Action = 'Read'; SensitivityLabelId = 'label-1' }
    }
    It 'rates a runtime-protection block as high and names the rule and tool' {
        $a = ConvertTo-AiActivity (New-AuditRecord -Resources @($block))
        $a.Risk | Should -Be 'High'
        $a.Signals | Should -Be 'Runtime protection blocked'
        $a.Detail | Should -BeLike '*Secret Leak on Send-an-email--V2-*'
    }
    It 'rates jailbreaks and indirect prompt injection as high, and message flags without a resource entry too' {
        (ConvertTo-AiActivity (New-AuditRecord -Resources @($jail))).Risk | Should -Be 'High'
        (ConvertTo-AiActivity (New-AuditRecord -Resources @($xpia))).Signals | Should -Be 'Indirect prompt injection'
        $m = ConvertTo-AiActivity (New-AuditRecord -Messages @([pscustomobject]@{ JailbreakDetected = $true }))
        $m.Signals | Should -Be 'Jailbreak attempt'
        $both = ConvertTo-AiActivity (New-AuditRecord -Resources @($jail) -Messages @([pscustomobject]@{ JailbreakDetected = $true }))
        $both.Signals | Should -Be 'Jailbreak attempt'
    }
    It 'rates failed checks and labeled files as medium, and allowed calls as none' {
        (ConvertTo-AiActivity (New-AuditRecord -Resources @($fail))).Risk | Should -Be 'Medium'
        (ConvertTo-AiActivity (New-AuditRecord -Resources @($doc))).Signals | Should -Be 'Labeled file accessed'
        (ConvertTo-AiActivity (New-AuditRecord -Resources @($allow))).Risk | Should -Be 'None'
        (ConvertTo-AiActivity (New-AuditRecord -Resources @($allow, $fail, $block))).Risk | Should -Be 'High'
    }
    It 'labels each operation once' {
        (ConvertTo-AiActivity (New-AuditRecord -Op 'AISpanOutput')).Kind | Should -Be 'Agent response'
        (ConvertTo-AiActivity (New-AuditRecord -Op 'CopilotInteraction')).Kind | Should -Be 'Interaction'
        (ConvertTo-AiActivity (New-AuditRecord -Op 'AIGuardrail')).Kind | Should -Be 'AIGuardrail'
    }
    It 'ties records to catalog agents by agent id, platform id or the id after the underscore' {
        $idx = New-AiAgentIndex -InfoTable @{ 't_1' = [pscustomobject]@{ AgentKeys = @('BOT-1', 'Default-x_src-1') }; 't_2' = [pscustomobject]@{ AgentKeys = @('obs-2') } }
        Resolve-AiActivityAgent -Activity ([pscustomobject]@{ AgentGuid = 'bot-1'; PlatformAgentId = '' }) -Index $idx | Should -Be 't_1'
        Resolve-AiActivityAgent -Activity ([pscustomobject]@{ AgentGuid = ''; PlatformAgentId = 'env_src-1' }) -Index $idx | Should -Be 't_1'
        Resolve-AiActivityAgent -Activity ([pscustomobject]@{ AgentGuid = 'obs-2'; PlatformAgentId = '' }) -Index $idx | Should -Be 't_2'
        Resolve-AiActivityAgent -Activity ([pscustomobject]@{ AgentGuid = 'nope'; PlatformAgentId = 'e_nope' }) -Index $idx | Should -Be ''
    }
    It 'summarises per agent, worst first, skipping events with no catalog agent' {
        $rows = @(
            [pscustomobject]@{ TitleId = 't_1'; Kind = 'Interaction'; Risk = 'None'; Signals = ''; User = 'a'; Time = [datetime]'2026-09-01'; AgentName = '' },
            [pscustomobject]@{ TitleId = 't_2'; Kind = 'Interaction'; Risk = 'High'; Signals = 'Jailbreak attempt'; User = 'a'; Time = [datetime]'2026-09-02'; AgentName = '' },
            [pscustomobject]@{ TitleId = 't_2'; Kind = 'Agent response'; Risk = 'None'; Signals = ''; User = 'b'; Time = [datetime]'2026-09-03'; AgentName = '' },
            [pscustomobject]@{ TitleId = ''; Kind = 'Interaction'; Risk = 'High'; Signals = 'x'; User = 'a'; Time = [datetime]'2026-09-04'; AgentName = '' })
        $s = @(Get-AiActivitySummary -Activities $rows -NameById @{ 't_1' = 'One'; 't_2' = 'Two' })
        $s.Count | Should -Be 2
        $s[0].Agent | Should -Be 'Two'; $s[0].Risk | Should -Be 'High'; $s[0].Users | Should -Be 2
        $s[0].Interactions | Should -Be 1; $s[0].Responses | Should -Be 1
        $s[1].Risk | Should -Be 'None'
    }
    It 'splits a long range into windows, merges and de-duplicates records, and tidies up its searches' {
        $script:created = 0; $script:deleted = 0
        Mock Wait-AuditPoll { }
        Mock Invoke-Graph {
            if ($Method -eq 'POST') { $script:created++; return @{ id = "q$script:created" } }
            if ($Method -eq 'DELETE') { $script:deleted++; return $null }
            if ($Uri -like '*/records*') { return @{ value = @(@{ id = 'same-record' }, @{ id = "rec-$($Uri.Length)-$script:created" }) } }
            @{ status = 'succeeded'; isRecordCountLimitExceeded = $false }
        }
        $r = @(Get-AiActivityRecords -Days 14 -WindowDays 7)
        $script:created | Should -Be 6
        $script:deleted | Should -Be 6
        @($r | Where-Object { $_.id -eq 'same-record' }).Count | Should -Be 1
    }
    It 'follows the records paging and warns when the record limit was hit' {
        Mock Wait-AuditPoll { }
        Mock Invoke-Graph {
            if ($Method -eq 'DELETE') { return $null }
            if ($Uri -like '*/next') { return @{ value = @(@{ id = 'b' }) } }
            if ($Uri -like '*/records*') { return @{ value = @(@{ id = 'a' }); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/next' } }
            @{ status = 'succeeded'; isRecordCountLimitExceeded = $true }
        }
        $out = @(Complete-AuditSearch -Id 'q1' 3>&1)
        @($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Message | Should -BeLike '*record limit*'
        @($out | Where-Object { $_ -isnot [System.Management.Automation.WarningRecord] }).Count | Should -Be 2
    }
    It 'reports a failed search instead of returning partial data silently' {
        Mock Wait-AuditPoll { }
        Mock Invoke-Graph { @{ status = 'failed' } }
        $out = @(Complete-AuditSearch -Id 'q1' 3>&1)
        @($out | Where-Object { $null -ne $_ -and $_ -isnot [System.Management.Automation.WarningRecord] }).Count | Should -Be 0
        @($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Message | Should -BeLike '*failed*'
    }
}

Describe 'Format-GraphError' {
    It 'puts the service code and message first and names the request' {
        $detail = 'GET https://graph.microsoft.com/v1.0/security/auditLog/queries/abc/records?$top=1000 HTTP/1.1 400 Bad Request Date: x request-id: y {"error":{"code":"BadRequest","message":"The query is not ready."}}'
        $m = Format-GraphError -Summary 'Response status code does not indicate success: BadRequest (Bad Request).' -Detail $detail
        $m | Should -BeLike '*BadRequest: The query is not ready.*'
        $m | Should -BeLike '*`[GET /v1.0/security/auditLog/queries/abc/records*'
        $m | Should -Not -BeLike '*request-id*'
    }
    It 'falls back to the summary when the body is not JSON' {
        (Format-GraphError -Summary 'boom' -Detail 'plain text') | Should -Be 'boom'
    }
    It 'names the failing step of an audit search' {
        Mock Wait-AuditPoll { }
        Mock Invoke-Graph { throw 'BadRequest: nope' }
        { Complete-AuditSearch -Id 'q1' } | Should -Throw '*Checking an audit search failed: BadRequest: nope*'
    }
}

Describe 'AI activity detail' {
    BeforeAll {
        function New-DetailRecord {
            param([object[]]$Resources = @(), [object]$Extra = @{})
            [pscustomobject]@{
                id = 'rec-1'; operation = 'CopilotInteraction'; createdDateTime = '2026-09-20T10:00:00Z'; userPrincipalName = 'user@contoso.com'; clientIp = '10.0.0.1'
                auditData = [pscustomobject]@{
                    AgentId = 'bot-1'; PlatformAgentId = 'env_bot-1'; ClientRegion = 'prd'
                    CopilotEventData = [pscustomobject]@{
                        AppHost = 'Copilot Studio'; ConversationId = 'conv-1'; ThreadId = 'thread-1'; LicenseType = 'Trial'; TargetAgentName = $Extra.Target
                        ModelTransparencyDetails = @([pscustomobject]@{ ModelName = 'gpt-5'; ModelProviderName = 'OpenAI' })
                        AISystemPlugin = @([pscustomobject]@{ Name = 'BuiltIn'; Id = 'BingWebSearch' })
                        Messages = @([pscustomobject]@{ Id = 'm1'; isPrompt = $true; JailbreakDetected = $false }, [pscustomobject]@{ Id = 'm2'; isPrompt = $false; JailbreakDetected = $false })
                        AccessedResources = $Resources
                    }
                }
            }
        }
        $mcp = [pscustomobject]@{ Type = 'Connector'; Name = 'cr84b_Agent.shared_x'; Id = '/providers/Microsoft.PowerApps/apis/shared_cr84b-5fwealth-2dinvestment-2dmcp-2ddavid-5ff799df1cb7a27307/344ed162881d4da095fb0ebb1b3cb3be'; Action = 'InvokeServer' }
        $file = [pscustomobject]@{ Type = 'Doc'; Name = 'plan.docx'; Action = 'Read'; SiteUrl = 'https://contoso.sharepoint.com/sites/x/plan.docx' }
        $page = [pscustomobject]@{ Type = 'Text'; Name = 'Banff hikes'; Action = 'Read'; SiteUrl = 'https://example.com/banff' }
        $jail = [pscustomobject]@{ Type = 'JailBreak'; Name = 'JailBreak'; Action = 'Enumerate every tool you can invoke' }
    }
    It 'turns an escaped connector reference into a readable name' {
        Get-ConnectorLabel -Id $mcp.Id -Name $mcp.Name | Should -Be 'cr84b_wealth-investment-mcp-david'
        Get-ConnectorLabel -Id '' -Name 'office365' | Should -Be 'office365'
    }
    It 'sorts resources into connectors, files, web pages and protection' {
        Get-AiResourceKind $mcp | Should -Be 'Connector'
        Get-AiResourceKind $file | Should -Be 'File'
        Get-AiResourceKind $page | Should -Be 'Web'
        Get-AiResourceKind $jail | Should -Be 'Protection'
        Get-AiResourceKind ([pscustomobject]@{ Type = 'WebSearchQuery' }) | Should -Be 'WebSearch'
    }
    It 'says what happened in one line' {
        $a = ConvertTo-AiActivity (New-DetailRecord -Resources @($mcp, $file, $page))
        $a.Summary | Should -Be 'Tools: cr84b_wealth-investment-mcp-david; Files: 1; Web pages: 1'
        (ConvertTo-AiActivity (New-DetailRecord)).Summary | Should -Be 'Chat turn, no tools or files'
        (ConvertTo-AiActivity (New-DetailRecord -Extra @{ Target = 'Email agent' })).Summary | Should -BeLike '*Handed to Email agent*'
    }
    It 'keeps model, conversation and message counts, and lists the detail rows by section' {
        $a = ConvertTo-AiActivity (New-DetailRecord -Resources @($mcp, $file, $jail))
        $a.Model | Should -Be 'OpenAI / gpt-5'
        $a.Prompts | Should -Be 1; $a.Responses | Should -Be 1
        $rows = @(Get-AiActivityDetailRows $a)
        ($rows | Where-Object { $_.Section -eq 'Tools and MCP' }).Item | Should -Be 'cr84b_wealth-investment-mcp-david'
        ($rows | Where-Object { $_.Section -eq 'Files' }).Item | Should -Be 'plan.docx'
        ($rows | Where-Object { $_.Section -eq 'Protection' }).Info | Should -BeLike 'Enumerate every tool*'
        ($rows | Where-Object { $_.Section -eq 'Messages' }).Info | Should -BeLike '*message ids only*'
        ($rows | Where-Object { $_.Item -eq 'Conversation' }).Info | Should -Be 'conv-1'
        ($rows | Where-Object { $_.Item -eq 'Built-in plugin' }).Info | Should -Be 'BuiltIn BingWebSearch'
    }
    It 'describes an agent response and its error' {
        $r = New-DetailRecord; $r.operation = 'AISpanOutput'
        $r.auditData | Add-Member -NotePropertyName ErrorType -NotePropertyValue 'Timeout' -Force
        $r.auditData | Add-Member -NotePropertyName ChannelName -NotePropertyValue 'Teams' -Force
        $a = ConvertTo-AiActivity $r
        $a.Summary | Should -Be 'Reply failed: Timeout'
        (@(Get-AiActivityDetailRows $a) | Where-Object { $_.Item -eq 'Error' }).Info | Should -Be 'Timeout'
    }
}

Describe 'Access scope changes' {
    BeforeEach {
        Mock Write-Host { }
        Mock Export-ActionLog { }
        Mock Test-Proceed { $true }
        $script:patches = @()
        $script:state = @{ availableTo = 'allowedForAll'; deployedTo = 'acquiredForNone'; allowedUsersAndGroups = @(); acquireUsersAndGroups = @() }
    }
    It 'builds a body with only what the target needs' {
        $none = New-AccessPatchBody -AvailableTo 'allowedForNone'
        @($none.Keys) | Should -Be @('availableTo')
        $some = New-AccessPatchBody -AvailableTo 'allowedForSome' -Allowed @([pscustomobject]@{ resourceType = 'user'; resourceId = 'u1' })
        ($some | ConvertTo-Json -Depth 5 -Compress) | Should -Match '"allowedUsersAndGroups":\[\{.*"resourceId":"u1"'
        $dep = New-AccessPatchBody -AvailableTo 'allowedForNone' -DeployedTo 'acquiredForNone' -IncludeDeployment
        $dep['deployedTo'] | Should -Be 'acquiredForNone'
        (New-AccessPatchBody -AvailableTo 'allowedForNone' -DeployedTo 'acquiredForNone').Contains('deployedTo') | Should -BeFalse
    }
    It 'reads the current scope and compares user lists regardless of order or case' {
        $s = Get-AccessState ([pscustomobject]@{ availableTo = 'allowedForSome'; allowedUsersAndGroups = @([pscustomobject]@{ resourceType = 'user'; resourceId = 'U1' }); deployedTo = 'acquiredForNone'; acquireUsersAndGroups = $null })
        $s.AvailableTo | Should -Be 'allowedForSome'; @($s.Allowed).Count | Should -Be 1; @($s.Acquire).Count | Should -Be 0
        Test-SameEntities @([pscustomobject]@{ resourceType = 'user'; resourceId = 'U1' }, [pscustomobject]@{ resourceType = 'group'; resourceId = 'g' }) @([pscustomobject]@{ resourceType = 'group'; resourceId = 'G' }, [pscustomobject]@{ resourceType = 'user'; resourceId = 'u1' }) | Should -BeTrue
        Test-SameEntities @([pscustomobject]@{ resourceType = 'user'; resourceId = 'u1' }) @() | Should -BeFalse
    }
    It 'resolves users and groups, and refuses a missing user or an ambiguous group' {
        Mock Get-UserInfo { if ($IdOrUpn -eq 'gone@x.com') { [pscustomobject]@{ Exists = $false; Enabled = $false } } else { [pscustomobject]@{ Id = 'u1'; Upn = $IdOrUpn; Exists = $true; Enabled = $true } } }
        Mock Invoke-Graph { if ($Uri -like '*Sales*') { @{ value = @(@{ id = 'g1'; displayName = 'Sales' }) } } else { @{ value = @(@{ id = 'a' }, @{ id = 'b' }) } } }
        $e = @(Resolve-AccessEntities -Users 'a@x.com' -Groups 'Sales')
        ($e | ForEach-Object { "$($_.resourceType):$($_.resourceId)" }) | Should -Be @('user:u1', 'group:g1')
        { Resolve-AccessEntities -Users 'gone@x.com' } | Should -Throw '*not an existing, enabled user*'
        { Resolve-AccessEntities -Groups 'Dup' } | Should -Throw '*matched 2*'
    }
    It 'reads the old scope first, logs it, then narrows availability' {
        Mock Invoke-Graph {
            if ($Method -eq 'PATCH') { $script:patches += ,@{ Uri = $Uri; Body = $Body }; return $null }
            $script:state
        }
        $log = @(Invoke-AvailabilityChange -Packages @((New-Pkg 'T_a' 'Alpha')) -To None -PassThru)
        $log[0].Result | Should -Be 'Done'
        $log[0].WasAvailableTo | Should -Be 'allowedForAll'
        $log[0].NewAvailableTo | Should -Be 'allowedForNone'
        $script:patches.Count | Should -Be 1
        ($script:patches[0].Body | ConvertFrom-Json).availableTo | Should -Be 'allowedForNone'
        $script:patches[0].Uri | Should -BeLike '*/T_a'
    }
    It 'skips an agent that already has the target scope and sends nothing' {
        $script:state.availableTo = 'allowedForNone'
        Mock Invoke-Graph { if ($Method -eq 'PATCH') { $script:patches += 1; return $null }; $script:state }
        $log = @(Invoke-AvailabilityChange -Packages @((New-Pkg 'T_a' 'Alpha')) -To None -PassThru)
        $log[0].Result | Should -Be 'Skipped'
        $script:patches.Count | Should -Be 0
    }
    It 'keeps each agent available to its owner with -OwnerOnly, and fails one with no valid owner' {
        Mock Get-UserInfo { if ($IdOrUpn -eq 'o1') { [pscustomobject]@{ Id = 'o1'; Upn = 'o1@x.com'; Exists = $true; Enabled = $true } } else { [pscustomobject]@{ Exists = $false; Enabled = $false } } }
        Mock Invoke-Graph { if ($Method -eq 'PATCH') { $script:patches += ,@{ Body = $Body }; return $null }; $script:state }
        $log = @(Invoke-AvailabilityChange -Packages @((New-Pkg 'T_a' 'Alpha' -OwnerId 'o1'), (New-Pkg 'T_b' 'Beta' -OwnerId 'zz')) -To Some -OwnerOnly -PassThru)
        $log[0].Result | Should -Be 'Done'; $log[0].NewAllowed | Should -Be 'o1@x.com'
        ($script:patches[0].Body | ConvertFrom-Json).allowedUsersAndGroups[0].resourceId | Should -Be 'o1'
        $log[1].Result | Should -Be 'Failed'; $log[1].Error | Should -BeLike '*no valid owner*'
        $script:patches.Count | Should -Be 1
    }
    It 'changes nothing under -WhatIf' {
        Mock Test-Proceed { $false }
        Mock Invoke-Graph { if ($Method -eq 'PATCH') { $script:patches += 1 }; $script:state }
        $log = @(Invoke-AvailabilityChange -Packages @((New-Pkg 'T_a' 'Alpha')) -To None -PassThru)
        $log[0].Result | Should -Be 'WhatIf'
        $script:patches.Count | Should -Be 0
    }
    It 'reports a failed PATCH and carries on' {
        Mock Invoke-Graph { if ($Method -eq 'PATCH') { throw 'BadRequest: nope' }; $script:state }
        $log = @(Invoke-AvailabilityChange -Packages @((New-Pkg 'T_a' 'Alpha'), (New-Pkg 'T_b' 'Beta')) -To None -PassThru)
        @($log | Where-Object { $_.Result -eq 'Failed' }).Count | Should -Be 2
        $log[0].Error | Should -BeLike '*nope*'
    }
    It 'restores the logged scope, including the user list' {
        Mock Invoke-Graph { $script:patches += ,@{ Uri = $Uri; Body = $Body }; $null }
        $row = [pscustomobject]@{ Id = 'T_a'; DisplayName = 'Alpha'; WasAvailableTo = 'allowedForSome'; WasAllowed = '[{"resourceType":"user","resourceId":"u1"}]'; WasDeployedTo = 'acquiredForNone'; WasAcquire = '[]'; IncludeDeployment = 'False' }
        $log = @(Invoke-AccessRestore -Records @($row) -PassThru)
        $log[0].Result | Should -Be 'Done'
        $b = $script:patches[0].Body | ConvertFrom-Json
        $b.availableTo | Should -Be 'allowedForSome'
        $b.allowedUsersAndGroups[0].resourceId | Should -Be 'u1'
        $b.PSObject.Properties.Name | Should -Not -Contain 'deployedTo'
    }
}

Describe 'Entra accountability' {
    BeforeEach {
        Mock Write-Host { }
        Mock Export-ActionLog { }
        Mock Test-Proceed { $true }
        $script:IdentitySponsorCache = @{}
        $script:users = @{
            enabled = [pscustomobject]@{ Id = 'enabled'; Upn = 'enabled@x.com'; Exists = $true; Enabled = $true }
            off     = [pscustomobject]@{ Id = 'off'; Upn = 'off@x.com'; Exists = $true; Enabled = $false }
            boss    = [pscustomobject]@{ Id = 'boss'; Upn = 'boss@x.com'; Exists = $true; Enabled = $true }
        }
        Mock Get-UserInfo { if ($script:users.ContainsKey([string]$IdOrUpn)) { $script:users[[string]$IdOrUpn] } else { [pscustomobject]@{ Id = $IdOrUpn; Upn = ''; Exists = $false; Enabled = $false } } }
        $script:identityOwners = @()
        Mock Get-IdentityOwners { @($script:identityOwners) }
        Mock Get-ManagerInfo { if ($UserId -eq 'off') { $script:users['boss'] } else { $null } }
    }
    It 'is satisfied by an enabled sponsor user or any sponsor group' {
        $p = New-Pkg 'T_a' 'Alpha' -IdentityId 'id1'
        $script:IdentitySponsorCache['id1'] = @([pscustomobject]@{ Id = 'enabled'; Kind = 'user' })
        (Resolve-AgentAccountability -Package $p).State | Should -Be 'OK'
        $script:IdentitySponsorCache['id1'] = @([pscustomobject]@{ Id = 'grp'; Kind = 'group' })
        (Resolve-AgentAccountability -Package $p).State | Should -Be 'OK'
    }
    It 'proposes the agent owner first, then an identity owner, then a manager, else flags it' {
        $script:IdentitySponsorCache['id1'] = @()
        $r = Resolve-AgentAccountability -Package (New-Pkg 'T_a' 'Alpha' -IdentityId 'id1' -OwnerId 'enabled')
        $r.State | Should -Be 'Proposed'; $r.Proposed | Should -Be 'enabled@x.com'; $r.Source | Should -Be 'Agent owner'; $r.Reason | Should -Be 'no sponsor'
        $script:identityOwners = @($script:users['enabled'])
        $r = Resolve-AgentAccountability -Package (New-Pkg 'T_a' 'Alpha' -IdentityId 'id1' -OwnerId 'off')
        $r.Source | Should -Be 'Agent identity owner'
        $script:identityOwners = @()
        $r = Resolve-AgentAccountability -Package (New-Pkg 'T_a' 'Alpha' -IdentityId 'id1' -OwnerId 'off')
        $r.Proposed | Should -Be 'boss@x.com'; $r.Source | Should -BeLike 'Manager of off@x.com'
        $r = Resolve-AgentAccountability -Package (New-Pkg 'T_a' 'Alpha' -IdentityId 'id1' -OwnerId '')
        $r.State | Should -Be 'Needs review'; $r.ProposedId | Should -Be ''
    }
    It 'treats disabled sponsors as a gap, and looks for owners only when asked' {
        $p = New-Pkg 'T_a' 'Alpha' -IdentityId 'id1' -OwnerId 'enabled'
        $script:IdentitySponsorCache['id1'] = @([pscustomobject]@{ Id = 'off'; Kind = 'user' })
        $r = Resolve-AgentAccountability -Package $p
        $r.SponsorGap | Should -BeTrue; $r.Reason | Should -Be 'sponsors are disabled'; $r.OwnerGap | Should -BeFalse
        $script:IdentitySponsorCache['id1'] = @([pscustomobject]@{ Id = 'enabled'; Kind = 'user' })
        $r = Resolve-AgentAccountability -Package $p -IncludeOwners
        $r.SponsorGap | Should -BeFalse; $r.OwnerGap | Should -BeTrue; $r.AddOwner | Should -BeTrue; $r.State | Should -Be 'Proposed'
    }
    It 'reports only agents with an identity and leaves unreadable identities out' {
        Mock Initialize-IdentitySponsorCache { $script:IdentitySponsorCache['id1'] = @(); $script:IdentitySponsorCache['id2'] = @([pscustomobject]@{ Id = 'enabled'; Kind = 'user' }) }
        Mock Initialize-IdentityOwnerCache { }
        Mock Initialize-UserCache { }
        Mock Initialize-ManagerCache { }
        $pk = @((New-Pkg 'T_a' 'Alpha' -IdentityId 'id1' -OwnerId 'enabled'), (New-Pkg 'T_b' 'Beta' -IdentityId 'id2'), (New-Pkg 'T_c' 'Gamma' -IdentityId 'id3'), (New-Pkg 'T_d' 'Delta'))
        $rep = Get-AccountabilityReport -Packages $pk
        $rep.Items.Id | Should -Be @('T_a')
        $rep.OkCount | Should -Be 1; $rep.Unreadable | Should -Be 1; $rep.NoIdentity | Should -Be 1
    }
    It 'adds the sponsor through the identity relationship and logs it for undo' {
        $script:posts = @()
        Mock Invoke-Graph { $script:posts += ,@{ Method = $Method; Uri = $Uri; Body = $Body }; $null }
        $item = [pscustomobject]@{ Id = 'T_a'; DisplayName = 'Alpha'; IdentityId = 'id1'; ProposedId = 'u1'; Proposed = 'u1@x.com'; Source = 'Agent owner'; AddSponsor = $true; AddOwner = $false }
        $log = @(Invoke-AccountabilityAssign -Items @($item) -PassThru)
        $log.Count | Should -Be 1; $log[0].Action | Should -Be 'addsponsor'; $log[0].Result | Should -Be 'Done'; $log[0].UserId | Should -Be 'u1'
        $script:posts[0].Uri | Should -Be 'https://graph.microsoft.com/beta/servicePrincipals/id1/microsoft.graph.agentIdentity/sponsors/$ref'
        ($script:posts[0].Body | ConvertFrom-Json).'@odata.id' | Should -Be 'https://graph.microsoft.com/beta/directoryObjects/u1'
    }
    It 'adds owner and sponsor as two separate logged calls, and hints when a sponsor call is refused' {
        $script:posts = @()
        Mock Invoke-Graph { $script:posts += $Uri; if ($Uri -like '*/sponsors/*') { throw 'Forbidden: Insufficient privileges' }; $null }
        $item = [pscustomobject]@{ Id = 'T_a'; DisplayName = 'Alpha'; IdentityId = 'id1'; ProposedId = 'u1'; Proposed = 'u1@x.com'; Source = 'Manual'; AddSponsor = $true; AddOwner = $true }
        $log = @(Invoke-AccountabilityAssign -Items @($item) -PassThru)
        $log.Count | Should -Be 2
        ($log | Where-Object { $_.Action -eq 'addsponsor' }).Result | Should -Be 'Failed'
        ($log | Where-Object { $_.Action -eq 'addsponsor' }).Error | Should -BeLike '*application-permission*'
        ($log | Where-Object { $_.Action -eq 'addowner' }).Result | Should -Be 'Done'
        $script:posts | Should -Contain 'https://graph.microsoft.com/beta/servicePrincipals/id1/microsoft.graph.agentIdentity/owners/$ref'
    }
    It 'removes what an earlier run added' {
        $script:deletes = @()
        Mock Invoke-Graph { $script:deletes += ,@{ Method = $Method; Uri = $Uri }; $null }
        Invoke-AccountabilityRemove -Records @([pscustomobject]@{ Action = 'addsponsor'; DisplayName = 'Alpha'; IdentityId = 'id1'; UserId = 'u1'; User = 'u1@x.com' })
        $script:deletes[0].Method | Should -Be 'DELETE'
        $script:deletes[0].Uri | Should -Be 'https://graph.microsoft.com/beta/servicePrincipals/id1/microsoft.graph.agentIdentity/sponsors/u1/$ref'
    }
}

Describe 'Policy: AI activity and restrict' {
    BeforeEach {
        $script:catalog = @((New-Pkg 'T_Abc' 'Alpha'), (New-Pkg 'T_def' 'Beta'), (New-Pkg 'T_ghi' 'Gamma'))
        foreach ($c in $script:catalog) { $c | Add-Member -NotePropertyName availableTo -NotePropertyValue 'allowedForAll' -Force }
        $script:catalog[2].availableTo = 'allowedForNone'
        Mock Get-Packages { $script:catalog }
        Mock Get-AgentInfoTable { @{} }
        $now = Get-Date
        $ev = {
            param($title, $risk, $signal, $ageDays = 1)
            [pscustomobject]@{ TitleId = $title; Risk = $risk; Signals = $signal; Time = $now.AddDays(-$ageDays); Kind = 'Interaction'; User = 'u'; AgentName = '' }
        }
        $script:acts = @(
            (& $ev 't_abc' 'High' 'Runtime protection blocked'), (& $ev 't_abc' 'High' 'Runtime protection blocked'), (& $ev 't_abc' 'High' 'Jailbreak attempt'),
            (& $ev 't_def' 'High' 'Jailbreak attempt'), (& $ev 't_def' 'Medium' 'Labeled file accessed'),
            (& $ev 't_ghi' 'High' 'Jailbreak attempt' 20))
        Mock Get-AiActivityData { [pscustomobject]@{ Days = $Days; Activities = $script:acts; Names = @{}; Unmapped = 0 } }
        function Doc($json) { $json | ConvertFrom-Json }
    }
    It 'matches agents with enough high-risk events and explains why, ignoring case in the agent id' {
        $d = Doc '{ "rules": [ { "name": "r", "when": { "aiActivity": { "days": 7, "minHigh": 3 } }, "then": { "action": "report" } } ] }'
        $p = Get-PolicyPlan $d
        $p.Matched.id | Should -Be @('T_Abc')
        $p.Evidence['T_Abc'] | Should -BeLike '3 high, 0 medium in 7 days: *Runtime protection blocked x2*'
    }
    It 'counts only events inside the window and can narrow to named signals' {
        $d = Doc '{ "rules": [ { "name": "r", "when": { "aiActivity": { "days": 7, "minHigh": 1 } }, "then": { "action": "report" } } ] }'
        (Get-PolicyPlan $d).Matched.id | Should -Not -Contain 'T_ghi'      # its only event is 20 days old
        $d = Doc '{ "rules": [ { "name": "r", "when": { "aiActivity": { "days": 30, "minHigh": 1, "signals": ["Jailbreak attempt"] } }, "then": { "action": "report" } } ] }'
        (Get-PolicyPlan $d).Matched.id | Should -Contain 'T_ghi'
        $d = Doc '{ "rules": [ { "name": "r", "when": { "aiActivity": { "days": 7, "minHigh": 1, "minMedium": 1 } }, "then": { "action": "report" } } ] }'
        (Get-PolicyPlan $d).Matched.id | Should -Be @('T_def')
    }
    It 'refuses an AI activity rule that would match every agent with any activity' {
        { Get-PolicyPlan (Doc '{ "rules": [ { "name": "x", "when": { "aiActivity": { "days": 7, "minHigh": 0 } }, "then": { "action": "report" } } ] }') } | Should -Throw '*minHigh or minMedium*'
    }
    It 'plans a restrict action and skips agents already at the target scope' {
        $d = Doc '{ "rules": [ { "name": "r", "when": { "aiActivity": { "days": 30, "minHigh": 1 } }, "then": { "action": "restrict", "availableTo": "none" } } ] }'
        $p = Get-PolicyPlan $d
        $p.Action | Should -Be 'restrict'
        $p.Restrict.To | Should -Be 'None'
        $p.Matched.id | Should -Contain 'T_ghi'
        $p.Actionable.id | Should -Not -Contain 'T_ghi'
        $p.Actionable.id | Should -Contain 'T_Abc'
    }
    It 'understands restricting to the owner or to named users, and rejects an empty list' {
        $o = Get-PolicyPlan (Doc '{ "rules": [ { "name": "r", "when": { "state": "active" }, "then": { "action": "restrict", "availableTo": "owner" } } ] }')
        $o.Restrict.To | Should -Be 'Some'; $o.Restrict.OwnerOnly | Should -BeTrue
        $n = Get-PolicyPlan (Doc '{ "rules": [ { "name": "r", "when": { "state": "active" }, "then": { "action": "restrict", "availableTo": "some", "users": ["a@x.com"] } } ] }')
        $n.Restrict.Users | Should -Be @('a@x.com')
        { Get-PolicyPlan (Doc '{ "rules": [ { "name": "r", "when": { "state": "active" }, "then": { "action": "restrict", "availableTo": "some" } } ] }') } | Should -Throw '*needs users, groups or ownerOnly*'
    }
    It 'applies a restrict step through the availability routine' {
        Mock Write-Host { }
        Mock Confirm-Batch { $true }
        Mock Invoke-AvailabilityChange { }
        $d = Doc '{ "rules": [ { "name": "r", "when": { "aiActivity": { "days": 7, "minHigh": 3 } }, "then": { "action": "restrict", "availableTo": "none", "includeDeployment": true } } ] }'
        Invoke-PolicyPlan -Plan @(Get-PolicyPlan $d) -Apply
        Should -Invoke Invoke-AvailabilityChange -Times 1 -ParameterFilter { $To -eq 'None' -and $IncludeDeployment -and @($Packages).Count -eq 1 }
    }
}

Describe 'Find-DirectoryGroups' {
    It 'searches by name or mail prefix, labels the group kind and sorts by name' {
        $script:uri = ''
        Mock Invoke-Graph {
            $script:uri = $Uri
            @{ value = @(
                @{ id = 'g2'; displayName = 'Zeta'; mail = $null; groupTypes = @(); securityEnabled = $true },
                @{ id = 'g1'; displayName = 'Alpha'; mail = 'a@x.com'; groupTypes = @('Unified'); securityEnabled = $false }) }
        }
        $g = @(Find-DirectoryGroups -Text "O'Neil")
        $g.Name | Should -Be @('Alpha', 'Zeta')
        $g[0].Kind | Should -Be 'Microsoft 365'; $g[1].Kind | Should -Be 'Security'
        [uri]::UnescapeDataString($script:uri) | Should -BeLike "*startswith(displayName,'O''Neil') or startswith(mail,'O''Neil')*"
    }
    It 'lists groups when no text is given' {
        Mock Invoke-Graph { @{ value = @() } }
        @(Find-DirectoryGroups -Text '').Count | Should -Be 0
    }
}

Describe 'Agent users are not people' {
    It 'leaves agent users out of the directory picker and still returns the requested number of people' {
        Mock Invoke-Graph {
            $script:agentUri = $Uri
            [pscustomobject]@{ value = @(
                [pscustomobject]@{ id = 'a1'; displayName = 'Abbas Agent'; userPrincipalName = 'abbas@x.com'; accountEnabled = $true; '@odata.type' = '#microsoft.graph.agentUser' },
                [pscustomobject]@{ id = 'u1'; displayName = 'Ann'; userPrincipalName = 'ann@x.com'; accountEnabled = $true },
                [pscustomobject]@{ id = 'u2'; displayName = 'Bo'; userPrincipalName = 'bo@x.com'; accountEnabled = $true }) }
        }
        (Find-DirectoryUsers -Text '' -Top 1).Name | Should -Be @('Ann')
        (Find-DirectoryUsers -Text '').Name | Should -Be @('Ann', 'Bo')
        $script:agentUri | Should -Match 'top=100'
    }
    It 'counts only real users as owners of an agent identity' {
        $script:IdentityOwnerCache = @{}; $script:UserCache = @{}
        Mock Invoke-GraphBatch { @{ 'idn9' = [pscustomobject]@{ Status = 200; Body = [pscustomobject]@{ value = @(
            [pscustomobject]@{ id = '11111111-1111-1111-1111-111111111111'; '@odata.type' = '#microsoft.graph.user' },
            [pscustomobject]@{ id = '22222222-2222-2222-2222-222222222222'; '@odata.type' = '#microsoft.graph.agentUser' }) } } } }
        Mock Initialize-UserCache { }
        Initialize-IdentityOwnerCache -AgentIdentityIds @('idn9')
        $script:IdentityOwnerCache['idn9'] | Should -Be @('11111111-1111-1111-1111-111111111111')
    }
    It 'marks agent user accounts and never proposes one as the accountable person' {
        $script:IdentitySponsorCache = @{ 'idz' = @() }
        $agent = [pscustomobject]@{ Id = 'agent1'; Upn = 'agent@x.com'; Exists = $true; Enabled = $true; IsAgent = $true }
        $human = [pscustomobject]@{ Id = 'human1'; Upn = 'human@x.com'; Exists = $true; Enabled = $true; IsAgent = $false }
        Mock Get-UserInfo { if ($IdOrUpn -eq 'agent1') { $agent } else { $human } }
        Mock Get-IdentityOwners { @($human) }
        Mock Get-ManagerInfo { $null }
        $r = Resolve-AgentAccountability -Package (New-Pkg 'T_z' 'Zed' -IdentityId 'idz' -OwnerId 'agent1')
        $r.Proposed | Should -Be 'human@x.com'
        $r.Source | Should -Be 'Agent identity owner'
    }
}
Describe 'Format-GraphError with a real response dump' {
    It 'finds the error body even when an earlier header also holds JSON' {
        $detail = 'POST https://graph.microsoft.com/beta/copilot/admin/catalog/packages/T_1/reassign HTTP/1.1 424 Failed Dependency Date: Fri request-id: abc x-ms-ags-diagnostic: {"ServerInfo":{"DataCenter":"UAE North","Slice":"E"}} X-Cache: CONFIG_NOCACHE Content-Type: application/json {"error":{"code":"UnknownError","message":"{\"StatusCode\":424,\"Message\":\"An error occurred while reassigning the agent.\"}"}}'
        $m = Format-GraphError -Summary 'Response status code does not indicate success: FailedDependency (Failed Dependency).' -Detail $detail
        $m | Should -BeLike '*UnknownError: *An error occurred while reassigning the agent.*'
        $m | Should -BeLike '*`[POST /beta/copilot/admin/catalog/packages/T_1/reassign`]'
    }
}
Describe 'Lookups and helpers' {
    It 'Get-Distinct keeps first-seen order and treats case as different, like Select-Object -Unique' {
        @('b', 'a', 'b', 'A', 'a' | Get-Distinct) | Should -Be @('b', 'a', 'A')
        @($null, 'x', $null | Get-Distinct).Count | Should -Be 2
    }
    It 'Resolve-Packages finds ids and names case-insensitively, rejects duplicates and unknowns, and accepts a supplied catalog' {
        $cat = @((New-Pkg 'T_abc' 'Alpha'), (New-Pkg 'P_def' 'Beta'), (New-Pkg 'T_g1' 'Dup'), (New-Pkg 'T_g2' 'Dup'))
        (Resolve-Packages @('t_ABC', 'beta') -Catalog $cat).id | Should -Be @('P_def', 'T_abc')
        { Resolve-Packages @('Dup') -Catalog $cat } | Should -Throw '*Multiple packages named*'
        { Resolve-Packages @('Nope') -Catalog $cat } | Should -Throw '*No package matching*'
        { Resolve-Packages @('T_missing') -Catalog $cat } | Should -Throw '*No package matching*'
    }
    It 'Resolve-Packages indexes a large catalog once instead of scanning it per name' {
        $cat = 1..5000 | ForEach-Object { New-Pkg ('T_{0:D6}' -f $_) "Agent $_" }
        $names = 1..500 | ForEach-Object { "Agent $($_ * 9)" }
        $time = Measure-Command { $r = @(Resolve-Packages $names -Catalog $cat) }
        $r.Count | Should -Be 500
        $time.TotalSeconds | Should -BeLessThan 3
    }
    It 'Select-PackageSet uses the supplied list (filtering Copilot agents on request) and reads the catalog otherwise' {
        Mock Get-Packages { @((New-Pkg 'T_live' 'Live')) }
        $a = New-Pkg 'T_a' 'A'; $b = New-Pkg 'T_b' 'B'; $b.supportedHosts = @('Outlook')
        @(Select-PackageSet -Packages @($a, $b) -Supplied).Count | Should -Be 2
        (Select-PackageSet -Packages @($a, $b) -Supplied -AgentsOnly).id | Should -Be @('T_a')
        (Select-PackageSet).id | Should -Be @('T_live')
        @(Select-PackageSet -Packages @() -Supplied).Count | Should -Be 0
    }
    It 'Get-StalePackages reads the supplied catalog and does not call the service' {
        Mock Get-Packages { throw 'must not read the catalog' }
        $old = New-Pkg 'T_old' 'Old'; $old | Add-Member -NotePropertyName lastModifiedDateTime -NotePropertyValue '2020-01-01T00:00:00Z'
        $new = New-Pkg 'T_new' 'New'; $new | Add-Member -NotePropertyName lastModifiedDateTime -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o'))
        (Get-StalePackages -Days 30 -By modified -Packages @($old, $new)).id | Should -Be @('T_old')
    }
    It 'Select-ActionTargets drops what is already in the target state' {
        $on = New-Pkg 'T_1' 'On' -Blocked $true; $off = New-Pkg 'T_2' 'Off'
        (Select-ActionTargets @($on, $off) 'block').id | Should -Be @('T_2')
        (Select-ActionTargets @($on, $off) 'unblock').id | Should -Be @('T_1')
        @(Select-ActionTargets @($on, $off) 'list').Count | Should -Be 2
    }
    It 'New-UserInfo gives found and missing users the same shape' {
        $f = New-UserInfo 'x' ([pscustomobject]@{ id = 'u1'; userPrincipalName = 'a@x.com'; displayName = 'A'; accountEnabled = $true })
        $m = New-UserInfo 'u2' $null
        $f.Exists | Should -BeTrue; $f.IsAgent | Should -BeFalse; $m.Exists | Should -BeFalse; $m.IsAgent | Should -BeFalse
        ($f.PSObject.Properties.Name -join ',') | Should -Be ($m.PSObject.Properties.Name -join ',')
        (New-UserInfo 'x' ([pscustomobject]@{ id = 'a1'; '@odata.type' = '#microsoft.graph.agentUser' })).IsAgent | Should -BeTrue
    }
    It 'Get-FailureSummary lists the first five failures only' {
        $recs = 1..7 | ForEach-Object { [pscustomobject]@{ Result = 'Failed'; DisplayName = "A$_"; Error = 'boom' } }
        $recs += [pscustomobject]@{ Result = 'Done'; DisplayName = 'ok'; Error = '' }
        ((Get-FailureSummary $recs) -split "`n").Count | Should -Be 5
        (Get-FailureSummary $recs) | Should -BeLike 'A1: boom*'
    }
    It 'Test-PermissionMatch treats a missing list as no permissions' {
        Test-PermissionMatch -Perms $null -Mode 'any' | Should -BeFalse
        Test-PermissionMatch -Perms @([pscustomobject]@{ Kind = 'Application'; Resource = 'Microsoft Graph'; Permission = 'X' }) -Mode 'graphapp' | Should -BeTrue
    }
    It 'Get-AccessLabel names both availability and deployment values and passes unknown ones through' {
        Get-AccessLabel 'allowedForAll' | Should -Be 'Everyone'
        Get-AccessLabel 'allowedForNone' | Should -Be 'Nobody'
        Get-AccessLabel 'acquiredForNone' | Should -Be 'Nobody'
        Get-AccessLabel 'acquiredForSome' | Should -Be 'Some users or groups'
        Get-AccessLabel 'acquiredForAll' | Should -Be 'Everyone'
        Get-AccessLabel '' | Should -Be ''
        Get-AccessLabel 'somethingNew' | Should -Be 'somethingNew'
    }
    It 'ConvertTo-FieldRows returns an array even for a single row, so a grid can bind to it' {
        $one = ConvertTo-FieldRows ([ordered]@{ Field = 'only' })
        $one -is [array] | Should -BeTrue
        @($one).Count | Should -Be 1
        (ConvertTo-FieldRows ([ordered]@{})) -is [array] | Should -BeTrue
        $rows = ConvertTo-FieldRows ([ordered]@{ a = '1'; b = ''; c = '3' })
        @($rows).Count | Should -Be 2
    }
}

Describe 'Output files and logs' {
    It 'Export-ActionLog writes to a path that contains square brackets' {
        Mock Write-Host { }
        foreach ($name in 'run[1].csv', 'run[1].json') {
            $OutFile = Join-Path $TestDrive $name
            Export-ActionLog -Records @([pscustomobject]@{ Id = 'T_1'; Result = 'Done' })
            Test-Path -LiteralPath $OutFile | Should -BeTrue
        }
    }
    It 'Save-Snapshot writes to a path that contains square brackets' {
        $path = Join-Path $TestDrive 'snap[1].json'
        Save-Snapshot -Path $path -Packages @((New-Pkg 'T_1' 'One'))
        (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).count | Should -Be 1
    }
}

Describe 'Audit conversion' {
    It 'matches a policy signal name literally, including text that looks like a wildcard' {
        Mock Get-AgentInfoTable { @{} }
        $script:catalog = @((New-Pkg 'T_Abc' 'Alpha'))
        Mock Get-Packages { $script:catalog }
        $now = Get-Date
        $acts = @([pscustomobject]@{ TitleId = 't_abc'; Risk = 'High'; Signals = 'Odd [name]'; Time = $now; Kind = 'Interaction'; User = 'u'; AgentName = '' })
        Mock Get-AiActivityData { [pscustomobject]@{ Days = 7; Activities = $acts; Names = @{}; Unmapped = 0 } }
        $doc = '{ "rules": [ { "name": "r", "when": { "aiActivity": { "days": 7, "minHigh": 1, "signals": ["Odd [name]"] } }, "then": { "action": "report" } } ] }' | ConvertFrom-Json
        (Get-PolicyPlan $doc).Matched.id | Should -Be @('T_Abc')
        $doc2 = '{ "rules": [ { "name": "r", "when": { "aiActivity": { "days": 7, "minHigh": 1, "signals": ["Odd *"] } }, "then": { "action": "report" } } ] }' | ConvertFrom-Json
        @((Get-PolicyPlan $doc2).Matched).Count | Should -Be 0
    }
    It 'does not fail on an event whose time could not be parsed' {
        $a = [pscustomobject]@{ Time = $null; Kind = 'Interaction'; User = 'u'; Agent = ''; AgentName = ''; App = ''; Conversation = ''; RecordId = 'r'; Model = ''; Prompts = 0; Responses = 0
                                Extra = [pscustomobject]@{ Resources = @() } }
        { Get-AiActivityDetailRows $a } | Should -Not -Throw
    }
    It 'counts prompts and responses and flags a jailbreak seen only in a message' {
        $r = [pscustomobject]@{ id = 'r'; operation = 'CopilotInteraction'; createdDateTime = '2026-09-20T10:00:00Z'; userPrincipalName = 'u@x.com'
            auditData = [pscustomobject]@{ AgentId = 'bot'; CopilotEventData = [pscustomobject]@{
                Messages = @([pscustomobject]@{ isPrompt = $true; JailbreakDetected = $true }, [pscustomobject]@{ isPrompt = $false; JailbreakDetected = $false }, [pscustomobject]@{ isPrompt = $false }) } } }
        $a = ConvertTo-AiActivity $r
        $a.Prompts | Should -Be 1; $a.Responses | Should -Be 2
        $a.Risk | Should -Be 'High'; $a.Signals | Should -Be 'Jailbreak attempt'
    }
    It 'checks an audit search before sleeping, so a finished search is not delayed' {
        $script:slept = 0
        Mock Wait-AuditPoll { $script:slept++ }
        Mock Invoke-Graph { if ($Method -eq 'DELETE') { return $null }; if ($Uri -like '*/records*') { return @{ value = @(@{ id = 'a' }) } }; @{ status = 'succeeded' } }
        @(Complete-AuditSearch -Id 'q1').Count | Should -Be 1
        $script:slept | Should -Be 0
    }
}

Describe 'Graph version per catalog call' {
    BeforeEach {
        Mock Write-Host { }
        Mock Export-ActionLog { }
        Mock Test-Proceed { $true }
        $script:uris = @()
        $OutFile = $null
        $DisableIdentity = $false
    }
    It 'reads the catalog from v1.0' {
        Mock Invoke-Graph { $script:uris += $Uri; @{ value = @() } }
        $null = Get-Packages
        $null = Get-Packages -AgentsOnly
        $script:uris.Count | Should -Be 2
        $script:uris | ForEach-Object { $_ | Should -BeLike 'https://graph.microsoft.com/v1.0/copilot/admin/catalog/packages*' }
    }
    It 'sends block and unblock to beta, the only version that has them' {
        Mock Invoke-Graph { $script:uris += $Uri }
        $null = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha') -Action block -PassThru
        $null = Invoke-PackageAction -Packages @(New-Pkg 'P_2' 'Beta' -Blocked $true) -Action unblock -PassThru
        $script:uris | Should -Be @('https://graph.microsoft.com/beta/copilot/admin/catalog/packages/P_1/block', 'https://graph.microsoft.com/beta/copilot/admin/catalog/packages/P_2/unblock')
    }
    It 'sends reassign to beta' {
        Mock Invoke-Graph { $script:uris += $Uri }
        $item = [pscustomobject]@{ Id = 'T_1'; DisplayName = 'Alpha'; CurrentOwnerId = 'o1'; NewOwnerId = 'o2'; NewOwnerUpn = 'new@x.com'; Source = 'test' }
        $null = Invoke-OwnerReassign -Items @($item) -PassThru
        $script:uris | Should -Be @('https://graph.microsoft.com/beta/copilot/admin/catalog/packages/T_1/reassign')
    }
    It 'reads and changes who can use an agent on v1.0' {
        Mock Invoke-Graph { $script:uris += '{0} {1}' -f $(if ($Method) { $Method } else { 'GET' }), $Uri; if ($Method -ne 'PATCH') { @{ availableTo = 'allowedForAll'; deployedTo = 'acquiredForAll'; allowedUsersAndGroups = @(); acquireUsersAndGroups = @() } } }
        $null = Invoke-AvailabilityChange -Packages @(New-Pkg 'T_a' 'Alpha') -To None -PassThru
        $script:uris | Should -Be @('GET https://graph.microsoft.com/v1.0/copilot/admin/catalog/packages/T_a', 'PATCH https://graph.microsoft.com/v1.0/copilot/admin/catalog/packages/T_a')
    }
}

Describe 'Entra agent risk' {
    BeforeEach {
        Mock Write-Host { }
        Mock Export-ActionLog { }
        Mock Test-Proceed { $true }
        Mock Start-Sleep { }
        $script:posts = @()
        $script:pkg = [pscustomobject]@{ id = 'T_1'; displayName = 'Alpha'; agentIdentityId = 'id1'; platform = 'Foundry' }
        $script:clean = [pscustomobject]@{ Level = 'none'; State = 'none'; Detail = '' }
        $script:confirmed = [pscustomobject]@{ Level = 'high'; State = 'confirmedCompromised'; Detail = 'adminConfirmedAgentCompromised' }
    }
    It 'reads every identity in one beta batch: a missing record means not flagged, other errors mean unknown' {
        Mock Invoke-GraphBatch {
            @{ 'a' = [pscustomobject]@{ Status = 200; Body = [pscustomobject]@{ riskLevel = 'high'; riskState = 'atRisk'; riskDetail = 'none' } }
               'b' = [pscustomobject]@{ Status = 404; Body = $null }
               'c' = [pscustomobject]@{ Status = 403; Body = $null } }
        }
        $s = Get-AgentRiskStates @('a', 'b', 'c', 'a', '')
        Should -Invoke Invoke-GraphBatch -Times 1 -ParameterFilter { @($Requests).Count -eq 3 -and $Version -eq 'beta' }
        $s['a'].Level | Should -Be 'high'; $s['a'].State | Should -Be 'atRisk'
        $s['b'].State | Should -Be 'none'
        $s['c'] | Should -BeNullOrEmpty
        (Get-AgentRiskStates @()).Count | Should -Be 0
    }
    It 'describes a state in words' {
        Format-AgentRisk $null | Should -Be 'unknown'
        Format-AgentRisk $script:clean | Should -Be 'not flagged'
        Format-AgentRisk $script:confirmed | Should -Be 'high (confirmedCompromised)'
    }
    It 'confirms an identity as compromised and logs the state before and after' {
        $script:reads = 0
        Mock Get-AgentRiskStates { $script:reads++; if ($script:reads -eq 1) { @{ 'id1' = $script:clean } } else { @{ 'id1' = $script:confirmed } } }
        Mock Invoke-Graph { $script:posts += , @{ Uri = $Uri; Body = $Body } }
        $log = @(Invoke-AgentRiskAction -Packages @($script:pkg) -PassThru)
        $log[0].Result | Should -Be 'Done'
        $log[0].Action | Should -Be 'confirmcompromised'
        $log[0].WasRiskState | Should -Be 'none'
        $log[0].NowRiskState | Should -Be 'confirmedCompromised'; $log[0].NowRiskLevel | Should -Be 'high'
        $script:posts.Count | Should -Be 1
        $script:posts[0].Uri | Should -Be 'https://graph.microsoft.com/beta/identityProtection/riskyAgents/confirmCompromised'
        @(($script:posts[0].Body | ConvertFrom-Json).agentIds) | Should -Be @('id1')
    }
    It 'sends a single identity as a one-item list' {
        Mock Get-AgentRiskStates { @{ 'id1' = $script:clean } }
        Mock Invoke-Graph { $script:posts += , @{ Body = $Body } }
        $null = Invoke-AgentRiskAction -Packages @($script:pkg)
        $script:posts[0].Body | Should -Be '{"agentIds":["id1"]}'
    }
    It 'skips an identity that is already confirmed and sends nothing' {
        Mock Get-AgentRiskStates { @{ 'id1' = $script:confirmed } }
        Mock Invoke-Graph { $script:posts += , @{ Uri = $Uri } }
        $log = @(Invoke-AgentRiskAction -Packages @($script:pkg) -PassThru)
        $log[0].Result | Should -Be 'Skipped'
        $script:posts.Count | Should -Be 0
    }
    It 'changes nothing when the proceed check says no (-WhatIf)' {
        Mock Test-Proceed { $false }
        Mock Get-AgentRiskStates { @{ 'id1' = $script:clean } }
        Mock Invoke-Graph { $script:posts += , @{ Uri = $Uri } }
        $log = @(Invoke-AgentRiskAction -Packages @($script:pkg) -PassThru)
        $log[0].Result | Should -Be 'WhatIf'
        $script:posts.Count | Should -Be 0
    }
    It 'records a failure with the role that is needed, and keeps going' {
        Mock Get-AgentRiskStates { @{ 'id1' = $script:clean; 'id2' = $script:clean } }
        Mock Invoke-Graph { if ($Body -match 'id1') { throw 'Forbidden' } }
        $two = @($script:pkg, [pscustomobject]@{ id = 'T_2'; displayName = 'Beta'; agentIdentityId = 'id2'; platform = '' })
        $log = @(Invoke-AgentRiskAction -Packages $two -PassThru)
        ($log | Where-Object Id -eq 'T_1').Result | Should -Be 'Failed'
        ($log | Where-Object Id -eq 'T_1').Error | Should -BeLike '*Security Administrator*'
        ($log | Where-Object Id -eq 'T_2').Result | Should -Be 'Done'
    }
    It 'leaves out agents that have no Entra identity' {
        Mock Get-AgentRiskStates { throw 'must not read' }
        Mock Invoke-Graph { throw 'must not call' }
        $none = [pscustomobject]@{ id = 'T_9'; displayName = 'NoIdentity'; agentIdentityId = ''; platform = '' }
        Invoke-AgentRiskAction -Packages @($none) -PassThru | Should -BeNullOrEmpty
    }
    It 'dismisses only an identity that has an active risk' {
        Mock Get-AgentRiskStates { @{ 'id1' = $script:confirmed; 'id2' = $script:clean } }
        Mock Invoke-Graph { $script:posts += , @{ Uri = $Uri; Body = $Body } }
        $two = @($script:pkg, [pscustomobject]@{ id = 'T_2'; displayName = 'Beta'; agentIdentityId = 'id2'; platform = '' })
        $log = @(Invoke-AgentRiskAction -Packages $two -Action dismiss -PassThru)
        ($log | Where-Object Id -eq 'T_1').Result | Should -Be 'Done'
        ($log | Where-Object Id -eq 'T_2').Result | Should -Be 'Skipped'
        $script:posts.Count | Should -Be 1
        $script:posts[0].Uri | Should -Be 'https://graph.microsoft.com/beta/identityProtection/riskyAgents/dismiss'
    }
    It 'undoes a logged confirmation by dismissing the risk of the same identities' {
        Mock Get-AgentRiskStates { @{ 'id1' = $script:confirmed } }
        Mock Invoke-Graph { $script:posts += , @{ Uri = $Uri; Body = $Body } }
        $rec = [pscustomobject]@{ Id = 'T_1'; DisplayName = 'Alpha'; IdentityId = 'id1'; WasRiskState = 'none' }
        $log = @(Invoke-AgentRiskDismiss -Records @($rec) -PassThru)
        $log[0].Action | Should -Be 'dismiss'
        $script:posts[0].Uri | Should -BeLike '*/riskyAgents/dismiss'
        @(($script:posts[0].Body | ConvertFrom-Json).agentIds) | Should -Be @('id1')
    }
    It 'warns that dismissing also clears a risk Entra had already raised' {
        Get-DismissNote @([pscustomobject]@{ DisplayName = 'Alpha'; WasRiskState = 'none' }) | Should -Be ''
        $note = Get-DismissNote @([pscustomobject]@{ DisplayName = 'Alpha'; WasRiskState = 'atRisk' }, [pscustomobject]@{ DisplayName = 'Beta'; WasRiskState = 'none' })
        $note | Should -BeLike '*Alpha*'
        $note | Should -Not -BeLike '*Beta*'
    }
}

Describe 'Entra agent risk: waiting for Entra to apply a change' {
    BeforeEach {
        Mock Write-Host { }
        Mock Export-ActionLog { }
        Mock Test-Proceed { $true }
        Mock Start-Sleep { }
        Mock Invoke-Graph { }
        $script:pkg = [pscustomobject]@{ id = 'T_1'; displayName = 'Alpha'; agentIdentityId = 'id1'; platform = 'Foundry' }
        $script:clean = [pscustomobject]@{ Level = 'none'; State = 'none'; Detail = '' }
        $script:confirmed = [pscustomobject]@{ Level = 'high'; State = 'confirmedCompromised'; Detail = 'adminConfirmedAgentCompromised' }
    }
    It 'keeps checking until Entra shows the new state, then marks it verified' {
        $script:reads = 0
        Mock Get-AgentRiskStates { $script:reads++; if ($script:reads -le 4) { @{ 'id1' = $script:clean } } else { @{ 'id1' = $script:confirmed } } }
        $log = @(Invoke-AgentRiskAction -Packages @($script:pkg) -PassThru)
        $log[0].Result | Should -Be 'Done'
        $log[0].Verified | Should -BeTrue
        $log[0].NowRiskState | Should -Be 'confirmedCompromised'
        Should -Invoke Start-Sleep -Times 3
    }
    It 'logs a request Entra accepted but never showed as done and not verified, instead of claiming success' {
        Mock Get-AgentRiskStates { @{ 'id1' = $script:clean } }
        $log = @(Invoke-AgentRiskAction -Packages @($script:pkg) -WaitSeconds 30 -PassThru)
        $log[0].Result | Should -Be 'Done'
        $log[0].Verified | Should -BeFalse
        $log[0].NowRiskState | Should -Be 'none'
        Should -Invoke Start-Sleep -Times 3
    }
    It 'does not read the state back at all with -WaitSeconds 0' {
        Mock Get-AgentRiskStates { @{ 'id1' = $script:clean } }
        $log = @(Invoke-AgentRiskAction -Packages @($script:pkg) -WaitSeconds 0 -PassThru)
        $log[0].Result | Should -Be 'Done'
        $log[0].Verified | Should -BeFalse
        Should -Invoke Get-AgentRiskStates -Times 1
        Should -Invoke Start-Sleep -Times 0
    }
    It 'checks all pending identities together rather than one read each' {
        $script:reads = 0
        Mock Get-AgentRiskStates { $script:reads++; $h = @{}; foreach ($i in $IdentityIds) { $h[$i] = $(if ($script:reads -eq 1) { $script:clean } else { $script:confirmed }) }; $h }
        $two = @($script:pkg, [pscustomobject]@{ id = 'T_2'; displayName = 'Beta'; agentIdentityId = 'id2'; platform = '' })
        $null = Invoke-AgentRiskAction -Packages $two -PassThru
        Should -Invoke Get-AgentRiskStates -Times 1 -ParameterFilter { @($IdentityIds).Count -eq 2 }
        Should -Invoke Get-AgentRiskStates -Times 2
    }
    It 'tells the person to dismiss again when a confirmation was not yet visible' {
        $note = Get-DismissNote @([pscustomobject]@{ DisplayName = 'Alpha'; WasRiskState = 'none'; Verified = 'False' }, [pscustomobject]@{ DisplayName = 'Beta'; WasRiskState = 'none'; Verified = 'True' })
        $note | Should -BeLike '*Alpha*dismiss it again*'
        $note | Should -Not -BeLike '*Beta*'
    }
}

Describe 'Sign-in help' {
    It 'turns the window-handle error of a non-interactive session into instructions' {
        $msg = "InteractiveBrowserCredential authentication failed: A window handle must be configured. See`nhttps://aka.ms/msal-net-wam#parent-window-handles"
        $help = Get-SignInHelp $msg
        $help | Should -BeLike '*-SignIn*'
        $help | Should -BeLike '*no saved sign-in*'
        $help | Should -BeLike '*A window handle must be configured*'
        $help | Should -Not -BeLike '*aka.ms*'
    }
    It 'explains the two-minute device code limit' {
        Get-SignInHelp 'Authentication timed out after 120 seconds due to inactivity. Please try again.' | Should -BeLike '*two minutes*-SignIn*'
    }
    It 'leaves any other error as it is' {
        Get-SignInHelp 'AADSTS50076: multi-factor authentication is required' | Should -Be 'AADSTS50076: multi-factor authentication is required'
    }
    It 'asks -SignIn for every permission the modes use, including the newest' {
        foreach ($scope in 'CopilotPackages.ReadWrite.All', 'ThreatHunting.Read.All', 'AgentIdentity.ReadWrite.All', 'AuditLogsQuery.Read.All', 'Group.Read.All', 'IdentityRiskyAgent.ReadWrite.All') {
            $script:AllScopes | Should -Contain $scope
        }
        @($script:AllScopes | Select-Object -Unique).Count | Should -Be @($script:AllScopes).Count
    }
}

Describe 'Endpoint AI: recognising tools and hiding secrets' {
    It 'recognises a tool by the name Defender gave it, or by its process' {
        (Resolve-EndpointAiTool -DefenderName 'Ollama Desktop').Key | Should -Be 'ollama'
        (Resolve-EndpointAiTool -DefenderName 'GitHub Copilot CLI').Key | Should -Be 'copilot-cli'
        (Resolve-EndpointAiTool -Process 'OLLAMA APP.EXE').Key | Should -Be 'ollama'
        (Resolve-EndpointAiTool -Process 'codex').Key | Should -Be 'codex-cli'
        Resolve-EndpointAiTool -Process 'notepad.exe' | Should -BeNullOrEmpty
        Resolve-EndpointAiTool -DefenderName 'Some Internal Bot' | Should -BeNullOrEmpty
    }
    It 'tells Claude Desktop from Claude Code by where claude.exe runs from' {
        (Resolve-EndpointAiTool -Process 'claude.exe' -Path 'C:\Program Files\WindowsApps\Claude_1.5.0_x64__abc\app\claude.exe').Key | Should -Be 'claude-desktop'
        (Resolve-EndpointAiTool -Process 'claude.exe' -Path 'C:\Users\a\.local\bin\claude.exe').Key | Should -Be 'claude-code'
        (Resolve-EndpointAiTool -DefenderName 'Claude Code').Key | Should -Be 'claude-code'
    }
    It 'hides a prompt, an api key and a bearer token, and shortens a long command' {
        Protect-CommandLine 'copilot.exe -p "summarise my payroll file"' | Should -Be 'copilot.exe -p "<prompt hidden>"'
        Protect-CommandLine 'tool --api-key abc123secret --model x' | Should -Be 'tool --api-key *** --model x'
        Protect-CommandLine 'curl -H Authorization: Bearer eyJhbGciOi.payload' | Should -Not -BeLike '*eyJhbGciOi*'
        Protect-CommandLine 'run sk-abcdefghijklmnop1234' | Should -Be 'run sk-***'
        (Protect-CommandLine ('x' * 500)).Length | Should -BeLessThan 240
        Protect-CommandLine '' | Should -Be ''
    }
    It 'builds queries from the catalog and the number of days' {
        $q = Get-EndpointAiQueries -Days 14
        $q.Agents | Should -BeLike '*Platform == "LocalAgents"*'
        $q.Processes | Should -BeLike '*ago(14d)*'
        $q.Processes | Should -BeLike '*"ollama.exe"*'
        $q.Outbound | Should -BeLike '*"anthropic.com"*'
        $q.Listening | Should -BeLike '*11434*'
        $alerts = Get-EndpointAiAlertQuery -Days 7 -DeviceNames @('lab', 'we"ird')
        $alerts | Should -BeLike '*"lab", "we\"ird"*'
        (Get-EndpointAiDeviceQuery -DeviceIds @('d1', 'd2')) | Should -BeLike '*"d1", "d2"*'
    }
}

Describe 'Endpoint AI: building rows and scoring risk' {
    BeforeAll {
        function New-EpData {
            @{
                Agents = @(
                    @{ AgentId = 'a1'; Name = 'Ollama Desktop'; Version = '1.0'; LifecycleStatus = ''; LastSeen = '2026-10-05T16:51:06Z'; FirstSeen = '2026-09-09T10:06:02Z'; Vendor = 'Ollama'; Process = 'ollama.exe'; Trusted = 'true'; AutoApprove = 'false'; Device = 'lab'; DeviceId = 'dev1'; Account = 'alice'; McpServers = $null; LocalMcps = $null }
                    @{ AgentId = 'a2'; Name = 'Claude Desktop'; Version = '2.0'; LifecycleStatus = 'Deleted'; LastSeen = '2026-09-23T16:06:59Z'; FirstSeen = '2026-09-09T10:06:02Z'; Vendor = 'Anthropic'; Process = 'claude.exe'; Trusted = 'true'; AutoApprove = 'false'; Device = 'lab'; DeviceId = 'dev1'; Account = 'alice' }
                    @{ AgentId = 'a3'; Name = 'Acme Helper'; Version = '3'; LifecycleStatus = ''; LastSeen = '2026-10-01T10:00:00Z'; FirstSeen = '2026-10-01T10:00:00Z'; Vendor = 'Acme'; Process = 'acme.exe'; Trusted = 'false'; AutoApprove = 'true'; Device = 'lab'; DeviceId = 'dev1'; Account = 'bob' }
                )
                Processes = @(
                    @{ DeviceId = 'dev1'; DeviceName = 'lab'; FileName = 'ollama.exe'; FolderPath = 'C:\Users\alice\AppData\Local\Programs\Ollama\ollama.exe'; Runs = 5; FirstSeen = '2026-09-22T14:09:00Z'; LastSeen = '2026-09-22T14:09:50Z'; Accounts = @('alice'); Parents = @('ollama app.exe'); ActiveAt = @('2026-09-22T14:00:00Z'); Command = 'ollama.exe serve'; FlagCommand = $null }
                    @{ DeviceId = 'dev1'; DeviceName = 'lab'; FileName = 'llama-server.exe'; FolderPath = 'C:\Ollama\lib\llama-server.exe'; Runs = 8; FirstSeen = '2026-09-22T14:09:00Z'; LastSeen = '2026-09-22T14:09:50Z'; Accounts = @('alice'); Parents = @('ollama.exe'); ActiveAt = @('2026-09-22T14:00:00Z'); Command = 'llama-server.exe --port 5 --host 127.0.0.1'; FlagCommand = $null }
                    @{ DeviceId = 'dev1'; DeviceName = 'lab'; FileName = 'copilot.exe'; FolderPath = 'C:\Users\alice\AppData\Local\GitHub CLI\copilot\copilot.exe'; Runs = 6; FirstSeen = '2026-09-10T13:14:00Z'; LastSeen = '2026-09-25T08:05:00Z'; Accounts = @('alice'); Parents = @('gh.exe'); ActiveAt = @('2026-09-25T08:00:00Z'); Command = 'copilot.exe -p "review the payroll export"'; FlagCommand = 'copilot.exe --yolo -p "x"' }
                )
                Mcp = @(); Files = @()
                Outbound = @(
                    @{ DeviceId = 'dev1'; DeviceName = 'lab'; Process = 'ollama.exe'; Host = 'ollama.com'; Hits = 17; LastSeen = '2026-10-05T16:47:00Z' }
                    @{ DeviceId = 'dev1'; DeviceName = 'lab'; Process = 'chrome.exe'; Host = 'chatgpt.com'; Hits = 3; LastSeen = '2026-10-05T16:47:00Z' }
                )
                Listening = @(
                    @{ DeviceId = 'dev1'; DeviceName = 'lab'; Process = 'ollama.exe'; LocalIP = '127.0.0.1'; LocalPort = 11434; Hits = 1; LastSeen = '2026-09-22T14:09:13Z' }
                )
                Software = @(@{ DeviceId = 'dev1'; DeviceName = 'lab'; SoftwareName = 'ollama_version_0.34.1'; SoftwareVendor = 'ollama'; SoftwareVersion = '0.34.1.0' })
                Vulnerabilities = @()
                Alerts = @(
                    @{ DeviceName = 'LAB'; AlertId = 'x1'; Timestamp = '2026-09-22T14:10:23Z'; Title = "An active 'SuspPrompt' malware was detected"; Severity = 'Low'; DetectionSource = 'Antivirus' }
                    @{ DeviceName = 'LAB'; AlertId = 'x2'; Timestamp = '2026-08-01T09:00:00Z'; Title = "'SuspPrompt' malware was prevented"; Severity = 'Informational'; DetectionSource = 'Antivirus' }
                    @{ DeviceName = 'LAB'; AlertId = 'x3'; Timestamp = '2026-09-22T14:11:00Z'; Title = 'Suspicious service created'; Severity = 'Medium'; DetectionSource = 'EDR' }
                )
                Devices = @(@{ DeviceId = 'dev1'; DeviceName = 'lab'; OSPlatform = 'Windows10'; OnboardingStatus = 'Onboarded'; DeviceType = 'Workstation'; ExposureLevel = 'High'; AssetValue = 'Normal' })
            }
        }
    }
    It 'makes one row per tool and device, merges every source, and leaves out removed agents' {
        $rows = @(New-EndpointAiRows -Data (New-EpData))
        ($rows.Tool | Sort-Object) | Should -Be @('Acme Helper', 'GitHub Copilot CLI', 'Ollama')
        $ollama = $rows | Where-Object Tool -eq 'Ollama'
        $ollama.Sources | Should -Be 'Defender discovery, Process telemetry, Software inventory'
        $ollama.Version | Should -Be '0.34.1.0'
        $ollama.Runs | Should -Be 13
        $ollama.User | Should -Be 'alice'
        $ollama.Evidence.Processes.Count | Should -Be 2
    }
    It 'counts an alert only for a tool that was active within 15 minutes of it, and only if it is about AI' {
        $rows = @(New-EndpointAiRows -Data (New-EpData))
        $ollama = $rows | Where-Object Tool -eq 'Ollama'
        $copilot = $rows | Where-Object Tool -eq 'GitHub Copilot CLI'
        @($ollama.Evidence.Alerts | Where-Object { $_.AiRelated -and $_.Near }).Count | Should -Be 1
        @($copilot.Evidence.Alerts | Where-Object { $_.Near }).Count | Should -Be 0
        @($ollama.Evidence.Alerts | Where-Object { $_.Title -like 'Suspicious service*' -and $_.AiRelated }).Count | Should -Be 0
        $ollama.Risk | Should -Be 'Medium'
        $ollama.Why | Should -BeLike '*1 AI-related alert near its activity*'
    }
    It 'rates auto-approve and an approval-skipping flag as high, and an untrusted process as medium' {
        $rows = @(New-EndpointAiRows -Data (New-EpData))
        $acme = $rows | Where-Object Tool -eq 'Acme Helper'
        $acme.Risk | Should -Be 'High'
        $acme.Why | Should -BeLike '*Approves its own actions*'
        ($acme.Reasons | Where-Object Level -eq 'Medium').Text | Should -BeLike '*not trusted*'
        $copilot = $rows | Where-Object Tool -eq 'GitHub Copilot CLI'
        $copilot.Risk | Should -Be 'High'
        $copilot.Evidence.Flag | Should -Be '--yolo'
        $copilot.Evidence.Processes[0].Command | Should -Be 'copilot.exe -p "<prompt hidden>"'
    }
    It 'rates a model server reachable from the network as high, but not one on the loopback address' {
        $loop = @(New-EndpointAiRows -Data (New-EpData)) | Where-Object Tool -eq 'Ollama'
        $loop.Evidence.Listeners.Count | Should -Be 1
        @($loop.Evidence.Listeners | Where-Object Exposed).Count | Should -Be 0
        $d = New-EpData
        $d.Listening = @(@{ DeviceId = 'dev1'; DeviceName = 'lab'; Process = 'ollama.exe'; LocalIP = '0.0.0.0'; LocalPort = 11434; Hits = 2; LastSeen = '2026-09-22T14:09:13Z' })
        $open = @(New-EndpointAiRows -Data $d) | Where-Object Tool -eq 'Ollama'
        $open.Risk | Should -Be 'High'
        ($open.Reasons | Where-Object Level -eq 'High').Short | Should -BeLike '*0.0.0.0:11434*'
    }
    It 'rates a critical vulnerability as high and a high one as medium' {
        $d = New-EpData
        $d.Vulnerabilities = @(@{ DeviceId = 'dev1'; DeviceName = 'lab'; SoftwareName = 'ollama_version_0.34.1'; SoftwareVersion = '0.34.1.0'; Cves = 3; Critical = 1; High = 2; Example = 'CVE-2026-0001' })
        $o = @(New-EndpointAiRows -Data $d) | Where-Object Tool -eq 'Ollama'
        $o.Risk | Should -Be 'High'
        $o.Why | Should -BeLike '*1 critical CVE*'
        $d.Vulnerabilities[0].Critical = 0
        (@(New-EndpointAiRows -Data $d) | Where-Object Tool -eq 'Ollama').Reasons.Short | Should -Contain '2 high CVEs in 0.34.1.0'
    }
    It 'flags a local MCP server that is fetched by a package runner' {
        $d = New-EpData
        $d.Mcp = @(@{ DeviceId = 'dev1'; DeviceName = 'lab'; FileName = 'node.exe'; Runs = 4; FirstSeen = '2026-09-30T10:00:00Z'; LastSeen = '2026-10-01T10:00:00Z'; Accounts = @('alice'); Parent = 'cursor.exe'; Command = 'npx -y @modelcontextprotocol/server-filesystem C:\' })
        $mcp = @(New-EndpointAiRows -Data $d) | Where-Object Tool -eq 'MCP server (local)'
        $mcp.Category | Should -Be 'MCP server'
        $mcp.Risk | Should -Be 'Medium'
        $mcp.Why | Should -BeLike '*Local MCP server fetched at start*'
    }
    It 'marks tools as unreviewed, sanctioned or unsanctioned depending on the approved list' {
        (@(New-EndpointAiRows -Data (New-EpData)) | Where-Object Tool -eq 'Ollama').Status | Should -Be 'Unreviewed'
        (@(New-EndpointAiRows -Data (New-EpData) -Sanctioned $null) | Where-Object Tool -eq 'Ollama').Status | Should -Be 'Unreviewed'
        $rows = @(New-EndpointAiRows -Data (New-EpData) -Sanctioned @('github'))
        ($rows | Where-Object Tool -eq 'GitHub Copilot CLI').Status | Should -Be 'Sanctioned'
        ($rows | Where-Object Tool -eq 'Ollama').Status | Should -Be 'Unsanctioned'
        ($rows | Where-Object Tool -eq 'Ollama').Why | Should -BeLike '*Not sanctioned*'
    }
    It 'sorts the highest risk first' {
        $rows = @(New-EndpointAiRows -Data (New-EpData))
        $rows[0].Risk | Should -Be 'High'
        $rows[-1].Risk | Should -Be 'Medium'
    }
    It 'gives a row with no evidence at all the level None' {
        $row = [pscustomobject]@{ AutoApprove = ''; Trusted = ''; Status = 'Unreviewed'; Reasons = @()
            Evidence = [pscustomobject]@{ Flag = ''; Listeners = @(); Software = @(); Alerts = @(); LocalMcps = (New-Object 'System.Collections.Generic.List[object]'); RemoteMcps = (New-Object 'System.Collections.Generic.List[object]')
                                          Files = (New-Object 'System.Collections.Generic.List[object]'); AssetValue = ''; ExposureLevel = '' } }
        (Get-EndpointAiRisk $row).Level | Should -Be 'None'
    }
    It 'lists named hosts first and sums the bare addresses into one line in the evidence' {
        $d = New-EpData
        $d.Outbound = @(
            @{ DeviceId = 'dev1'; DeviceName = 'lab'; Process = 'ollama.exe'; Host = 'ollama.com'; Hits = 17; LastSeen = '2026-10-05T16:47:00Z' }
            @{ DeviceId = 'dev1'; DeviceName = 'lab'; Process = 'ollama.exe'; Host = '140.82.112.22'; Hits = 3; LastSeen = '2026-10-05T16:47:00Z' }
            @{ DeviceId = 'dev1'; DeviceName = 'lab'; Process = 'ollama.exe'; Host = '140.82.113.6'; Hits = 2; LastSeen = '2026-10-05T16:47:00Z' })
        $o = @(New-EndpointAiRows -Data $d) | Where-Object Tool -eq 'Ollama'
        $net = @(Get-EndpointAiDetailRows $o | Where-Object Section -eq 'Network')
        $net.Count | Should -Be 2
        $net[0].Item | Should -Be 'ollama.com'
        $net[1].Item | Should -Be 'IP addresses without a name'
        $net[1].Info | Should -BeLike '2 addresses, 5 connections*'
    }
}

Describe 'Endpoint AI: reading the data' {
    It 'runs the queries, reports progress, and returns rows with coverage' {
        $script:said = @()
        Mock Invoke-HuntingQuery {
            if ($Query -like '*summarize Devices = count() by OnboardingStatus*') { @(@{ OnboardingStatus = 'Onboarded'; Devices = 3 }, @{ OnboardingStatus = 'Can be onboarded'; Devices = 8 }) }
            elseif ($Query -like '*Platform == "LocalAgents"*') { @(@{ AgentId = 'a1'; Name = 'Ollama Desktop'; Version = '1.0'; LifecycleStatus = ''; LastSeen = '2026-10-05T16:51:06Z'; FirstSeen = '2026-09-09T10:06:02Z'; Vendor = 'Ollama'; Process = 'ollama.exe'; Trusted = 'true'; AutoApprove = 'false'; Device = 'lab'; DeviceId = 'dev1'; Account = 'alice' }, @{ AgentId = 'a2'; Name = 'Claude Desktop'; LifecycleStatus = 'Deleted'; Device = 'lab'; DeviceId = 'dev1' }) }
            elseif ($Query -like 'DeviceInfo*') { @(@{ DeviceId = 'dev1'; DeviceName = 'lab'; OSPlatform = 'Windows10'; OnboardingStatus = 'Onboarded'; DeviceType = 'Workstation'; ExposureLevel = 'Low'; AssetValue = 'Normal' }) }
            else { @() }
        }
        $data = Get-EndpointAiData -Days 7 -OnStatus { param($m) $script:said += $m }
        $data.Rows.Count | Should -Be 1
        $data.Rows[0].Tool | Should -Be 'Ollama'
        $data.Rows[0].Risk | Should -Be 'None'
        $data.Coverage['Onboarded'] | Should -Be 3
        $data.RemovedAgents | Should -Be 1
        Should -Invoke Invoke-HuntingQuery -Times 11
        $script:said.Count | Should -Be 11
        $script:said[0] | Should -BeLike 'Reading Defender local agent discovery*'
    }
    It 'says what is needed when Advanced Hunting is not available' {
        Mock Invoke-HuntingQuery { throw 'Advanced Hunting query failed (403). Endpoint AI needs Advanced Hunting' }
        { Get-EndpointAiData -Days 7 } | Should -Throw '*Advanced Hunting*'
    }
}

Describe 'Endpoint AI: lists given on the command line' {
    It 'splits a comma or semicolon separated value, so a scheduled task can pass a list' {
        ConvertTo-NameList @('GitHub,Microsoft') | Should -Be @('GitHub', 'Microsoft')
        ConvertTo-NameList @('lab-* ; vm-1') | Should -Be @('lab-*', 'vm-1')
        ConvertTo-NameList @('GitHub', 'Microsoft') | Should -Be @('GitHub', 'Microsoft')
        @(ConvertTo-NameList $null).Count | Should -Be 0
        @(ConvertTo-NameList @('', ' ,')).Count | Should -Be 0
    }
}

Describe 'Local AI agent block: the rule' {
    BeforeAll {
        function New-BlockRow {
            param([string]$ToolKey = 'ollama', [string]$Tool = 'Ollama', [string[]]$Paths = @('C:\Users\alice\AppData\Local\Programs\Ollama\ollama.exe', 'C:\Users\alice\AppData\Local\Programs\Ollama\lib\ollama\llama-server.exe'), [string]$DeviceId = '1a044ec134703a7684c3421732bbf03b1f9884d7')
            [pscustomobject]@{ ToolKey = $ToolKey; Tool = $Tool; Device = 'lab'; DeviceId = $DeviceId; Blocked = ''
                               Evidence = [pscustomobject]@{ Processes = @($Paths | ForEach-Object { [pscustomobject]@{ File = (Split-Path $_ -Leaf); Path = $_ } }) } }
        }
    }
    It 'names a rule after the tool and the first 12 characters of the device id, with safe characters only' {
        Get-LocalAgentBlockId -ToolKey 'ollama' -DeviceId '1a044ec134703a7684c3421732bbf03b1f9884d7' | Should -Be 'a365ba-block-ollama-1a044ec13470'
        Get-LocalAgentBlockId -ToolKey 'defender:Acme Helper' -DeviceId 'AB-12' | Should -Be 'a365ba-block-defender-acme-helper-ab12'
    }
    It 'turns a path into a pattern that ignores the version folder but nothing else' {
        $rx = { param($p) '(?i)^(' + (ConvertTo-PathRegex $p) + ')$' }
        $claude = 'C:\Program Files\WindowsApps\Claude_1.52386.3.0_x64__pzs8sxrjxfjjc\app\claude.exe'
        [regex]::IsMatch($claude, (& $rx $claude)) | Should -BeTrue
        [regex]::IsMatch('C:\Program Files\WindowsApps\Claude_1.60000.1.0_x64__pzs8sxrjxfjjc\app\claude.exe', (& $rx $claude)) | Should -BeTrue
        [regex]::IsMatch('C:\Users\bob\claude.exe', (& $rx $claude)) | Should -BeFalse
        $rg = 'C:\Users\alice\AppData\Local\copilot\pkg\win32-x64\1.0.87\ripgrep\bin\win32-x64\rg.exe'
        [regex]::IsMatch('C:\Users\alice\AppData\Local\copilot\pkg\win32-x64\1.0.99\ripgrep\bin\win32-x64\rg.exe', (& $rx $rg)) | Should -BeTrue
        [regex]::IsMatch('C:\Users\alice\AppData\Local\copilot\pkg\win32-x64\1.0.99\ripgrep\bin\win32-x64\rgXexe', (& $rx $rg)) | Should -BeFalse
        [regex]::IsMatch('C:\Users\alice\AppData\Local\copilot\pkg\win32-x64\1.0.99\other\bin\win32-x64\rg.exe', (& $rx $rg)) | Should -BeFalse
        (ConvertTo-PathRegex 'C:\Program Files\x\a.exe') | Should -Not -BeLike '*\ *'
    }
    It 'says why a row cannot be blocked' {
        Test-LocalAgentBlockable (New-BlockRow) | Should -Be ''
        Test-LocalAgentBlockable (New-BlockRow -DeviceId '') | Should -BeLike '*no device id*'
        Test-LocalAgentBlockable (New-BlockRow -ToolKey 'mcp-server' -Tool 'MCP server (local)') | Should -BeLike '*not a program*'
        Test-LocalAgentBlockable (New-BlockRow -Paths @()) | Should -BeLike '*nothing to match*'
        Test-LocalAgentBlockable (New-BlockRow -Paths @('C:\Windows\System32\tool.exe')) | Should -BeLike '*Windows folder*'
        Test-LocalAgentBlockable (New-BlockRow -Paths @('C:\Program Files\WindowsApps\Microsoft.MicrosoftOfficeHub_19.1.0.0_x64__8wekyb3d8bbwe\M365Copilot.exe')) | Should -BeLike '*Microsoft''s own app packages*'
        Test-LocalAgentBlockable (New-BlockRow -Paths @('C:\Program Files\WindowsApps\Claude_1.5.0.0_x64__abc\app\claude.exe')) | Should -Be ''
        Get-LocalAgentBlockPaths (New-BlockRow -Paths @('C:\Windows\System32\tool.exe', 'D:\apps\tool.exe', 'D:\apps\tool.exe')) | Should -Be @('D:\apps\tool.exe')
        (Get-LocalAgentBlockPaths (New-BlockRow -Paths @('C:\x\App_1.2.3\a.exe', 'C:\x\App_1.2.4\a.exe'))) | Should -Be @('C:\x\App_<version>\a.exe')
        (Get-LocalAgentBlockPaths (New-BlockRow -Paths @('C:\x\App_1.2.3\a.exe', 'C:\x\App_1.2.4\a.exe')) -Raw).Count | Should -Be 2
        Get-LocalAgentBlockWarning (New-BlockRow -Paths @('C:\Program Files\WindowsApps\Claude_1.5.0.0_x64__abc\app\claude.exe')) | Should -BeLike 'Installed from the Microsoft Store*'
        Get-LocalAgentBlockWarning (New-BlockRow) | Should -Be ''
    }
    It 'limits the query to the one device and the files that tool ran from' {
        $q = New-LocalAgentBlockQuery (New-BlockRow)
        $q | Should -BeLike '*DeviceProcessEvents*'
        $q | Should -BeLike '*DeviceId == "1a044ec134703a7684c3421732bbf03b1f9884d7"*'
        $q | Should -BeLike '*FolderPath matches regex @"(?i)^(C:\\Users\\alice\\AppData\\Local\\Programs\\Ollama\\ollama\.exe|C:\\Users\\alice*'
        $q | Should -BeLike '*| project Timestamp, ReportId, DeviceId, DeviceName, FileName, FolderPath, SHA1, SHA256, ProcessCommandLine*'
    }
    It 'builds a rule that stops and quarantines on that device and carries the columns the action needs' {
        $r = New-LocalAgentBlockRule -Row (New-BlockRow) -Operator 'admin@x.com'
        $r.id | Should -Be 'a365ba-block-ollama-1a044ec13470'
        $r.displayName | Should -Be 'Agent365 Bulk Actions: block Ollama on lab'
        $r.status | Should -Be 'enabled'
        $r.schedule.frequency | Should -Be 'PT1H'
        $r.description | Should -BeLike '*admin@x.com*'
        $a = $r.detectionAction.automatedActions.stopAndQuarantineFiles
        @($a).Count | Should -Be 1
        $a[0].deviceIdColumn | Should -Be 'DeviceId'; $a[0].sha1Column | Should -Be 'SHA1'
        $a[0].'@odata.type' | Should -Be '#microsoft.graph.security.stopAndQuarantineFileAction'
        $r.detectionAction.alertTemplate.entityMappings.hosts[0].deviceIdColumn | Should -Be 'DeviceId'
        $r.detectionAction.alertTemplate.severity | Should -Be 'informational'
        ($r | ConvertTo-Json -Depth 12) | Should -Match '"stopAndQuarantineFiles":\s*\['
    }
}

Describe 'Local AI agent block: creating and removing' {
    BeforeAll {
        function New-BlockRow {
            param([string]$ToolKey = 'ollama', [string]$Tool = 'Ollama', [string[]]$Paths = @('C:\Users\alice\AppData\Local\Programs\Ollama\ollama.exe'), [string]$DeviceId = '1a044ec134703a7684c3421732bbf03b1f9884d7')
            [pscustomobject]@{ ToolKey = $ToolKey; Tool = $Tool; Device = 'lab'; DeviceId = $DeviceId; Blocked = ''
                               Evidence = [pscustomobject]@{ Processes = @($Paths | ForEach-Object { [pscustomobject]@{ File = (Split-Path $_ -Leaf); Path = $_ } }) } }
        }
    }
    BeforeEach {
        Mock Write-Host { }
        Mock Export-ActionLog { }
        Mock Test-Proceed { $true }
        $script:calls = @()
    }
    It 'lists only the rules this tool made, following the next link' {
        Mock Invoke-Graph {
            $script:calls += $Uri
            if ($Uri -like '*skip=1') { @{ value = @(@{ id = 'a365ba-block-cursor-aaa'; displayName = 'c' }) } }
            else { @{ value = @(@{ id = 'a365ba-block-ollama-bbb'; displayName = 'o' }, @{ id = 'someone-elses-rule'; displayName = 'x' }); '@odata.nextLink' = 'https://graph.microsoft.com/beta/security/rules/detectionRules?skip=1' } }
        }
        $b = Get-LocalAgentBlocks
        ($b.Keys | Sort-Object) | Should -Be @('a365ba-block-cursor-aaa', 'a365ba-block-ollama-bbb')
        $script:calls.Count | Should -Be 2
    }
    It 'creates the rule on the beta detection rules endpoint and logs the files and rule id' {
        Mock Invoke-Graph { if ($Method -eq 'POST') { $script:calls += , @{ Uri = $Uri; Body = $Body } } else { @{ value = @() } } }
        $log = @(Invoke-LocalAgentBlock -Rows @(New-BlockRow) -PassThru)
        $log[0].Result | Should -Be 'Done'
        $log[0].Action | Should -Be 'blocklocalagent'
        $log[0].RuleId | Should -Be 'a365ba-block-ollama-1a044ec13470'
        $log[0].Files | Should -Be 'C:\Users\alice\AppData\Local\Programs\Ollama\ollama.exe'
        $script:calls.Count | Should -Be 1
        $script:calls[0].Uri | Should -Be 'https://graph.microsoft.com/beta/security/rules/detectionRules'
        ($script:calls[0].Body | ConvertFrom-Json).id | Should -Be 'a365ba-block-ollama-1a044ec13470'
    }
    It 'skips a row that is already blocked or cannot be blocked, and sends nothing' {
        Mock Invoke-Graph { if ($Method -eq 'POST') { $script:calls += , @{ Uri = $Uri } } else { @{ value = @(@{ id = 'a365ba-block-ollama-1a044ec13470'; displayName = 'o' }) } } }
        $log = @(Invoke-LocalAgentBlock -Rows @((New-BlockRow), (New-BlockRow -ToolKey 'mcp-server' -Tool 'MCP server (local)')) -PassThru)
        ($log | Where-Object Tool -eq 'Ollama').Error | Should -BeLike 'Already blocked*'
        ($log | Where-Object Tool -eq 'MCP server (local)').Error | Should -BeLike '*not a program*'
        @($log | Where-Object Result -eq 'Skipped').Count | Should -Be 2
        $script:calls.Count | Should -Be 0
    }
    It 'changes nothing when the proceed check says no (-WhatIf)' {
        Mock Test-Proceed { $false }
        Mock Invoke-Graph { if ($Method -eq 'POST') { $script:calls += , @{ Uri = $Uri } } else { @{ value = @() } } }
        $log = @(Invoke-LocalAgentBlock -Rows @(New-BlockRow) -PassThru)
        $log[0].Result | Should -Be 'WhatIf'
        $script:calls.Count | Should -Be 0
    }
    It 'records a refusal with the permission and role that are needed' {
        Mock Invoke-Graph { if ($Method -eq 'POST') { throw 'Forbidden' } else { @{ value = @() } } }
        $log = @(Invoke-LocalAgentBlock -Rows @(New-BlockRow) -PassThru)
        $log[0].Result | Should -Be 'Failed'
        $log[0].Error | Should -BeLike '*CustomDetection.ReadWrite.All*'
    }
    It 'removes a rule by id and reports a failure without stopping' {
        Mock Invoke-Graph { $script:calls += , @{ Method = $Method; Uri = $Uri }; if ($Uri -like '*bad*') { throw 'boom' } }
        $rules = @([pscustomobject]@{ id = 'a365ba-block-ollama-aaa'; displayName = 'Agent365 Bulk Actions: block Ollama on lab' }, [pscustomobject]@{ id = 'a365ba-block-bad-bbb'; displayName = 'Agent365 Bulk Actions: block Bad on lab' })
        $log = @(Invoke-LocalAgentUnblock -Rules $rules -PassThru)
        ($log | Where-Object RuleId -eq 'a365ba-block-ollama-aaa').Result | Should -Be 'Done'
        ($log | Where-Object RuleId -eq 'a365ba-block-bad-bbb').Result | Should -Be 'Failed'
        $script:calls[0].Method | Should -Be 'DELETE'
        $script:calls[0].Uri | Should -Be 'https://graph.microsoft.com/beta/security/rules/detectionRules/a365ba-block-ollama-aaa'
    }
    It 'marks a row as blocked when its rule exists' {
        $data = @{
            Agents = @(@{ AgentId = 'a1'; Name = 'Ollama Desktop'; Version = '1.0'; LifecycleStatus = ''; LastSeen = '2026-10-05T16:51:06Z'; FirstSeen = '2026-09-09T10:06:02Z'; Vendor = 'Ollama'; Process = 'ollama.exe'; Trusted = 'true'; AutoApprove = 'false'; Device = 'lab'; DeviceId = 'dev1'; Account = 'alice' })
            Processes = @(); Mcp = @(); Files = @(); Outbound = @(); Listening = @(); Software = @(); Vulnerabilities = @(); Alerts = @(); Devices = @()
        }
        (@(New-EndpointAiRows -Data $data) | Select-Object -First 1).Blocked | Should -Be ''
        $blocks = @{ (Get-LocalAgentBlockId -ToolKey 'ollama' -DeviceId 'dev1') = @{ id = 'x' } }
        $row = @(New-EndpointAiRows -Data $data -Blocks $blocks) | Select-Object -First 1
        $row.Blocked | Should -Be 'Blocked'
        $row.ToolKey | Should -Be 'ollama'
    }
}

Describe 'Local AI agent block: how the service behaves' {
    BeforeAll {
        function New-BlockRow {
            param([string]$ToolKey = 'ollama', [string]$Tool = 'Ollama', [string[]]$Paths = @('C:\Users\alice\AppData\Local\Programs\Ollama\ollama.exe'), [string]$DeviceId = '1a044ec134703a7684c3421732bbf03b1f9884d7')
            [pscustomobject]@{ ToolKey = $ToolKey; Tool = $Tool; Device = 'lab'; DeviceId = $DeviceId; Blocked = ''
                               Evidence = [pscustomobject]@{ Processes = @($Paths | ForEach-Object { [pscustomobject]@{ File = (Split-Path $_ -Leaf); Path = $_ } }) } }
        }
        $script:ruleId = 'a365ba-block-ollama-1a044ec13470'
    }
    BeforeEach {
        Mock Write-Host { }
        Mock Export-ActionLog { }
        Mock Test-Proceed { $true }
        $script:calls = @()
        $script:RecentlyUnblocked = @{}
    }
    It 'counts only an enabled rule that was not just removed as blocking' {
        Test-LocalAgentBlockActive -Blocks @{ $script:ruleId = @{ status = 'enabled' } } -RuleId $script:ruleId | Should -BeTrue
        Test-LocalAgentBlockActive -Blocks @{ $script:ruleId = @{ status = 'disabled' } } -RuleId $script:ruleId | Should -BeFalse
        Test-LocalAgentBlockActive -Blocks @{} -RuleId $script:ruleId | Should -BeFalse
        $script:RecentlyUnblocked[$script:ruleId] = Get-Date
        Test-LocalAgentBlockActive -Blocks @{ $script:ruleId = @{ status = 'enabled' } } -RuleId $script:ruleId | Should -BeFalse
    }
    It 'treats a rule the service no longer knows as removed, not as a failure' {
        Mock Invoke-Graph { throw 'Custom detection rule with ID x was not found. NotFound' }
        $log = @(Invoke-LocalAgentUnblock -Rules @([pscustomobject]@{ id = $script:ruleId; displayName = 'r' }) -PassThru)
        $log[0].Result | Should -Be 'Done'
        $log[0].Error | Should -BeLike '*no longer had the rule*'
    }
    It 'does not trust the list for a rule it just removed, so blocking again creates it afresh' {
        Mock Invoke-Graph {
            if ($Method -eq 'DELETE') { return }
            if ($Method -in 'POST', 'PATCH') { $script:calls += , @{ Method = $Method; Uri = $Uri }; return }
            @{ value = @(@{ id = $script:ruleId; status = 'enabled'; displayName = 'o' }) }
        }
        $null = Invoke-LocalAgentUnblock -Rules @([pscustomobject]@{ id = $script:ruleId; displayName = 'r' }) -PassThru
        $log = @(Invoke-LocalAgentBlock -Rows @(New-BlockRow) -PassThru)
        $log[0].Result | Should -Be 'Done'
        $script:calls.Count | Should -Be 1
        $script:calls[0].Method | Should -Be 'POST'
        $script:RecentlyUnblocked.ContainsKey($script:ruleId) | Should -BeFalse
    }
    It 'switches a disabled rule back on with a complete update that carries its id' {
        Mock Invoke-Graph {
            if ($Method -in 'POST', 'PATCH') { $script:calls += , @{ Method = $Method; Uri = $Uri; Body = $Body }; return }
            @{ value = @(@{ id = $script:ruleId; status = 'disabled'; displayName = 'o' }) }
        }
        $log = @(Invoke-LocalAgentBlock -Rows @(New-BlockRow) -PassThru)
        $log[0].Result | Should -Be 'Done'
        $script:calls.Count | Should -Be 1
        $script:calls[0].Method | Should -Be 'PATCH'
        $script:calls[0].Uri | Should -Be "https://graph.microsoft.com/beta/security/rules/detectionRules/$script:ruleId"
        $body = $script:calls[0].Body | ConvertFrom-Json
        $body.id | Should -Be $script:ruleId
        $body.status | Should -Be 'enabled'
        $body.detectionAction.automatedActions.stopAndQuarantineFiles[0].sha1Column | Should -Be 'SHA1'
    }
    It 'updates the rule instead when creating it says it already exists' {
        Mock Invoke-Graph {
            if ($Method -eq 'POST') { $script:calls += , @{ Method = 'POST' }; throw 'A rule with this id already exists' }
            if ($Method -eq 'PATCH') { $script:calls += , @{ Method = 'PATCH' }; return }
            @{ value = @() }
        }
        $log = @(Invoke-LocalAgentBlock -Rows @(New-BlockRow) -PassThru)
        $log[0].Result | Should -Be 'Done'
        ($script:calls | ForEach-Object { $_.Method }) | Should -Be @('POST', 'PATCH')
    }
    It 'still reports any other creation error' {
        Mock Invoke-Graph { if ($Method -eq 'POST') { throw 'Bad request: query is invalid' } else { @{ value = @() } } }
        $log = @(Invoke-LocalAgentBlock -Rows @(New-BlockRow) -PassThru)
        $log[0].Result | Should -Be 'Failed'
        $log[0].Error | Should -BeLike '*query is invalid*'
    }
    It 'marks a row as blocked only for an enabled rule' {
        $data = @{
            Agents = @(@{ AgentId = 'a1'; Name = 'Ollama Desktop'; Version = '1.0'; LifecycleStatus = ''; LastSeen = '2026-10-05T16:51:06Z'; FirstSeen = '2026-09-09T10:06:02Z'; Vendor = 'Ollama'; Process = 'ollama.exe'; Trusted = 'true'; AutoApprove = 'false'; Device = 'lab'; DeviceId = 'dev1'; Account = 'alice' })
            Processes = @(); Mcp = @(); Files = @(); Outbound = @(); Listening = @(); Software = @(); Vulnerabilities = @(); Alerts = @(); Devices = @()
        }
        $rid = Get-LocalAgentBlockId -ToolKey 'ollama' -DeviceId 'dev1'
        (@(New-EndpointAiRows -Data $data -Blocks @{ $rid = @{ id = $rid; status = 'disabled' } }) | Select-Object -First 1).Blocked | Should -Be ''
        (@(New-EndpointAiRows -Data $data -Blocks @{ $rid = @{ id = $rid; status = 'enabled' } }) | Select-Object -First 1).Blocked | Should -Be 'Blocked'
    }
}

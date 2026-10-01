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
            Mock Get-AgentIdentityState { $false }
            $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -IdentityId 'ID-1') -Action block -PassThru
            $log.Identity | Should -Be 'Disabled (by platform)'
            Should -Invoke Set-AgentIdentityState -Times 0
        }
        It 'waits for the platform and then records an unblock re-enabling the identity' {
            $script:reads = 0
            Mock Get-AgentIdentityState { $script:reads++; $script:reads -ge 2 }
            $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -Blocked $true -IdentityId 'ID-1') -Action unblock -PassThru
            $log.Identity | Should -Be 'Enabled (by platform)'
            $script:reads | Should -BeGreaterOrEqual 2
        }
        It 'forces the change itself only when the platform left the identity in the wrong state' {
            Mock Get-AgentIdentityState { $true }
            $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -IdentityId 'ID-1') -Action block -PassThru
            $log.Identity | Should -Be 'Disabled (by tool)'
            Should -Invoke Set-AgentIdentityState -Times 1 -ParameterFilter { $AgentIdentityId -eq 'ID-1' -and $Enabled -eq $false }
        }
        It 'reports a failed forced change without failing the block' {
            Mock Get-AgentIdentityState { $true }
            Mock Set-AgentIdentityState { throw 'Forbidden' }
            $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -IdentityId 'ID-1') -Action block -PassThru
            $log.Result | Should -Be 'Done'
            $log.Identity | Should -Be 'Failed'
            $log.Error | Should -Match 'Forbidden'
        }
        It 'reports an unreadable identity without changing it' {
            Mock Get-AgentIdentityState { $null }
            $log = Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -IdentityId 'ID-1') -Action block -PassThru
            $log.Identity | Should -Be 'Unreadable'
            Should -Invoke Set-AgentIdentityState -Times 0
        }
        It 'does nothing for identities without -DisableIdentity' {
            $DisableIdentity = $false
            Mock Get-AgentIdentityState { $true }
            Invoke-PackageAction -Packages @(New-Pkg 'P_1' 'Alpha' -IdentityId 'ID-1') -Action block | Out-Null
            Should -Invoke Get-AgentIdentityState -Times 0
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
    It 'allows shared agents only' {
        Test-Reassignable (New-Pkg 'P_1' 'a' -Type 'shared') | Should -BeTrue
        Test-Reassignable (New-Pkg 'P_2' 'b' -Type 'thirdParty') | Should -BeFalse
        Test-Reassignable (New-Pkg 'P_3' 'c' -Type 'lob') | Should -BeFalse
        Test-Reassignable (New-Pkg 'P_4' 'd' -Type 'firstParty') | Should -BeFalse
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
        $i = (Get-AgentInfoTable)['t_abc']
        $i.Tools[0].Name | Should -Be 'search_web'
        $i.Tools[0].Authentication | Should -Be 'Invoker'
        $i.McpServers[0].Name | Should -Be 'Work IQ Mail'
        $i.Channels | Should -Be @('MsTeams', 'Microsoft365Copilot')
        $i.SharedWith.Count | Should -Be 1
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
            DataSources = @(); Capabilities = @(); SharedWith = @('g1') }
        $row = Get-InventoryRows -Packages @(New-Pkg 'P_has' 'Agent') -InfoTable @{ 'p_has' = $info }
        $row.ToolCount | Should -Be 2
        $row.McpServers | Should -Be 'Work IQ Mail'
        $row.SharedWithCount | Should -Be 1
    }
}

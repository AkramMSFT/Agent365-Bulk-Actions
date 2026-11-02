BeforeAll {
    . (Join-Path $PSScriptRoot '..\tools\Test-ConditionalAccessLive.ps1')
    function New-Try { param([string]$Probe, [double]$Minutes, [string]$Outcome) [pscustomobject]@{ Probe = $Probe; Minutes = $Minutes; Outcome = $Outcome } }
}

Describe 'The live Conditional Access test' {
    Context 'policies stay aimed at the test' {
        It 'refuses a policy that targets everyone' {
            $body = { param($conditions) @{ displayName = "$($script:LivePrefix): x"; conditions = $conditions } }
            { Assert-LivePolicyIsNarrow (& $body @{ users = @{ includeUsers = @('All') } }) } | Should -Throw '*targets everyone*'
            { Assert-LivePolicyIsNarrow (& $body @{ users = @{ includeUsers = @('None') }; clientApplications = @{ includeAgentIdServicePrincipals = @('All') } }) } | Should -Throw '*targets everyone*'
            { Assert-LivePolicyIsNarrow (& $body @{ users = @{ includeUsers = @('None') }; agents = @{ includeAgentUsers = @('All') } }) } | Should -Throw '*targets everyone*'
            { Assert-LivePolicyIsNarrow (& $body @{ users = @{ includeUsers = @('someone') } }) } | Should -Not -Throw
        }
        It 'refuses a policy without the test name, which cleanup finds it by' {
            { Assert-LivePolicyIsNarrow @{ displayName = 'Something else'; conditions = @{ users = @{ includeUsers = @('someone') } } } } | Should -Throw '*test prefix*'
        }
        It 'writes nothing when a policy is refused' {
            Mock Invoke-Graph { throw 'not expected' }
            { New-LivePolicy -Name 'x' -Conditions @{ users = @{ includeUsers = @('All') } } } | Should -Throw '*targets everyone*'
            Should -Invoke Invoke-Graph -Times 0 -Exactly
        }
    }
    Context 'token requests' {
        It 'calls a Conditional Access refusal denied, and anything else an error' {
            Get-LiveOutcome ([pscustomobject]@{ Ok = $true; Code = 0 }) | Should -Be 'Issued'
            Get-LiveOutcome ([pscustomobject]@{ Ok = $false; Code = 53003 }) | Should -Be 'Denied'
            Get-LiveOutcome ([pscustomobject]@{ Ok = $false; Code = 65001 }) | Should -Be 'Error 65001'
        }
        It 'reports a refused request without what was sent' {
            Mock Invoke-RestMethod { throw 'failed' }
            $r = Request-LiveToken -Tenant 't' -Form @{ client_secret = 'do-not-keep' }
            $r.Ok | Should -BeFalse; $r.Token | Should -Be ''
            ($r | ConvertTo-Json -Compress) | Should -Not -BeLike '*do-not-keep*'
        }
    }
    Context 'judging a round' {
        It 'needs the last five tries to agree before calling it settled' {
            Test-LiveSettled -History @('Denied', 'Denied', 'Denied', 'Denied') -Expected 'Denied' | Should -BeFalse
            Test-LiveSettled -History @('Issued', 'Denied', 'Denied', 'Denied', 'Denied', 'Denied') -Expected 'Denied' | Should -BeTrue
            Test-LiveSettled -History @('Denied', 'Denied', 'Issued', 'Denied', 'Denied', 'Denied') -Expected 'Denied' | Should -BeFalse
        }
        It 'tells a pass, a failure and a policy still taking effect apart' {
            $line = { param($outcomes, $expected) Get-LiveRoundLine -Probe 'P' -Expected $expected -Tries @($outcomes | ForEach-Object -Begin { $i = 0 } -Process { New-Try 'P' ($i++) $_ }) }
            (& $line @('Issued', 'Denied', 'Denied', 'Denied', 'Denied', 'Denied') 'Denied').Verdict | Should -Be 'PASS'
            (& $line @('Issued', 'Issued', 'Issued', 'Issued', 'Issued') 'Denied').Verdict | Should -Be 'FAIL'
            (& $line @('Denied', 'Issued', 'Denied', 'Issued', 'Denied', 'Issued') 'Denied').Verdict | Should -Be 'NOT SETTLED'
            (& $line @('Denied', 'Denied', 'Denied', 'Denied', 'Denied') 'Issued').Verdict | Should -Be 'FAIL'
        }
        It 'records when a token was first refused and last issued, and any other outcome' {
            $l = Get-LiveRoundLine -Probe 'P' -Expected 'Denied' -Tries @((New-Try 'P' 0 'Issued'), (New-Try 'Other' 0 'Denied'), (New-Try 'P' 1 'Denied'), (New-Try 'P' 2 'Issued'), (New-Try 'P' 3 'Error 1'))
            $l.Tries | Should -Be 4; $l.Issued | Should -Be 2; $l.Denied | Should -Be 1; $l.FirstDeniedMin | Should -Be 1; $l.LastIssuedMin | Should -Be 2; $l.Other | Should -Be 'Error 1 x1'
            (Format-LiveLine $l) | Should -BeLike 'NOT SETTLED: P. Expected Denied. Issued 2, denied 1, other: Error 1 x1, first denied at 1 min, last issued at 2 min'
        }
    }
    Context 'cleanup' {
        BeforeEach {
            $script:deleted = New-Object 'System.Collections.Generic.List[string]'
            Mock Get-CaPoliciesRaw { @(@{ id = 'p-test'; displayName = "$($script:LivePrefix): x" }, @{ id = 'p-real'; displayName = 'A real policy' }) }
            Mock Get-GraphAll { @() }
            Mock Invoke-Graph { if ($Method -eq 'DELETE') { $script:deleted.Add($Uri) } }
        }
        It 'removes what carries the test name and never anything else' {
            Remove-LiveObjects -Ctx $null
            ($script:deleted -join ' ') | Should -BeLike '*p-test*'
            ($script:deleted -join ' ') | Should -Not -BeLike '*p-real*'
        }
        It 'removes the ids a run knows even when listing finds nothing, and dismisses the risk it set' {
            $ctx = [pscustomobject]@{ Policies = (New-Object 'System.Collections.Generic.List[string]'); IdentityId = 'i1'; AgentUserId = 'u1'; BlueprintObject = 'b1' }
            $ctx.Policies.Add('p-known')
            Remove-LiveObjects -Ctx $ctx
            $all = $script:deleted -join ' '
            foreach ($id in 'p-known', '/i1', '/u1', '/b1') { $all | Should -BeLike "*$id*" }
            Should -Invoke Invoke-Graph -ParameterFilter { $Method -eq 'POST' -and $Uri -like '*/dismiss' -and $Body -like '*i1*' }
        }
        It 'carries on past a failure, and says what is left' {
            Mock Invoke-Graph { if ($Method -eq 'DELETE' -and $Uri -like '*/u1') { throw 'Forbidden' }; if ($Method -eq 'DELETE') { $script:deleted.Add($Uri) } }
            Mock Write-Warning { $script:warned += @($Message) }
            $script:warned = @()
            $ctx = [pscustomobject]@{ Policies = (New-Object 'System.Collections.Generic.List[string]'); IdentityId = 'i1'; AgentUserId = 'u1'; BlueprintObject = 'b1' }
            Remove-LiveObjects -Ctx $ctx
            ($script:deleted -join ' ') | Should -BeLike '*/b1*'
            ($script:warned -join ' ') | Should -BeLike '*1 object(s) could not be removed*-CleanupOnly*'
        }
        It 'does not count something already gone as a failure' {
            Mock Invoke-Graph { if ($Method -eq 'DELETE') { throw 'NotFound' } }
            Mock Write-Warning { $script:warned += @($Message) }
            $script:warned = @()
            Remove-LiveObjects -Ctx $null
            @($script:warned).Count | Should -Be 0
        }
    }
}

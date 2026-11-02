BeforeAll {
    . (Join-Path $PSScriptRoot '..\tools\Watch-GraphApi.ps1')

    function New-Csdl {
        param([switch]$V1)
        $beta = -not $V1
        @"
<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx"><edmx:DataServices>
<Schema Namespace="microsoft.graph" Alias="graph" xmlns="http://docs.oasis-open.org/odata/ns/edm">
  <EnumType Name="agentKind"><Member Name="declarative" Value="0" /><Member Name="custom" Value="1" /></EnumType>
  <EntityType Name="entity" Abstract="true"><Key><PropertyRef Name="id" /></Key><Property Name="id" Type="Edm.String" /></EntityType>
  <EntityType Name="directoryObject" BaseType="graph.entity" />
  <EntityType Name="user" BaseType="graph.directoryObject"><Property Name="displayName" Type="Edm.String" /><Property Name="userAgent" Type="Edm.String" /><NavigationProperty Name="manager" Type="graph.directoryObject" /></EntityType>
  <EntityType Name="servicePrincipal" BaseType="graph.directoryObject"><Property Name="appId" Type="Edm.String" /></EntityType>
  <EntityType Name="agentIdentity" BaseType="graph.servicePrincipal"><Property Name="agentIdentityBlueprintId" Type="Edm.String" />$(if ($beta) { '<NavigationProperty Name="sponsors" Type="Collection(graph.directoryObject)" />' })</EntityType>
  <EntityType Name="copilotPackage" BaseType="graph.entity"><Property Name="kind" Type="graph.agentKind" /></EntityType>
  <ComplexType Name="conditionSet"><Property Name="users" Type="Collection(Edm.String)" />$(if ($beta) { '<Property Name="includeAgentIds" Type="Collection(Edm.String)" />' })</ComplexType>
  <EntityType Name="conditionalAccessPolicy" BaseType="graph.entity"><Property Name="conditions" Type="graph.conditionSet" /></EntityType>
  <EntityType Name="security" BaseType="graph.entity" />
  <Action Name="revokeSignInSessions" IsBound="true"><Parameter Name="bindingParameter" Type="graph.user" /></Action>
  $(if ($beta) { '<Action Name="block" IsBound="true"><Parameter Name="bindingParameter" Type="graph.copilotPackage" /></Action>' })
  <Annotations Target="graph.user/manager"><Annotation Term="Org.OData.Core.V1.Revisions"><Collection><Record><PropertyValue Property="Date" Date="2026-01-01" /><PropertyValue Property="Kind"><EnumMember>Org.OData.Core.V1.RevisionKind/Deprecated</EnumMember></PropertyValue><PropertyValue Property="RemovalDate" Date="2027-01-01" /><PropertyValue Property="Description" String="Use managers instead." /></Record></Collection></Annotation></Annotations>
  <EntityContainer Name="GraphService">
    <EntitySet Name="users" EntityType="graph.user" />
    <EntitySet Name="servicePrincipals" EntityType="graph.servicePrincipal" />
    <EntitySet Name="packages" EntityType="graph.copilotPackage" />
    <EntitySet Name="policies" EntityType="graph.conditionalAccessPolicy" />
    <Singleton Name="security" Type="graph.security" />
  </EntityContainer>
</Schema>
<Schema Namespace="microsoft.graph.security" Alias="self" xmlns="http://docs.oasis-open.org/odata/ns/edm">
  <Action Name="runHuntingQuery" IsBound="true"><Parameter Name="bindingParameter" Type="graph.security" /></Action>
</Schema>
</edmx:DataServices></edmx:Edmx>
"@
    }

    $script:beta = ConvertTo-EdmModel ([xml](New-Csdl))
    $script:v1 = ConvertTo-EdmModel ([xml](New-Csdl -V1))
}

Describe 'Resolving Graph paths against the metadata' {
    It 'follows <Path>' -ForEach @(
        @{ Path = '/users' }
        @{ Path = '/users/{id}/manager' }
        @{ Path = "/users(userPrincipalName='{id}')/manager" }
        @{ Path = '/users/{id}/revokeSignInSessions' }
        @{ Path = '/servicePrincipals/microsoft.graph.agentIdentity' }
        @{ Path = '/servicePrincipals/{id}/microsoft.graph.agentIdentity/sponsors/{id}/$ref' }
        @{ Path = '/servicePrincipals/{id}/graph.agentIdentity/sponsors/$ref' }
        @{ Path = '/packages/{id}/block' }
        @{ Path = '/security/runHuntingQuery' }
        @{ Path = '/security/microsoft.graph.security.runHuntingQuery' }
        @{ Path = '/policies/{id}/conditions/users' }
        @{ Path = '/users?$select=id' }
    ) {
        (Resolve-GraphPath $script:beta $Path).Found | Should -BeTrue
    }

    It 'stops at the first segment that does not exist: <Path>' -ForEach @(
        @{ Path = '/agents'; At = '/agents' }
        @{ Path = '/users/{id}/sponsors'; At = 'sponsors' }
        @{ Path = '/users/{id}/{id}'; At = '{id}' }
        @{ Path = '/users/revokeSignInSessions'; At = 'revokeSignInSessions' }
        @{ Path = '/servicePrincipals/{id}/microsoft.graph.user'; At = 'microsoft.graph.user' }
        @{ Path = '/users/{id}/revokeSignInSessions/x'; At = 'x' }
    ) {
        $r = Resolve-GraphPath $script:beta $Path
        $r.Found | Should -BeFalse
        $r.FailedAt | Should -Be $At.TrimStart('/')
    }

    It 'knows what exists only on beta' {
        (Resolve-GraphPath $script:v1 '/servicePrincipals/{id}/microsoft.graph.agentIdentity/sponsors').Found | Should -BeFalse
        (Resolve-GraphPath $script:v1 '/packages/{id}/block').Found | Should -BeFalse
        (Resolve-GraphPath $script:v1 '/servicePrincipals/{id}/microsoft.graph.agentIdentity').Found | Should -BeTrue
    }

    It 'lists nested properties and records deprecations' {
        Get-EdmPropertyPaths $script:beta 'microsoft.graph.conditionalAccessPolicy' | Should -Contain 'conditions.includeAgentIds'
        $script:beta.Deprecated['microsoft.graph.user/manager'].RemovalDate | Should -Be '2027-01-01'
    }
}

Describe 'The report' {
    BeforeAll {
        $script:endpoints = @(
            [pscustomobject]@{ version = 'v1.0'; path = '/users/{id}/manager'; use = 'Managers' }
            [pscustomobject]@{ version = 'beta'; path = '/servicePrincipals/{id}/microsoft.graph.agentIdentity'; use = 'Identity' }
            [pscustomobject]@{ version = 'beta'; path = '/policies/{id}'; use = 'Policies' }
            [pscustomobject]@{ version = 'beta'; path = '/packages/{id}/block'; use = 'Block' }
            [pscustomobject]@{ version = 'beta'; path = '/agents'; use = 'Gone' }
        )
        $script:models = @{ 'v1.0' = $script:v1; 'beta' = $script:beta }
    }

    It 'finds missing, deprecated and promotable endpoints and the beta properties v1.0 lacks' {
        $r = Get-GraphApiReport -Models $script:models -Endpoints $script:endpoints -Calls @() -Baseline $null -Changelog @()
        $r.Missing.Path | Should -Be '/agents'
        $r.Deprecated.Path | Should -Be '/users/{id}/manager'
        $r.Promotable.Path | Should -Be @('/servicePrincipals/{id}/microsoft.graph.agentIdentity', '/policies/{id}')
        ($r.Promotable | Where-Object Path -eq '/servicePrincipals/{id}/microsoft.graph.agentIdentity').V1Lacks | Should -Be 'sponsors'
        ($r.Promotable | Where-Object Path -eq '/policies/{id}').V1Lacks | Should -Be 'conditions.includeAgentIds'
        $r.Promoted.Count | Should -Be 0
    }

    It 'reports only what moved since the baseline' {
        $first = Get-GraphApiReport -Models $script:models -Endpoints $script:endpoints -Calls @() -Baseline $null -Changelog @()
        $baseline = ConvertTo-GraphApiBaseline $first | ConvertTo-Json -Depth 4 | ConvertFrom-Json
        $same = Get-GraphApiReport -Models $script:models -Endpoints $script:endpoints[0..3] -Calls @() -Baseline $baseline -Changelog @()
        $same.Promoted.Count | Should -Be 0
        $same.Diff['beta'].Added.Count | Should -Be 0
        $same.HasFindings | Should -BeTrue

        $baseline.endpoints[0].inV1 = $false
        $baseline.endpoints[1].v1Lacks = @('conditions.includeAgentIds', 'conditions.retired')
        $baseline.beta = @($baseline.beta | Where-Object { $_ -ne 'microsoft.graph.agentIdentity' }) + 'microsoft.graph.oldAgent'
        $moved = Get-GraphApiReport -Models $script:models -Endpoints $script:endpoints[1..3] -Calls @() -Baseline $baseline -Changelog @()
        ($moved.Promoted | Where-Object Path -like '*agentIdentity').Change | Should -Be 'new in v1.0'
        ($moved.Promoted | Where-Object Path -eq '/policies/{id}').Change | Should -Be 'v1.0 gained conditions.retired'
        $moved.Diff['beta'].Added | Should -Be 'microsoft.graph.agentIdentity'
        $moved.Diff['beta'].Removed | Should -Be 'microsoft.graph.oldAgent'
        $moved.HasFindings | Should -BeTrue
    }

    It 'says nothing changed when nothing did' {
        $eps = @($script:endpoints[1])
        $baseline = ConvertTo-GraphApiBaseline (Get-GraphApiReport -Models $script:models -Endpoints $eps -Calls @() -Baseline $null -Changelog @()) | ConvertTo-Json -Depth 4 | ConvertFrom-Json
        $r = Get-GraphApiReport -Models $script:models -Endpoints $eps -Calls @() -Baseline $baseline -Changelog @()
        $r.HasFindings | Should -BeFalse
        ConvertTo-GraphApiMarkdown $r -Days 7 | Should -Match 'Nothing changed\.'
    }

    It 'writes a Markdown section per finding' {
        $md = ConvertTo-GraphApiMarkdown (Get-GraphApiReport -Models $script:models -Endpoints $script:endpoints -Calls @() -Baseline $null -Changelog @()) -Days 7
        $md | Should -Match '## Not found in their version'
        $md | Should -Match '## Deprecated'
        $md | Should -Match '## Beta endpoints also in v1.0'
        $md | Should -Match 'no baseline yet'
    }
}

Describe 'The watched surface' {
    It 'keeps agent, Copilot and MCP elements and leaves out look-alikes' {
        $s = Get-WatchedSurface $script:beta
        $s | Should -Contain 'microsoft.graph.agentIdentity'
        $s | Should -Contain 'microsoft.graph.agentIdentity/sponsors'
        $s | Should -Contain 'microsoft.graph.agentKind/custom'
        $s | Should -Contain 'microsoft.graph.conditionSet/includeAgentIds'
        $s | Should -Contain 'microsoft.graph.block(microsoft.graph.copilotPackage)'
        $s | Should -Not -Contain 'microsoft.graph.user/userAgent'
        $s | Should -Not -Contain 'microsoft.graph.user/displayName'
    }
}

Describe 'The Graph changelog' {
    It 'keeps recent entries about the watched areas, with their links' {
        $feed = [xml]@'
<rss version="2.0"><channel>
<item><category>Prod</category><category>beta</category><title>Identity and access</title>
<description>&lt;div&gt;Added the &lt;a href="https://learn.microsoft.com/x"&gt;agentIdentityLifecyclePolicy&lt;/a&gt; resource.&lt;/div&gt;&lt;div&gt;Added the &lt;b&gt;color&lt;/b&gt; property.&lt;/div&gt;</description>
<pubDate>Thu, 01 Oct 2026 00:00:00 Z</pubDate></item>
<item><category>Prod</category><category>v1.0</category><title>Users</title><description>&lt;div&gt;Added the userAgent property.&lt;/div&gt;</description><pubDate>Thu, 01 Oct 2026 00:00:00 Z</pubDate></item>
<item><category>Prod</category><category>v1.0</category><title>Identity and access</title><description>&lt;div&gt;Promoted conditionalAccessPolicy changes.&lt;/div&gt;</description><pubDate>Mon, 01 Jun 2026 00:00:00 Z</pubDate></item>
</channel></rss>
'@
        $c = @(Get-GraphChangelog -Feed $feed -Since ([datetime]'2026-09-01'))
        $c.Count | Should -Be 1
        $c[0].Change | Should -Be 'Added the agentIdentityLifecyclePolicy resource.'
        $c[0].Version | Should -Be 'beta'
        $c[0].Date | Should -Be '2026-10-01'
        $c[0].Link | Should -Be 'https://learn.microsoft.com/x'
    }
}

Describe 'The endpoint list' {
    It 'normalizes <Text>' -ForEach @(
        @{ Text = '/users/$($u.id)/manager?`$select=id'; Path = '/users/{id}/manager' }
        @{ Text = '/servicePrincipals/{0}/microsoft.graph.agentIdentity/{1}/$ref'; Path = '/servicePrincipals/{id}/microsoft.graph.agentIdentity/{id}/$ref' }
        @{ Text = "/applications(appId='{0}')"; Path = "/applications(appId='{id}')" }
        @{ Text = '/users/$_`'; Path = '/users/{id}' }
        @{ Text = '/identityProtection/riskyAgents/'; Path = '/identityProtection/riskyAgents' }
    ) {
        ConvertTo-EndpointPath $Text | Should -Be $Path
    }

    It 'matches calls to listed endpoints by version and prefix' {
        $eps = @([pscustomobject]@{ version = 'beta'; path = '/servicePrincipals/{id}/microsoft.graph.agentIdentity/owners/{id}/$ref' })
        Test-EndpointListed -Endpoints $eps -Version 'beta' -Path '/servicePrincipals/{id}/microsoft.graph.agentIdentity/{id}/{id}/$ref' | Should -BeTrue
        Test-EndpointListed -Endpoints $eps -Version 'beta' -Path '/servicePrincipals' | Should -BeTrue
        Test-EndpointListed -Endpoints $eps -Version 'v1.0' -Path '/servicePrincipals' | Should -BeFalse
        Test-EndpointListed -Endpoints $eps -Version 'beta' -Path '/servicePrincipals/{id}/microsoft.graph.agentIdentity/sponsors' | Should -BeFalse
    }

    It 'lists every Graph call the script makes' {
        $eps = @(Get-Content -LiteralPath $script:EndpointsFile -Raw | ConvertFrom-Json)
        $calls = @(Get-ScriptGraphCalls)
        $calls.Count | Should -BeGreaterThan 30
        $missing = @($calls | Where-Object { -not (Test-EndpointListed -Endpoints $eps -Version $_.Version -Path $_.Path) } | ForEach-Object { '{0} {1} (line {2})' -f $_.Version, $_.Path, $_.Line })
        $missing | Should -BeNullOrEmpty -Because 'tools/graph-endpoints.json must list every endpoint the script calls'
    }

    It 'holds well-formed entries' {
        foreach ($e in @(Get-Content -LiteralPath $script:EndpointsFile -Raw | ConvertFrom-Json)) {
            $e.version | Should -BeIn @('v1.0', 'beta')
            $e.path | Should -Match '^/'
            $e.use | Should -Not -BeNullOrEmpty
        }
    }
}

<#
.SYNOPSIS
    Checks the Microsoft Graph endpoints Agent365-Bulk-Actions calls against the published API metadata and changelog.

.DESCRIPTION
    Reads the live $metadata of Graph v1.0 and beta and the Graph changelog, then reports:

    - beta endpoints the kit calls that now exist in v1.0, and the beta properties v1.0 still lacks
    - endpoints that no longer resolve in their version, or that Microsoft marks deprecated
    - Graph calls in the script that tools/graph-endpoints.json does not list
    - types, properties, relationships, actions, functions and enum members about agents, Copilot and MCP
      added or removed since tools/graph-api-baseline.json
    - changelog entries about those areas and the APIs the kit calls

    Read-only and anonymous: no sign-in and no tenant. The scheduled GitHub workflow graph-api-watch.yml runs it
    every week and keeps one issue up to date with the report.

.PARAMETER Days
    How many days of the changelog to read. Default 30.

.PARAMETER OutFile
    Writes the report as Markdown to this file.

.PARAMETER UpdateBaseline
    Saves the current agent, Copilot and MCP surface of both versions as the new baseline. Run it after reviewing a report.

.PARAMETER MetadataPath
    A folder holding v1.0.csdl and beta.csdl, used instead of downloading the metadata.

.PARAMETER ChangelogPath
    A saved copy of the changelog RSS feed, used instead of downloading it.

.PARAMETER PassThru
    Returns the report object.

.EXAMPLE
    ./tools/Watch-GraphApi.ps1 -OutFile graph-api-watch.md

.EXAMPLE
    ./tools/Watch-GraphApi.ps1 -UpdateBaseline
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 365)][int]$Days = 30,
    [string]$OutFile,
    [switch]$UpdateBaseline,
    [string]$MetadataPath,
    [string]$ChangelogPath,
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$script:LoadOnly = ($MyInvocation.InvocationName -eq '.')
$script:KitScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'Agent365-Bulk-Actions.ps1'
$script:EndpointsFile = Join-Path $PSScriptRoot 'graph-endpoints.json'
$script:BaselineFile = Join-Path $PSScriptRoot 'graph-api-baseline.json'
$script:ChangelogUri = 'https://developer.microsoft.com/en-us/graph/changelog/rss'
$script:WatchPattern = 'agent|copilot|mcp'
$script:IgnorePattern = 'userAgent|uploadAgent|partnerAgent|onPremisesAgent|onPremisesPublishing|connectorAgent|syncAgent|synchronization|hybridAgentUpdater|deviceManagement|deviceComanagement|deviceProtection|android|win32|microsoftTunnel|bitLocker|cloudPc|windowsUpdate|teamwork|printer|scheduleEntity|dragonCopilot'
$script:ChangelogPattern = "$script:WatchPattern|conditionalAccess|detectionRule|huntingQuery|auditLog|alerts_v2|revokeSignInSessions|oauth2PermissionGrant|copilotPackage"
$script:MaxListed = 150

function Invoke-WithRetry {
    param([scriptblock]$Action, [int]$Tries = 3)
    for ($i = 1; ; $i++) {
        try { return & $Action }
        catch { if ($i -ge $Tries) { throw }; Start-Sleep -Seconds (5 * $i) }
    }
}

function Get-GraphMetadata {
    param([ValidateSet('v1.0', 'beta')][string]$Version, [string]$Folder)
    if ($Folder) { return [xml](Get-Content -LiteralPath (Join-Path $Folder "$Version.csdl") -Raw) }
    [xml](Invoke-WithRetry { (Invoke-WebRequest -Uri "https://graph.microsoft.com/$Version/`$metadata" -UseBasicParsing).Content })
}

function Get-GraphChangelogFeed {
    param([string]$Path)
    if ($Path) { return [xml](Get-Content -LiteralPath $Path -Raw) }
    [xml](Invoke-WithRetry { (Invoke-WebRequest -Uri $script:ChangelogUri -UseBasicParsing).Content })
}

# 'graph.user' or 'Collection(self.alert)' -> full name and whether it is a collection.
function Resolve-EdmName {
    param([string]$Name, [hashtable]$Aliases)
    $collection = $Name -match '^Collection\((.+)\)$'
    if ($collection) { $Name = $Matches[1] }
    $i = $Name.LastIndexOf('.')
    if ($i -gt 0 -and $Aliases.ContainsKey($Name.Substring(0, $i))) { $Name = $Aliases[$Name.Substring(0, $i)] + $Name.Substring($i) }
    [pscustomobject]@{ Name = $Name; Collection = $collection }
}

# The deprecation record of an element's Org.OData.Core.V1.Revisions annotation, if any.
function Get-EdmDeprecation {
    param([System.Xml.XmlElement]$Element)
    foreach ($a in $Element.ChildNodes) {
        if ($a.LocalName -ne 'Annotation' -or $a.GetAttribute('Term') -ne 'Org.OData.Core.V1.Revisions') { continue }
        foreach ($r in $a.SelectNodes('.//*[local-name()="Record"]')) {
            $pv = @{}
            foreach ($p in $r.ChildNodes) {
                if ($p.LocalName -ne 'PropertyValue') { continue }
                $v = @('Date', 'String', 'EnumMember' | ForEach-Object { $p.GetAttribute($_) } | Where-Object { $_ })
                $pv[$p.GetAttribute('Property')] = $(if ($v) { $v[0] } else { $p.InnerText })
            }
            if ($pv.Kind -like '*Deprecated') { return [pscustomobject]@{ Date = $pv.Date; RemovalDate = $pv.RemovalDate; Description = $pv.Description } }
        }
    }
}

function ConvertTo-EdmModel {
    param([xml]$Xml)
    $schemas = @($Xml.DocumentElement.SelectNodes('//*[local-name()="Schema"]'))
    $aliases = @{}
    foreach ($s in $schemas) { if ($s.GetAttribute('Alias')) { $aliases[$s.GetAttribute('Alias')] = $s.GetAttribute('Namespace') } }
    $types = @{}; $ops = @{}; $container = @{}; $deprecated = @{}; $containerName = ''
    foreach ($s in $schemas) {
        $ns = $s.GetAttribute('Namespace')
        foreach ($e in $s.ChildNodes) {
            if ($e -isnot [System.Xml.XmlElement]) { continue }
            $kind = $e.LocalName
            if ($kind -in 'EntityType', 'ComplexType', 'EnumType') {
                $full = "$ns.$($e.GetAttribute('Name'))"
                $base = $e.GetAttribute('BaseType')
                $t = @{ Kind = $kind; Base = $(if ($base) { (Resolve-EdmName $base $aliases).Name }); Members = [ordered]@{} }
                foreach ($m in $e.ChildNodes) {
                    if ($m -isnot [System.Xml.XmlElement] -or $m.LocalName -notin 'Property', 'NavigationProperty', 'Member') { continue }
                    $name = $m.GetAttribute('Name')
                    $r = if ($m.LocalName -ne 'Member') { Resolve-EdmName $m.GetAttribute('Type') $aliases }
                    $t.Members[$name] = [pscustomobject]@{ Kind = $m.LocalName; Type = $r.Name; Collection = [bool]$r.Collection }
                    $d = Get-EdmDeprecation $m; if ($d) { $deprecated["$full/$name"] = $d }
                }
                $d = Get-EdmDeprecation $e; if ($d) { $deprecated[$full] = $d }
                $types[$full] = $t
            }
            elseif ($kind -in 'Action', 'Function' -and $e.GetAttribute('IsBound') -eq 'true') {
                $p = @($e.ChildNodes | Where-Object { $_.LocalName -eq 'Parameter' })[0]
                $b = Resolve-EdmName $p.GetAttribute('Type') $aliases
                if (-not $ops.ContainsKey($b.Name)) { $ops[$b.Name] = New-Object 'System.Collections.Generic.List[object]' }
                $ops[$b.Name].Add([pscustomobject]@{ Name = $e.GetAttribute('Name'); Kind = $kind; Namespace = $ns; Collection = [bool]$b.Collection })
                $d = Get-EdmDeprecation $e; if ($d) { $deprecated["$ns.$($e.GetAttribute('Name'))"] = $d }
            }
            elseif ($kind -eq 'EntityContainer') {
                $containerName = "$ns.$($e.GetAttribute('Name'))"
                foreach ($c in $e.ChildNodes) {
                    if ($c -isnot [System.Xml.XmlElement]) { continue }
                    $type = switch ($c.LocalName) { 'EntitySet' { $c.GetAttribute('EntityType') } 'Singleton' { $c.GetAttribute('Type') } }
                    if (-not $type) { continue }
                    $container[$c.GetAttribute('Name')] = [pscustomobject]@{ Type = (Resolve-EdmName $type $aliases).Name; Collection = ($c.LocalName -eq 'EntitySet') }
                    $d = Get-EdmDeprecation $c; if ($d) { $deprecated["$containerName/$($c.GetAttribute('Name'))"] = $d }
                }
            }
            elseif ($kind -eq 'Annotations') {
                $target = ($e.GetAttribute('Target') -replace '\(.*\)', '') -split '/', 2
                $target[0] = (Resolve-EdmName $target[0] $aliases).Name
                $d = Get-EdmDeprecation $e; if ($d) { $deprecated[($target -join '/')] = $d }
            }
        }
    }
    [pscustomobject]@{ Aliases = $aliases; Types = $types; Operations = $ops; Container = $container; ContainerName = $containerName; Deprecated = $deprecated }
}

function Test-EdmDerived {
    param($Model, [string]$Type, [string]$From)
    for ($t = $Type; $t; $t = $Model.Types[$t].Base) { if ($t -eq $From) { return $true }; if (-not $Model.Types.ContainsKey($t)) { break } }
    $false
}

function Find-EdmMember {
    param($Model, [string]$Type, [string]$Name)
    for ($t = $Type; $t -and $Model.Types.ContainsKey($t); $t = $Model.Types[$t].Base) {
        $m = $Model.Types[$t].Members[$Name]
        if ($m -and $m.Kind -ne 'Member') { return [pscustomobject]@{ Owner = $t; Kind = $m.Kind; Type = $m.Type; Collection = $m.Collection } }
    }
}

function Find-EdmOperation {
    param($Model, [string]$Type, [bool]$Collection, [string]$Name)
    for ($t = $Type; $t; $t = $Model.Types[$t].Base) {
        $op = @($Model.Operations[$t] | Where-Object { $_ -and $_.Name -eq $Name -and $_.Collection -eq $Collection })[0]
        if ($op) { return $op }
        if (-not $Model.Types.ContainsKey($t)) { break }
    }
}

# Property paths of a type, following complex properties a few levels down: 'conditions.clientApplications.includeAgentIdServicePrincipals'.
function Get-EdmPropertyPaths {
    param($Model, [string]$Type, [string]$Prefix = '', [int]$Depth = 4)
    for ($t = $Type; $t -and $Model.Types.ContainsKey($t); $t = $Model.Types[$t].Base) {
        foreach ($k in $Model.Types[$t].Members.Keys) {
            $m = $Model.Types[$t].Members[$k]
            "$Prefix$k"
            if ($m.Kind -eq 'Property' -and $Depth -gt 1 -and $Model.Types.ContainsKey([string]$m.Type) -and $Model.Types[$m.Type].Kind -eq 'ComplexType') {
                Get-EdmPropertyPaths $Model $m.Type "$Prefix$k." ($Depth - 1)
            }
        }
    }
}

# Walks an OData path through the model: entity sets and singletons, keys ({...}), casts, properties,
# relationships, bound actions and functions, and $ref / $count / $value.
function Resolve-GraphPath {
    param($Model, [string]$Path)
    $out = [pscustomobject]@{ Path = $Path; Found = $false; Type = $null; FailedAt = $null; Targets = New-Object 'System.Collections.Generic.List[string]' }
    $segs = @((($Path -split '\?')[0]).Trim('/') -split '/' | Where-Object { $_ })
    if (-not $segs) { return $out }
    $first = $segs[0]; $keyed = $false
    if ($first -match '^([^(]+)\(.*\)$') { $first = $Matches[1]; $keyed = $true }
    $c = $Model.Container[$first]
    if (-not $c) { $out.FailedAt = $segs[0]; return $out }
    $type = $c.Type; $coll = $c.Collection -and -not $keyed; $done = $false
    $out.Targets.Add("$($Model.ContainerName)/$first"); $out.Targets.Add($type)
    foreach ($seg in @($segs | Select-Object -Skip 1)) {
        $fail = $done
        if (-not $fail -and $seg -match '^\{.*\}$') { if ($coll) { $coll = $false; continue } else { $fail = $true } }
        if (-not $fail -and $seg -in '$ref', '$count', '$value') { $done = $true; continue }
        if (-not $fail -and $seg.Contains('.')) {
            $cast = (Resolve-EdmName $seg $Model.Aliases).Name
            if ($Model.Types.ContainsKey($cast) -and (Test-EdmDerived $Model $cast $type)) { $type = $cast; $out.Targets.Add($type); continue }
        }
        if (-not $fail) {
            $m = Find-EdmMember $Model $type $seg
            if ($m) { $out.Targets.Add("$($m.Owner)/$seg"); $out.Targets.Add($m.Type); $type = $m.Type; $coll = $m.Collection; continue }
            $name = $seg -replace '\(.*\)$', ''
            $op = Find-EdmOperation $Model $type $coll $name.Substring($name.LastIndexOf('.') + 1)
            if ($op) { $out.Targets.Add("$($op.Namespace).$($op.Name)"); $type = $null; $done = $true; continue }
        }
        $out.FailedAt = $seg
        return $out
    }
    $out.Found = $true; $out.Type = $type
    $out
}

# The agent, Copilot and MCP part of a model, one line per element, sorted.
function Get-WatchedSurface {
    param($Model, [string]$Pattern = $script:WatchPattern, [string]$Ignore = $script:IgnorePattern)
    $watch = [regex]::new($Pattern, 'IgnoreCase'); $skip = [regex]::new($Ignore, 'IgnoreCase')
    $hit = { param([string]$n) $watch.IsMatch($n) -and -not $skip.IsMatch($n) }
    $items = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($k in $Model.Container.Keys) { if (& $hit $k) { [void]$items.Add("$($Model.ContainerName)/$k") } }
    foreach ($full in $Model.Types.Keys) {
        $t = $Model.Types[$full]
        if ($skip.IsMatch($full)) { continue }
        $all = & $hit $full.Substring($full.LastIndexOf('.') + 1)
        if ($all) { [void]$items.Add($full) }
        foreach ($m in $t.Members.Keys) { if ($all -or (& $hit $m)) { [void]$items.Add("$full/$m") } }
    }
    foreach ($b in $Model.Operations.Keys) {
        $bound = & $hit $b.Substring($b.LastIndexOf('.') + 1)
        foreach ($op in $Model.Operations[$b]) {
            if ($bound -or (& $hit $op.Name)) { [void]$items.Add(('{0}.{1}({2}{3})' -f $op.Namespace, $op.Name, $b, $(if ($op.Collection) { '[]' }))) }
        }
    }
    @($items | Sort-Object)
}

function Get-GraphChangelog {
    param([xml]$Feed, [datetime]$Since, [string]$Pattern = $script:ChangelogPattern, [string]$Ignore = $script:IgnorePattern)
    $watch = [regex]::new($Pattern, 'IgnoreCase'); $skip = [regex]::new($Ignore, 'IgnoreCase')
    foreach ($item in @($Feed.rss.channel.item)) {
        if ([string]$item.pubDate -notmatch '(\d{1,2} \w{3} \d{4})') { continue }
        $date = [datetime]::ParseExact($Matches[1], 'd MMM yyyy', [cultureinfo]::InvariantCulture)
        if ($date -lt $Since.Date) { continue }
        $version = @(@($item.category) | Where-Object { $_ -in 'v1.0', 'beta' })[0]
        foreach ($part in ([string]$item.description -split '</div>')) {
            $text = ([Net.WebUtility]::HtmlDecode(($part -replace '<[^>]+>', '')) -replace '\s+', ' ').Trim()
            if (-not $text -or -not $watch.IsMatch($text) -or $skip.IsMatch($text)) { continue }
            $link = if ($part -match 'href="([^"]+)"') { $Matches[1] }
            [pscustomobject]@{ Date = $date.ToString('yyyy-MM-dd'); Version = $version; Area = [string]$item.title; Change = $text; Link = $link }
        }
    }
}

# '/users/$($u.id)/manager?$select=id' -> '/users/{id}/manager'
function ConvertTo-EndpointPath {
    param([string]$Text)
    $p = (($Text -split '\?')[0]) -replace '`', ''
    $p = $p -replace '\$\([^)]*\)', '{id}' -replace '\{\d+\}', '{id}' -replace '\$(?!(ref|count|value|batch)\b)[\w:]+', '{id}'
    $p.TrimEnd('/')
}

# Graph paths written literally in the script: full URLs and the relative urls of batch requests.
function Get-ScriptGraphCalls {
    param([string]$Path = $script:KitScript)
    $lines = @(Get-Content -LiteralPath $Path)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        foreach ($m in [regex]::Matches($lines[$i], 'https://graph\.microsoft\.com/(v1\.0|beta)(/[^\s"''?`]*)')) {
            $p = ConvertTo-EndpointPath $m.Groups[2].Value
            if ($p) { [pscustomobject]@{ Version = $m.Groups[1].Value; Path = $p; Line = $i + 1 } }
        }
        foreach ($m in [regex]::Matches($lines[$i], 'url\s*=\s*\(?\s*([''"])(/.*?)\1')) {
            $version = 'v1.0'
            for ($j = $i; $j -lt [Math]::Min($i + 3, $lines.Count); $j++) {
                if ($lines[$j] -match 'Invoke-GraphBatch') { if ($lines[$j] -match '-Version\s+(beta|v1\.0)') { $version = $Matches[1] }; break }
            }
            [pscustomobject]@{ Version = $version; Path = (ConvertTo-EndpointPath $m.Groups[2].Value); Line = $i + 1 }
        }
    }
}

# A call is listed when an endpoint of the same version starts with its path; {id} in the call matches any segment.
function Test-EndpointListed {
    param([object[]]$Endpoints, [string]$Version, [string]$Path)
    $want = @($Path.Trim('/') -split '/')
    foreach ($e in @($Endpoints | Where-Object { $_.version -eq $Version })) {
        $have = @($e.path.Trim('/') -split '/')
        if ($have.Count -lt $want.Count) { continue }
        $same = $true
        for ($k = 0; $k -lt $want.Count; $k++) { if ($want[$k] -ne '{id}' -and $want[$k] -ne $have[$k]) { $same = $false; break } }
        if ($same) { return $true }
    }
    $false
}

function Compare-Surface {
    param([string[]]$Now, [string[]]$Was)
    $n = New-Object 'System.Collections.Generic.HashSet[string]' (, [string[]]@($Now))
    $w = New-Object 'System.Collections.Generic.HashSet[string]' (, [string[]]@($Was))
    [pscustomobject]@{ Added = @($Now | Where-Object { -not $w.Contains($_) }); Removed = @($Was | Where-Object { -not $n.Contains($_) }) }
}

# How a beta endpoint's v1.0 coverage moved since the baseline: '' when it did not.
function Get-PromotionChange {
    param($Row, $Known)
    if (-not $Known) { return '' }
    if ($Row.InV1 -ne [bool]$Known.inV1) { return $(if ($Row.InV1) { 'new in v1.0' } else { 'no longer in v1.0' }) }
    $was = @($Known.v1Lacks)
    $gained = @($was | Where-Object { $_ -notin $Row.V1Lacks }); $added = @($Row.V1Lacks | Where-Object { $_ -notin $was })
    @($(if ($gained) { 'v1.0 gained ' + ($gained -join ', ') }), $(if ($added) { 'beta added ' + ($added -join ', ') }) | Where-Object { $_ }) -join '; '
}

function Get-GraphApiReport {
    param([hashtable]$Models, [object[]]$Endpoints, [object[]]$Calls, $Baseline, [object[]]$Changelog)
    $known = @{}
    if ($Baseline -and $Baseline.endpoints) { foreach ($b in @($Baseline.endpoints)) { $known[$b.path] = $b } }
    $rows = foreach ($e in $Endpoints) {
        $model = $Models[$e.version]
        $own = Resolve-GraphPath $model $e.path
        $v1 = if ($e.version -eq 'beta') { Resolve-GraphPath $Models['v1.0'] $e.path }
        $lacks = @()
        if ($v1 -and $v1.Found -and $own.Type -and $v1.Type) {
            $have = New-Object 'System.Collections.Generic.HashSet[string]' (, [string[]]@(Get-EdmPropertyPaths $Models['v1.0'] $v1.Type))
            $lacks = @(Get-EdmPropertyPaths $model $own.Type | Where-Object { -not $have.Contains($_) } | Sort-Object -Unique)
        }
        $dep = @($own.Targets | Select-Object -Unique | ForEach-Object { $d = $model.Deprecated[$_]; if ($d) { [pscustomobject]@{ Element = $_; Date = $d.Date; RemovalDate = $d.RemovalDate; Description = $d.Description } } })
        $row = [pscustomobject]@{ Version = $e.version; Path = $e.path; Use = $e.use; Found = $own.Found; FailedAt = $own.FailedAt
                                  InV1 = [bool]($v1 -and $v1.Found); V1Lacks = $lacks; Deprecated = $dep; Change = '' }
        if ($e.version -eq 'beta') { $row.Change = Get-PromotionChange -Row $row -Known $known[$e.path] }
        $row
    }
    $unlisted = @($Calls | Where-Object { -not (Test-EndpointListed -Endpoints $Endpoints -Version $_.Version -Path $_.Path) } |
        Group-Object Version, Path | ForEach-Object { [pscustomobject]@{ Version = $_.Group[0].Version; Path = $_.Group[0].Path; Lines = @($_.Group.Line) } })
    $surface = [ordered]@{}; $diff = [ordered]@{}
    foreach ($v in 'v1.0', 'beta') {
        $surface[$v] = Get-WatchedSurface $Models[$v]
        if ($Baseline) { $diff[$v] = Compare-Surface -Now $surface[$v] -Was @($Baseline.$v) }
    }
    $report = [pscustomobject]@{
        Checked    = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
        Endpoints  = @($rows)
        Promotable = @($rows | Where-Object { $_.Version -eq 'beta' -and $_.Found -and ($_.InV1 -or $_.Change) })
        Promoted   = @($rows | Where-Object { $_.Change })
        Missing    = @($rows | Where-Object { -not $_.Found })
        Deprecated = @($rows | Where-Object { $_.Deprecated.Count })
        Unlisted   = $unlisted
        Baseline   = $(if ($Baseline) { [string]$Baseline.updated })
        Surface    = $surface
        Diff       = $diff
        Changelog  = @($Changelog)
        HasFindings = $false
    }
    $changes = @($diff.Values | ForEach-Object { $_.Added.Count + $_.Removed.Count } | Measure-Object -Sum).Sum
    $report.HasFindings = [bool]($report.Promoted.Count + $report.Missing.Count + $report.Deprecated.Count + $unlisted.Count + $changes + $report.Changelog.Count)
    $report
}

function ConvertTo-GraphApiBaseline {
    param($Report)
    $baseline = [ordered]@{ updated = $Report.Checked; watch = $script:WatchPattern; ignore = $script:IgnorePattern
                            endpoints = @($Report.Endpoints | Where-Object { $_.Version -eq 'beta' } | ForEach-Object { [ordered]@{ path = $_.Path; inV1 = $_.InV1; v1Lacks = @($_.V1Lacks) } }) }
    foreach ($v in $Report.Surface.Keys) { $baseline[$v] = @($Report.Surface[$v]) }
    $baseline
}

function ConvertTo-MdCell { param([string]$Text) ($Text -replace '\|', '\|' -replace '\r?\n', ' ').Trim() }

function Format-MdList {
    param([string[]]$Items)
    $shown = @($Items | Select-Object -First $script:MaxListed | ForEach-Object { '- `{0}`' -f $_ })
    if ($Items.Count -gt $script:MaxListed) { $shown += ('- and {0} more' -f ($Items.Count - $script:MaxListed)) }
    $shown
}

function ConvertTo-GraphApiMarkdown {
    param($Report, [int]$Days)
    $md = New-Object 'System.Collections.Generic.List[string]'
    $md.Add('# Microsoft Graph API watch'); $md.Add('')
    $md.Add(('Checked on {0} against the live `$metadata` of Graph v1.0 and beta and the last {1} days of the [Graph changelog](https://developer.microsoft.com/graph/changelog).' -f $Report.Checked, $Days)); $md.Add('')
    $surface = if ($Report.Baseline) {
        ($Report.Diff.Keys | ForEach-Object { '{0}: {1} added, {2} removed' -f $_, $Report.Diff[$_].Added.Count, $Report.Diff[$_].Removed.Count }) -join '; '
    } else { 'no baseline yet: run with -UpdateBaseline' }
    $md.Add('| Check | Result |'); $md.Add('| --- | --- |')
    $md.Add(('| Endpoints the kit calls | {0} listed, {1} found in their version |' -f $Report.Endpoints.Count, @($Report.Endpoints | Where-Object Found).Count))
    $md.Add(('| Beta endpoints also in v1.0 | {0}, {1} changed since the baseline |' -f @($Report.Promotable | Where-Object InV1).Count, $Report.Promoted.Count))
    $md.Add(('| Not found in their version | {0} |' -f $Report.Missing.Count))
    $md.Add(('| Deprecated | {0} |' -f $Report.Deprecated.Count))
    $md.Add(('| Calls missing from graph-endpoints.json | {0} |' -f $Report.Unlisted.Count))
    $md.Add(('| Agent, Copilot and MCP surface since the baseline{0} | {1} |' -f $(if ($Report.Baseline) { " of $($Report.Baseline)" }), $surface))
    $md.Add(('| Changelog entries | {0} |' -f $Report.Changelog.Count))
    if ($Report.Promotable.Count) {
        $md.Add(''); $md.Add('## Beta endpoints also in v1.0'); $md.Add('')
        $md.Add('A call can move to v1.0 when the properties it reads and writes exist there. The full lists are in graph-api-baseline.json.'); $md.Add('')
        $md.Add('| Endpoint | Used for | Beta properties v1.0 lacks | Change since the baseline |'); $md.Add('| --- | --- | --- | --- |')
        foreach ($r in $Report.Promotable) {
            $lacks = if (-not $r.InV1) { 'not in v1.0' } elseif ($r.V1Lacks.Count -eq 0) { 'none' } elseif ($r.V1Lacks.Count -le 4) { $r.V1Lacks -join ', ' } else { '{0}: {1} and more' -f $r.V1Lacks.Count, (($r.V1Lacks | Select-Object -First 4) -join ', ') }
            $md.Add(('| `{0}` | {1} | {2} | {3} |' -f $r.Path, (ConvertTo-MdCell $r.Use), $lacks, (ConvertTo-MdCell $r.Change)))
        }
    }
    if ($Report.Missing.Count) {
        $md.Add(''); $md.Add('## Not found in their version'); $md.Add('')
        $md.Add('| Version | Endpoint | Used for | Fails at |'); $md.Add('| --- | --- | --- | --- |')
        foreach ($r in $Report.Missing) { $md.Add(('| {0} | `{1}` | {2} | `{3}` |' -f $r.Version, $r.Path, (ConvertTo-MdCell $r.Use), $r.FailedAt)) }
    }
    if ($Report.Deprecated.Count) {
        $md.Add(''); $md.Add('## Deprecated'); $md.Add('')
        $md.Add('| Version | Endpoint | Element | Since | Removal | Note |'); $md.Add('| --- | --- | --- | --- | --- | --- |')
        foreach ($r in $Report.Deprecated) { foreach ($d in $r.Deprecated) { $md.Add(('| {0} | `{1}` | `{2}` | {3} | {4} | {5} |' -f $r.Version, $r.Path, $d.Element, $d.Date, $d.RemovalDate, (ConvertTo-MdCell $d.Description))) } }
    }
    if ($Report.Unlisted.Count) {
        $md.Add(''); $md.Add('## Calls missing from graph-endpoints.json'); $md.Add('')
        $md.Add('| Version | Path | Script lines |'); $md.Add('| --- | --- | --- |')
        foreach ($u in $Report.Unlisted) { $md.Add(('| {0} | `{1}` | {2} |' -f $u.Version, $u.Path, ($u.Lines -join ', '))) }
    }
    foreach ($v in $Report.Diff.Keys) {
        foreach ($side in 'Added', 'Removed') {
            $items = @($Report.Diff[$v].$side)
            if (-not $items.Count) { continue }
            $md.Add(''); $md.Add(('## {0} in {1} since the baseline' -f $side, $v)); $md.Add('')
            foreach ($l in (Format-MdList $items)) { $md.Add($l) }
        }
    }
    if ($Report.Changelog.Count) {
        $md.Add(''); $md.Add('## Changelog'); $md.Add('')
        $md.Add('| Date | Version | Area | Change |'); $md.Add('| --- | --- | --- | --- |')
        foreach ($c in @($Report.Changelog | Select-Object -First $script:MaxListed)) {
            $text = ConvertTo-MdCell $c.Change
            if ($c.Link) { $text = '[{0}]({1})' -f ($text -replace '[\[\]]', ''), $c.Link }
            $md.Add(('| {0} | {1} | {2} | {3} |' -f $c.Date, $c.Version, (ConvertTo-MdCell $c.Area), $text))
        }
        if ($Report.Changelog.Count -gt $script:MaxListed) { $md.Add(''); $md.Add(('and {0} more entries.' -f ($Report.Changelog.Count - $script:MaxListed))) }
    }
    if (-not $Report.HasFindings) { $md.Add(''); $md.Add('Nothing changed.') }
    $md.Add(''); $md.Add('After reviewing the surface changes, refresh the baseline with `./tools/Watch-GraphApi.ps1 -UpdateBaseline` and commit it.')
    $md -join "`n"
}

if ($script:LoadOnly) { return }

$models = @{}
foreach ($v in 'v1.0', 'beta') {
    Write-Host "Reading the Graph $v metadata..."
    $models[$v] = ConvertTo-EdmModel (Get-GraphMetadata -Version $v -Folder $MetadataPath)
}

$endpoints = @(Get-Content -LiteralPath $script:EndpointsFile -Raw | ConvertFrom-Json)

if ($UpdateBaseline) {
    $baseline = ConvertTo-GraphApiBaseline (Get-GraphApiReport -Models $models -Endpoints $endpoints -Calls @() -Baseline $null -Changelog @())
    [IO.File]::WriteAllText($script:BaselineFile, (($baseline | ConvertTo-Json -Depth 4) -replace "`r`n", "`n") + "`n")
    Write-Host ('Baseline saved to {0}: {1} beta endpoints, {2} v1.0 and {3} beta elements.' -f $script:BaselineFile, $baseline.endpoints.Count, $baseline['v1.0'].Count, $baseline['beta'].Count)
    return
}

Write-Host 'Reading the Graph changelog...'
$changelog = @(Get-GraphChangelog -Feed (Get-GraphChangelogFeed -Path $ChangelogPath) -Since (Get-Date).AddDays(-$Days))
$baseline = if (Test-Path -LiteralPath $script:BaselineFile) { Get-Content -LiteralPath $script:BaselineFile -Raw | ConvertFrom-Json }
$report = Get-GraphApiReport -Models $models -Endpoints $endpoints -Calls @(Get-ScriptGraphCalls) -Baseline $baseline -Changelog $changelog
$markdown = ConvertTo-GraphApiMarkdown -Report $report -Days $Days
if ($OutFile) { Set-Content -LiteralPath $OutFile -Value $markdown -Encoding utf8NoBOM; Write-Host "Report written to $OutFile" }
else { Write-Host "`n$markdown" }
if ($PassThru) { $report }

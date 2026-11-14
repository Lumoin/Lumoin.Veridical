<#
.SYNOPSIS
Runs the non-Slow MSTest suite of Lumoin.Veridical.Tests under dotnet.wasm as several Node invocations.

.DESCRIPTION
The browser-wasm runtime is single threaded, so the platform timeout does not interrupt a running
test, and test enumeration returns nothing there, so the suite cannot be selected by listing it.
Each shard is therefore one Node process with a filter over the fully qualified test name.

A test that stalls, or that ends the process (the Mono interpreter can stop the process on an
internal assertion), would otherwise cost the rest of its shard. The script watches each process:
when its output has not grown for -TestStallMinutes, or the process ends without a run summary,
the test that was running is recorded as stalled, and the shard is run again without that test.
The final attempt of a shard is its result; the stalled tests are listed beside it so that each
can be gated in its own source. The last shard selects everything the others do not, so a new test
namespace is never left out. The script exits non-zero when a shard failed, stalled or crashed.

Publish the host first, in the mode to be measured:
  dotnet publish test/Lumoin.Veridical.Tests.Wasm -c Release -p:RunAOTCompilation=false

.PARAMETER PublishDirectory
The published host directory; the default is the Release publish output of this project.

.PARAMETER NodePath
The Node executable. The default is the newest one the wasm-tools workload installs under the dotnet root.

.PARAMETER ResultsDirectory
Where the per-attempt log and TRX files and the summary are written.

.PARAMETER TestStallMinutes
How long a process may produce no output before its current test is recorded as stalled and stopped.

.PARAMETER MaxReruns
How many times one shard is run again after a stall or crash.

.PARAMETER MaxParallel
How many processes run at the same time; each is a separate single-threaded process.

.PARAMETER Shard
Names of the shards to run, as separate values or one comma-separated value; all when omitted.

.PARAMETER Seed
Value of VERIDICAL_TEST_SEED for the run, which varies the seeds of the agreement sweeps.
#>
[CmdletBinding()]
param(
    [string]$PublishDirectory = (Join-Path $PSScriptRoot 'bin/Release/net11.0/publish'),
    [string]$NodePath = '',
    [string]$ResultsDirectory = (Join-Path $PSScriptRoot 'shard-results'),
    [int]$TestStallMinutes = 10,
    [int]$MaxReruns = 25,
    [int]$MaxParallel = 1,
    [string[]]$Shard = @(),
    [string]$Seed = ''
)

$ErrorActionPreference = 'Stop'

$namespacePrefix = 'FullyQualifiedName~Lumoin.Veridical.Tests'
$notSlow = 'TestCategory!=Slow'

$algebraicBls = "$namespacePrefix.Algebraic.Bls12Curve381"
$algebraicBn = "$namespacePrefix.Algebraic.Bn254"
$algebraicP256 = "$namespacePrefix.Algebraic.P256"
$algebraicLongfellow = "$namespacePrefix.Algebraic.Longfellow"
$algebraicOther = "$namespacePrefix.Algebraic."
$topLevelNamespaces = 'Algebraic', 'Spartan', 'Gkr', 'ConstraintSystems', 'Bbs', 'Commitments', 'Mdoc', 'Analysis', 'Longfellow'

#Each value is the filter of the shard. The final shard negates every namespace selected above.
$shards = [ordered]@{
    'algebraic-bls12'              = $algebraicBls
    'algebraic-bn254'              = $algebraicBn
    'algebraic-p256'               = $algebraicP256
    'algebraic-longfellow'         = "$algebraicLongfellow&FullyQualifiedName!~Tests.Algebraic.LongfellowMlDsa"
    'algebraic-mldsa'              = "$namespacePrefix.Algebraic.LongfellowMlDsa"
    'algebraic-rest'               = "$algebraicOther&FullyQualifiedName!~Tests.Algebraic.Bls12Curve381&FullyQualifiedName!~Tests.Algebraic.Bn254&FullyQualifiedName!~Tests.Algebraic.P256&FullyQualifiedName!~Tests.Algebraic.Longfellow"
    'spartan'                      = "$namespacePrefix.Spartan.&FullyQualifiedName!~MaskedSpartanIndistinguishabilityTests"
    'spartan-indistinguishability' = "$namespacePrefix.Spartan.MaskedSpartanIndistinguishabilityTests"
    'gkr'                          = "$namespacePrefix.Gkr."
    'constraint-systems'           = "$namespacePrefix.ConstraintSystems."
    'bbs'                          = "$namespacePrefix.Bbs."
    'commitments'                  = "$namespacePrefix.Commitments."
    'mdoc'                         = "$namespacePrefix.Mdoc."
    'longfellow'                   = "$namespacePrefix.Longfellow."
    'analysis'                     = "$namespacePrefix.Analysis."
}
$negations = ($topLevelNamespaces | ForEach-Object { "FullyQualifiedName!~Lumoin.Veridical.Tests.$_." }) -join '&'
$shards['everything-else'] = $negations

#A comma-separated list is accepted too, because a file invocation passes it as one string.
$Shard = @($Shard | ForEach-Object { $_ -split ',' } | Where-Object { $_ -ne '' })
if ($Shard.Count -gt 0) {
    $unknown = $Shard | Where-Object { -not $shards.Contains($_) }
    if ($unknown) {
        throw "Unknown shard(s): $($unknown -join ', '). Known: $($shards.Keys -join ', ')"
    }
}

$application = Join-Path $PublishDirectory 'wwwroot/main.mjs'
if (-not (Test-Path $application)) {
    throw "The published host was not found at $application. Publish the host first."
}

if ($NodePath -eq '') {
    $dotnetRoot = if ($env:DOTNET_ROOT) { $env:DOTNET_ROOT } else { Split-Path (Get-Command dotnet).Source }
    #Several pack versions can be installed side by side; the newest one carries the V8 the host needs.
    $candidate = Get-ChildItem -Path (Join-Path $dotnetRoot 'packs') -Directory -Filter 'Microsoft.NET.Runtime.Emscripten.*.Node.*' |
        ForEach-Object { Get-ChildItem -Path $_.FullName -Recurse -Include 'node', 'node.exe' -File } |
        Sort-Object { [version]($_.Directory.Parent.Parent.Name -replace '[^0-9.].*$', '') } -Descending |
        Select-Object -First 1
    if ($null -eq $candidate) {
        throw 'The workload Node was not found; pass -NodePath.'
    }

    $NodePath = $candidate.FullName
}

New-Item -ItemType Directory -Force -Path $ResultsDirectory | Out-Null
$selected = if ($Shard.Count -gt 0) { $Shard } else { @($shards.Keys) }
$overall = [Diagnostics.Stopwatch]::StartNew()

#The state of each shard across its attempts: the tests excluded so far and the attempt number.
$state = @{}
foreach ($name in $selected) {
    $state[$name] = [pscustomobject]@{ Stalled = [System.Collections.Generic.List[string]]::new(); Attempt = 0; Minutes = 0.0 }
}

function Start-Attempt([string]$name) {
    $shardState = $state[$name]
    $shardState.Attempt++
    $filter = "$($shards[$name])&$notSlow"
    foreach ($test in $shardState.Stalled) {
        $filter += "&FullyQualifiedName!~.$test"
    }

    $stem = Join-Path $ResultsDirectory "$name.$($shardState.Attempt)"
    $arguments = @(
        '--experimental-wasm-exnref', "`"$application`"",
        '--output', 'Detailed',
        '--filter', "`"$filter`"",
        '--trx-out', "`"$stem.trx`""
    )
    if ($Seed -ne '') {
        $env:VERIDICAL_TEST_SEED = $Seed
    }

    $process = Start-Process -FilePath $NodePath -ArgumentList $arguments -NoNewWindow -PassThru `
        -RedirectStandardOutput "$stem.log" -RedirectStandardError "$stem.err.log"
    return [pscustomobject]@{
        Name = $name; Process = $process; Stem = $stem; Clock = [Diagnostics.Stopwatch]::StartNew()
        LastSize = -1; LastChange = [Diagnostics.Stopwatch]::StartNew(); Stalled = $false
    }
}

function Get-AttemptText($running) {
    #The platform writes the run summary and the failure details of a failing run to standard error.
    $text = ''
    foreach ($path in "$($running.Stem).log", "$($running.Stem).err.log") {
        if (Test-Path $path) { $text += (Get-Content -Raw $path) + "`n" }
    }

    return $text
}

function Get-LastStartedTest([string]$text) {
    $lines = $text -split "`n" | Where-Object { $_ -match '^running ' }
    if ($lines) {
        return ($lines | Select-Object -Last 1).Trim() -replace '^running ', ''
    }

    return ''
}

$final = @{}
$active = @()
$queue = [System.Collections.Queue]::new($selected)
while ($queue.Count -gt 0 -or $active.Count -gt 0) {
    while ($queue.Count -gt 0 -and $active.Count -lt $MaxParallel) {
        $active += Start-Attempt $queue.Dequeue()
    }

    Start-Sleep -Seconds 5
    foreach ($running in @($active)) {
        $size = 0
        foreach ($path in "$($running.Stem).log", "$($running.Stem).err.log") {
            if (Test-Path $path) { $size += (Get-Item $path).Length }
        }

        if ($size -ne $running.LastSize) {
            $running.LastSize = $size
            $running.LastChange.Restart()
        }

        if (-not $running.Process.HasExited -and $running.LastChange.Elapsed.TotalMinutes -gt $TestStallMinutes) {
            #Only the process this script started is stopped, by its identifier.
            Stop-Process -Id $running.Process.Id -Force
            $running.Stalled = $true
        }

        if (-not $running.Process.HasExited) {
            continue
        }

        $running.Process.WaitForExit()
        $text = Get-AttemptText $running
        $shardState = $state[$running.Name]
        $shardState.Minutes += $running.Clock.Elapsed.TotalMinutes
        $active = @($active | Where-Object { $_.Stem -ne $running.Stem })

        $hasSummary = $text -match '(?s)Test run summary:.*?total:\s*(\d+).*?failed:\s*(\d+).*?succeeded:\s*(\d+).*?skipped:\s*(\d+)'
        if ($hasSummary -and -not $running.Stalled) {
            $final[$running.Name] = [pscustomobject]@{
                Shard = $running.Name; Status = if ([int]$Matches[2] -gt 0) { 'FAILED' } else { 'OK' }
                Total = [int]$Matches[1]; Passed = [int]$Matches[3]; Failed = [int]$Matches[2]; Skipped = [int]$Matches[4]
                Attempts = $shardState.Attempt; Stalled = ($shardState.Stalled -join ' ')
            }

            continue
        }

        #No summary: the test that was running when the process stopped is excluded from the next attempt.
        $test = Get-LastStartedTest $text
        if ($test -ne '' -and -not $shardState.Stalled.Contains($test) -and $shardState.Attempt -le $MaxReruns) {
            $shardState.Stalled.Add($test)
            $queue.Enqueue($running.Name)
        }
        else {
            $final[$running.Name] = [pscustomobject]@{
                Shard = $running.Name; Status = if ($running.Stalled) { 'STALLED' } else { 'CRASH' }
                Total = 0; Passed = 0; Failed = 0; Skipped = 0
                Attempts = $shardState.Attempt; Stalled = ($shardState.Stalled -join ' ')
            }
        }
    }
}

$results = @($selected | ForEach-Object { $final[$_] })
foreach ($result in $results) {
    $result | Add-Member -NotePropertyName Minutes -NotePropertyValue ([math]::Round($state[$result.Shard].Minutes, 1))
}

$results | Format-Table Shard, Status, Total, Passed, Failed, Skipped, Attempts, Minutes -AutoSize | Out-String | Write-Host
foreach ($result in $results | Where-Object { $_.Stalled -ne '' }) {
    Write-Host "Stalled in $($result.Shard), excluded from its final attempt: $($result.Stalled)"
}

$totals = [pscustomobject]@{
    Total = ($results | Measure-Object Total -Sum).Sum; Passed = ($results | Measure-Object Passed -Sum).Sum
    Failed = ($results | Measure-Object Failed -Sum).Sum; Skipped = ($results | Measure-Object Skipped -Sum).Sum
    WallMinutes = [math]::Round($overall.Elapsed.TotalMinutes, 1)
}
$totals | Format-List | Out-String | Write-Host
$results | ConvertTo-Json | Set-Content -Path (Join-Path $ResultsDirectory 'summary.json')

if ($results | Where-Object { $_.Status -ne 'OK' -or $_.Stalled -ne '' }) {
    exit 1
}

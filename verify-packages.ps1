# Verifies every NuGet package in the full dependency graph against the
# signature and trusted-signer (owners) requirements in NuGet.config --
# the same NU3034 check a clean-cache CI restore performs, runnable
# locally before pushing.
#
# The graph is enumerated from the packages.lock.json files (direct AND
# transitive packages -- a transitive package with an unlisted owner fails
# CI restore exactly like a direct one) plus .config/dotnet-tools.json
# (dotnet tool restore enforces the same policy). Packages must be in the
# local cache (run a restore first); missing ones are reported, not failed,
# since for example RID-specific ILCompiler packages only appear after a
# matching publish.

$globalPackages = if ($env:NUGET_PACKAGES) { $env:NUGET_PACKAGES } else { Join-Path $HOME '.nuget/packages' }
Write-Host "NuGet global packages folder: $globalPackages"

# Collect unique id|version pairs from every lock file outside bin/obj.
$pairs = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
Get-ChildItem -Recurse -Filter packages.lock.json | Where-Object { $_.FullName -notmatch '\\(bin|obj)\\' } | ForEach-Object {
    $lock = Get-Content $_.FullName -Raw | ConvertFrom-Json
    foreach ($framework in $lock.dependencies.PSObject.Properties) {
        foreach ($dependency in $framework.Value.PSObject.Properties) {
            if ($dependency.Value.type -ne 'Project' -and $dependency.Value.resolved) {
                [void]$pairs.Add("$($dependency.Name)|$($dependency.Value.resolved)")
            }
        }
    }
}

# Local dotnet tools are restored with the same NuGet.config policy.
$toolsManifest = Join-Path (Get-Location) '.config/dotnet-tools.json'
if (Test-Path $toolsManifest) {
    $tools = Get-Content $toolsManifest -Raw | ConvertFrom-Json
    foreach ($tool in $tools.tools.PSObject.Properties) {
        [void]$pairs.Add("$($tool.Name)|$($tool.Value.version)")
    }
}

Write-Host "Verifying $($pairs.Count) packages (direct + transitive + tools)."

$failedPackages = @()
$missingPackages = @()
foreach ($pair in $pairs) {
    $id, $version = $pair.Split('|')
    $packagePath = Join-Path $globalPackages $id.ToLowerInvariant() $version.ToLowerInvariant() "$($id.ToLowerInvariant()).$($version.ToLowerInvariant()).nupkg"

    if (-not (Test-Path $packagePath)) {
        $missingPackages += $pair
        Write-Host "MISSING (not in local cache, skipping): $id $version"
        continue
    }

    $output = & dotnet nuget verify --all "$packagePath" --configfile NuGet.config 2>&1
    if ($LASTEXITCODE -ne 0) {
        $failedPackages += $pair
        Write-Host "FAILED: $id $version" -ForegroundColor Red
        Write-Host ($output -join [Environment]::NewLine)
    } else {
        Write-Host "ok: $id $version"
    }
}

Write-Host ""
Write-Host "Verified: $($pairs.Count - $failedPackages.Count - $missingPackages.Count), missing from cache: $($missingPackages.Count), failed: $($failedPackages.Count)"
if ($failedPackages.Count -gt 0) {
    Write-Host "One or more package verifications failed:" -ForegroundColor Red
    $failedPackages | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    exit 1
}

Write-Host "All cached package verifications succeeded." -ForegroundColor Green

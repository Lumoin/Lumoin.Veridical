#Requires -Version 7.0

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

$globalPackagesFolder = if ($env:NUGET_PACKAGES) { $env:NUGET_PACKAGES } else { Join-Path -Path $env:USERPROFILE -ChildPath '.nuget' -AdditionalChildPath 'packages' }
Write-Output "NuGet global packages folder: $globalPackagesFolder"

$pairs = [System.Collections.Generic.List[string]]::new()

$lockFiles = Get-ChildItem -Path '.' -Filter 'packages.lock.json' -Recurse -File |
    Where-Object -FilterScript { $_.FullName -notmatch '\\(bin|obj)\\' }

foreach ($lockFile in $lockFiles) {
    $lockDocument = ConvertFrom-Json -InputObject (Get-Content -Path $lockFile.FullName -Raw)

    foreach ($frameworkProperty in $lockDocument.dependencies.PSObject.Properties) {
        foreach ($packageProperty in $frameworkProperty.Value.PSObject.Properties) {
            $dependency = $packageProperty.Value

            if ($dependency.type -ne 'Project' -and $null -ne $dependency.resolved) {
                $pairs.Add("$($packageProperty.Name)|$($dependency.resolved)")
            }
        }
    }
}

$toolsManifestPath = Join-Path -Path '.config' -ChildPath 'dotnet-tools.json'
if (Test-Path -Path $toolsManifestPath -PathType Leaf) {
    $toolsManifest = ConvertFrom-Json -InputObject (Get-Content -Path $toolsManifestPath -Raw)

    foreach ($toolProperty in $toolsManifest.tools.PSObject.Properties) {
        $pairs.Add("$($toolProperty.Name)|$($toolProperty.Value.version)")
    }
}

$uniquePairs = @($pairs | Sort-Object -Unique)
$total = $uniquePairs.Count
Write-Output "Verifying $total packages (direct + transitive + tools)."

$failedCount = 0
$missingCount = 0

foreach ($pair in $uniquePairs) {
    $id, $version = $pair -split '\|', 2
    $idLower = $id.ToLowerInvariant()
    $versionLower = $version.ToLowerInvariant()
    $packagePath = Join-Path -Path $globalPackagesFolder -ChildPath $idLower -AdditionalChildPath $versionLower, "$idLower.$versionLower.nupkg"

    if (-not (Test-Path -Path $packagePath -PathType Leaf)) {
        $missingCount++
        Write-Output "MISSING (not in local cache, skipping): $id $version"
        continue
    }

    $verifyOutput = & dotnet nuget verify --all $packagePath --configfile NuGet.config 2>&1
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        $failedCount++
        Write-Output "FAILED: $id $version"

        foreach ($line in $verifyOutput) {
            Write-Output $line.ToString()
        }
    }
    else {
        Write-Output "ok: $id $version"
    }
}

Write-Output ''
$verifiedCount = $total - $failedCount - $missingCount
Write-Output "Verified: $verifiedCount, missing from cache: $missingCount, failed: $failedCount"

if ($failedCount -gt 0) {
    Write-Output 'One or more package verifications failed.'
    exit 1
}

Write-Output 'All cached package verifications succeeded.'

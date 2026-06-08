#!/bin/bash
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
#
# Requires jq (preinstalled on the GitHub-hosted runners and common locally).

set -u

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required to parse packages.lock.json files." >&2
    exit 2
fi

globalPackages="${NUGET_PACKAGES:-$HOME/.nuget/packages}"
echo "NuGet global packages folder: $globalPackages"

# Unique "id|version" pairs from every lock file outside bin/obj, plus the
# local dotnet tools manifest.
pairs=$( {
    find . -name packages.lock.json -not -path '*/bin/*' -not -path '*/obj/*' -print0 |
        xargs -0 cat |
        jq -r '.dependencies[] | to_entries[] | select(.value.type != "Project") | select(.value.resolved != null) | "\(.key)|\(.value.resolved)"'
    if [ -f .config/dotnet-tools.json ]; then
        jq -r '.tools | to_entries[] | "\(.key)|\(.value.version)"' .config/dotnet-tools.json
    fi
} | sort -fu )

total=$(printf '%s\n' "$pairs" | wc -l)
echo "Verifying $total packages (direct + transitive + tools)."

failed=0
missing=0
while IFS='|' read -r id version; do
    idLower=$(printf '%s' "$id" | tr '[:upper:]' '[:lower:]')
    versionLower=$(printf '%s' "$version" | tr '[:upper:]' '[:lower:]')
    packagePath="$globalPackages/$idLower/$versionLower/$idLower.$versionLower.nupkg"

    if [ ! -f "$packagePath" ]; then
        missing=$((missing + 1))
        echo "MISSING (not in local cache, skipping): $id $version"
        continue
    fi

    if ! output=$(dotnet nuget verify --all "$packagePath" --configfile NuGet.config 2>&1); then
        failed=$((failed + 1))
        echo "FAILED: $id $version"
        printf '%s\n' "$output"
    else
        echo "ok: $id $version"
    fi
done <<< "$pairs"

echo ""
echo "Verified: $((total - failed - missing)), missing from cache: $missing, failed: $failed"
if [ "$failed" -gt 0 ]; then
    echo "One or more package verifications failed."
    exit 1
fi

echo "All cached package verifications succeeded."

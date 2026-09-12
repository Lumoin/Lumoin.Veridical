# Mutation testing with Stryker.NET

Stryker.NET runs here to produce an informational mutation score for a deliberately
narrow set of source files. It is not a merge gate: `stryker-config.json` sets its
`break` threshold to `0`, so the tool's own exit code never fails a build. Read the
score to find where the test suite's assertions are weaker than its coverage numbers
suggest, then close the gaps it finds the way any other test gap gets closed.

## Prerequisites

- The exact .NET SDK version pinned in `global.json`. Roll-forward is disabled for
  that pin, so a different installed SDK will not be substituted.
- A tool restore, from the repository root, to install `dotnet-stryker` from
  `.config/dotnet-tools.json`:

  ```powershell
  dotnet tool restore
  ```

## Running Stryker

From `test/Lumoin.Veridical.Tests/`, in PowerShell:

```powershell
$env:VERIDICAL_STRYKER_RUN = "true"
dotnet tool run dotnet-stryker --config-file stryker-config.json --concurrency 1 --reporter progress --log-to-file
Remove-Item Env:\VERIDICAL_STRYKER_RUN
```

`VERIDICAL_STRYKER_RUN` gates the `PropertyGroup` in `Lumoin.Veridical.Tests.csproj`
that switches the test host Stryker instruments; unset it as soon as the run finishes
so an ordinary `dotnet build` or `dotnet test` is never affected. The `--concurrency 1`
override above takes precedence over the `2` in the tracked config — see the
concurrency caution below for why the first run on a given host should always pass it
explicitly rather than relying on the tracked default. The switched build restores
without the package lock file, so a Stryker run leaves `packages.lock.json` untouched.

**Fallback.** Setting `UseVSTest` alone left the MSTest test host active (the suite
still started through the Microsoft.Testing.Platform entry point instead of VsTest),
so the tracked property group carries the explicit pair alongside it: `UseVSTest`
stays `true`, and `EnableMSTestRunner` and `TestingPlatformDotnetTestSupport` are
both set to `false`. If a future SDK update makes `UseVSTest=true` sufficient on its
own, the pair can be dropped, but leaving it in place is harmless either way.

## Where reports land

Stryker writes its reports under `StrykerOutput/` (the `html`, `json`, and `markdown`
reporters are all configured), and `--log-to-file` writes its own log alongside them.
`StrykerOutput/` is listed in `.gitignore`, so nothing it produces is ever staged by an
ordinary `git add`.

## Triaging survivors

A mutant that survives (Stryker's tests did not catch the change) falls into one of
three buckets:

- **Real test gap.** The suite has no assertion that would have caught the mutated
  behavior. Write the missing test, to the same quality bar as the rest of the suite,
  and confirm it kills the mutant.
- **Equivalent mutant.** The mutated code is behaviorally indistinguishable from the
  original for every reachable input, so no test could ever kill it. Record this in the
  code (or in the change that examines it) rather than searching for an unwritable
  test.
- **Dead code.** The surviving mutant sits in code no execution path reaches. Fix the
  dead code in its own commit, kept separate from any test additions the same run
  motivated.

## Concurrency caution

Start at `--concurrency 1` on a host with many cores before trusting the tracked
config's `concurrency: 2`. Stryker.NET has an open issue (Stryker-NET/stryker-net#3727)
describing a race between its coverage analysis and the VsTest runner that reproduces
more readily under concurrent test-runner instances; a clean run at `1` does not rule
it out at `2`, but running at `1` first keeps a hang or a flaky failure from being
misread as a problem with the mutated code itself. Only raise concurrency, or drop the
override and rely on the tracked config's value, once a run at `1` has completed
cleanly on that host.

## What stays tracked

`.config/dotnet-tools.json` (the `dotnet-stryker` tool-manifest entry) and
`stryker-config.json` are checked-in configuration. Everything Stryker produces at run
time — reports, logs — lands under `StrykerOutput/`, which git ignores; a report is
never committed.

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
dotnet tool run dotnet-stryker --config-file stryker-config.json --output ../../StrykerOutput --concurrency 1 --reporter progress --log-to-file
Remove-Item Env:\VERIDICAL_STRYKER_RUN
```

`VERIDICAL_STRYKER_RUN` gates the `PropertyGroup` in `Lumoin.Veridical.Tests.csproj`
that switches the test host Stryker instruments; unset it as soon as the run finishes
so an ordinary `dotnet build` or `dotnet test` is never affected. The `--concurrency 1`
override above takes precedence over the value in the tracked config — see the
concurrency caution below for why the first run on a given host should always pass it
explicitly rather than relying on the tracked default. The output folder is given on
the command line because Stryker 4.16 rejects an `output` key inside the config file.
The switched build restores without the package lock file in the test project and in
the Benchmarks project (which references it), so a Stryker run leaves every tracked
`packages.lock.json` untouched. Stryker builds the whole solution in place and then
replaces the assembly under test inside the test project's `bin/` with its mutated
build: never run `dotnet build` or `dotnet test` in the tree while a run is in
progress, or the run is destroyed.

The `mutate` entries are glob patterns. Each is written with a `**/` prefix followed by
the file's path inside the project the `project` key names, so it matches whichever
base directory Stryker resolves patterns against (the source project's folder in
project mode, the solution's folder when a `solution` key is present). Stryker
generates mutants for every file of the project before it applies the list: the
"N mutants created" line is that pre-filter total and says nothing about the slice.
The list takes effect afterwards, once the initial coverage run has finished, as a
line reporting the mutants that "got status Ignored" because of the file pattern
filter, followed by the count that will actually be tested. Judge a slice's scope by
those lines, never by the creation count; a list that matches nothing shows up there
as zero ignored mutants and a tested count equal to the total.

## Slices over another project

One config file mutates one project. `stryker-config-backends.json` is the slice over
the per-ISA scalar kernels in `Lumoin.Veridical.Backends.Managed` (the AVX-512, AVX2
and portable-SIMD backends and the VPCLMULQDQ GF(2^128) kernel). Its mutants are only
killed on a host whose CPU runs those paths — the agreement tests skip elsewhere and
leave the mutants uncovered — so that slice runs on an AVX-512 machine:

```powershell
$env:VERIDICAL_STRYKER_RUN = "true"
dotnet tool run dotnet-stryker --config-file stryker-config-backends.json --output ../../StrykerOutput --reporter progress --log-to-file
Remove-Item Env:\VERIDICAL_STRYKER_RUN
```

Its `test-case-filter` names the fourteen test classes that exercise those kernels (the
per-backend agreement tests, the dispatch, batch, multilinear-extension and managed-backend
tests) instead of the whole non-Slow suite. Stryker compiles every mutant of the project
into the assembly under test before the `mutate` list narrows what is tested, so a
whole-suite coverage run executes the BigInteger reference arithmetic with every mutation
point instrumented and takes hours; the fourteen classes give the same kill power for the
kernels in minutes. The filter is a config key: Stryker 4.16 has no command-line option for
it. That config also sets `coverage-analysis` to `off`: with a test set this small, running every
filtered test against every mutant costs little, and it removes the per-test coverage attribution
that otherwise decides which tests a mutant sees — attribution that has been observed to drop a
mutant's discriminating test when many classes are in the run, so that the same mutant is killed
in a one-class run and reported as surviving in the full slice.

To try a single file first, copy the config next to it, shorten its `mutate` list (and, if
useful, its `test-case-filter`), run with `--config-file` naming the copy, and delete the
copy afterwards; copies are never committed.

**Lower tiers.** On an AVX-512 host the dispatch facades never take their AVX2, NEON,
WebAssembly or serial arms, so the slice is run again with a runtime switch that hides a
tier: `DOTNET_EnableAVX512=0` makes the facades select AVX2, and `DOTNET_EnableAVX2=0`
withdraws AVX-512 as well and leaves only the serial fallback (`DOTNET_EnableAVX512F`, the
name from before the AVX-512 instruction sets were merged into one switch, does nothing on
.NET 10 and later). Under a switch the tests that require the hidden feature report
`Assert.Inconclusive` and that tier's own kernel files survive wholesale, so no single run's
score means anything for the slice: a mutant counts as covered when at least one
configuration kills it, and the runs are compared per file. Two groups stay uncovered on any
x64 host by construction: the NEON and WebAssembly arm bodies, and the AVX-512 condition's
`&&`, which only a host reporting AVX-512F without 512-bit acceleration tells apart from `||`
(`DOTNET_PreferredVectorBitWidth=256` reproduces such a host).

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

`.config/dotnet-tools.json` (the `dotnet-stryker` tool-manifest entry),
`stryker-config.json` and `stryker-config-backends.json` are checked-in configuration. Everything Stryker produces at run
time — reports, logs — lands under `StrykerOutput/`, which git ignores; a report is
never committed.

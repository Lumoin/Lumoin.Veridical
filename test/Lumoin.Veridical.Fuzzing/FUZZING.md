# Fuzzing the hand-written decoders (W1-c)

The library parses several hostile-by-assumption binary formats with hand-written readers:
the Circom `.r1cs` / `.wtns` readers, the ZkInterface FlatBuffers decoder and its R1CS /
witness readers, the Longfellow circuit reader, the compressed sumcheck round-polynomial
reader, the raw R1CS witness reader, and the compressed elliptic-curve point decoders. A
decoder that meets malformed input must reject it with a *documented* exception, never crash
with an undocumented one (an out-of-range index, an overflow, a null dereference) or loop /
allocate unboundedly.

Two harnesses cover this, at two levels of investment.

## 1. Deterministic corpus-replay harness — runs today, no extra tooling

`test/Lumoin.Veridical.Tests/Fuzzing/` (`DecoderRobustnessTests`, `DecoderFuzzTargets`,
`DeterministicMutations`) feeds each committed seed corpus and a fixed, reproducible catalogue
of mutations (bit flips, byte pins, truncation, extension, header-window fills, length-field
tampering) through every decoder target. Each target declares the exception types that count as
a graceful rejection; anything else fails the test with the reproducing input's hex bytes.

- Smoke sweep runs in the normal test leg (`TestCategory != Slow`).
- The full per-corpus sweep is `TestCategory = Slow` (runs in the slow-tests workflow).
- It needs no external package, so it is the standing regression net. Run it with:

  ```
  dotnet test --project test/Lumoin.Veridical.Tests/Lumoin.Veridical.Tests.csproj \
      --filter "FullyQualifiedName~DecoderRobustnessTests"
  ```

`DecoderFuzzTargets.All` is the canonical target registry (name -> invocation ->
expected-rejection set). It covers the public external parsers **and** the internal Longfellow
and curve decoders (reachable from the test assembly via `InternalsVisibleTo`).

## 2. SharpFuzz / libFuzzer harness — coverage-guided, staged but inert

`test/Lumoin.Veridical.Fuzzing/` is a console libFuzzer host (`Program.cs`) over the public
external parsers — the true wire-format attack surface. It mirrors the corresponding subset of
`DecoderFuzzTargets`. Each process fuzzes one target, named by the first argument:

```
circom-r1cs  circom-wtns  zkinterface-decoder  zkinterface-r1cs  zkinterface-wtns
compressed-round-poly  raw-r1cs-witness
```

It is **built inert by default**: without `-p:EnableSharpFuzz=true` the libFuzzer entry point is
not compiled and the program only prints this activation notice. The project is intentionally
**not** in `Lumoin.Veridical.slnx`, so a normal solution restore never pulls SharpFuzz.

### Why it is gated

SharpFuzz is a NuGet package whose owner is **not** in the repository's trusted-signers
allowlist (`NuGet.config` `<owners>`). With `signatureValidationMode=require`, an unconditional
reference would fail restore with NU3034. Adding a package owner is a supply-chain trust
decision reserved to the repository owner — the same gate that currently keeps
ReportGenerator / dotnet-validate commented out in `main.yml`. OSS-Fuzz also still excludes
.NET, so coverage-guided fuzzing here is necessarily self-hosted.

### Activation (owner steps)

1. **Trust the package.** Add SharpFuzz's nuget.org owner account to the `<owners>` list in
   `NuGet.config` (verify the account on the SharpFuzz nuget.org page first). Confirm the version
   pin in `Directory.Packages.props` (`SharpFuzz`, currently `2.1.1`) is current. The default lock
   file omits SharpFuzz, so the first `EnableSharpFuzz=true` restore must regenerate it — restore
   with `--force-evaluate` (or delete `test/Lumoin.Veridical.Fuzzing/packages.lock.json` first) to
   avoid a locked-mode NU1004.
2. **Install the instrumenter** (a global tool that rewrites IL to add libFuzzer coverage
   counters):

   ```
   dotnet tool install --global SharpFuzz.CommandLine
   ```

3. **Publish the host and instrument the assemblies under fuzz.** libFuzzer needs the target
   code instrumented; instrument the Veridical assemblies the target exercises (Core and
   Backends.Managed), not the framework:

   ```
   dotnet publish test/Lumoin.Veridical.Fuzzing/Lumoin.Veridical.Fuzzing.csproj \
       -c Release -p:EnableSharpFuzz=true -o out/fuzz
   sharpfuzz out/fuzz/Lumoin.Veridical.Core.dll
   sharpfuzz out/fuzz/Lumoin.Veridical.Backends.Managed.dll
   ```

4. **Run a target.** Seed the corpus from the committed fixtures (see below), then:

   ```
   mkdir -p corpus/circom-r1cs findings/circom-r1cs
   cp test/Lumoin.Veridical.Tests/ConstraintSystems/Interop/Circom/Fixtures/*/poseidon2.r1cs corpus/circom-r1cs/
   out/fuzz/Lumoin.Veridical.Fuzzing circom-r1cs \
       -artifact_prefix=findings/circom-r1cs/ -max_total_time=900 corpus/circom-r1cs
   ```

   The first argument selects the target; everything after it is passed straight to libFuzzer.
   A crash is written under `-artifact_prefix`; replay it by passing the crash file as the sole
   corpus argument.

### Seed corpus

Committed fixtures that seed each target (the mutators start from these valid inputs):

| Target | Seeds |
|---|---|
| `circom-r1cs` | `test/.../Circom/Fixtures/{bls12_381,bn254}/poseidon2.r1cs` (+ the hand-crafted `multiplier2` bytes in `CircomR1csFixtures`, whose header sits at the front) |
| `circom-wtns` | `test/.../Circom/Fixtures/{bls12_381,bn254}/poseidon2.wtns` |
| `zkinterface-*` | `test/.../ZkInterface/Fixtures/example.zkif`, `test/.../ZkInterface/Fixtures/{bls12_381,bn254}/multiplier2.zkif` |
| `compressed-round-poly`, `raw-r1cs-witness` | no natural seed; start libFuzzer from an empty corpus |

The Longfellow circuit and curve-point decoders are internal; they are fuzzed by the
deterministic harness (harness 1) rather than this console host.

### Weekly scheduled CI

Add the workflow below as `.github/workflows/fuzz.yml` when activating. It is deliberately
`workflow_dispatch` first (never auto-runs, no surprise red runs before step 1 above is done);
flip the commented `schedule` on for the weekly cadence once a manual run is green. It mirrors
the `harden-runner` egress hardening the other Ubuntu legs use.

```yaml
name: Fuzz decoders

on:
  workflow_dispatch:
  # Enable after a green manual run:
  # schedule:
  #   - cron: "0 3 * * 1"   # 03:00 UTC every Monday

permissions:
  contents: read

jobs:
  fuzz:
    runs-on: ubuntu-latest
    timeout-minutes: 120
    strategy:
      fail-fast: false
      matrix:
        target:
          - circom-r1cs
          - circom-wtns
          - zkinterface-decoder
          - zkinterface-r1cs
          - zkinterface-wtns
          - compressed-round-poly
          - raw-r1cs-witness
    steps:
      - uses: step-security/harden-runner@v2
        with:
          egress-policy: audit   # tighten to block + an allowlist once endpoints are known
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          global-json-file: global.json
      - name: Install SharpFuzz instrumenter
        run: dotnet tool install --global SharpFuzz.CommandLine
      - name: Publish + instrument
        run: |
          dotnet publish test/Lumoin.Veridical.Fuzzing/Lumoin.Veridical.Fuzzing.csproj \
            -c Release -p:EnableSharpFuzz=true -o out/fuzz
          sharpfuzz out/fuzz/Lumoin.Veridical.Core.dll
          sharpfuzz out/fuzz/Lumoin.Veridical.Backends.Managed.dll
      - name: Seed corpus
        run: |
          mkdir -p corpus findings
          # copy the committed fixtures for ${{ matrix.target }} into corpus/ (see the table above)
      - name: Fuzz ${{ matrix.target }}
        run: |
          out/fuzz/Lumoin.Veridical.Fuzzing ${{ matrix.target }} \
            -artifact_prefix=findings/ -max_total_time=1800 corpus || true
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: fuzz-findings-${{ matrix.target }}
          path: findings/
```

## Triaging a crash

A crash is a decoder throwing an exception outside its documented rejection set, or hanging /
allocating without bound. To triage:

1. Reproduce deterministically. For a libFuzzer artifact, re-run the target with the crash file
   as the corpus. For a `DecoderRobustnessTests` failure, the assertion message carries the
   reproducing input as lowercase hex — feed it back through the same target.
2. Decide the contract. If the input is genuinely malformed, the fix is to reject it early with
   the decoder's documented exception (`ArgumentException` for the framing readers). Do **not**
   widen a target's `ExpectedRejections` to silence a crash unless the exception really is an
   intended, documented rejection signal.
3. Pin it. Add a fast regression test at the decoder's own level (see the two below), not only
   the Slow sweep, so normal CI catches a regression.

## Findings to date

The first deterministic sweep surfaced two undocumented `OverflowException` paths on hostile
input, both fixed and pinned:

- `CircomR1csReader` accepted `nWires` / `nConstraints` above `int.MaxValue` and overflowed the
  `checked (int)` cast during construction. Now rejected at header validation; pinned by
  `CircomR1csReaderTests.R1csRejectsHeaderCountAboveInt32Range`.
- The ZkInterface R1CS and witness builders allowed a variable id of exactly `int.MaxValue`,
  whose `+1` column count overflowed. Guards tightened to `>= int.MaxValue`; pinned by
  `ZkInterfaceBuilderBoundaryTests`.

The pairing-reference compressed-point decoders were separately hardened to reject off-curve and
non-canonical inputs (verified square roots) in the same wave.

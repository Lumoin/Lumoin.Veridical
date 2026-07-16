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

1. **Trust the package.** DONE — the SharpFuzz owner (`Metalnem`, owner of both `SharpFuzz` and
   `SharpFuzz.CommandLine` on nuget.org) is in the `<owners>` list in `NuGet.config`, and
   `Directory.Packages.props` pins `SharpFuzz` `2.3.0`. The default lock file omits SharpFuzz, so
   the first `EnableSharpFuzz=true` restore must regenerate it — restore with `--force-evaluate`
   (or delete `test/Lumoin.Veridical.Fuzzing/packages.lock.json` first) to avoid a locked-mode
   NU1004.
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

4. **Build the `libfuzzer-dotnet` loader.** The loader launches the instrumented .NET host and
   drives it with libFuzzer over shared memory; running the host directly only replays a corpus,
   it does not fuzz. Its source lives in its own repo (`Metalnem/libfuzzer-dotnet`, split out of
   the SharpFuzz repo — the old `sharpfuzz/master` path 404s), and `clang` supplies the libFuzzer
   runtime:

   ```
   curl -fsSL https://raw.githubusercontent.com/Metalnem/libfuzzer-dotnet/master/libfuzzer-dotnet.cc -o libfuzzer-dotnet.cc
   clang -fsanitize=fuzzer libfuzzer-dotnet.cc -o libfuzzer-dotnet
   ```

5. **Run a target.** Seed the corpus from the committed fixtures (see below), then drive the host
   through the loader — `--target_arg` carries the fuzz-target name to `Program.Main`, and the
   remaining flags plus the corpus dir go to libFuzzer:

   ```
   mkdir -p corpus/circom-r1cs findings/circom-r1cs
   cp test/Lumoin.Veridical.Tests/ConstraintSystems/Interop/Circom/Fixtures/*/poseidon2.r1cs corpus/circom-r1cs/
   ./libfuzzer-dotnet --target_path=out/fuzz/Lumoin.Veridical.Fuzzing --target_arg=circom-r1cs \
       -artifact_prefix=findings/circom-r1cs/ -max_total_time=900 corpus/circom-r1cs
   ```

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

The workflow is committed as `.github/workflows/fuzz.yml`: a weekly (Monday 03:00 UTC)
matrixed deep run over the seven targets, plus `workflow_dispatch`. It restores with
`-p:EnableSharpFuzz=true`, installs the instrumenter, publishes + instruments Core and
Backends.Managed, builds `libfuzzer-dotnet`, seeds from the committed fixtures, and runs each
target for `FUZZ_SECONDS_PER_TARGET` (30 min). A crash makes the target's leg red and uploads
the reproducing artifact. Scheduled runs fire on the default branch only, so it stays dormant
until this branch is merged.

Operational notes:

- **Run it once via `workflow_dispatch` and confirm green before trusting the schedule.** The
  SharpFuzz → `libfuzzer-dotnet` toolchain is exercised for the first time here and its exact
  loader invocation can shift between SharpFuzz versions.
- **`egress-policy` is `audit`**, not `block`, because the fuzz toolchain's endpoint set is not
  yet enumerated. After the first run, read the audit log and switch to `block` with an
  allowed-endpoints list (mirror `COMMON_ALLOWED_ENDPOINTS` in `main.yml`, plus
  `raw.githubusercontent.com:443` for the loader source).
- **No corpus persistence yet.** Each run starts from the committed seeds. Wiring `actions/cache`
  on `corpus/<target>` would let coverage compound week over week — the single biggest lever for
  a coverage-guided fuzzer's yield.
- The deterministic harness (harness 1) remains the PR-time decoder gate; this job is the
  open-ended discovery search, not a merge gate.

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

A later systematic audit (2026-07-13) of every hand-written untrusted-binary parser against the
invariant *decoded allocation and work must be bounded by input size* confirmed the parsers are
overwhelmingly safe — each sizes its allocation by the actual input length, length-derives counts
from the buffer, or parameter-gates with an exact `if(bytes.Length != expected) throw` before
allocating. It surfaced and fixed four gaps:

- `ZkInterfaceWitnessReader` sized the dense `z[1..]` vector from the header's `free_variable_id`
  (and referenced ids), a declared count decoupled from the input in the sparse case — a few dozen
  bytes could rent gigabytes. The witness builder now caps the column count at the source byte
  length — pinned by `ZkInterfaceBuilderBoundaryTests` and `ZkInterfaceWitnessReaderTests` — and, at
  intake, caps the per-witness byte accumulator at `Array.MaxLength`. That accumulator ceiling is
  reachable only by hundreds of megabytes of assignments aliasing one column, so like the
  `RelaxedR1cs` guard below it is untestable at unit scale and is not pinned by a dedicated test.
- `ZkInterfaceCursorDecoder` re-expanded aliased FlatBuffers offsets (many vector elements pointing
  at one shared table), turning an `M`-byte message into `O(M²)` decoded events. A decode-work
  budget bounds total decoded events by the source byte length; pinned by
  `ZkInterfaceCursorDecoderTests.DecoderRejectsOffsetAliasingAmplification`.
- `CircomWitnessReader` lacked the `nWitness` int-range guard its `.r1cs` sibling already had, so
  `(nWitness − 1) · scalarSize` overflowed to an undocumented `OverflowException` on a ~2 GiB input.
  Now rejected at header parse; pinned by
  `CircomWitnessReaderTests.Multiplier2WitnessRejectsNWitnessAboveAddressableRange`.
- `RelaxedR1csWitness.FromCanonical` could overflow `witnessBytes.Length + errorBytes.Length` on a
  >2 GiB combined input; now rejected with the documented `ArgumentException`.

A follow-up verification pass (2026-07-16) tightened two of these guards and closed one the first
audit missed. The two ZkInterface witness-builder ceilings above were gated on `int.MaxValue`, 56
bytes above the `Array.MaxLength` limit of the `List<byte>` / pooled `byte[]` they protect; they now
use `Array.MaxLength`, matching the `CircomWitnessReader` and `RelaxedR1csWitness` siblings, so the
accumulator can no longer leak the very `OutOfMemoryException` its contract converts. Separately,
`ZkInterfaceR1csInstanceBuilder` accumulated coefficient bytes into a `List<byte>` with no intake cap
of its own: the decode-work budget bounds the *number* of decoded terms by the source byte length,
not the 32 bytes each term accrues, and an aliased `constraints` / `variable_ids` vector amortises
one 4-byte offset element across many terms — so an ~90 MB stream could grow one matrix's
`valueBytes` past `Array.MaxLength` and throw an undocumented `OutOfMemoryException` mid-decode. The
instance builder now carries the same per-matrix intake accumulator cap as the witness builder.

A further adversarial review pass (2026-07-16) closed two more gaps. The decode-work budget bounded
only the *event* axis: it charged one unit per decoded term but let each term hand the
canonical-scalar writer an attacker-sized coefficient span to scan, so a `constraints` vector
aliasing a few offsets onto one over-long (zero-padded) coefficient could drive `O(M²)` byte work
while the event count stayed far under budget — an asymmetric-CPU amplification through the R1CS
instance reader. The budget now also charges the coefficient bytes each term and assignment scans, so
a re-read aliased coefficient exhausts it; pinned by
`ZkInterfaceCursorDecoderTests.DecoderRejectsCoefficientScanAmplification`. Separately,
`R1csMatrix.ComputeBufferSize` multiplied the non-zero count by the per-triple byte width in `Int32`,
which wraps negative for a non-zero count between ~53.7M and the accumulator cap's ~67.1M ceiling —
reachable from an accumulated constraint system before that cap trips — so the product is now taken
in `Int64` and a count exceeding a single addressable array is rejected with a descriptive
`ArgumentException`; pinned by
`R1csMatrixTests.ComputeBufferSizeRejectsNonzeroCountExceedingAddressableBuffer`.

The remaining int-overflow edges require multi-gigabyte inputs and already surface as
`ArgumentOutOfRangeException` — an `ArgumentException` subtype, so the documented rejection contract
holds.

# WASM deployment

This document records the WASM deployment story for the hashing
layer (`Lumoin.Veridical.Hashing`) and the scalar field-arithmetic
layer (`Lumoin.Veridical.Backends.Managed`). It's for someone
considering deploying either into a browser, a WASI runtime, or any
other WebAssembly host.

## § 1 What the codebase ships today

`Lumoin.Veridical.Hashing` includes a WebAssembly SIMD backend
(`Blake3WasmPackedSimdBackend`) alongside the existing portable
scalar, AVX2, AVX-512, and AArch64 NEON backends.
`Blake3BackendSelection.SelectBest()` picks `WasmPackedSimd` when
`System.Runtime.Intrinsics.Wasm.PackedSimd.IsSupported` is true,
which is the case under any .NET runtime hosted in a WASM
environment that supports the 128-bit SIMD proposal. On every
other host the `IsSupported` gate folds to a constant `false` at
JIT time and the WASM backend is dead-code-eliminated; the
existing AVX2/AVX-512/NEON/portable dispatch is unaffected.

The WASM backend is structurally the same as the NEON backend:
four chunks compressed in parallel via `Vector128<uint>`, the
seven-round BLAKE3 sequence run lane-wise, message-permutation
permutation between rounds. The shift-or rotation composition is
shared too — both ISAs lack a single-instruction 32-bit rotate.

`Lumoin.Veridical.Backends.Managed` likewise ships WebAssembly
SIMD scalar field backends for both wired curves
(`Bls12Curve381WasmScalarBackend`, `Bn254WasmScalarBackend`):
2-wide lane-interleaved add/subtract (and batch forms) plus the
lane-interleaved 32-bit-limb CIOS batch Montgomery multiply, the
same algorithms as the NEON backends. The dispatch facades
(`Bls12Curve381SimdScalarBackend` / `Bn254SimdScalarBackend`)
select them under `PackedSimd.IsSupported`, after AVX-512/AVX2/NEON
(mutually exclusive in practice — a WASM host has no AVX or NEON).
Their bodies are written exclusively in cross-platform `Vector128`
operations, which buys two things: under WASM each operation lowers
to its native SIMD128 instruction (notably the 32×32→64 partial
product is a plain `i64x2.mul` on always-zero high halves — simpler
than NEON's `XTN` + `UMULL` composition, since WASM has the 64-bit
lane multiply NEON lacks), and off WASM the internal counter-free
cores execute correctly on any host, so the agreement tests run the
exact arithmetic against the BigInteger reference on x64/ARM
development machines and CI unconditionally — a stronger
correctness story than the mirror-of-NEON argument the BLAKE3
backend rests on.

Production source (`src/Lumoin.Veridical.Core/` and
`src/Lumoin.Veridical.Hashing/`) compiles cleanly under
`EnableTrimAnalyzer=true` and `EnableAotAnalyzer=true` for any
target the .NET 10 SDK accepts. No `[DynamicallyAccessedMembers]`
or `[UnconditionalSuppressMessage]` is needed; the hashing layer
is reflection-free and AOT-friendly by construction.

## § 2 Why no AOT verification harness ships in-repo

WASM AOT publishing in .NET 10 requires a non-trivial external
toolchain installation: at minimum the `wasm-tools` or
`wasi-experimental` workloads, and for the actual AOT lowering
step (LLVM IR → linked WASM binary) the upstream
[wasi-sdk](https://github.com/WebAssembly/wasi-sdk/releases)
C/C++ toolchain (~625 MB installed). NativeAOT (`PublishAot=true`)
does not target any WASM RID; the available path is Mono
AOT-to-LLVM, gated by `RunAOTCompilation=true`. .NET 11 is
expected to make WASM a first-class NativeAOT target without the
external SDK dependency, at which point the verification scaffolding
in §3 becomes worth standing up as a recurring CI lane.

Until then, the existing 105 BLAKE3 canonical-vector conformance
tests run under the desktop JIT verify the hashing layer's
byte-correctness; the WASM backend's correctness is guaranteed by
the algorithm being a copy of the NEON Vector128 path (which the
existing NEON conformance tests cover) plus the JIT-time guarantee
that `Vector128.Add`/`Xor`/`ShiftLeftLogical`/`ShiftRightLogical`
have identical semantics across SIMD ISAs.

## § 3 Verification harness recipe (future direction)

When .NET 11 (or any later release) makes WASM AOT publishing a
non-friction story, the following recipe lifts straight back into
a new `Lumoin.Veridical.Hashing.Wasm.Verification` project. The
shape was prototyped, runs end-to-end on the reference machine,
and is archived here so the rediscovery cost is zero.

### § 3.1 Verification project (csproj)

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <RootNamespace>Lumoin.Veridical.Hashing.Wasm.Verification</RootNamespace>
    <!--
      .NET 10: PublishAot is not supported on any WASM RID
      (NETSDK1203). Use RunAOTCompilation=true under the
      wasi-experimental workload instead. When .NET 11 lands
      first-class NativeAOT WASM support, switch to PublishAot=true.
    -->
    <RunAOTCompilation Condition="'$(RuntimeIdentifier)' == 'wasi-wasm'">true</RunAOTCompilation>
    <WasmBuildNative Condition="'$(RuntimeIdentifier)' == 'wasi-wasm'">true</WasmBuildNative>

    <InvariantGlobalization>true</InvariantGlobalization>
    <EnableTrimAnalyzer>true</EnableTrimAnalyzer>
    <EnableAotAnalyzer>true</EnableAotAnalyzer>
    <IsPackable>false</IsPackable>
  </PropertyGroup>

  <ItemGroup>
    <ProjectReference Include="..\..\src\Lumoin.Veridical.Core\Lumoin.Veridical.Core.csproj" />
    <ProjectReference Include="..\..\src\Lumoin.Veridical.Hashing\Lumoin.Veridical.Hashing.csproj" />
  </ItemGroup>
</Project>
```

### § 3.2 Harness `Program.cs`

The harness emits canonical BLAKE3 outputs as `mode:index:hex`
lines on stdout. Input set covers every length boundary the
upstream canonical vectors define.

```csharp
using System;
using System.IO;
using System.Text;

namespace Lumoin.Veridical.Hashing.Wasm.Verification;

internal static class Program
{
    private const string CanonicalKey = "whats the Elvish word for friend";
    private const string CanonicalDeriveKeyContext =
        "BLAKE3 2019-12-27 16:29:52 test vectors context";

    private static readonly int[] HashLengths =
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 63, 64, 65, 127, 128, 129, 1023];
    private static readonly int[] KeyedHashLengths =
        [0, 1, 2, 63, 64, 1023];
    private static readonly int[] DeriveKeyLengths =
        [0, 1, 2, 63, 64, 1023];

    public static int Main(string[] args)
    {
        TextWriter writer = Console.Out;
        Span<byte> output = stackalloc byte[Lumoin.Veridical.Hashing.Blake3Hasher.DefaultOutputSizeBytes];

        for(int i = 0; i < HashLengths.Length; i++)
        {
            byte[] input = BuildCanonicalInput(HashLengths[i]);
            Lumoin.Veridical.Hashing.Blake3.Hash(input, output);
            EmitLine(writer, "hash", i, output);
        }

        byte[] key = Encoding.ASCII.GetBytes(CanonicalKey);
        for(int i = 0; i < KeyedHashLengths.Length; i++)
        {
            byte[] input = BuildCanonicalInput(KeyedHashLengths[i]);
            Lumoin.Veridical.Hashing.Blake3.HashKeyed(key, input, output);
            EmitLine(writer, "keyed_hash", i, output);
        }

        for(int i = 0; i < DeriveKeyLengths.Length; i++)
        {
            byte[] keyMaterial = BuildCanonicalInput(DeriveKeyLengths[i]);
            Lumoin.Veridical.Hashing.Blake3.DeriveKey(
                CanonicalDeriveKeyContext, keyMaterial, output);
            EmitLine(writer, "derive_key", i, output);
        }
        return 0;
    }

    private static byte[] BuildCanonicalInput(int length)
    {
        byte[] input = new byte[length];
        for(int i = 0; i < length; i++) { input[i] = (byte)(i % 251); }
        return input;
    }

    private static void EmitLine(TextWriter writer, string mode, int index, ReadOnlySpan<byte> output)
    {
        writer.Write(mode);
        writer.Write(':');
        writer.Write(index);
        writer.Write(':');
        writer.Write(Convert.ToHexStringLower(output));
        writer.Write('\n');
    }
}
```

### § 3.3 End-to-end verify shell script

```bash
#!/bin/bash
# Publish the wasi-wasm bundle, capture the JIT reference, run
# the WASM bundle under wasmtime, compare byte-for-byte.
set -euo pipefail
PROJECT=test/Lumoin.Veridical.Hashing.Wasm.Verification/Lumoin.Veridical.Hashing.Wasm.Verification.csproj
APP_BUNDLE=test/Lumoin.Veridical.Hashing.Wasm.Verification/bin/Release/net10.0/wasi-wasm/AppBundle
JIT_OUT=$(mktemp); WASM_OUT=$(mktemp)
trap 'rm -f "$JIT_OUT" "$WASM_OUT"' EXIT

dotnet publish "$PROJECT" -c Release -r wasi-wasm --verbosity quiet
dotnet run --project "$PROJECT" -c Release --no-build --verbosity quiet > "$JIT_OUT"

# DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 is required even though
# System.Globalization.Invariant=true is in the runtimeconfig --
# the Mono WASI runtime does not honor the runtimeconfig setting
# in .NET 10 and traps on load_icu_data without the env var.
(cd "$APP_BUNDLE" && wasmtime run -S http \
    --env DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 \
    --dir . dotnet.wasm Lumoin.Veridical.Hashing.Wasm.Verification) \
    > "$WASM_OUT"

cmp -s "$JIT_OUT" "$WASM_OUT"
```

### § 3.4 Reference output (28 lines, 2094 bytes)

The harness output is anchored to the upstream canonical BLAKE3
test vectors — every line's hex string is the first 32 bytes of
the corresponding canonical XOF output. Recording the full output
here lets a future verifier diff against it directly without
re-running the harness:

```
hash:0:af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
hash:1:2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213
hash:2:7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63
hash:3:e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f
hash:4:f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32
hash:5:b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2
hash:6:06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844
hash:7:3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe
hash:8:2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb
hash:9:e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b
hash:10:4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98
hash:11:de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee
hash:12:d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d
hash:13:f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef
hash:14:683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12
hash:15:10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11
keyed_hash:0:92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26
keyed_hash:1:6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b
keyed_hash:2:5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a
keyed_hash:3:bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae
keyed_hash:4:ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6
keyed_hash:5:c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e
derive_key:0:2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d
derive_key:1:b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c
derive_key:2:1f166565a7df0098ee65922d7fea425fb18b9943f19d6161e2d17939356168e6
derive_key:3:b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3
derive_key:4:a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e
derive_key:5:74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5
```

## § 4 `System.Numerics` and related primitives in use

- **`System.Numerics.BitOperations.RotateRight`** drives the
  portable scalar G function's rotations. The JIT lowers it to a
  single `ROR` on x86, the equivalent rotate on ARM64 / RISC-V,
  and the shift-or composition on WASM where no single-instruction
  32-bit rotate exists.
- **`System.Numerics.BigInteger`** is the foundation of the
  `Bls12Curve381BigIntegerScalarReference` in
  `Lumoin.Veridical.Core`. Not in the BLAKE3 path, but in scope
  for a future BBS+ WASM verification.
- **`System.Numerics.Vector<T>`** is the cross-platform SIMD type.
  The per-ISA x64/ARM backends target `Vector128`/`Vector256`/
  `Vector512` from `System.Runtime.Intrinsics` directly with
  ISA-specific intrinsics where they pay; the WASM scalar field
  backends realise the once-anticipated collapse onto pure
  cross-platform `Vector128` bodies (see § 1).
- **`System.Runtime.Intrinsics.Wasm.PackedSimd`** is the WASM
  128-bit SIMD intrinsic surface, gated on `PackedSimd.IsSupported`.
  Both the `Blake3WasmPackedSimdBackend` and the scalar field
  backends use cross-platform `Vector128` operations exclusively,
  so no PackedSimd-specific intrinsics are required today; the gate
  is the discriminator and the runtime lowering picks the right
  WASM SIMD instructions (`i64x2.mul` for the Montgomery partial
  products, `v128.bitselect` for the constant-time selects, the
  sign-flip + `i64x2.gt_s` sequence for unsigned 64-bit compares).
  PackedSimd-specific intrinsics (byte swizzles, lane shifts) would
  only matter if a future micro-optimisation needed them.

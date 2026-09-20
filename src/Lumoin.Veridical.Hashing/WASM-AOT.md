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
external SDK dependency, at which point standing up that verification
as a recurring CI lane becomes worthwhile.

Until then, the existing 105 BLAKE3 canonical-vector conformance
tests run under the desktop JIT verify the hashing layer's
byte-correctness; the WASM backend's correctness is guaranteed by
the algorithm being a copy of the NEON Vector128 path (which the
existing NEON conformance tests cover) plus the JIT-time guarantee
that `Vector128.Add`/`Xor`/`ShiftLeftLogical`/`ShiftRightLogical`
have identical semantics across SIMD ISAs.

## § 3 `System.Numerics` and related primitives in use

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

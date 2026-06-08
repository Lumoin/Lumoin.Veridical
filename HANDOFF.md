# Batch LF handoff — P-256 + Longfellow-style ZK-over-ECDSA

> **Temporary.** This file is a one-off to move work between machines, not a
> standing process. Once the batch lands and is picked up on the other machine,
> it can be deleted — the durable record is the commit history and the code.

This is a self-contained handoff so work can continue on another machine. It
carries everything that normally lives in machine-local notes — the agent
memory under `~/.claude/...` and the working notes under `tempdocs/` (which is
**gitignored**, see [§ tempdocs setup](#tempdocs-setup)) do **not** travel with
the repo. Read this file top to bottom; it is the source of truth for where the
batch is and what comes next. Update it as you make progress and push it with
the code.

Current position: **LF.4b.3 complete** (commit `e44ef46`). Next actionable step:
**LF.4b.4** (Ligero prover responses). Everything is committed and green
(20 Ligero tests). Nothing is in flight.

---

## 1. Project conventions (HONOR EXACTLY — these are not in the repo otherwise)

These are standing rules for this codebase. They override default habits.

- **.NET 10/11 only.** Don't open net8.0/net9.0 artifacts. `dotnet test` needs
  `--project <csproj>`.
- **Commands: NO `cd` prefix.** The working directory is already the repo root;
  a `cd …;`/`cd … &&` prefix defeats the prefix-anchored permission allowlist
  (`dotnet*`/`git*`/`grep*`) and causes prompts. Run commands directly.
- **Test invocation:** `dotnet test --project test/Lumoin.Veridical.Tests/Lumoin.Veridical.Tests.csproj --filter "FullyQualifiedName~Commitments.Ligero"`.
  Run it in the **background** (≈30–60 s; poll the log / await the notification).
  Never pipe `dotnet test` through `Select-String`/`Select-Object` in the Bash
  tool (forces a prompt and fails under bash).
- **Comment style:** line comments are `//Text` (NO space after `//`). XML doc
  comments keep the standard `/// ` space.
- **Layout:** curly braces on every block; blank line before `return`; blank
  line before a block's closing `}` except cascading closes / case-switch-else.
- **Pattern matching** over `switch`/`case`/`break` statements (switch
  expressions / `is` patterns).
- **No underscores in identifiers**, even in tests. When digits need separating,
  insert a real word (the codebase uses "Curve" between "Bls12" and "381").
- **Named constants** for magic numbers (sample/iteration counts, sizes, bounds)
  with a why-comment, even in tests.
- **No `new byte[]` scratch in tests** — use `stackalloc` / `SensitiveMemoryPool`
  to stay production-like. `new byte[]` is OK only for genuinely stored data.
- **Getters over fields.**
- **No analyzer dodges:** don't restructure to slip past an analyzer; use the API
  it points to (or the intent-revealing assert), or suppress with a
  `Justification`. A suppression may itself signal a real design smell (e.g.
  CA1822 ⇒ the member should be `const`). MSTEST0037 ⇒ use
  `Assert.IsGreaterThanOrEqualTo(bound, actual)` / `IsLessThanOrEqualTo(bound, actual)`
  (and `IsLessThan(upperBound, value)`), i.e. **bound first, actual second**.
- **Delegate-per-backend composability:** surface backend swap points as
  delegates; flag batching/GPU/FFT substrate spots, don't pre-design them.
- **Performance is deferred.** Keep references correctness-first; systematic perf
  (CRT-FFT encoder, batch inversion, batched Merkle paths) is its own later batch.
  Baselines are markers only.
- **Commit per sub-step** (`LF.4b.N: …`). **No `Co-Authored-By: Claude` trailer**
  on commits or PR bodies for this project. The user pushes; there are unpushed
  commits on `main`.
- **Test field oracle:** `SmallPrimeFieldScalars` (mod 2³¹−1 Mersenne, on 32-byte
  spans, `CurveParameterSet.None`) in
  `test/Lumoin.Veridical.Tests/TestInfrastructure/`. Reference scalar/field
  backends live in `src/Lumoin.Veridical.Backends.Managed`.
  `DeterministicScalarFill.FillCanonical(span, salt, reduce, curve)` for static
  test material; for a stateful per-call random use a small local
  `ScalarRandomDelegate` (see `LigeroTableauTests`).
- **Python is `py`** on the original box (bare `python` is the Store stub).

---

## 2. Batch goal

Bring **Longfellow-style ZK over ECDSA mdoc credentials** into Veridical, and
make **P-256 a first-class curve** so Verifiable can consume this library (its
SECDSA sits on it). Longfellow = sumcheck + **Ligero over P-256**, non-NTT
Reed–Solomon, transparent, Fiat–Shamir. Paper: "Anonymous Credentials from
ECDSA" (Frigo & Shelat, eprint 2024/2010); Ligero core follows eprint 2022/1608.

**Scope decisions already made (by the user):**
- Ligero ships as a **GENERAL reusable argument** — it implements the
  `PolynomialCommitmentProvider` seam and drops into Spartan like Hyrax/BaseFold.
  (Longfellow then consumes it.)
- Correctness-first **O(n²) barycentric** RS encoder now; CRT-FFT perf is a
  deferred seam behind the encoder delegate.
- End-to-end first over a **small prime field**, then over the **P-256 scalar
  field** (Fp256).

**Hard constraint that shapes everything:** `Scalar.SizeBytes` is a `const = 32`,
hard-assumed by ~82 sites and by the G1 scalar-mul/MSM delegate contracts. P-256
was a drop-in **only** because it is 32-byte. P-384 (48 B) and P-521 (66 B) are
**not** drop-ins — curve-broadening to them is STASHED. Do not try to widen
`Scalar.SizeBytes`.

---

## 3. Status — what is DONE

All committed on `main`, all green.

| Step | Commit | What |
|------|--------|------|
| LF.1 | `b0f8e05` | P-256 scalar field `Fn` (`P256BigIntegerScalarReference`) + `WellKnownCurves.GetScalarFieldOrder`. NOT added to `ThrowIfCurveNotWired` (that guard = full Spartan/Hyrax/BaseFold support; P-256 is for ECDSA+Longfellow). |
| LF.2 | `2481bb4` | P-256 base field `Fp` + G1 (`P256BigIntegerG1Reference`), short-Weierstrass a=−3, SEC1 compressed (33 B). `WellKnownCurves` wires sizes/generator/identity. No hash-to-curve. |
| LF.3a | `5dcde75` | `P256EcdsaReference` sign/verify, gated bidirectionally vs `System.Security.Cryptography.ECDsa` over nistP256. Hash stays caller-side; caller supplies nonce `k`. |
| LF.3b | `7da8290`, `8706f99` | mdoc-shaped POCO + swappable span-based `CanonicalCredentialSerializer` + mint/verify + tamper test. Public mdoc model deliberately kept test-side until LF.5. |
| LF.4 (research) | — | Design note (was `tempdocs/LF4-ligero-design.md`, gitignored). **Its load-bearing content is inlined in [§5](#5-the-ligero-lf4b-protocol-spec) below.** |
| LF.4a | `f0c999f` | `Algebraic/BarycentricInterpolation` + `Commitments/Ligero/LigeroReedSolomonEncoder` (systematic non-NTT RS). Gated vs a BigInteger Horner oracle over the small field AND Fp256. |
| LF.4b.1 | `74c59f5` | `Commitments/Ligero/LigeroParameters` (tableau layout + validation). |
| LF.4b.2 | `ab5e3ca` | `LigeroQuadraticConstraint` + `LigeroTableau` (`Build` + `CommitColumns` + `GetColumn`/`GetRowSpan` + `Dispose`). |
| LF.4b.3 | `e44ef46` | `WellKnownLigeroDomainLabels` + `WellKnownLigeroTranscriptLabels` + `FiatShamirTranscriptLigeroExtensions` (challenge-scalar vectors + bias-free distinct column-index sampler). |

### Files in play

Production (`src/Lumoin.Veridical.Core/`):
- `Algebraic/BarycentricInterpolation.cs`
- `Commitments/Ligero/LigeroReedSolomonEncoder.cs`
- `Commitments/Ligero/LigeroParameters.cs`
- `Commitments/Ligero/LigeroQuadraticConstraint.cs`
- `Commitments/Ligero/LigeroTableau.cs`
- `Commitments/Ligero/WellKnownLigeroDomainLabels.cs`
- `Commitments/Ligero/WellKnownLigeroTranscriptLabels.cs`
- `Commitments/Ligero/FiatShamirTranscriptLigeroExtensions.cs`

P-256 reference backends (`src/Lumoin.Veridical.Backends.Managed/`):
- `P256BigIntegerScalarReference.cs`, `P256BigIntegerG1Reference.cs`,
  `P256EcdsaReference.cs`

Tests (`test/Lumoin.Veridical.Tests/Commitments/Ligero/`):
- `LigeroReedSolomonEncoderTests.cs`, `LigeroParametersTests.cs`,
  `LigeroTableauTests.cs`, `FiatShamirTranscriptLigeroTests.cs`
- Test infra: `TestInfrastructure/SmallPrimeFieldScalars.cs`;
  `Spartan/DeterministicScalarRandom.cs` (BLS/BN254 only — for the small field
  write a local deterministic `ScalarRandomDelegate`, as `LigeroTableauTests` does).

---

## 4. Reusable API surface already available

You do not need to build hashing, Merkle, transcript, or field primitives — they
exist and are wired. Key signatures:

**RS encoder** (`LigeroReedSolomonEncoder`, static): systematic — copies the
message prefix, interpolates the extension.
```
Encode(ReadOnlySpan<byte> message, int messageLength,
       Span<byte> codeword, int codewordLength,
       ScalarAddDelegate add, ScalarSubtractDelegate subtract,
       ScalarMultiplyDelegate multiply, ScalarInvertDelegate invert,
       CurveParameterSet curve, SensitiveMemoryPool<byte> pool)
```

**Barycentric interpolation** (`BarycentricInterpolation`, static), the verifier
needs `EvaluateAtPoints` for `interpolate_req_columns`:
```
ComputeConsecutiveNodeWeights(int nodeCount, Span<byte> weights, subtract, multiply, invert, curve, pool)
EvaluateAtConsecutivePoints(values, weights, nodeCount, firstPoint, pointCount, results, add, sub, mul, inv, curve, pool)
EvaluateAtPoints(values, weights, nodeCount, ReadOnlySpan<int> points, results, add, sub, mul, inv, curve, pool)
```
All buffers are canonical layout: `length · 32` bytes, one big-endian field
element per 32-byte slot. Points/nodes must be small integers below the field
order; evaluation points must be ≥ `nodeCount` (never coincide with a node) — for
the verifier the points are `dblock + idx[·]`, always ≥ `dblock` ≥ `block`.

**`LigeroParameters`** — from `(witnessCount nw, quadraticConstraintCount nq,
inverseRate, openedColumnCount nreq, block)` with `block ≥ 2·nreq`, derives:
`RandomCount r = nreq`, `WitnessPerRow w = block − r`,
`DoubleBlock dblock = 2·block − 1`, `BlockExtension blockExt = rateinv·block`,
`BlockEncoded blockEnc = dblock + blockExt = (2+rateinv)·block − 1`,
`WitnessRowCount nwrow = ceil(nw/w)`, `QuadraticTripleCount nqtriples = ceil(nq/w)`,
`WitnessQuadraticRowCount nwqrow = nwrow + 3·nqtriples`, `RowCount = nwqrow + 3`.
Row indices: `LowDegreeRowIndex=0`, `DotRowIndex=1`, `QuadraticRowIndex=2`,
`FirstWitnessRowIndex=3` are **`const`** (reference them as
`LigeroParameters.FirstWitnessRowIndex`, not `parameters.…`).
`FirstQuadraticRowIndex`/`FirstQuadraticXRowIndex`/`…YRowIndex`/`…ZRowIndex` are
**instance** properties.

**`LigeroTableau`** (disposable; clears witness+blinding bytes on dispose):
```
static LigeroTableau Build(LigeroParameters, ReadOnlySpan<byte> witnesses,
    ReadOnlySpan<LigeroQuadraticConstraint> quadraticConstraints,
    ScalarRandomDelegate random, add, subtract, multiply, invert,
    CurveParameterSet curve, SensitiveMemoryPool<byte> pool)
MerkleTree CommitColumns(FiatShamirHashDelegate columnHash, string hashAlgorithm,
    MerkleHashDelegate merkleHash, SensitiveMemoryPool<byte> pool)   //leaves = blockExt columns [dblock,blockEnc), padded to next pow2
void GetColumn(int columnIndex, Span<byte> destination)             //gathers RowCount scalars (one per row)
internal ReadOnlySpan<byte> GetRowSpan(int rowIndex)               //whole blockEnc row — for the response combiners
```

**Transcript** (`FiatShamirTranscript` + `FiatShamirTranscriptLigeroExtensions`):
```
FiatShamirTranscript.Initialise(FiatShamirDomainLabel, ReadOnlySpan<byte> seed, string hashFunction, FiatShamirHashDelegate hash, pool)
transcript.AbsorbBytes(FiatShamirOperationLabel, ReadOnlySpan<byte>, hash)              //generic absorb
transcript.AbsorbLigeroTableauRoot(MerkleRoot, hash)
transcript.SqueezeLigeroChallengeScalars(FiatShamirOperationLabel label, int count, Span<byte> dest /*count·32*/, squeeze, hash, ScalarReduceDelegate reduce, curve, pool)
transcript.SqueezeLigeroDistinctColumnIndices(int extensionWidth, int count, Span<int> dest, squeeze, hash)
```
Labels are pinned in `WellKnownLigeroTranscriptLabels`: `TableauRoot`,
`LowDegreeChallenge` (`u_ldt`), `LinearChallenge` (`αl`),
`QuadraticConstraintChallenge` (`αq`), `QuadraticRowChallenge` (`u_quad`),
`ColumnIndex`. Domain label: `WellKnownLigeroDomainLabels.LigeroV1`.

**Merkle** (`Commitments/BaseFold/`): `MerkleTree.Build(leaves, leafCount /*pow2*/, MerkleHashDelegate hash, pool)`;
`tree.BuildPath(leafIndex, pool)` → `MerkleAuthenticationPath`;
`path.Verify(MerkleRoot root, int leafIndex, ReadOnlySpan<byte> leafBytes, MerkleHashDelegate hash)`.
`MerkleRoot.FromBytes(span, pool)`.

**Hash backends** (`src/Lumoin.Veridical.Backends.Managed/Blake3FiatShamirBackend`):
`GetHash()` → `FiatShamirHashDelegate`, `GetSqueeze()` → `FiatShamirSqueezeDelegate`.
The column-leaf one-shot bytes→32 hash is `Lumoin.Veridical.Hashing.Blake3.Hash(input, output)`
(32-byte output ⇒ fixed hash). The 2-to-1 `MerkleHashDelegate` is
`Blake3.Hash(left‖right, output)` — see the `HashTwoToOne` helpers in the tests.
`WellKnownHashAlgorithms.Blake3` is the algorithm-name string.

---

## 5. The Ligero (LF.4b) protocol spec

This is the implementation reference for the remaining steps. It was distilled
from `google/longfellow-zk` `lib/ligero/{ligero_param,ligero_prover,ligero_verifier}.h`
(study-only — implement independently, no mechanical translation).

### Layout

Pick `block`, `rateinv`, `nreq` with `block ≥ 2·nreq`. Then `r = nreq`,
`w = block − r`, `dblock = 2·block − 1`, `blockExt = rateinv·block`,
`blockEnc = dblock + blockExt`. Rows: `nwrow = ceil(nw/w)`,
`nqtriples = ceil(nq/w)`, `nwqrow = nwrow + 3·nqtriples`, `nrow = nwqrow + 3`.
Indices `ildt=0, idot=1, iquad=2, iw=3, iq=3+nwrow`; quadratic rows are
`iqx=iq, iqy=iq+nqtriples, iqz=iqy+nqtriples`. A row's first `block` (resp.
`dblock`) entries are the message; RS-extend to `blockEnc`. Merkle leaves are the
`blockExt` columns `[dblock, blockEnc)`; `nreq` of them are opened.
**All of this layout + the tableau build + the column commitment is DONE** in
`LigeroParameters` / `LigeroTableau`.

### Row contents (DONE in `LigeroTableau.Build`)

- **ILDT**: `block` random; extend(block→blockEnc).
- **IDOT**: `dblock` random, then subtract the W-block sum from column `r` so the
  witness block `[r, r+w)` sums to 0; extend(dblock→blockEnc).
- **IQUAD**: `dblock` random but columns `[r, r+w)` zeroed; extend(dblock→blockEnc).
- **Witness rows i**: `[random r | witnesses w]` (zero-padded); extend(block→blockEnc).
- **Quadratic rows** (per triple i: rows x/y/z): `[random r | operands w]` holding
  `W[c.x]`, `W[c.y]`, `W[c.z]` for constraints `c = j + i·w`; extend(block→blockEnc).
  Prover asserts `W[z] = W[x]·W[y]`.

### Constraint matrix A — `inner_product_vector`, shape `[nwqrow, w]` (TODO, LF.4b.4)

This models the **linear** half of the constraint system and is **not built
yet** — LF.4b.4 introduces it. Clear A; for each linear term `(c, w, k)` (constraint
c, witness w, coefficient k): `A[w] += k · αl[c]`. Quadratic routing: with
`Ax = A[nwrow·w]`, `Ay = Ax + nqtriples·w`, `Az = Ay + nqtriples·w`, for each
constraint `iw = j + i·w`: `Ax[iw] += αq[iw][0]; A[x] -= αq[iw][0]` and the same
for y/z with `αq[iw][1]`, `αq[iw][2]`. (`A[witnessIndex]` lives in the first
`nwrow·w` block, row-major by w.)

### Prover responses (TODO, LF.4b.4)

- `y_ldt[block] = ILDT_row[0..block) + Σ_i u_ldt[i] · row_{iw+i}[0..block)` over all
  `nwqrow` rows.
- `y_dot[dblock] = IDOT_row[0..dblock)`; for each row i:
  `Aext = [0^r | A[i,:]]` (length block), RS-extend(block→dblock);
  `y_dot += Aext ⊗ row_{iw+i}[0..dblock)` (pointwise over dblock).
- `y_quad[dblock] = IQUAD_row[0..dblock)`; for each triple i:
  `tmp = z_row[0..dblock) − x_row ⊗ y_row`; `y_quad += u_quad[i] · tmp`.
  Assert the W-block of `y_quad` is 0; transmit `y_quad_0 = y_quad[0..r)` and
  `y_quad_2 = y_quad[block..dblock)` (middle `w` omitted, = 0).
- `req[nrow][nreq]` = gather columns `dblock + idx[j]` of every row
  (`LigeroTableau.GetColumn`). Merkle-open those columns
  (`tree.BuildPath(idx[j], pool)`).

### Verifier checks (TODO, LF.4b.5) — replay challenges, then:

- **merkle_check**: recompute each opened column's leaf hash from `req[:,j]`
  (the column-hash one-shot), verify the path (`path.Verify`).
- **low_degree_check**: `yc[nreq] = req[ildt,:] + Σ_i u_ldt[i] · req[iw+i,:]`;
  `yp =` interpolate `y_ldt` (nodeCount=block) to the opened positions
  `dblock + idx`; assert `yc == yp`.
- **dot_check**: `yc = req[idot,:]`; for each row i: `Aext = [0^r | A[i,:]]`
  extend(block→blockEnc), gather its opened columns `Areq`,
  `yc += Areq ⊗ req[iw+i,:]`; `yp =` interpolate `y_dot` (nodeCount=dblock) to the
  opened positions; assert `yc == yp`. **Plus the value check:**
  `Σ_c b[c]·αl[c] == Σ_{j∈[r,block)} y_dot[j]` (`dot(b, αl) == dot1(y_dot[r..block))`,
  where `b` is the per-linear-constraint target vector).
- **quadratic_check**:
  `yc = req[iquad,:] + Σ_i u_quad[i] · (req[iqz+i,:] − req[iqx+i,:] ⊗ req[iqy+i,:])`;
  rebuild `y_quad = [y_quad_0 | 0^w | y_quad_2]`; `yp =` interpolate (nodeCount=dblock)
  to the opened positions; assert `yc == yp`.

`interpolate_req_columns(ylen, y)` = `BarycentricInterpolation.EvaluateAtPoints(y,
weights(ylen), ylen, points = dblock+idx[·], …)`.

Challenge order (the schedule labels in `WellKnownLigeroTranscriptLabels`):
absorb the tableau root, squeeze `u_ldt[nwqrow]`, `αl[nl]`, `αq[nq][3]`,
`u_quad[nqtriples]`, then the `nreq` distinct column indices in `[0, blockExt)`.
Each prover response is absorbed before the challenge that depends on it.

---

## 6. What to do next

Build order — each gated green before the next:

1. **LF.4b.4 — prover responses.** Add the linear-constraint model (a
   `LigeroLinearConstraint` term `(constraintIndex, witnessIndex, coefficient)` and
   the `b` target vector) and build the **A matrix** (§5). Then produce `y_ldt`,
   `y_dot`, `y_quad` (+ `y_quad_0`/`y_quad_2`) and the opened-column `req` +
   Merkle paths. Package into a `LigeroProof`-style carrier. Use `GetRowSpan` for
   the row combinations and `GetColumn` for `req`. Gate the prover-side arithmetic
   over the small field against hand-built vectors.
2. **LF.4b.5 — verifier checks.** merkle_check, low_degree_check, dot_check (+ the
   dot **value** check `Σ b·αl == Σ y_dot[r..block)` — easy to forget), and
   quadratic_check, per §5. The verifier replays the exact challenge schedule.
3. **LF.4b.6 — end-to-end gate.** Honest proof verifies; then a tampered witness /
   a flipped constraint / a corrupted opened column ⇒ rejects. Small field
   (`SmallPrimeFieldScalars`, `CurveParameterSet.None`) first, then the **P-256
   scalar field** (`P256BigIntegerScalarReference`). Pin the soundness params
   (`rateinv`, `nreq`) as NAMED CONSTS with a why-comment (interleaved-RS
   proximity error ≈ `(1−δ)^nreq` plus the RS/affine-line terms; `δ` from the
   chosen rate; target a stated bit-security level).
4. **Wrap as a `PolynomialCommitmentProvider`** (general reusable — the user's
   decision), in `Commitments/Ligero/`. Mirror how Hyrax/BaseFold expose the seam
   so Ligero drops into Spartan.
5. **LF.4c** — the sumcheck→Ligero constraint-extraction seam (simulate the
   sumcheck verifier to derive the linear+quadratic constraints on
   (witness ‖ pad) Ligero proves). May fold into LF.5.
6. **LF.5** — the ECDSA-verification circuit + the end-to-end age-threshold ZK
   proof from a dummy mdoc.

---

## 7. Gotchas / findings (learned the hard way)

- **`WellKnownAlgebraicTags.ScalarFor` supports ONLY BLS12-381 and BN254** — not
  `None` (small field), not P-256. `LigeroTableau.Build` keeps the random bytes
  verbatim and discards the random delegate's returned tag, so the inbound tag is
  ceremonial: it passes **`Tag.Empty`** to stay curve-agnostic. Do the same in any
  new prover code over the small field or P-256.
- **`blockExt` is NOT generally a power of two** (`= rateinv·block`). BaseFold's
  `SqueezeBaseFoldQueryIndex` masks low bits and only works for pow2 domains;
  Ligero's `SqueezeLigeroDistinctColumnIndices` instead uses **bias-free rejection**
  (a `UInt128` acceptance limit) + dedup re-squeeze. Don't "simplify" it to a mask.
- **Encode-in-place aliasing is safe**: `LigeroTableau` passes a row's own prefix as
  the `Encode` message and the whole row as the codeword. `Encode`'s systematic
  copy is then an identity copy of that region (safe), and the extension write is
  disjoint from the message read.
- **MerkleTree.Build requires a pow2 leaf count.** `CommitColumns` pads the
  `blockExt` leaves up to the next power of two with zero leaves; sampled indices
  only ever fall in `[0, blockExt)`, so padding leaves are never opened.
- **`const` vs instance row indices** on `LigeroParameters` (see §4) — a compile
  error (`CS0176`) if you reference a `const` through an instance.
- **`Build` rents-then-fills inside a `try/catch`** so an unsatisfied-constraint
  throw clears and returns the pooled buffer rather than leaking it. Keep that
  discipline in new pooled prover code (this repo had a SensitiveMemory
  finalizer/use-after-free incident; lifetimes matter).

---

## 8. Build & test

```
dotnet build src/Lumoin.Veridical.Core/Lumoin.Veridical.Core.csproj
dotnet test  --project test/Lumoin.Veridical.Tests/Lumoin.Veridical.Tests.csproj --filter "FullyQualifiedName~Commitments.Ligero"
```
20 Ligero tests should pass. Run the test command in the background; it takes
≈30–60 s including the build.

---

## tempdocs setup

`tempdocs/` is **gitignored** (`.gitignore` line 373), so nothing in it travels
with the repo. Two things normally live there on the original machine:

1. **The original design note + resume notes** (`tempdocs/LF4-ligero-design.md`,
   `tempdocs/LF4b-RESUME.md`). Their load-bearing content is already inlined in
   this HANDOFF (§5 is the full protocol spec), so you do **not** need to recreate
   them. If you want a scratch space, just create `tempdocs/` locally
   (`mkdir tempdocs` — it will not be committed).

2. **The Longfellow reference (study-only, optional)** — only needed to
   disambiguate the spec in §5; the implementation is independent (no mechanical
   translation, per the project rule). To fetch it on a new machine:
   ```
   git clone https://github.com/google/longfellow-zk tempdocs/longfellow-zk-reference
   ```
   Relevant files: `lib/ligero/{ligero_param,ligero_prover,ligero_verifier}.h`,
   `lib/algebra/{reed_solomon,crt_convolution}.h` (the latter two are the CRT-FFT
   *perf* realization of the same RS map — our encoder is the correctness-first
   barycentric O(n²) equivalent; do not port the FFT path now). Apache-2.0.

Keep this HANDOFF.md updated as you complete LF.4b.4 → LF.5 and push it with the
code.

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Engines;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using Lumoin.Veridical.Tests.Algebraic;
using System;

namespace Lumoin.Veridical.Benchmarks.Scalar;

/// <summary>
/// Per-batch-size throughput of the lane-interleaved batch <see cref="ScalarBatchMultiplyDelegate"/>
/// across the BLS12-381 scalar field, the BN254 scalar field, and the P-256 base field Fp256, with a
/// serial baseline, the library's own dispatch selection, and the AVX-512 and AVX2 per-ISA kernels
/// measured side by side. <c>ScalarBatchAddBenchmarks</c> measures only batch add/subtract for
/// BLS12-381 and the BN254 scalar benchmarks measure only the BigInteger reference; this class is the
/// batch-multiply counterpart and the only one that puts the per-ISA kernels next to the dispatch
/// facade and next to each other.
/// </summary>
/// <remarks>
/// <para>
/// Rows are grouped into three <see cref="BenchmarkCategoryAttribute"/> categories, one per field,
/// rendered as separate tables by <see cref="BenchmarkLogicalGroupRule.ByCategory"/>. Every category
/// carries the same four rows: a Baseline (a serial comparison with no lane parallelism), a dispatch
/// row (the delegate a caller gets by asking the library for "the batch multiply", with no ISA named),
/// and two forced rows, "AVX-512" and "AVX2", that call one specific per-ISA kernel directly regardless
/// of which one dispatch would have picked.
/// </para>
/// <para>
/// For BLS12-381 and BN254 the Baseline is the BigInteger reference's own batch-multiply delegate and
/// the dispatch row is <see cref="Bls12Curve381SimdScalarBackend.GetBatchMultiply"/> /
/// <see cref="Bn254SimdScalarBackend.GetBatchMultiply"/>, which already degrade to a serial loop on a
/// host with neither AVX-512 nor AVX2 rather than throwing. P-256 base-field arithmetic has no
/// dispatch facade class in the library (only the two per-ISA batch backends and the scalar Montgomery
/// backend), so the Baseline is a serial loop over
/// <see cref="P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery"/> and the dispatch row is assembled
/// in <see cref="Setup"/> by the same AVX-512-then-AVX2 order the two curve facades use internally,
/// falling back to that same serial loop when neither ISA is present.
/// </para>
/// <para>
/// A forced row never throws on a host that lacks its ISA: <see cref="Setup"/> resolves it to the
/// dispatch delegate instead, and its <see cref="BenchmarkAttribute.Description"/> says so. On a host
/// without AVX-512, the "AVX-512" row in every category is therefore identical to that category's
/// dispatch row and its numbers should be read as a duplicate, not as an AVX-512 measurement; the same
/// holds for "AVX2" on a host without AVX2. The AVX-512-versus-AVX2 comparison this class exists to
/// support is only meaningful read on a host that has both.
/// </para>
/// <para>
/// Operands are canonical, reduced, deterministically seeded scalars: for the two curves,
/// <see cref="Bls12Curve381BigIntegerScalarReference.GetReduce"/> and
/// <see cref="Bn254BigIntegerScalarReference.GetReduce"/> fold random 64-byte input down to a value
/// below the field order. For P-256, <see cref="P256BaseFieldReference.GetReduce"/> folds the same
/// width of random input down to a value below the base-field prime; the batch kernels under test treat
/// their inputs as Montgomery residues, but a residue is just another 32-byte value below the modulus,
/// so a canonical reduced value is a valid Montgomery-domain residue as far as the arithmetic these
/// kernels perform — and therefore the timing — is concerned. This class does not check that the
/// products it computes are correct; that is the job of the backend agreement tests, not a throughput
/// benchmark.
/// </para>
/// <para>
/// <see cref="BatchSize"/> sweeps the same four sizes for the same reason as
/// <c>ScalarBatchAddBenchmarks.BatchSize</c>: 16 exercises a few SIMD pairs/quartets/octets plus a
/// serial tail, 64 fills a few hundred bytes of cache, 256 crosses one cache line per scalar, and 1024
/// is the rough size of a prover sub-phase batch. Every operand buffer is sized once for the largest
/// swept size in <see cref="Setup"/>, and every timed body only slices into it.
/// </para>
/// <para>
/// <see cref="CryptographicOperationCounters"/> are disabled in <see cref="Setup"/> so timing reflects
/// pure arithmetic, matching every other benchmark in this namespace. No timed body allocates: operand
/// and result buffers are prepared once in <see cref="Setup"/>, and every row is a delegate invocation
/// over a pre-sliced span.
/// </para>
/// <para>
/// This class is the throughput instrument for two comparisons: reading a batch kernel's row before
/// and after a change to how it interleaves lanes, on the same host, gated per affected backend; and
/// reading the "AVX-512" row against the "AVX2" row within a category on a host that has both, to see
/// whether the wider lane count actually pays for itself once the tail handling and register pressure
/// of that kernel are accounted for. Neither comparison is asserted by this class; it only produces the
/// numbers to read.
/// </para>
/// </remarks>
[Config(typeof(Config))]
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput)]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
public class ScalarBatchMultiplyBenchmarks
{
    /// <summary>
    /// BenchmarkDotNet config that raises the build timeout, the same reason and value as
    /// <c>Gf2kBatchMultiplyBenchmarks.Config</c>: the solution's cold build exceeds BenchmarkDotNet's
    /// default two-minute timeout, and ten minutes covers the first-run compile without affecting the
    /// cached builds that follow it.
    /// </summary>
    private sealed class Config : ManualConfig
    {
        /// <summary>Sets <see cref="ManualConfig.BuildTimeout"/> to ten minutes.</summary>
        public Config() => BuildTimeout = TimeSpan.FromMinutes(10);
    }


    /// <summary>The canonical byte width of one field element in every category here: 256 bits, big-endian.</summary>
    private const int ScalarBytes = 32;

    /// <summary>
    /// Width of the raw random input handed to a <see cref="ScalarReduceDelegate"/>: double the
    /// canonical width, the same wide-input size <c>ScalarBatchAddBenchmarks</c> and
    /// <c>ScalarMultiplyInvertBenchmarks</c> reduce through, wide enough for every reduce delegate used
    /// here to fold down to its field's canonical range.
    /// </summary>
    private const int RawReduceInputBytes = 2 * ScalarBytes;

    /// <summary>Seed of the BLS12-381 operand stream, so successive runs measure the same inputs.</summary>
    private const int BenchmarkSeed = 0x5EED5EED;

    /// <summary>Added to <see cref="BenchmarkSeed"/> for the BN254 operand stream, so the three categories draw from distinct pseudorandom sequences.</summary>
    private const int Bn254SeedOffset = 1;

    /// <summary>Added to <see cref="BenchmarkSeed"/> for the P-256 operand stream, for the same reason as <see cref="Bn254SeedOffset"/>.</summary>
    private const int P256SeedOffset = 2;

    /// <summary>
    /// The largest size <see cref="BatchSize"/> sweeps. Every operand and result buffer is allocated
    /// once at this size in <see cref="Setup"/>, and each <see cref="BatchSize"/> iteration takes a
    /// slice rather than reallocating.
    /// </summary>
    private const int MaxBatchSize = 1024;

    /// <summary><see cref="BenchmarkCategoryAttribute"/> name for the BLS12-381 scalar-field rows.</summary>
    private const string Bls12Curve381Category = "BLS12-381";

    /// <summary><see cref="BenchmarkCategoryAttribute"/> name for the BN254 scalar-field rows.</summary>
    private const string Bn254Category = "BN254";

    /// <summary><see cref="BenchmarkCategoryAttribute"/> name for the P-256 base-field Fp256 rows.</summary>
    private const string P256Category = "P-256 base field";


    /// <summary>The BLS12-381 curve identity passed to every BLS12-381 row's delegate.</summary>
    private static CurveParameterSet Bls { get; } = CurveParameterSet.Bls12Curve381;

    /// <summary>The BN254 curve identity passed to every BN254 row's delegate.</summary>
    private static CurveParameterSet Bn { get; } = CurveParameterSet.Bn254;

    /// <summary>
    /// The curve identity passed to every P-256 base-field row's delegate. Base-field arithmetic is
    /// not curve-routed, so every P-256 backend used here ignores this argument; <see cref="CurveParameterSet.None"/>
    /// matches how the backends themselves are called elsewhere.
    /// </summary>
    private static CurveParameterSet P256Curve { get; } = CurveParameterSet.None;


    /// <summary>
    /// Batch sizes the benchmark sweeps, the same rationale as <c>ScalarBatchAddBenchmarks.BatchSize</c>:
    /// 16 exercises a few SIMD pairs/quartets/octets plus a serial tail, 64 fills a few hundred bytes of
    /// cache, 256 crosses one cache line per scalar, 1024 is the rough size of a prover sub-phase batch.
    /// </summary>
    [Params(16, 64, 256, 1024)]
    public int BatchSize { get; set; }


    /// <summary>Left operands of the BLS12-381 rows: <see cref="MaxBatchSize"/> reduced scalars concatenated.</summary>
    private byte[] blsABatch = null!;

    /// <summary>Right operands of the BLS12-381 rows, laid out like <see cref="blsABatch"/>.</summary>
    private byte[] blsBBatch = null!;

    /// <summary>Result buffer of the BLS12-381 rows, sized like <see cref="blsABatch"/>.</summary>
    private byte[] blsResultBatch = null!;

    /// <summary>Left operands of the BN254 rows: <see cref="MaxBatchSize"/> reduced scalars concatenated.</summary>
    private byte[] bnABatch = null!;

    /// <summary>Right operands of the BN254 rows, laid out like <see cref="bnABatch"/>.</summary>
    private byte[] bnBBatch = null!;

    /// <summary>Result buffer of the BN254 rows, sized like <see cref="bnABatch"/>.</summary>
    private byte[] bnResultBatch = null!;

    /// <summary>Left operands of the P-256 base-field rows: <see cref="MaxBatchSize"/> reduced field elements concatenated.</summary>
    private byte[] p256ABatch = null!;

    /// <summary>Right operands of the P-256 base-field rows, laid out like <see cref="p256ABatch"/>.</summary>
    private byte[] p256BBatch = null!;

    /// <summary>Result buffer of the P-256 base-field rows, sized like <see cref="p256ABatch"/>.</summary>
    private byte[] p256ResultBatch = null!;


    /// <summary>The BigInteger reference's batch-multiply delegate: the BLS12-381 category's Baseline row.</summary>
    private ScalarBatchMultiplyDelegate blsBaselineBatchMultiply = null!;

    /// <summary>The dispatch facade's batch-multiply delegate: the BLS12-381 category's dispatch row.</summary>
    private ScalarBatchMultiplyDelegate blsDispatchBatchMultiply = null!;

    /// <summary>
    /// The AVX-512 backend's batch-multiply delegate when <see cref="Bls12Curve381Avx512ScalarBackend.IsSupported"/>,
    /// else <see cref="blsDispatchBatchMultiply"/> (see the class remarks on reading a duplicated row).
    /// </summary>
    private ScalarBatchMultiplyDelegate blsAvx512BatchMultiply = null!;

    /// <summary>
    /// The AVX2 backend's batch-multiply delegate when <see cref="Bls12Curve381Avx2ScalarBackend.IsSupported"/>,
    /// else <see cref="blsDispatchBatchMultiply"/>.
    /// </summary>
    private ScalarBatchMultiplyDelegate blsAvx2BatchMultiply = null!;

    /// <summary>The BigInteger reference's batch-multiply delegate: the BN254 category's Baseline row.</summary>
    private ScalarBatchMultiplyDelegate bnBaselineBatchMultiply = null!;

    /// <summary>The dispatch facade's batch-multiply delegate: the BN254 category's dispatch row.</summary>
    private ScalarBatchMultiplyDelegate bnDispatchBatchMultiply = null!;

    /// <summary>
    /// The AVX-512 backend's batch-multiply delegate when <see cref="Bn254Avx512ScalarBackend.IsSupported"/>,
    /// else <see cref="bnDispatchBatchMultiply"/>.
    /// </summary>
    private ScalarBatchMultiplyDelegate bnAvx512BatchMultiply = null!;

    /// <summary>
    /// The AVX2 backend's batch-multiply delegate when <see cref="Bn254Avx2ScalarBackend.IsSupported"/>,
    /// else <see cref="bnDispatchBatchMultiply"/>.
    /// </summary>
    private ScalarBatchMultiplyDelegate bnAvx2BatchMultiply = null!;

    /// <summary>
    /// The single-element Montgomery-domain multiply <see cref="P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery"/>
    /// returns, looped by <see cref="P256SerialBatchMultiply"/> to form the P-256 category's Baseline row
    /// and the ultimate fallback of <see cref="p256DispatchBatchMultiply"/>.
    /// </summary>
    private ScalarMultiplyDelegate p256SerialMultiplyMontgomery = null!;

    /// <summary>
    /// The P-256 category's dispatch row: assembled in <see cref="Setup"/> by trying
    /// <see cref="P256BaseFieldMontgomeryBatchBackendAvx512"/>, then <see cref="P256BaseFieldMontgomeryBatchBackendAvx2"/>,
    /// then <see cref="P256SerialBatchMultiply"/> — the same order the curve dispatch facades use, assembled
    /// by hand because no dispatch facade class exists for the P-256 base field.
    /// </summary>
    private ScalarBatchMultiplyDelegate p256DispatchBatchMultiply = null!;

    /// <summary>
    /// The AVX-512 batch backend's Montgomery-domain multiply delegate when
    /// <see cref="P256BaseFieldMontgomeryBatchBackendAvx512.IsSupported"/>, else <see cref="p256DispatchBatchMultiply"/>.
    /// </summary>
    private ScalarBatchMultiplyDelegate p256Avx512BatchMultiply = null!;

    /// <summary>
    /// The AVX2 batch backend's Montgomery-domain multiply delegate when
    /// <see cref="P256BaseFieldMontgomeryBatchBackendAvx2.IsSupported"/>, else <see cref="p256DispatchBatchMultiply"/>.
    /// </summary>
    private ScalarBatchMultiplyDelegate p256Avx2BatchMultiply = null!;


    /// <summary>
    /// Disables the cryptographic operation counters, then resolves every row's delegate and fills
    /// every operand buffer for all three categories.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;

        SetupBls();
        SetupBn254();
        SetupP256();
    }


    /// <summary>Resolves the BLS12-381 rows' delegates and fills the BLS12-381 operand buffers.</summary>
    private void SetupBls()
    {
        blsBaselineBatchMultiply = Bls12Curve381BigIntegerScalarReference.GetBatchMultiply();
        blsDispatchBatchMultiply = Bls12Curve381SimdScalarBackend.GetBatchMultiply();
        blsAvx512BatchMultiply = Bls12Curve381Avx512ScalarBackend.IsSupported
            ? Bls12Curve381Avx512ScalarBackend.GetBatchMultiply()
            : blsDispatchBatchMultiply;
        blsAvx2BatchMultiply = Bls12Curve381Avx2ScalarBackend.IsSupported
            ? Bls12Curve381Avx2ScalarBackend.GetBatchMultiply()
            : blsDispatchBatchMultiply;

        blsABatch = new byte[MaxBatchSize * ScalarBytes];
        blsBBatch = new byte[MaxBatchSize * ScalarBytes];
        blsResultBatch = new byte[MaxBatchSize * ScalarBytes];

        ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
        FillReducedOperands(reduce, Bls, BenchmarkSeed, blsABatch, blsBBatch);
    }


    /// <summary>Resolves the BN254 rows' delegates and fills the BN254 operand buffers.</summary>
    private void SetupBn254()
    {
        bnBaselineBatchMultiply = Bn254BigIntegerScalarReference.GetBatchMultiply();
        bnDispatchBatchMultiply = Bn254SimdScalarBackend.GetBatchMultiply();
        bnAvx512BatchMultiply = Bn254Avx512ScalarBackend.IsSupported
            ? Bn254Avx512ScalarBackend.GetBatchMultiply()
            : bnDispatchBatchMultiply;
        bnAvx2BatchMultiply = Bn254Avx2ScalarBackend.IsSupported
            ? Bn254Avx2ScalarBackend.GetBatchMultiply()
            : bnDispatchBatchMultiply;

        bnABatch = new byte[MaxBatchSize * ScalarBytes];
        bnBBatch = new byte[MaxBatchSize * ScalarBytes];
        bnResultBatch = new byte[MaxBatchSize * ScalarBytes];

        ScalarReduceDelegate reduce = Bn254BigIntegerScalarReference.GetReduce();
        FillReducedOperands(reduce, Bn, BenchmarkSeed + Bn254SeedOffset, bnABatch, bnBBatch);
    }


    /// <summary>
    /// Resolves the P-256 base-field rows' delegates — assembling the dispatch row by hand in
    /// AVX-512-then-AVX2-then-serial order, since no dispatch facade class exists for this field — and
    /// fills the P-256 operand buffers.
    /// </summary>
    private void SetupP256()
    {
        p256SerialMultiplyMontgomery = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();

        bool avx512Supported = P256BaseFieldMontgomeryBatchBackendAvx512.IsSupported;
        bool avx2Supported = P256BaseFieldMontgomeryBatchBackendAvx2.IsSupported;

        p256DispatchBatchMultiply = (avx512Supported, avx2Supported) switch
        {
            (true, _) => P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery(),
            (false, true) => P256BaseFieldMontgomeryBatchBackendAvx2.GetBatchMultiplyMontgomery(),
            _ => P256SerialBatchMultiply
        };

        p256Avx512BatchMultiply = avx512Supported
            ? P256BaseFieldMontgomeryBatchBackendAvx512.GetBatchMultiplyMontgomery()
            : p256DispatchBatchMultiply;
        p256Avx2BatchMultiply = avx2Supported
            ? P256BaseFieldMontgomeryBatchBackendAvx2.GetBatchMultiplyMontgomery()
            : p256DispatchBatchMultiply;

        p256ABatch = new byte[MaxBatchSize * ScalarBytes];
        p256BBatch = new byte[MaxBatchSize * ScalarBytes];
        p256ResultBatch = new byte[MaxBatchSize * ScalarBytes];

        ScalarReduceDelegate reduce = P256BaseFieldReference.GetReduce();
        FillReducedOperands(reduce, P256Curve, BenchmarkSeed + P256SeedOffset, p256ABatch, p256BBatch);
    }


    /// <summary>
    /// Fills <paramref name="aBatch"/> and <paramref name="bBatch"/> with <see cref="MaxBatchSize"/>
    /// reduced field elements each, drawn from a <see cref="Random"/> seeded with <paramref name="seed"/>
    /// through <paramref name="reduce"/>, so successive runs measure the same deterministic inputs.
    /// </summary>
    private static void FillReducedOperands(ScalarReduceDelegate reduce, CurveParameterSet curve, int seed, Span<byte> aBatch, Span<byte> bBatch)
    {
        Random rng = new(seed);
        Span<byte> raw = stackalloc byte[RawReduceInputBytes];
        for(int i = 0; i < MaxBatchSize; i++)
        {
            int offset = i * ScalarBytes;
            rng.NextBytes(raw);
            reduce(raw, aBatch.Slice(offset, ScalarBytes), curve);
            rng.NextBytes(raw);
            reduce(raw, bBatch.Slice(offset, ScalarBytes), curve);
        }
    }


    /// <summary>Invokes <paramref name="batchMultiply"/> over the first <see cref="BatchSize"/> elements of the given buffers.</summary>
    private void RunBatchMultiply(ScalarBatchMultiplyDelegate batchMultiply, byte[] aBatch, byte[] bBatch, byte[] resultBatch, CurveParameterSet curve)
    {
        int total = BatchSize * ScalarBytes;
        batchMultiply(aBatch.AsSpan(0, total), bBatch.AsSpan(0, total), resultBatch.AsSpan(0, total), BatchSize, curve);
    }


    /// <summary>
    /// Loops <see cref="p256SerialMultiplyMontgomery"/> over <paramref name="count"/> pairs: the P-256
    /// category's serial Montgomery-domain comparison, and the ultimate fallback of
    /// <see cref="p256DispatchBatchMultiply"/> on a host with neither AVX-512 nor AVX2.
    /// </summary>
    private void P256SerialBatchMultiply(
        ReadOnlySpan<byte> leftOperandsConcatenated,
        ReadOnlySpan<byte> rightOperandsConcatenated,
        Span<byte> resultsConcatenated,
        int count,
        CurveParameterSet curve)
    {
        for(int i = 0; i < count; i++)
        {
            int offset = i * ScalarBytes;
            p256SerialMultiplyMontgomery(
                leftOperandsConcatenated.Slice(offset, ScalarBytes),
                rightOperandsConcatenated.Slice(offset, ScalarBytes),
                resultsConcatenated.Slice(offset, ScalarBytes),
                curve);
        }
    }


    /// <summary>Benchmarks the BigInteger reference's batch multiply over the BLS12-381 scalar field.</summary>
    [BenchmarkCategory(Bls12Curve381Category)]
    [Benchmark(Baseline = true, Description = "BigInteger BatchMultiply")]
    public void BlsBaseline() => RunBatchMultiply(blsBaselineBatchMultiply, blsABatch, blsBBatch, blsResultBatch, Bls);

    /// <summary>Benchmarks the dispatch facade's batch multiply over the BLS12-381 scalar field.</summary>
    [BenchmarkCategory(Bls12Curve381Category)]
    [Benchmark(Description = "SIMD BatchMultiply (dispatch)")]
    public void BlsDispatch() => RunBatchMultiply(blsDispatchBatchMultiply, blsABatch, blsBBatch, blsResultBatch, Bls);

    /// <summary>Benchmarks the AVX-512 backend's batch multiply over the BLS12-381 scalar field directly.</summary>
    [BenchmarkCategory(Bls12Curve381Category)]
    [Benchmark(Description = "AVX-512 (falls back to dispatch where unsupported)")]
    public void BlsAvx512() => RunBatchMultiply(blsAvx512BatchMultiply, blsABatch, blsBBatch, blsResultBatch, Bls);

    /// <summary>Benchmarks the AVX2 backend's batch multiply over the BLS12-381 scalar field directly.</summary>
    [BenchmarkCategory(Bls12Curve381Category)]
    [Benchmark(Description = "AVX2 (falls back to dispatch where unsupported)")]
    public void BlsAvx2() => RunBatchMultiply(blsAvx2BatchMultiply, blsABatch, blsBBatch, blsResultBatch, Bls);


    /// <summary>Benchmarks the BigInteger reference's batch multiply over the BN254 scalar field.</summary>
    [BenchmarkCategory(Bn254Category)]
    [Benchmark(Baseline = true, Description = "BigInteger BatchMultiply")]
    public void Bn254Baseline() => RunBatchMultiply(bnBaselineBatchMultiply, bnABatch, bnBBatch, bnResultBatch, Bn);

    /// <summary>Benchmarks the dispatch facade's batch multiply over the BN254 scalar field.</summary>
    [BenchmarkCategory(Bn254Category)]
    [Benchmark(Description = "SIMD BatchMultiply (dispatch)")]
    public void Bn254Dispatch() => RunBatchMultiply(bnDispatchBatchMultiply, bnABatch, bnBBatch, bnResultBatch, Bn);

    /// <summary>Benchmarks the AVX-512 backend's batch multiply over the BN254 scalar field directly.</summary>
    [BenchmarkCategory(Bn254Category)]
    [Benchmark(Description = "AVX-512 (falls back to dispatch where unsupported)")]
    public void Bn254Avx512() => RunBatchMultiply(bnAvx512BatchMultiply, bnABatch, bnBBatch, bnResultBatch, Bn);

    /// <summary>Benchmarks the AVX2 backend's batch multiply over the BN254 scalar field directly.</summary>
    [BenchmarkCategory(Bn254Category)]
    [Benchmark(Description = "AVX2 (falls back to dispatch where unsupported)")]
    public void Bn254Avx2() => RunBatchMultiply(bnAvx2BatchMultiply, bnABatch, bnBBatch, bnResultBatch, Bn);


    /// <summary>Benchmarks the serial Montgomery-domain multiply loop over the P-256 base field.</summary>
    [BenchmarkCategory(P256Category)]
    [Benchmark(Baseline = true, Description = "Serial Montgomery multiply loop")]
    public void P256Baseline()
    {
        int total = BatchSize * ScalarBytes;
        P256SerialBatchMultiply(p256ABatch.AsSpan(0, total), p256BBatch.AsSpan(0, total), p256ResultBatch.AsSpan(0, total), BatchSize, P256Curve);
    }

    /// <summary>Benchmarks the assembled dispatch delegate's batch multiply over the P-256 base field.</summary>
    [BenchmarkCategory(P256Category)]
    [Benchmark(Description = "SIMD BatchMultiply (dispatch)")]
    public void P256Dispatch() => RunBatchMultiply(p256DispatchBatchMultiply, p256ABatch, p256BBatch, p256ResultBatch, P256Curve);

    /// <summary>Benchmarks the AVX-512 batch backend's Montgomery-domain multiply over the P-256 base field directly.</summary>
    [BenchmarkCategory(P256Category)]
    [Benchmark(Description = "AVX-512 (falls back to dispatch where unsupported)")]
    public void P256Avx512() => RunBatchMultiply(p256Avx512BatchMultiply, p256ABatch, p256BBatch, p256ResultBatch, P256Curve);

    /// <summary>Benchmarks the AVX2 batch backend's Montgomery-domain multiply over the P-256 base field directly.</summary>
    [BenchmarkCategory(P256Category)]
    [Benchmark(Description = "AVX2 (falls back to dispatch where unsupported)")]
    public void P256Avx2() => RunBatchMultiply(p256Avx2BatchMultiply, p256ABatch, p256BBatch, p256ResultBatch, P256Curve);
}

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using Lumoin.Veridical.Tests.Algebraic;
using System;

namespace Lumoin.Veridical.Benchmarks.Scalar;

/// <summary>
/// Per-call timing of single-element scalar multiplication and inversion across the
/// scalar backends, for both curves, with BigInteger as the baseline.
/// </summary>
/// <remarks>
/// <para>
/// The Simd_* methods route through the dispatch facade, so on this host they
/// exercise the highest-capability backend (AVX-512 &gt; AVX2 &gt; NEON). The serial
/// CIOS Montgomery multiply and the Fermat inversion ladder are ISA-independent, so
/// these rows measure the scalar limb arithmetic rather than lane parallelism —
/// the value here is the head-to-head against the BigInteger reference, which informs
/// whether routing protocol code through SIMD is a win per operation. The measured
/// answer (recorded when the SIMD scalar foundation landed) is yes on both: the single-element multiply
/// is ~0.65x and the invert ~0.5x of the reference, both allocation-free — the
/// Montgomery-domain ladder of zero-alloc CIOS multiplies beats the allocating,
/// canonical-domain
/// <see cref="System.Numerics.BigInteger.ModPow(System.Numerics.BigInteger, System.Numerics.BigInteger, System.Numerics.BigInteger)"/>
/// despite the naive 256-step exponent handling.
/// </para>
/// <para>
/// Counters are disabled in <see cref="Setup"/> so timing reflects pure arithmetic.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput)]
public class ScalarMultiplyInvertBenchmarks
{
    private const int ScalarBytes = 32;
    private const int BenchmarkSeed = 0x5EED5EED;
    private static readonly CurveParameterSet Bls = CurveParameterSet.Bls12Curve381;
    private static readonly CurveParameterSet Bn = CurveParameterSet.Bn254;


    private byte[] blsA = null!;
    private byte[] blsB = null!;
    private byte[] bnA = null!;
    private byte[] bnB = null!;
    private byte[] resultBytes = null!;

    private ScalarMultiplyDelegate blsBigIntegerMultiply = null!;
    private ScalarMultiplyDelegate blsSimdMultiply = null!;
    private ScalarInvertDelegate blsBigIntegerInvert = null!;
    private ScalarInvertDelegate blsSimdInvert = null!;

    private ScalarMultiplyDelegate bnBigIntegerMultiply = null!;
    private ScalarMultiplyDelegate bnSimdMultiply = null!;
    private ScalarInvertDelegate bnBigIntegerInvert = null!;
    private ScalarInvertDelegate bnSimdInvert = null!;


    [GlobalSetup]
    public void Setup()
    {
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;

        blsBigIntegerMultiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
        blsBigIntegerInvert = Bls12Curve381BigIntegerScalarReference.GetInvert();
        bnBigIntegerMultiply = Bn254BigIntegerScalarReference.GetMultiply();
        bnBigIntegerInvert = Bn254BigIntegerScalarReference.GetInvert();

        //Route SIMD through the dispatch facade; fall back to BigInteger on hosts
        //with no SIMD support so the Simd_* rows degenerate rather than throw.
        if(Bls12Curve381SimdScalarBackend.IsSupported)
        {
            blsSimdMultiply = Bls12Curve381SimdScalarBackend.GetMultiply();
            blsSimdInvert = Bls12Curve381SimdScalarBackend.GetInvert();
        }
        else
        {
            blsSimdMultiply = blsBigIntegerMultiply;
            blsSimdInvert = blsBigIntegerInvert;
        }

        if(Bn254SimdScalarBackend.IsSupported)
        {
            bnSimdMultiply = Bn254SimdScalarBackend.GetMultiply();
            bnSimdInvert = Bn254SimdScalarBackend.GetInvert();
        }
        else
        {
            bnSimdMultiply = bnBigIntegerMultiply;
            bnSimdInvert = bnBigIntegerInvert;
        }

        resultBytes = new byte[ScalarBytes];
        blsA = ReducedScalar(Bls12Curve381BigIntegerScalarReference.GetReduce(), Bls, 1);
        blsB = ReducedScalar(Bls12Curve381BigIntegerScalarReference.GetReduce(), Bls, 2);
        bnA = ReducedScalar(Bn254BigIntegerScalarReference.GetReduce(), Bn, 3);
        bnB = ReducedScalar(Bn254BigIntegerScalarReference.GetReduce(), Bn, 4);
    }


    private static byte[] ReducedScalar(ScalarReduceDelegate reduce, CurveParameterSet curve, int salt)
    {
        byte[] result = new byte[ScalarBytes];
        Random rng = new(BenchmarkSeed + salt);
        Span<byte> raw = stackalloc byte[64];
        rng.NextBytes(raw);
        reduce(raw, result, curve);

        return result;
    }


    [Benchmark(Baseline = true, Description = "BLS BigInteger Multiply")]
    public void BlsBigIntegerMultiply() => blsBigIntegerMultiply(blsA, blsB, resultBytes, Bls);

    [Benchmark(Description = "BLS SIMD Multiply")]
    public void BlsSimdMultiply() => blsSimdMultiply(blsA, blsB, resultBytes, Bls);

    [Benchmark(Description = "BLS BigInteger Invert")]
    public void BlsBigIntegerInvert() => blsBigIntegerInvert(blsA, resultBytes, Bls);

    [Benchmark(Description = "BLS SIMD Invert")]
    public void BlsSimdInvert() => blsSimdInvert(blsA, resultBytes, Bls);

    [Benchmark(Description = "BN254 BigInteger Multiply")]
    public void BnBigIntegerMultiply() => bnBigIntegerMultiply(bnA, bnB, resultBytes, Bn);

    [Benchmark(Description = "BN254 SIMD Multiply")]
    public void BnSimdMultiply() => bnSimdMultiply(bnA, bnB, resultBytes, Bn);

    [Benchmark(Description = "BN254 BigInteger Invert")]
    public void BnBigIntegerInvert() => bnBigIntegerInvert(bnA, resultBytes, Bn);

    [Benchmark(Description = "BN254 SIMD Invert")]
    public void BnSimdInvert() => bnSimdInvert(bnA, resultBytes, Bn);
}

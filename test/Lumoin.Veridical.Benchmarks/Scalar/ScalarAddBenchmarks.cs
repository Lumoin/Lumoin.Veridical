using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using Lumoin.Veridical.Tests.Algebraic;
using System;

namespace Lumoin.Veridical.Benchmarks.Scalar;

/// <summary>
/// Per-call timing of single-element <see cref="ScalarAddDelegate"/> and
/// <see cref="ScalarSubtractDelegate"/> across the available scalar
/// backends. BigInteger is the baseline.
/// </summary>
/// <remarks>
/// <para>
/// The Simd_* methods route through <see cref="Bls12Curve381SimdScalarBackend"/>'s
/// dispatch facade, so on AVX2 hosts they exercise the 4-wide AVX2
/// scalar path (which for single ops is mostly the limb-arithmetic plus
/// one <see cref="System.Runtime.Intrinsics.X86.Avx2.BlendVariable(System.Runtime.Intrinsics.Vector256{byte}, System.Runtime.Intrinsics.Vector256{byte}, System.Runtime.Intrinsics.Vector256{byte})"/>)
/// and on AArch64 hosts the 2-wide NEON path. Hosts without SIMD support
/// fall back to the BigInteger path; the comparison is then trivially
/// 1:1.
/// </para>
/// <para>
/// Operation counters are explicitly disabled in <see cref="Setup"/> so
/// the benchmark measures pure arithmetic and not the (small but real)
/// cost of the counter bump.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput)]
public class ScalarAddBenchmarks
{
    private const int ScalarBytes = 32;
    private const int BenchmarkSeed = 0x5EED5EED;
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    private byte[] aBytes = null!;
    private byte[] bBytes = null!;
    private byte[] resultBytes = null!;

    private ScalarAddDelegate bigIntegerAdd = null!;
    private ScalarSubtractDelegate bigIntegerSubtract = null!;
    private ScalarAddDelegate simdAdd = null!;
    private ScalarSubtractDelegate simdSubtract = null!;


    /// <summary>Resolves the BigInteger and SIMD add/subtract delegates and prepares two reduced scalars.</summary>
    [GlobalSetup]
    public void Setup()
    {
        //Keep counters off during benchmarking so the timing reflects pure
        //arithmetic. The branch on IsCountingEnabled is essentially free, but
        //leaving them on would still add a measurable Counter.Add path when
        //OTel listeners are attached in some hosting environments.
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;

        bigIntegerAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
        bigIntegerSubtract = Bls12Curve381BigIntegerScalarReference.GetSubtract();
        ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

        //Route SIMD through the dispatch facade so the per-ISA pick is made
        //once at setup. On hosts with no SIMD support we fall back to the
        //BigInteger delegates, which makes the Simd_* benchmark rows degenerate
        //to a measurement of the BigInteger path — accurate but not interesting.
        if(Bls12Curve381SimdScalarBackend.IsSupported)
        {
            simdAdd = Bls12Curve381SimdScalarBackend.GetAdd();
            simdSubtract = Bls12Curve381SimdScalarBackend.GetSubtract();
        }
        else
        {
            simdAdd = bigIntegerAdd;
            simdSubtract = bigIntegerSubtract;
        }

        //Generate two reduced scalars deterministically so successive benchmark
        //runs measure the same input distribution.
        aBytes = new byte[ScalarBytes];
        bBytes = new byte[ScalarBytes];
        resultBytes = new byte[ScalarBytes];

        Random rng = new(BenchmarkSeed);
        Span<byte> raw = stackalloc byte[64];
        rng.NextBytes(raw);
        reduce(raw, aBytes, Curve);
        rng.NextBytes(raw);
        reduce(raw, bBytes, Curve);
    }


    /// <summary>Benchmarks BigInteger addition over the BLS12-381 scalar field.</summary>
    [Benchmark(Baseline = true, Description = "BigInteger Add")]
    public void BigIntegerAdd()
    {
        bigIntegerAdd(aBytes, bBytes, resultBytes, Curve);
    }


    /// <summary>Benchmarks SIMD addition over the BLS12-381 scalar field via the dispatch facade.</summary>
    [Benchmark(Description = "SIMD Add (AVX2 or NEON via dispatch)")]
    public void SimdAdd()
    {
        simdAdd(aBytes, bBytes, resultBytes, Curve);
    }


    /// <summary>Benchmarks BigInteger subtraction over the BLS12-381 scalar field.</summary>
    [Benchmark(Description = "BigInteger Subtract")]
    public void BigIntegerSubtract()
    {
        bigIntegerSubtract(aBytes, bBytes, resultBytes, Curve);
    }


    /// <summary>Benchmarks SIMD subtraction over the BLS12-381 scalar field via the dispatch facade.</summary>
    [Benchmark(Description = "SIMD Subtract")]
    public void SimdSubtract()
    {
        simdSubtract(aBytes, bBytes, resultBytes, Curve);
    }
}
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using Lumoin.Veridical.Tests.Algebraic;
using System;

namespace Lumoin.Veridical.Benchmarks.Bn254;

/// <summary>
/// Per-call timing of the BN254 scalar-field primitives on the BigInteger
/// reference backend — the only BN254 scalar backend in the codebase. This is a
/// correctness-first <em>baseline marker</em>: BN254 has no SIMD backend yet
/// (unlike BLS12-381's experimental AVX-512/NEON scalar backends in the test
/// project), so there is nothing to compare against here. The rows record where
/// BN254 field arithmetic stands before any acceleration work, so a future SIMD
/// effort has a reference point and a regression gate.
/// </summary>
/// <remarks>
/// Operation counters are disabled in <see cref="Setup"/> so the timing reflects
/// pure arithmetic, matching the BLS12-381 scalar benchmarks' methodology.
/// </remarks>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput)]
public class Bn254ScalarBenchmarks
{
    private const int ScalarBytes = 32;
    private const int BenchmarkSeed = 0x5EED5EED;
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bn254;


    private byte[] aBytes = null!;
    private byte[] bBytes = null!;
    private byte[] resultBytes = null!;

    private ScalarAddDelegate add = null!;
    private ScalarSubtractDelegate subtract = null!;
    private ScalarMultiplyDelegate multiply = null!;
    private ScalarInvertDelegate invert = null!;


    /// <summary>Resolves the BN254 BigInteger scalar op delegates and prepares two reduced operands.</summary>
    [GlobalSetup]
    public void Setup()
    {
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;

        add = Bn254BigIntegerScalarReference.GetAdd();
        subtract = Bn254BigIntegerScalarReference.GetSubtract();
        multiply = Bn254BigIntegerScalarReference.GetMultiply();
        invert = Bn254BigIntegerScalarReference.GetInvert();
        ScalarReduceDelegate reduce = Bn254BigIntegerScalarReference.GetReduce();

        //Two reduced scalars derived deterministically so successive runs measure
        //the same input distribution. A reduced random value is non-zero with
        //overwhelming probability, so it is a valid inversion input.
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


    /// <summary>Benchmarks BigInteger addition over the BN254 scalar field.</summary>
    [Benchmark(Baseline = true, Description = "BN254 BigInteger Add")]
    public void Add254()
    {
        add(aBytes, bBytes, resultBytes, Curve);
    }


    /// <summary>Benchmarks BigInteger subtraction over the BN254 scalar field.</summary>
    [Benchmark(Description = "BN254 BigInteger Subtract")]
    public void Subtract254()
    {
        subtract(aBytes, bBytes, resultBytes, Curve);
    }


    /// <summary>Benchmarks BigInteger multiplication over the BN254 scalar field.</summary>
    [Benchmark(Description = "BN254 BigInteger Multiply")]
    public void Multiply254()
    {
        multiply(aBytes, bBytes, resultBytes, Curve);
    }


    /// <summary>Benchmarks BigInteger inversion over the BN254 scalar field.</summary>
    [Benchmark(Description = "BN254 BigInteger Invert")]
    public void Invert254()
    {
        invert(aBytes, resultBytes, Curve);
    }
}

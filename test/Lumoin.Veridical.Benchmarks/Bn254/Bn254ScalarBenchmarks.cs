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
/// reference backend. This class measures the reference backend alone; the
/// SIMD comparison for BN254 lives in
/// <see cref="Lumoin.Veridical.Benchmarks.Scalar.ScalarMultiplyInvertBenchmarks"/>,
/// which times <see cref="Bn254SimdScalarBackend"/>, the dispatch facade over
/// the per-ISA AVX-512, AVX2, NEON and WebAssembly backends in
/// <c>Lumoin.Veridical.Backends.Managed</c>, for multiply and invert against
/// this same reference. The rows here are that comparison's fixed point: the
/// reference-backend timing every BN254 SIMD row in this namespace is read
/// against.
/// </summary>
/// <remarks>
/// Operation counters are disabled in <see cref="Setup"/> so the timing reflects
/// pure arithmetic, matching the BLS12-381 scalar benchmarks' methodology.
/// </remarks>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput)]
public class Bn254ScalarBenchmarks
{
    /// <summary>The byte width of one BN254 scalar.</summary>
    private const int ScalarBytes = 32;

    /// <summary>The fixed seed for the benchmark's pseudo-random operand generator, so successive runs measure the same input distribution.</summary>
    private const int BenchmarkSeed = 0x5EED5EED;

    /// <summary>The BN254 curve tag every delegate call in this benchmark routes over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bn254;


    /// <summary>The first reduced scalar operand, prepared once in <see cref="Setup"/>.</summary>
    private byte[] aBytes = null!;

    /// <summary>The second reduced scalar operand, prepared once in <see cref="Setup"/>.</summary>
    private byte[] bBytes = null!;

    /// <summary>The scratch buffer every benchmarked operation writes its result into.</summary>
    private byte[] resultBytes = null!;

    /// <summary>The BN254 BigInteger scalar addition delegate under benchmark.</summary>
    private ScalarAddDelegate add = null!;

    /// <summary>The BN254 BigInteger scalar subtraction delegate under benchmark.</summary>
    private ScalarSubtractDelegate subtract = null!;

    /// <summary>The BN254 BigInteger scalar multiplication delegate under benchmark.</summary>
    private ScalarMultiplyDelegate multiply = null!;

    /// <summary>The BN254 BigInteger scalar inversion delegate under benchmark.</summary>
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

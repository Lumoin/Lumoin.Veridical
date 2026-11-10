using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using Lumoin.Veridical.Tests.Algebraic;
using System;

namespace Lumoin.Veridical.Benchmarks.Algebraic;

/// <summary>
/// Per-call timing of the three P-256 base field (Fp256) arithmetic backends head
/// to head: the correctness-first <see cref="P256BaseFieldReference"/> BigInteger
/// oracle (baseline), the allocation-free CIOS <see cref="P256BaseFieldMontgomeryBackend"/>,
/// and the Solinas fast-reduction <see cref="P256BaseFieldSolinasBackend"/>. Multiply
/// and invert are the costly ops the Ligero encoder is dominated by; add/subtract are
/// included for completeness. The BigInteger multiply/invert allocate (product-then-mod,
/// 256-step ModPow), so the [MemoryDiagnoser] allocation column is part of the story.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput)]
public class Fp256FieldOpBenchmarks
{
    /// <summary>The width in bytes of one Fp256 element.</summary>
    private const int ScalarBytes = 32;
    /// <summary>The seed of the generator that draws the operands, fixed so every run measures the same inputs.</summary>
    private const int BenchmarkSeed = 0x5EED5EED;
    /// <summary>The curve tag passed to the scalar delegates; the P-256 base-field kernels do not depend on it.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.None;

    /// <summary>The left operand, a reduced field element.</summary>
    private byte[] a = null!;
    /// <summary>The right operand, a reduced field element.</summary>
    private byte[] b = null!;
    /// <summary>The destination of every operation.</summary>
    private byte[] result = null!;

    /// <summary>The BigInteger reference multiply.</summary>
    private ScalarMultiplyDelegate bigIntegerMultiply = null!;
    /// <summary>The BigInteger reference inversion.</summary>
    private ScalarInvertDelegate bigIntegerInvert = null!;
    /// <summary>The BigInteger reference addition.</summary>
    private ScalarAddDelegate bigIntegerAdd = null!;
    /// <summary>The BigInteger reference subtraction.</summary>
    private ScalarSubtractDelegate bigIntegerSubtract = null!;

    /// <summary>The Montgomery-domain multiply.</summary>
    private ScalarMultiplyDelegate montgomeryMultiply = null!;
    /// <summary>The Montgomery-domain inversion.</summary>
    private ScalarInvertDelegate montgomeryInvert = null!;
    /// <summary>The Montgomery-domain addition.</summary>
    private ScalarAddDelegate montgomeryAdd = null!;
    /// <summary>The Montgomery-domain subtraction.</summary>
    private ScalarSubtractDelegate montgomerySubtract = null!;

    /// <summary>The Solinas-reduction multiply.</summary>
    private ScalarMultiplyDelegate solinasMultiply = null!;
    /// <summary>The Solinas-reduction inversion.</summary>
    private ScalarInvertDelegate solinasInvert = null!;
    /// <summary>The Solinas-reduction addition.</summary>
    private ScalarAddDelegate solinasAdd = null!;
    /// <summary>The Solinas-reduction subtraction.</summary>
    private ScalarSubtractDelegate solinasSubtract = null!;


    /// <summary>Resolves the BigInteger, Montgomery, and Solinas Fp256 op delegates and prepares two reduced operands.</summary>
    [GlobalSetup]
    public void Setup()
    {
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;

        ScalarReduceDelegate reduce = P256BaseFieldReference.GetReduce();

        bigIntegerMultiply = P256BaseFieldReference.GetMultiply();
        bigIntegerInvert = P256BaseFieldReference.GetInvert();
        bigIntegerAdd = P256BaseFieldReference.GetAdd();
        bigIntegerSubtract = P256BaseFieldReference.GetSubtract();

        montgomeryMultiply = P256BaseFieldMontgomeryBackend.GetMultiply();
        montgomeryInvert = P256BaseFieldMontgomeryBackend.GetInvert();
        montgomeryAdd = P256BaseFieldMontgomeryBackend.GetAdd();
        montgomerySubtract = P256BaseFieldMontgomeryBackend.GetSubtract();

        solinasMultiply = P256BaseFieldSolinasBackend.GetMultiply();
        solinasInvert = P256BaseFieldSolinasBackend.GetInvert();
        solinasAdd = P256BaseFieldSolinasBackend.GetAdd();
        solinasSubtract = P256BaseFieldSolinasBackend.GetSubtract();

        result = new byte[ScalarBytes];
        a = ReducedScalar(reduce, 1);
        b = ReducedScalar(reduce, 2);
    }


    /// <summary>Draws a wide random value from a generator seeded by the salt and reduces it into a canonical field element.</summary>
    private static byte[] ReducedScalar(ScalarReduceDelegate reduce, int salt)
    {
        byte[] value = new byte[ScalarBytes];
        Span<byte> raw = stackalloc byte[64];
        new Random(BenchmarkSeed + salt).NextBytes(raw);
        reduce(raw, value, Curve);

        return value;
    }


    /// <summary>Benchmarks BigInteger multiplication over the P-256 base field.</summary>
    [Benchmark(Baseline = true, Description = "Multiply: BigInteger")]
    public void BigIntegerMultiply() => bigIntegerMultiply(a, b, result, Curve);

    /// <summary>Benchmarks Montgomery-domain multiplication over the P-256 base field.</summary>
    [Benchmark(Description = "Multiply: Montgomery")]
    public void MontgomeryMultiply() => montgomeryMultiply(a, b, result, Curve);

    /// <summary>Benchmarks Solinas fast-reduction multiplication over the P-256 base field.</summary>
    [Benchmark(Description = "Multiply: Solinas")]
    public void SolinasMultiply() => solinasMultiply(a, b, result, Curve);

    /// <summary>Benchmarks BigInteger inversion over the P-256 base field.</summary>
    [Benchmark(Description = "Invert: BigInteger")]
    public void BigIntegerInvert() => bigIntegerInvert(a, result, Curve);

    /// <summary>Benchmarks Montgomery-domain inversion over the P-256 base field.</summary>
    [Benchmark(Description = "Invert: Montgomery")]
    public void MontgomeryInvert() => montgomeryInvert(a, result, Curve);

    /// <summary>Benchmarks Solinas-backend inversion over the P-256 base field.</summary>
    [Benchmark(Description = "Invert: Solinas")]
    public void SolinasInvert() => solinasInvert(a, result, Curve);

    /// <summary>Benchmarks BigInteger addition over the P-256 base field.</summary>
    [Benchmark(Description = "Add: BigInteger")]
    public void BigIntegerAdd() => bigIntegerAdd(a, b, result, Curve);

    /// <summary>Benchmarks Montgomery-domain addition over the P-256 base field.</summary>
    [Benchmark(Description = "Add: Montgomery")]
    public void MontgomeryAdd() => montgomeryAdd(a, b, result, Curve);

    /// <summary>Benchmarks Solinas-backend addition over the P-256 base field.</summary>
    [Benchmark(Description = "Add: Solinas")]
    public void SolinasAdd() => solinasAdd(a, b, result, Curve);

    /// <summary>Benchmarks BigInteger subtraction over the P-256 base field.</summary>
    [Benchmark(Description = "Subtract: BigInteger")]
    public void BigIntegerSubtract() => bigIntegerSubtract(a, b, result, Curve);

    /// <summary>Benchmarks Montgomery-domain subtraction over the P-256 base field.</summary>
    [Benchmark(Description = "Subtract: Montgomery")]
    public void MontgomerySubtract() => montgomerySubtract(a, b, result, Curve);

    /// <summary>Benchmarks Solinas-backend subtraction over the P-256 base field.</summary>
    [Benchmark(Description = "Subtract: Solinas")]
    public void SolinasSubtract() => solinasSubtract(a, b, result, Curve);
}

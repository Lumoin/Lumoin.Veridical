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
    private const int ScalarBytes = 32;
    private const int BenchmarkSeed = 0x5EED5EED;
    private static readonly CurveParameterSet Curve = CurveParameterSet.None;

    private byte[] a = null!;
    private byte[] b = null!;
    private byte[] result = null!;

    private ScalarMultiplyDelegate bigIntegerMultiply = null!;
    private ScalarInvertDelegate bigIntegerInvert = null!;
    private ScalarAddDelegate bigIntegerAdd = null!;
    private ScalarSubtractDelegate bigIntegerSubtract = null!;

    private ScalarMultiplyDelegate montgomeryMultiply = null!;
    private ScalarInvertDelegate montgomeryInvert = null!;
    private ScalarAddDelegate montgomeryAdd = null!;
    private ScalarSubtractDelegate montgomerySubtract = null!;

    private ScalarMultiplyDelegate solinasMultiply = null!;
    private ScalarInvertDelegate solinasInvert = null!;
    private ScalarAddDelegate solinasAdd = null!;
    private ScalarSubtractDelegate solinasSubtract = null!;


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


    private static byte[] ReducedScalar(ScalarReduceDelegate reduce, int salt)
    {
        byte[] value = new byte[ScalarBytes];
        Span<byte> raw = stackalloc byte[64];
        new Random(BenchmarkSeed + salt).NextBytes(raw);
        reduce(raw, value, Curve);

        return value;
    }


    [Benchmark(Baseline = true, Description = "Multiply: BigInteger")]
    public void BigIntegerMultiply() => bigIntegerMultiply(a, b, result, Curve);

    [Benchmark(Description = "Multiply: Montgomery")]
    public void MontgomeryMultiply() => montgomeryMultiply(a, b, result, Curve);

    [Benchmark(Description = "Multiply: Solinas")]
    public void SolinasMultiply() => solinasMultiply(a, b, result, Curve);

    [Benchmark(Description = "Invert: BigInteger")]
    public void BigIntegerInvert() => bigIntegerInvert(a, result, Curve);

    [Benchmark(Description = "Invert: Montgomery")]
    public void MontgomeryInvert() => montgomeryInvert(a, result, Curve);

    [Benchmark(Description = "Invert: Solinas")]
    public void SolinasInvert() => solinasInvert(a, result, Curve);

    [Benchmark(Description = "Add: BigInteger")]
    public void BigIntegerAdd() => bigIntegerAdd(a, b, result, Curve);

    [Benchmark(Description = "Add: Montgomery")]
    public void MontgomeryAdd() => montgomeryAdd(a, b, result, Curve);

    [Benchmark(Description = "Add: Solinas")]
    public void SolinasAdd() => solinasAdd(a, b, result, Curve);

    [Benchmark(Description = "Subtract: BigInteger")]
    public void BigIntegerSubtract() => bigIntegerSubtract(a, b, result, Curve);

    [Benchmark(Description = "Subtract: Montgomery")]
    public void MontgomerySubtract() => montgomerySubtract(a, b, result, Curve);

    [Benchmark(Description = "Subtract: Solinas")]
    public void SolinasSubtract() => solinasSubtract(a, b, result, Curve);
}

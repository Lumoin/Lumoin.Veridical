using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;

namespace Lumoin.Veridical.Benchmarks.Spartan;

/// <summary>
/// The batch-multiply seam's payoff in the Spartan prover's hottest loop:
/// one relaxed outer round polynomial (twelve modular products per MLE
/// pair), per-element versus batched, BigInteger reference versus the
/// facade-routed SIMD backend. The batched/SIMD cell is the production
/// configuration the seam exists for; the batched/BigInteger cell isolates
/// the gather-and-block overhead (its batch delegate is a loop over the
/// single-element multiply, so any delta against per-element/BigInteger is
/// pure plumbing cost).
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput)]
public class SumcheckRoundPolynomialBenchmarks
{
    private const int ScalarBytes = 32;
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;

    private static readonly ScalarAddDelegate Add = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static readonly ScalarSubtractDelegate Subtract = Bls12Curve381BigIntegerScalarReference.GetSubtract();
    private static readonly ScalarMultiplyDelegate Multiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    private static readonly ScalarArithmeticBackend ReferenceBatch = TestScalarBackends.Bls12Curve381Reference;


    /// <summary>
    /// MLE variable counts: 10 is a 1k-row instance's first round, 13 an 8k-row
    /// one — the sizes where the round polynomial dominates a prove.
    /// </summary>
    [Params(10, 13)]
    public int VariableCount { get; set; }


    private byte[] az = null!;
    private byte[] bz = null!;
    private byte[] cz = null!;
    private byte[] e = null!;
    private byte[] eq = null!;
    private byte[] u = null!;
    private ScalarAddDelegate simdAdd = null!;
    private ScalarSubtractDelegate simdSubtract = null!;
    private ScalarMultiplyDelegate simdMultiply = null!;
    private ScalarArithmeticBackend simdBatch = null!;
    private BaseMemoryPool pool = null!;


    [GlobalSetup]
    public void Setup()
    {
        pool = BaseMemoryPool.Shared;
        ScalarArithmeticBackend backend = TestScalarBackends.Bls12Curve381;
        simdAdd = backend.Add;
        simdSubtract = backend.Subtract;
        simdMultiply = backend.Multiply;
        simdBatch = backend;

        int evaluationCount = 1 << VariableCount;
        az = BuildCanonicalTable(evaluationCount, 11);
        bz = BuildCanonicalTable(evaluationCount, 13);
        cz = BuildCanonicalTable(evaluationCount, 17);
        e = BuildCanonicalTable(evaluationCount, 19);
        eq = BuildCanonicalTable(evaluationCount, 23);
        u = BuildCanonicalTable(1, 29);
    }


    [Benchmark(Baseline = true)]
    public int PerElementBigInteger()
    {
        using Polynomial result = SumcheckRoundComputation.ComputeOuterRoundPolynomialRelaxed(
            az, bz, cz, e, eq, u, VariableCount, Add, Subtract, Multiply, Curve, pool);

        return result.AsReadOnlySpan().Length;
    }


    [Benchmark]
    public int BatchedBigInteger()
    {
        using Polynomial result = SumcheckRoundComputation.ComputeOuterRoundPolynomialRelaxed(
            az, bz, cz, e, eq, u, VariableCount, Add, Subtract, Multiply, Curve, pool, ReferenceBatch);

        return result.AsReadOnlySpan().Length;
    }


    [Benchmark]
    public int PerElementSimd()
    {
        using Polynomial result = SumcheckRoundComputation.ComputeOuterRoundPolynomialRelaxed(
            az, bz, cz, e, eq, u, VariableCount, simdAdd, simdSubtract, simdMultiply, Curve, pool);

        return result.AsReadOnlySpan().Length;
    }


    [Benchmark]
    public int BatchedSimd()
    {
        using Polynomial result = SumcheckRoundComputation.ComputeOuterRoundPolynomialRelaxed(
            az, bz, cz, e, eq, u, VariableCount, simdAdd, simdSubtract, simdMultiply, Curve, pool, simdBatch);

        return result.AsReadOnlySpan().Length;
    }


    private static byte[] BuildCanonicalTable(int count, int salt)
    {
        byte[] table = new byte[count * ScalarBytes];
        DeterministicScalarFill.FillCanonical(table, salt, Bls12Curve381BigIntegerScalarReference.GetReduce(), Curve);

        return table;
    }
}

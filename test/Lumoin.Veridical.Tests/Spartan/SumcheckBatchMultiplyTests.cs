using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// The batch-multiply seam's byte-identity gates: the sumcheck
/// round-polynomial computation must produce identical coefficients with the
/// per-element multiply, the BigInteger reference batch, and the
/// facade-routed SIMD batch (<see cref="TestScalarBackends"/>) — field
/// operations are exact and the accumulation is commutative, so any
/// divergence is a defect in the batched gather/block plumbing, not a
/// tolerance. Sizes cover a sub-block table, the exact block boundary, and a
/// multi-block table.
/// </summary>
[TestClass]
internal sealed class SumcheckBatchMultiplyTests
{
    private static readonly ScalarAddDelegate Add = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static readonly ScalarSubtractDelegate Subtract = Bls12Curve381BigIntegerScalarReference.GetSubtract();
    private static readonly ScalarMultiplyDelegate Multiply = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly ScalarArithmeticBackend ReferenceBatch = TestScalarBackends.Bls12Curve381Reference;
    private static readonly ScalarArithmeticBackend SimdBatch = TestScalarBackends.Bls12Curve381;

    private const int ScalarSize = 32;
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    //3 variables: 4 pairs (sub-block); 11: 1024 pairs (exactly one block);
    //12: 2048 pairs (two blocks).
    [TestMethod]
    [DataRow(3)]
    [DataRow(11)]
    [DataRow(12)]
    public void OuterRelaxedRoundPolynomialIsByteIdenticalUnderBatching(int variableCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        int evaluationCount = 1 << variableCount;
        int tableBytes = evaluationCount * ScalarSize;

        using IMemoryOwner<byte> tablesOwner = pool.Rent(5 * tableBytes);
        Span<byte> tables = tablesOwner.Memory.Span[..(5 * tableBytes)];
        FillCanonical(tables, salt: 101);
        ReadOnlySpan<byte> az = tables[..tableBytes];
        ReadOnlySpan<byte> bz = tables.Slice(tableBytes, tableBytes);
        ReadOnlySpan<byte> cz = tables.Slice(2 * tableBytes, tableBytes);
        ReadOnlySpan<byte> e = tables.Slice(3 * tableBytes, tableBytes);
        ReadOnlySpan<byte> eq = tables.Slice(4 * tableBytes, tableBytes);

        Span<byte> u = stackalloc byte[ScalarSize];
        u.Clear();
        u[^1] = 0x07;

        using Polynomial scalarPath = SumcheckRoundComputation.ComputeOuterRoundPolynomialRelaxed(
            az, bz, cz, e, eq, u, variableCount, Add, Subtract, Multiply, Curve, pool);
        using Polynomial referencePath = SumcheckRoundComputation.ComputeOuterRoundPolynomialRelaxed(
            az, bz, cz, e, eq, u, variableCount, Add, Subtract, Multiply, Curve, pool, ReferenceBatch);
        using Polynomial simdPath = SumcheckRoundComputation.ComputeOuterRoundPolynomialRelaxed(
            az, bz, cz, e, eq, u, variableCount, Add, Subtract, Multiply, Curve, pool, SimdBatch);

        Assert.IsTrue(
            scalarPath.AsReadOnlySpan().SequenceEqual(referencePath.AsReadOnlySpan()),
            $"The BigInteger batch path must be byte-identical to the per-element path at {variableCount} variables.");
        Assert.IsTrue(
            scalarPath.AsReadOnlySpan().SequenceEqual(simdPath.AsReadOnlySpan()),
            $"The SIMD batch path must be byte-identical to the per-element path at {variableCount} variables.");
    }


    [TestMethod]
    [DataRow(3)]
    [DataRow(11)]
    [DataRow(12)]
    public void InnerRoundPolynomialIsByteIdenticalUnderBatching(int variableCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        int evaluationCount = 1 << variableCount;
        int tableBytes = evaluationCount * ScalarSize;

        using IMemoryOwner<byte> tablesOwner = pool.Rent(2 * tableBytes);
        Span<byte> tables = tablesOwner.Memory.Span[..(2 * tableBytes)];
        FillCanonical(tables, salt: 211);
        ReadOnlySpan<byte> abc = tables[..tableBytes];
        ReadOnlySpan<byte> z = tables.Slice(tableBytes, tableBytes);

        using Polynomial scalarPath = SumcheckRoundComputation.ComputeInnerRoundPolynomial(
            abc, z, variableCount, Add, Subtract, Multiply, Curve, pool);
        using Polynomial referencePath = SumcheckRoundComputation.ComputeInnerRoundPolynomial(
            abc, z, variableCount, Add, Subtract, Multiply, Curve, pool, ReferenceBatch);
        using Polynomial simdPath = SumcheckRoundComputation.ComputeInnerRoundPolynomial(
            abc, z, variableCount, Add, Subtract, Multiply, Curve, pool, SimdBatch);

        Assert.IsTrue(
            scalarPath.AsReadOnlySpan().SequenceEqual(referencePath.AsReadOnlySpan()),
            $"The BigInteger batch path must be byte-identical to the per-element path at {variableCount} variables.");
        Assert.IsTrue(
            scalarPath.AsReadOnlySpan().SequenceEqual(simdPath.AsReadOnlySpan()),
            $"The SIMD batch path must be byte-identical to the per-element path at {variableCount} variables.");
    }


    private static void FillCanonical(Span<byte> destination, int salt) =>
        DeterministicScalarFill.FillCanonical(destination, salt, Reduce, Curve);
}

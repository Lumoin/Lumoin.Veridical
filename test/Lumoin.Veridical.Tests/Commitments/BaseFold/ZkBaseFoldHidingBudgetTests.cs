using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// The bounded-independence hiding budget enforcement (design doc §3.3, the
/// ZK-BF deferred follow-on): a lift provider advertising
/// <see cref="PolynomialCommitmentProvider.IsHiding"/> must refuse — loudly,
/// never silently — a commit or open whose mask degrees of freedom
/// <c>(2^t − 1)·2^d</c> cannot cover the codeword positions an opening reveals.
/// These tests pin the budget arithmetic of
/// <see cref="ZkBaseFoldPolynomialCommitmentScheme.MeetsHidingBudget"/> and
/// <see cref="ZkBaseFoldPolynomialCommitmentScheme.GetMinimumExtraVariableCount"/>
/// against hand-computed values, and assert both lift factories throw an
/// actionable <see cref="InvalidOperationException"/> on an under-budget commit.
/// </summary>
[TestClass]
internal sealed class ZkBaseFoldHidingBudgetTests
{
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate Invert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly ScalarHashToScalarDelegate HashToScalar = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static readonly ScalarRandomDelegate Random = Bls12Curve381BigIntegerScalarReference.GetRandom();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;

    private const int ScalarSize = 32;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    //A small query count keeps the hand computations below followable; the wired
    //classical-security base oracle is InverseRate·BaseDimension = 8 entries.
    private const int TestQueryCount = 12;
    private const int BaseOracleLength = 8;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    //Hand computation: DOF = (2^t − 1)·2^d versus Q* = Q·(d + t + 1) + 8.
    //d = 3, t = 4: DOF = 15·8 = 120 ≥ 12·8 + 8 = 104 → met.
    [DataRow(3, 4, true)]
    //d = 3, t = 3: DOF = 7·8 = 56 < 12·7 + 8 = 92 → unmet.
    [DataRow(3, 3, false)]
    //d = 2, t = 5: DOF = 31·4 = 124 ≥ 12·8 + 8 = 104 → met.
    [DataRow(2, 5, true)]
    //d = 2, t = 2 (the pre-enforcement toy configuration): DOF = 3·4 = 12 < 12·5 + 8 = 68 → unmet.
    [DataRow(2, 2, false)]
    //d = 1, t = 6: DOF = 63·2 = 126 ≥ 12·8 + 8 = 104 → met.
    [DataRow(1, 6, true)]
    public void MeetsHidingBudgetMatchesHandComputedValues(int variableCount, int extraVariableCount, bool expected)
    {
        Assert.AreEqual(
            expected,
            ZkBaseFoldPolynomialCommitmentScheme.MeetsHidingBudget(variableCount, extraVariableCount, Curve, TestQueryCount),
            $"Budget verdict for d = {variableCount}, t = {extraVariableCount}, Q = {TestQueryCount} must match the hand computation.");
    }


    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    public void MinimumExtraVariableCountIsTheSmallestBudgetMeetingLift(int variableCount)
    {
        int minimum = ZkBaseFoldPolynomialCommitmentScheme.GetMinimumExtraVariableCount(variableCount, Curve, TestQueryCount);

        Assert.IsTrue(
            ZkBaseFoldPolynomialCommitmentScheme.MeetsHidingBudget(variableCount, minimum, Curve, TestQueryCount),
            $"The reported minimum t = {minimum} must itself meet the budget for d = {variableCount}.");
        if(minimum > 1)
        {
            Assert.IsFalse(
                ZkBaseFoldPolynomialCommitmentScheme.MeetsHidingBudget(variableCount, minimum - 1, Curve, TestQueryCount),
                $"t = {minimum - 1} must not meet the budget for d = {variableCount}, or the minimum is not minimal.");
        }
    }


    [TestMethod]
    public void MinimumLiftAtProductionQueryCountMatchesTheDesignDocEstimate()
    {
        //Design doc §3.3: for Q ≈ 273 and small d, t ≈ 9–11 suffices. The exact
        //fixed point under the reveal bound Q·(d + t + 1) + 8 at d = 2 is t = 10:
        //DOF = 1023·4 = 4092 ≥ 273·13 + 8 = 3557, while t = 9 gives 2044 < 3284.
        const int ProductionQueryCount = 273;
        const int SmallWitnessVariableCount = 2;
        const int ExpectedMinimumLift = 10;

        Assert.AreEqual(
            ExpectedMinimumLift,
            ZkBaseFoldPolynomialCommitmentScheme.GetMinimumExtraVariableCount(SmallWitnessVariableCount, Curve, ProductionQueryCount),
            "The production-shape minimum lift must land inside the design doc's t ≈ 9–11 estimate.");
    }


    [TestMethod]
    public void UnderBudgetCommitThroughTheLiftProviderThrowsActionably()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //d = 3 at Q = 12 needs t = 4; t = 2 is under budget.
        const int VariableCount = 3;
        const int UnderBudgetLift = 2;

        using PolynomialCommitmentProvider provider = ZkBaseFoldPolynomialCommitmentScheme.CreateZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            Random, HashToScalar, UnderBudgetLift, DigestSizeBytes);

        using MultilinearExtension witness = BuildRandomMle(VariableCount, salt: 17, pool);

        InvalidOperationException thrown = Assert.ThrowsExactly<InvalidOperationException>(
            () => provider.Commit(witness, pool),
            "An under-budget commit must be refused loudly.");

        int minimum = ZkBaseFoldPolynomialCommitmentScheme.GetMinimumExtraVariableCount(VariableCount, Curve, TestQueryCount);
        Assert.Contains(
            $"is {minimum} ", thrown.Message,
            "The refusal must name the smallest sufficient lift so the caller can fix the configuration.");
    }


    [TestMethod]
    public void UnderBudgetCommitThroughTheFullZeroKnowledgeProviderThrows()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        const int VariableCount = 3;
        const int UnderBudgetLift = 2;

        using PolynomialCommitmentProvider provider = ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            Random, HashToScalar, UnderBudgetLift, DigestSizeBytes);

        using MultilinearExtension witness = BuildRandomMle(VariableCount, salt: 19, pool);

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => provider.Commit(witness, pool),
            "The full-ZK provider must enforce the same budget as the lift-only one.");
    }


    [TestMethod]
    public void RevealBoundArithmeticIsPinned()
    {
        //Pin the reveal-bound side of the budget through the public surface: at
        //d = 3, t = 4 the DOF is (2^4 − 1)·2^3 = 120 and the bound is
        //Q·(d + t + 1) + BaseOracleLength. Q = 14 gives 14·8 + 8 = 120 = DOF —
        //met exactly at the boundary — and Q = 15 gives 128 > 120 — unmet. The
        //boundary transition pins both formula terms (the per-query factor and
        //the base-oracle constant).
        const int VariableCount = 3;
        const int Lift = 4;
        const int BoundaryMetQueryCount = 14;
        const int BoundaryUnmetQueryCount = 15;

        Assert.IsTrue(
            ZkBaseFoldPolynomialCommitmentScheme.MeetsHidingBudget(VariableCount, Lift, Curve, BoundaryMetQueryCount),
            $"DOF 120 must cover exactly {BoundaryMetQueryCount}·8 + {BaseOracleLength} = 120 revealed positions.");
        Assert.IsFalse(
            ZkBaseFoldPolynomialCommitmentScheme.MeetsHidingBudget(VariableCount, Lift, Curve, BoundaryUnmetQueryCount),
            $"DOF 120 must not cover {BoundaryUnmetQueryCount}·8 + {BaseOracleLength} = 128 revealed positions.");
    }


    private static MultilinearExtension BuildRandomMle(int variableCount, int salt, BaseMemoryPool pool)
    {
        int evaluationCount = 1 << variableCount;
        using IMemoryOwner<byte> owner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> evals = owner.Memory.Span[..(evaluationCount * ScalarSize)];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < evaluationCount; i++)
        {
            wide.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 137) + (i * 19) + 1);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 11) + (i * 31) + 3);
            Reduce(wide, evals.Slice(i * ScalarSize, ScalarSize), Curve);
        }

        return MultilinearExtension.FromEvaluations(evals, variableCount, Curve, pool);
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.ZkBaseFold.HidingBudget.Test"u8;
}

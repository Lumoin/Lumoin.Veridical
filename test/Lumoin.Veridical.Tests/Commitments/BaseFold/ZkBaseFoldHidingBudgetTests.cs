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
/// The bounded-independence hiding budget enforcement: a lift provider advertising
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
    /// <summary>The BLS12-381 scalar-field addition delegate this test's commitment scheme uses.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    /// <summary>The BLS12-381 scalar-field subtraction delegate this test's commitment scheme uses.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    /// <summary>The BLS12-381 scalar-field multiplication delegate this test's commitment scheme uses.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    /// <summary>The BLS12-381 scalar-field inversion delegate this test's commitment scheme uses.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    /// <summary>The BLS12-381 scalar-field canonical-reduction delegate this test uses to build random witness evaluations.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    /// <summary>The BLS12-381 scalar-field hash-to-scalar delegate this test's zero-knowledge provider uses.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    /// <summary>The BLS12-381 scalar-field random-sampling delegate this test's zero-knowledge provider draws masking scalars from.</summary>
    private static ScalarRandomDelegate Random { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();
    /// <summary>The Fiat–Shamir hash delegate this test's transcripts use, backed by the BLAKE3 reference.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    /// <summary>The Fiat–Shamir squeeze delegate this test's transcripts use, backed by the BLAKE3 reference.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    /// <summary>The Merkle two-to-one hash delegate this test's commitment scheme uses, backed by <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The byte width of one canonical scalar this test's witness evaluations use.</summary>
    private const int ScalarSize = 32;
    /// <summary>The digest width, in bytes, this test's Merkle hashing uses.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The IOPP query count this test's hand computations use; kept small so the arithmetic stays followable.</summary>
    private const int TestQueryCount = 12;
    /// <summary>The wired classical-security base oracle's entry count, <c>InverseRate·BaseDimension = 8</c>, added to the reveal bound.</summary>
    private const int BaseOracleLength = 8;

    /// <summary>The curve this test's scalars and commitment scheme operate over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>
    /// Verifies that <see cref="ZkBaseFoldPolynomialCommitmentScheme.MeetsHidingBudget"/> matches
    /// a hand computation of the mask degrees of freedom <c>(2^t − 1)·2^d</c> against the reveal
    /// bound <c>Q·(d + t + 1) + 8</c>, across several <c>(d, t)</c> combinations.
    /// </summary>
    /// <remarks>
    /// <list type="bullet">
    ///   <item><description><c>d = 3, t = 4</c>: DOF = 15·8 = 120 ≥ 12·8 + 8 = 104 → met.</description></item>
    ///   <item><description><c>d = 3, t = 3</c>: DOF = 7·8 = 56 &lt; 12·7 + 8 = 92 → unmet.</description></item>
    ///   <item><description><c>d = 2, t = 5</c>: DOF = 31·4 = 124 ≥ 12·8 + 8 = 104 → met.</description></item>
    ///   <item><description><c>d = 2, t = 2</c> (a minimal toy configuration): DOF = 3·4 = 12 &lt; 12·5 + 8 = 68 → unmet.</description></item>
    ///   <item><description><c>d = 1, t = 6</c>: DOF = 63·2 = 126 ≥ 12·8 + 8 = 104 → met.</description></item>
    /// </list>
    /// </remarks>
    /// <param name="variableCount">The witness variable count <c>d</c>.</param>
    /// <param name="extraVariableCount">The lift's extra variable count <c>t</c>.</param>
    /// <param name="expected">Whether the budget is expected to be met for this combination.</param>
    [TestMethod]
    [DataRow(3, 4, true)]
    [DataRow(3, 3, false)]
    [DataRow(2, 5, true)]
    [DataRow(2, 2, false)]
    [DataRow(1, 6, true)]
    public void MeetsHidingBudgetMatchesHandComputedValues(int variableCount, int extraVariableCount, bool expected)
    {
        Assert.AreEqual(
            expected,
            ZkBaseFoldPolynomialCommitmentScheme.MeetsHidingBudget(variableCount, extraVariableCount, Curve, TestQueryCount),
            $"Budget verdict for d = {variableCount}, t = {extraVariableCount}, Q = {TestQueryCount} must match the hand computation.");
    }


    /// <summary>Verifies that <see cref="ZkBaseFoldPolynomialCommitmentScheme.GetMinimumExtraVariableCount"/> returns the smallest lift meeting the hiding budget: the reported minimum itself meets the budget, and one less does not.</summary>
    /// <param name="variableCount">The witness variable count to compute the minimum lift for.</param>
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


    /// <summary>Verifies that the minimum lift at a production-scale query count (273) is exactly 10, pinning the reveal-bound arithmetic at realistic scale.</summary>
    [TestMethod]
    public void MinimumLiftAtProductionQueryCountMatchesTheDesignDocEstimate()
    {
        //For Q ≈ 273 and small d, t ≈ 9–11 suffices. The exact
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


    /// <summary>Verifies that committing through the lift-only zero-knowledge provider with an under-budget lift throws an <see cref="InvalidOperationException"/> naming the smallest sufficient lift.</summary>
    [TestMethod]
    public void UnderBudgetCommitThroughTheLiftProviderThrowsActionably()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //d = 3 at Q = 12 needs t = 4; t = 2 is under budget.
        const int VariableCount = 3;
        const int UnderBudgetLift = 2;

        using PolynomialCommitmentProvider provider = ZkBaseFoldPolynomialCommitmentScheme.CreateZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            Random, HashToScalar, UnderBudgetLift, pool, DigestSizeBytes);

        using MultilinearExtension witness = BuildRandomMle(VariableCount, salt: 17, pool);

        InvalidOperationException thrown = Assert.ThrowsExactly<InvalidOperationException>(
            () => provider.Commit(witness, pool),
            "An under-budget commit must be refused loudly.");

        int minimum = ZkBaseFoldPolynomialCommitmentScheme.GetMinimumExtraVariableCount(VariableCount, Curve, TestQueryCount);
        Assert.Contains(
            $"is {minimum} ", thrown.Message,
            "The refusal must name the smallest sufficient lift so the caller can fix the configuration.");
    }


    /// <summary>Verifies that the full zero-knowledge provider enforces the same hiding-budget check as the lift-only provider, throwing on an under-budget commit.</summary>
    [TestMethod]
    public void UnderBudgetCommitThroughTheFullZeroKnowledgeProviderThrows()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        const int VariableCount = 3;
        const int UnderBudgetLift = 2;

        using PolynomialCommitmentProvider provider = ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            Random, HashToScalar, UnderBudgetLift, pool, DigestSizeBytes);

        using MultilinearExtension witness = BuildRandomMle(VariableCount, salt: 19, pool);

        _ = Assert.ThrowsExactly<InvalidOperationException>(
            () => provider.Commit(witness, pool),
            "The full-ZK provider must enforce the same budget as the lift-only one.");
    }


    /// <summary>Pins the reveal-bound arithmetic at its exact boundary: a query count landing exactly on the degrees-of-freedom limit meets the budget, and one more query does not.</summary>
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


    /// <summary>Builds a multilinear extension over deterministic pseudo-random evaluations derived from a salt, for the hiding-budget tests to commit.</summary>
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


    /// <summary>Computes the BLAKE3 two-to-one Merkle compression of two digests.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>The domain-separation seed this test derives its zero-knowledge providers from.</summary>
    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.ZkBaseFold.HidingBudget.Test"u8;
}

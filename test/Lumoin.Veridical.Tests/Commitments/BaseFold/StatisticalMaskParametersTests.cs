using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// The statistical-mask parameter policy
/// (<see cref="WellKnownStatisticalMaskParameters"/>): the
/// resolved shape must satisfy the filler ledger (enough all-ones-weighted
/// entropy to launder the weighted opening's round reveals), carry the
/// commitment's own minimum hiding lift, and be the smallest such shape — all
/// deterministically from the sumcheck shape, since prover and verifier derive
/// it independently with no wire data.
/// </summary>
[TestClass]
internal sealed class StatisticalMaskParametersTests
{
    /// <summary>The rank slack this test mirrors from <see cref="WellKnownStatisticalMaskParameters"/>: the weighted opening reveals ≈ 2·rounds + 2 functionals, and the ledger pads by this many ranks.</summary>
    private const int RankSlack = 8;

    /// <summary>The curve this test's mask parameters are computed over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Verifies that the resolved statistical-mask shape satisfies the filler ledger, carries the commitment's minimum hiding lift, and is the smallest such shape, across several sumcheck variable counts and query counts.</summary>
    /// <param name="sumcheckVariableCount">The sumcheck's variable count <c>d</c>.</param>
    /// <param name="queryCount">The commitment's query count <c>Q</c>.</param>
    [TestMethod]
    [DataRow(1, 8)]
    [DataRow(2, 12)]
    [DataRow(3, 273)]
    [DataRow(8, 273)]
    [DataRow(20, 273)]
    public void ResolvedShapeSatisfiesTheFillerLedgerAndIsMinimal(int sumcheckVariableCount, int queryCount)
    {
        StatisticalMaskParameters parameters = WellKnownStatisticalMaskParameters.CreateClassicalSecurity(sumcheckVariableCount, Curve, queryCount);

        Assert.AreEqual((2 * sumcheckVariableCount) + 1, parameters.MaskCoefficientCount, "The mask is the sum-of-univariates: 2d + 1 coefficients.");
        Assert.AreEqual(1 << parameters.CoefficientVariableCount, parameters.CoefficientCount, "The committed vector is a power-of-two multilinear table.");
        Assert.AreEqual(parameters.CoefficientCount - parameters.MaskCoefficientCount, parameters.FillerCount, "Every non-mask coordinate is filler.");

        //The lift must be exactly the commitment's enforced minimum.
        Assert.AreEqual(
            ZkBaseFoldPolynomialCommitmentScheme.GetMinimumExtraVariableCount(parameters.CoefficientVariableCount, Curve, queryCount),
            parameters.ExtraVariableCount,
            "The coefficient commitment must carry its minimum hiding lift.");

        //The filler ledger: F ≥ 2·(ℓ₂ + t_C) + 2 + slack.
        int requiredFiller = (2 * parameters.LiftedVariableCount) + 2 + RankSlack;
        Assert.IsGreaterThanOrEqualTo(requiredFiller, parameters.FillerCount, "The filler must rank-cover the weighted opening's reveals with slack.");

        //Minimality: one variable fewer must not fit the same ledger (its own
        //lift recomputed, since the lift shrinks with the variable count).
        int smaller = parameters.CoefficientVariableCount - 1;
        if(smaller >= 1)
        {
            int smallerLift = ZkBaseFoldPolynomialCommitmentScheme.GetMinimumExtraVariableCount(smaller, Curve, queryCount);
            int smallerRequired = (2 * (smaller + smallerLift)) + 2 + RankSlack;
            Assert.IsGreaterThan(
                1 << smaller, parameters.MaskCoefficientCount + smallerRequired,
                "The resolved variable count must be the smallest satisfying the ledger.");
        }
    }


    /// <summary>Verifies that a cubic (degree-3) mask, as the Spartan outer sumcheck uses, resolves to <c>3d + 1</c> coefficients under the same filler ledger as the default quadratic mask.</summary>
    /// <param name="sumcheckVariableCount">The sumcheck's variable count <c>d</c>.</param>
    /// <param name="queryCount">The commitment's query count <c>Q</c>.</param>
    [TestMethod]
    [DataRow(1, 12)]
    [DataRow(4, 273)]
    [DataRow(20, 273)]
    public void CubicDegreeResolvesTheLargerMask(int sumcheckVariableCount, int queryCount)
    {
        StatisticalMaskParameters parameters = WellKnownStatisticalMaskParameters.CreateClassicalSecurity(sumcheckVariableCount, Curve, queryCount, perVariableDegree: 3);

        Assert.AreEqual((3 * sumcheckVariableCount) + 1, parameters.MaskCoefficientCount, "A cubic mask carries 3d + 1 coefficients.");

        int requiredFiller = (2 * parameters.LiftedVariableCount) + 2 + RankSlack;
        Assert.IsGreaterThanOrEqualTo(requiredFiller, parameters.FillerCount, "The filler must rank-cover the weighted opening's reveals with slack.");
    }


    /// <summary>Verifies the Pedersen/IPA mask shape: no dimension lift, and filler covering exactly the two cleartext functionals of the committed vector (σ_F and the IPA final scalar) with the usual slack.</summary>
    /// <param name="sumcheckVariableCount">The sumcheck's variable count.</param>
    /// <param name="perVariableDegree">The per-variable mask degree.</param>
    [TestMethod]
    [DataRow(1, 2)]
    [DataRow(1, 3)]
    [DataRow(4, 3)]
    [DataRow(20, 2)]
    [DataRow(20, 3)]
    public void PedersenIpaShapeHasNoLiftAndCoversTheCleartextReveals(int sumcheckVariableCount, int perVariableDegree)
    {
        const int CleartextRevealCount = 2;

        StatisticalMaskParameters parameters = WellKnownStatisticalMaskParameters.CreatePedersenIpa(sumcheckVariableCount, perVariableDegree);

        Assert.AreEqual((perVariableDegree * sumcheckVariableCount) + 1, parameters.MaskCoefficientCount, "The mask carries perVariableDegree·d + 1 coefficients.");
        Assert.AreEqual(0, parameters.ExtraVariableCount, "A Pedersen commitment needs no dimension lift.");
        Assert.AreEqual(parameters.CoefficientVariableCount, parameters.LiftedVariableCount, "Without a lift the opening runs over ℓ₂ variables.");
        Assert.IsGreaterThanOrEqualTo(CleartextRevealCount + RankSlack, parameters.FillerCount, "The filler must cover the cleartext IPA reveals with slack.");

        //Minimality: one variable fewer must not fit.
        int smaller = parameters.CoefficientVariableCount - 1;
        if(smaller >= 1)
        {
            Assert.IsGreaterThan(
                1 << smaller, parameters.MaskCoefficientCount + CleartextRevealCount + RankSlack,
                "The resolved variable count must be the smallest satisfying the ledger.");
        }
    }


    /// <summary>Verifies that a per-variable mask degree outside the supported kernel range (below 2 or above 3) is refused by both the classical-security and Pedersen/IPA factories.</summary>
    [TestMethod]
    public void DegreeOutsideTheKernelRangeIsRefused()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => WellKnownStatisticalMaskParameters.CreateClassicalSecurity(4, Curve, 273, perVariableDegree: 1));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => WellKnownStatisticalMaskParameters.CreateClassicalSecurity(4, Curve, 273, perVariableDegree: 4));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => WellKnownStatisticalMaskParameters.CreatePedersenIpa(4, perVariableDegree: 1));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => WellKnownStatisticalMaskParameters.CreatePedersenIpa(4, perVariableDegree: 4));
    }


    /// <summary>Pins the production-scale mask shape at <c>d = 2</c> and query count 273: the resolved coefficient variable count, extra (lift) variable count, and filler count all match the hand-derived values.</summary>
    [TestMethod]
    public void ProductionShapeIsPinned()
    {
        //d = 2 at the production query count: mask 5 coefficients; ℓ₂ = 6 with
        //t_C = 6 (hand-derived from the budget: 63·64 = 4032 ≥ 273·13 + 8 = 3557,
        //while t = 5 gives 1984 < 3284) — filler ledger 5 + (2·12 + 2 + 8) = 39 ≤ 64,
        //and ℓ₂ = 5 fails (its t_C = 7 needs 5 + 36 = 41 > 32).
        const int ProductionQueryCount = 273;

        StatisticalMaskParameters parameters = WellKnownStatisticalMaskParameters.CreateClassicalSecurity(2, Curve, ProductionQueryCount);

        Assert.AreEqual(6, parameters.CoefficientVariableCount, "ℓ₂ must resolve to 6 at d = 2, Q = 273.");
        Assert.AreEqual(6, parameters.ExtraVariableCount, "t_C must resolve to 6 at ℓ₂ = 6, Q = 273.");
        Assert.AreEqual(59, parameters.FillerCount, "Filler is the full remainder: 64 − 5.");
    }
}

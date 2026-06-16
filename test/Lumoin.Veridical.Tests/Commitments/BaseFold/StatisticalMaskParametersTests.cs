using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// The statistical-mask parameter policy
/// (<see cref="WellKnownStatisticalMaskParameters"/>, design doc §2 v3): the
/// resolved shape must satisfy the filler ledger (enough all-ones-weighted
/// entropy to launder the weighted opening's round reveals), carry the
/// commitment's own minimum hiding lift, and be the smallest such shape — all
/// deterministically from the sumcheck shape, since prover and verifier derive
/// it independently with no wire data.
/// </summary>
[TestClass]
internal sealed class StatisticalMaskParametersTests
{
    //The ledger constants mirrored from the policy: the weighted opening
    //reveals ≈ 2·rounds + 2 functionals, rank-slacked by 8 (design doc §3).
    private const int RankSlack = 8;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


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


    [TestMethod]
    [DataRow(1, 12)]
    [DataRow(4, 273)]
    [DataRow(20, 273)]
    public void CubicDegreeResolvesTheLargerMask(int sumcheckVariableCount, int queryCount)
    {
        //The Spartan outer sumcheck's degree-3 masks: 3d + 1 coefficients, the
        //same filler ledger.
        StatisticalMaskParameters parameters = WellKnownStatisticalMaskParameters.CreateClassicalSecurity(sumcheckVariableCount, Curve, queryCount, perVariableDegree: 3);

        Assert.AreEqual((3 * sumcheckVariableCount) + 1, parameters.MaskCoefficientCount, "A cubic mask carries 3d + 1 coefficients.");

        int requiredFiller = (2 * parameters.LiftedVariableCount) + 2 + RankSlack;
        Assert.IsGreaterThanOrEqualTo(requiredFiller, parameters.FillerCount, "The filler must rank-cover the weighted opening's reveals with slack.");
    }


    [TestMethod]
    [DataRow(1, 2)]
    [DataRow(1, 3)]
    [DataRow(4, 3)]
    [DataRow(20, 2)]
    [DataRow(20, 3)]
    public void PedersenIpaShapeHasNoLiftAndCoversTheCleartextReveals(int sumcheckVariableCount, int perVariableDegree)
    {
        //The Pedersen/IPA ledger: only σ_F and the IPA final scalar are
        //cleartext functionals of the committed vector.
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


    [TestMethod]
    public void DegreeOutsideTheKernelRangeIsRefused()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => WellKnownStatisticalMaskParameters.CreateClassicalSecurity(4, Curve, 273, perVariableDegree: 1));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => WellKnownStatisticalMaskParameters.CreateClassicalSecurity(4, Curve, 273, perVariableDegree: 4));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => WellKnownStatisticalMaskParameters.CreatePedersenIpa(4, perVariableDegree: 1));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => WellKnownStatisticalMaskParameters.CreatePedersenIpa(4, perVariableDegree: 4));
    }


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

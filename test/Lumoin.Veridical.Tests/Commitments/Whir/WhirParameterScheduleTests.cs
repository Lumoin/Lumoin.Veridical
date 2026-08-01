using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments.Whir;
using System;
using System.Linq;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Tests for the WHIR parameter-schedule derivation (4.2 phase A): the
/// per-round rate/proximity/query schedule of WHIR Construction 5.1 and the
/// round-by-round soundness ledger of WHIR Theorem 5.2. The query schedules
/// are pinned to hand-derived values from the paper's formulas so any drift
/// in the derivation — a changed radius, slack or rounding — surfaces as an
/// exact-count mismatch, and the ledger invariants (every row at or above
/// the target, the union bound below the worst row) are asserted for both
/// wired regimes.
/// </summary>
[TestClass]
internal sealed class WhirParameterScheduleTests
{
    //The pinned shape: a 2^20-coefficient message at initial rate 1/2 with the
    //paper's constant folding parameter k = 4 gives five iterations and a
    //constant final polynomial — large enough to exercise the rate improvement
    //across five distinct rates, small enough to derive by hand.
    private const int PinnedVariableCount = 20;
    private const int PinnedInitialRateLog2 = 1;
    private const int PinnedIterationCount = 5;

    private const double ClassicalSecurityBits = WellKnownWhirParameters.ClassicalSecurityLevelBits;

    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void UniqueDecodingQueryScheduleMatchesPinnedCounts()
    {
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Curve,
            PinnedVariableCount,
            PinnedInitialRateLog2,
            regime: WhirSoundnessRegime.UniqueDecoding);

        //δ_i = (1 - 2^-rateLog2)/2 at rate exponents {1, 4, 7, 10, 13} and
        //t_i = ⌈128 / -log2(1 - δ_i)⌉, derived by hand from Theorem 5.2.
        int[] expectedQueryCounts = [309, 141, 130, 129, 129];
        int[] actualQueryCounts = [.. schedule.Rounds.Select(static round => round.QueryCount)];

        Assert.AreEqual(PinnedIterationCount, schedule.IterationCount);
        Assert.AreEqual(0, schedule.FinalVariableCount);
        CollectionAssert.AreEqual(expectedQueryCounts, actualQueryCounts);
    }


    [TestMethod]
    public void JohnsonQueryScheduleMatchesPinnedCounts()
    {
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Curve,
            PinnedVariableCount,
            PinnedInitialRateLog2,
            regime: WhirSoundnessRegime.ListDecodingJohnson);

        //δ_i = 1 - (21/20)·√(2^-rateLog2) at rate exponents {1, 4, 7, 10, 13}:
        //the STIR-style decay from 298 queries to 20 across five rounds.
        int[] expectedQueryCounts = [298, 67, 38, 26, 20];
        int[] actualQueryCounts = [.. schedule.Rounds.Select(static round => round.QueryCount)];

        CollectionAssert.AreEqual(expectedQueryCounts, actualQueryCounts);
    }


    [TestMethod]
    [DataRow(WhirSoundnessRegime.UniqueDecoding)]
    [DataRow(WhirSoundnessRegime.ListDecodingJohnson)]
    public void RoundRowsSatisfyDomainAndRateInvariants(WhirSoundnessRegime regime)
    {
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Curve,
            PinnedVariableCount,
            PinnedInitialRateLog2,
            regime: regime);

        for (int i = 0; i < schedule.IterationCount; i++)
        {
            WhirRoundParameters round = schedule.Rounds[i];

            //Domains halve per round while k variables fold away, so the
            //inverse-rate exponent grows by k - 1 per round.
            Assert.AreEqual(i, round.OracleIndex);
            Assert.AreEqual(PinnedVariableCount - (i * schedule.FoldingParameter), round.VariableCount);
            Assert.AreEqual(PinnedVariableCount + PinnedInitialRateLog2 - i, round.DomainSizeLog2);
            Assert.AreEqual(PinnedInitialRateLog2 + (i * (schedule.FoldingParameter - 1)), round.RateLog2);
            Assert.IsGreaterThan(0.0, round.ProximityParameter);
            Assert.IsLessThan(1.0, round.ProximityParameter);

            if (i > 0)
            {
                //The rate improvement must never price a later round above an
                //earlier one.
                Assert.IsLessThanOrEqualTo(schedule.Rounds[i - 1].QueryCount, round.QueryCount);
            }
        }
    }


    [TestMethod]
    [DataRow(WhirSoundnessRegime.UniqueDecoding)]
    [DataRow(WhirSoundnessRegime.ListDecodingJohnson)]
    public void LedgerRowsAllReachTargetAndUnionBoundSitsBelowWorstRow(WhirSoundnessRegime regime)
    {
        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            Curve,
            PinnedVariableCount,
            PinnedInitialRateLog2,
            regime: regime);

        //One fold row per sumcheck round, an out-of-domain and a shift row per
        //main-loop iteration, and the final-randomness row.
        int expectedRowCount = (PinnedIterationCount * schedule.FoldingParameter) + (2 * (PinnedIterationCount - 1)) + 1;
        Assert.HasCount(expectedRowCount, schedule.LedgerRows);

        foreach (WhirSoundnessLedgerRow row in schedule.LedgerRows)
        {
            Assert.IsGreaterThanOrEqualTo(ClassicalSecurityBits, row.ErrorBits, $"Row {row.Kind} at iteration {row.Iteration} misses the target.");
        }

        Assert.AreEqual(schedule.LedgerRows.Min(static row => row.ErrorBits), schedule.MinimumRoundBits);
        Assert.IsLessThan(schedule.MinimumRoundBits, schedule.UnionBoundBits);
        Assert.IsGreaterThanOrEqualTo(ClassicalSecurityBits, schedule.MinimumRoundBits);
    }


    [TestMethod]
    public void CapacityRegimeIsRejectedBySchedule()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => WhirParameterSchedule.Create(
            Curve,
            PinnedVariableCount,
            PinnedInitialRateLog2,
            regime: WhirSoundnessRegime.ConjecturedCapacity));
    }


    [TestMethod]
    public void CapacityRegimeStaysAvailableForQueryComparison()
    {
        //δ = 1 - (3/2)·ρ at rate 1/2 coincides with the unique-decoding radius,
        //and the count follows: the comparison figures stay reproducible even
        //though no schedule carries them.
        int queryCount = WellKnownWhirParameters.ComputeQueryCount(
            WellKnownWhirParameters.ClassicalSecurityLevelBits,
            PinnedInitialRateLog2,
            WhirSoundnessRegime.ConjecturedCapacity);

        Assert.AreEqual(309, queryCount);
        Assert.Throws<ArgumentOutOfRangeException>(() => WellKnownWhirParameters.ListSizeBound(
            WhirSoundnessRegime.ConjecturedCapacity,
            PinnedInitialRateLog2));
        Assert.Throws<ArgumentOutOfRangeException>(() => WellKnownWhirParameters.MutualCorrelatedAgreementErrorBits(
            WhirSoundnessRegime.ConjecturedCapacity,
            254,
            PinnedVariableCount,
            PinnedInitialRateLog2));
    }


    [TestMethod]
    public void InitialDomainBeyondTwoAdicityIsRejected()
    {
        //BN254's scalar field has two-adicity 28; a 2^26 message at rate 1/8
        //would need a 2^29 domain. The same shape fits BLS12-381 (two-adicity 32).
        const int VariableCount = 26;
        const int InverseRateLog2 = 3;

        Assert.Throws<ArgumentException>(() => WhirParameterSchedule.Create(
            CurveParameterSet.Bn254,
            VariableCount,
            InverseRateLog2));

        WhirParameterSchedule schedule = WhirParameterSchedule.Create(Curve, VariableCount, InverseRateLog2);
        Assert.AreEqual(VariableCount + InverseRateLog2, schedule.Rounds[0].DomainSizeLog2);

        //26 = 6·4 + 2, so this is the file's one shape whose final polynomial
        //keeps a nonzero remainder of variables.
        Assert.AreEqual(VariableCount % WellKnownWhirParameters.DefaultFoldingParameter, schedule.FinalVariableCount);
    }


    [TestMethod]
    public void QueryCountBeyondFoldedDomainIsRejected()
    {
        //A 2^8 message at rate 1/2 needs 309 unique-decoding queries against a
        //folded query domain of only 2^5 elements; the shape must fail loudly
        //instead of silently degrading below the target.
        const int TinyVariableCount = 8;

        Assert.Throws<ArgumentException>(() => WhirParameterSchedule.Create(
            Curve,
            TinyVariableCount,
            PinnedInitialRateLog2,
            regime: WhirSoundnessRegime.UniqueDecoding));
    }


    [TestMethod]
    public void ProximityParametersMatchPaperFormulas()
    {
        //At rate 1/2: UD δ = (1 - 1/2)/2 = 1/4; JB δ = 1 - (21/20)/√2;
        //CB δ = 1 - (3/2)/2 = 1/4 (Section 6.2 of the WHIR paper).
        const double Tolerance = 1e-12;

        Assert.AreEqual(0.25, WellKnownWhirParameters.ProximityParameter(WhirSoundnessRegime.UniqueDecoding, PinnedInitialRateLog2), Tolerance);
        Assert.AreEqual(1.0 - (1.05 / Math.Sqrt(2.0)), WellKnownWhirParameters.ProximityParameter(WhirSoundnessRegime.ListDecodingJohnson, PinnedInitialRateLog2), Tolerance);
        Assert.AreEqual(0.25, WellKnownWhirParameters.ProximityParameter(WhirSoundnessRegime.ConjecturedCapacity, PinnedInitialRateLog2), Tolerance);
    }


    [TestMethod]
    public void ListSizeBoundsMatchJohnsonBound()
    {
        //Unique decoding pins a single codeword; the Johnson bound at the wired
        //slack is 10/ρ = 10·2^rateLog2.
        const double Tolerance = 1e-12;
        const int JohnsonListAtRateHalf = 20;

        Assert.AreEqual(1.0, WellKnownWhirParameters.ListSizeBound(WhirSoundnessRegime.UniqueDecoding, PinnedInitialRateLog2), Tolerance);
        Assert.AreEqual(JohnsonListAtRateHalf, WellKnownWhirParameters.ListSizeBound(WhirSoundnessRegime.ListDecodingJohnson, PinnedInitialRateLog2), Tolerance);
    }


    [TestMethod]
    public void MutualCorrelatedAgreementErrorMatchesCorollaryUnderUniqueDecoding()
    {
        //Corollary 4.11 at ℓ = 2: err* = 2^m/(ρ·|F|), so the bits are exactly
        //fieldFloorBits - m - rateLog2.
        const int FieldFloorBits = 254;
        const int FoldedVariableCount = 19;

        double errorBits = WellKnownWhirParameters.MutualCorrelatedAgreementErrorBits(
            WhirSoundnessRegime.UniqueDecoding,
            FieldFloorBits,
            FoldedVariableCount,
            PinnedInitialRateLog2);

        Assert.AreEqual((double)(FieldFloorBits - FoldedVariableCount - PinnedInitialRateLog2), errorBits);
    }


    [TestMethod]
    public void MutualCorrelatedAgreementErrorMatchesConjectureUnderJohnson()
    {
        //Conjecture 4.12 Item 1 at ℓ = 2 and slack η = √ρ/20:
        //err* = 2^(2m)·(10/√ρ)^7/|F|, so at m = 19 and rate 1/2 the bits are
        //254 - 38 - 7·(log2(10) + 1/2) ≈ 189.2465 — a literal pin so a sign or
        //coefficient slip cannot hide above the coarse ledger threshold.
        const int FieldFloorBits = 254;
        const int FoldedVariableCount = 19;
        const double ExpectedBits = 189.24650333578846;
        const double Tolerance = 1e-9;

        double errorBits = WellKnownWhirParameters.MutualCorrelatedAgreementErrorBits(
            WhirSoundnessRegime.ListDecodingJohnson,
            FieldFloorBits,
            FoldedVariableCount,
            PinnedInitialRateLog2);

        Assert.AreEqual(ExpectedBits, errorBits, Tolerance);
    }
}

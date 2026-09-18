using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments.Whir;
using System;
using System.Linq;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Tests for the WHIR parameter-schedule derivation: the
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
    /// <summary>The pinned shape's message size: a 2^20-coefficient message, large enough to exercise the rate improvement across five distinct rates while staying small enough to derive by hand.</summary>
    private const int PinnedVariableCount = 20;

    /// <summary>The pinned shape's initial rate exponent (rate 1/2).</summary>
    private const int PinnedInitialRateLog2 = 1;

    /// <summary>The pinned shape's expected iteration count: with the paper's constant folding parameter <c>k = 4</c>, a 2^20-variable message folds to a constant final polynomial in exactly five iterations.</summary>
    private const int PinnedIterationCount = 5;

    /// <summary>The wired classical security target in bits, read from the library's default WHIR parameters.</summary>
    private const double ClassicalSecurityBits = WellKnownWhirParameters.ClassicalSecurityLevelBits;

    /// <summary>The curve every schedule in this class is derived over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Verifies that the unique-decoding regime's per-round query counts for the pinned shape match the hand-derived values from WHIR Theorem 5.2.</summary>
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
        Assert.AreSequenceEqual(expectedQueryCounts, actualQueryCounts);
    }


    /// <summary>Verifies that the Johnson list-decoding regime's per-round query counts for the pinned shape match the hand-derived STIR-style decay.</summary>
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

        Assert.AreSequenceEqual(expectedQueryCounts, actualQueryCounts);
    }


    /// <summary>Verifies that every round row's oracle index, variable count, domain size and rate exponent follow the fold-by-<c>k</c> recurrence, that its proximity parameter is a valid probability, and that query counts never decrease round over round.</summary>
    /// <param name="regime">The soundness regime to derive the schedule under.</param>
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


    /// <summary>Verifies the soundness ledger's row count and shape, that every row meets the classical security target, and that the union bound sits strictly below the ledger's worst (minimum-bits) row.</summary>
    /// <param name="regime">The soundness regime to derive the schedule under.</param>
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


    /// <summary>Verifies that requesting a full schedule under the conjectured-capacity regime is rejected, since that regime is wired only for the standalone query-count comparison.</summary>
    [TestMethod]
    public void CapacityRegimeIsRejectedBySchedule()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => WhirParameterSchedule.Create(
            Curve,
            PinnedVariableCount,
            PinnedInitialRateLog2,
            regime: WhirSoundnessRegime.ConjecturedCapacity));
    }


    /// <summary>Verifies that the conjectured-capacity regime's standalone query count is reproducible, while its list-size and mutual-correlated-agreement helpers, which no schedule carries, still reject that regime.</summary>
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


    /// <summary>Verifies that a shape whose initial domain would exceed a curve's two-adicity is rejected on that curve, while the same shape schedules successfully on a curve with enough two-adicity, and that a nonzero folding remainder is reported as the final variable count.</summary>
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


    /// <summary>Verifies that a shape whose required query count exceeds its folded query domain's size fails loudly instead of silently pricing less than the target soundness.</summary>
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


    /// <summary>Verifies each regime's proximity parameter at rate 1/2 against its hand-computed value from Section 6.2 of the WHIR paper.</summary>
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


    /// <summary>Verifies that unique decoding pins a list size of one codeword, and that the Johnson list bound at the wired slack equals <c>10/ρ</c>.</summary>
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


    /// <summary>Verifies that the unique-decoding mutual-correlated-agreement error, at list parameter <c>ℓ = 2</c>, matches Corollary 4.11's closed form exactly.</summary>
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


    /// <summary>Verifies that, at the same target soundness and shape, the Johnson regime's larger proximity radius prices strictly fewer queries than unique decoding in every round and in total, while both still meet the classical security target.</summary>
    [TestMethod]
    public void JohnsonRegimePricesFewerQueriesThanUniqueDecoding()
    {
        //Both regimes target the same 2^-128 per-round soundness on the same
        //shape. The Johnson schedule pays strictly fewer queries in every
        //round — a 46% total discount — through its larger proximity radius,
        //priced by the BCHKS25 Theorem 1.5 correlated-agreement error. This
        //test pins both totals side by side so the radius-bought gap stays
        //visible and can never be mistaken for a free improvement.
        const int UniqueDecodingTotalQueryCount = 838;
        const int JohnsonTotalQueryCount = 449;

        WhirParameterSchedule uniqueDecoding = WhirParameterSchedule.Create(
            Curve,
            PinnedVariableCount,
            PinnedInitialRateLog2,
            regime: WhirSoundnessRegime.UniqueDecoding);
        WhirParameterSchedule johnson = WhirParameterSchedule.Create(
            Curve,
            PinnedVariableCount,
            PinnedInitialRateLog2,
            regime: WhirSoundnessRegime.ListDecodingJohnson);

        Assert.AreEqual(UniqueDecodingTotalQueryCount, uniqueDecoding.Rounds.Sum(static round => round.QueryCount));
        Assert.AreEqual(JohnsonTotalQueryCount, johnson.Rounds.Sum(static round => round.QueryCount));

        for (int i = 0; i < uniqueDecoding.IterationCount; i++)
        {
            //The mechanism of the discount: a strictly larger radius per
            //round, hence strictly fewer queries per round.
            Assert.IsGreaterThan(uniqueDecoding.Rounds[i].ProximityParameter, johnson.Rounds[i].ProximityParameter);
            Assert.IsLessThan(uniqueDecoding.Rounds[i].QueryCount, johnson.Rounds[i].QueryCount);
        }

        //Same soundness target on both sides of the gap: what differs is the
        //length of the proof chain carrying it, not the claimed level.
        Assert.IsGreaterThanOrEqualTo(ClassicalSecurityBits, uniqueDecoding.MinimumRoundBits);
        Assert.IsGreaterThanOrEqualTo(ClassicalSecurityBits, johnson.MinimumRoundBits);
    }


    /// <summary>Verifies that the Johnson mutual-correlated-agreement error at the default Johnson parameter matches BCHKS25 Theorem 1.5's closed form to a literal, hand-computed bit count.</summary>
    [TestMethod]
    public void MutualCorrelatedAgreementErrorMatchesBchks25TheoremUnderJohnson()
    {
        //BCHKS25 Theorem 1.5 at the default m_J = 10:
        //err* = (2·10.5^5/3)·2^m·ρ^(-5/2)/|F|, so at m = 19 and rate 1/2 the
        //bits are 254 - log2(2·10.5^5/3) - 19 - 2.5 ≈ 216.1234 — a literal pin
        //so a sign or coefficient slip cannot hide above the coarse ledger
        //threshold.
        const int FieldFloorBits = 254;
        const int FoldedVariableCount = 19;
        const double ExpectedBits = 216.12337538682704;
        const double Tolerance = 1e-9;

        double errorBits = WellKnownWhirParameters.MutualCorrelatedAgreementErrorBits(
            WhirSoundnessRegime.ListDecodingJohnson,
            FieldFloorBits,
            FoldedVariableCount,
            PinnedInitialRateLog2);

        Assert.AreEqual(ExpectedBits, errorBits, Tolerance);
    }


    /// <summary>Verifies the Johnson mutual-correlated-agreement error against a small shape hand-derived independently from BCHKS25 Theorem 1.5, anchoring the constant and both exponents against a value derived outside this codebase's formula.</summary>
    [TestMethod]
    public void JohnsonAgreementErrorMatchesIndependentTheoremAnchor()
    {
        //An independent hand-derivation of BCHKS25 Theorem 1.5 at a shape
        //small enough to check on paper: message length 2^4, rate 1/4 and a
        //64-bit field give 64 - log2(2·10.5^5/3) - 4 - 2.5·2
        //= 38.623375386827 bits, anchoring the constant and both exponents
        //against a value derived outside this codebase's formula.
        const int AnchorFieldBits = 64;
        const int AnchorVariableCount = 4;
        const int AnchorRateLog2 = 2;
        const double AnchorBits = 38.623375386827;
        const double Tolerance = 1e-9;

        double errorBits = WellKnownWhirParameters.MutualCorrelatedAgreementErrorBits(
            WhirSoundnessRegime.ListDecodingJohnson,
            AnchorFieldBits,
            AnchorVariableCount,
            AnchorRateLog2);

        Assert.AreEqual(AnchorBits, errorBits, Tolerance);
    }


    /// <summary>Verifies that the proven BCHKS25 mutual-correlated-agreement bound prices strictly more error bits than the superseded Conjecture 4.12 Item 1 pricing at every wired shape, so the theorem upgrade can never silently weaken a ledger row.</summary>
    [TestMethod]
    public void Bchks25ErrorStrictlyImprovesOnSupersededConjecturePricing()
    {
        //The superseded Conjecture 4.12 Item 1 pricing at ℓ = 2 and η = √ρ/20
        //was err* = 2^(2m)·(10/√ρ)^7/|F|; the proven BCHKS25 bound must price
        //strictly MORE bits at every wired shape, so the theorem upgrade can
        //never silently weaken a ledger row.
        const int FieldFloorBits = 254;
        const int FoldedVariableCount = 19;

        double supersededConjectureBits = FieldFloorBits
            - (2.0 * FoldedVariableCount)
            - (7.0 * (Math.Log2(10.0) + (PinnedInitialRateLog2 / 2.0)));
        double provenBits = WellKnownWhirParameters.MutualCorrelatedAgreementErrorBits(
            WhirSoundnessRegime.ListDecodingJohnson,
            FieldFloorBits,
            FoldedVariableCount,
            PinnedInitialRateLog2);

        Assert.IsGreaterThan(supersededConjectureBits, provenBits);
    }


    /// <summary>Verifies that choosing a non-default Johnson proximity parameter self-prices consistently across the radius, list-size bound and error-bit formulas, and that the trade-off (smaller parameter, smaller radius, more queries, fewer error bits) moves in the expected direction relative to the default.</summary>
    [TestMethod]
    public void JohnsonProximityParameterSelfPricesRadiusListAndError()
    {
        //The BCHKS25 Johnson proximity parameter m_J trades along one axis:
        //a larger m_J shrinks the slack η = √ρ/(2m_J), widening the radius
        //(fewer queries) while growing both the list bound m_J/ρ and the
        //error constant 2·(m_J + 1/2)^5/3. Every figure is computed FROM the
        //chosen m_J, so any choice self-prices; this pins the formulas at a
        //non-default value and the trade's direction across values.
        const int SmallJohnsonParameter = 4;
        const int FieldFloorBits = 254;
        const int FoldedVariableCount = 19;
        const double Tolerance = 1e-12;

        double delta = WellKnownWhirParameters.ProximityParameter(
            WhirSoundnessRegime.ListDecodingJohnson,
            PinnedInitialRateLog2,
            SmallJohnsonParameter);
        Assert.AreEqual(1.0 - (1.125 / Math.Sqrt(2.0)), delta, Tolerance);

        double listSize = WellKnownWhirParameters.ListSizeBound(
            WhirSoundnessRegime.ListDecodingJohnson,
            PinnedInitialRateLog2,
            SmallJohnsonParameter);
        Assert.AreEqual(SmallJohnsonParameter * Math.Pow(2.0, PinnedInitialRateLog2), listSize, Tolerance);

        //Direction of the trade against the default m_J = 10: smaller m_J
        //means a smaller radius (more queries) but a smaller error constant
        //(more bits per row).
        Assert.IsLessThan(
            WellKnownWhirParameters.ProximityParameter(WhirSoundnessRegime.ListDecodingJohnson, PinnedInitialRateLog2),
            delta);
        Assert.IsGreaterThan(
            WellKnownWhirParameters.MutualCorrelatedAgreementErrorBits(
                WhirSoundnessRegime.ListDecodingJohnson,
                FieldFloorBits,
                FoldedVariableCount,
                PinnedInitialRateLog2),
            WellKnownWhirParameters.MutualCorrelatedAgreementErrorBits(
                WhirSoundnessRegime.ListDecodingJohnson,
                FieldFloorBits,
                FoldedVariableCount,
                PinnedInitialRateLog2,
                SmallJohnsonParameter));
    }
}

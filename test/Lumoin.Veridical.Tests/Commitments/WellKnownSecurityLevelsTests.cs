using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// Pins the per-proof-path security-level ledger in <see cref="WellKnownSecurityLevels"/>: the scalar-field
/// floor, the Ligero opened-column derivation at both the wired rate-1/16 shape and the legacy rate-1/4 shape,
/// the Spartan sumcheck term, the combined Spartan-over-Ligero and masked-ZK-BaseFold ledgers, the soundness
/// clamp guard, and the BaseFold IOPP proximity bound — so a regression in any one term cannot silently
/// understate or overstate the bits a deployed proof actually realises.
/// </summary>
[TestClass]
internal sealed class WellKnownSecurityLevelsTests
{
    //The model is exact for these shapes; compare the floating-point figures within a small tolerance.
    private const double Tolerance = 1e-9;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    //Pins the conservative scalar-field-size floor for both wired curves.
    [TestMethod]
    public void ScalarFieldFloorIs254ForBls12Curve381And253ForBn254()
    {
        Assert.AreEqual(254, WellKnownSecurityLevels.ScalarFieldSoundnessFloorBits(Curve));
        Assert.AreEqual(253, WellKnownSecurityLevels.ScalarFieldSoundnessFloorBits(CurveParameterSet.Bn254));
    }


    //Pins the wired rate-1/16 Johnson opened-column count and its per-column bits.
    [TestMethod]
    public void RateSixteenJohnsonQueryCountIsSixtyFour()
    {
        const int InverseRate = 16;
        const int ExpectedQueryCount = 64;
        const double ExpectedBitsPerColumn = 2.0;

        Assert.AreEqual(ExpectedQueryCount, WellKnownLigeroParameters.ClassicalSecurityQueryCount(InverseRate, LigeroSoundnessRegime.ListDecodingJohnson));
        Assert.AreEqual(ExpectedBitsPerColumn, WellKnownLigeroParameters.BitsPerOpenedColumn(LigeroSoundnessRegime.ListDecodingJohnson, InverseRate), Tolerance);
    }


    //Pins the legacy rate-1/4 Johnson opened-column count against the library's own default.
    [TestMethod]
    public void RateFourJohnsonQueryCountIsOneHundredTwentyEight()
    {
        const int InverseRate = 4;
        const int ExpectedQueryCount = 128;

        int queryCount = WellKnownLigeroParameters.ClassicalSecurityQueryCount(InverseRate, LigeroSoundnessRegime.ListDecodingJohnson);

        Assert.AreEqual(ExpectedQueryCount, queryCount);
        Assert.AreEqual(WellKnownLigeroParameters.ClassicalSecurityDefaultQueryCount, queryCount);
    }


    //Pins that a 6-variable polynomial at rate 1/16 opens the full 64-column target for exactly 128 bits.
    [TestMethod]
    public void SixVariableRateSixteenOpeningRealisesFullTarget()
    {
        const int VariableCount = 6;
        const int InverseRate = 16;
        const int QueryCount = 64;
        const double ExpectedBits = 128.0;

        Assert.AreEqual(ExpectedBits, WellKnownSecurityLevels.LigeroProximitySoundnessBits(VariableCount, InverseRate, QueryCount), Tolerance);
    }


    //Pins that a 6-variable polynomial at the legacy rate 1/4 clamps to 24 opened columns (its extension
    //width), so raising the requested query count past that width is a no-op.
    [TestMethod]
    public void SixVariableRateFourOpeningClampsToTwentyFourBits()
    {
        const int VariableCount = 6;
        const int InverseRate = 4;
        const int RequestedQueryCountAtTarget = 128;
        const int RequestedQueryCountPastExtension = 32;
        const double ExpectedBits = 24.0;

        Assert.AreEqual(ExpectedBits, WellKnownSecurityLevels.LigeroProximitySoundnessBits(VariableCount, InverseRate, RequestedQueryCountAtTarget), Tolerance);
        Assert.AreEqual(ExpectedBits, WellKnownSecurityLevels.LigeroProximitySoundnessBits(VariableCount, InverseRate, RequestedQueryCountPastExtension), Tolerance);
    }


    //Pins the Spartan sumcheck Fiat-Shamir term at 6 outer and 6 inner rounds: 254 - log2(3*6 + 2*6).
    [TestMethod]
    public void SpartanSumcheckTermIsNearTwoHundredFortyNineBits()
    {
        const int OuterRoundCount = 6;
        const int InnerRoundCount = 6;
        const int SumcheckWeight = 30;

        double expected = WellKnownSecurityLevels.ScalarFieldSoundnessFloorBits(Curve) - Math.Log2(SumcheckWeight);

        Assert.AreEqual(expected, WellKnownSecurityLevels.SpartanSumcheckSoundnessBits(Curve, OuterRoundCount, InnerRoundCount), Tolerance);
    }


    //Pins the wired CLI shape's ledger: at 6/6 sumcheck rounds and rate-1/16, 64-column Ligero, the proximity
    //term is the bottleneck, landing exactly on the 128-bit target, unmasked.
    [TestMethod]
    public void WiredCliShapeLedgerBottleneckIsProximityAtOneHundredTwentyEight()
    {
        const int OuterRoundCount = 6;
        const int InnerRoundCount = 6;
        const int InverseRate = 16;
        const int QueryCount = 64;
        const double ExpectedProximityBits = 128.0;
        const double ExpectedFieldTermBits = 233.0;

        SecurityLevelLedger ledger = WellKnownSecurityLevels.ComputeSpartanOverLigero(Curve, OuterRoundCount, InnerRoundCount, InverseRate, QueryCount);

        Assert.AreEqual(ExpectedProximityBits, ledger.ProximityBits, Tolerance);
        Assert.AreEqual(ExpectedProximityBits, ledger.EffectiveBits, Tolerance);
        Assert.AreEqual(ExpectedFieldTermBits, ledger.FieldTermBits, Tolerance);
        Assert.AreEqual(HidingKind.None, ledger.Hiding);
    }


    //Pins that the legacy rate-1/4, 32-column shape realises only 24 bits — the clamp's practical bite on the
    //same 6/6 sumcheck shape the wired CLI shape uses.
    [TestMethod]
    public void LegacyRateFourShapeLedgerRealisesTwentyFourBits()
    {
        const int OuterRoundCount = 6;
        const int InnerRoundCount = 6;
        const int InverseRate = 4;
        const int QueryCount = 32;
        const double ExpectedEffectiveBits = 24.0;

        SecurityLevelLedger ledger = WellKnownSecurityLevels.ComputeSpartanOverLigero(Curve, OuterRoundCount, InnerRoundCount, InverseRate, QueryCount);

        Assert.AreEqual(ExpectedEffectiveBits, ledger.EffectiveBits, Tolerance);
    }


    //Pins the clamp guard's three boundary shapes: the legacy rate-1/4 shape and a 5-variable rate-1/16 shape
    //(extension width 60, short of the 64-column target) both throw, while the wired 6-variable rate-1/16
    //shape does not.
    [TestMethod]
    public void ClampGuardThrowsForUnderTargetShapes()
    {
        const int WiredVariableCount = 6;
        const int LegacyInverseRate = 4;
        const int LegacyQueryCount = 32;
        const int ShortVariableCount = 5;
        const int WiredInverseRate = 16;
        const int WiredQueryCount = 64;

        Assert.ThrowsExactly<ArgumentException>(() => WellKnownSecurityLevels.ThrowIfLigeroSoundnessClamped(WiredVariableCount, LegacyInverseRate, LegacyQueryCount));
        Assert.ThrowsExactly<ArgumentException>(() => WellKnownSecurityLevels.ThrowIfLigeroSoundnessClamped(ShortVariableCount, WiredInverseRate, WiredQueryCount));
        WellKnownSecurityLevels.ThrowIfLigeroSoundnessClamped(WiredVariableCount, WiredInverseRate, WiredQueryCount);
    }


    //Pins that the BaseFold IOPP's own default query count clears the 128-bit target with only a little
    //headroom (not orders of magnitude over it).
    [TestMethod]
    public void BaseFoldWiredQueryCountMeetsTarget()
    {
        const double LowerBound = 128.0;
        const double UpperBound = 132.0;

        double bits = WellKnownSecurityLevels.BaseFoldProximitySoundnessBits(WellKnownBaseFoldIoppParameters.ClassicalSecurityDefaultQueryCount);

        Assert.IsGreaterThanOrEqualTo(LowerBound, bits);
        Assert.IsLessThan(UpperBound, bits);
    }


    //Pins that the masked ZK BaseFold ledger (a 2-variable hiding lift over the 6/6 sumcheck shape) is
    //statistically hiding and still clears the 128-bit target.
    [TestMethod]
    public void MaskedZkBaseFoldLedgerIsStatisticallyHiding()
    {
        const int OuterRoundCount = 6;
        const int InnerRoundCount = 6;
        const int QueryCount = 273;
        const int ExtraVariableCount = 2;
        const double ExpectedMinimumEffectiveBits = 128.0;

        SecurityLevelLedger ledger = WellKnownSecurityLevels.ComputeMaskedSpartanOverZkBaseFold(Curve, OuterRoundCount, InnerRoundCount, QueryCount, ExtraVariableCount);

        Assert.AreEqual(HidingKind.Statistical, ledger.Hiding);
        Assert.IsGreaterThanOrEqualTo(ExpectedMinimumEffectiveBits, ledger.EffectiveBits);
    }


    //Pins that the default-inverse-rate opening-size path is byte-identical to explicitly requesting rate 4.
    [TestMethod]
    [DataRow(2)]
    [DataRow(6)]
    [DataRow(10)]
    public void DefaultRateOpeningSizeIsUnchanged(int variableCount)
    {
        const int QueryCount = 32;
        const int DigestSizeBytes = 32;
        const int ExplicitDefaultInverseRate = 4;

        int defaultPathSize = LigeroPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(variableCount, Curve, QueryCount, DigestSizeBytes);
        int explicitPathSize = LigeroPolynomialCommitmentScheme.GetEvaluationProofSizeBytes(variableCount, Curve, QueryCount, DigestSizeBytes, ExplicitDefaultInverseRate);

        Assert.AreEqual(explicitPathSize, defaultPathSize, "The default inverse-rate path must be byte-identical to explicit rate 4.");
    }
}

using Lumoin.Veridical.Core.Commitments.Ligero;

namespace Lumoin.Veridical.Tests.Commitments.Ligero;

/// <summary>
/// Pins the Ligero polynomial-commitment soundness derivation in <see cref="WellKnownLigeroParameters"/>: the
/// per-regime proximity parameter, the per-opened-column soundness, and the 128-bit-classical opened-column
/// count must reproduce the documented interleaved-Reed-Solomon model, so a regression in the derivation
/// cannot silently lower the realised soundness. The wired default is the conservative provable Johnson bound.
/// </summary>
[TestClass]
internal sealed class WellKnownLigeroParametersTests
{
    //The 128-bit target and the wired rate-1/4 figures the derivation must reproduce.
    private const int SecurityLevelBits = 128;
    private const int InverseRate = 4;

    //The opened-column counts at rate 1/4 under each regime: Johnson is the conservative provable default.
    private const int JohnsonQueryCount = 128;
    private const int CapacityQueryCount = 64;
    private const int UniqueDecodingQueryCount = 189;

    //The model is exact at this rate; compare the floating-point figures within a small tolerance.
    private const double Tolerance = 1e-9;


    [TestMethod]
    public void ProximityParameterMatchesEachRegimeAtRateOneQuarter()
    {
        Assert.AreEqual(0.375, WellKnownLigeroParameters.ProximityParameter(LigeroSoundnessRegime.UniqueDecoding, InverseRate), Tolerance);
        Assert.AreEqual(0.5, WellKnownLigeroParameters.ProximityParameter(LigeroSoundnessRegime.ListDecodingJohnson, InverseRate), Tolerance);
        Assert.AreEqual(0.75, WellKnownLigeroParameters.ProximityParameter(LigeroSoundnessRegime.ConjecturedCapacity, InverseRate), Tolerance);
    }


    [TestMethod]
    public void ReedSolomonRelativeDistanceAndJohnsonRadiusAreNamedDerivations()
    {
        Assert.AreEqual(0.75, WellKnownLigeroParameters.ReedSolomonRelativeDistance(InverseRate), Tolerance);

        //J(x) = 1 − √(1 − x): the rate-1/4 RS distance 0.75 maps to the Johnson radius 0.5, and the endpoints
        //are fixed points.
        Assert.AreEqual(0.5, WellKnownLigeroParameters.JohnsonRadius(0.75), Tolerance);
        Assert.AreEqual(0.0, WellKnownLigeroParameters.JohnsonRadius(0.0), Tolerance);
        Assert.AreEqual(1.0, WellKnownLigeroParameters.JohnsonRadius(1.0), Tolerance);
    }


    [TestMethod]
    public void BitsPerOpenedColumnIsNegativeLog2OfOneMinusDelta()
    {
        Assert.AreEqual(1.0, WellKnownLigeroParameters.BitsPerOpenedColumn(LigeroSoundnessRegime.ListDecodingJohnson, InverseRate), Tolerance);
        Assert.AreEqual(2.0, WellKnownLigeroParameters.BitsPerOpenedColumn(LigeroSoundnessRegime.ConjecturedCapacity, InverseRate), Tolerance);
    }


    [TestMethod]
    public void ComputeQueryCountReachesTheTargetUnderEachRegime()
    {
        Assert.AreEqual(JohnsonQueryCount, WellKnownLigeroParameters.ComputeQueryCount(SecurityLevelBits, InverseRate, LigeroSoundnessRegime.ListDecodingJohnson));
        Assert.AreEqual(CapacityQueryCount, WellKnownLigeroParameters.ComputeQueryCount(SecurityLevelBits, InverseRate, LigeroSoundnessRegime.ConjecturedCapacity));
        Assert.AreEqual(UniqueDecodingQueryCount, WellKnownLigeroParameters.ComputeQueryCount(SecurityLevelBits, InverseRate, LigeroSoundnessRegime.UniqueDecoding));
    }


    [TestMethod]
    public void DefaultRegimeIsTheConservativeProvableJohnsonBound()
    {
        //The default count equals the Johnson-regime count — pinning the regime choice through the derivation
        //rather than a constant-versus-constant compare — and is 128 at the wired rate.
        int johnsonCount = WellKnownLigeroParameters.ComputeQueryCount(SecurityLevelBits, InverseRate, LigeroSoundnessRegime.ListDecodingJohnson);

        Assert.AreEqual(johnsonCount, WellKnownLigeroParameters.ClassicalSecurityDefaultQueryCount);
        Assert.AreEqual(JohnsonQueryCount, WellKnownLigeroParameters.ClassicalSecurityDefaultQueryCount);
    }


    [TestMethod]
    public void EffectiveSecurityBitsMeetsTheTargetAtTheDefaultQueryCount()
    {
        double bits = WellKnownLigeroParameters.EffectiveSecurityBits(
            LigeroSoundnessRegime.ListDecodingJohnson, InverseRate, WellKnownLigeroParameters.ClassicalSecurityDefaultQueryCount);

        Assert.AreEqual(128.0, bits, Tolerance);
    }
}

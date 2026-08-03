using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.Whir;
using System;

namespace Lumoin.Veridical.Tests.Commitments.Whir;

/// <summary>
/// Tests for the WHIR entries of <see cref="WellKnownSecurityLevels"/>
/// (4.2 phase B): the realised round-by-round figure of the full-λ shape and
/// the loud clamp guard — a shape that cannot reach the target must throw up
/// front rather than silently degrade.
/// </summary>
[TestClass]
internal sealed class WhirSecurityLevelsTests
{
    /// <summary>
    /// The full-λ shape's variable count: 2^12 coefficients carry the
    /// classical 128-bit target through three iterations at rate 1/4.
    /// </summary>
    private const int FullVariableCount = 12;

    /// <summary>The full-λ shape's initial inverse-rate exponent: rate 1/4.</summary>
    private const int FullInitialRateLog2 = 2;

    /// <summary>
    /// An under-target variable count at the same rate: the first round's
    /// folded query domain has 2^6 elements, far below the 189 queries the
    /// 128-bit target prices there.
    /// </summary>
    private const int UnderTargetVariableCount = 8;


    [TestMethod]
    public void FullShapeRealisesTheClassicalTarget()
    {
        double realisedBits = WellKnownSecurityLevels.WhirProximitySoundnessBits(
            CurveParameterSet.Bls12Curve381, FullVariableCount, FullInitialRateLog2);

        WhirParameterSchedule schedule = WhirParameterSchedule.Create(
            CurveParameterSet.Bls12Curve381, FullVariableCount, FullInitialRateLog2);

        Assert.IsGreaterThanOrEqualTo(WellKnownWhirParameters.ClassicalSecurityLevelBits, realisedBits, "The full shape must reach the 128-bit target.");
        Assert.AreEqual(schedule.MinimumRoundBits, realisedBits, "The figure must be the schedule's worst ledger row.");
    }


    [TestMethod]
    public void UnderTargetShapeThrowsWithRealisedFigures()
    {
        Assert.Throws<ArgumentException>(
            () => WellKnownSecurityLevels.ThrowIfWhirSoundnessClamped(
                CurveParameterSet.Bls12Curve381, UnderTargetVariableCount, FullInitialRateLog2),
            "A shape whose query counts cannot fit their folded query domains must be refused.");
    }


    [TestMethod]
    public void FullShapeGuardPasses()
    {
        WellKnownSecurityLevels.ThrowIfWhirSoundnessClamped(
            CurveParameterSet.Bls12Curve381, FullVariableCount, FullInitialRateLog2);
    }
}

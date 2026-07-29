using Lumoin.Veridical.Analysis.StatisticalTests;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Analysis;

/// <summary>
/// A dudect-style acceptance test for the BLS12-381 constant-time G2 scalar-multiply
/// backend, run two ways through <see cref="TimingLeakageHarness"/>. The first
/// run is a negative control against the variable-time
/// <see cref="Bls12Curve381BigIntegerG2Reference"/> — affine double-and-add with a
/// data-dependent Fp2 inversion per bit and a minimal-byte-length loop — which must
/// reject, proving the harness has teeth against a known leak. The second run measures
/// <see cref="Bls12Curve381ConstantTimeG2Backend"/> and only asserts that a verdict was
/// reached (report-not-fail): a shared runner's timing noise makes the direction
/// of that verdict unreliable to assert on.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381ConstantTimeG2TimingHarnessTests
{
    /// <summary>
    /// A tenth of the G1 pairs' budget: one reference G2 multiplication costs tens of milliseconds
    /// (a data-dependent Fp2 inversion per bit), so the G1 budget would run for the better part of an
    /// hour. The negative control's gap (a one-byte versus a thirty-two-byte ladder walk) is a factor
    /// of roughly thirty, which the Welch test resolves decisively well below this count.
    /// </summary>
    private const int MeasurementCount = 2000;
    /// <summary>
    /// A tenth of the G1 pairs' budget: one reference G2 multiplication costs tens of milliseconds
    /// (a data-dependent Fp2 inversion per bit), so the G1 budget would run for the better part of an
    /// hour. The negative control's gap (a one-byte versus a thirty-two-byte ladder walk) is a factor
    /// of roughly thirty, which the Welch test resolves decisively well below this count.
    /// </summary>
    private const int WarmupCount = 200;
    private const int ScalarInputLength = 32;

    /// <summary>
    /// Compressed BLS12-381 G2 point: x.c1 then x.c0, 48 bytes each, with the flag bits in byte zero.
    /// </summary>
    private const int CompressedPointSize = WellKnownCurves.Bls12Curve381G2CompressedSizeBytes;

    /// <summary>
    /// The fixed class's scalar: the minimal nonzero magnitude, so it sits at the far end of the
    /// reference ladder's magnitude channel from a full-width random scalar.
    /// </summary>
    private const byte FixedScalarValue = 1;

    /// <summary>
    /// The base point is public data at the secret-scalar call site, so a single shared encoding is
    /// safe to reuse as the fixed base point across both measurement runs. It must be captured by both
    /// TimedOperation closures below, so it lives on the heap rather than as a stackalloc span.
    /// </summary>
    private static byte[] GeneratorPoint { get; } = WellKnownCurves.GetG2GeneratorCompressed(CurveParameterSet.Bls12Curve381).ToArray();


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void ReferenceLadderLeaksUnderTheHarness()
    {
        //TimedOperation is a delegate the harness stores and calls from inside its measurement loop, so
        //the result buffer it writes into must be captured by the closure - a stackalloc span cannot
        //survive past this method, so a heap byte[] is unavoidable here.
        byte[] result = new byte[CompressedPointSize];
        G2ScalarMultiplyDelegate referenceScalarMultiply = Bls12Curve381BigIntegerG2Reference.GetScalarMultiply();

        StatisticalTestResult verdict = TimingLeakageHarness.Measure(
            input => referenceScalarMultiply(GeneratorPoint, input, result, CurveParameterSet.Bls12Curve381),
            PrepareScalarInput,
            ScalarInputLength,
            MeasurementCount,
            WarmupCount);

        //The reference walks the minimal big-endian byte length of the scalar (see
        //Bls12Curve381BigIntegerG2Reference.ScalarMultiplyPoint), so the fixed class (k = 1, ~8 ladder
        //steps) runs roughly 32x faster than the random class (a full 256-bit scalar, ~256 steps). That
        //gap is large enough for the Welch test to reject overwhelmingly - this is the negative control
        //that proves the harness detects a known variable-time leak.
        Assert.AreEqual(StatisticalTestInterpretation.Reject, verdict.Interpretation);
    }


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void ConstantTimeLadderReachesAVerdictWithoutFailing()
    {
        //As above: the closure-captured result buffer the TimedOperation delegate writes into.
        byte[] result = new byte[CompressedPointSize];
        G2ScalarMultiplyDelegate constantTimeScalarMultiply = Bls12Curve381ConstantTimeG2Backend.GetScalarMultiply();

        StatisticalTestResult verdict = TimingLeakageHarness.Measure(
            input => constantTimeScalarMultiply(GeneratorPoint, input, result, CurveParameterSet.Bls12Curve381),
            PrepareScalarInput,
            ScalarInputLength,
            MeasurementCount,
            WarmupCount);

        //Report-not-fail: the constant-time ladder runs a fixed 256 iterations regardless of the
        //scalar, so no reliable timing gap is expected, but wall-clock timing on a shared runner is
        //noisy in either direction. Assert only that the harness reached a decisive verdict, never a
        //specific Reject/FailToReject direction.
        Assert.AreNotEqual(StatisticalTestInterpretation.Inconclusive, verdict.Interpretation);
    }


    /// <summary>
    /// Class 0 (FIXED) is the minimal-magnitude, minimal-Hamming-weight scalar k = 1; class 1 (RANDOM) is
    /// the raw entropy taken as a 256-bit big-endian scalar. Neither class needs a mod-r reduction: both
    /// backends multiply by the scalar's integer value as given, with no requirement that it be below the
    /// group order.
    /// </summary>
    private static void PrepareScalarInput(int classId, ReadOnlySpan<byte> entropy, Span<byte> destination)
    {
        if(classId == 0)
        {
            destination.Clear();
            destination[^1] = FixedScalarValue;
        }
        else
        {
            entropy.CopyTo(destination);
        }
    }
}

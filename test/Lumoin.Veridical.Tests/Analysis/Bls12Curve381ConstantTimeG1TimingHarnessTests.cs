using Lumoin.Veridical.Analysis.StatisticalTests;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Analysis;

/// <summary>
/// A dudect-style acceptance test for the BLS12-381 constant-time scalar-multiply
/// backend, run two ways through <see cref="TimingLeakageHarness"/>. The first
/// run is a negative control against the variable-time
/// <see cref="Bls12Curve381BigIntegerG1Reference"/> ladder, whose runtime depends on the
/// scalar's minimal byte length — it must reject, proving the harness has teeth
/// against a known leak. The second run measures
/// <see cref="Bls12Curve381ConstantTimeG1Backend"/> and only asserts that a verdict was
/// reached (report-not-fail): a shared runner's timing noise makes the direction
/// of that verdict unreliable to assert on.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381ConstantTimeG1TimingHarnessTests
{
    /// <summary>
    /// A modest live-measurement budget: enough to reach a decisive verdict quickly
    /// on a shared runner, far below a real leakage assessment's budget.
    /// </summary>
    private const int MeasurementCount = 20000;
    /// <summary>
    /// A modest live-measurement budget: enough to reach a decisive verdict quickly
    /// on a shared runner, far below a real leakage assessment's budget.
    /// </summary>
    private const int WarmupCount = 2000;
    private const int ScalarInputLength = 32;

    /// <summary>
    /// Compressed BLS12-381 G1 point: the 48-byte x-coordinate with the flag bits in byte zero.
    /// </summary>
    private const int CompressedPointSize = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;

    /// <summary>
    /// The fixed class's scalar: the minimal nonzero magnitude, so it sits at the far end of the
    /// reference ladder's magnitude channel from a full-width random scalar.
    /// </summary>
    private const byte FixedScalarValue = 1;

    /// <summary>
    /// The base point is public data at every secret-scalar call site, so a single shared encoding is
    /// safe to reuse as the fixed base point across both measurement runs. It must be captured by both
    /// TimedOperation closures below, so it lives on the heap rather than as a stackalloc span.
    /// </summary>
    private static byte[] GeneratorPoint { get; } = WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.Bls12Curve381).ToArray();


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void ReferenceLadderLeaksUnderTheHarness()
    {
        //TimedOperation is a delegate the harness stores and calls from inside its measurement loop, so
        //the result buffer it writes into must be captured by the closure - a stackalloc span cannot
        //survive past this method, so a heap byte[] is unavoidable here.
        byte[] result = new byte[CompressedPointSize];
        G1ScalarMultiplyDelegate referenceScalarMultiply = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

        StatisticalTestResult verdict = TimingLeakageHarness.Measure(
            input => referenceScalarMultiply(GeneratorPoint, input, result, CurveParameterSet.Bls12Curve381),
            PrepareScalarInput,
            ScalarInputLength,
            MeasurementCount,
            WarmupCount);

        //The reference walks the minimal big-endian byte length of the scalar (see
        //Bls12Curve381BigIntegerG1Reference.ScalarMultiplyPoint), so the fixed class (k = 1, ~8 ladder
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
        G1ScalarMultiplyDelegate constantTimeScalarMultiply = Bls12Curve381ConstantTimeG1Backend.GetScalarMultiply();

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

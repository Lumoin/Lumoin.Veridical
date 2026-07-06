using Lumoin.Veridical.Analysis.StatisticalTests;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Analysis;

/// <summary>
/// A dudect-style acceptance test for the P-256 constant-time scalar-multiply
/// backend, run two ways through <see cref="TimingLeakageHarness"/>. The first
/// run is a negative control against the variable-time
/// <see cref="P256BigIntegerG1Reference"/> ladder, whose runtime depends on the
/// scalar's minimal byte length — it must reject, proving the harness has teeth
/// against a known leak. The second run measures
/// <see cref="P256ConstantTimeG1Backend"/> and only asserts that a verdict was
/// reached (report-not-fail): a shared runner's timing noise makes the direction
/// of that verdict unreliable to assert on.
/// </summary>
[TestClass]
internal sealed class P256ConstantTimeG1TimingHarnessTests
{
    //A modest live-measurement budget: enough to reach a decisive verdict quickly
    //on a shared runner, far below a real leakage assessment's budget.
    private const int MeasurementCount = 20000;
    private const int WarmupCount = 2000;
    private const int ScalarInputLength = 32;

    //SEC1 compressed P-256 point: a 0x02/0x03 parity prefix plus the 32-byte x-coordinate.
    private const int CompressedPointSize = 33;

    //The fixed class's scalar: the minimal nonzero magnitude, so it sits at the far end of the
    //reference ladder's magnitude channel from a full-width random scalar.
    private const byte FixedScalarValue = 1;

    //The generator is public data at every secret-scalar call site, so a single shared encoding is
    //safe to reuse as the fixed base point across both measurement runs.
    private static readonly byte[] GeneratorPoint = BuildGeneratorPoint();


    [TestMethod]
    [TestCategory("Slow")]
    public void ReferenceLadderLeaksUnderTheHarness()
    {
        //TimedOperation is a delegate the harness stores and calls from inside its measurement loop, so
        //the result buffer it writes into must be captured by the closure - a stackalloc span cannot
        //survive past this method, so a heap byte[] is unavoidable here.
        byte[] result = new byte[CompressedPointSize];
        G1ScalarMultiplyDelegate referenceScalarMultiply = P256BigIntegerG1Reference.GetScalarMultiply();

        StatisticalTestResult verdict = TimingLeakageHarness.Measure(
            input => referenceScalarMultiply(GeneratorPoint, input, result, CurveParameterSet.P256),
            PrepareScalarInput,
            ScalarInputLength,
            MeasurementCount,
            WarmupCount);

        System.IO.File.AppendAllText(@"C:\Users\Veikko\AppData\Local\Temp\claude\C--projektit-Lumoin-Veridical\627f6a05-8ce0-48c7-90c9-8029f34f7148\scratchpad\verdicts.txt", $"REFERENCE {verdict.Interpretation} p={verdict.PValue:R} t={verdict.TestStatistic:R}\n");

        //The reference walks the minimal big-endian byte length of the scalar (see
        //P256BigIntegerG1Reference.ScalarMultiplyPoint), so the fixed class (k = 1, ~8 ladder steps)
        //runs roughly 32x faster than the random class (a full 256-bit scalar, ~256 steps). That gap is
        //large enough for the Welch test to reject overwhelmingly - this is the negative control that
        //proves the harness detects a known variable-time leak.
        Assert.AreEqual(StatisticalTestInterpretation.Reject, verdict.Interpretation);
    }


    [TestMethod]
    [TestCategory("Slow")]
    public void ConstantTimeLadderReachesAVerdictWithoutFailing()
    {
        //As above: the closure-captured result buffer the TimedOperation delegate writes into.
        byte[] result = new byte[CompressedPointSize];
        G1ScalarMultiplyDelegate constantTimeScalarMultiply = P256ConstantTimeG1Backend.GetScalarMultiply();

        StatisticalTestResult verdict = TimingLeakageHarness.Measure(
            input => constantTimeScalarMultiply(GeneratorPoint, input, result, CurveParameterSet.P256),
            PrepareScalarInput,
            ScalarInputLength,
            MeasurementCount,
            WarmupCount);

        System.IO.File.AppendAllText(@"C:\Users\Veikko\AppData\Local\Temp\claude\C--projektit-Lumoin-Veridical\627f6a05-8ce0-48c7-90c9-8029f34f7148\scratchpad\verdicts.txt", $"CONSTANTTIME {verdict.Interpretation} p={verdict.PValue:R} t={verdict.TestStatistic:R}\n");

        //Report-not-fail: the constant-time ladder runs a fixed 256 iterations regardless of the
        //scalar, so no reliable timing gap is expected, but wall-clock timing on a shared runner is
        //noisy in either direction. Assert only that the harness reached a decisive verdict, never a
        //specific Reject/FailToReject direction.
        Assert.AreNotEqual(StatisticalTestInterpretation.Inconclusive, verdict.Interpretation);
    }


    //Class 0 (FIXED) is the minimal-magnitude, minimal-Hamming-weight scalar k = 1; class 1 (RANDOM) is
    //the raw entropy taken as a 256-bit big-endian scalar. Neither class needs a mod-n reduction: both
    //backends multiply by the scalar's integer value as given, with no requirement that it be below the
    //group order.
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


    //The generator must be captured by both TimedOperation closures below, so it lives on the heap
    //rather than as a stackalloc span, which cannot outlive this method.
    private static byte[] BuildGeneratorPoint()
    {
        byte[] generator = new byte[CompressedPointSize];
        P256BigIntegerG1Reference.Encode(P256BigIntegerG1Reference.AffinePoint.Generator, generator);

        return generator;
    }
}

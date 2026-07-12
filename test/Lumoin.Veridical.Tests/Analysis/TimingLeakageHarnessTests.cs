using Lumoin.Veridical.Analysis.StatisticalTests;
using System;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Analysis;

/// <summary>
/// Tests the dudect-style timing harness. The crop-and-Welch decision is exercised
/// deterministically over synthetic timing samples — identical distributions fail
/// to reject, a mean shift rejects, and a shift masked by a shared slow tail is
/// unmasked by the crop. A [Slow] end-to-end measurement confirms the live loop
/// reaches a decisive verdict without asserting a noise-sensitive direction.
/// </summary>
[TestClass]
internal sealed class TimingLeakageHarnessTests
{
    //Enough synthetic observations per class that the Welch dof is comfortably
    //large and the crop percentiles land on clean boundaries.
    private const int SyntheticSamplesPerClass = 1000;

    //A modest live-measurement budget: enough to reach a decisive verdict quickly
    //on a shared runner, far below a real leakage assessment's budget.
    private const int SlowMeasurementCount = 20000;
    private const int SlowWarmupCount = 2000;
    private const int SlowInputLength = 32;


    [TestMethod]
    public void DetectIdenticalDistributionsFailToReject()
    {
        double[] classZero = BuildJittered(100.0, SyntheticSamplesPerClass);
        double[] classOne = BuildJittered(100.0, SyntheticSamplesPerClass);

        StatisticalTestResult result = TimingLeakageHarness.Detect(classZero, classOne);

        Assert.AreEqual(StatisticalTestInterpretation.FailToReject, result.Interpretation);
    }


    [TestMethod]
    public void DetectMeanShiftRejects()
    {
        double[] classZero = BuildJittered(100.0, SyntheticSamplesPerClass);
        double[] classOne = BuildJittered(140.0, SyntheticSamplesPerClass);

        StatisticalTestResult result = TimingLeakageHarness.Detect(classZero, classOne);

        Assert.AreEqual(StatisticalTestInterpretation.Reject, result.Interpretation);
        Assert.IsLessThan(0.05, result.PValue);
    }


    [TestMethod]
    public void DetectUnmasksAShiftHiddenUnderASharedSlowTail()
    {
        //Both classes carry the same heavy scheduling-noise tail. The untrimmed test
        //drowns the 40-unit core shift in the tail's variance, but a crop that drops
        //the shared tail exposes it — and Detect reports the strongest crop.
        double[] classZero = BuildJitteredWithTail(100.0, SyntheticSamplesPerClass);
        double[] classOne = BuildJitteredWithTail(140.0, SyntheticSamplesPerClass);

        StatisticalTestResult result = TimingLeakageHarness.Detect(classZero, classOne);

        Assert.AreEqual(StatisticalTestInterpretation.Reject, result.Interpretation);
    }


    [TestMethod]
    public void DetectTooFewObservationsIsInconclusive()
    {
        double[] single = [1.0];
        double[] other = BuildJittered(100.0, SyntheticSamplesPerClass);

        StatisticalTestResult result = TimingLeakageHarness.Detect(single, other);

        Assert.AreEqual(StatisticalTestInterpretation.Inconclusive, result.Interpretation);
    }


    [TestMethod]
    [TestCategory("Slow")]
    public void MeasureProducesADecisiveVerdict()
    {
        //Times a fixed-time comparison of the input against a zero reference under a
        //fixed versus random input class. On a shared runner the direction is noisy,
        //so this asserts only that the harness ran end to end and reached a verdict
        //(report-not-fail); a real assessment reads the statistic and p-value.
        StatisticalTestResult result = TimingLeakageHarness.Measure(
            static input =>
            {
                Span<byte> reference = stackalloc byte[SlowInputLength];
                _ = CryptographicOperations.FixedTimeEquals(input, reference);
            },
            static (classId, entropy, destination) =>
            {
                if(classId == 0)
                {
                    destination.Clear();
                }
                else
                {
                    entropy.CopyTo(destination);
                }
            },
            SlowInputLength,
            SlowMeasurementCount,
            SlowWarmupCount);

        Assert.AreNotEqual(StatisticalTestInterpretation.Inconclusive, result.Interpretation);
    }


    //A small deterministic spread over [baseline, baseline+0.9] so the sample
    //variance is positive (a constant sample is inconclusive) while the class mean
    //stays at the baseline.
    private static double[] BuildJittered(double baseline, int count)
    {
        double[] values = new double[count];
        for(int i = 0; i < count; i++)
        {
            values[i] = baseline + ((i % 10) * 0.1);
        }

        return values;
    }


    //As BuildJittered, but one observation in ten is a large shared outlier — the
    //slow tail OS scheduling adds equally to both classes. The tail is exactly a
    //tenth of the sample, so the 0.9 crop removes it while leaving the core.
    private static double[] BuildJitteredWithTail(double baseline, int count)
    {
        double[] values = BuildJittered(baseline, count);
        for(int i = 0; i < count; i += 10)
        {
            values[i] = 50000.0;
        }

        return values;
    }
}

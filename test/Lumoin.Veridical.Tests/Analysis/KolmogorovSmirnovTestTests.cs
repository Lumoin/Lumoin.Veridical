using Lumoin.Veridical.Analysis.StatisticalTests;
using System;

namespace Lumoin.Veridical.Tests.Analysis;

/// <summary>
/// Behavioural tests for the two-sample Kolmogorov-Smirnov test: identical and
/// same-distribution samples fail to reject; clearly-separated samples reject;
/// degenerate inputs are inconclusive.
/// </summary>
[TestClass]
internal sealed class KolmogorovSmirnovTestTests
{
    [TestMethod]
    public void IdenticalSamplesFailToReject()
    {
        double[] sample = BuildArithmetic(0.0, 1.0, 200);

        StatisticalTestResult result = KolmogorovSmirnovTest.TwoSample(sample, sample);

        Assert.AreEqual(StatisticalTestInterpretation.FailToReject, result.Interpretation);
        Assert.AreEqual(0.0, result.TestStatistic, 1e-12, "Identical samples have zero supremum distance.");
    }


    [TestMethod]
    public void SameDistributionFailsToReject()
    {
        //Two interleaved arithmetic ramps over the same range: same empirical
        //distribution, so the KS distance is small and the null is not rejected.
        double[] first = BuildArithmetic(0.0, 2.0, 100);
        double[] second = BuildArithmetic(1.0, 2.0, 100);

        StatisticalTestResult result = KolmogorovSmirnovTest.TwoSample(first, second);

        Assert.AreEqual(StatisticalTestInterpretation.FailToReject, result.Interpretation);
    }


    [TestMethod]
    public void DisjointSamplesReject()
    {
        //Completely separated supports: the empirical CDFs diverge to a distance
        //of 1, so the test rejects decisively.
        double[] low = BuildArithmetic(0.0, 1.0, 100);
        double[] high = BuildArithmetic(1000.0, 1.0, 100);

        StatisticalTestResult result = KolmogorovSmirnovTest.TwoSample(low, high);

        Assert.AreEqual(StatisticalTestInterpretation.Reject, result.Interpretation);
        Assert.AreEqual(1.0, result.TestStatistic, 1e-12, "Disjoint supports give a supremum distance of one.");
        Assert.IsLessThan(0.05, result.PValue);
    }


    [TestMethod]
    public void TooFewObservationsAreInconclusive()
    {
        double[] single = [1.0];
        double[] other = [1.0, 2.0, 3.0];

        StatisticalTestResult result = KolmogorovSmirnovTest.TwoSample(single, other);

        Assert.AreEqual(StatisticalTestInterpretation.Inconclusive, result.Interpretation);
    }


    [TestMethod]
    public void SignificanceLevelOutOfRangeThrows()
    {
        double[] a = [1.0, 2.0];
        double[] b = [3.0, 4.0];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => KolmogorovSmirnovTest.TwoSample(a, b, 0.0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => KolmogorovSmirnovTest.TwoSample(a, b, 1.0));
    }


    private static double[] BuildArithmetic(double start, double step, int count)
    {
        double[] values = new double[count];
        for(int i = 0; i < count; i++)
        {
            values[i] = start + (step * i);
        }

        return values;
    }
}

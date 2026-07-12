using Lumoin.Veridical.Analysis.StatisticalTests;
using System;

namespace Lumoin.Veridical.Tests.Analysis;

/// <summary>
/// Behavioural tests for Welch's two-sample t-test: identical samples fail to
/// reject, a large mean separation rejects, the statistic matches its hand
/// computation and is antisymmetric under swapping, and degenerate inputs are
/// inconclusive.
/// </summary>
[TestClass]
internal sealed class WelchTTestTests
{
    [TestMethod]
    public void IdenticalSamplesFailToReject()
    {
        double[] sample = BuildArithmetic(10.0, 0.5, 50);

        StatisticalTestResult result = WelchTTest.TwoSample(sample, sample);

        Assert.AreEqual(StatisticalTestInterpretation.FailToReject, result.Interpretation);
        Assert.AreEqual(0.0, result.TestStatistic, 1e-12, "Identical samples have zero mean difference.");
        Assert.AreEqual(1.0, result.PValue, 1e-9, "A zero statistic is the least extreme, so p = 1.");
    }


    [TestMethod]
    public void StatisticMatchesHandComputation()
    {
        //first = 1..5 (mean 3, sample variance 2.5, n 5); second = 6..10 (mean 8,
        //variance 2.5, n 5). t = (3 − 8) / √(2.5/5 + 2.5/5) = −5 / √1 = −5.
        double[] first = [1.0, 2.0, 3.0, 4.0, 5.0];
        double[] second = [6.0, 7.0, 8.0, 9.0, 10.0];

        StatisticalTestResult result = WelchTTest.TwoSample(first, second);

        Assert.AreEqual(-5.0, result.TestStatistic, 1e-12);
        Assert.AreEqual(StatisticalTestInterpretation.Reject, result.Interpretation);
        Assert.IsLessThan(0.05, result.PValue);
        Assert.IsGreaterThan(0.0, result.PValue);
    }


    [TestMethod]
    public void SwappingSamplesNegatesStatisticAndKeepsPValue()
    {
        double[] first = [1.0, 2.0, 3.0, 4.0, 5.0];
        double[] second = [6.0, 7.0, 8.0, 9.0, 10.0];

        StatisticalTestResult forward = WelchTTest.TwoSample(first, second);
        StatisticalTestResult reversed = WelchTTest.TwoSample(second, first);

        Assert.AreEqual(-forward.TestStatistic, reversed.TestStatistic, 1e-12);
        Assert.AreEqual(forward.PValue, reversed.PValue, 1e-12);
    }


    [TestMethod]
    public void ConstantSamplesAreInconclusive()
    {
        //No spread in either class: the pooled standard error is zero, so the
        //statistic is undefined and the test is inconclusive.
        double[] first = [5.0, 5.0, 5.0, 5.0];
        double[] second = [7.0, 7.0, 7.0, 7.0];

        StatisticalTestResult result = WelchTTest.TwoSample(first, second);

        Assert.AreEqual(StatisticalTestInterpretation.Inconclusive, result.Interpretation);
    }


    [TestMethod]
    public void TooFewObservationsAreInconclusive()
    {
        double[] single = [1.0];
        double[] other = [1.0, 2.0, 3.0];

        StatisticalTestResult result = WelchTTest.TwoSample(single, other);

        Assert.AreEqual(StatisticalTestInterpretation.Inconclusive, result.Interpretation);
    }


    [TestMethod]
    public void SignificanceLevelOutOfRangeThrows()
    {
        double[] a = [1.0, 2.0, 3.0];
        double[] b = [4.0, 5.0, 6.0];

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => WelchTTest.TwoSample(a, b, 0.0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => WelchTTest.TwoSample(a, b, 1.0));
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

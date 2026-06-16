using Lumoin.Veridical.Analysis.StatisticalTests;
using System;

namespace Lumoin.Veridical.Tests.Analysis;

/// <summary>
/// Behavioural tests for the chi-squared goodness-of-fit and homogeneity tests,
/// including a textbook worked example whose statistic and verdict are known.
/// </summary>
[TestClass]
internal sealed class ChiSquaredTestTests
{
    [TestMethod]
    public void GoodnessOfFitMatchesUniformExpectation()
    {
        //Observed counts equal to expectation give a zero statistic and p = 1.
        long[] observed = [10, 10, 10, 10, 10, 10];
        double[] expected = [10, 10, 10, 10, 10, 10];

        StatisticalTestResult result = ChiSquaredTest.GoodnessOfFit(observed, expected);

        Assert.AreEqual(0.0, result.TestStatistic, 1e-12);
        Assert.AreEqual(1.0, result.PValue, 1e-12);
        Assert.AreEqual(5, result.DegreesOfFreedom);
        Assert.AreEqual(StatisticalTestInterpretation.FailToReject, result.Interpretation);
    }


    [TestMethod]
    public void GoodnessOfFitWorkedExampleMatchesKnownStatistic()
    {
        //Classic fair-die example: 60 rolls, observed [5,8,9,8,10,20], expected
        //10 each. Statistic = Σ (O−E)²/E = (25+4+1+4+0+100)/10 = 13.4, 5 dof.
        //The 5% critical value is 11.07, so 13.4 rejects.
        long[] observed = [5, 8, 9, 8, 10, 20];
        double[] expected = [10, 10, 10, 10, 10, 10];

        StatisticalTestResult result = ChiSquaredTest.GoodnessOfFit(observed, expected);

        Assert.AreEqual(13.4, result.TestStatistic, 1e-9);
        Assert.AreEqual(5, result.DegreesOfFreedom);
        Assert.AreEqual(StatisticalTestInterpretation.Reject, result.Interpretation);
        Assert.IsLessThan(0.05, result.PValue);
    }


    [TestMethod]
    public void HomogeneityOfIdenticalDistributionsFailsToReject()
    {
        long[] first = [50, 60, 40, 50];
        long[] second = [50, 60, 40, 50];

        StatisticalTestResult result = ChiSquaredTest.Homogeneity(first, second);

        Assert.AreEqual(0.0, result.TestStatistic, 1e-9);
        Assert.AreEqual(StatisticalTestInterpretation.FailToReject, result.Interpretation);
    }


    [TestMethod]
    public void HomogeneityOfDivergentDistributionsRejects()
    {
        //Opposite skews over the same bins, ample counts: the homogeneity null is
        //rejected decisively.
        long[] first = [200, 150, 100, 50];
        long[] second = [50, 100, 150, 200];

        StatisticalTestResult result = ChiSquaredTest.Homogeneity(first, second);

        Assert.AreEqual(StatisticalTestInterpretation.Reject, result.Interpretation);
        Assert.IsLessThan(0.05, result.PValue);
    }


    [TestMethod]
    public void GoodnessOfFitWithNonPositiveExpectedIsInconclusive()
    {
        long[] observed = [10, 0, 10];
        double[] expected = [10, 0, 10];

        StatisticalTestResult result = ChiSquaredTest.GoodnessOfFit(observed, expected);

        Assert.AreEqual(StatisticalTestInterpretation.Inconclusive, result.Interpretation);
    }


    [TestMethod]
    public void MismatchedLengthsThrow()
    {
        long[] observed = [1, 2, 3];
        double[] expected = [1, 2];

        Assert.ThrowsExactly<ArgumentException>(() => ChiSquaredTest.GoodnessOfFit(observed, expected));
    }
}

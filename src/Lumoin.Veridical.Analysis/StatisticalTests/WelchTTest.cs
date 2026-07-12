using System;

namespace Lumoin.Veridical.Analysis.StatisticalTests;

/// <summary>
/// Welch's two-sample t-test: tests whether two samples share a mean without
/// assuming they share a variance. The statistic is the difference of means over
/// the pooled standard error <c>√(s₁²/n₁ + s₂²/n₂)</c>; the degrees of freedom
/// follow the Welch–Satterthwaite approximation and the p-value comes from the
/// Student's t distribution. This is the statistic the dudect constant-time
/// methodology reads: the two samples are one operation's timings under a fixed
/// versus a random secret class, and a rejected null is evidence of a
/// data-dependent code path.
/// </summary>
public static class WelchTTest
{
    /// <summary>
    /// Tests whether <paramref name="first"/> and <paramref name="second"/> share
    /// a mean. The null hypothesis is that they do; a small p-value rejects it.
    /// The test is two-tailed.
    /// </summary>
    /// <param name="first">The first sample of real-valued observations.</param>
    /// <param name="second">The second sample.</param>
    /// <param name="significanceLevel">The significance level the verdict is taken against (for example 0.05).</param>
    /// <returns>
    /// The signed t statistic, the two-tailed p-value, and the verdict. A sample
    /// with fewer than two observations, or two samples with no combined variance,
    /// yield <see cref="StatisticalTestInterpretation.Inconclusive"/>.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="significanceLevel"/> is outside <c>(0, 1)</c>.</exception>
    public static StatisticalTestResult TwoSample(ReadOnlySpan<double> first, ReadOnlySpan<double> second, double significanceLevel = 0.05)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(significanceLevel, 0.0);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(significanceLevel, 1.0);

        if(first.Length < 2 || second.Length < 2)
        {
            return StatisticalTestResult.Inconclusive(significanceLevel);
        }

        (double meanFirst, double varianceFirst) = MeanAndVariance(first);
        (double meanSecond, double varianceSecond) = MeanAndVariance(second);

        double squaredErrorFirst = varianceFirst / first.Length;
        double squaredErrorSecond = varianceSecond / second.Length;
        double pooledSquaredError = squaredErrorFirst + squaredErrorSecond;

        //No spread in either sample: the means are equal with no scale to weigh a
        //difference against, or differ with none — nothing the t-test can rank.
        if(pooledSquaredError <= 0.0)
        {
            return StatisticalTestResult.Inconclusive(significanceLevel);
        }

        double tStatistic = (meanFirst - meanSecond) / Math.Sqrt(pooledSquaredError);

        //Welch–Satterthwaite degrees of freedom.
        double degreesOfFreedom = pooledSquaredError * pooledSquaredError
            / (((squaredErrorFirst * squaredErrorFirst) / (first.Length - 1))
                + ((squaredErrorSecond * squaredErrorSecond) / (second.Length - 1)));

        //Two-tailed Student's t p-value P(|T| ≥ |t|) = I_{v/(v+t²)}(v/2, 1/2).
        double betaArgument = degreesOfFreedom / (degreesOfFreedom + (tStatistic * tStatistic));
        double pValue = StatisticalSpecialFunctions.RegularizedIncompleteBeta(degreesOfFreedom / 2.0, 0.5, betaArgument);

        return StatisticalTestResult.Decisive(tStatistic, degreesOfFreedom: null, pValue, significanceLevel);
    }


    //Sample mean and unbiased (n−1) sample variance in one numerically stable
    //Welford pass.
    private static (double Mean, double Variance) MeanAndVariance(ReadOnlySpan<double> sample)
    {
        double mean = 0.0;
        double sumSquaredDeviations = 0.0;
        int count = 0;
        foreach(double value in sample)
        {
            count++;
            double delta = value - mean;
            mean += delta / count;
            sumSquaredDeviations += delta * (value - mean);
        }

        double variance = sumSquaredDeviations / (count - 1);

        return (mean, variance);
    }
}

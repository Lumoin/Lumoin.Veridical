using System;

namespace Lumoin.Veridical.Analysis.StatisticalTests;

/// <summary>
/// Pearson chi-squared tests over categorical counts: a goodness-of-fit test of
/// observed counts against an expected distribution, and a homogeneity test of
/// whether two count vectors (two empirical distributions over the same bins)
/// come from the same distribution. The p-value is the chi-squared survival
/// function (the regularized upper incomplete gamma).
/// </summary>
public static class ChiSquaredTest
{
    //Pearson's approximation degrades when expected cell counts are very small.
    //Below this floor a cell makes the test unreliable; the whole test is then
    //reported inconclusive rather than producing a misleading p-value.
    private const double MinimumExpectedCount = 1.0;


    /// <summary>
    /// Goodness-of-fit: tests whether <paramref name="observed"/> counts are
    /// consistent with <paramref name="expected"/> counts (same length, same
    /// total ideally). Degrees of freedom are <c>bins − 1</c>.
    /// </summary>
    /// <param name="observed">The observed counts per bin.</param>
    /// <param name="expected">The expected counts per bin; each must be positive.</param>
    /// <param name="significanceLevel">The significance level (for example 0.05).</param>
    /// <returns>The statistic, degrees of freedom, p-value, and verdict. Fewer than two bins, or any expected count below the reliability floor, yields <see cref="StatisticalTestInterpretation.Inconclusive"/>.</returns>
    /// <exception cref="ArgumentException">When the spans differ in length.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="significanceLevel"/> is outside <c>(0, 1)</c>.</exception>
    public static StatisticalTestResult GoodnessOfFit(ReadOnlySpan<long> observed, ReadOnlySpan<double> expected, double significanceLevel = 0.05)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(significanceLevel, 0.0);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(significanceLevel, 1.0);
        if(observed.Length != expected.Length)
        {
            throw new ArgumentException($"Observed ({observed.Length}) and expected ({expected.Length}) must have the same number of bins.", nameof(expected));
        }

        int bins = observed.Length;
        if(bins < 2)
        {
            return StatisticalTestResult.Inconclusive(significanceLevel);
        }

        double statistic = 0.0;
        for(int i = 0; i < bins; i++)
        {
            if(expected[i] < MinimumExpectedCount)
            {
                return StatisticalTestResult.Inconclusive(significanceLevel, bins - 1);
            }

            double difference = observed[i] - expected[i];
            statistic += difference * difference / expected[i];
        }

        int degreesOfFreedom = bins - 1;
        double pValue = StatisticalSpecialFunctions.RegularizedUpperIncompleteGamma(degreesOfFreedom / 2.0, statistic / 2.0);

        return StatisticalTestResult.Decisive(statistic, degreesOfFreedom, pValue, significanceLevel);
    }


    /// <summary>
    /// Homogeneity: tests whether two empirical distributions <paramref name="first"/>
    /// and <paramref name="second"/> over the same bins come from the same
    /// underlying distribution, via the 2×<c>k</c> contingency table. Degrees of
    /// freedom are <c>bins − 1</c>.
    /// </summary>
    /// <param name="first">The first distribution's per-bin counts.</param>
    /// <param name="second">The second distribution's per-bin counts (same length).</param>
    /// <param name="significanceLevel">The significance level (for example 0.05).</param>
    /// <returns>The statistic, degrees of freedom, p-value, and verdict. Bins with a zero combined total are dropped (they contribute no information); fewer than two surviving bins, an empty row, or an expected cell below the reliability floor yields <see cref="StatisticalTestInterpretation.Inconclusive"/>.</returns>
    /// <exception cref="ArgumentException">When the spans differ in length.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="significanceLevel"/> is outside <c>(0, 1)</c>.</exception>
    public static StatisticalTestResult Homogeneity(ReadOnlySpan<long> first, ReadOnlySpan<long> second, double significanceLevel = 0.05)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(significanceLevel, 0.0);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(significanceLevel, 1.0);
        if(first.Length != second.Length)
        {
            throw new ArgumentException($"The two distributions must have the same number of bins; received {first.Length} and {second.Length}.", nameof(second));
        }

        long rowTotalFirst = 0;
        long rowTotalSecond = 0;
        int usableBins = 0;
        for(int i = 0; i < first.Length; i++)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(first[i]);
            ArgumentOutOfRangeException.ThrowIfNegative(second[i]);
            rowTotalFirst += first[i];
            rowTotalSecond += second[i];
            if(first[i] + second[i] > 0)
            {
                usableBins++;
            }
        }

        long grandTotal = rowTotalFirst + rowTotalSecond;
        if(usableBins < 2 || rowTotalFirst == 0 || rowTotalSecond == 0)
        {
            return StatisticalTestResult.Inconclusive(significanceLevel);
        }

        //Expected cell = rowTotal · columnTotal / grandTotal. Sum the Pearson
        //terms over both rows of every bin with a non-zero column total.
        double statistic = 0.0;
        for(int i = 0; i < first.Length; i++)
        {
            long columnTotal = first[i] + second[i];
            if(columnTotal == 0)
            {
                continue;
            }

            double expectedFirst = (double)rowTotalFirst * columnTotal / grandTotal;
            double expectedSecond = (double)rowTotalSecond * columnTotal / grandTotal;
            if(expectedFirst < MinimumExpectedCount || expectedSecond < MinimumExpectedCount)
            {
                return StatisticalTestResult.Inconclusive(significanceLevel, usableBins - 1);
            }

            double differenceFirst = first[i] - expectedFirst;
            double differenceSecond = second[i] - expectedSecond;
            statistic += (differenceFirst * differenceFirst / expectedFirst) + (differenceSecond * differenceSecond / expectedSecond);
        }

        int degreesOfFreedom = usableBins - 1;
        double pValue = StatisticalSpecialFunctions.RegularizedUpperIncompleteGamma(degreesOfFreedom / 2.0, statistic / 2.0);

        return StatisticalTestResult.Decisive(statistic, degreesOfFreedom, pValue, significanceLevel);
    }
}

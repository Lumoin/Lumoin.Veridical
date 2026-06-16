using System.Diagnostics;

namespace Lumoin.Veridical.Analysis.StatisticalTests;

/// <summary>
/// The outcome of a statistical hypothesis test: the test statistic, the
/// degrees of freedom (where the test has them), the p-value, the significance
/// level the verdict was taken against, and the <see cref="StatisticalTestInterpretation"/>.
/// </summary>
/// <remarks>
/// A small p-value means the observed difference is unlikely under the null
/// hypothesis. The <see cref="Interpretation"/> compares the p-value to
/// <see cref="SignificanceLevel"/>: below it rejects the null, at or above it
/// fails to reject. A degenerate test (no usable data) is
/// <see cref="StatisticalTestInterpretation.Inconclusive"/> with a p-value that
/// should not be read.
/// </remarks>
[DebuggerDisplay("{Interpretation} (statistic = {TestStatistic}, p = {PValue}, alpha = {SignificanceLevel})")]
public readonly record struct StatisticalTestResult
{
    /// <summary>The computed test statistic.</summary>
    public double TestStatistic { get; }

    /// <summary>The degrees of freedom, for tests that have them (chi-squared); <see langword="null"/> otherwise (Kolmogorov-Smirnov).</summary>
    public int? DegreesOfFreedom { get; }

    /// <summary>The probability, under the null hypothesis, of a statistic at least as extreme as <see cref="TestStatistic"/>.</summary>
    public double PValue { get; }

    /// <summary>The significance level the verdict was taken against (for example 0.05).</summary>
    public double SignificanceLevel { get; }

    /// <summary>The verdict.</summary>
    public StatisticalTestInterpretation Interpretation { get; }


    private StatisticalTestResult(
        double testStatistic,
        int? degreesOfFreedom,
        double pValue,
        double significanceLevel,
        StatisticalTestInterpretation interpretation)
    {
        TestStatistic = testStatistic;
        DegreesOfFreedom = degreesOfFreedom;
        PValue = pValue;
        SignificanceLevel = significanceLevel;
        Interpretation = interpretation;
    }


    /// <summary>
    /// Builds a decisive result, deriving the interpretation from the p-value:
    /// <see cref="StatisticalTestInterpretation.Reject"/> when
    /// <paramref name="pValue"/> is below <paramref name="significanceLevel"/>,
    /// otherwise <see cref="StatisticalTestInterpretation.FailToReject"/>.
    /// </summary>
    public static StatisticalTestResult Decisive(double testStatistic, int? degreesOfFreedom, double pValue, double significanceLevel)
    {
        StatisticalTestInterpretation interpretation = pValue < significanceLevel
            ? StatisticalTestInterpretation.Reject
            : StatisticalTestInterpretation.FailToReject;

        return new StatisticalTestResult(testStatistic, degreesOfFreedom, pValue, significanceLevel, interpretation);
    }


    /// <summary>
    /// Builds an <see cref="StatisticalTestInterpretation.Inconclusive"/> result
    /// for a test that could not be evaluated on the supplied data. The statistic
    /// and p-value carry <see cref="double.NaN"/>.
    /// </summary>
    public static StatisticalTestResult Inconclusive(double significanceLevel, int? degreesOfFreedom = null)
    {
        return new StatisticalTestResult(double.NaN, degreesOfFreedom, double.NaN, significanceLevel, StatisticalTestInterpretation.Inconclusive);
    }
}

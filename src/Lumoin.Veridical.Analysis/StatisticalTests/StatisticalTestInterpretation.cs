namespace Lumoin.Veridical.Analysis.StatisticalTests;

/// <summary>
/// The verdict of a statistical hypothesis test against its null hypothesis.
/// </summary>
public enum StatisticalTestInterpretation
{
    /// <summary>
    /// The test could not be evaluated meaningfully (degenerate input — empty or
    /// constant samples, non-positive expected counts). No conclusion is drawn;
    /// the p-value is not interpretable.
    /// </summary>
    Inconclusive = 0,

    /// <summary>
    /// The null hypothesis is rejected at the chosen significance level (the
    /// p-value is below it): the samples differ more than chance would explain.
    /// </summary>
    Reject = 1,

    /// <summary>
    /// The null hypothesis is not rejected at the chosen significance level (the
    /// p-value is at or above it): the test found no significant difference. This
    /// is not positive evidence of equality — only an absence of detected
    /// difference at the tested scale.
    /// </summary>
    FailToReject = 2
}

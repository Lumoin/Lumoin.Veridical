using System;

namespace Lumoin.Veridical.Analysis.StatisticalTests;

/// <summary>
/// The two-sample Kolmogorov-Smirnov test: a distribution-free test of whether
/// two samples are drawn from the same continuous distribution. The statistic
/// is the supremum distance between the two empirical cumulative distribution
/// functions; the p-value comes from the asymptotic Kolmogorov distribution.
/// </summary>
/// <remarks>
/// The test is a static function over two real-valued samples. A caller
/// comparing non-numeric artifacts (proof bytes, codeword positions) first
/// projects each artifact to a real-valued metric — the comparison metric the
/// caller chooses — and passes the two resulting samples here.
/// </remarks>
public static class KolmogorovSmirnovTest
{
    /// <summary>
    /// Tests whether <paramref name="first"/> and <paramref name="second"/> are
    /// drawn from the same distribution. The null hypothesis is that they are;
    /// a small p-value rejects it.
    /// </summary>
    /// <param name="first">The first sample of real-valued observations.</param>
    /// <param name="second">The second sample.</param>
    /// <param name="significanceLevel">The significance level the verdict is taken against (for example 0.05).</param>
    /// <returns>The test statistic <c>D</c>, the p-value, and the verdict. Empty or single-element samples yield <see cref="StatisticalTestInterpretation.Inconclusive"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="significanceLevel"/> is outside <c>(0, 1)</c>.</exception>
    public static StatisticalTestResult TwoSample(ReadOnlySpan<double> first, ReadOnlySpan<double> second, double significanceLevel = 0.05)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(significanceLevel, 0.0);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(significanceLevel, 1.0);

        if(first.Length < 2 || second.Length < 2)
        {
            return StatisticalTestResult.Inconclusive(significanceLevel);
        }

        double[] a = first.ToArray();
        double[] b = second.ToArray();
        Array.Sort(a);
        Array.Sort(b);

        int na = a.Length;
        int nb = b.Length;
        int i = 0;
        int j = 0;
        double cumulativeA = 0.0;
        double cumulativeB = 0.0;
        double distance = 0.0;

        //Walk the merged order of the two sorted samples, advancing the empirical
        //CDFs in lockstep and tracking the largest gap between them. Ties (equal
        //values within or across samples) are advanced fully before measuring.
        while(i < na && j < nb)
        {
            double av = a[i];
            double bv = b[j];

            if(av <= bv)
            {
                double value = av;
                do
                {
                    i++;
                }
                while(i < na && a[i] == value);
                cumulativeA = (double)i / na;
            }

            if(bv <= av)
            {
                double value = bv;
                do
                {
                    j++;
                }
                while(j < nb && b[j] == value);
                cumulativeB = (double)j / nb;
            }

            double gap = Math.Abs(cumulativeA - cumulativeB);
            if(gap > distance)
            {
                distance = gap;
            }
        }

        //Asymptotic p-value: λ = (√n_e + 0.12 + 0.11/√n_e)·D with the effective
        //sample size n_e = n_a·n_b/(n_a+n_b); p = Q_KS(λ).
        double effectiveSize = (double)na * nb / (na + nb);
        double rootEffective = Math.Sqrt(effectiveSize);
        double lambda = (rootEffective + 0.12 + (0.11 / rootEffective)) * distance;
        double pValue = StatisticalSpecialFunctions.KolmogorovSurvival(lambda);

        return StatisticalTestResult.Decisive(distance, degreesOfFreedom: null, pValue, significanceLevel);
    }
}

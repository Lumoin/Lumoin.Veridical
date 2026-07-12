using System;

namespace Lumoin.Veridical.Analysis.StatisticalTests;

/// <summary>
/// The special functions the distribution tests need for their p-values: the
/// log-gamma function, the regularized upper incomplete gamma function (the
/// chi-squared survival function), and the Kolmogorov distribution survival
/// function. Implemented inline so the analysis layer carries no numeric-library
/// dependency; the implementations follow the standard Lanczos / series /
/// continued-fraction forms and are validated against published reference values
/// in the test suite.
/// </summary>
internal static class StatisticalSpecialFunctions
{
    //Convergence controls for the incomplete-gamma series and continued
    //fraction. The iteration cap is generous; convergence to the relative
    //tolerance happens far sooner for the arguments these tests produce.
    private const int MaximumIterations = 1000;
    private const double RelativeTolerance = 1e-14;

    //A floor that stands in for zero in the continued-fraction recurrence,
    //avoiding division by an exact zero (Numerical Recipes' "FPMIN").
    private const double Tiny = 1e-300;

    //Lanczos coefficients for g = 7, nine terms — the standard high-accuracy set.
    private static readonly double[] LanczosCoefficients =
    [
        0.99999999999980993,
        676.5203681218851,
        -1259.1392167224028,
        771.32342877765313,
        -176.61502916214059,
        12.507343278686905,
        -0.13857109526572012,
        9.9843695780195716e-6,
        1.5056327351493116e-7
    ];

    private const double LanczosG = 7.0;


    /// <summary>The natural logarithm of the gamma function, via the Lanczos approximation with the reflection formula for arguments below 0.5.</summary>
    internal static double LogGamma(double x)
    {
        if(x < 0.5)
        {
            //Reflection: Γ(x)·Γ(1−x) = π / sin(πx).
            return Math.Log(Math.PI / Math.Sin(Math.PI * x)) - LogGamma(1.0 - x);
        }

        double z = x - 1.0;
        double a = LanczosCoefficients[0];
        double t = z + LanczosG + 0.5;
        for(int i = 1; i < LanczosCoefficients.Length; i++)
        {
            a += LanczosCoefficients[i] / (z + i);
        }

        return (0.5 * Math.Log(2.0 * Math.PI)) + ((z + 0.5) * Math.Log(t)) - t + Math.Log(a);
    }


    /// <summary>
    /// The regularized upper incomplete gamma function <c>Q(a, x) = Γ(a, x) / Γ(a)</c>,
    /// equivalently the survival function of the gamma distribution. For a
    /// chi-squared statistic <c>X²</c> with <c>k</c> degrees of freedom the
    /// p-value is <c>Q(k/2, X²/2)</c>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="a"/> is not positive or <paramref name="x"/> is negative.</exception>
    internal static double RegularizedUpperIncompleteGamma(double a, double x)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(a);
        ArgumentOutOfRangeException.ThrowIfNegative(x);

        if(x == 0.0)
        {
            return 1.0;
        }

        //Below the transition point the lower series converges fastest; above it
        //the continued fraction for the upper function does.
        return x < a + 1.0
            ? 1.0 - LowerSeries(a, x)
            : UpperContinuedFraction(a, x);
    }


    /// <summary>
    /// The regularized incomplete beta function <c>I_x(a, b)</c>, the cumulative
    /// distribution function of the beta distribution. For a Student's t statistic
    /// <c>t</c> with <c>v</c> degrees of freedom the two-tailed p-value
    /// <c>P(|T| ≥ |t|)</c> is <c>I_{v/(v+t²)}(v/2, 1/2)</c>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="a"/> or <paramref name="b"/> is not positive.</exception>
    internal static double RegularizedIncompleteBeta(double a, double b, double x)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(a);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(b);

        if(x <= 0.0)
        {
            return 0.0;
        }

        if(x >= 1.0)
        {
            return 1.0;
        }

        //The normalising factor x^a·(1−x)^b / (a·B(a,b)) in front of both
        //continued-fraction branches, carried in log space for range.
        double logFront = LogGamma(a + b) - LogGamma(a) - LogGamma(b) + (a * Math.Log(x)) + (b * Math.Log(1.0 - x));
        double front = Math.Exp(logFront);

        //The continued fraction converges fastest where x sits below the mode; the
        //symmetry I_x(a,b) = 1 − I_{1−x}(b,a) reaches the other side.
        return x < (a + 1.0) / (a + b + 2.0)
            ? front * BetaContinuedFraction(a, b, x) / a
            : 1.0 - (front * BetaContinuedFraction(b, a, 1.0 - x) / b);
    }


    /// <summary>
    /// The survival function of the Kolmogorov distribution,
    /// <c>Q_KS(λ) = 2 · Σ_{j≥1} (−1)^{j−1} e^{−2 j² λ²}</c>, used for the
    /// two-sample Kolmogorov-Smirnov p-value. Clamped to <c>[0, 1]</c>.
    /// </summary>
    internal static double KolmogorovSurvival(double lambda)
    {
        if(lambda <= 0.0)
        {
            return 1.0;
        }

        double twoLambdaSquared = 2.0 * lambda * lambda;
        double sum = 0.0;
        for(int j = 1; j <= 100; j++)
        {
            double term = Math.Exp(-twoLambdaSquared * j * j);
            sum += ((j & 1) == 1 ? 1.0 : -1.0) * term;

            //Converged once the alternating terms are negligible relative to the
            //running sum.
            if(term <= RelativeTolerance * Math.Abs(sum) || term <= 1e-300)
            {
                break;
            }
        }

        double q = 2.0 * sum;

        return q < 0.0 ? 0.0 : (q > 1.0 ? 1.0 : q);
    }


    //Lower regularized incomplete gamma P(a, x) by its power series, valid and
    //fast for x < a + 1.
    private static double LowerSeries(double a, double x)
    {
        double logNormaliser = (a * Math.Log(x)) - x - LogGamma(a);
        double term = 1.0 / a;
        double sum = term;
        double denominator = a;
        for(int n = 0; n < MaximumIterations; n++)
        {
            denominator += 1.0;
            term *= x / denominator;
            sum += term;
            if(Math.Abs(term) < Math.Abs(sum) * RelativeTolerance)
            {
                break;
            }
        }

        return sum * Math.Exp(logNormaliser);
    }


    //Upper regularized incomplete gamma Q(a, x) by the Lentz continued fraction,
    //valid and fast for x >= a + 1.
    private static double UpperContinuedFraction(double a, double x)
    {
        double logNormaliser = (a * Math.Log(x)) - x - LogGamma(a);

        double b = x + 1.0 - a;
        double c = 1.0 / Tiny;
        double d = 1.0 / b;
        double h = d;
        for(int i = 1; i < MaximumIterations; i++)
        {
            double an = -i * (i - a);
            b += 2.0;
            d = (an * d) + b;
            if(Math.Abs(d) < Tiny)
            {
                d = Tiny;
            }

            c = b + (an / c);
            if(Math.Abs(c) < Tiny)
            {
                c = Tiny;
            }

            d = 1.0 / d;
            double delta = d * c;
            h *= delta;
            if(Math.Abs(delta - 1.0) < RelativeTolerance)
            {
                break;
            }
        }

        return Math.Exp(logNormaliser) * h;
    }


    //The modified Lentz continued fraction for the incomplete beta (Numerical
    //Recipes' "betacf") — the fraction RegularizedIncompleteBeta multiplies by its
    //leading factor. Alternating even/odd recurrence steps, guarded against a zero
    //denominator by the FPMIN floor as elsewhere in this file.
    private static double BetaContinuedFraction(double a, double b, double x)
    {
        double qab = a + b;
        double qap = a + 1.0;
        double qam = a - 1.0;
        double c = 1.0;
        double d = 1.0 - (qab * x / qap);
        if(Math.Abs(d) < Tiny)
        {
            d = Tiny;
        }

        d = 1.0 / d;
        double h = d;
        for(int m = 1; m < MaximumIterations; m++)
        {
            int twoM = 2 * m;

            //Even step d_{2m}.
            double even = m * (b - m) * x / ((qam + twoM) * (a + twoM));
            d = 1.0 + (even * d);
            if(Math.Abs(d) < Tiny)
            {
                d = Tiny;
            }

            c = 1.0 + (even / c);
            if(Math.Abs(c) < Tiny)
            {
                c = Tiny;
            }

            d = 1.0 / d;
            h *= d * c;

            //Odd step d_{2m+1}.
            double odd = -(a + m) * (qab + m) * x / ((a + twoM) * (qap + twoM));
            d = 1.0 + (odd * d);
            if(Math.Abs(d) < Tiny)
            {
                d = Tiny;
            }

            c = 1.0 + (odd / c);
            if(Math.Abs(c) < Tiny)
            {
                c = Tiny;
            }

            d = 1.0 / d;
            double delta = d * c;
            h *= delta;
            if(Math.Abs(delta - 1.0) < RelativeTolerance)
            {
                break;
            }
        }

        return h;
    }
}

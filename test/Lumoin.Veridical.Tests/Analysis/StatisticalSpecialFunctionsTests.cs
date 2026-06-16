using Lumoin.Veridical.Analysis.StatisticalTests;
using System;

namespace Lumoin.Veridical.Tests.Analysis;

/// <summary>
/// Validates the analysis layer's special functions against published reference
/// values: exact log-gamma points, the chi-squared 5% critical values (where the
/// survival function must equal 0.05), and known Kolmogorov-distribution
/// survival values. These gate the p-value correctness the distribution tests
/// depend on.
/// </summary>
[TestClass]
internal sealed class StatisticalSpecialFunctionsTests
{
    [TestMethod]
    public void LogGammaMatchesKnownValues()
    {
        //Γ(1) = Γ(2) = 1 → log = 0; Γ(1/2) = √π → log = ½·ln π;
        //Γ(5) = 4! = 24; Γ(10) = 9! = 362880.
        Assert.AreEqual(0.0, StatisticalSpecialFunctions.LogGamma(1.0), 1e-12);
        Assert.AreEqual(0.0, StatisticalSpecialFunctions.LogGamma(2.0), 1e-12);
        Assert.AreEqual(0.5723649429247001, StatisticalSpecialFunctions.LogGamma(0.5), 1e-12);
        Assert.AreEqual(Math.Log(24.0), StatisticalSpecialFunctions.LogGamma(5.0), 1e-11);
        Assert.AreEqual(Math.Log(362880.0), StatisticalSpecialFunctions.LogGamma(10.0), 1e-10);
    }


    [TestMethod]
    public void ChiSquaredSurvivalMatchesFivePercentCriticalValues()
    {
        //For k degrees of freedom the 5% critical value c satisfies
        //Q(k/2, c/2) = 0.05. Published values: k=1 → 3.841459, k=2 → 5.991465,
        //k=5 → 11.070498, k=10 → 18.307038.
        AssertChiSquaredSurvival(1, 3.841459);
        AssertChiSquaredSurvival(2, 5.991465);
        AssertChiSquaredSurvival(5, 11.070498);
        AssertChiSquaredSurvival(10, 18.307038);
    }


    [TestMethod]
    public void ChiSquaredSurvivalAtZeroIsOne()
    {
        Assert.AreEqual(1.0, StatisticalSpecialFunctions.RegularizedUpperIncompleteGamma(0.5, 0.0), 1e-15);
        Assert.AreEqual(1.0, StatisticalSpecialFunctions.RegularizedUpperIncompleteGamma(5.0, 0.0), 1e-15);
    }


    [TestMethod]
    public void KolmogorovSurvivalMatchesKnownValues()
    {
        //Q_KS(0) = 1; Q_KS(1) = 2(e⁻² − e⁻⁸ + e⁻¹⁸ − …) ≈ 0.2699996717; the 5%
        //asymptotic critical value is λ ≈ 1.3581, where Q_KS ≈ 0.05.
        Assert.AreEqual(1.0, StatisticalSpecialFunctions.KolmogorovSurvival(0.0), 1e-15);
        Assert.AreEqual(0.26999967167735, StatisticalSpecialFunctions.KolmogorovSurvival(1.0), 1e-12);
        Assert.AreEqual(0.05, StatisticalSpecialFunctions.KolmogorovSurvival(1.3581), 1e-3);
    }


    private static void AssertChiSquaredSurvival(int degreesOfFreedom, double criticalValue)
    {
        double survival = StatisticalSpecialFunctions.RegularizedUpperIncompleteGamma(degreesOfFreedom / 2.0, criticalValue / 2.0);
        Assert.AreEqual(0.05, survival, 1e-4, $"Chi-squared survival at the 5% critical value for {degreesOfFreedom} dof must be 0.05.");
    }
}

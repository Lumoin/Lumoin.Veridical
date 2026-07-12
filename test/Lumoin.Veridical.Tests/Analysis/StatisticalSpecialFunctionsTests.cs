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


    [TestMethod]
    public void IncompleteBetaBoundaryValues()
    {
        //I_0(a,b) = 0 and I_1(a,b) = 1 for all positive a, b.
        Assert.AreEqual(0.0, StatisticalSpecialFunctions.RegularizedIncompleteBeta(2.0, 3.0, 0.0), 1e-15);
        Assert.AreEqual(1.0, StatisticalSpecialFunctions.RegularizedIncompleteBeta(2.0, 3.0, 1.0), 1e-15);
    }


    [TestMethod]
    public void IncompleteBetaMatchesClosedForms()
    {
        //I_x(1,1) = x; I_x(a,1) = x^a; I_x(1,b) = 1 − (1−x)^b.
        Assert.AreEqual(0.42, StatisticalSpecialFunctions.RegularizedIncompleteBeta(1.0, 1.0, 0.42), 1e-12);
        Assert.AreEqual(Math.Pow(0.3, 3.0), StatisticalSpecialFunctions.RegularizedIncompleteBeta(3.0, 1.0, 0.3), 1e-12);
        Assert.AreEqual(1.0 - Math.Pow(0.7, 4.0), StatisticalSpecialFunctions.RegularizedIncompleteBeta(1.0, 4.0, 0.3), 1e-12);
    }


    [TestMethod]
    public void IncompleteBetaMatchesKnownValue()
    {
        //∫₀^0.5 t(1−t)² dt / B(2,3) = 0.0572916… / (1/12) = 0.6875.
        Assert.AreEqual(0.6875, StatisticalSpecialFunctions.RegularizedIncompleteBeta(2.0, 3.0, 0.5), 1e-12);
    }


    [TestMethod]
    public void IncompleteBetaSatisfiesReflectionSymmetry()
    {
        //I_x(a,b) = 1 − I_{1−x}(b,a).
        double left = StatisticalSpecialFunctions.RegularizedIncompleteBeta(2.5, 4.0, 0.37);
        double right = 1.0 - StatisticalSpecialFunctions.RegularizedIncompleteBeta(4.0, 2.5, 0.63);
        Assert.AreEqual(left, right, 1e-12);
    }


    [TestMethod]
    public void StudentTTwoTailedMatchesFivePercentCriticalValues()
    {
        //The 5% two-tailed Student-t critical values t* satisfy
        //I_{v/(v+t*²)}(v/2, 1/2) = 0.05. Published: v=2 → 4.302653,
        //v=5 → 2.570582, v=8 → 2.306004, v=10 → 2.228139.
        AssertStudentTTwoTailed(2, 4.302653);
        AssertStudentTTwoTailed(5, 2.570582);
        AssertStudentTTwoTailed(8, 2.306004);
        AssertStudentTTwoTailed(10, 2.228139);
    }


    [TestMethod]
    public void IncompleteBetaThrowsOnNonPositiveParameters()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => StatisticalSpecialFunctions.RegularizedIncompleteBeta(0.0, 1.0, 0.5));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => StatisticalSpecialFunctions.RegularizedIncompleteBeta(1.0, -1.0, 0.5));
    }


    private static void AssertStudentTTwoTailed(int degreesOfFreedom, double criticalT)
    {
        double x = degreesOfFreedom / (degreesOfFreedom + (criticalT * criticalT));
        double p = StatisticalSpecialFunctions.RegularizedIncompleteBeta(degreesOfFreedom / 2.0, 0.5, x);
        Assert.AreEqual(0.05, p, 1e-4, $"The two-tailed t p-value at the 5% critical value for {degreesOfFreedom} dof must be 0.05.");
    }


    private static void AssertChiSquaredSurvival(int degreesOfFreedom, double criticalValue)
    {
        double survival = StatisticalSpecialFunctions.RegularizedUpperIncompleteGamma(degreesOfFreedom / 2.0, criticalValue / 2.0);
        Assert.AreEqual(0.05, survival, 1e-4, $"Chi-squared survival at the 5% critical value for {degreesOfFreedom} dof must be 0.05.");
    }
}

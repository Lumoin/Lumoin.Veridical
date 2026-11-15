using Lumoin.Base;
using Lumoin.Veridical.Cli;
using System;

namespace Lumoin.Veridical.Tests.ToolTests;

/// <summary>
/// In-process tests of <see cref="AnalysisOperations"/>, the shared implementation behind the
/// <c>analysis-*</c> subcommands and their MCP tools: the BaseFold leakage experiments at small scale and
/// the statistical tests over small sample sets.
/// </summary>
[TestClass]
internal sealed class AnalysisOperationsTests
{
    private const int VariableCount = 2;

    private const int SampleCount = 40;

    private const double Significance = 0.05;

    private const string LowSamples = "1.0\n1.1\n0.9\n1.2\n0.8\n1.0\n1.1\n0.9\n";

    private const string HighSamples = "5.0\n5.1\n4.9\n5.2\n4.8\n5.0\n5.1\n4.9\n";


    [TestMethod]
    public void BaseFoldLeakageReportsEveryExperimentAndTheStructuralLeakOfThePlainProvider()
    {
        string report = AnalysisOperations.BaseFoldLeakage(VariableCount, SampleCount, Significance, hiding: false, BaseMemoryPool.Shared);

        Assert.Contains("plain provider", report, StringComparison.Ordinal);
        Assert.Contains("[byte-distribution]", report, StringComparison.Ordinal);
        Assert.Contains("[classifier]", report, StringComparison.Ordinal);
        Assert.Contains("signal=StructurallyCertain", report, StringComparison.Ordinal);
    }


    [TestMethod]
    public void BaseFoldLeakageOfTheHidingProviderDoesNotReportAStructuralLeak()
    {
        string report = AnalysisOperations.BaseFoldLeakage(VariableCount, SampleCount, Significance, hiding: true, BaseMemoryPool.Shared);

        Assert.Contains("hiding provider", report, StringComparison.Ordinal);
        Assert.DoesNotContain("signal=StructurallyCertain", report, StringComparison.Ordinal);
    }


    [TestMethod]
    public void BaseFoldLeakageRejectsOutOfRangeArguments()
    {
        Assert.ThrowsExactly<ArgumentException>(() => AnalysisOperations.BaseFoldLeakage(0, SampleCount, Significance, false, BaseMemoryPool.Shared));
        Assert.ThrowsExactly<ArgumentException>(() => AnalysisOperations.BaseFoldLeakage(VariableCount, 1, Significance, false, BaseMemoryPool.Shared));
        Assert.ThrowsExactly<ArgumentException>(() => AnalysisOperations.BaseFoldLeakage(VariableCount, SampleCount, 1.5, false, BaseMemoryPool.Shared));
    }


    [TestMethod]
    public void WelchTRejectsTheNullForSeparatedSamplesAndNotForIdenticalOnes()
    {
        string separated = AnalysisOperations.WelchT(LowSamples, HighSamples, Significance);
        string identical = AnalysisOperations.WelchT(LowSamples, LowSamples, Significance);

        Assert.Contains("Reject", separated, StringComparison.Ordinal);
        Assert.Contains("FailToReject", identical, StringComparison.Ordinal);
    }


    [TestMethod]
    public void KolmogorovSmirnovRejectsTheNullForSeparatedSamples()
    {
        string separated = AnalysisOperations.KolmogorovSmirnov(LowSamples, HighSamples, Significance);

        Assert.Contains("Reject", separated, StringComparison.Ordinal);
        Assert.Contains("p=", separated, StringComparison.Ordinal);
    }


    [TestMethod]
    public void ChiSquaredHomogeneityAndGoodnessOfFitReportTheirNames()
    {
        string homogeneity = AnalysisOperations.ChiSquared("50\n50\n50\n50\n", "50\n50\n50\n50\n", goodnessOfFit: false, Significance);
        string fit = AnalysisOperations.ChiSquared("90\n10\n", "50\n50\n", goodnessOfFit: true, Significance);

        Assert.Contains("chi-squared homogeneity test: FailToReject", homogeneity, StringComparison.Ordinal);
        Assert.Contains("chi-squared goodness-of-fit test: Reject", fit, StringComparison.Ordinal);
    }


    [TestMethod]
    public void StatisticalTestsRejectNonNumericInput()
    {
        Assert.ThrowsExactly<ArgumentException>(() => AnalysisOperations.WelchT("1.0\nabc\n", HighSamples, Significance));
        Assert.ThrowsExactly<ArgumentException>(() => AnalysisOperations.ChiSquared("1\n-2\n", "1\n2\n", false, Significance));
        Assert.ThrowsExactly<ArgumentException>(() => AnalysisOperations.KolmogorovSmirnov(LowSamples, HighSamples, 0.0));
    }
}

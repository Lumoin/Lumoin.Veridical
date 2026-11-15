using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.IO;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.ToolTests;

/// <summary>
/// End-to-end tests of the <c>analysis-*</c> subcommands: the built <c>veridical</c> executable is run as a
/// subprocess over small sample files and its report and exit codes are checked. Inconclusive when the
/// executable has not been built.
/// </summary>
[TestClass]
internal sealed class AnalysisCliTests
{
    private const string LowSamples = "1.0\n1.1\n0.9\n1.2\n0.8\n1.0\n1.1\n0.9\n";

    private const string HighSamples = "5.0\n5.1\n4.9\n5.2\n4.8\n5.0\n5.1\n4.9\n";


    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Skips every test of the class under WebAssembly, where the runtime cannot start the executable as a child process.
    /// </summary>
    [TestInitialize]
    public void RequireSubprocessSupport() => RuntimeRequirements.RequireProcessSpawning();


    [TestMethod]
    public async Task BaseFoldLeakageCommandPrintsOneLinePerExperimentAndExitsZero()
    {
        string executable = RequireExecutable();

        CliResult result = await VeridicalCliTestHelpers.RunCliAsync(executable, ["analysis-basefold-leakage", "--variables", "2", "--samples", "40"], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        Assert.Contains("[byte-distribution]", result.Stdout, StringComparison.Ordinal);
        Assert.Contains("[classifier]", result.Stdout, StringComparison.Ordinal);
        Assert.Contains("signal=StructurallyCertain", result.Stdout, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task BaseFoldLeakageCommandWithAnInvalidSignificanceExitsOne()
    {
        string executable = RequireExecutable();

        CliResult result = await VeridicalCliTestHelpers.RunCliAsync(executable, ["analysis-basefold-leakage", "--significance", "2"], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("Error:", result.Stderr, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task WelchTKolmogorovSmirnovAndChiSquaredCommandsReportOverFiles()
    {
        string executable = RequireExecutable();
        string lowPath = VeridicalCliTestHelpers.WriteTemporaryFile(LowSamples);
        string highPath = VeridicalCliTestHelpers.WriteTemporaryFile(HighSamples);
        string evenPath = VeridicalCliTestHelpers.WriteTemporaryFile("50\n50\n50\n50\n");
        try
        {
            CliResult welch = await VeridicalCliTestHelpers.RunCliAsync(executable, ["analysis-welch-t", lowPath, highPath], TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(0, welch.ExitCode, welch.Stderr);
            Assert.Contains("Welch two-sample t-test: Reject", welch.Stdout, StringComparison.Ordinal);

            CliResult ks = await VeridicalCliTestHelpers.RunCliAsync(executable, ["analysis-ks", lowPath, highPath], TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(0, ks.ExitCode, ks.Stderr);
            Assert.Contains("Kolmogorov-Smirnov test: Reject", ks.Stdout, StringComparison.Ordinal);

            CliResult chi = await VeridicalCliTestHelpers.RunCliAsync(executable, ["analysis-chi-squared", evenPath, evenPath], TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(0, chi.ExitCode, chi.Stderr);
            Assert.Contains("chi-squared homogeneity test: FailToReject", chi.Stdout, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(lowPath);
            File.Delete(highPath);
            File.Delete(evenPath);
        }
    }


    [TestMethod]
    public async Task StatisticalCommandsWithAMissingOrNonNumericFileExitOne()
    {
        string executable = RequireExecutable();
        string lowPath = VeridicalCliTestHelpers.WriteTemporaryFile(LowSamples);
        string badPath = VeridicalCliTestHelpers.WriteTemporaryFile("1.0\nabc\n");
        try
        {
            CliResult missing = await VeridicalCliTestHelpers.RunCliAsync(executable, ["analysis-welch-t", lowPath, lowPath + ".missing"], TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(1, missing.ExitCode);
            Assert.Contains("could not read the second sample set", missing.Stderr, StringComparison.Ordinal);

            CliResult bad = await VeridicalCliTestHelpers.RunCliAsync(executable, ["analysis-ks", lowPath, badPath], TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(1, bad.ExitCode);
            Assert.Contains("Error:", bad.Stderr, StringComparison.Ordinal);

            CliResult noArguments = await VeridicalCliTestHelpers.RunCliAsync(executable, ["analysis-welch-t"], TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(1, noArguments.ExitCode);
        }
        finally
        {
            File.Delete(lowPath);
            File.Delete(badPath);
        }
    }


    private static string RequireExecutable()
    {
        string? executable = VeridicalCliTestHelpers.GetExecutablePath();
        if(executable is null)
        {
            Assert.Inconclusive("The veridical executable was not found; build the solution first.");
        }

        return executable;
    }
}

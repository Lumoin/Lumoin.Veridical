using System;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.ToolTests;

/// <summary>
/// End-to-end tests that run the built <c>veridical</c> executable as a subprocess
/// and assert on its output and exit code — the same way a user or CI invokes it.
/// Inconclusive when the executable has not been built.
/// </summary>
[TestClass]
internal sealed class CliIntegrationTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task SelfTestCommandPassesAndExitsZero()
    {
        string? executable = VeridicalCliTestHelpers.GetExecutablePath();
        if(executable is null)
        {
            Assert.Inconclusive("The veridical executable was not found; build the solution first.");
        }

        CliResult result = await VeridicalCliTestHelpers.RunCliAsync(executable, ["selftest"], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, $"selftest must exit zero. stdout:\n{result.Stdout}\nstderr:\n{result.Stderr}");
        Assert.Contains("All conformance vectors passed.", result.Stdout, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task InfoCommandPrintsPlatformAndExitsZero()
    {
        string? executable = VeridicalCliTestHelpers.GetExecutablePath();
        if(executable is null)
        {
            Assert.Inconclusive("The veridical executable was not found; build the solution first.");
        }

        CliResult result = await VeridicalCliTestHelpers.RunCliAsync(executable, ["info"], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("OS:", result.Stdout, StringComparison.Ordinal);
        Assert.Contains("scalar backend:", result.Stdout, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task HashCommandMatchesKnownVector()
    {
        string? executable = VeridicalCliTestHelpers.GetExecutablePath();
        if(executable is null)
        {
            Assert.Inconclusive("The veridical executable was not found; build the solution first.");
        }

        //BLAKE3-256 of the UTF-8 bytes of "hello".
        const string HelloHash = "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f";

        CliResult result = await VeridicalCliTestHelpers.RunCliAsync(executable, ["hash", "hello"], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains(HelloHash, result.Stdout, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task HashCommandHexAndTextAgree()
    {
        string? executable = VeridicalCliTestHelpers.GetExecutablePath();
        if(executable is null)
        {
            Assert.Inconclusive("The veridical executable was not found; build the solution first.");
        }

        //"hello" as hex is 68656c6c6f; --hex must hash the same bytes as the text form.
        CliResult viaText = await VeridicalCliTestHelpers.RunCliAsync(executable, ["hash", "hello"], TestContext.CancellationToken)
            .ConfigureAwait(false);
        CliResult viaHex = await VeridicalCliTestHelpers.RunCliAsync(executable, ["hash", "68656c6c6f", "--hex"], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(0, viaText.ExitCode);
        Assert.AreEqual(0, viaHex.ExitCode);
        Assert.AreEqual(viaText.Stdout.Trim(), viaHex.Stdout.Trim());
    }
}

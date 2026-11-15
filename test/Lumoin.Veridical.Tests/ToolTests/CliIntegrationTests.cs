using System;
using System.IO;
using System.Threading.Tasks;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;

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


    /// <summary>
    /// Skips every test of the class under WebAssembly, where the runtime cannot start the executable as a child process.
    /// </summary>
    [TestInitialize]
    public void RequireSubprocessSupport() => RuntimeRequirements.RequireProcessSpawning();


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


    [TestMethod]
    public async Task LongfellowJwtProveWithoutRequiredOptionsExitsOne()
    {
        string? executable = VeridicalCliTestHelpers.GetExecutablePath();
        if(executable is null)
        {
            Assert.Inconclusive("The veridical executable was not found; build the solution first.");
        }

        CliResult result = await VeridicalCliTestHelpers.RunCliAsync(executable, ["longfellow-jwt-prove", "token.txt"], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
    }


    [TestMethod]
    public async Task LongfellowJwtProveWithAnUnreadableTokenExitsOne()
    {
        string? executable = VeridicalCliTestHelpers.GetExecutablePath();
        if(executable is null)
        {
            Assert.Inconclusive("The veridical executable was not found; build the solution first.");
        }

        string missing = Path.Combine(Path.GetTempPath(), $"veridical-missing-{Guid.NewGuid():N}.txt");
        CliResult result = await VeridicalCliTestHelpers.RunCliAsync(executable, LongfellowJwtProveArguments(missing), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
        Assert.Contains("could not read the token", result.Stderr, StringComparison.Ordinal);
    }


    [TestMethod]
    public async Task LongfellowJwtProveWithATokenThatCannotSatisfyTheStatementExitsOneWithoutEchoingIt()
    {
        string? executable = VeridicalCliTestHelpers.GetExecutablePath();
        if(executable is null)
        {
            Assert.Inconclusive("The veridical executable was not found; build the solution first.");
        }

        string tokenPath = VeridicalCliTestHelpers.WriteTemporaryFile(UnprovableToken);
        try
        {
            CliResult result = await VeridicalCliTestHelpers.RunCliAsync(executable, LongfellowJwtProveArguments(tokenPath), TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.AreEqual(1, result.ExitCode);
            Assert.Contains("Error:", result.Stderr, StringComparison.Ordinal);
            Assert.DoesNotContain(UnprovableToken, result.Stderr + result.Stdout, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(tokenPath);
        }
    }


    [TestMethod]
    public async Task LongfellowJwtVerifyWithAMalformedProofExitsOne()
    {
        string? executable = VeridicalCliTestHelpers.GetExecutablePath();
        if(executable is null)
        {
            Assert.Inconclusive("The veridical executable was not found; build the solution first.");
        }

        string proofPath = VeridicalCliTestHelpers.WriteTemporaryFile("not-hex!");
        string presentationPath = VeridicalCliTestHelpers.WriteTemporaryFile("a.b.cc");
        try
        {
            CliResult result = await VeridicalCliTestHelpers.RunCliAsync(executable, LongfellowJwtVerifyArguments(proofPath, presentationPath, ErikaAttribute), TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.AreEqual(1, result.ExitCode);
            Assert.Contains("MALFORMED", result.Stdout, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(proofPath);
            File.Delete(presentationPath);
        }
    }


    /// <summary>
    /// The full round trip through the executable: the reference token proves, the proof verifies, a proof
    /// with one flipped hex digit is rejected, and the same proof does not verify a different attribute value.
    /// </summary>
    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public async Task LongfellowJwtProveThenVerifyRoundTripsAndRejectsTampering()
    {
        string? executable = VeridicalCliTestHelpers.GetExecutablePath();
        if(executable is null)
        {
            Assert.Inconclusive("The veridical executable was not found; build the solution first.");
        }

        string tokenPath = VeridicalCliTestHelpers.WriteTemporaryFile(LongfellowJwtTestVectors.ErikaToken.Token);
        string presentationPath = VeridicalCliTestHelpers.WriteTemporaryFile(LongfellowJwtTestVectors.ErikaToken.Token);
        string proofPath = string.Empty;
        string tamperedPath = string.Empty;
        try
        {
            CliResult prove = await VeridicalCliTestHelpers.RunCliAsync(executable, LongfellowJwtProveArguments(tokenPath), TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.AreEqual(0, prove.ExitCode, $"prove must exit zero. stderr:\n{prove.Stderr}");

            string proofHex = prove.Stdout.Trim();
            proofPath = VeridicalCliTestHelpers.WriteTemporaryFile(proofHex);
            CliResult valid = await VeridicalCliTestHelpers.RunCliAsync(executable, LongfellowJwtVerifyArguments(proofPath, presentationPath, ErikaAttribute), TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.AreEqual(0, valid.ExitCode, $"verify must exit zero. stdout:\n{valid.Stdout}");
            Assert.Contains("VALID: proves given_name = Erika", valid.Stdout, StringComparison.Ordinal);

            //A flipped digit inside the sumcheck segment, past the 32-byte commitment root.
            char flipped = proofHex[TamperedDigitIndex] == '0' ? '1' : '0';
            tamperedPath = VeridicalCliTestHelpers.WriteTemporaryFile(string.Concat(proofHex.AsSpan(0, TamperedDigitIndex), flipped.ToString(), proofHex.AsSpan(TamperedDigitIndex + 1)));
            CliResult tampered = await VeridicalCliTestHelpers.RunCliAsync(executable, LongfellowJwtVerifyArguments(tamperedPath, presentationPath, ErikaAttribute), TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.AreEqual(1, tampered.ExitCode);
            Assert.Contains("REJECTED", tampered.Stdout, StringComparison.Ordinal);

            CliResult wrongValue = await VeridicalCliTestHelpers.RunCliAsync(executable, LongfellowJwtVerifyArguments(proofPath, presentationPath, "given_name=Wrong"), TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.AreEqual(1, wrongValue.ExitCode);
            Assert.Contains("REJECTED", wrongValue.Stdout, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(tokenPath);
            File.Delete(presentationPath);
            File.Delete(proofPath);
            File.Delete(tamperedPath);
        }
    }


    private const string ErikaAttribute = "given_name=Erika";

    private const string JwtSeed = "cli-jwt-roundtrip";

    private const string UnprovableToken = "aaaa.bbbb.cccc~dddd.eeee.ffff";

    private const int TamperedDigitIndex = 100;


    private static string[] LongfellowJwtProveArguments(string tokenPath)
    {
        LongfellowJwtTestVectors.TokenVector vector = LongfellowJwtTestVectors.ErikaToken;

        return ["longfellow-jwt-prove", tokenPath, "--issuer-key-x", vector.PkX, "--issuer-key-y", vector.PkY, "--attribute", ErikaAttribute, "--seed", JwtSeed];
    }


    private static string[] LongfellowJwtVerifyArguments(string proofPath, string presentationPath, string attribute)
    {
        LongfellowJwtTestVectors.TokenVector vector = LongfellowJwtTestVectors.ErikaToken;

        return ["longfellow-jwt-verify", proofPath, "--presentation", presentationPath, "--issuer-key-x", vector.PkX, "--issuer-key-y", vector.PkY, "--attribute", attribute, "--seed", JwtSeed];
    }
}

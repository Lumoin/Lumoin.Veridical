using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.IO;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.ToolTests;

/// <summary>
/// End-to-end tests of the <c>bbs-*</c> subcommands: the built <c>veridical</c> executable is run as a
/// subprocess through key generation, signing, verification, proof generation with selective disclosure and
/// proof verification, and its exit codes are checked for tampered and invalid input. Inconclusive when the
/// executable has not been built.
/// </summary>
[TestClass]
internal sealed class BbsCliTests
{
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Skips every test of the class under WebAssembly, where the runtime cannot start the executable as a child process.
    /// </summary>
    [TestInitialize]
    public void RequireSubprocessSupport() => RuntimeRequirements.RequireProcessSpawning();


    [TestMethod]
    public async Task KeygenWritesTheSecretKeyToTheNamedFileAndPrintsOnlyThePublicKey()
    {
        string executable = RequireExecutable();
        string secretPath = NewMissingPath();
        try
        {
            CliResult result = await VeridicalCliTestHelpers.RunCliAsync(executable, ["bbs-keygen", "--secret-key-file", secretPath], TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.AreEqual(0, result.ExitCode, result.Stderr);
            string secret = (await File.ReadAllTextAsync(secretPath, TestContext.CancellationToken).ConfigureAwait(false)).Trim();
            Assert.AreEqual(64, secret.Length);
            Assert.AreEqual(192, result.Stdout.Trim().Length);
            Assert.DoesNotContain(secret, result.Stdout + result.Stderr, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(secretPath);
        }
    }


    [TestMethod]
    public async Task KeygenRefusesToOverwriteAnExistingSecretKeyFile()
    {
        string executable = RequireExecutable();
        string secretPath = VeridicalCliTestHelpers.WriteTemporaryFile("existing");
        try
        {
            CliResult result = await VeridicalCliTestHelpers.RunCliAsync(executable, ["bbs-keygen", "--secret-key-file", secretPath], TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.AreEqual(1, result.ExitCode);
            Assert.AreEqual("existing", await File.ReadAllTextAsync(secretPath, TestContext.CancellationToken).ConfigureAwait(false));
        }
        finally
        {
            File.Delete(secretPath);
        }
    }


    [TestMethod]
    public async Task KeygenWithoutTheSecretKeyFileOptionExitsOne()
    {
        string executable = RequireExecutable();

        CliResult result = await VeridicalCliTestHelpers.RunCliAsync(executable, ["bbs-keygen"], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(1, result.ExitCode);
    }


    [TestMethod]
    public async Task SignVerifyAndSelectiveDisclosureProofRoundTrip()
    {
        string executable = RequireExecutable();
        string secretPath = NewMissingPath();
        string messagesPath = VeridicalCliTestHelpers.WriteTemporaryFile("alpha\nbeta\ngamma\ndelta\n");
        string signaturePath = string.Empty;
        string proofPath = string.Empty;
        string disclosedPath = VeridicalCliTestHelpers.WriteTemporaryFile("0=alpha\n2=gamma\n");
        string tamperedPath = VeridicalCliTestHelpers.WriteTemporaryFile("0=alpha\n2=changed\n");
        string tamperedMessagesPath = VeridicalCliTestHelpers.WriteTemporaryFile("alpha\nbeta\ngamma\nchanged\n");
        try
        {
            CliResult keygen = await VeridicalCliTestHelpers.RunCliAsync(executable, ["bbs-keygen", "--secret-key-file", secretPath], TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.AreEqual(0, keygen.ExitCode, keygen.Stderr);
            string publicKey = keygen.Stdout.Trim();

            CliResult sign = await VeridicalCliTestHelpers.RunCliAsync(executable, ["bbs-sign", messagesPath, "--secret-key-file", secretPath, "--public-key", publicKey, "--header", "cli-header"], TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.AreEqual(0, sign.ExitCode, sign.Stderr);
            signaturePath = VeridicalCliTestHelpers.WriteTemporaryFile(sign.Stdout.Trim());

            CliResult verify = await VeridicalCliTestHelpers.RunCliAsync(executable, ["bbs-verify", signaturePath, "--messages-file", messagesPath, "--public-key", publicKey, "--header", "cli-header"], TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.AreEqual(0, verify.ExitCode, verify.Stdout);
            Assert.Contains("VALID: proves a BBS signature over 4 message(s)", verify.Stdout, StringComparison.Ordinal);

            CliResult tamperedVerify = await VeridicalCliTestHelpers.RunCliAsync(executable, ["bbs-verify", signaturePath, "--messages-file", tamperedMessagesPath, "--public-key", publicKey, "--header", "cli-header"], TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.AreEqual(1, tamperedVerify.ExitCode);
            Assert.Contains("REJECTED", tamperedVerify.Stdout, StringComparison.Ordinal);

            CliResult generate = await VeridicalCliTestHelpers.RunCliAsync(
                executable,
                ["bbs-proof-generate", signaturePath, "--messages-file", messagesPath, "--public-key", publicKey, "--header", "cli-header", "--presentation-header", "cli-presentation", "--disclose", "0,2"],
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(0, generate.ExitCode, generate.Stderr);
            proofPath = VeridicalCliTestHelpers.WriteTemporaryFile(generate.Stdout.Trim());
            Assert.DoesNotContain("beta", generate.Stdout, StringComparison.Ordinal);

            string[] proofVerifyArguments = ["bbs-proof-verify", proofPath, "--disclosed-messages-file", disclosedPath, "--public-key", publicKey, "--header", "cli-header", "--presentation-header", "cli-presentation"];
            CliResult proofVerify = await VeridicalCliTestHelpers.RunCliAsync(executable, proofVerifyArguments, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(0, proofVerify.ExitCode, proofVerify.Stdout);
            Assert.Contains("VALID", proofVerify.Stdout, StringComparison.Ordinal);

            string[] tamperedArguments = ["bbs-proof-verify", proofPath, "--disclosed-messages-file", tamperedPath, "--public-key", publicKey, "--header", "cli-header", "--presentation-header", "cli-presentation"];
            CliResult tamperedProof = await VeridicalCliTestHelpers.RunCliAsync(executable, tamperedArguments, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(1, tamperedProof.ExitCode);
            Assert.Contains("REJECTED", tamperedProof.Stdout, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(secretPath);
            File.Delete(messagesPath);
            File.Delete(signaturePath);
            File.Delete(proofPath);
            File.Delete(disclosedPath);
            File.Delete(tamperedPath);
            File.Delete(tamperedMessagesPath);
        }
    }


    [TestMethod]
    public async Task SignWithAnUnreadableSecretKeyFileExitsOne()
    {
        string executable = RequireExecutable();
        string messagesPath = VeridicalCliTestHelpers.WriteTemporaryFile("alpha\n");
        try
        {
            CliResult result = await VeridicalCliTestHelpers.RunCliAsync(
                executable,
                ["bbs-sign", messagesPath, "--secret-key-file", NewMissingPath(), "--public-key", new string('0', 192)],
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(1, result.ExitCode);
            Assert.Contains("could not read the secret key", result.Stderr, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(messagesPath);
        }
    }


    [TestMethod]
    public async Task VerifyWithAMalformedSignatureExitsOne()
    {
        string executable = RequireExecutable();
        string signaturePath = VeridicalCliTestHelpers.WriteTemporaryFile("not-hex");
        string messagesPath = VeridicalCliTestHelpers.WriteTemporaryFile("alpha\n");
        try
        {
            CliResult result = await VeridicalCliTestHelpers.RunCliAsync(
                executable,
                ["bbs-verify", signaturePath, "--messages-file", messagesPath, "--public-key", new string('0', 192)],
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(1, result.ExitCode);
            Assert.Contains("MALFORMED", result.Stdout, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(signaturePath);
            File.Delete(messagesPath);
        }
    }


    [TestMethod]
    public async Task ProofGenerateWithAnOutOfRangeIndexExitsOne()
    {
        string executable = RequireExecutable();
        string signaturePath = VeridicalCliTestHelpers.WriteTemporaryFile(new string('1', 160));
        string messagesPath = VeridicalCliTestHelpers.WriteTemporaryFile("alpha\n");
        try
        {
            CliResult result = await VeridicalCliTestHelpers.RunCliAsync(
                executable,
                ["bbs-proof-generate", signaturePath, "--messages-file", messagesPath, "--public-key", new string('0', 192), "--disclose", "x"],
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(1, result.ExitCode);
            Assert.Contains("Error:", result.Stderr, StringComparison.Ordinal);
        }
        finally
        {
            File.Delete(signaturePath);
            File.Delete(messagesPath);
        }
    }


    private static string NewMissingPath() => Path.Combine(Path.GetTempPath(), $"veridical-test-{Guid.NewGuid():N}.key");


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

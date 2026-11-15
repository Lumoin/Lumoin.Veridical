using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.ToolTests;

/// <summary>
/// End-to-end tests of the signature-result, ECIES and transferable-proof subcommands: the built <c>veridical</c>
/// executable is run as a subprocess, secrets and plaintexts move only through files, secret outputs are created
/// exclusively, and the exit codes are checked for tampered input. Inconclusive when the executable has not been built.
/// </summary>
[TestClass]
internal sealed class SecdsaProofCliTests
{
    private const string MessageHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    private const string AnotherMessageHash = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

    private const string Plaintext = "deadbeefcafe0123456789";

    private const string AssociatedData = "616263";

    private const string AdditionalSecret = "5365637265744461746121";

    private const ulong RecipientKey = 23;

    private const ulong ProverWitness = 13;

    private const ulong SecondGeneratorScalar = 5;

    private const ulong ChallengerSigningKey = 31;

    private const ulong ProverSigningKey = 37;

    private const int PointHexLength = 66;

    private const int RecordProofHexOffset = 3 * PointHexLength;


    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Skips every test of the class under WebAssembly, where the runtime cannot start the executable as a child process.
    /// </summary>
    [TestInitialize]
    public void RequireSubprocessSupport() => RuntimeRequirements.RequireProcessSpawning();


    [TestMethod]
    public async Task SignatureResultRecordProvesAndChecksAndAlarmsOnTamperedInput()
    {
        string executable = RequireExecutable();
        string pinPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(7));
        string hardwarePath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(11));
        try
        {
            string publicKey = await PublicKeyAsync(executable, 7, 11).ConfigureAwait(false);
            CliResult sign = await RunAsync(executable, "secdsa-split-sign", "--pin-key-file", pinPath, "--hardware-key-file", hardwarePath, "--message-hash", MessageHash).ConfigureAwait(false);
            Assert.AreEqual(0, sign.ExitCode, sign.Stderr);

            CliResult prove = await RunAsync(executable, "secdsa-result-prove", "--public-key", publicKey, "--message-hash", MessageHash, "--signature", sign.Stdout.Trim()).ConfigureAwait(false);
            Assert.AreEqual(0, prove.ExitCode, prove.Stderr);
            string record = prove.Stdout.Trim();

            CliResult check = await RunAsync(executable, "secdsa-result-check", "--public-key", publicKey, "--message-hash", MessageHash, "--record", record).ConfigureAwait(false);
            Assert.AreEqual(0, check.ExitCode, check.Stdout);
            Assert.Contains("VALID", check.Stdout, StringComparison.Ordinal);

            string flipped = record[..RecordProofHexOffset] + Flip(record[RecordProofHexOffset..]);
            CliResult tamperedProof = await RunAsync(executable, "secdsa-result-check", "--public-key", publicKey, "--message-hash", MessageHash, "--record", flipped).ConfigureAwait(false);
            Assert.AreEqual(1, tamperedProof.ExitCode);

            CliResult wrongMessage = await RunAsync(executable, "secdsa-result-check", "--public-key", publicKey, "--message-hash", AnotherMessageHash, "--record", record).ConfigureAwait(false);
            Assert.AreEqual(1, wrongMessage.ExitCode);

            CliResult wrongSignature = await RunAsync(executable, "secdsa-result-prove", "--public-key", publicKey, "--message-hash", AnotherMessageHash, "--signature", sign.Stdout.Trim()).ConfigureAwait(false);
            Assert.AreEqual(1, wrongSignature.ExitCode);
        }
        finally
        {
            File.Delete(pinPath);
            File.Delete(hardwarePath);
        }
    }


    [TestMethod]
    public async Task EciesRoundTripsOneShotAndPhasedWithSecretsOnlyInFiles()
    {
        string executable = RequireExecutable();
        string privatePath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(RecipientKey));
        string plaintextPath = VeridicalCliTestHelpers.WriteTemporaryFile(Plaintext);
        string decryptedPath = TemporaryOutputPath("plain");
        string agreedPath = TemporaryOutputPath("z");
        string phasedPath = TemporaryOutputPath("phased");
        string tamperedOutputPath = TemporaryOutputPath("tampered");
        try
        {
            string recipient = await PublicKeyAsync(executable, 1, RecipientKey).ConfigureAwait(false);

            CliResult encrypt = await RunAsync(executable, "secdsa-ecies-encrypt", "--recipient-public-key", recipient, "--plaintext-file", plaintextPath, "--aad", AssociatedData).ConfigureAwait(false);
            Assert.AreEqual(0, encrypt.ExitCode, encrypt.Stderr);
            string ciphertext = encrypt.Stdout.Trim();
            Assert.DoesNotContain(Plaintext, ciphertext, StringComparison.Ordinal);

            CliResult decrypt = await RunAsync(executable, "secdsa-ecies-decrypt", "--private-key-file", privatePath, "--ciphertext", ciphertext, "--aad", AssociatedData, "--output", decryptedPath).ConfigureAwait(false);
            Assert.AreEqual(0, decrypt.ExitCode, decrypt.Stderr);
            Assert.AreEqual(Plaintext, (await File.ReadAllTextAsync(decryptedPath, TestContext.CancellationToken).ConfigureAwait(false)).Trim());
            Assert.DoesNotContain(Plaintext, decrypt.Stdout + decrypt.Stderr, StringComparison.Ordinal);

            CliResult overwrite = await RunAsync(executable, "secdsa-ecies-decrypt", "--private-key-file", privatePath, "--ciphertext", ciphertext, "--aad", AssociatedData, "--output", decryptedPath).ConfigureAwait(false);
            Assert.AreEqual(1, overwrite.ExitCode);

            //A tampered ciphertext and a wrong associated data release no plaintext and create no output file.
            CliResult tampered = await RunAsync(executable, "secdsa-ecies-decrypt", "--private-key-file", privatePath, "--ciphertext", Flip(ciphertext), "--aad", AssociatedData, "--output", tamperedOutputPath).ConfigureAwait(false);
            Assert.AreEqual(1, tampered.ExitCode);
            Assert.IsFalse(File.Exists(tamperedOutputPath));
            CliResult wrongData = await RunAsync(executable, "secdsa-ecies-decrypt", "--private-key-file", privatePath, "--ciphertext", ciphertext, "--aad", "616264", "--output", tamperedOutputPath).ConfigureAwait(false);
            Assert.AreEqual(1, wrongData.ExitCode);
            Assert.IsFalse(File.Exists(tamperedOutputPath));

            //The phased path with the key holder as a separate agreement step.
            CliResult prepare = await RunAsync(executable, "secdsa-ecies-prepare-decryption", "--ciphertext", ciphertext).ConfigureAwait(false);
            Assert.AreEqual(0, prepare.ExitCode, prepare.Stderr);
            Assert.AreEqual(ciphertext[..PointHexLength], prepare.Stdout.Trim());

            CliResult agree = await RunAsync(executable, "secdsa-ecies-agree", "--private-key-file", privatePath, "--point", prepare.Stdout.Trim(), "--output", agreedPath).ConfigureAwait(false);
            Assert.AreEqual(0, agree.ExitCode, agree.Stderr);
            Assert.AreEqual(string.Empty, agree.Stdout.Trim());

            CliResult complete = await RunAsync(executable, "secdsa-ecies-complete-decryption", "--shared-secret-file", agreedPath, "--ciphertext", ciphertext, "--aad", AssociatedData, "--output", phasedPath).ConfigureAwait(false);
            Assert.AreEqual(0, complete.ExitCode, complete.Stderr);
            Assert.AreEqual(Plaintext, (await File.ReadAllTextAsync(phasedPath, TestContext.CancellationToken).ConfigureAwait(false)).Trim());

            CliResult offCurve = await RunAsync(executable, "secdsa-ecies-prepare-decryption", "--ciphertext", "02" + new string('0', 62) + "01" + new string('0', 64)).ConfigureAwait(false);
            Assert.AreEqual(1, offCurve.ExitCode);
        }
        finally
        {
            File.Delete(privatePath);
            File.Delete(plaintextPath);
            File.Delete(decryptedPath);
            File.Delete(agreedPath);
            File.Delete(phasedPath);
            File.Delete(tamperedOutputPath);
        }
    }


    [TestMethod]
    public async Task TransferableProofRunsChallengeRespondAndVerifyAcrossProcesses()
    {
        string executable = RequireExecutable();
        string witnessPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(ProverWitness));
        string challengerKeyPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(ChallengerSigningKey));
        string proverKeyPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(ProverSigningKey));
        string secretDataPath = VeridicalCliTestHelpers.WriteTemporaryFile(AdditionalSecret);
        string agreedPath = TemporaryOutputPath("z");
        string wrongAgreedPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(1));
        string recoveredPath = TemporaryOutputPath("asd");
        try
        {
            string generators = await PublicKeyAsync(executable, 1, 1).ConfigureAwait(false) + await PublicKeyAsync(executable, 1, SecondGeneratorScalar).ConfigureAwait(false);
            string publicKeys = await PublicKeyAsync(executable, ProverWitness, 1).ConfigureAwait(false) + await PublicKeyAsync(executable, ProverWitness, SecondGeneratorScalar).ConfigureAwait(false);
            string challengerPublic = await PublicKeyAsync(executable, 1, ChallengerSigningKey).ConfigureAwait(false);
            string proverPublic = await PublicKeyAsync(executable, 1, ProverSigningKey).ConfigureAwait(false);

            CliResult challengeResult = await RunAsync(
                executable, "secdsa-proof-challenge", "--signing-key-file", challengerKeyPath, "--generators", generators, "--public-keys", publicKeys,
                "--aad", AssociatedData, "--additional-secret-data-file", secretDataPath).ConfigureAwait(false);
            Assert.AreEqual(0, challengeResult.ExitCode, challengeResult.Stderr);
            Assert.DoesNotContain(AdditionalSecret, challengeResult.Stdout + challengeResult.Stderr, StringComparison.Ordinal);
            using JsonDocument document = JsonDocument.Parse(challengeResult.Stdout);
            string challenge = document.RootElement.GetProperty("challenge").GetString() ?? string.Empty;
            string ciphertext = document.RootElement.GetProperty("ciphertext").GetString() ?? string.Empty;

            //Phase one: the prover verifies the challenge and gets E for the key holder.
            CliResult prepare = await RunAsync(
                executable, "secdsa-proof-respond-prepare", "--challenge", challenge, "--generators", generators, "--public-keys", publicKeys,
                "--aad", AssociatedData, "--challenger-public-key", challengerPublic).ConfigureAwait(false);
            Assert.AreEqual(0, prepare.ExitCode, prepare.Stderr);
            Assert.AreEqual(ciphertext[..PointHexLength], prepare.Stdout.Trim());

            CliResult wrongChallenger = await RunAsync(
                executable, "secdsa-proof-respond-prepare", "--challenge", challenge, "--generators", generators, "--public-keys", publicKeys,
                "--aad", AssociatedData, "--challenger-public-key", proverPublic).ConfigureAwait(false);
            Assert.AreEqual(1, wrongChallenger.ExitCode);

            CliResult wrongData = await RunAsync(
                executable, "secdsa-proof-respond-prepare", "--challenge", challenge, "--generators", generators, "--public-keys", publicKeys,
                "--aad", "616264", "--challenger-public-key", challengerPublic).ConfigureAwait(false);
            Assert.AreEqual(1, wrongData.ExitCode);

            //The key holder, a separate step: Z_AB from d*E.
            CliResult agree = await RunAsync(executable, "secdsa-ecies-agree", "--private-key-file", witnessPath, "--point", prepare.Stdout.Trim(), "--output", agreedPath).ConfigureAwait(false);
            Assert.AreEqual(0, agree.ExitCode, agree.Stderr);

            //A wrong shared secret yields no response.
            CliResult wrongSecret = await RunAsync(
                executable, "secdsa-proof-respond-complete", "--shared-secret-file", wrongAgreedPath, "--challenge", challenge, "--ciphertext", ciphertext,
                "--generators", generators, "--public-keys", publicKeys, "--aad", AssociatedData, "--signing-key-file", proverKeyPath).ConfigureAwait(false);
            Assert.AreEqual(1, wrongSecret.ExitCode);
            Assert.AreEqual(string.Empty, wrongSecret.Stdout.Trim());

            CliResult respond = await RunAsync(
                executable, "secdsa-proof-respond-complete", "--shared-secret-file", agreedPath, "--challenge", challenge, "--ciphertext", ciphertext,
                "--generators", generators, "--public-keys", publicKeys, "--aad", AssociatedData, "--signing-key-file", proverKeyPath,
                "--additional-secret-data-output", recoveredPath).ConfigureAwait(false);
            Assert.AreEqual(0, respond.ExitCode, respond.Stderr);
            string response = respond.Stdout.Trim();
            Assert.AreEqual(AdditionalSecret, (await File.ReadAllTextAsync(recoveredPath, TestContext.CancellationToken).ConfigureAwait(false)).Trim());
            Assert.DoesNotContain(AdditionalSecret, respond.Stdout + respond.Stderr, StringComparison.Ordinal);

            CliResult verify = await RunAsync(
                executable, "secdsa-proof-verify", "--challenge", challenge, "--response", response, "--generators", generators, "--public-keys", publicKeys,
                "--aad", AssociatedData, "--challenger-public-key", challengerPublic, "--prover-public-key", proverPublic).ConfigureAwait(false);
            Assert.AreEqual(0, verify.ExitCode, verify.Stdout);
            Assert.Contains("VALID", verify.Stdout, StringComparison.Ordinal);

            CliResult wrongProver = await RunAsync(
                executable, "secdsa-proof-verify", "--challenge", challenge, "--response", response, "--generators", generators, "--public-keys", publicKeys,
                "--aad", AssociatedData, "--challenger-public-key", challengerPublic, "--prover-public-key", challengerPublic).ConfigureAwait(false);
            Assert.AreEqual(1, wrongProver.ExitCode);

            CliResult tamperedResponse = await RunAsync(
                executable, "secdsa-proof-verify", "--challenge", challenge, "--response", Flip(response), "--generators", generators, "--public-keys", publicKeys,
                "--aad", AssociatedData, "--challenger-public-key", challengerPublic, "--prover-public-key", proverPublic).ConfigureAwait(false);
            Assert.AreEqual(1, tamperedResponse.ExitCode);

            CliResult otherData = await RunAsync(
                executable, "secdsa-proof-verify", "--challenge", challenge, "--response", response, "--generators", generators, "--public-keys", publicKeys,
                "--aad", "616264", "--challenger-public-key", challengerPublic, "--prover-public-key", proverPublic).ConfigureAwait(false);
            Assert.AreEqual(1, otherData.ExitCode);
        }
        finally
        {
            File.Delete(witnessPath);
            File.Delete(challengerKeyPath);
            File.Delete(proverKeyPath);
            File.Delete(secretDataPath);
            File.Delete(agreedPath);
            File.Delete(wrongAgreedPath);
            File.Delete(recoveredPath);
        }
    }


    [TestMethod]
    public async Task TransferableProofChallengeOnAStatementThatDoesNotHoldIsNeverAnsweredByTheRespondPhases()
    {
        string executable = RequireExecutable();
        string witnessPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(ProverWitness));
        string challengerKeyPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(ChallengerSigningKey));
        string proverKeyPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(ProverSigningKey));
        string agreedPath = TemporaryOutputPath("z");
        try
        {
            string generators = await PublicKeyAsync(executable, 1, 1).ConfigureAwait(false) + await PublicKeyAsync(executable, 1, SecondGeneratorScalar).ConfigureAwait(false);

            //D1 is built with another witness, so D0 = d*G0 and D1 != d*G1.
            string publicKeys = await PublicKeyAsync(executable, ProverWitness, 1).ConfigureAwait(false) + await PublicKeyAsync(executable, ProverWitness + 1, SecondGeneratorScalar).ConfigureAwait(false);
            string challengerPublic = await PublicKeyAsync(executable, 1, ChallengerSigningKey).ConfigureAwait(false);

            CliResult challengeResult = await RunAsync(
                executable, "secdsa-proof-challenge", "--signing-key-file", challengerKeyPath, "--generators", generators, "--public-keys", publicKeys).ConfigureAwait(false);
            Assert.AreEqual(0, challengeResult.ExitCode, challengeResult.Stderr);
            using JsonDocument document = JsonDocument.Parse(challengeResult.Stdout);
            string challenge = document.RootElement.GetProperty("challenge").GetString() ?? string.Empty;
            string ciphertext = document.RootElement.GetProperty("ciphertext").GetString() ?? string.Empty;

            CliResult prepare = await RunAsync(
                executable, "secdsa-proof-respond-prepare", "--challenge", challenge, "--generators", generators, "--public-keys", publicKeys,
                "--challenger-public-key", challengerPublic).ConfigureAwait(false);
            Assert.AreEqual(0, prepare.ExitCode, prepare.Stderr);
            CliResult agree = await RunAsync(executable, "secdsa-ecies-agree", "--private-key-file", witnessPath, "--point", prepare.Stdout.Trim(), "--output", agreedPath).ConfigureAwait(false);
            Assert.AreEqual(0, agree.ExitCode, agree.Stderr);

            CliResult respond = await RunAsync(
                executable, "secdsa-proof-respond-complete", "--shared-secret-file", agreedPath, "--challenge", challenge, "--ciphertext", ciphertext,
                "--generators", generators, "--public-keys", publicKeys, "--signing-key-file", proverKeyPath).ConfigureAwait(false);
            Assert.AreEqual(1, respond.ExitCode);
            Assert.AreEqual(string.Empty, respond.Stdout.Trim());
        }
        finally
        {
            File.Delete(witnessPath);
            File.Delete(challengerKeyPath);
            File.Delete(proverKeyPath);
            File.Delete(agreedPath);
        }
    }


    private async Task<string> PublicKeyAsync(string executable, ulong pin, ulong hardware)
    {
        string pinPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(pin));
        string hardwarePath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(hardware));
        try
        {
            CliResult result = await RunAsync(executable, "secdsa-public-key", "--pin-key-file", pinPath, "--hardware-key-file", hardwarePath).ConfigureAwait(false);
            Assert.AreEqual(0, result.ExitCode, result.Stderr);

            return result.Stdout.Trim();
        }
        finally
        {
            File.Delete(pinPath);
            File.Delete(hardwarePath);
        }
    }


    private Task<CliResult> RunAsync(string executable, params string[] arguments) =>
        VeridicalCliTestHelpers.RunCliAsync(executable, arguments, TestContext.CancellationToken);


    private static string TemporaryOutputPath(string suffix) => Path.Combine(Path.GetTempPath(), $"veridical-test-{Guid.NewGuid():N}.{suffix}");


    private static string Flip(string hex) => hex[..^1] + (hex[^1] == '0' ? "1" : "0");


    private static string Scalar(ulong value) => value.ToString("x64", CultureInfo.InvariantCulture);


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

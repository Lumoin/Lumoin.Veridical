using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Globalization;
using System.IO;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.ToolTests;

/// <summary>
/// End-to-end tests of the <c>secdsa-*</c> subcommands: the built <c>veridical</c> executable is run as a
/// subprocess, secret scalars are passed only as files, and the exit codes are checked for tampered and
/// invalid input. Inconclusive when the executable has not been built.
/// </summary>
[TestClass]
internal sealed class SecdsaCliTests
{
    //SHA-256 of "abc", a fixed 32-byte message hash.
    private const string MessageHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    private const string AnotherMessageHash = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

    private const ulong PinKey = 7;

    private const ulong HardwareKey = 11;

    private const ulong DlWitness = 13;

    private const ulong VerifierEphemeralKey = 19;

    private const string Salt = "73616c74";

    private const string SharedInfo = "696e666f";

    private const string Message = "6d657373616765";

    private const int SignatureHexLength = 128;


    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Skips every test of the class under WebAssembly, where the runtime cannot start the executable as a child process.
    /// </summary>
    [TestInitialize]
    public void RequireSubprocessSupport() => RuntimeRequirements.RequireProcessSpawning();


    [TestMethod]
    public async Task SplitSignVerifyRecoverAndVerifyFullRoundTripWithKeysOnlyInFiles()
    {
        string executable = RequireExecutable();
        string pinPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(PinKey));
        string hardwarePath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(HardwareKey));
        try
        {
            CliResult publicKeyResult = await RunAsync(executable, "secdsa-public-key", "--pin-key-file", pinPath, "--hardware-key-file", hardwarePath).ConfigureAwait(false);
            Assert.AreEqual(0, publicKeyResult.ExitCode, publicKeyResult.Stderr);
            string publicKey = publicKeyResult.Stdout.Trim();

            CliResult sign = await RunAsync(executable, "secdsa-split-sign", "--pin-key-file", pinPath, "--hardware-key-file", hardwarePath, "--message-hash", MessageHash).ConfigureAwait(false);
            Assert.AreEqual(0, sign.ExitCode, sign.Stderr);
            string signature = sign.Stdout.Trim();
            Assert.AreEqual(SignatureHexLength, signature.Length);
            Assert.DoesNotContain(Scalar(PinKey), sign.Stdout + sign.Stderr, StringComparison.Ordinal);
            Assert.DoesNotContain(Scalar(HardwareKey), sign.Stdout + sign.Stderr, StringComparison.Ordinal);

            CliResult valid = await RunAsync(executable, "secdsa-verify", "--public-key", publicKey, "--message-hash", MessageHash, "--signature", signature).ConfigureAwait(false);
            Assert.AreEqual(0, valid.ExitCode, valid.Stdout);
            Assert.Contains("VALID", valid.Stdout, StringComparison.Ordinal);

            CliResult wrongHash = await RunAsync(executable, "secdsa-verify", "--public-key", publicKey, "--message-hash", AnotherMessageHash, "--signature", signature).ConfigureAwait(false);
            Assert.AreEqual(1, wrongHash.ExitCode);
            Assert.Contains("REJECTED", wrongHash.Stdout, StringComparison.Ordinal);

            CliResult recover = await RunAsync(executable, "secdsa-recover-nonce-point", "--public-key", publicKey, "--message-hash", MessageHash, "--signature", signature).ConfigureAwait(false);
            Assert.AreEqual(0, recover.ExitCode, recover.Stderr);

            CliResult full = await RunAsync(executable, "secdsa-verify-full", "--public-key", publicKey, "--message-hash", MessageHash, "--nonce-point", recover.Stdout.Trim(), "--s", signature[64..]).ConfigureAwait(false);
            Assert.AreEqual(0, full.ExitCode, full.Stdout);
        }
        finally
        {
            File.Delete(pinPath);
            File.Delete(hardwarePath);
        }
    }


    [TestMethod]
    public async Task SplitSignWithAMissingKeyFileOrAZeroScalarExitsOne()
    {
        string executable = RequireExecutable();
        string zeroPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(0));
        string hardwarePath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(HardwareKey));
        try
        {
            CliResult missing = await RunAsync(executable, "secdsa-split-sign", "--pin-key-file", zeroPath + ".missing", "--hardware-key-file", hardwarePath, "--message-hash", MessageHash).ConfigureAwait(false);
            Assert.AreEqual(1, missing.ExitCode);
            Assert.Contains("could not read the pin key", missing.Stderr, StringComparison.Ordinal);

            CliResult zero = await RunAsync(executable, "secdsa-split-sign", "--pin-key-file", zeroPath, "--hardware-key-file", hardwarePath, "--message-hash", MessageHash).ConfigureAwait(false);
            Assert.AreEqual(1, zero.ExitCode);
            Assert.Contains("Error:", zero.Stderr, StringComparison.Ordinal);

            CliResult noOptions = await RunAsync(executable, "secdsa-split-sign").ConfigureAwait(false);
            Assert.AreEqual(1, noOptions.ExitCode);
        }
        finally
        {
            File.Delete(zeroPath);
            File.Delete(hardwarePath);
        }
    }


    [TestMethod]
    public async Task DlEqualityEvidenceBlindingAndControlRelationsRoundTrip()
    {
        string executable = RequireExecutable();
        string witnessPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(DlWitness));
        string blindingWitnessPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(VerifierEphemeralKey));
        try
        {
            string g = await PublicKeyAsync(executable, 1, 1).ConfigureAwait(false);
            string other = await PublicKeyAsync(executable, 1, VerifierEphemeralKey).ConfigureAwait(false);
            string witnessPoint = await PublicKeyAsync(executable, 1, DlWitness).ConfigureAwait(false);
            string witnessOtherPoint = await PublicKeyAsync(executable, DlWitness, VerifierEphemeralKey).ConfigureAwait(false);

            CliResult dlProve = await RunAsync(executable, "secdsa-dl-prove", "--witness-file", witnessPath, "--generators", g + other, "--public-keys", witnessPoint + witnessOtherPoint, "--challenge", Message).ConfigureAwait(false);
            Assert.AreEqual(0, dlProve.ExitCode, dlProve.Stderr);
            CliResult dlVerify = await RunAsync(executable, "secdsa-dl-verify", "--generators", g + other, "--public-keys", witnessPoint + witnessOtherPoint, "--challenge", Message, "--proof", dlProve.Stdout.Trim()).ConfigureAwait(false);
            Assert.AreEqual(0, dlVerify.ExitCode, dlVerify.Stdout);
            CliResult dlWrong = await RunAsync(executable, "secdsa-dl-verify", "--generators", g + other, "--public-keys", witnessPoint + witnessOtherPoint, "--proof", dlProve.Stdout.Trim()).ConfigureAwait(false);
            Assert.AreEqual(1, dlWrong.ExitCode);

            CliResult blindProve = await RunAsync(executable, "secdsa-blinding-prove", "--g", g, "--g-double-prime", other, "--y-prime", witnessPoint, "--y-double-prime", witnessOtherPoint, "--witness-file", blindingWitnessPath).ConfigureAwait(false);
            Assert.AreEqual(0, blindProve.ExitCode, blindProve.Stderr);
            CliResult blindVerify = await RunAsync(executable, "secdsa-blinding-verify", "--g", g, "--g-double-prime", other, "--y-prime", witnessPoint, "--y-double-prime", witnessOtherPoint, "--proof", blindProve.Stdout.Trim()).ConfigureAwait(false);
            Assert.AreEqual(0, blindVerify.ExitCode, blindVerify.Stdout);

            CliResult controlProve = await RunAsync(executable, "secdsa-control-prove", "--h", g, "--w", other, "--h-prime", witnessPoint, "--w-prime", witnessOtherPoint, "--witness-file", witnessPath, "--record-context", Message).ConfigureAwait(false);
            Assert.AreEqual(0, controlProve.ExitCode, controlProve.Stderr);
            CliResult controlVerify = await RunAsync(executable, "secdsa-control-verify", "--h", g, "--w", other, "--h-prime", witnessPoint, "--w-prime", witnessOtherPoint, "--record-context", Message, "--proof", controlProve.Stdout.Trim()).ConfigureAwait(false);
            Assert.AreEqual(0, controlVerify.ExitCode, controlVerify.Stdout);
            CliResult controlWrong = await RunAsync(executable, "secdsa-control-verify", "--h", g, "--w", other, "--h-prime", witnessPoint, "--w-prime", witnessOtherPoint, "--record-context", Salt, "--proof", controlProve.Stdout.Trim()).ConfigureAwait(false);
            Assert.AreEqual(1, controlWrong.ExitCode);
        }
        finally
        {
            File.Delete(witnessPath);
            File.Delete(blindingWitnessPath);
        }
    }


    [TestMethod]
    public async Task EcdhMacSignVerifyDeriveKeyAndSplitSignRoundTrip()
    {
        string executable = RequireExecutable();
        string proverPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(PinKey));
        string verifierPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(VerifierEphemeralKey));
        string walletPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(2));
        string wscaPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(3));
        string basePath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(5));
        string composedPath = VeridicalCliTestHelpers.WriteTemporaryFile(Scalar(30));
        string macKeyPath = Path.Combine(Path.GetTempPath(), $"veridical-test-{Guid.NewGuid():N}.key");
        try
        {
            string proverPublic = await PublicKeyAsync(executable, 1, PinKey).ConfigureAwait(false);
            string verifierPublic = await PublicKeyAsync(executable, 1, VerifierEphemeralKey).ConfigureAwait(false);

            CliResult sign = await RunAsync(executable, "secdsa-ecdh-mac-sign", "--private-key-file", proverPath, "--verifier-ephemeral-public-key", verifierPublic, "--salt", Salt, "--shared-info", SharedInfo, "--message", Message).ConfigureAwait(false);
            Assert.AreEqual(0, sign.ExitCode, sign.Stderr);
            string mac = sign.Stdout.Trim();

            CliResult verify = await RunAsync(executable, "secdsa-ecdh-mac-verify", "--prover-public-key", proverPublic, "--verifier-ephemeral-private-key-file", verifierPath, "--salt", Salt, "--shared-info", SharedInfo, "--message", Message, "--mac", mac).ConfigureAwait(false);
            Assert.AreEqual(0, verify.ExitCode, verify.Stdout);
            CliResult tampered = await RunAsync(executable, "secdsa-ecdh-mac-verify", "--prover-public-key", proverPublic, "--verifier-ephemeral-private-key-file", verifierPath, "--salt", Salt, "--shared-info", SharedInfo, "--message", SharedInfo, "--mac", mac).ConfigureAwait(false);
            Assert.AreEqual(1, tampered.ExitCode);

            CliResult derive = await RunAsync(executable, "secdsa-ecdh-mac-derive-key", "--private-key-file", proverPath, "--peer-public-point", verifierPublic, "--salt", Salt, "--shared-info", SharedInfo, "--output", macKeyPath).ConfigureAwait(false);
            Assert.AreEqual(0, derive.ExitCode, derive.Stderr);
            string macKey = (await File.ReadAllTextAsync(macKeyPath, TestContext.CancellationToken).ConfigureAwait(false)).Trim();
            Assert.AreEqual(64, macKey.Length);
            Assert.DoesNotContain(macKey, derive.Stdout + derive.Stderr, StringComparison.Ordinal);
            CliResult overwrite = await RunAsync(executable, "secdsa-ecdh-mac-derive-key", "--private-key-file", proverPath, "--peer-public-point", verifierPublic, "--output", macKeyPath).ConfigureAwait(false);
            Assert.AreEqual(1, overwrite.ExitCode);

            CliResult split = await RunAsync(executable, "secdsa-ecdh-mac-split-sign", "--wallet-key-share-file", walletPath, "--wsca-key-share-file", wscaPath, "--base-key-file", basePath, "--verifier-ephemeral-public-key", verifierPublic, "--salt", Salt, "--shared-info", SharedInfo, "--message", Message).ConfigureAwait(false);
            Assert.AreEqual(0, split.ExitCode, split.Stderr);
            CliResult direct = await RunAsync(executable, "secdsa-ecdh-mac-sign", "--private-key-file", composedPath, "--verifier-ephemeral-public-key", verifierPublic, "--salt", Salt, "--shared-info", SharedInfo, "--message", Message).ConfigureAwait(false);
            Assert.AreEqual(direct.Stdout.Trim(), split.Stdout.Trim());
        }
        finally
        {
            File.Delete(proverPath);
            File.Delete(verifierPath);
            File.Delete(walletPath);
            File.Delete(wscaPath);
            File.Delete(basePath);
            File.Delete(composedPath);
            File.Delete(macKeyPath);
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

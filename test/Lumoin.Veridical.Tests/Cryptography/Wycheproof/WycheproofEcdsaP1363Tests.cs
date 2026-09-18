using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Secdsa;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Cryptography.Wycheproof;

/// <summary>
/// Gates three independent ECDSA-P-256 verifiers against the complete C2SP/wycheproof
/// secp256r1 IEEE P1363 catalogue: the in-repo BigInteger reference
/// (<see cref="P256EcdsaReference"/>), the public <see cref="SecdsaAlgorithm.Verify"/>
/// wired with BigInteger reference delegates, and the same public API wired with the
/// constant-time <see cref="P256ManagedScalarBackend"/> and
/// <see cref="P256ManagedG1Backend"/> bundles. The catalogue is the canonical register
/// of historically exploited ECDSA verification bugs — CVE-2022-21449 (Psychic
/// Signatures: r = 0, s = 0), range-check gaps, arithmetic edge cases, point
/// duplication, Shamir multiplication hazards — so passing it means the verifier
/// rejects them all, not just the trivial cases.
/// </summary>
[TestClass]
internal sealed class WycheproofEcdsaP1363Tests
{
    /// <summary>
    /// The IEEE P1363 signature size in bytes: the P-256 field size is 32
    /// bytes, and P1363 concatenates <c>r‖s</c> each 32 bytes.
    /// </summary>
    private const int P1363SignatureSizeBytes = 64;

    /// <summary>
    /// The SHA-256 digest size in bytes: 256 bits.
    /// </summary>
    private const int DigestSizeBytes = 32;

    /// <summary>
    /// The cap on mismatches listed in a failure message, to keep the
    /// output readable when verification breaks widely.
    /// </summary>
    private const int MaxPrintedMismatches = 20;

    /// <summary>
    /// The expected SHA-256 hash of the P1363 fixture file; see
    /// <c>Fixtures/FIXTURES.md</c>.
    /// </summary>
    private const string PinnedP1363Sha256 = "c60de693930e386c3a5472d08081623ef8504decc54b38ac01ec6b2a2575c986";

    /// <summary>
    /// The expected SHA-256 hash of the ASN.1 fixture file; see
    /// <c>Fixtures/FIXTURES.md</c>.
    /// </summary>
    private const string PinnedAsn1Sha256 = "182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332";

    /// <summary>
    /// The BigInteger-backed scalar multiplication delegate, wired once per
    /// test run.
    /// </summary>
    private static ScalarMultiplyDelegate BigIntegerScalarMultiply { get; } =
        P256BigIntegerScalarReference.GetMultiply();

    /// <summary>
    /// The BigInteger-backed scalar inversion delegate, wired once per
    /// test run.
    /// </summary>
    private static ScalarInvertDelegate BigIntegerScalarInvert { get; } =
        P256BigIntegerScalarReference.GetInvert();

    /// <summary>
    /// The BigInteger-backed scalar reduction delegate, wired once per
    /// test run.
    /// </summary>
    private static ScalarReduceDelegate BigIntegerScalarReduce { get; } =
        P256BigIntegerScalarReference.GetReduce();

    /// <summary>
    /// The BigInteger-backed G1 scalar multiplication delegate, wired once
    /// per test run.
    /// </summary>
    private static G1ScalarMultiplyDelegate BigIntegerG1ScalarMultiply { get; } =
        P256BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>
    /// The BigInteger-backed G1 addition delegate, wired once per test run.
    /// </summary>
    private static G1AddDelegate BigIntegerG1Add { get; } =
        P256BigIntegerG1Reference.GetAdd();

    /// <summary>
    /// The constant-time scalar-arithmetic backend, wired once per test run.
    /// </summary>
    private static ScalarArithmeticBackend CtScalarBackend { get; } =
        P256ManagedScalarBackend.Create();

    /// <summary>
    /// The constant-time G1-arithmetic backend, wired once per test run.
    /// </summary>
    private static G1ArithmeticBackend CtG1Backend { get; } =
        P256ManagedG1Backend.Create();


    /// <summary>
    /// Every P1363 vector in the catalogue matches the in-repo BigInteger
    /// reference verifier's accept/reject verdict.
    /// </summary>
    [TestMethod]
    public void EveryP1363VectorMatchesTheReferenceVerifier()
    {
        WycheproofFileResult? file = WycheproofEcdsaFixtures.TryLoadP1363();
        if(file is null)
        {
            Assert.Inconclusive(
                "P1363 fixture file not found. See Cryptography/Wycheproof/Fixtures/FIXTURES.md.");
        }

        var mismatches = new List<string>();
        int processed = 0;

        foreach(WycheproofVector v in file.Vectors)
        {
            bool actual = RunReferenceVerifier(v);
            RecordResult(v, actual, mismatches);
            processed++;
        }

        Assert.AreEqual(file.DeclaredNumberOfTests, processed,
            $"Processed vector count {processed} does not match the fixture's declared numberOfTests {file.DeclaredNumberOfTests}.");
        AssertNoMismatches(mismatches, "P256EcdsaReference");
    }


    /// <summary>
    /// Every P1363 vector in the catalogue matches
    /// <see cref="SecdsaAlgorithm.Verify"/>'s verdict when wired with
    /// BigInteger reference delegates.
    /// </summary>
    [TestMethod]
    public void EveryP1363VectorMatchesSecdsaAlgorithmWithBigIntegerDelegates()
    {
        WycheproofFileResult? file = WycheproofEcdsaFixtures.TryLoadP1363();
        if(file is null)
        {
            Assert.Inconclusive(
                "P1363 fixture file not found. See Cryptography/Wycheproof/Fixtures/FIXTURES.md.");
        }

        var mismatches = new List<string>();
        int processed = 0;

        foreach(WycheproofVector v in file.Vectors)
        {
            bool actual = RunSecdsaVerifierBigInteger(v);
            RecordResult(v, actual, mismatches);
            processed++;
        }

        Assert.AreEqual(file.DeclaredNumberOfTests, processed,
            $"Processed vector count {processed} does not match the fixture's declared numberOfTests {file.DeclaredNumberOfTests}.");
        AssertNoMismatches(mismatches, "SecdsaAlgorithm/BigIntegerDelegates");
    }


    /// <summary>
    /// Every P1363 vector in the catalogue matches
    /// <see cref="SecdsaAlgorithm.Verify"/>'s verdict when wired with the
    /// constant-time backend bundles.
    /// </summary>
    [TestMethod]
    public void EveryP1363VectorMatchesSecdsaAlgorithmWithConstantTimeBundles()
    {
        WycheproofFileResult? file = WycheproofEcdsaFixtures.TryLoadP1363();
        if(file is null)
        {
            Assert.Inconclusive(
                "P1363 fixture file not found. See Cryptography/Wycheproof/Fixtures/FIXTURES.md.");
        }

        var mismatches = new List<string>();
        int processed = 0;

        foreach(WycheproofVector v in file.Vectors)
        {
            bool actual = RunSecdsaVerifierConstantTime(v);
            RecordResult(v, actual, mismatches);
            processed++;
        }

        Assert.AreEqual(file.DeclaredNumberOfTests, processed,
            $"Processed vector count {processed} does not match the fixture's declared numberOfTests {file.DeclaredNumberOfTests}.");
        AssertNoMismatches(mismatches, "SecdsaAlgorithm/ConstantTimeBundles");
    }


    /// <summary>
    /// The on-disk fixture files hash to the pinned values in
    /// <see cref="PinnedP1363Sha256"/> and <see cref="PinnedAsn1Sha256"/>.
    /// A missing file fails the assertion rather than reporting zero
    /// vectors processed.
    /// </summary>
    [TestMethod]
    public void FixtureIntegrityMatchesPinnedHashes()
    {
        string actualP1363 = WycheproofEcdsaFixtures.ComputeFileSha256Hex(WycheproofEcdsaFixtures.P1363FileName);
        string actualAsn1 = WycheproofEcdsaFixtures.ComputeFileSha256Hex(WycheproofEcdsaFixtures.Asn1FileName);

        if(string.IsNullOrEmpty(actualP1363) || string.IsNullOrEmpty(actualAsn1))
        {
            Assert.Fail(
                "Fixture files are committed and copied by the csproj; absence indicates the copy pipeline regressed.");
        }

        Assert.AreEqual(PinnedP1363Sha256, actualP1363,
            "SHA-256 of ecdsa_secp256r1_sha256_p1363_test.json does not match the pinned hash. Re-pin after a deliberate upstream update.");
        Assert.AreEqual(PinnedAsn1Sha256, actualAsn1,
            "SHA-256 of ecdsa_secp256r1_sha256_test.json does not match the pinned hash. Re-pin after a deliberate upstream update.");
    }


    /// <summary>
    /// Verifies one vector against the in-repo BigInteger reference
    /// verifier, treating a non-64-byte signature and an
    /// argument-validation rejection alike as a failed verification.
    /// </summary>
    private static bool RunReferenceVerifier(WycheproofVector v)
    {
        if(v.Signature.Length != P1363SignatureSizeBytes)
        {
            //The fixed-width API cannot present a non-64-byte signature; treat as rejected.
            return false;
        }

        Span<byte> digest = stackalloc byte[DigestSizeBytes];
        SHA256.HashData(v.Message, digest);

        ReadOnlySpan<byte> sig = v.Signature;
        ReadOnlySpan<byte> r = sig[..DigestSizeBytes];
        ReadOnlySpan<byte> s = sig[DigestSizeBytes..];

        try
        {
            return P256EcdsaReference.Verify(v.CompressedKey, digest, r, s);
        }
        catch(ArgumentException)
        {
            return false;
        }
    }


    /// <summary>
    /// Verifies one vector through <see cref="SecdsaAlgorithm.Verify"/>
    /// wired with BigInteger reference delegates, treating a non-64-byte
    /// signature and an argument-validation rejection alike as a failed
    /// verification.
    /// </summary>
    private static bool RunSecdsaVerifierBigInteger(WycheproofVector v)
    {
        if(v.Signature.Length != P1363SignatureSizeBytes)
        {
            return false;
        }

        Span<byte> digest = stackalloc byte[DigestSizeBytes];
        SHA256.HashData(v.Message, digest);

        ReadOnlySpan<byte> sig = v.Signature;
        ReadOnlySpan<byte> r = sig[..DigestSizeBytes];
        ReadOnlySpan<byte> s = sig[DigestSizeBytes..];

        try
        {
            return SecdsaAlgorithm.Verify(
                v.CompressedKey, digest, r, s,
                BigIntegerScalarMultiply, BigIntegerScalarInvert, BigIntegerScalarReduce,
                BigIntegerG1ScalarMultiply, BigIntegerG1Add);
        }
        catch(ArgumentException)
        {
            return false;
        }
    }


    /// <summary>
    /// Verifies one vector through <see cref="SecdsaAlgorithm.Verify"/>
    /// wired with the constant-time backend bundles, treating a
    /// non-64-byte signature and an argument-validation rejection alike as
    /// a failed verification.
    /// </summary>
    private static bool RunSecdsaVerifierConstantTime(WycheproofVector v)
    {
        if(v.Signature.Length != P1363SignatureSizeBytes)
        {
            return false;
        }

        Span<byte> digest = stackalloc byte[DigestSizeBytes];
        SHA256.HashData(v.Message, digest);

        ReadOnlySpan<byte> sig = v.Signature;
        ReadOnlySpan<byte> r = sig[..DigestSizeBytes];
        ReadOnlySpan<byte> s = sig[DigestSizeBytes..];

        try
        {
            return SecdsaAlgorithm.Verify(
                v.CompressedKey, digest, r, s,
                CtScalarBackend.Multiply, CtScalarBackend.Invert, CtScalarBackend.Reduce,
                CtG1Backend.ScalarMultiply, CtG1Backend.Add);
        }
        catch(ArgumentException)
        {
            return false;
        }
    }


    /// <summary>
    /// Records a mismatch when a vector's actual verification result
    /// differs from its declared expectation. A non-64-byte P1363
    /// signature makes the runner return false, which is correct when the
    /// vector expects rejection and a recorded mismatch when it expects
    /// acceptance.
    /// </summary>
    private static void RecordResult(WycheproofVector v, bool actual, List<string> mismatches)
    {
        if(actual == v.ExpectedValid)
        {
            return;
        }

        string flags = string.Join(", ", v.Flags);
        mismatches.Add(
            $"tcId {v.TcId}: \"{v.Comment}\" (flags: [{flags}]) — expected {(v.ExpectedValid ? "valid" : "invalid")}, got {(actual ? "valid" : "invalid")}");
    }


    /// <summary>
    /// Fails the test with every recorded mismatch listed against
    /// <paramref name="target"/>, capped at
    /// <see cref="MaxPrintedMismatches"/> entries.
    /// </summary>
    private static void AssertNoMismatches(List<string> mismatches, string target)
    {
        if(mismatches.Count == 0)
        {
            return;
        }

        var sb = new StringBuilder();
        sb.AppendLine(CultureInfo.InvariantCulture, $"{mismatches.Count} mismatch(es) against {target}:");
        foreach(string entry in mismatches.Take(MaxPrintedMismatches))
        {
            sb.AppendLine(entry);
        }

        int extra = mismatches.Count - MaxPrintedMismatches;
        if(extra > 0)
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"...and {extra} more.");
        }

        Assert.IsEmpty(mismatches, sb.ToString());
    }
}

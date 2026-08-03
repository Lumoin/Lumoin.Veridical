using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Longfellow;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using static Lumoin.Veridical.Tests.Algebraic.LongfellowKernelZkTestHarness;

namespace Lumoin.Veridical.Tests.Longfellow;

/// <summary>
/// The JWT-statement facade gates: the verifier public-input assembly pinned against the kernel
/// harness's convention without compiling the circuit, the fast unprovable-token and malformed
/// key-binding rejections, and the Slow end-to-end proofs — the reference token through the
/// facade at the production Ligero shape with tamper rejections, and a freshly generated token
/// that exercises the encode seam and proves the extractor beyond the single reference vector.
/// </summary>
[TestClass]
internal sealed class LongfellowJwtFacadeTests
{
    /// <summary>The disclosed attribute identifier of the reference token's pinned statement.</summary>
    private const string ErikaAttributeId = "given_name";

    /// <summary>The disclosed attribute value of the reference token's pinned statement.</summary>
    private const string ErikaAttributeValue = "Erika";

    /// <summary>The Fiat-Shamir session seed of the facade end-to-end gates.</summary>
    private static byte[] FacadeTranscriptSeed { get; } = Encoding.ASCII.GetBytes("jwt-facade-e2e");

    /// <summary>The proof byte the tamper probe flips: inside the sumcheck segment, past the commitment root.</summary>
    private const int TamperOffset = DigestSize + 8;

    /// <summary>The truncation length of the malformed-proof probe: past the commitment root, far short of the sumcheck segment.</summary>
    private const int TruncatedProofBytes = DigestSize + 8;

    /// <summary>The byte count cut from the envelope's tail for the Ligero-segment truncation probe: small enough that the cut lands inside the Ligero segment, past the fixed-size sumcheck segment.</summary>
    private const int LigeroTailTruncationBytes = 8;


    /// <summary>
    /// The agreement gate: the facade's verifier public-input assembly over the Erika vector
    /// byte-equals an independent construction in the kernel harness's convention — the constant
    /// one, the issuer key, the reference's hardcoded <c>e2</c>, the attribute fill, and the
    /// little-endian element reversal — without compiling the circuit.
    /// </summary>
    [TestMethod]
    public void TheVerifierPublicInputAssemblyMatchesTheHarnessConvention()
    {
        LongfellowJwtTestVectors.TokenVector vector = LongfellowJwtTestVectors.ErikaToken;
        LongfellowJwtStatement statement = NewErikaStatement();
        LongfellowLogicFieldOperations field = LongfellowJwtBundles.NewFieldBundle();

        byte[] token = Encoding.ASCII.GetBytes(vector.Token);
        Assert.IsTrue(LongfellowJwsCompact.TrySplitPresentation(token, out _, out Range keyBindingRange), "The reference token must split.");
        Span<byte> digest = stackalloc byte[ScalarSize];
        Assert.IsTrue(LongfellowJwsCompact.TryComputeKeyBindingDigest(token.AsSpan()[keyBindingRange], digest), "The key-binding digest must compute.");

        int elementCount = LongfellowJwtBundles.PublicInputElementCount(statement.Attributes.Count);
        int regionBytes = elementCount * ScalarSize;

        //The independent expectation: the harness's public-region fill order over the Core types,
        //then the harness's little-endian element reversal.
        using IMemoryOwner<byte> canonicalOwner = BaseMemoryPool.Shared.Rent(regionBytes);
        Span<byte> canonical = canonicalOwner.Memory.Span[..regionBytes];
        field.Compiler.One.Span.CopyTo(canonical[..ScalarSize]);
        int cursor = 1;
        ParseScalar(vector.PkX).CopyTo(canonical.Slice(cursor * ScalarSize, ScalarSize));
        cursor++;
        ParseScalar(vector.PkY).CopyTo(canonical.Slice(cursor * ScalarSize, ScalarSize));
        cursor++;
        ParseScalar(vector.E2).CopyTo(canonical.Slice(cursor * ScalarSize, ScalarSize));
        cursor++;
        LongfellowJwtWitness.FillAttribute(field, new LongfellowJwtOpenedAttribute(Encoding.UTF8.GetBytes(ErikaAttributeId), Encoding.UTF8.GetBytes(ErikaAttributeValue)), canonical, ref cursor);
        Assert.AreEqual(elementCount, cursor, "The independent fill must cover exactly the public-input elements.");

        using IMemoryOwner<byte> expectedOwner = BaseMemoryPool.Shared.Rent(regionBytes);
        Span<byte> expected = expectedOwner.Memory.Span[..regionBytes];
        for(int i = 0; i < elementCount; i++)
        {
            for(int b = 0; b < ScalarSize; b++)
            {
                expected[(i * ScalarSize) + b] = canonical[(i * ScalarSize) + ScalarSize - 1 - b];
            }
        }

        using IMemoryOwner<byte> actualOwner = BaseMemoryPool.Shared.Rent(regionBytes);
        Span<byte> actual = actualOwner.Memory.Span[..regionBytes];
        LongfellowJwtBundles.AssembleVerifierPublicInputs(field, statement, digest, actual, BaseMemoryPool.Shared);

        Assert.AreSequenceEqual(expected.ToArray(), actual.ToArray(), "The facade's public-input assembly must equal the harness convention byte for byte.");
    }


    /// <summary>A token that cannot satisfy the statement rejects at the witness gate, before any circuit compilation.</summary>
    [TestMethod]
    public void ProveRejectsATokenThatCannotSatisfyTheStatement()
    {
        LongfellowJwtTestVectors.TokenVector vector = LongfellowJwtTestVectors.ErikaToken;
        LongfellowJwtStatement statement = LongfellowJwtStatement.Create(
            ParseScalar(vector.PkX),
            ParseScalar(vector.PkY),
            [LongfellowJwtAttribute.FromStrings(ErikaAttributeId, "Wrong")],
            LongfellowJwtZkSpec.SevenBlocks);

        byte[] token = Encoding.ASCII.GetBytes(vector.Token);
        Assert.ThrowsExactly<ArgumentException>(
            () => LongfellowJwt.Prove(token, statement, FacadeTranscriptSeed, BaseMemoryPool.Shared).Dispose(),
            "A token lacking the required attribute value must not produce a witness.");
    }


    /// <summary>An issuer signing input past the block capacity rejects at the witness generator's capacity guard, before any signature check or circuit compilation.</summary>
    [TestMethod]
    public void ProveRejectsAnOversizedTokenAtTheCapacityGuard()
    {
        //Structurally valid segments whose signing input exceeds the seven-block maximum of 439
        //bytes; the 86-character signatures decode past the fixed-width pair so parsing succeeds
        //and the capacity guard is the branch that rejects.
        const int OversizedPayloadCharacterCount = 600;
        const int RawSignatureCharacterCount = 86;
        string oversized = "aaaaaaaaaa." + new string('a', OversizedPayloadCharacterCount) + "." + new string('A', RawSignatureCharacterCount)
            + "~aa.bb." + new string('A', RawSignatureCharacterCount);

        Assert.ThrowsExactly<ArgumentException>(
            () => LongfellowJwt.Prove(Encoding.ASCII.GetBytes(oversized), NewErikaStatement(), FacadeTranscriptSeed, BaseMemoryPool.Shared).Dispose(),
            "A token whose signing input exceeds the block capacity must reject at the witness gate.");
    }


    /// <summary>The malformed key-binding rejections answer before any circuit compilation: unparseable structure, a short signature, and an invalid unpadded length.</summary>
    [TestMethod]
    public void VerifyAnswersMalformedKeyBindingBeforeCompiling()
    {
        LongfellowJwtStatement statement = NewErikaStatement();
        Span<byte> emptyEnvelope = stackalloc byte[LongfellowJwtProof.MinimumSizeBytes];
        using LongfellowJwtProof proof = LongfellowJwtProof.FromCanonical(emptyEnvelope, BaseMemoryPool.Shared);

        Assert.AreEqual(
            LongfellowJwtVerdict.MalformedKeyBinding,
            LongfellowJwt.Verify(proof, Encoding.ASCII.GetBytes("nodots"), statement, FacadeTranscriptSeed, BaseMemoryPool.Shared),
            "A structurally unparseable key-binding JWS answers a malformed verdict.");
        Assert.AreEqual(
            LongfellowJwtVerdict.MalformedKeyBinding,
            LongfellowJwt.Verify(proof, Encoding.ASCII.GetBytes("a.b.cc"), statement, FacadeTranscriptSeed, BaseMemoryPool.Shared),
            "A signature segment decoding below the fixed-width pair answers a malformed verdict.");
        Assert.AreEqual(
            LongfellowJwtVerdict.MalformedKeyBinding,
            LongfellowJwt.Verify(proof, Encoding.ASCII.GetBytes("a.b.ccccc"), statement, FacadeTranscriptSeed, BaseMemoryPool.Shared),
            "A signature segment with an invalid unpadded length answers a malformed verdict.");
    }


    /// <summary>
    /// The facade end-to-end gate: the reference token proves and verifies at the production
    /// Ligero shape; a tampered proof rejects, a truncated envelope answers malformed, and a
    /// key-binding presentation whose recomputed digest differs rejects.
    /// </summary>
    [TestMethod]
    [TestCategory("Slow")]
    public void TheFacadeProvesAndVerifiesTheReferenceTokenEndToEnd()
    {
        LongfellowJwtStatement statement = NewErikaStatement();
        byte[] token = Encoding.ASCII.GetBytes(LongfellowJwtTestVectors.ErikaToken.Token);
        Assert.IsTrue(LongfellowJwsCompact.TrySplitPresentation(token, out _, out Range keyBindingRange), "The reference token must split.");
        byte[] keyBinding = token.AsSpan()[keyBindingRange].ToArray();

        using LongfellowJwtProof proof = LongfellowJwt.Prove(token, statement, FacadeTranscriptSeed, BaseMemoryPool.Shared);
        Assert.AreEqual(
            LongfellowJwtVerdict.Accepted,
            LongfellowJwt.Verify(proof, keyBinding, statement, FacadeTranscriptSeed, BaseMemoryPool.Shared),
            "The reference token's proof must verify.");

        //A flipped byte inside the sumcheck segment diverges the challenge stream.
        ReadOnlySpan<byte> proofBytes = proof.AsReadOnlySpan();
        using IMemoryOwner<byte> tamperedOwner = BaseMemoryPool.Shared.Rent(proofBytes.Length);
        Span<byte> tamperedBytes = tamperedOwner.Memory.Span[..proofBytes.Length];
        proofBytes.CopyTo(tamperedBytes);
        tamperedBytes[TamperOffset] ^= 0x01;
        using LongfellowJwtProof tampered = LongfellowJwtProof.FromCanonical(tamperedBytes, BaseMemoryPool.Shared);
        Assert.AreEqual(
            LongfellowJwtVerdict.Rejected,
            LongfellowJwt.Verify(tampered, keyBinding, statement, FacadeTranscriptSeed, BaseMemoryPool.Shared),
            "A tampered proof must reject.");

        //An envelope cut inside the sumcheck segment cannot parse.
        using LongfellowJwtProof truncated = LongfellowJwtProof.FromCanonical(proofBytes[..TruncatedProofBytes], BaseMemoryPool.Shared);
        Assert.AreEqual(
            LongfellowJwtVerdict.MalformedProof,
            LongfellowJwt.Verify(truncated, keyBinding, statement, FacadeTranscriptSeed, BaseMemoryPool.Shared),
            "A truncated envelope answers a malformed verdict.");

        //An envelope cut inside the Ligero segment's tail leaves the sumcheck parse intact and
        //drives the Ligero segment's own parse rejection.
        using LongfellowJwtProof ligeroTruncated = LongfellowJwtProof.FromCanonical(proofBytes[..^LigeroTailTruncationBytes], BaseMemoryPool.Shared);
        Assert.AreEqual(
            LongfellowJwtVerdict.MalformedProof,
            LongfellowJwt.Verify(ligeroTruncated, keyBinding, statement, FacadeTranscriptSeed, BaseMemoryPool.Shared),
            "An envelope truncated inside the Ligero segment answers a malformed verdict.");

        //A key-binding payload flip changes the recomputed digest, so the proof no longer binds it.
        byte[] alteredKeyBinding = (byte[])keyBinding.Clone();
        Assert.IsTrue(LongfellowJwsCompact.TryParse(alteredKeyBinding, out LongfellowJwsCompactSegments segments), "The key-binding JWS must parse.");
        alteredKeyBinding[segments.PayloadIndex] = alteredKeyBinding[segments.PayloadIndex] == (byte)'A' ? (byte)'B' : (byte)'A';
        Assert.AreEqual(
            LongfellowJwtVerdict.Rejected,
            LongfellowJwt.Verify(proof, alteredKeyBinding, statement, FacadeTranscriptSeed, BaseMemoryPool.Shared),
            "A key-binding presentation with a different recomputed digest must reject.");
    }


    /// <summary>
    /// The generated-token gate: a fresh issuer and device key pair, a token assembled through
    /// the encode seam — the <c>cnf</c> coordinates ride the injected encoder — proves and
    /// verifies through the facade, so the extractor works beyond the single reference vector.
    /// </summary>
    [TestMethod]
    [TestCategory("Slow")]
    public void TheFacadeProvesAndVerifiesAGeneratedToken()
    {
        using ECDsa issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa deviceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters issuerParameters = issuerKey.ExportParameters(includePrivateParameters: false);
        ECParameters deviceParameters = deviceKey.ExportParameters(includePrivateParameters: false);

        string deviceX = LongfellowJwsTestCodecs.Encoder(deviceParameters.Q.X);
        string deviceY = LongfellowJwsTestCodecs.Encoder(deviceParameters.Q.Y);
        //Plain concatenation keeps the cnf prefix byte-identical to the pattern the witness
        //generator's device-key extraction searches for.
        string payloadJson = "{\"iss\":\"https://issuer.example\",\"given_name\":\"Testi\",\"age_over_18\":true,"
            + "\"cnf\":{\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + deviceX + "\",\"y\":\"" + deviceY + "\"}}}";
        string issuerJws = SignCompactJws(issuerKey, /*lang=json,strict*/ """{"alg":"ES256","typ":"JWT"}""", payloadJson);
        string keyBindingJws = SignCompactJws(deviceKey, /*lang=json,strict*/ """{"alg":"ES256","typ":"kb2+jwt"}""", /*lang=json,strict*/ """{"nonce":"123123123","aud":"RP"}""");

        byte[] token = Encoding.ASCII.GetBytes(issuerJws + "~" + keyBindingJws);
        LongfellowJwtStatement statement = LongfellowJwtStatement.Create(
            issuerParameters.Q.X,
            issuerParameters.Q.Y,
            [LongfellowJwtAttribute.FromStrings(ErikaAttributeId, "Testi")],
            LongfellowJwtZkSpec.SevenBlocks);

        using LongfellowJwtProof proof = LongfellowJwt.Prove(token, statement, FacadeTranscriptSeed, BaseMemoryPool.Shared);
        Assert.AreEqual(
            LongfellowJwtVerdict.Accepted,
            LongfellowJwt.Verify(proof, Encoding.ASCII.GetBytes(keyBindingJws), statement, FacadeTranscriptSeed, BaseMemoryPool.Shared),
            "The generated token's proof must verify.");
    }


    /// <summary>Builds the reference token's pinned statement at seven blocks.</summary>
    /// <returns>The statement.</returns>
    private static LongfellowJwtStatement NewErikaStatement()
    {
        LongfellowJwtTestVectors.TokenVector vector = LongfellowJwtTestVectors.ErikaToken;

        return LongfellowJwtStatement.Create(
            ParseScalar(vector.PkX),
            ParseScalar(vector.PkY),
            [LongfellowJwtAttribute.FromStrings(ErikaAttributeId, ErikaAttributeValue)],
            LongfellowJwtZkSpec.SevenBlocks);
    }


    /// <summary>Signs one compact JWS over the encode seam: both segments ride the injected encoder and the signature is the raw fixed-width pair.</summary>
    /// <param name="key">The signing key.</param>
    /// <param name="headerJson">The header JSON.</param>
    /// <param name="payloadJson">The payload JSON.</param>
    /// <returns>The compact JWS.</returns>
    private static string SignCompactJws(ECDsa key, string headerJson, string payloadJson)
    {
        string signingInput = LongfellowJwsTestCodecs.Encoder(Encoding.UTF8.GetBytes(headerJson))
            + "."
            + LongfellowJwsTestCodecs.Encoder(Encoding.UTF8.GetBytes(payloadJson));
        byte[] signature = key.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        return signingInput + "." + LongfellowJwsTestCodecs.Encoder(signature);
    }


    /// <summary>Parses a canonical scalar from the reference's 0x-prefixed hex form.</summary>
    /// <param name="text">The 0x-prefixed hex string.</param>
    /// <returns>The canonical big-endian bytes.</returns>
    private static byte[] ParseScalar(string text)
    {
        return Canonical(BigInteger.Parse("0" + text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture));
    }
}

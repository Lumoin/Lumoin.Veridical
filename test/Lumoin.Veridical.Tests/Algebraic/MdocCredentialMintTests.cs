using Lumoin.Veridical.Core;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Exercises the credential composition the Longfellow end-to-end proof (LF.5)
/// stands on: an mdoc-shaped credential POCO, a swappable canonical-serializer
/// delegate (here a deterministic dummy; ISO 18013-5 CBOR/COSE is the real one
/// a consuming library supplies — the same POCO-plus-serialization-delegate
/// split Verifiable uses), and the LF.3a ECDSA reference as the issuer's
/// signing primitive. Mint signs the canonical bytes; verify recomputes them.
/// </summary>
/// <remarks>
/// The credential model is deliberately test-side and minimal: the in-circuit
/// proof (LF.5) pins exactly which fields and encoding the proof commits to,
/// and the public model graduates to the library then rather than being
/// guessed at now. What is real here is the composition — POCO → canonical
/// bytes (via the delegate seam) → SHA-256 → ECDSA-P-256 — and that a tamper
/// anywhere in the claims breaks the issuer signature.
/// </remarks>
[TestClass]
internal sealed class MdocCredentialMintTests
{
    private const int ScalarSize = 32;
    private const int CompressedSize = 33;
    private const int SerializationScratch = 512;
    private const string NonceHex = "1234567890abcdeffedcba9876543210112233445566778899aabbccddeeff00";


    [TestMethod]
    public void AMintedCredentialVerifiesUnderTheIssuerKey()
    {
        using ECDsa issuer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        MdocCredential credential = SampleCredential();

        Span<byte> publicKey = stackalloc byte[CompressedSize];
        Span<byte> r = stackalloc byte[ScalarSize];
        Span<byte> s = stackalloc byte[ScalarSize];
        Mint(issuer, credential, DummyCanonicalSerialize, publicKey, r, s);

        bool valid = VerifyIssuerSignature(credential, DummyCanonicalSerialize, publicKey, r, s);
        Assert.IsTrue(valid, "A freshly minted mdoc credential must verify under the issuer key.");
    }


    [TestMethod]
    public void TamperingAClaimBreaksTheIssuerSignature()
    {
        using ECDsa issuer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        MdocCredential credential = SampleCredential();

        Span<byte> publicKey = stackalloc byte[CompressedSize];
        Span<byte> r = stackalloc byte[ScalarSize];
        Span<byte> s = stackalloc byte[ScalarSize];
        Mint(issuer, credential, DummyCanonicalSerialize, publicKey, r, s);

        //Flip the age-over-18 assertion from true to false and re-serialize:
        //the issuer signature was over the original canonical bytes.
        MdocCredential tampered = credential with
        {
            Claims =
            [
                new MdocClaim("age_over_18", new byte[] { 0x00 }),
                new MdocClaim("birth_year", credential.Claims[1].ElementValue),
            ],
        };

        bool valid = VerifyIssuerSignature(tampered, DummyCanonicalSerialize, publicKey, r, s);
        Assert.IsFalse(valid, "A tampered claim must break the issuer signature.");
    }


    private static MdocCredential SampleCredential() => new(
        DocType: "org.iso.18013.5.1.mDL",
        Claims:
        [
            new MdocClaim("age_over_18", new byte[] { 0x01 }),
            new MdocClaim("birth_year", new byte[] { 0x07, 0xC5 }),
        ]);


    private static void Mint(
        ECDsa issuer,
        MdocCredential credential,
        CanonicalCredentialSerializer serialize,
        Span<byte> publicKeyCompressed,
        Span<byte> r,
        Span<byte> s)
    {
        ExportPublicKeyCompressed(issuer, publicKeyCompressed);
        ECParameters parameters = issuer.ExportParameters(includePrivateParameters: true);

        Span<byte> privateKey = stackalloc byte[ScalarSize];
        LeftPad(parameters.D, privateKey);

        Span<byte> digest = stackalloc byte[ScalarSize];
        HashCanonical(credential, serialize, digest);

        Span<byte> nonce = stackalloc byte[ScalarSize];
        Convert.FromHexString(NonceHex).CopyTo(nonce);

        P256EcdsaReference.Sign(privateKey, digest, nonce, r, s);
    }


    private static bool VerifyIssuerSignature(
        MdocCredential credential,
        CanonicalCredentialSerializer serialize,
        ReadOnlySpan<byte> publicKeyCompressed,
        ReadOnlySpan<byte> r,
        ReadOnlySpan<byte> s)
    {
        Span<byte> digest = stackalloc byte[ScalarSize];
        HashCanonical(credential, serialize, digest);

        return P256EcdsaReference.Verify(publicKeyCompressed, digest, r, s);
    }


    private static void HashCanonical(MdocCredential credential, CanonicalCredentialSerializer serialize, Span<byte> digest)
    {
        Span<byte> canonical = stackalloc byte[SerializationScratch];
        int written = serialize(credential, canonical);
        SHA256.HashData(canonical[..written], digest);
    }


    /// <summary>
    /// A deterministic, length-prefixed canonical encoding standing in for the
    /// real ISO 18013-5 CBOR/COSE serializer. Claims are sorted by identifier
    /// so the encoding is independent of POCO ordering; every field is written
    /// as a two-byte big-endian length followed by its bytes.
    /// </summary>
    private static int DummyCanonicalSerialize(in MdocCredential credential, Span<byte> destination)
    {
        int offset = 0;
        offset += WriteString(credential.DocType, destination[offset..]);

        List<MdocClaim> ordered = [.. credential.Claims];
        ordered.Sort(static (left, right) => string.CompareOrdinal(left.ElementIdentifier, right.ElementIdentifier));
        foreach(MdocClaim claim in ordered)
        {
            offset += WriteString(claim.ElementIdentifier, destination[offset..]);
            offset += WriteLengthPrefixed(claim.ElementValue.Span, destination[offset..]);
        }

        return offset;
    }


    private static int WriteString(string value, Span<byte> destination)
    {
        int written = System.Text.Encoding.UTF8.GetBytes(value, destination[sizeof(ushort)..]);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)written);

        return sizeof(ushort) + written;
    }


    private static int WriteLengthPrefixed(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)value.Length);
        value.CopyTo(destination[sizeof(ushort)..]);

        return sizeof(ushort) + value.Length;
    }


    private static void ExportPublicKeyCompressed(ECDsa ecdsa, Span<byte> destination)
    {
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: false);
        Span<byte> x = stackalloc byte[ScalarSize];
        Span<byte> y = stackalloc byte[ScalarSize];
        LeftPad(parameters.Q.X, x);
        LeftPad(parameters.Q.Y, y);

        destination[0] = (byte)(0x02 | (y[^1] & 0x01));
        x.CopyTo(destination[1..]);
    }


    private static void LeftPad(byte[]? source, Span<byte> destination)
    {
        destination.Clear();
        ArgumentNullException.ThrowIfNull(source);
        source.CopyTo(destination[(destination.Length - source.Length)..]);
    }
}


/// <summary>An mdoc-shaped credential: a document type and its issuer-signed claims.</summary>
internal sealed record MdocCredential(string DocType, IReadOnlyList<MdocClaim> Claims);


/// <summary>A single issuer-signed claim (an ISO 18013-5 element identifier and its value).</summary>
internal sealed record MdocClaim(string ElementIdentifier, ReadOnlyMemory<byte> ElementValue);


/// <summary>
/// The swap seam: a span-based canonical serializer for a credential. A
/// consuming library supplies the real ISO 18013-5 CBOR/COSE encoder; tests
/// supply a deterministic dummy. Returns the number of bytes written.
/// </summary>
internal delegate int CanonicalCredentialSerializer(in MdocCredential credential, Span<byte> destination);

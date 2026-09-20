using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Exercises the credential composition the Longfellow end-to-end mdoc proof
/// stands on: an mdoc-shaped credential POCO, a swappable canonical-serializer
/// delegate (here a deterministic dummy; ISO 18013-5 CBOR/COSE is the real one
/// a consuming library supplies — the same POCO-plus-serialization-delegate
/// split Verifiable uses), and the P-256 ECDSA reference as the issuer's
/// signing primitive. Mint signs the canonical bytes; verify recomputes them.
/// </summary>
/// <remarks>
/// The credential model is deliberately test-side and minimal: the in-circuit
/// proof pins exactly which fields and encoding the proof commits to, while
/// the actual field encoding is a concern for whichever library supplies the
/// real serializer. What is real here is the composition — POCO → canonical
/// bytes (via the delegate seam) → SHA-256 → ECDSA-P-256 — and that a tamper
/// anywhere in the claims breaks the issuer signature.
/// </remarks>
[TestClass]
internal sealed class MdocCredentialMintTests
{
    /// <summary>The canonical scalar width in bytes for a P-256 field or curve-order element.</summary>
    private const int ScalarSize = 32;

    /// <summary>The SEC1 compressed public-key width in bytes: a one-byte parity prefix plus the 32-byte x-coordinate.</summary>
    private const int CompressedSize = 33;

    /// <summary>The stack buffer width the dummy canonical serializer writes into; large enough for this fixture's two claims.</summary>
    private const int SerializationScratch = 512;

    /// <summary>A fixed ECDSA nonce, deterministic test material standing in for the RFC 6979 derivation production signing uses.</summary>
    private const string NonceHex = "1234567890abcdeffedcba9876543210112233445566778899aabbccddeeff00";

    /// <summary>The ISO 18013-5 <c>age_over_18</c> element value asserting the claim is true: a single byte set to 1.</summary>
    private static byte[] AgeOverThresholdAsserted { get; } = [0x01];

    /// <summary>The ISO 18013-5 <c>age_over_18</c> element value asserting the claim is false: a single byte set to 0.</summary>
    private static byte[] AgeOverThresholdDenied { get; } = [0x00];

    /// <summary>The ISO 18013-5 <c>birth_year</c> element value for 1989, as a big-endian 16-bit integer (<c>0x07C5</c>).</summary>
    private static byte[] BirthYear1989 { get; } = [0x07, 0xC5];


    /// <summary>Verifies that a freshly minted mdoc credential's issuer signature checks out against the issuer's own public key.</summary>
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


    /// <summary>Verifies that flipping the age-over-18 assertion and re-serializing breaks the issuer signature, which was computed over the original canonical bytes.</summary>
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
                new MdocClaim("age_over_18", AgeOverThresholdDenied),
                new MdocClaim("birth_year", credential.Claims[1].ElementValue),
            ],
        };

        bool valid = VerifyIssuerSignature(tampered, DummyCanonicalSerialize, publicKey, r, s);
        Assert.IsFalse(valid, "A tampered claim must break the issuer signature.");
    }


    /// <summary>Builds a sample mdoc credential asserting age-over-18 and a 1989 birth year.</summary>
    /// <returns>The unsigned sample credential.</returns>
    private static MdocCredential SampleCredential() => new(
        DocType: "org.iso.18013.5.1.mDL",
        Claims:
        [
            new MdocClaim("age_over_18", AgeOverThresholdAsserted),
            new MdocClaim("birth_year", BirthYear1989),
        ]);


    /// <summary>Signs a credential's canonical digest with the issuer's P-256 key under the fixed test nonce, and exports the issuer's compressed public key.</summary>
    /// <param name="issuer">The issuer keypair to sign with and export the public key from.</param>
    /// <param name="credential">The credential to sign.</param>
    /// <param name="serialize">The canonical serializer producing the bytes the signature covers.</param>
    /// <param name="publicKeyCompressed">The buffer receiving the issuer's compressed public key.</param>
    /// <param name="r">The buffer receiving the ECDSA signature's <c>r</c> component.</param>
    /// <param name="s">The buffer receiving the ECDSA signature's <c>s</c> component.</param>
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


    /// <summary>Verifies a credential's canonical digest against an ECDSA signature and the issuer's compressed public key.</summary>
    /// <param name="credential">The credential whose canonical digest is checked.</param>
    /// <param name="serialize">The canonical serializer producing the bytes the digest is computed over.</param>
    /// <param name="publicKeyCompressed">The issuer's compressed public key.</param>
    /// <param name="r">The ECDSA signature's <c>r</c> component.</param>
    /// <param name="s">The ECDSA signature's <c>s</c> component.</param>
    /// <returns><see langword="true"/> when the signature verifies against the credential's canonical digest.</returns>
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


    /// <summary>Computes the SHA-256 digest of a credential's canonical encoding, the digest the issuer signature is over.</summary>
    /// <param name="credential">The credential to encode and hash.</param>
    /// <param name="serialize">The canonical serializer producing the bytes to hash.</param>
    /// <param name="digest">The buffer receiving the 32-byte digest.</param>
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


    /// <summary>Writes a length-prefixed UTF-8 string: a two-byte big-endian length followed by the encoded bytes.</summary>
    /// <param name="value">The string to encode.</param>
    /// <param name="destination">The buffer receiving the length prefix and the encoded bytes.</param>
    /// <returns>The total number of bytes written, including the length prefix.</returns>
    private static int WriteString(string value, Span<byte> destination)
    {
        int written = System.Text.Encoding.UTF8.GetBytes(value, destination[sizeof(ushort)..]);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)written);

        return sizeof(ushort) + written;
    }


    /// <summary>Writes a length-prefixed byte value: a two-byte big-endian length followed by the raw bytes.</summary>
    /// <param name="value">The bytes to write.</param>
    /// <param name="destination">The buffer receiving the length prefix and the raw bytes.</param>
    /// <returns>The total number of bytes written, including the length prefix.</returns>
    private static int WriteLengthPrefixed(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)value.Length);
        value.CopyTo(destination[sizeof(ushort)..]);

        return sizeof(ushort) + value.Length;
    }


    /// <summary>Exports an ECDSA key's public point in SEC1 compressed form.</summary>
    /// <param name="ecdsa">The key whose public point is exported.</param>
    /// <param name="destination">The buffer receiving the compressed point.</param>
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


    /// <summary>Right-aligns a big-endian byte array into a wider fixed-size buffer, zero-filling the leading bytes.</summary>
    /// <param name="source">The source bytes to right-align; must not be <see langword="null"/>.</param>
    /// <param name="destination">The buffer receiving the zero-padded, right-aligned bytes.</param>
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

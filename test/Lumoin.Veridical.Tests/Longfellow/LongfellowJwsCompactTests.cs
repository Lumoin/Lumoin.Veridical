using Lumoin.Veridical.Longfellow;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Globalization;
using System.Numerics;
using System.Text;
using static Lumoin.Veridical.Tests.Algebraic.LongfellowKernelZkTestHarness;

namespace Lumoin.Veridical.Tests.Longfellow;

/// <summary>
/// The host-side extractor gates: structural compact-JWS parsing against manual splits of the
/// reference tokens, the key-binding digest conformance pin against the reference's own hardcoded
/// <c>e2</c> values, the strict unpadded-length arithmetic, and segment decoding through the
/// consumer-wired base64url seam — pinned against known plaintext, not only a round trip.
/// </summary>
[TestClass]
internal sealed class LongfellowJwsCompactTests
{
    /// <summary>The issuer JWS header every reference token carries, the external decode oracle.</summary>
    private const string ErikaHeaderJson = /*lang=json,strict*/ """{"alg":"ES256","typ":"JWT"}""";

    /// <summary>The byte count of the deterministic round-trip payload; long enough to cross several base64url groups and end on a partial one.</summary>
    private const int RoundTripByteCount = 47;

    /// <summary>The deterministic fill stride keeping round-trip bytes distinct within a byte's range.</summary>
    private const int RoundTripFillStride = 7;


    /// <summary>Pins the structural split of both reference tokens against manual dot and tilde arithmetic.</summary>
    [TestMethod]
    public void TheReferenceTokensSplitAndParseAtTheManualOffsets()
    {
        foreach(LongfellowJwtTestVectors.TokenVector vector in new[] { LongfellowJwtTestVectors.ErikaToken, LongfellowJwtTestVectors.RicherToken })
        {
            byte[] token = Encoding.ASCII.GetBytes(vector.Token);
            int tilde = vector.Token.IndexOf('~', StringComparison.Ordinal);

            Assert.IsTrue(LongfellowJwsCompact.TrySplitPresentation(token, out Range issuerRange, out Range keyBindingRange), "The reference token must split at its tilde.");
            Assert.AreEqual(tilde, issuerRange.End.GetOffset(token.Length), "The issuer JWS must end at the tilde.");
            Assert.AreEqual(tilde + 1, keyBindingRange.Start.GetOffset(token.Length), "The key-binding JWS must start after the tilde.");

            ReadOnlySpan<byte> issuer = token.AsSpan()[issuerRange];
            int firstDot = vector.Token.IndexOf('.', StringComparison.Ordinal);
            int secondDot = vector.Token.IndexOf('.', firstDot + 1);

            Assert.IsTrue(LongfellowJwsCompact.TryParse(issuer, out LongfellowJwsCompactSegments segments), "The issuer JWS must parse.");
            Assert.AreEqual(0, segments.HeaderIndex, "The header starts the JWS.");
            Assert.AreEqual(firstDot, segments.HeaderLength, "The header must end at the first dot.");
            Assert.AreEqual(firstDot + 1, segments.PayloadIndex, "The payload must start after the first dot.");
            Assert.AreEqual(secondDot - firstDot - 1, segments.PayloadLength, "The payload must end at the second dot.");
            Assert.AreEqual(secondDot, segments.SigningInputLength, "The signing input is the prefix before the second dot.");
            Assert.AreEqual(secondDot + 1, segments.SignatureIndex, "The signature must start after the second dot.");
            Assert.AreEqual(tilde - secondDot - 1, segments.SignatureLength, "The signature must run to the tilde.");
        }
    }


    /// <summary>Pins the structural rejections: dotless and one-dot inputs, an empty signature, a tildeless or key-binding-less token.</summary>
    [TestMethod]
    public void MalformedStructuralShapesAreRejected()
    {
        Assert.IsFalse(LongfellowJwsCompact.TryParse(Encoding.ASCII.GetBytes("nodotsatall"), out _), "A dotless input must not parse.");
        Assert.IsFalse(LongfellowJwsCompact.TryParse(Encoding.ASCII.GetBytes("one.dot"), out _), "A one-dot input must not parse.");
        Assert.IsFalse(LongfellowJwsCompact.TryParse(Encoding.ASCII.GetBytes("a.b."), out _), "An empty signature must not parse.");
        Assert.IsFalse(LongfellowJwsCompact.TryParse([], out _), "An empty input must not parse.");

        Assert.IsFalse(LongfellowJwsCompact.TrySplitPresentation(Encoding.ASCII.GetBytes("a.b.c"), out _, out _), "A tildeless token must not split.");
        Assert.IsFalse(LongfellowJwsCompact.TrySplitPresentation(Encoding.ASCII.GetBytes("a.b.c~"), out _, out _), "An empty key-binding part must not split.");
        Assert.IsFalse(LongfellowJwsCompact.TrySplitPresentation([], out _, out _), "An empty token must not split.");
    }


    /// <summary>
    /// Pins the FIRST-tilde split rule and the structural acceptance of an empty issuer segment:
    /// a key-binding remainder keeps every later tilde, and a leading tilde splits with an empty
    /// issuer — the reference's own acceptance, failing later at the cryptographic stage.
    /// </summary>
    [TestMethod]
    public void ThePresentationSplitTakesTheFirstTildeAndStaysStructural()
    {
        byte[] multiTilde = Encoding.ASCII.GetBytes("a.b.c~d.e.f~x");
        int firstTilde = Array.IndexOf(multiTilde, (byte)'~');

        Assert.IsTrue(LongfellowJwsCompact.TrySplitPresentation(multiTilde, out Range issuer, out Range keyBinding), "A multi-tilde token must split.");
        Assert.AreEqual(firstTilde, issuer.End.GetOffset(multiTilde.Length), "The issuer JWS must end at the FIRST tilde.");
        Assert.AreSequenceEqual(
            Encoding.ASCII.GetBytes("d.e.f~x"),
            multiTilde.AsSpan()[keyBinding].ToArray(),
            "The key-binding remainder must keep everything after the first tilde, later tildes included.");

        byte[] leadingTilde = Encoding.ASCII.GetBytes("~d.e.f");
        Assert.IsTrue(LongfellowJwsCompact.TrySplitPresentation(leadingTilde, out Range emptyIssuer, out Range remainder), "A leading tilde must split structurally.");
        Assert.AreEqual(0, emptyIssuer.End.GetOffset(leadingTilde.Length), "The issuer segment is empty and fails later at JWS parsing, not here.");
        Assert.AreEqual(1, remainder.Start.GetOffset(leadingTilde.Length), "The key-binding remainder must start after the leading tilde.");
    }


    /// <summary>Pins the strict unpadded base64url length arithmetic, including the invalid one-character remainder.</summary>
    [TestMethod]
    public void StrictDecodedLengthMatchesTheUnpaddedContract()
    {
        Assert.AreEqual(0, LongfellowJwsCompact.StrictDecodedLength(0), "Zero characters decode to zero bytes.");
        Assert.AreEqual(-1, LongfellowJwsCompact.StrictDecodedLength(1), "A one-character remainder carries no data.");
        Assert.AreEqual(1, LongfellowJwsCompact.StrictDecodedLength(2), "Two characters decode to one byte.");
        Assert.AreEqual(2, LongfellowJwsCompact.StrictDecodedLength(3), "Three characters decode to two bytes.");
        Assert.AreEqual(3, LongfellowJwsCompact.StrictDecodedLength(4), "One full group decodes to three bytes.");
        Assert.AreEqual(-1, LongfellowJwsCompact.StrictDecodedLength(5), "A one-character remainder after a group carries no data.");
        Assert.AreEqual(32, LongfellowJwsCompact.StrictDecodedLength(43), "A P-256 coordinate's 43 characters decode to 32 bytes.");
        Assert.AreEqual(64, LongfellowJwsCompact.StrictDecodedLength(86), "A raw signature's 86 characters decode to the 64-byte pair.");
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => LongfellowJwsCompact.StrictDecodedLength(-1), "A negative count is a contract violation.");
    }


    /// <summary>
    /// The headline conformance pin: the key-binding digest computed from each reference token's
    /// presented key-binding JWS equals the <c>e2</c> value the reference test hardcodes for it.
    /// </summary>
    [TestMethod]
    public void TheKeyBindingDigestEqualsTheReferenceVectors()
    {
        Span<byte> digest = stackalloc byte[ScalarSize];
        foreach(LongfellowJwtTestVectors.TokenVector vector in new[] { LongfellowJwtTestVectors.ErikaToken, LongfellowJwtTestVectors.RicherToken })
        {
            byte[] token = Encoding.ASCII.GetBytes(vector.Token);
            Assert.IsTrue(LongfellowJwsCompact.TrySplitPresentation(token, out _, out Range keyBindingRange), "The reference token must split.");

            digest.Clear();
            Assert.IsTrue(LongfellowJwsCompact.TryComputeKeyBindingDigest(token.AsSpan()[keyBindingRange], digest), "The key-binding digest must compute.");

            Assert.AreSequenceEqual(ParseScalar(vector.E2), digest.ToArray(), "The computed key-binding digest must equal the reference's hardcoded e2.");
        }
    }


    /// <summary>Pins the digest destination contract and the malformed key-binding rejection.</summary>
    [TestMethod]
    public void TheKeyBindingDigestContractHolds()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => ComputeDigestIntoWrongSizeDestination(),
            "A wrong-size destination is a contract violation.");

        Span<byte> digest = stackalloc byte[ScalarSize];
        Assert.IsFalse(LongfellowJwsCompact.TryComputeKeyBindingDigest(Encoding.ASCII.GetBytes("nodots"), digest), "A structurally malformed key-binding JWS must not produce a digest.");
    }


    /// <summary>Decodes the Erika issuer header through the seam and pins the exact known JSON plaintext — an external oracle, not a self-referential round trip.</summary>
    [TestMethod]
    public void TheErikaHeaderSegmentDecodesToTheKnownJson()
    {
        byte[] token = Encoding.ASCII.GetBytes(LongfellowJwtTestVectors.ErikaToken.Token);
        Assert.IsTrue(LongfellowJwsCompact.TrySplitPresentation(token, out Range issuerRange, out _), "The reference token must split.");
        ReadOnlySpan<byte> issuer = token.AsSpan()[issuerRange];
        Assert.IsTrue(LongfellowJwsCompact.TryParse(issuer, out LongfellowJwsCompactSegments segments), "The issuer JWS must parse.");

        using IMemoryOwner<byte> decoded = LongfellowJwsCompact.DecodeSegment(
            issuer.Slice(segments.HeaderIndex, segments.HeaderLength), LongfellowJwsTestCodecs.Decoder, BaseMemoryPool.Shared);

        Assert.AreSequenceEqual(Encoding.ASCII.GetBytes(ErikaHeaderJson), decoded.Memory.ToArray(), "The decoded header must equal the known reference header JSON.");
    }


    /// <summary>Round-trips deterministic bytes through the encode and decode seam and pins the right-sized result buffer.</summary>
    [TestMethod]
    public void SegmentDecodingRoundTripsThroughTheSeamRightSized()
    {
        Span<byte> original = stackalloc byte[RoundTripByteCount];
        for(int i = 0; i < original.Length; i++)
        {
            original[i] = (byte)(i * RoundTripFillStride);
        }

        string encoded = LongfellowJwsTestCodecs.Encoder(original);
        byte[] encodedBytes = Encoding.ASCII.GetBytes(encoded);

        using IMemoryOwner<byte> decoded = LongfellowJwsCompact.DecodeSegment(encodedBytes, LongfellowJwsTestCodecs.Decoder, BaseMemoryPool.Shared);

        Assert.HasCount(RoundTripByteCount, decoded.Memory, "The decoded buffer must be right-sized to the decoded byte count.");
        Assert.HasCount(LongfellowJwsCompact.StrictDecodedLength(encodedBytes.Length), decoded.Memory, "The decoded length must match the strict length arithmetic.");
        Assert.AreSequenceEqual(original.ToArray(), decoded.Memory.ToArray(), "The round trip must reproduce the original bytes.");
    }


    /// <summary>Pins the seam's hostile-content rejections: a literal padding character, a non-ASCII byte, and an empty segment.</summary>
    [TestMethod]
    public void HostileSegmentContentRejectsThroughTheSeam()
    {
        Assert.ThrowsExactly<FormatException>(
            () => LongfellowJwsCompact.DecodeSegment(Encoding.ASCII.GetBytes("AA=="), LongfellowJwsTestCodecs.Decoder, BaseMemoryPool.Shared).Dispose(),
            "A padding character is invalid in unpadded base64url.");

        byte[] nonAscii = Encoding.ASCII.GetBytes("AAAA");
        nonAscii[1] = 0x80;
        Assert.ThrowsExactly<FormatException>(
            () => LongfellowJwsCompact.DecodeSegment(nonAscii, LongfellowJwsTestCodecs.Decoder, BaseMemoryPool.Shared).Dispose(),
            "A byte above 0x7F is malformed in a compact serialization.");

        Assert.ThrowsExactly<ArgumentException>(
            () => LongfellowJwsCompact.DecodeSegment([], LongfellowJwsTestCodecs.Decoder, BaseMemoryPool.Shared).Dispose(),
            "An empty segment is a contract violation.");
        Assert.ThrowsExactly<ArgumentNullException>(
            () => LongfellowJwsCompact.DecodeSegment(Encoding.ASCII.GetBytes("AAAA"), null!, BaseMemoryPool.Shared).Dispose(),
            "A null decoder is a contract violation.");
    }


    /// <summary>Drives the digest computation into a deliberately wrong-size destination; the single-expression probe the destination-contract assertion invokes.</summary>
    private static void ComputeDigestIntoWrongSizeDestination()
    {
        Span<byte> destination = stackalloc byte[ScalarSize - 1];
        _ = LongfellowJwsCompact.TryComputeKeyBindingDigest(Encoding.ASCII.GetBytes("a.b.c"), destination);
    }


    /// <summary>Parses a canonical scalar from the reference's 0x-prefixed hex form.</summary>
    /// <param name="text">The 0x-prefixed hex string.</param>
    /// <returns>The canonical big-endian bytes.</returns>
    private static byte[] ParseScalar(string text)
    {
        return Canonical(BigInteger.Parse("0" + text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture));
    }
}

using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The wire-format-conformant Fiat–Shamir TRANSCRIPT, gated as a faithful port
/// of google/longfellow-zk's <c>lib/random/transcript.h</c> <c>Transcript</c> (with its <c>FSPRF</c>
/// AES-256-ECB pseudo-random function) and the <c>lib/random/random.h</c> challenge generators
/// (<c>elt</c>, <c>nat</c>, <c>choose</c>).
/// </summary>
/// <remarks>
/// <para>
/// The anchor file (transcript-anchor-output.txt in TestMaterial/Longfellow) covers two seeds
/// (<c>"test"</c> and a one-byte variant) and two versions (6, the deployed mdoc default, and 4,
/// the reference's transcript-test value). For each, it records the squeezed challenges from the
/// representative absorb sequence the Ligero flow drives (a 100-byte payload, a field element, a
/// field-element array, a 32-byte commitment root via <c>write_commitment</c>, short tags): the PRF
/// key snapshots, raw PRF bytes, GF(2^128) field elements, naturals via <c>nat()</c>, and index
/// subsets via <c>choose()</c>/<c>gen_idx</c>.
/// </para>
/// <para>
/// The C# gates reproduce every anchor value byte for byte: the SHA-256 snapshot keying, the
/// AES-256-ECB block stream, the typed absorb framing, the field-element squeeze, the rejection-sampled
/// naturals (including the high-bit mask), and the partial-Fisher–Yates index subset. The cross-layer
/// smoke absorbs the Ligero commitment root through <see cref="LongfellowTranscript.AbsorbCommitmentRoot"/>
/// and pins the first post-root index subset and element challenge against the commitment step's
/// production dimensions — the first commitment/transcript conformance point. The adversarial duals show a one-byte-different
/// seed changes the whole stream, and that versions 4 and 6 produce identical streams (documenting that
/// this reference snapshot stores the version but does not branch on it in the exercised paths).
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowTranscriptTests
{
    /// <summary>The repository-relative path to the transcript anchor file.</summary>
    private const string AnchorRelativePath = "TestMaterial/Longfellow/transcript-anchor-output.txt";

    /// <summary>The reference's GF(2^128) <c>Field::kBytes</c>: a field element is 16 little-endian bytes.</summary>
    private const int FieldElementBytes = 16;

    /// <summary>The byte width of a SHA-256 digest and of a Merkle commitment root.</summary>
    private const int DigestSize = 32;

    /// <summary>The fixed ASCII seed ("test") most transcripts in this file are constructed from.</summary>
    private static byte[] TestSeed { get; } = Encoding.ASCII.GetBytes("test");

    /// <summary>The label-to-value lines, parsed once from the anchor file.</summary>
    private static Dictionary<string, string> Anchors { get; } = LoadAnchors();


    /// <summary>Verifies that a freshly seeded transcript's initial PRF key snapshot matches the reference.</summary>
    [TestMethod]
    public void TheInitialKeySnapshotMatchesTheReference()
    {
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);

        Span<byte> key = stackalloc byte[DigestSize];
        transcript.SnapshotKey(key);

        AssertHex("v6_key_init", key, "The initial PRF key snapshot must match the reference.");
    }


    /// <summary>Verifies that a freshly seeded transcript's first 32 squeezed PRF bytes match the reference.</summary>
    [TestMethod]
    public void TheInitialRawByteSqueezeMatchesTheReference()
    {
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);

        Span<byte> bytes = stackalloc byte[DigestSize];
        transcript.SqueezeBytes(bytes);

        AssertHex("v6_bytes_init", bytes, "The first 32 PRF bytes must match the reference.");
    }


    /// <summary>Verifies that the PRF key snapshot after absorbing the 100-byte counter payload matches the reference.</summary>
    [TestMethod]
    public void TheKeyAfterAbsorbingThePayloadMatchesTheReference()
    {
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);
        transcript.AbsorbByteString(CounterPayload(100));

        Span<byte> key = stackalloc byte[DigestSize];
        transcript.SnapshotKey(key);

        AssertHex("v6_key_afterbytes", key, "The PRF key after the 100-byte payload must match the reference.");
    }


    /// <summary>
    /// Verifies that the squeezed field-element challenges after the payload absorb, a single
    /// absorbed element, and a two-element array absorb each match the reference.
    /// </summary>
    [TestMethod]
    public void TheFieldElementChallengesMatchTheReferenceAcrossTheAbsorbSequence()
    {
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);
        transcript.AbsorbByteString(CounterPayload(100));

        //eltA: 16 elements squeezed after the 100-byte payload (the gen_uldt-shape draw).
        AssertSqueezedElements(transcript, "v6_eltA", 16);

        //Absorb a single field element of_scalar(7); the reference's basis element for 7.
        transcript.AbsorbFieldElement(OfScalar(7));
        AssertSqueezedElements(transcript, "v6_eltB", 16);

        //Absorb an array of two elements {of_scalar(8), of_scalar(9)}.
        Span<byte> array = stackalloc byte[2 * FieldElementBytes];
        OfScalar(8).CopyTo(array[..FieldElementBytes]);
        OfScalar(9).CopyTo(array.Slice(FieldElementBytes, FieldElementBytes));
        transcript.AbsorbFieldElementArray(array, 2);
        AssertSqueezedElements(transcript, "v6_eltC", 16);
    }


    /// <summary>Verifies that one chained <c>SqueezeFieldElements</c> call produces the same bytes as the reference's per-element array-generator draw.</summary>
    [TestMethod]
    public void TheChainedArraySqueezeEqualsTheReferenceGeneratorDraw()
    {
        //One SqueezeFieldElements call is one reference array-generator call (elt(Elt[], n, F),
        //the gen_uldt shape): its concatenated output must equal the per-element anchor run.
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);
        transcript.AbsorbByteString(CounterPayload(100));

        Span<byte> elements = stackalloc byte[16 * FieldElementBytes];
        transcript.SqueezeFieldElements(elements, 16);
        for(int i = 0; i < 16; i++)
        {
            AssertHex($"v6_eltA{i}", elements.Slice(i * FieldElementBytes, FieldElementBytes), $"Chained element {i} must match the reference draw.");
        }
    }


    /// <summary>Verifies that absorbing a 32-byte commitment root through the typed byte-array path, then squeezing field elements, matches the reference.</summary>
    [TestMethod]
    public void TheCommitmentRootAbsorbAndPostRootChallengesMatchTheReference()
    {
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);
        transcript.AbsorbByteString(CounterPayload(100));
        DrainElements(transcript, 16);

        transcript.AbsorbFieldElement(OfScalar(7));
        DrainElements(transcript, 16);

        Span<byte> array = stackalloc byte[2 * FieldElementBytes];
        OfScalar(8).CopyTo(array[..FieldElementBytes]);
        OfScalar(9).CopyTo(array.Slice(FieldElementBytes, FieldElementBytes));
        transcript.AbsorbFieldElementArray(array, 2);
        DrainElements(transcript, 16);

        //Absorb a 32-byte root with the fixed 0xA0+i pattern via the typed byte-array write (the same
        //path write_commitment takes), then squeeze the first post-root element challenges.
        Span<byte> root = stackalloc byte[DigestSize];
        for(int i = 0; i < DigestSize; i++)
        {
            root[i] = (byte)(0xA0 + i);
        }

        transcript.AbsorbCommitmentRoot(root);
        AssertSqueezedElements(transcript, "v6_eltPostRoot", 4);
    }


    /// <summary>Verifies that the rejection-sampled natural-number challenges, drawn at a range of bounds after the absorb sequence, match the reference.</summary>
    [TestMethod]
    public void TheNaturalChallengesMatchTheReference()
    {
        using LongfellowTranscript transcript = AdvanceToNatStage(version: 6);

        ulong[] bounds =
        [
            1, 1, 1, 2, 2, 2, 7, 7, 7, 7, 32, 32, 32, 32,
            256, 256, 256, 256, 1000, 10000, 60000, 65535, 100000, 100000
        ];

        string[] expected = Anchors["v6_nat"].Split(',');
        Assert.HasCount(bounds.Length, expected, "The natural bound list must match the reference's count.");

        for(int i = 0; i < bounds.Length; i++)
        {
            ulong got = transcript.SqueezeNatural(bounds[i]);
            Assert.AreEqual(ulong.Parse(expected[i], CultureInfo.InvariantCulture), got, $"nat({bounds[i]}) at index {i} must match the reference.");
        }
    }


    /// <summary>Verifies that four independently drawn index subsets, at a range of bounds, each match the reference's <c>choose()</c> draws.</summary>
    [TestMethod]
    public void TheIndexSubsetChallengesMatchTheReference()
    {
        //Each reference choose() draws from the SAME post-"choose"-tag transcript state, so the four
        //subsets are INDEPENDENT, not chained: each is regenerated from a fresh transcript advanced to
        //the choose stage.
        AssertChosenSubsetIndependently("v6_ch31", bound: 31, count: 20);
        AssertChosenSubsetIndependently("v6_ch32", bound: 32, count: 20);
        AssertChosenSubsetIndependently("v6_ch1000", bound: 1000, count: 20);
        AssertChosenSubsetIndependently("v6_ch65535", bound: 65535, count: 20);
    }


    /// <summary>Verifies that transcript versions 4 and 6 squeeze byte-identical field-element streams after the same absorb, and that both match the reference.</summary>
    [TestMethod]
    public void Version4AndVersion6ProduceIdenticalStreams()
    {
        //This snapshot stores the version but never branches on it in the exercised paths; the two
        //full streams must be byte-identical. The anchor file pins both prefixes; here the C# port confirms
        //its own version-6 and version-4 runs agree on the post-payload element challenges.
        using LongfellowTranscript version6 = NewTranscript(TestSeed, version: 6);
        using LongfellowTranscript version4 = NewTranscript(TestSeed, version: 4);
        version6.AbsorbByteString(CounterPayload(100));
        version4.AbsorbByteString(CounterPayload(100));

        Span<byte> a = stackalloc byte[FieldElementBytes];
        Span<byte> b = stackalloc byte[FieldElementBytes];
        for(int i = 0; i < 16; i++)
        {
            version6.SqueezeFieldElementBytes(a);
            version4.SqueezeFieldElementBytes(b);
            Assert.IsTrue(a.SequenceEqual(b), $"Version 4 and 6 must squeeze identical element {i}.");
        }

        //And both must equal the reference's v4_* value, which equals v6_* in the anchor file.
        Assert.AreEqual(Anchors["v4_eltA0"], Anchors["v6_eltA0"], "The reference confirms v4 and v6 agree.");
    }


    /// <summary>Verifies that flipping one byte of the seed changes the PRF key, and that the altered key matches the reference's alternate-seed value.</summary>
    [TestMethod]
    public void AOneByteDifferentSeedChangesTheStream()
    {
        byte[] altSeed = (byte[])TestSeed.Clone();
        altSeed[^1] ^= 0x01;

        using LongfellowTranscript baseline = NewTranscript(TestSeed, version: 6);
        using LongfellowTranscript altered = NewTranscript(altSeed, version: 6);

        Span<byte> baselineKey = stackalloc byte[DigestSize];
        Span<byte> alteredKey = stackalloc byte[DigestSize];
        baseline.SnapshotKey(baselineKey);
        altered.SnapshotKey(alteredKey);

        Assert.IsFalse(baselineKey.SequenceEqual(alteredKey), "A one-byte-different seed must change the PRF key.");

        //The altered key must also match the reference's valt_key_init value.
        AssertHex("valt_key_init", alteredKey, "The altered-seed key must match the reference.");
    }


    /// <summary>
    /// Verifies that absorbing the commitment step's production-shaped root and then drawing an
    /// index subset and field-element challenges matches the reference, the cross-layer
    /// conformance point between the commitment step and the transcript.
    /// </summary>
    [TestMethod]
    public void TheCrossLayerCommitmentRootBindsTheLigeroProductionDimensions()
    {
        //The Ligero commitment root for the small production tuple (nw=8 nq=1 rateinv=4 nreq=2). The
        //transcript absorbs it exactly as write_commitment does, then gen_idx draws nreq=2 distinct
        //columns over block_enc - dblock = 23. This is the first point where the commitment step and
        //the transcript step meet.
        byte[] c2Root = Convert.FromHexString("894ee3d5c0926fc02d935bbf5857d6256407f290a267afc3ec72831992186bf4");

        using LongfellowTranscript transcript = NewTranscript(Encoding.ASCII.GetBytes("c2"), version: 6);
        transcript.AbsorbCommitmentRoot(c2Root);

        //gen_idx: choose nreq distinct naturals over [0, block_enc - dblock).
        const int chooseBound = 23;
        const int chooseCount = 2;
        Span<int> chosen = stackalloc int[chooseCount];
        transcript.SqueezeIndexSubset(chooseBound, chooseCount, chosen);

        string[] expectedIndices = Anchors["c2_genidx"].Split(',');
        Assert.HasCount(chooseCount, expectedIndices, "The gen_idx count must match the reference.");
        for(int i = 0; i < chooseCount; i++)
        {
            Assert.AreEqual(int.Parse(expectedIndices[i], CultureInfo.InvariantCulture), chosen[i], $"gen_idx column {i} must match the reference.");
        }

        //The first post-commit element challenge (gen_uldt shape) is an INDEPENDENT draw from the same
        //post-root state, so it regenerates from a fresh transcript rather than chaining after the
        //gen_idx draw above.
        using LongfellowTranscript elementTranscript = NewTranscript(Encoding.ASCII.GetBytes("c2"), version: 6);
        elementTranscript.AbsorbCommitmentRoot(c2Root);
        AssertSqueezedElements(elementTranscript, "c2_eltPostRoot", 2);
    }


    /// <summary>Verifies that absorbing a field element shorter than the fixed element width throws <see cref="ArgumentException"/>.</summary>
    [TestMethod]
    public void RejectsAMisSizedFieldElementAbsorb()
    {
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);
        byte[] tooShort = new byte[FieldElementBytes - 1];
        Assert.ThrowsExactly<ArgumentException>(() => transcript.AbsorbFieldElement(tooShort));
    }


    /// <summary>Verifies that absorbing a commitment root shorter than the digest width throws <see cref="ArgumentException"/>.</summary>
    [TestMethod]
    public void RejectsAMisSizedCommitmentRoot()
    {
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);
        byte[] wrongLength = new byte[DigestSize - 1];
        Assert.ThrowsExactly<ArgumentException>(() => transcript.AbsorbCommitmentRoot(wrongLength));
    }


    /// <summary>Verifies that squeezing a natural challenge with a zero bound throws <see cref="ArgumentOutOfRangeException"/>.</summary>
    [TestMethod]
    public void RejectsAZeroNaturalBound()
    {
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => transcript.SqueezeNatural(0));
    }


    /// <summary>
    /// Verifies that absorbing the same element through the single-element path and the
    /// one-element-array path produces distinct transcript keys, since the two typed paths use
    /// distinct domain-separation tags.
    /// </summary>
    [TestMethod]
    public void ASingleFieldElementAndAnArrayOfOneElementProduceDistinctTranscripts()
    {
        //Trail of Bits TOB-LIBZK-2: the field-element and array domain-separation tags collided (both
        //1) in the audited reference; the fixed reference uses distinct tags (field element 1, array
        //2). Absorbing the same element through the two typed paths must diverge the transcript state.
        byte[] element = new byte[FieldElementBytes];
        element[0] = 0x2A;
        element[FieldElementBytes - 1] = 0x7E;

        using LongfellowTranscript single = NewTranscript(TestSeed, version: 6);
        using LongfellowTranscript array = NewTranscript(TestSeed, version: 6);
        single.AbsorbFieldElement(element);
        array.AbsorbFieldElementArray(element, 1);

        Span<byte> singleKey = stackalloc byte[DigestSize];
        Span<byte> arrayKey = stackalloc byte[DigestSize];
        single.SnapshotKey(singleKey);
        array.SnapshotKey(arrayKey);

        Assert.IsFalse(singleKey.SequenceEqual(arrayKey), "A single field-element absorb and a one-element array absorb must produce distinct transcript keys.");
    }


    /// <summary>
    /// Advances a fresh transcript through the absorb sequence up to the point right before the
    /// nat() draws: payload, eltA drain, of_scalar(7), eltB drain, array, eltC drain, root,
    /// eltPostRoot drain, then the "nats" tag absorb. The reference draws the naturals immediately
    /// after that tag.
    /// </summary>
    private static LongfellowTranscript AdvanceToNatStage(int version)
    {
        LongfellowTranscript transcript = NewTranscript(TestSeed, version);
        transcript.AbsorbByteString(CounterPayload(100));
        DrainElements(transcript, 16);

        transcript.AbsorbFieldElement(OfScalar(7));
        DrainElements(transcript, 16);

        Span<byte> array = stackalloc byte[2 * FieldElementBytes];
        OfScalar(8).CopyTo(array[..FieldElementBytes]);
        OfScalar(9).CopyTo(array.Slice(FieldElementBytes, FieldElementBytes));
        transcript.AbsorbFieldElementArray(array, 2);
        DrainElements(transcript, 16);

        Span<byte> root = stackalloc byte[DigestSize];
        for(int i = 0; i < DigestSize; i++)
        {
            root[i] = (byte)(0xA0 + i);
        }

        transcript.AbsorbCommitmentRoot(root);
        DrainElements(transcript, 4);

        transcript.AbsorbByteString(Encoding.ASCII.GetBytes("nats"));

        return transcript;
    }


    /// <summary>
    /// Advances further: through the nat() draws and the "choose" tag absorb, leaving the
    /// transcript positioned exactly where the reference begins its choose() draws.
    /// </summary>
    private static LongfellowTranscript AdvanceToChooseStage(int version)
    {
        LongfellowTranscript transcript = AdvanceToNatStage(version);

        ulong[] bounds =
        [
            1, 1, 1, 2, 2, 2, 7, 7, 7, 7, 32, 32, 32, 32,
            256, 256, 256, 256, 1000, 10000, 60000, 65535, 100000, 100000
        ];
        foreach(ulong bound in bounds)
        {
            _ = transcript.SqueezeNatural(bound);
        }

        transcript.AbsorbByteString(Encoding.ASCII.GetBytes("choose"));

        return transcript;
    }


    /// <summary>Squeezes <paramref name="count"/> field elements and asserts each matches the reference's prefix{i} anchor line.</summary>
    private static void AssertSqueezedElements(LongfellowTranscript transcript, string prefix, int count)
    {
        Span<byte> element = stackalloc byte[FieldElementBytes];
        for(int i = 0; i < count; i++)
        {
            transcript.SqueezeFieldElementBytes(element);
            AssertHex($"{prefix}{i}", element, $"Element {prefix}{i} must match the reference.");
        }
    }


    /// <summary>Squeezes and discards <paramref name="count"/> field elements to advance the PRF stream.</summary>
    private static void DrainElements(LongfellowTranscript transcript, int count)
    {
        Span<byte> element = stackalloc byte[FieldElementBytes];
        for(int i = 0; i < count; i++)
        {
            transcript.SqueezeFieldElementBytes(element);
        }
    }


    /// <summary>
    /// Rebuilds a transcript to the post-"choose"-tag state, draws one distinct-natural subset, and
    /// asserts it matches the reference's comma-separated anchor value. Each subset is an independent
    /// draw from that shared state, so a fresh transcript is built per call.
    /// </summary>
    private static void AssertChosenSubsetIndependently(string label, int bound, int count)
    {
        using LongfellowTranscript transcript = AdvanceToChooseStage(version: 6);

        Span<int> chosen = stackalloc int[count];
        transcript.SqueezeIndexSubset(bound, count, chosen);

        string[] expected = Anchors[label].Split(',');
        Assert.HasCount(count, expected, $"The {label} subset size must match the reference.");
        for(int i = 0; i < count; i++)
        {
            Assert.AreEqual(int.Parse(expected[i], CultureInfo.InvariantCulture), chosen[i], $"{label} index {i} must match the reference.");
        }
    }


    /// <summary>Builds a counter byte string d[i] = i, the payload the reference's transcript test absorbs.</summary>
    private static byte[] CounterPayload(int length)
    {
        byte[] payload = new byte[length];
        for(int i = 0; i < length; i++)
        {
            payload[i] = (byte)i;
        }

        return payload;
    }


    /// <summary>
    /// Returns the reference's GF(2^128) of_scalar(u) over the production subfield (GF2_128&lt;4&gt;)
    /// for one of the small scalars the transcript test absorbs (7, 8, 9): the basis-combined
    /// element's to_bytes_field bytes, read directly from the anchor file (the ofscalar7/8/9
    /// lines) since the transcript only absorbs them and never interprets the bytes, so the gate
    /// needs the exact bytes the reference wrote, not a re-derivation.
    /// </summary>
    private static byte[] OfScalar(int value) =>
        value switch
        {
            7 or 8 or 9 => Convert.FromHexString(Anchors[$"ofscalar{value}"]),
            _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Only the absorbed scalars 7, 8, 9 are pinned.")
        };


    /// <summary>Builds a fresh transcript over the given seed and version, at the fixed 16-byte element width and SHA-256/AES-256-ECB backends.</summary>
    private static LongfellowTranscript NewTranscript(ReadOnlySpan<byte> seed, int version) =>
        new(seed, version, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Computes AES-256-ECB over a single 16-byte block with no padding: the reference's <c>PRF::Eval</c>.</summary>
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    /// <summary>Asserts that the actual bytes equal the anchor's hex-decoded value for the given label.</summary>
    private static void AssertHex(string label, ReadOnlySpan<byte> actual, string message)
    {
        byte[] expected = Convert.FromHexString(Anchors[label]);
        Assert.IsTrue(actual.SequenceEqual(expected), $"{message} (label {label})");
    }


    /// <summary>
    /// Parses the anchor file into a label-to-value map. Each line is "label=value"; the value is
    /// hex for keys/bytes/elements and a comma list for naturals/subsets.
    /// </summary>
    private static Dictionary<string, string> LoadAnchors()
    {
        string path = $"../../../{AnchorRelativePath}";
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach(string line in File.ReadAllLines(path))
        {
            if(line.Length == 0)
            {
                continue;
            }

            //Most lines are one "label=value"; the c2 dimension line carries several space-separated
            //"label=value" tokens. Values never contain spaces (hex strings, comma-joined integers),
            //so splitting on spaces and then on the first '=' parses both shapes.
            foreach(string token in line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            {
                int separator = token.IndexOf('=', StringComparison.Ordinal);
                if(separator < 0)
                {
                    continue;
                }

                map[token[..separator]] = token[(separator + 1)..];
            }
        }

        return map;
    }
}

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
/// The wire-format-conformant Fiat–Shamir TRANSCRIPT (conformance step C.3), gated as a faithful port
/// of google/longfellow-zk's <c>lib/random/transcript.h</c> <c>Transcript</c> (with its <c>FSPRF</c>
/// AES-256-ECB pseudo-random function) and the <c>lib/random/random.h</c> challenge generators
/// (<c>elt</c>, <c>nat</c>, <c>choose</c>), anchored to a challenge dump the reference itself computes.
/// </summary>
/// <remarks>
/// <para>
/// The oracle dump (transcript-anchor-output.txt in TestMaterial/Longfellow) is computed by the
/// reference implementation running in its own build environment; the production procedure is
/// development tooling outside this repository. For two seeds (<c>"test"</c> and a one-byte variant)
/// and two versions (6, the deployed mdoc default, and 4, the reference's transcript-test value), it
/// constructs a <c>Transcript</c>, performs the representative absorb sequence the Ligero flow drives
/// (a 100-byte payload, a field element, a field-element array, a 32-byte commitment root via
/// <c>write_commitment</c>, short tags), and dumps every squeezed challenge: the PRF key snapshots,
/// raw PRF bytes, GF(2^128) field elements, naturals via <c>nat()</c>, and index subsets via
/// <c>choose()</c>/<c>gen_idx</c>.
/// </para>
/// <para>
/// The C# gates reproduce every dumped value byte for byte: the SHA-256 snapshot keying, the
/// AES-256-ECB block stream, the typed absorb framing, the field-element squeeze, the rejection-sampled
/// naturals (including the high-bit mask), and the partial-Fisher–Yates index subset. The cross-layer
/// smoke absorbs the C.2 commitment root through <see cref="LongfellowTranscript.AbsorbCommitmentRoot"/>
/// and pins the first post-root index subset and element challenge against the C.2 production
/// dimensions — the first C.2 × C.3 conformance point. The adversarial duals show a one-byte-different
/// seed changes the whole stream, and that versions 4 and 6 produce identical streams (documenting that
/// this reference snapshot stores the version but does not branch on it in the exercised paths).
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowTranscriptTests
{
    private const string DumpRelativePath = "TestMaterial/Longfellow/transcript-anchor-output.txt";

    //The reference's GF(2^128) Field::kBytes: a field element is 16 little-endian bytes.
    private const int FieldElementBytes = 16;
    private const int DigestSize = 32;

    private static readonly byte[] TestSeed = Encoding.ASCII.GetBytes("test");

    //Parsed once: the dumped label -> value lines from the oracle output.
    private static Dictionary<string, string> Anchors { get; } = LoadAnchors();


    [TestMethod]
    public void TheInitialKeySnapshotMatchesTheReference()
    {
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);

        Span<byte> key = stackalloc byte[DigestSize];
        transcript.SnapshotKey(key);

        AssertHex("v6_key_init", key, "The initial PRF key snapshot must match the reference.");
    }


    [TestMethod]
    public void TheInitialRawByteSqueezeMatchesTheReference()
    {
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);

        Span<byte> bytes = stackalloc byte[DigestSize];
        transcript.SqueezeBytes(bytes);

        AssertHex("v6_bytes_init", bytes, "The first 32 PRF bytes must match the reference.");
    }


    [TestMethod]
    public void TheKeyAfterAbsorbingThePayloadMatchesTheReference()
    {
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);
        transcript.AbsorbByteString(CounterPayload(100));

        Span<byte> key = stackalloc byte[DigestSize];
        transcript.SnapshotKey(key);

        AssertHex("v6_key_afterbytes", key, "The PRF key after the 100-byte payload must match the reference.");
    }


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


    [TestMethod]
    public void TheIndexSubsetChallengesMatchTheReference()
    {
        //Each reference choose() draws from the SAME post-"choose"-tag transcript state (the harness
        //clones the transcript per draw), so the four subsets are INDEPENDENT, not chained: each is
        //regenerated from a fresh transcript advanced to the choose stage.
        AssertChosenSubsetIndependently("v6_ch31", bound: 31, count: 20);
        AssertChosenSubsetIndependently("v6_ch32", bound: 32, count: 20);
        AssertChosenSubsetIndependently("v6_ch1000", bound: 1000, count: 20);
        AssertChosenSubsetIndependently("v6_ch65535", bound: 65535, count: 20);
    }


    [TestMethod]
    public void Version4AndVersion6ProduceIdenticalStreams()
    {
        //This snapshot stores the version but never branches on it in the exercised paths; the two
        //full streams must be byte-identical. The dump pins both prefixes; here the C# port confirms
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

        //And both must equal the reference's v4_* dump, which equals v6_* in the oracle file.
        Assert.AreEqual(Anchors["v4_eltA0"], Anchors["v6_eltA0"], "The reference dump confirms v4 and v6 agree.");
    }


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

        //The altered key must also match the reference's valt_key_init dump.
        AssertHex("valt_key_init", alteredKey, "The altered-seed key must match the reference.");
    }


    [TestMethod]
    public void TheCrossLayerCommitmentRootBindsTheC2ProductionDimensions()
    {
        //The C.2 commitment root for the small production tuple (nw=8 nq=1 rateinv=4 nreq=2). The
        //transcript absorbs it exactly as write_commitment does, then gen_idx draws nreq=2 distinct
        //columns over block_enc - dblock = 23. This is the first cross-layer (C.2 x C.3) point.
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
        //post-root state (the reference clones per generator), so it regenerates from a fresh
        //transcript rather than chaining after the gen_idx draw above.
        using LongfellowTranscript elementTranscript = NewTranscript(Encoding.ASCII.GetBytes("c2"), version: 6);
        elementTranscript.AbsorbCommitmentRoot(c2Root);
        AssertSqueezedElements(elementTranscript, "c2_eltPostRoot", 2);
    }


    [TestMethod]
    public void RejectsAMisSizedFieldElementAbsorb()
    {
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);
        byte[] tooShort = new byte[FieldElementBytes - 1];
        Assert.ThrowsExactly<ArgumentException>(() => transcript.AbsorbFieldElement(tooShort));
    }


    [TestMethod]
    public void RejectsAMisSizedCommitmentRoot()
    {
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);
        byte[] wrongLength = new byte[DigestSize - 1];
        Assert.ThrowsExactly<ArgumentException>(() => transcript.AbsorbCommitmentRoot(wrongLength));
    }


    [TestMethod]
    public void RejectsAZeroNaturalBound()
    {
        using LongfellowTranscript transcript = NewTranscript(TestSeed, version: 6);
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => transcript.SqueezeNatural(0));
    }


    //Advances a fresh transcript through the absorb sequence up to the point right before the nat()
    //draws: payload, eltA drain, of_scalar(7), eltB drain, array, eltC drain, root, eltPostRoot drain,
    //then the "nats" tag absorb. The reference draws the naturals immediately after that tag.
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


    //Advances further: through the nat() draws and the "choose" tag absorb, leaving the transcript
    //positioned exactly where the reference begins its choose() draws.
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


    //Squeezes `count` field elements and asserts each matches the reference's prefix{i} dump line.
    private static void AssertSqueezedElements(LongfellowTranscript transcript, string prefix, int count)
    {
        Span<byte> element = stackalloc byte[FieldElementBytes];
        for(int i = 0; i < count; i++)
        {
            transcript.SqueezeFieldElementBytes(element);
            AssertHex($"{prefix}{i}", element, $"Element {prefix}{i} must match the reference.");
        }
    }


    //Squeezes and discards `count` field elements to advance the PRF stream.
    private static void DrainElements(LongfellowTranscript transcript, int count)
    {
        Span<byte> element = stackalloc byte[FieldElementBytes];
        for(int i = 0; i < count; i++)
        {
            transcript.SqueezeFieldElementBytes(element);
        }
    }


    //Rebuilds a transcript to the post-"choose"-tag state, draws one distinct-natural subset, and
    //asserts it matches the reference's comma-separated dump. Each subset is an independent draw from
    //that shared state (the harness clones per generator), so a fresh transcript is built per call.
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


    //A counter byte string d[i] = i, the payload the reference's transcript test absorbs.
    private static byte[] CounterPayload(int length)
    {
        byte[] payload = new byte[length];
        for(int i = 0; i < length; i++)
        {
            payload[i] = (byte)i;
        }

        return payload;
    }


    //The reference's GF(2^128) of_scalar(u) over the production subfield (GF2_128<4>): the bits of u
    //are coordinates over the subfield basis beta_[]. For the small scalars the transcript test
    //absorbs (7, 8, 9), the basis-combined element's to_bytes_field bytes come from the reference dump
    //(the ofscalar7/8/9 lines), since the transcript only absorbs them — it never interprets the
    //bytes, so the gate needs the exact bytes the reference wrote, not a re-derivation.
    private static byte[] OfScalar(int value) =>
        value switch
        {
            7 or 8 or 9 => Convert.FromHexString(Anchors[$"ofscalar{value}"]),
            _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Only the absorbed scalars 7, 8, 9 are pinned.")
        };


    private static LongfellowTranscript NewTranscript(ReadOnlySpan<byte> seed, int version) =>
        new(seed, version, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    //AES-256-ECB over a single 16-byte block with no padding: the reference's PRF::Eval.
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    private static void AssertHex(string label, ReadOnlySpan<byte> actual, string message)
    {
        byte[] expected = Convert.FromHexString(Anchors[label]);
        Assert.IsTrue(actual.SequenceEqual(expected), $"{message} (label {label})");
    }


    //Parses the oracle dump into a label -> value map. Each line is "label=value"; the value is hex for
    //keys/bytes/elements and a comma list for naturals/subsets.
    private static Dictionary<string, string> LoadAnchors()
    {
        string path = $"../../../{DumpRelativePath}";
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

using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The wire-format-conformant zk SUMCHECK SEGMENT (conformance step C.7), gated as a faithful port of
/// google/longfellow-zk's <c>ZkProof&lt;Field&gt;::write_sc_proof</c> / <c>read_sc_proof</c>
/// (<c>lib/zk/zk_proof.h</c>) and the transcript-driven layer-walk replay
/// (<c>VerifierLayers::layers</c>, <c>lib/sumcheck/verifier_layers.h</c>) framed by
/// <c>ZkCommon::initialize_sumcheck_fiat_shamir</c> and <c>TranscriptSumcheck::write_input</c>.
/// </summary>
/// <remarks>
/// <para>
/// The sc anchor (sc-anchor-output.txt in TestMaterial/Longfellow) is computed by the reference
/// implementation in its own build environment via development tooling outside this repository. It
/// compiles a small GF2_128&lt;4&gt; circuit (the field-satisfiable relation
/// <c>w == (x + y)·(x + z)·x</c>, logc = 0, nl = 3), runs the genuine sumcheck prover under the fixed FS
/// seed "sc7", and dumps the circuit shape, the input element bytes, the sc segment bytes through the
/// real <c>write_sc_proof</c>, every Fiat–Shamir challenge the verifier replays (Q, G, per-layer
/// alpha/beta, per-round per-hand challenge and folded claim, per-layer wc claims, the input-binding
/// challenge), and the reference's full sumcheck verifier accept.
/// </para>
/// <para>
/// The gates:
/// </para>
/// <list type="bullet">
///   <item><description><b>Read then Write</b>: our reader parses the anchor's <c>sc_bytes</c>, and our writer re-serializes the parsed proof to exactly those bytes (byte-identical round-trip both ways).</description></item>
///   <item><description><b>Size derivation</b>: the serialized size equals the reference's <c>sc_len</c>, derived from the circuit's per-layer <c>logw</c> exactly as <c>read_sc_proof</c> derives it.</description></item>
///   <item><description><b>Challenge replay</b>: our verifier replays the layer walk over the parsed proof and reproduces every dumped challenge and folded claim, including the input-binding challenge — the k != 1 reconstruction and the GF(2^128) Lagrange fold are exercised end to end.</description></item>
///   <item><description><b>Tampered round poly</b>: flipping a transmitted round-polynomial point diverges the squeezed challenge stream from the reference's.</description></item>
///   <item><description><b>Tampered claim</b>: flipping a wc claim diverges the next layer's challenge stream.</description></item>
///   <item><description><b>Truncated segment</b>: a sc buffer short by any number of bytes fails to parse (Read returns null), mirroring <c>read_sc_proof</c>'s underflow rejection.</description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class LongfellowSumcheckTests
{
    private const string ScDumpRelativePath = "TestMaterial/Longfellow/sc-anchor-output.txt";

    private const int ElementBytes = 16;
    private const int ScalarSize = Scalar.SizeBytes;
    private const int TranscriptVersion = 6;

    private static readonly byte[] TranscriptSeed = Encoding.ASCII.GetBytes("sc7");

    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();

    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(ScDumpRelativePath);


    [TestMethod]
    public void OurReaderParsesTheReferenceBytes()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] referenceBytes = Convert.FromHexString(Anchors["sc_bytes"]);

        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        using LongfellowSumcheckProof? parsed = LongfellowSumcheckProofSerializer.Read(circuit, profile, BaseMemoryPool.Shared, referenceBytes, out int read);

        Assert.IsNotNull(parsed, "Read must parse the reference sc bytes.");
        Assert.AreEqual(referenceBytes.Length, read, "Read must consume the whole sc segment.");
    }


    [TestMethod]
    public void OurWriteReproducesTheReferenceBytes()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] referenceBytes = Convert.FromHexString(Anchors["sc_bytes"]);
        int expectedLength = int.Parse(Anchors["sc_len"], System.Globalization.CultureInfo.InvariantCulture);

        Assert.HasCount(expectedLength, referenceBytes, "The anchor length and the dumped bytes must agree.");

        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        int size = LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile);
        Assert.AreEqual(expectedLength, size, "The size derived from the circuit shape must match sc_len.");

        using LongfellowSumcheckProof? parsed = LongfellowSumcheckProofSerializer.Read(circuit, profile, BaseMemoryPool.Shared, referenceBytes, out _);
        Assert.IsNotNull(parsed);

        byte[] written = new byte[size];
        int writtenCount = LongfellowSumcheckProofSerializer.Write(circuit, parsed, profile, written);

        Assert.AreEqual(expectedLength, writtenCount, "Write must produce exactly sc_len bytes.");
        Assert.IsTrue(written.AsSpan().SequenceEqual(referenceBytes), "Our serialized sc bytes must equal the reference's write_sc_proof output.");
    }


    [TestMethod]
    public void TheReplayReproducesEveryChallengeAndClaim()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] referenceBytes = Convert.FromHexString(Anchors["sc_bytes"]);

        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        using LongfellowSumcheckProof? parsed = LongfellowSumcheckProofSerializer.Read(circuit, profile, BaseMemoryPool.Shared, referenceBytes, out _);
        Assert.IsNotNull(parsed);

        byte[] inputElements = BuildInputElements(circuit);

        using LongfellowTranscript transcript = NewTranscript();

        var observer = new PinningObserver(Anchors);
        bool accepted = LongfellowSumcheckVerifier.Verify(
            circuit, parsed, inputElements, transcript, Add, Subtract, Multiply, Invert, profile,
            CurveParameterSet.None, BaseMemoryPool.Shared, out LongfellowSumcheckVerificationResult result, observer);

        Assert.IsTrue(accepted, $"The replay must complete (result {result}).");
        Assert.AreEqual(LongfellowSumcheckVerificationResult.Accepted, result);
        observer.AssertComplete();
    }


    [TestMethod]
    public void AReferenceAcceptIsRecorded()
    {
        //The harness records the reference's own full sumcheck Verifier accept over the same proof.
        Assert.AreEqual("1", Anchors["ref_sumcheck_verify"], "The reference sumcheck verifier must accept the dumped proof.");
        Assert.AreEqual("ok", Anchors["ref_sumcheck_why"], "The reference verdict must be ok.");
    }


    [TestMethod]
    public void ATamperedRoundPolynomialDivergesTheChallengeStream()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] referenceBytes = Convert.FromHexString(Anchors["sc_bytes"]);

        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        using LongfellowSumcheckProof? parsed = LongfellowSumcheckProofSerializer.Read(circuit, profile, BaseMemoryPool.Shared, referenceBytes, out _);
        Assert.IsNotNull(parsed);

        //Flip one byte of layer 0, hand 0, round 0, point 0 (a transmitted point). The first squeezed
        //challenge after that absorb must differ from the reference's.
        Span<byte> tampered = stackalloc byte[ScalarSize];
        parsed.RoundPolynomialPoint(0, 0, 0, 0).CopyTo(tampered);
        tampered[ScalarSize - 1] ^= 0x01;
        parsed.SetRoundPolynomialPoint(0, 0, 0, 0, tampered);

        byte[] inputElements = BuildInputElements(circuit);

        using LongfellowTranscript transcript = NewTranscript();

        var observer = new CaptureObserver();
        LongfellowSumcheckVerifier.Verify(
            circuit, parsed, inputElements, transcript, Add, Subtract, Multiply, Invert, profile,
            CurveParameterSet.None, BaseMemoryPool.Shared, out _, observer);

        byte[] referenceChallenge = ParseElement(Anchors["L0_r0_h0_chal"]);
        Assert.IsFalse(observer.FirstRoundChallenge.AsSpan().SequenceEqual(referenceChallenge), "A tampered round polynomial must change the first squeezed challenge.");
    }


    [TestMethod]
    public void ATamperedClaimDivergesTheNextLayerChallengeStream()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] referenceBytes = Convert.FromHexString(Anchors["sc_bytes"]);

        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        using LongfellowSumcheckProof? parsed = LongfellowSumcheckProofSerializer.Read(circuit, profile, BaseMemoryPool.Shared, referenceBytes, out _);
        Assert.IsNotNull(parsed);

        //Flip one byte of layer 0's wc[0]. The entering claim of layer 1 and its alpha/beta must change.
        Span<byte> tampered = stackalloc byte[ScalarSize];
        parsed.Claim(0, 0).CopyTo(tampered);
        tampered[ScalarSize - 1] ^= 0x01;
        parsed.SetClaim(0, 0, tampered);

        byte[] inputElements = BuildInputElements(circuit);

        using LongfellowTranscript transcript = NewTranscript();

        var observer = new CaptureObserver();
        LongfellowSumcheckVerifier.Verify(
            circuit, parsed, inputElements, transcript, Add, Subtract, Multiply, Invert, profile,
            CurveParameterSet.None, BaseMemoryPool.Shared, out _, observer);

        byte[] referenceAlpha = ParseElement(Anchors["L1_alpha"]);
        Assert.IsFalse(observer.SecondLayerAlpha.AsSpan().SequenceEqual(referenceAlpha), "A tampered claim must change the next layer's alpha challenge.");
    }


    [TestMethod]
    public void ATruncatedSegmentFailsToParse()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] referenceBytes = Convert.FromHexString(Anchors["sc_bytes"]);

        //read_sc_proof rejects any buffer short of the needed per-layer bytes. Drop the trailing bytes
        //one at a time and assert every truncation fails to parse.
        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        for(int drop = 1; drop <= referenceBytes.Length; drop++)
        {
            ReadOnlySpan<byte> truncated = referenceBytes.AsSpan(0, referenceBytes.Length - drop);
            using LongfellowSumcheckProof? parsed = LongfellowSumcheckProofSerializer.Read(circuit, profile, BaseMemoryPool.Shared, truncated, out _);
            Assert.IsNull(parsed, $"A sc buffer short by {drop} bytes must fail to parse.");
        }
    }


    //Reconstructs the circuit shape from the anchor's dumped parameters.
    private static LongfellowSumcheckCircuit BuildCircuit()
    {
        int nl = int.Parse(Anchors["nl"], System.Globalization.CultureInfo.InvariantCulture);
        var layers = new LongfellowSumcheckLayer[nl];
        for(int i = 0; i < nl; i++)
        {
            int nw = int.Parse(Anchors[$"layer{i}_nw"], System.Globalization.CultureInfo.InvariantCulture);
            int logw = int.Parse(Anchors[$"layer{i}_logw"], System.Globalization.CultureInfo.InvariantCulture);
            int nterms = int.Parse(Anchors[$"layer{i}_nterms"], System.Globalization.CultureInfo.InvariantCulture);
            layers[i] = new LongfellowSumcheckLayer(nw, logw, nterms);
        }

        byte[] id = Convert.FromHexString(Anchors["id"]);

        return new LongfellowSumcheckCircuit(
            int.Parse(Anchors["nv"], System.Globalization.CultureInfo.InvariantCulture),
            int.Parse(Anchors["logv"], System.Globalization.CultureInfo.InvariantCulture),
            int.Parse(Anchors["nc"], System.Globalization.CultureInfo.InvariantCulture),
            int.Parse(Anchors["logc"], System.Globalization.CultureInfo.InvariantCulture),
            int.Parse(Anchors["ninputs"], System.Globalization.CultureInfo.InvariantCulture),
            int.Parse(Anchors["npub_in"], System.Globalization.CultureInfo.InvariantCulture),
            id,
            layers);
    }


    //The input column bytes (little-endian to_bytes_field) the verifier's write_input absorbs.
    private static byte[] BuildInputElements(LongfellowSumcheckCircuit circuit)
    {
        byte[] inputElements = new byte[circuit.InputCount * ElementBytes];
        for(int i = 0; i < circuit.InputCount; i++)
        {
            byte[] element = Convert.FromHexString(Anchors[$"input{i}"]);
            element.CopyTo(inputElements.AsSpan(i * ElementBytes, ElementBytes));
        }

        return inputElements;
    }


    //Parses a 16-byte little-endian element into a 32-byte big-endian canonical scalar.
    private static byte[] ParseElement(string hex)
    {
        byte[] littleEndian = Convert.FromHexString(hex);
        byte[] canonical = new byte[ScalarSize];
        for(int i = 0; i < ElementBytes; i++)
        {
            canonical[ScalarSize - 1 - i] = littleEndian[i];
        }

        return canonical;
    }


    private static LongfellowTranscript NewTranscript() =>
        new(TranscriptSeed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    private static Dictionary<string, string> LoadAnchors(string relativePath)
    {
        string path = $"../../../{relativePath}";
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach(string line in File.ReadAllLines(path))
        {
            if(line.Length == 0)
            {
                continue;
            }

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


    //Pins every reconstructed challenge and claim against the dumped anchor values.
    private sealed class PinningObserver: LongfellowSumcheckVerifier.IReplayObserver
    {
        private readonly Dictionary<string, string> anchors;
        private bool sawInputChallenge;

        public PinningObserver(Dictionary<string, string> anchors)
        {
            this.anchors = anchors;
        }

        public void OnQ(int index, ReadOnlySpan<byte> value) => AssertElement($"q{index}", value);

        public void OnG(int index, ReadOnlySpan<byte> value) => AssertElement($"g{index}", value);

        public void OnLayerBegin(int layer, ReadOnlySpan<byte> alpha, ReadOnlySpan<byte> beta, ReadOnlySpan<byte> claimIn)
        {
            AssertElement($"L{layer}_alpha", alpha);
            AssertElement($"L{layer}_beta", beta);
            AssertElement($"L{layer}_claim_in", claimIn);
        }

        public void OnRound(int layer, int round, int hand, ReadOnlySpan<byte> sum01, ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> claim)
        {
            AssertElement($"L{layer}_r{round}_h{hand}_sum01", sum01);
            AssertElement($"L{layer}_r{round}_h{hand}_chal", challenge);
            AssertElement($"L{layer}_r{round}_h{hand}_claim", claim);
        }

        public void OnLayerClaims(int layer, ReadOnlySpan<byte> claim0, ReadOnlySpan<byte> claim1)
        {
            AssertElement($"L{layer}_wc0", claim0);
            AssertElement($"L{layer}_wc1", claim1);
        }

        public void OnInputChallenge(ReadOnlySpan<byte> value)
        {
            AssertElement("input_alpha", value);
            sawInputChallenge = true;
        }

        public void AssertComplete() => Assert.IsTrue(sawInputChallenge, "The replay must squeeze the input-binding challenge.");

        private void AssertElement(string key, ReadOnlySpan<byte> value)
        {
            byte[] expected = ParseElement(anchors[key]);
            Assert.IsTrue(value.SequenceEqual(expected), $"The replay's {key} must match the reference's dumped value.");
        }
    }


    //Captures the first squeezed round challenge and the second layer's alpha for the tamper duals.
    private sealed class CaptureObserver: LongfellowSumcheckVerifier.IReplayObserver
    {
        public byte[] FirstRoundChallenge { get; } = new byte[ScalarSize];

        public byte[] SecondLayerAlpha { get; } = new byte[ScalarSize];

        private bool capturedFirstChallenge;

        public void OnQ(int index, ReadOnlySpan<byte> value)
        {
        }

        public void OnG(int index, ReadOnlySpan<byte> value)
        {
        }

        public void OnLayerBegin(int layer, ReadOnlySpan<byte> alpha, ReadOnlySpan<byte> beta, ReadOnlySpan<byte> claimIn)
        {
            if(layer == 1)
            {
                alpha.CopyTo(SecondLayerAlpha);
            }
        }

        public void OnRound(int layer, int round, int hand, ReadOnlySpan<byte> sum01, ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> claim)
        {
            if(!capturedFirstChallenge)
            {
                challenge.CopyTo(FirstRoundChallenge);
                capturedFirstChallenge = true;
            }
        }

        public void OnLayerClaims(int layer, ReadOnlySpan<byte> claim0, ReadOnlySpan<byte> claim1)
        {
        }

        public void OnInputChallenge(ReadOnlySpan<byte> value)
        {
        }
    }
}

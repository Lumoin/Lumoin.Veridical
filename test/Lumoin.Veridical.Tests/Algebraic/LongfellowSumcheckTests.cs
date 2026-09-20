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
/// The wire-format-conformant zk SUMCHECK SEGMENT, gated as a faithful port of
/// google/longfellow-zk's <c>ZkProof&lt;Field&gt;::write_sc_proof</c> / <c>read_sc_proof</c>
/// (<c>lib/zk/zk_proof.h</c>) and the transcript-driven layer-walk replay
/// (<c>VerifierLayers::layers</c>, <c>lib/sumcheck/verifier_layers.h</c>) framed by
/// <c>ZkCommon::initialize_sumcheck_fiat_shamir</c> and <c>TranscriptSumcheck::write_input</c>.
/// </summary>
/// <remarks>
/// <para>
/// The gates:
/// </para>
/// <list type="bullet">
///   <item><description><b>Read then Write</b>: our reader parses the anchor's <c>sc_bytes</c>, and our writer re-serializes the parsed proof to exactly those bytes (byte-identical round-trip both ways).</description></item>
///   <item><description><b>Size derivation</b>: the serialized size equals the reference's <c>sc_len</c>, derived from the circuit's per-layer <c>logw</c> exactly as <c>read_sc_proof</c> derives it.</description></item>
///   <item><description><b>Challenge replay</b>: our verifier replays the layer walk over the parsed proof and reproduces every reference challenge and folded claim, including the input-binding challenge — the k != 1 reconstruction and the GF(2^128) Lagrange fold are exercised end to end.</description></item>
///   <item><description><b>Tampered round poly</b>: flipping a transmitted round-polynomial point diverges the squeezed challenge stream from the reference's.</description></item>
///   <item><description><b>Tampered claim</b>: flipping a wc claim diverges the next layer's challenge stream.</description></item>
///   <item><description><b>Truncated segment</b>: a sc buffer short by any number of bytes fails to parse (Read returns null), mirroring <c>read_sc_proof</c>'s underflow rejection.</description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class LongfellowSumcheckTests: IDisposable
{
    /// <summary>The independent compiler and circuit lifetime for this test.</summary>
    private LongfellowCircuitTestScope CircuitScope { get; } = new();

    /// <summary>Calls <see cref="Dispose"/> after each test, including when an assertion fails.</summary>
    [TestCleanup]
    public void DisposeCircuits()
    {
        Dispose();
    }


    /// <summary>Releases this test's compiler and circuit storage. Repeated calls have no effect.</summary>
    public void Dispose()
    {
        CircuitScope.Dispose();
    }


    /// <summary>The path, relative to the test project directory, to the GF(2^128) sumcheck-segment anchor this test cross-checks against.</summary>
    private const string SumcheckAnchorRelativePath = "TestMaterial/Longfellow/sc-anchor-output.txt";

    /// <summary>The on-wire element width, in bytes, for the GF(2^128) field.</summary>
    private const int ElementBytes = 16;

    /// <summary>The canonical scalar width in bytes.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The transcript wire-format version (6, the deployed mdoc flow's value) the verifier's replay is baked at.</summary>
    private const int TranscriptVersion = 6;

    /// <summary>The Fiat–Shamir transcript seed matching the anchor.</summary>
    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("sc7");

    /// <summary>The GF(2^128) addition delegate (XOR).</summary>
    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) subtraction delegate (coincides with addition).</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) multiplication delegate.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) inversion delegate.</summary>
    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>The parsed key/value map loaded from the GF(2^128) sumcheck-segment anchor.</summary>
    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(SumcheckAnchorRelativePath);


    /// <summary>Verifies that our reader parses the anchor's <c>sc_bytes</c> and consumes the whole sumcheck segment.</summary>
    [TestMethod]
    public void OurReaderParsesTheReferenceBytes()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] referenceBytes = Convert.FromHexString(Anchors["sc_bytes"]);

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        using LongfellowSumcheckProof? parsed = LongfellowSumcheckProofSerializer.Read(circuit, profile, BaseMemoryPool.Shared, referenceBytes, out int read);

        Assert.IsNotNull(parsed, "Read must parse the reference sc bytes.");
        Assert.AreEqual(referenceBytes.Length, read, "Read must consume the whole sc segment.");
    }


    /// <summary>Verifies that the serialized size derived from the circuit shape matches the reference's <c>sc_len</c>, and that re-serializing the parsed proof reproduces the reference's bytes exactly.</summary>
    [TestMethod]
    public void OurWriteReproducesTheReferenceBytes()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] referenceBytes = Convert.FromHexString(Anchors["sc_bytes"]);
        int expectedLength = int.Parse(Anchors["sc_len"], System.Globalization.CultureInfo.InvariantCulture);

        Assert.HasCount(expectedLength, referenceBytes, "The anchor length and the reference bytes must agree.");

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        int size = LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile);
        Assert.AreEqual(expectedLength, size, "The size derived from the circuit shape must match sc_len.");

        using LongfellowSumcheckProof? parsed = LongfellowSumcheckProofSerializer.Read(circuit, profile, BaseMemoryPool.Shared, referenceBytes, out _);
        Assert.IsNotNull(parsed);

        byte[] written = new byte[size];
        int writtenCount = LongfellowSumcheckProofSerializer.Write(circuit, parsed, profile, written);

        Assert.AreEqual(expectedLength, writtenCount, "Write must produce exactly sc_len bytes.");
        Assert.IsTrue(written.AsSpan().SequenceEqual(referenceBytes), "Our serialized sc bytes must equal the reference's write_sc_proof output.");
    }


    /// <summary>Verifies that replaying the layer walk over the parsed proof reproduces every reference Fiat–Shamir challenge and folded claim, including the input-binding challenge, and that verification accepts.</summary>
    [TestMethod]
    public void TheReplayReproducesEveryChallengeAndClaim()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] referenceBytes = Convert.FromHexString(Anchors["sc_bytes"]);

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
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


    /// <summary>Verifies that the anchor records the reference's own sumcheck verifier accepting the same proof.</summary>
    [TestMethod]
    public void AReferenceAcceptIsRecorded()
    {
        //The anchor records the reference's own full sumcheck Verifier accept over the same proof.
        Assert.AreEqual("1", Anchors["ref_sumcheck_verify"], "The reference sumcheck verifier must accept the anchor's proof.");
        Assert.AreEqual("ok", Anchors["ref_sumcheck_why"], "The reference verdict must be ok.");
    }


    /// <summary>Verifies that flipping a byte of a transmitted round-polynomial point changes the first squeezed Fiat–Shamir challenge.</summary>
    [TestMethod]
    public void ATamperedRoundPolynomialDivergesTheChallengeStream()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] referenceBytes = Convert.FromHexString(Anchors["sc_bytes"]);

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
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


    /// <summary>Verifies that flipping a byte of a layer's folded claim changes the next layer's alpha challenge.</summary>
    [TestMethod]
    public void ATamperedClaimDivergesTheNextLayerChallengeStream()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] referenceBytes = Convert.FromHexString(Anchors["sc_bytes"]);

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
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


    /// <summary>Verifies that truncating the sumcheck segment by any number of trailing bytes makes the reader fail to parse.</summary>
    [TestMethod]
    public void ATruncatedSegmentFailsToParse()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] referenceBytes = Convert.FromHexString(Anchors["sc_bytes"]);

        //read_sc_proof rejects any buffer short of the needed per-layer bytes. Drop the trailing bytes
        //one at a time and assert every truncation fails to parse.
        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        for(int drop = 1; drop <= referenceBytes.Length; drop++)
        {
            ReadOnlySpan<byte> truncated = referenceBytes.AsSpan(0, referenceBytes.Length - drop);
            using LongfellowSumcheckProof? parsed = LongfellowSumcheckProofSerializer.Read(circuit, profile, BaseMemoryPool.Shared, truncated, out _);
            Assert.IsNull(parsed, $"A sc buffer short by {drop} bytes must fail to parse.");
        }
    }


    /// <summary>
    /// Reconstructs the circuit shape from the anchor's parameters, with circuit owners released
    /// at test cleanup.
    /// </summary>
    private LongfellowSumcheckCircuit BuildCircuit()
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

        return CircuitScope.CreateCircuit(
            int.Parse(Anchors["nv"], System.Globalization.CultureInfo.InvariantCulture),
            int.Parse(Anchors["logv"], System.Globalization.CultureInfo.InvariantCulture),
            int.Parse(Anchors["nc"], System.Globalization.CultureInfo.InvariantCulture),
            int.Parse(Anchors["logc"], System.Globalization.CultureInfo.InvariantCulture),
            int.Parse(Anchors["ninputs"], System.Globalization.CultureInfo.InvariantCulture),
            int.Parse(Anchors["npub_in"], System.Globalization.CultureInfo.InvariantCulture),
            id,
            layers);
    }


    /// <summary>Builds the input column bytes (little-endian <c>to_bytes_field</c>) the verifier's <c>write_input</c> absorbs.</summary>
    /// <param name="circuit">The circuit whose <see cref="LongfellowSumcheckCircuit.InputCount"/> sizes the column.</param>
    /// <returns>The input element bytes.</returns>
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


    /// <summary>Parses a 16-byte little-endian element, hex-encoded, into a 32-byte big-endian canonical scalar.</summary>
    /// <param name="hex">The little-endian element bytes, hex-encoded.</param>
    /// <returns>The canonical big-endian scalar.</returns>
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


    /// <summary>Creates a transcript seeded with <see cref="TranscriptSeed"/> at the GF(2^128) element width.</summary>
    /// <returns>The new transcript.</returns>
    private static LongfellowTranscript NewTranscript() =>
        new(TranscriptSeed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Creates the LCH14 additive-FFT engine over the GF(2^128) production subfield.</summary>
    /// <returns>The new additive-FFT engine.</returns>
    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>Encrypts one block with AES-256 in ECB mode and no padding: the transcript's PRF squeezes through this primitive.</summary>
    /// <param name="key">The 32-byte AES key.</param>
    /// <param name="input">The plaintext block.</param>
    /// <param name="output">Receives the ciphertext block.</param>
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    /// <summary>
    /// Loads the anchor at <paramref name="relativePath"/> (resolved from the test binary's output
    /// directory) into a flat key/value map, splitting each non-empty line on spaces and each token on its
    /// first <c>=</c>.
    /// </summary>
    /// <param name="relativePath">The anchor file's path, relative to the test project directory.</param>
    /// <returns>The parsed key/value map.</returns>
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


    /// <summary>A replay observer that pins every reconstructed challenge and claim against the anchor values.</summary>
    private sealed class PinningObserver: LongfellowSumcheckVerifier.IReplayObserver
    {
        /// <summary>The anchor's parsed key/value map, supplying the expected element for every pinned key.</summary>
        private Dictionary<string, string> Anchors { get; }

        /// <summary>Whether <see cref="OnInputChallenge"/> has fired, so <see cref="AssertComplete"/> can confirm the replay reached it.</summary>
        private bool sawInputChallenge;

        /// <summary>Creates an observer that pins against the given anchor key/value map.</summary>
        /// <param name="anchors">The anchor's parsed key/value map.</param>
        public PinningObserver(Dictionary<string, string> anchors)
        {
            this.Anchors = anchors;
        }

        /// <summary>Pins a squeezed <c>Q</c> element against the anchor's <c>q{index}</c> value.</summary>
        /// <param name="index">The <c>Q</c> element's index.</param>
        /// <param name="value">The squeezed element bytes.</param>
        public void OnQ(int index, ReadOnlySpan<byte> value) => AssertElement($"q{index}", value);

        /// <summary>Pins a squeezed <c>G</c> element against the anchor's <c>g{index}</c> value.</summary>
        /// <param name="index">The <c>G</c> element's index.</param>
        /// <param name="value">The squeezed element bytes.</param>
        public void OnG(int index, ReadOnlySpan<byte> value) => AssertElement($"g{index}", value);

        /// <summary>Pins a layer's entering alpha, beta and claim against the anchor's per-layer values.</summary>
        /// <param name="layer">The layer index.</param>
        /// <param name="alpha">The layer's alpha challenge.</param>
        /// <param name="beta">The layer's beta challenge.</param>
        /// <param name="claimIn">The layer's entering claim.</param>
        public void OnLayerBegin(int layer, ReadOnlySpan<byte> alpha, ReadOnlySpan<byte> beta, ReadOnlySpan<byte> claimIn)
        {
            AssertElement($"L{layer}_alpha", alpha);
            AssertElement($"L{layer}_beta", beta);
            AssertElement($"L{layer}_claim_in", claimIn);
        }

        /// <summary>Pins one sumcheck round's transmitted sum, squeezed challenge and folded claim against the anchor's per-round values.</summary>
        /// <param name="layer">The layer index.</param>
        /// <param name="round">The round index within the hand.</param>
        /// <param name="hand">The hand index within the layer.</param>
        /// <param name="sum01">The round's transmitted sum-at-0/sum-at-1 point.</param>
        /// <param name="challenge">The round's squeezed challenge.</param>
        /// <param name="claim">The round's folded claim.</param>
        public void OnRound(int layer, int round, int hand, ReadOnlySpan<byte> sum01, ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> claim)
        {
            AssertElement($"L{layer}_r{round}_h{hand}_sum01", sum01);
            AssertElement($"L{layer}_r{round}_h{hand}_chal", challenge);
            AssertElement($"L{layer}_r{round}_h{hand}_claim", claim);
        }

        /// <summary>Pins a layer's two output-wire claims against the anchor's <c>wc0</c>/<c>wc1</c> values.</summary>
        /// <param name="layer">The layer index.</param>
        /// <param name="claim0">The first output-wire claim.</param>
        /// <param name="claim1">The second output-wire claim.</param>
        public void OnLayerClaims(int layer, ReadOnlySpan<byte> claim0, ReadOnlySpan<byte> claim1)
        {
            AssertElement($"L{layer}_wc0", claim0);
            AssertElement($"L{layer}_wc1", claim1);
        }

        /// <summary>Pins the input-binding challenge against the anchor's <c>input_alpha</c> value and records that the replay reached it.</summary>
        /// <param name="value">The squeezed input-binding challenge.</param>
        public void OnInputChallenge(ReadOnlySpan<byte> value)
        {
            AssertElement("input_alpha", value);
            sawInputChallenge = true;
        }

        /// <summary>Asserts that the replay squeezed the input-binding challenge, so no step of the walk was silently skipped.</summary>
        public void AssertComplete() => Assert.IsTrue(sawInputChallenge, "The replay must squeeze the input-binding challenge.");

        /// <summary>Asserts that a replayed element equals the anchor's value for <paramref name="key"/>.</summary>
        /// <param name="key">The anchor key naming the expected value.</param>
        /// <param name="value">The replayed element bytes.</param>
        private void AssertElement(string key, ReadOnlySpan<byte> value)
        {
            byte[] expected = ParseElement(Anchors[key]);
            Assert.IsTrue(value.SequenceEqual(expected), $"The replay's {key} must match the reference's recorded value.");
        }
    }


    /// <summary>A replay observer that captures the first squeezed round challenge and the second layer's alpha, for the tamper-divergence tests.</summary>
    private sealed class CaptureObserver: LongfellowSumcheckVerifier.IReplayObserver
    {
        /// <summary>The first round challenge the replay squeezed.</summary>
        public byte[] FirstRoundChallenge { get; } = new byte[ScalarSize];

        /// <summary>Layer 1's entering alpha challenge.</summary>
        public byte[] SecondLayerAlpha { get; } = new byte[ScalarSize];

        /// <summary>Whether <see cref="FirstRoundChallenge"/> has already been captured, so later rounds do not overwrite it.</summary>
        private bool capturedFirstChallenge;

        /// <summary>Ignores the squeezed <c>Q</c> element; this observer only captures round and layer-begin data.</summary>
        /// <param name="index">The <c>Q</c> element's index.</param>
        /// <param name="value">The squeezed element bytes.</param>
        public void OnQ(int index, ReadOnlySpan<byte> value)
        {
        }

        /// <summary>Ignores the squeezed <c>G</c> element; this observer only captures round and layer-begin data.</summary>
        /// <param name="index">The <c>G</c> element's index.</param>
        /// <param name="value">The squeezed element bytes.</param>
        public void OnG(int index, ReadOnlySpan<byte> value)
        {
        }

        /// <summary>Captures layer 1's alpha challenge into <see cref="SecondLayerAlpha"/>.</summary>
        /// <param name="layer">The layer index.</param>
        /// <param name="alpha">The layer's alpha challenge.</param>
        /// <param name="beta">The layer's beta challenge.</param>
        /// <param name="claimIn">The layer's entering claim.</param>
        public void OnLayerBegin(int layer, ReadOnlySpan<byte> alpha, ReadOnlySpan<byte> beta, ReadOnlySpan<byte> claimIn)
        {
            if(layer == 1)
            {
                alpha.CopyTo(SecondLayerAlpha);
            }
        }

        /// <summary>Captures the first round's squeezed challenge into <see cref="FirstRoundChallenge"/>; later rounds are ignored.</summary>
        /// <param name="layer">The layer index.</param>
        /// <param name="round">The round index within the hand.</param>
        /// <param name="hand">The hand index within the layer.</param>
        /// <param name="sum01">The round's transmitted sum-at-0/sum-at-1 point.</param>
        /// <param name="challenge">The round's squeezed challenge.</param>
        /// <param name="claim">The round's folded claim.</param>
        public void OnRound(int layer, int round, int hand, ReadOnlySpan<byte> sum01, ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> claim)
        {
            if(!capturedFirstChallenge)
            {
                challenge.CopyTo(FirstRoundChallenge);
                capturedFirstChallenge = true;
            }
        }

        /// <summary>Ignores the layer's output-wire claims; this observer only captures round and layer-begin data.</summary>
        /// <param name="layer">The layer index.</param>
        /// <param name="claim0">The first output-wire claim.</param>
        /// <param name="claim1">The second output-wire claim.</param>
        public void OnLayerClaims(int layer, ReadOnlySpan<byte> claim0, ReadOnlySpan<byte> claim1)
        {
        }

        /// <summary>Ignores the input-binding challenge; this observer only captures round and layer-begin data.</summary>
        /// <param name="value">The squeezed input-binding challenge.</param>
        public void OnInputChallenge(ReadOnlySpan<byte> value)
        {
        }
    }
}

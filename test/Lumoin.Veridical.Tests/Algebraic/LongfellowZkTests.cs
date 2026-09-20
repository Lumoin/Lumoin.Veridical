using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
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
/// The wire-format-conformant END-TO-END ZK verifier, gated as a faithful port of
/// google/longfellow-zk's <c>ZkCommon::verifier_constraints</c> (<c>lib/zk/zk_common.h</c>) and the full
/// <c>ZkVerifier</c> composition (<c>lib/zk/zk_verifier.h</c>): parse a complete <c>ZkProof</c> envelope
/// (<c>com ‖ sc ‖ com_proof</c>), replay the sumcheck to build the Ligero <c>A·w = b</c> constraint
/// system, run the Ligero verifier with the circuit-derived parameters.
/// </summary>
/// <remarks>
/// <para>
/// The gates:
/// </para>
/// <list type="bullet">
///   <item><description><b>Parameter derivation</b>: the circuit-derived <see cref="LongfellowLigeroParameters"/> match the reference's param_* fields (nw, nq, block_enc, block, dblock, block_ext, r, w, nwrow, nqtriples, nwqrow, nrow); pad_size and n_witness match.</description></item>
///   <item><description><b>Constraint system</b>: our verifier_constraints port reproduces the reference's cn, every A term (c, w, k) in order, and every b target — which transitively pins the Quad::bind_gh_all and Eq::eval math (the A coefficients are the eqq routing terms).</description></item>
///   <item><description><b>End-to-end accept</b>: our composed verifier accepts the reference's full proof bytes, parse through Ligero verify.</description></item>
///   <item><description><b>Reference accept</b>: the anchor records the reference's own ZkVerifier accept over the same bytes.</description></item>
///   <item><description><b>Rejection duals</b>: a tampered sc byte, a tampered com_proof byte, a tampered root byte and a tampered public input each reject (the catching layer is reported in the test name).</description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class LongfellowZkTests: IDisposable
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


    /// <summary>The repository-relative path to the reference's end-to-end ZK verification anchor.</summary>
    private const string ZkAnchorRelativePath = "TestMaterial/Longfellow/zk-anchor-output.txt";

    /// <summary>The GF(2^128) on-wire element width in bytes.</summary>
    private const int ElementBytes = 16;

    /// <summary>The canonical scalar width in bytes.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The commitment root and SHA-256 digest width in bytes.</summary>
    private const int DigestSize = 32;

    /// <summary>The Fiat-Shamir transcript version tag matching the anchor.</summary>
    private const int TranscriptVersion = 6;

    /// <summary>The full GF(2^128) field element width in bytes.</summary>
    private const int FieldBytes = 16;

    /// <summary>The production GF(2^16) subfield element width in bytes.</summary>
    private const int Production16SubFieldBytes = 2;

    /// <summary>The Ligero inverse rate the anchor's parameters were derived at.</summary>
    private const int InverseRate = 4;

    /// <summary>The number of opened Ligero columns the anchor's parameters were derived at.</summary>
    private const int OpenedColumnCount = 2;

    /// <summary>The fixed Fiat-Shamir seed ("zk8") matching the anchor.</summary>
    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("zk8");

    /// <summary>The GF(2^128) field addition delegate.</summary>
    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) field subtraction delegate.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) field multiplication delegate.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) field inversion delegate.</summary>
    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>The parsed key/value pairs of the reference's end-to-end ZK verification anchor.</summary>
    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(ZkAnchorRelativePath);


    /// <summary>Pins that the circuit-derived Ligero parameters and the pad/witness sizing match every corresponding field the anchor recorded.</summary>
    [TestMethod]
    public void TheDerivedParametersMatchTheReference()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, FieldBytes, Production16SubFieldBytes);

        Assert.AreEqual(Anchor("pad_size"), LongfellowZkVerifier.PadSize(circuit), "pad_size must match.");
        Assert.AreEqual(Anchor("n_witness"), LongfellowZkVerifier.WitnessCount(circuit), "n_witness must match.");

        Assert.AreEqual(Anchor("param_nw"), parameters.WitnessCount, "nw must match.");
        Assert.AreEqual(Anchor("param_nq"), parameters.QuadraticConstraintCount, "nq must match.");
        Assert.AreEqual(Anchor("param_rateinv"), parameters.InverseRate, "rateinv must match.");
        Assert.AreEqual(Anchor("param_nreq"), parameters.OpenedColumnCount, "nreq must match.");
        Assert.AreEqual(Anchor("param_block_enc"), parameters.BlockEncoded, "block_enc must match.");
        Assert.AreEqual(Anchor("param_block"), parameters.Block, "block must match.");
        Assert.AreEqual(Anchor("param_dblock"), parameters.DoubleBlock, "dblock must match.");
        Assert.AreEqual(Anchor("param_block_ext"), parameters.BlockExtension, "block_ext must match.");
        Assert.AreEqual(Anchor("param_r"), parameters.RandomCount, "r must match.");
        Assert.AreEqual(Anchor("param_w"), parameters.WitnessPerRow, "w must match.");
        Assert.AreEqual(Anchor("param_nwrow"), parameters.WitnessRowCount, "nwrow must match.");
        Assert.AreEqual(Anchor("param_nqtriples"), parameters.QuadraticTripleCount, "nqtriples must match.");
        Assert.AreEqual(Anchor("param_nwqrow"), parameters.WitnessQuadraticRowCount, "nwqrow must match.");
        Assert.AreEqual(Anchor("param_nrow"), parameters.RowCount, "nrow must match.");
    }


    /// <summary>Pins that replaying the sumcheck and building the Ligero constraint system reproduces the reference's constraint count, every A term (constraint index, witness index, coefficient) in order, the per-layer eqq value pinned through each layer's claim_pad(2) term, and every b target.</summary>
    [TestMethod]
    public void TheConstraintSystemMatchesTheReference()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] proofBytes = Convert.FromHexString(Anchors["proof_bytes"]);
        byte[] publicInputs = BuildPublicInputs(circuit);

        //Parse the sumcheck segment out of the envelope, then drive the constraint build directly.
        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        int scSize = LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile);
        ReadOnlySpan<byte> scBytes = proofBytes.AsSpan(DigestSize, scSize);

        using LongfellowSumcheckProof? sumcheckProof = LongfellowSumcheckProofSerializer.Read(circuit, profile, BaseMemoryPool.Shared, scBytes, out _);
        Assert.IsNotNull(sumcheckProof);

        using LongfellowTranscript transcript = NewTranscript();

        //recv_commitment then the FS setup, exactly as the verifier does, before the constraint build.
        transcript.AbsorbCommitmentRoot(proofBytes.AsSpan(0, DigestSize));
        AbsorbFiatShamirSetup(circuit, publicInputs, transcript);

        int firstPadIndex = LongfellowZkVerifier.WitnessCount(circuit);
        using LongfellowZkConstraintBuilder.ConstraintSystem system = LongfellowZkConstraintBuilder.Build(
            circuit, sumcheckProof, publicInputs, firstPadIndex, transcript, Add, Subtract, Multiply, Invert, profile,
            CurveParameterSet.None, BaseMemoryPool.Shared);

        Assert.AreEqual(Anchor("vc_cn"), system.ConstraintCount, "The constraint count cn must match.");
        Assert.HasCount(Anchor("vc_a_terms"), system.Terms, "The A term count must match.");

        for(int i = 0; i < system.Terms.Count; i++)
        {
            LigeroLinearConstraint term = system.Terms[i];
            Assert.AreEqual(Anchor($"vc_a{i}_c"), term.ConstraintIndex, $"A term {i} constraint index must match.");
            Assert.AreEqual(Anchor($"vc_a{i}_w"), term.WitnessIndex, $"A term {i} witness index must match.");
            byte[] expectedK = ParseElement(Anchors[$"vc_a{i}_k"]);
            Assert.IsTrue(term.Coefficient.Span.SequenceEqual(expectedK), $"A term {i} coefficient k must match.");
        }

        //The Quad/Eq math is pinned directly: each layer constraint's claim_pad(2) term equals -eqq (= eqq
        //over GF(2)), so the last A term of every layer must equal the anchor's per-layer eqq = eqv·bind_quad.
        for(int layer = 0; layer < circuit.LayerCount; layer++)
        {
            int padBase = LongfellowZkVerifier.WitnessCount(circuit);
            for(int prior = 0; prior < layer; prior++)
            {
                padBase += LayerPadSize(circuit.Layers[prior].HandRounds);
            }

            int claimPadTwoWitness = padBase + ClaimPadIndex(circuit.Layers[layer].HandRounds, 2);
            LigeroLinearConstraint claimPadTwoTerm = FindTerm(system, layer, claimPadTwoWitness);
            byte[] expectedEqq = ParseElement(Anchors[$"vc_L{layer}_eqq"]);
            Assert.IsTrue(claimPadTwoTerm.Coefficient.Span.SequenceEqual(expectedEqq), $"Layer {layer}'s claim_pad(2) term must equal eqq (= eqv·bind_quad).");
        }

        int targetCount = system.Targets.Length / ScalarSize;
        Assert.AreEqual(system.ConstraintCount, targetCount, "The target count must equal cn.");
        for(int i = 0; i < targetCount; i++)
        {
            byte[] expectedB = ParseElement(Anchors[$"vc_b{i}"]);
            Assert.IsTrue(system.Targets.Slice(i * ScalarSize, ScalarSize).SequenceEqual(expectedB), $"Target b{i} must match.");
        }
    }


    /// <summary>Pins that the composed verifier accepts the reference's full proof bytes parsed against the reference's public inputs.</summary>
    [TestMethod]
    public void OurVerifierAcceptsTheReferenceProof()
    {
        AssertVerdict(Convert.FromHexString(Anchors["proof_bytes"]), BuildPublicInputs(BuildCircuit()), expectedAccept: true, LongfellowZkVerificationResult.Accepted);
    }


    /// <summary>Pins that the anchor itself records a successful parse, a successful prove, and a successful ZkVerifier accept over the same bytes.</summary>
    [TestMethod]
    public void AReferenceAcceptIsRecorded()
    {
        Assert.AreEqual("1", Anchors["ref_parsed"], "The reference must parse the full proof envelope.");
        Assert.AreEqual("1", Anchors["ref_zk_verify"], "The reference ZkVerifier must accept the full proof.");
        Assert.AreEqual("1", Anchors["proved"], "The reference ZkProver must have produced the proof.");
    }


    /// <summary>Pins that flipping a byte inside the sumcheck segment diverges the derived challenge stream and constraint coefficients, so the Ligero opening does not match the commitment and verification is rejected.</summary>
    [TestMethod]
    public void ATamperedSumcheckByteIsRejectedByLigero()
    {
        byte[] proofBytes = Convert.FromHexString(Anchors["proof_bytes"]);

        //Flip a byte inside the sumcheck segment (after the 32-byte root). The derived challenge stream
        //and the constraint coefficients diverge; the Ligero opening does not match the commitment.
        int scStart = DigestSize;
        proofBytes[scStart + 8] ^= 0x01;

        AssertVerdict(proofBytes, BuildPublicInputs(BuildCircuit()), expectedAccept: false, LongfellowZkVerificationResult.LigeroRejected);
    }


    /// <summary>Pins that flipping a byte inside the com_proof segment breaks the response rows and opened columns' recomputation, so a Ligero check fails.</summary>
    [TestMethod]
    public void ATamperedComProofByteIsRejectedByLigero()
    {
        byte[] proofBytes = Convert.FromHexString(Anchors["proof_bytes"]);

        //Flip a byte inside the com_proof segment (after com + sc). The response rows / opened columns no
        //longer recompute consistently; a Ligero check fails.
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        int comProofStart = DigestSize + LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile);
        proofBytes[comProofStart + 4] ^= 0x01;

        AssertVerdict(proofBytes, BuildPublicInputs(circuit), expectedAccept: false, LongfellowZkVerificationResult.LigeroRejected);
    }


    /// <summary>Pins that flipping a byte of the commitment root moves the whole challenge stream, so the Merkle check does not recompute the differing root from the opened leaves.</summary>
    [TestMethod]
    public void ATamperedRootByteIsRejectedByLigero()
    {
        byte[] proofBytes = Convert.FromHexString(Anchors["proof_bytes"]);

        //Flip a byte of the commitment root. The absorbed root moves the whole challenge stream, and the
        //Merkle check does not recompute the differing root from the opened leaves.
        proofBytes[0] ^= 0x01;

        AssertVerdict(proofBytes, BuildPublicInputs(BuildCircuit()), expectedAccept: false, LongfellowZkVerificationResult.LigeroRejected);
    }


    /// <summary>Pins that flipping a byte of a public input moves the Fiat-Shamir challenge stream and changes the input-constraint public binding, so Ligero verification fails.</summary>
    [TestMethod]
    public void ATamperedPublicInputIsRejectedByLigero()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] proofBytes = Convert.FromHexString(Anchors["proof_bytes"]);
        byte[] publicInputs = BuildPublicInputs(circuit);

        //Flip a byte of a public input. It enters the FS setup (moving the challenge stream) and the
        //input-constraint public binding (changing b), so the Ligero verification fails.
        publicInputs[ElementBytes + 1] ^= 0x01;

        AssertVerdict(proofBytes, publicInputs, expectedAccept: false, LongfellowZkVerificationResult.LigeroRejected);
    }


    /// <summary>Builds the circuit and verifies the given proof bytes against the given public inputs, asserting both the accept/reject verdict and its cause match what is expected. Circuit owners are released at this test's cleanup.</summary>
    private void AssertVerdict(byte[] proofBytes, byte[] publicInputs, bool expectedAccept, LongfellowZkVerificationResult expectedResult)
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, FieldBytes, Production16SubFieldBytes);

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowTranscript transcript = NewTranscript();

        bool accepted = LongfellowZkVerifier.Verify(
            circuit,
            parameters,
            proofBytes,
            publicInputs,
            Production16SubFieldBytes,
            transcript,
            fft,
            Add,
            Subtract,
            Multiply,
            Invert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared,
            out LongfellowZkVerificationResult result);

        Assert.AreEqual(expectedAccept, accepted, $"The verdict must be {(expectedAccept ? "accept" : "reject")} (result {result}).");
        Assert.AreEqual(expectedResult, result, "The verdict cause must match the expected layer.");
    }


    /// <summary>The reference's PadLayout layer size: <c>claim_pad(3) = 4·logw + 3</c>.</summary>
    private static int LayerPadSize(int handRounds) => (4 * handRounds) + 3;

    /// <summary>The reference's PadLayout claim-pad index: <c>claim_pad(n) = 4·logw + n</c>.</summary>
    private static int ClaimPadIndex(int handRounds, int n) => (4 * handRounds) + n;


    /// <summary>Finds the single A term for the given constraint and witness index.</summary>
    private static LigeroLinearConstraint FindTerm(LongfellowZkConstraintBuilder.ConstraintSystem system, int constraintIndex, int witnessIndex)
    {
        foreach(LigeroLinearConstraint term in system.Terms)
        {
            if(term.ConstraintIndex == constraintIndex && term.WitnessIndex == witnessIndex)
            {
                return term;
            }
        }

        Assert.Fail($"No A term for constraint {constraintIndex}, witness {witnessIndex}.");

        return default;
    }


    /// <summary>Reconstructs the circuit shape with its per-layer Quad terms from the anchor's recorded parameters; circuit owners are released at this test's cleanup.</summary>
    private LongfellowSumcheckCircuit BuildCircuit()
    {
        int nl = Anchor("nl");
        var layers = new LongfellowSumcheckLayer[nl];
        for(int i = 0; i < nl; i++)
        {
            int nw = Anchor($"layer{i}_nw");
            int logw = Anchor($"layer{i}_logw");
            int nterms = Anchor($"layer{i}_nterms");

            var quadTerms = new LongfellowSumcheckQuadTerm[nterms];
            for(int t = 0; t < nterms; t++)
            {
                int gate = Anchor($"L{i}_t{t}_g");
                int left = Anchor($"L{i}_t{t}_h0");
                int right = Anchor($"L{i}_t{t}_h1");
                byte[] v = ParseElement(Anchors[$"L{i}_t{t}_v"]);
                quadTerms[t] = new LongfellowSumcheckQuadTerm(gate, left, right, v);
            }

            layers[i] = new LongfellowSumcheckLayer(nw, logw, nterms, quadTerms);
        }

        byte[] id = Convert.FromHexString(Anchors["id"]);

        return CircuitScope.CreateCircuit(
            Anchor("nv"),
            Anchor("logv"),
            Anchor("nc"),
            Anchor("logc"),
            Anchor("ninputs"),
            Anchor("npub_in"),
            id,
            layers);
    }


    /// <summary>The public input element bytes (little-endian to_bytes_field): the first npub_in inputs.</summary>
    private static byte[] BuildPublicInputs(LongfellowSumcheckCircuit circuit)
    {
        byte[] publicInputs = new byte[circuit.PublicInputCount * ElementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            byte[] element = Convert.FromHexString(Anchors[$"input{i}"]);
            element.CopyTo(publicInputs.AsSpan(i * ElementBytes, ElementBytes));
        }

        return publicInputs;
    }


    /// <summary>The reference's ZkCommon::initialize_sumcheck_fiat_shamir: absorbs id, public inputs, zero, and nterms zero bytes (no input column — the ZK verifier never absorbs the witness).</summary>
    private static void AbsorbFiatShamirSetup(LongfellowSumcheckCircuit circuit, byte[] publicInputs, LongfellowTranscript transcript)
    {
        transcript.AbsorbByteString(circuit.Id.Span);
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            transcript.AbsorbFieldElement(publicInputs.AsSpan(i * ElementBytes, ElementBytes));
        }

        Span<byte> zeroElement = stackalloc byte[ElementBytes];
        zeroElement.Clear();
        transcript.AbsorbFieldElement(zeroElement);

        byte[] zeros = new byte[circuit.TermCount];
        transcript.AbsorbByteString(zeros);
    }


    /// <summary>Parses a 16-byte little-endian element into a 32-byte big-endian canonical scalar.</summary>
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


    /// <summary>Parses the anchor value for the given key as a base-10 integer.</summary>
    private static int Anchor(string key) => int.Parse(Anchors[key], CultureInfo.InvariantCulture);


    /// <summary>Builds a fresh transcript under the fixed seed and version the anchor uses.</summary>
    private static LongfellowTranscript NewTranscript() =>
        new(TranscriptSeed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Builds the GF(2^128) additive FFT at the production-16 subfield.</summary>
    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>The one-shot leaf hash: SHA256 over the whole nonce-plus-column input span.</summary>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        SHA256.HashData(input, output);
    }


    /// <summary>The reference's node combine: SHA256(left || right).</summary>
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[left.Length + right.Length];
        left.CopyTo(combined);
        right.CopyTo(combined[left.Length..]);
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>AES-256 in ECB mode, no padding: the reference's block-cipher-based Fiat-Shamir expansion primitive.</summary>
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    /// <summary>Reads the anchor's whitespace-separated <c>key=value</c> tokens into a lookup, skipping blank lines and tokens with no <c>=</c>.</summary>
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
}

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
/// The wire-format-conformant END-TO-END ZK verifier (conformance step C.8), gated as a faithful port of
/// google/longfellow-zk's <c>ZkCommon::verifier_constraints</c> (<c>lib/zk/zk_common.h</c>) and the full
/// <c>ZkVerifier</c> composition (<c>lib/zk/zk_verifier.h</c>): parse a complete <c>ZkProof</c> envelope
/// (<c>com ‖ sc ‖ com_proof</c>), replay the sumcheck to build the Ligero <c>A·w = b</c> constraint
/// system, run the Ligero verifier with the circuit-derived parameters.
/// </summary>
/// <remarks>
/// <para>
/// The zk anchor (zk-anchor-output.txt in TestMaterial/Longfellow) is computed by the reference
/// implementation in its own build environment via development tooling outside this repository. It
/// compiles the same small GF2_128&lt;4&gt; circuit C.7 used (the field-satisfiable relation
/// <c>w == (x + y)·(x + z)·x</c>, logc = 0, nl = 3), runs the real ZkProver (commit + prove) under the
/// fixed FS seed "zk8", serializes the whole ZkProof envelope, and runs the reference ZkVerifier over the
/// parsed bytes. It dumps the circuit shape, the per-layer Quad wiring terms, the witness/public inputs,
/// the derived LigeroParam, the full proof bytes, the verifier_constraints output (cn, the A/b system,
/// the per-layer bind_quad/eqv/eqq), and the reference ZkVerifier accept.
/// </para>
/// <para>
/// The gates:
/// </para>
/// <list type="bullet">
///   <item><description><b>Parameter derivation</b>: the circuit-derived <see cref="LongfellowLigeroParameters"/> match the reference's param_* fields (nw, nq, block_enc, block, dblock, block_ext, r, w, nwrow, nqtriples, nwqrow, nrow); pad_size and n_witness match.</description></item>
///   <item><description><b>Constraint system</b>: our verifier_constraints port reproduces the reference's cn, every A term (c, w, k) in order, and every b target — which transitively pins the Quad::bind_gh_all and Eq::eval math (the A coefficients are the eqq routing terms).</description></item>
///   <item><description><b>End-to-end accept</b>: our composed verifier accepts the reference's full proof bytes, parse through Ligero verify.</description></item>
///   <item><description><b>Reference accept</b>: the harness records the reference's own ZkVerifier accept over the same bytes.</description></item>
///   <item><description><b>Rejection duals</b>: a tampered sc byte, a tampered com_proof byte, a tampered root byte and a tampered public input each reject (the catching layer is reported in the test name).</description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class LongfellowZkTests
{
    private const string ZkDumpRelativePath = "TestMaterial/Longfellow/zk-anchor-output.txt";

    private const int ElementBytes = 16;
    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSize = 32;
    private const int TranscriptVersion = 6;

    private const int FieldBytes = 16;
    private const int Production16SubFieldBytes = 2;
    private const int InverseRate = 4;
    private const int OpenedColumnCount = 2;

    private static readonly byte[] TranscriptSeed = Encoding.ASCII.GetBytes("zk8");

    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();

    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(ZkDumpRelativePath);


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


    [TestMethod]
    public void TheConstraintSystemMatchesTheReference()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] proofBytes = Convert.FromHexString(Anchors["proof_bytes"]);
        byte[] publicInputs = BuildPublicInputs(circuit);

        //Parse the sumcheck segment out of the envelope, then drive the constraint build directly.
        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
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
        //over GF(2)), so the last A term of every layer must equal the dumped per-layer eqq = eqv·bind_quad.
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


    [TestMethod]
    public void OurVerifierAcceptsTheReferenceProof()
    {
        AssertVerdict(Convert.FromHexString(Anchors["proof_bytes"]), BuildPublicInputs(BuildCircuit()), expectedAccept: true, LongfellowZkVerificationResult.Accepted);
    }


    [TestMethod]
    public void AReferenceAcceptIsRecorded()
    {
        Assert.AreEqual("1", Anchors["ref_parsed"], "The reference must parse the full proof envelope.");
        Assert.AreEqual("1", Anchors["ref_zk_verify"], "The reference ZkVerifier must accept the full proof.");
        Assert.AreEqual("1", Anchors["proved"], "The reference ZkProver must have produced the proof.");
    }


    [TestMethod]
    public void ATamperedSumcheckByteIsRejectedByLigero()
    {
        byte[] proofBytes = Convert.FromHexString(Anchors["proof_bytes"]);

        //Flip a byte inside the sumcheck segment (after the 32-byte root). The derived challenge stream
        //and the constraint coefficients diverge; the Ligero opening no longer matches the commitment.
        int scStart = DigestSize;
        proofBytes[scStart + 8] ^= 0x01;

        AssertVerdict(proofBytes, BuildPublicInputs(BuildCircuit()), expectedAccept: false, LongfellowZkVerificationResult.LigeroRejected);
    }


    [TestMethod]
    public void ATamperedComProofByteIsRejectedByLigero()
    {
        byte[] proofBytes = Convert.FromHexString(Anchors["proof_bytes"]);

        //Flip a byte inside the com_proof segment (after com + sc). The response rows / opened columns no
        //longer recompute consistently; a Ligero check fails.
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        int comProofStart = DigestSize + LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile);
        proofBytes[comProofStart + 4] ^= 0x01;

        AssertVerdict(proofBytes, BuildPublicInputs(circuit), expectedAccept: false, LongfellowZkVerificationResult.LigeroRejected);
    }


    [TestMethod]
    public void ATamperedRootByteIsRejectedByLigero()
    {
        byte[] proofBytes = Convert.FromHexString(Anchors["proof_bytes"]);

        //Flip a byte of the commitment root. The absorbed root moves the whole challenge stream, and the
        //Merkle check no longer recomputes the (now-different) root from the opened leaves.
        proofBytes[0] ^= 0x01;

        AssertVerdict(proofBytes, BuildPublicInputs(BuildCircuit()), expectedAccept: false, LongfellowZkVerificationResult.LigeroRejected);
    }


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


    private static void AssertVerdict(byte[] proofBytes, byte[] publicInputs, bool expectedAccept, LongfellowZkVerificationResult expectedResult)
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


    //The reference PadLayout: layer_size = claim_pad(3) = 4·logw + 3; claim_pad(n) = 4·logw + n.
    private static int LayerPadSize(int handRounds) => (4 * handRounds) + 3;

    private static int ClaimPadIndex(int handRounds, int n) => (4 * handRounds) + n;


    //Finds the single A term for the given constraint and witness index.
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


    //Reconstructs the circuit shape with its per-layer Quad terms from the anchor's dumped parameters.
    private static LongfellowSumcheckCircuit BuildCircuit()
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

        return new LongfellowSumcheckCircuit(
            Anchor("nv"),
            Anchor("logv"),
            Anchor("nc"),
            Anchor("logc"),
            Anchor("ninputs"),
            Anchor("npub_in"),
            id,
            layers);
    }


    //The public input element bytes (little-endian to_bytes_field): the first npub_in inputs.
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


    //ZkCommon::initialize_sumcheck_fiat_shamir: id, public inputs, zero, nterms zero bytes (no input
    //column — the ZK verifier never absorbs the witness).
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


    private static int Anchor(string key) => int.Parse(Anchors[key], CultureInfo.InvariantCulture);


    private static LongfellowTranscript NewTranscript() =>
        new(TranscriptSeed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        SHA256.HashData(input, output);
    }


    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[left.Length + right.Length];
        left.CopyTo(combined);
        right.CopyTo(combined[left.Length..]);
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


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
}

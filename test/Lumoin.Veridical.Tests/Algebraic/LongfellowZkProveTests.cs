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
/// The wire-format-conformant END-TO-END ZK PROVER (conformance step C.9), gated as a faithful port of
/// google/longfellow-zk's <c>ZkProver</c> (<c>lib/zk/zk_prover.h</c>): commit a sumcheck witness and a
/// random pad encrypting the sumcheck transcript, run the sumcheck emitting the padded transcript, then
/// prove with Ligero that the committed witness and pad satisfy the sumcheck verifier — producing a
/// complete <c>ZkProof</c> envelope (<c>com ‖ sc ‖ com_proof</c>) byte-identical to the reference's.
/// </summary>
/// <remarks>
/// <para>
/// The zk anchor (zk-anchor-output.txt in TestMaterial/Longfellow) is computed by the reference
/// implementation in its own build environment via development tooling outside this repository. It
/// compiles the same small GF2_128&lt;4&gt; circuit C.7/C.8 used (the field-satisfiable relation
/// <c>w == (x + y)·(x + z)·x</c>, logc = 0, nl = 3), runs the real ZkProver (commit + prove) under the
/// fixed FS seed "zk8" and the counter random engine (the k-th byte = k &amp; 0xFF), serializes the whole
/// ZkProof envelope, and runs the reference ZkVerifier over the parsed bytes. The fixed witnesses are
/// x = of_scalar(3) (public), y = of_scalar(5), z = of_scalar(7), w = the field product (private);
/// W[0] is the constant-one wire.
/// </para>
/// <para>
/// The gates:
/// </para>
/// <list type="bullet">
///   <item><description><b>Byte identity</b>: our prover's complete ZkProof envelope equals the reference's 1864 proof bytes, segment for segment (the commitment root, the sumcheck segment, the Ligero proof).</description></item>
///   <item><description><b>Self-verify</b>: our C.8 verifier accepts our prover's proof.</description></item>
///   <item><description><b>Witness dual</b>: a different satisfying witness produces a different but still-accepted proof; an unsatisfying witness is unprovable (the circuit output is non-zero).</description></item>
///   <item><description><b>Seed dual</b>: a different Fiat–Shamir seed produces a different but still-accepted proof.</description></item>
/// </list>
/// <para>
/// The reverse gate — feeding our proof bytes to the reference's ZkVerifier in Docker — is recorded by
/// the anchor's <c>ref_zk_verify</c> over the byte-identical bytes (our envelope equals the reference's,
/// so the reference's own accept over those bytes is the reverse gate; the C.8 anchor already records it).
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowZkProveTests
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

    //The anchor's subfield_boundary is 0 (the reference rebases it: 0 < npub_in, so it stays 0).
    private const int SubfieldBoundary = 0;

    private static readonly byte[] TranscriptSeed = Encoding.ASCII.GetBytes("zk8");

    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();

    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(ZkDumpRelativePath);


    [TestMethod]
    public void TheProofEnvelopeMatchesTheReferenceByteForByte()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] witnessColumn = BuildWitnessColumn(circuit);

        byte[] proof = ProduceProof(circuit, witnessColumn, TranscriptSeed);

        byte[] expected = Convert.FromHexString(Anchors["proof_bytes"]);

        //Write the proof for the out-of-repo Docker reverse gate (the reference ZkVerifier over our bytes).
        string? reverseGatePath = Environment.GetEnvironmentVariable("ZK_REVERSE_GATE_PATH");
        if(reverseGatePath is not null)
        {
            File.WriteAllBytes(reverseGatePath, proof);
        }

        Assert.HasCount(expected.Length, proof, "The proof length must match the reference's 1864 bytes.");
        Assert.IsTrue(proof.AsSpan().SequenceEqual(expected), "The full proof envelope must be byte-identical to the reference.");
    }


    [TestMethod]
    public void TheSegmentBoundariesMatchTheReference()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] witnessColumn = BuildWitnessColumn(circuit);

        byte[] proof = ProduceProof(circuit, witnessColumn, TranscriptSeed);

        int comLen = int.Parse(Anchors["seg_com_len"], CultureInfo.InvariantCulture);
        int scLen = int.Parse(Anchors["seg_sc_len"], CultureInfo.InvariantCulture);

        Assert.AreEqual(DigestSize, comLen, "The com segment is the 32-byte root.");
        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        Assert.AreEqual(scLen, LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile), "The sc segment length must match the reference.");

        //The root segment equals the anchor's com_root.
        byte[] expectedRoot = Convert.FromHexString(Anchors["com_root"]);
        Assert.IsTrue(proof.AsSpan(0, DigestSize).SequenceEqual(expectedRoot), "The commitment root must match the reference's com_root.");
    }


    [TestMethod]
    public void OurVerifierAcceptsOurProof()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] witnessColumn = BuildWitnessColumn(circuit);

        byte[] proof = ProduceProof(circuit, witnessColumn, TranscriptSeed);

        AssertVerifies(circuit, proof, PublicInputBytes(circuit, witnessColumn), expectedAccept: true);
    }


    [TestMethod]
    public void ADifferentSatisfyingWitnessProducesADifferentButValidProof()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] baselineColumn = BuildWitnessColumn(circuit);
        byte[] baselineProof = ProduceProof(circuit, baselineColumn, TranscriptSeed);

        //A different satisfying witness: x = of_scalar(9) (public), y = 2, z = 4, w = (x+y)(x+z)x.
        byte[] alternativeColumn = BuildSatisfyingColumn(circuit, 9, 2, 4);
        byte[] alternativeProof = ProduceProof(circuit, alternativeColumn, TranscriptSeed);

        Assert.IsFalse(alternativeProof.AsSpan().SequenceEqual(baselineProof), "A different witness must change the proof.");
        AssertVerifies(circuit, alternativeProof, PublicInputBytes(circuit, alternativeColumn), expectedAccept: true);
    }


    [TestMethod]
    public void AnUnsatisfyingWitnessIsUnprovable()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();

        //Break the relation: keep x/y/z but set w to a wrong value so w != (x+y)(x+z)x.
        byte[] column = BuildWitnessColumn(circuit);
        column[(4 * ScalarSize) + ScalarSize - 1] ^= 0x01;

        Assert.ThrowsExactly<InvalidOperationException>(() => ProduceProof(circuit, column, TranscriptSeed));
    }


    [TestMethod]
    public void ADifferentSeedProducesADifferentButValidProof()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] witnessColumn = BuildWitnessColumn(circuit);

        byte[] baselineProof = ProduceProof(circuit, witnessColumn, TranscriptSeed);
        byte[] alternativeProof = ProduceProof(circuit, witnessColumn, Encoding.ASCII.GetBytes("zk9"));

        Assert.IsFalse(alternativeProof.AsSpan().SequenceEqual(baselineProof), "A different seed must change the proof.");
        AssertVerifies(circuit, alternativeProof, PublicInputBytes(circuit, witnessColumn), expectedAccept: true, alternativeSeed: Encoding.ASCII.GetBytes("zk9"));
    }


    //Runs the full prover over the witness column and the seed, returning the serialized envelope.
    private static byte[] ProduceProof(LongfellowSumcheckCircuit circuit, byte[] witnessColumn, byte[] seed)
    {
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, FieldBytes, Production16SubFieldBytes);

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowTranscript transcript = NewTranscript(seed);
        LongfellowRandomByteSource random = NewCounterSource();

        return LongfellowZkProver.Prove(
            circuit,
            parameters,
            witnessColumn,
            Production16SubFieldBytes,
            SubfieldBoundary,
            random,
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
            BaseMemoryPool.Shared);
    }


    private static void AssertVerifies(LongfellowSumcheckCircuit circuit, byte[] proof, byte[] publicInputs, bool expectedAccept, byte[]? alternativeSeed = null)
    {
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, FieldBytes, Production16SubFieldBytes);

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowTranscript transcript = NewTranscript(alternativeSeed ?? TranscriptSeed);

        bool accepted = LongfellowZkVerifier.Verify(
            circuit,
            parameters,
            proof,
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


    //The full witness column (all ninputs) as canonical scalars, from the anchor's input0..input(n-1).
    private static byte[] BuildWitnessColumn(LongfellowSumcheckCircuit circuit)
    {
        byte[] column = new byte[circuit.InputCount * ScalarSize];
        for(int i = 0; i < circuit.InputCount; i++)
        {
            byte[] element = ParseElement(Anchors[$"input{i}"]);
            element.CopyTo(column.AsSpan(i * ScalarSize, ScalarSize));
        }

        return column;
    }


    //Builds a satisfying witness column [one, x, y, z, w] from the small-integer field values, where
    //x/y/z are of_scalar(...) (the LCH14 subfield basis) and w = (x+y)·(x+z)·x. The constant-one wire is
    //the field one.
    private static byte[] BuildSatisfyingColumn(LongfellowSumcheckCircuit circuit, uint x, uint y, uint z)
    {
        using Lch14AdditiveFft fft = NewFft();

        byte[] column = new byte[circuit.InputCount * ScalarSize];

        Span<byte> one = column.AsSpan(0, ScalarSize);
        one.Clear();
        one[ScalarSize - 1] = 0x01;

        OfScalar(fft, x, column.AsSpan(ScalarSize, ScalarSize));
        OfScalar(fft, y, column.AsSpan(2 * ScalarSize, ScalarSize));
        OfScalar(fft, z, column.AsSpan(3 * ScalarSize, ScalarSize));

        //w = (x + y)·(x + z)·x.
        Span<byte> xPlusY = stackalloc byte[ScalarSize];
        Span<byte> xPlusZ = stackalloc byte[ScalarSize];
        Add(column.AsSpan(ScalarSize, ScalarSize), column.AsSpan(2 * ScalarSize, ScalarSize), xPlusY, CurveParameterSet.None);
        Add(column.AsSpan(ScalarSize, ScalarSize), column.AsSpan(3 * ScalarSize, ScalarSize), xPlusZ, CurveParameterSet.None);

        Span<byte> w = column.AsSpan(4 * ScalarSize, ScalarSize);
        Multiply(xPlusY, xPlusZ, w, CurveParameterSet.None);
        Multiply(w, column.AsSpan(ScalarSize, ScalarSize), w, CurveParameterSet.None);

        return column;
    }


    //of_scalar(u): the GF(2^128) element Σ_bit beta_[bit], the subfield basis combination the reference
    //of_scalar computes. beta_[k] = NodeElement basis; the FFT's BasisElement(k) is beta_[k].
    private static void OfScalar(Lch14AdditiveFft fft, uint value, Span<byte> destination)
    {
        destination.Clear();
        Span<byte> accumulator = stackalloc byte[ScalarSize];
        accumulator.Clear();

        int bit = 0;
        uint remaining = value;
        while(remaining != 0)
        {
            if((remaining & 1) != 0)
            {
                Add(accumulator, fft.BasisElement(bit), accumulator, CurveParameterSet.None);
            }

            remaining >>= 1;
            bit++;
        }

        accumulator.CopyTo(destination);
    }


    //The public input element bytes (little-endian to_bytes_field): the first npub_in witness elements.
    private static byte[] PublicInputBytes(LongfellowSumcheckCircuit circuit, byte[] witnessColumn)
    {
        byte[] publicInputs = new byte[circuit.PublicInputCount * ElementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            ToBytesField(witnessColumn.AsSpan(i * ScalarSize, ScalarSize), publicInputs.AsSpan(i * ElementBytes, ElementBytes));
        }

        return publicInputs;
    }


    //A fresh deterministic counter source: the k-th byte produced is (k & 0xFF), identical to the C++
    //oracle's CounterRandomEngine. Each call returns a new source so a test restarts the stream at 0.
    private static LongfellowRandomByteSource NewCounterSource()
    {
        ulong counter = 0;

        return destination =>
        {
            for(int i = 0; i < destination.Length; i++)
            {
                destination[i] = (byte)(counter & 0xFF);
                counter++;
            }
        };
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


    //to_bytes_field: the low 16 big-endian bytes of a canonical scalar reverse into 16 little-endian bytes.
    private static void ToBytesField(ReadOnlySpan<byte> canonical, Span<byte> littleEndian)
    {
        for(int i = 0; i < ElementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }


    private static int Anchor(string key) => int.Parse(Anchors[key], CultureInfo.InvariantCulture);


    private static LongfellowTranscript NewTranscript(byte[] seed) =>
        new(seed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


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

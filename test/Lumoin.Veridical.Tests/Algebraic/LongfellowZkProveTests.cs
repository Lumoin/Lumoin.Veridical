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
/// The wire-format-conformant END-TO-END ZK PROVER, gated as a faithful port of
/// google/longfellow-zk's <c>ZkProver</c> (<c>lib/zk/zk_prover.h</c>): commit a sumcheck witness and a
/// random pad encrypting the sumcheck transcript, run the sumcheck emitting the padded transcript, then
/// prove with Ligero that the committed witness and pad satisfy the sumcheck verifier — producing a
/// complete <c>ZkProof</c> envelope (<c>com ‖ sc ‖ com_proof</c>) byte-identical to the reference's.
/// </summary>
/// <remarks>
/// <para>
/// The zk anchor (zk-anchor-output.txt in TestMaterial/Longfellow) records google/longfellow-zk's
/// ZkProver output for a small GF2_128&lt;4&gt; circuit (the field-satisfiable relation
/// <c>w == (x + y)·(x + z)·x</c>, logc = 0, nl = 3): the complete ZkProof envelope for that circuit
/// under the fixed FS seed "zk8" and the counter random engine (the k-th byte = k &amp; 0xFF), together
/// with the reference verifier's own acceptance of that envelope. The fixed witnesses are
/// x = of_scalar(3) (public), y = of_scalar(5), z = of_scalar(7), w = the field product (private);
/// W[0] is the constant-one wire.
/// </para>
/// <para>
/// The gates:
/// </para>
/// <list type="bullet">
///   <item><description><b>Byte identity</b>: our prover's complete ZkProof envelope equals the reference's 1864 proof bytes, segment for segment (the commitment root, the sumcheck segment, the Ligero proof).</description></item>
///   <item><description><b>Self-verify</b>: our end-to-end verifier accepts our prover's proof.</description></item>
///   <item><description><b>Witness dual</b>: a different satisfying witness produces a different but still-accepted proof; an unsatisfying witness is unprovable (the circuit output is non-zero).</description></item>
///   <item><description><b>Seed dual</b>: a different Fiat–Shamir seed produces a different but still-accepted proof.</description></item>
/// </list>
/// <para>
/// The reverse gate — that the reference's own verifier accepts our proof bytes — follows from byte
/// identity: our envelope equals the reference's, so the anchor's <c>ref_zk_verify</c> field already
/// records the reference's accept over those same bytes.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowZkProveTests: IDisposable
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


    /// <summary>The path, relative to the test project directory, to the GF(2^128) end-to-end ZK anchor this test cross-checks against.</summary>
    private const string ZkAnchorRelativePath = "TestMaterial/Longfellow/zk-anchor-output.txt";

    /// <summary>The on-wire element width, in bytes, for the GF(2^128) field.</summary>
    private const int ElementBytes = 16;

    /// <summary>The canonical scalar width in bytes.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The SHA-256 digest width in bytes, matching the commitment root size.</summary>
    private const int DigestSize = 32;

    /// <summary>The transcript wire-format version (6, the deployed mdoc flow's value) the prover and verifier must agree on to derive the identical challenge stream.</summary>
    private const int TranscriptVersion = 6;

    /// <summary>The GF(2^128) field element width in bytes.</summary>
    private const int FieldBytes = 16;

    /// <summary>The GF(2^128) subfield element width in bytes that the LCH14 production-16 additive-FFT engine operates over.</summary>
    private const int Production16SubFieldBytes = 2;

    /// <summary>The Ligero code's inverse rate this test fixes for the anchor circuit's Ligero parameters.</summary>
    private const int InverseRate = 4;

    /// <summary>The number of Ligero columns opened per proof for the anchor circuit's Ligero parameters.</summary>
    private const int OpenedColumnCount = 2;

    /// <summary>The anchor's <c>subfield_boundary</c>, rebased to start at the public-input count; zero because zero is already below <c>npub_in</c>, so rebasing leaves it at zero.</summary>
    private const int SubfieldBoundary = 0;

    /// <summary>The Fiat–Shamir transcript seed matching the anchor's recorded values.</summary>
    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("zk8");

    /// <summary>The GF(2^128) addition delegate (XOR).</summary>
    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) subtraction delegate (coincides with addition).</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) multiplication delegate.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) inversion delegate.</summary>
    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>The parsed key/value map loaded from the GF(2^128) end-to-end ZK anchor.</summary>
    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(ZkAnchorRelativePath);


    /// <summary>Verifies that our prover's complete <c>ZkProof</c> envelope is byte-identical to the reference's proof bytes.</summary>
    [TestMethod]
    public void TheProofEnvelopeMatchesTheReferenceByteForByte()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] witnessColumn = BuildWitnessColumn(circuit);

        using LongfellowZkProofEnvelope proof = ProduceProof(circuit, witnessColumn, TranscriptSeed);

        byte[] expected = Convert.FromHexString(Anchors["proof_bytes"]);

        Assert.AreEqual(expected.Length, proof.Length, "The proof length must match the reference's 1864 bytes.");
        Assert.IsTrue(proof.Bytes.SequenceEqual(expected), "The full proof envelope must be byte-identical to the reference.");
    }


    /// <summary>Verifies that the commitment-root and sumcheck-segment lengths, and the commitment root's bytes, match the reference's anchor values.</summary>
    [TestMethod]
    public void TheSegmentBoundariesMatchTheReference()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] witnessColumn = BuildWitnessColumn(circuit);

        using LongfellowZkProofEnvelope proof = ProduceProof(circuit, witnessColumn, TranscriptSeed);

        int comLen = int.Parse(Anchors["seg_com_len"], CultureInfo.InvariantCulture);
        int scLen = int.Parse(Anchors["seg_sc_len"], CultureInfo.InvariantCulture);

        Assert.AreEqual(DigestSize, comLen, "The com segment is the 32-byte root.");
        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        Assert.AreEqual(scLen, LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile), "The sc segment length must match the reference.");

        //The root segment equals the anchor's com_root.
        byte[] expectedRoot = Convert.FromHexString(Anchors["com_root"]);
        Assert.IsTrue(proof.Bytes[..DigestSize].SequenceEqual(expectedRoot), "The commitment root must match the reference's com_root.");
    }


    /// <summary>Verifies that our verifier accepts our prover's proof for the anchor circuit and witness.</summary>
    [TestMethod]
    public void OurVerifierAcceptsOurProof()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] witnessColumn = BuildWitnessColumn(circuit);

        using LongfellowZkProofEnvelope proof = ProduceProof(circuit, witnessColumn, TranscriptSeed);

        AssertVerifies(circuit, proof.Bytes, PublicInputBytes(circuit, witnessColumn), expectedAccept: true);
    }


    /// <summary>Verifies that a different satisfying witness produces a different proof, and that the different proof still verifies.</summary>
    [TestMethod]
    public void ADifferentSatisfyingWitnessProducesADifferentButValidProof()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] baselineColumn = BuildWitnessColumn(circuit);
        using LongfellowZkProofEnvelope baselineProof = ProduceProof(circuit, baselineColumn, TranscriptSeed);

        //A different satisfying witness: x = of_scalar(9) (public), y = 2, z = 4, w = (x+y)(x+z)x.
        byte[] alternativeColumn = BuildSatisfyingColumn(circuit, 9, 2, 4);
        using LongfellowZkProofEnvelope alternativeProof = ProduceProof(circuit, alternativeColumn, TranscriptSeed);

        Assert.IsFalse(alternativeProof.Bytes.SequenceEqual(baselineProof.Bytes), "A different witness must change the proof.");
        AssertVerifies(circuit, alternativeProof.Bytes, PublicInputBytes(circuit, alternativeColumn), expectedAccept: true);
    }


    /// <summary>Verifies that proving a witness column that does not satisfy the circuit relation throws <see cref="InvalidOperationException"/>.</summary>
    [TestMethod]
    public void AnUnsatisfyingWitnessIsUnprovable()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();

        //Break the relation: keep x/y/z but set w to a wrong value so w != (x+y)(x+z)x.
        byte[] column = BuildWitnessColumn(circuit);
        column[(4 * ScalarSize) + ScalarSize - 1] ^= 0x01;

        Assert.ThrowsExactly<InvalidOperationException>(() => ProduceProof(circuit, column, TranscriptSeed));
    }


    /// <summary>Verifies that a different Fiat–Shamir seed produces a different proof, and that the different proof still verifies under that seed.</summary>
    [TestMethod]
    public void ADifferentSeedProducesADifferentButValidProof()
    {
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        byte[] witnessColumn = BuildWitnessColumn(circuit);

        using LongfellowZkProofEnvelope baselineProof = ProduceProof(circuit, witnessColumn, TranscriptSeed);
        using LongfellowZkProofEnvelope alternativeProof = ProduceProof(circuit, witnessColumn, Encoding.ASCII.GetBytes("zk9"));

        Assert.IsFalse(alternativeProof.Bytes.SequenceEqual(baselineProof.Bytes), "A different seed must change the proof.");
        AssertVerifies(circuit, alternativeProof.Bytes, PublicInputBytes(circuit, witnessColumn), expectedAccept: true, alternativeSeed: Encoding.ASCII.GetBytes("zk9"));
    }


    /// <summary>Runs the full prover over the witness column and the seed.</summary>
    /// <param name="circuit">The circuit to prove.</param>
    /// <param name="witnessColumn">The full canonical-scalar witness column.</param>
    /// <param name="seed">The transcript seed.</param>
    /// <returns>The pooled proof envelope; the caller disposes it.</returns>
    private static LongfellowZkProofEnvelope ProduceProof(LongfellowSumcheckCircuit circuit, byte[] witnessColumn, byte[] seed)
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


    /// <summary>Verifies <paramref name="proof"/> and asserts the acceptance verdict matches <paramref name="expectedAccept"/>.</summary>
    /// <param name="circuit">The circuit the proof was produced for.</param>
    /// <param name="proof">The candidate proof bytes.</param>
    /// <param name="publicInputs">The public input bytes.</param>
    /// <param name="expectedAccept">The expected verification verdict.</param>
    /// <param name="alternativeSeed">The transcript seed, when different from <see cref="TranscriptSeed"/>.</param>
    private static void AssertVerifies(LongfellowSumcheckCircuit circuit, ReadOnlySpan<byte> proof, byte[] publicInputs, bool expectedAccept, byte[]? alternativeSeed = null)
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


    /// <summary>Reconstructs the circuit shape with its per-layer Quad terms from the anchor's recorded parameters, with circuit owners released at test cleanup.</summary>
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


    /// <summary>Builds the full witness column (all <c>ninputs</c>) as canonical scalars, from the anchor's <c>input0..input(n-1)</c> values.</summary>
    /// <param name="circuit">The circuit whose <see cref="LongfellowSumcheckCircuit.InputCount"/> sizes the column.</param>
    /// <returns>The canonical-scalar witness column.</returns>
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


    /// <summary>
    /// Builds a satisfying witness column <c>[one, x, y, z, w]</c> from the small-integer field values,
    /// where <c>x</c>/<c>y</c>/<c>z</c> are <c>of_scalar(...)</c> (the LCH14 subfield basis) and
    /// <c>w = (x+y)·(x+z)·x</c>. The constant-one wire is the field one.
    /// </summary>
    /// <param name="circuit">The circuit whose <see cref="LongfellowSumcheckCircuit.InputCount"/> sizes the column.</param>
    /// <param name="x">The public witness value.</param>
    /// <param name="y">A private witness value.</param>
    /// <param name="z">A private witness value.</param>
    /// <returns>The canonical-scalar witness column.</returns>
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


    /// <summary>
    /// Computes <c>of_scalar(u)</c>: the GF(2^128) element <c>Σ_bit beta_[bit]</c>, the subfield basis
    /// combination the reference <c>of_scalar</c> computes. <c>beta_[k]</c> is the basis element the
    /// FFT's <see cref="Lch14AdditiveFft.BasisElement"/> returns for <c>k</c>.
    /// </summary>
    /// <param name="fft">The additive-FFT engine supplying the subfield basis.</param>
    /// <param name="value">The integer to encode.</param>
    /// <param name="destination">Receives the canonical big-endian scalar.</param>
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


    /// <summary>Produces the public-input element bytes (little-endian <c>to_bytes_field</c>): the first <c>npub_in</c> witness elements.</summary>
    /// <param name="circuit">The circuit whose <see cref="LongfellowSumcheckCircuit.PublicInputCount"/> bounds the slice.</param>
    /// <param name="witnessColumn">The full canonical-scalar witness column.</param>
    /// <returns>The public inputs, little-endian and element-width framed.</returns>
    private static byte[] PublicInputBytes(LongfellowSumcheckCircuit circuit, byte[] witnessColumn)
    {
        byte[] publicInputs = new byte[circuit.PublicInputCount * ElementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            ToBytesField(witnessColumn.AsSpan(i * ScalarSize, ScalarSize), publicInputs.AsSpan(i * ElementBytes, ElementBytes));
        }

        return publicInputs;
    }


    /// <summary>
    /// Creates a fresh deterministic counter source: the k-th byte produced is <c>k &amp; 0xFF</c>,
    /// identical to the C++ oracle's <c>CounterRandomEngine</c>. Each call returns a new source so a
    /// test restarts the stream at zero.
    /// </summary>
    /// <returns>A deterministic counter-based random byte source.</returns>
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


    /// <summary>Computes <c>to_bytes_field</c>: the low 16 big-endian bytes of a canonical scalar reversed into 16 little-endian bytes.</summary>
    /// <param name="canonical">The canonical big-endian scalar.</param>
    /// <param name="littleEndian">Receives the little-endian element bytes.</param>
    private static void ToBytesField(ReadOnlySpan<byte> canonical, Span<byte> littleEndian)
    {
        for(int i = 0; i < ElementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }


    /// <summary>Parses the anchor's <paramref name="key"/> value as a base-10 integer.</summary>
    /// <param name="key">The anchor key to look up.</param>
    /// <returns>The parsed integer value.</returns>
    private static int Anchor(string key) => int.Parse(Anchors[key], CultureInfo.InvariantCulture);


    /// <summary>Creates a transcript seeded and sized the way the reference seeds the prover's.</summary>
    /// <param name="seed">The transcript seed bytes.</param>
    /// <returns>The new transcript.</returns>
    private static LongfellowTranscript NewTranscript(byte[] seed) =>
        new(seed, TranscriptVersion, 16, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Creates the LCH14 additive-FFT engine over the GF(2^128) production subfield.</summary>
    /// <returns>The new additive-FFT engine.</returns>
    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>Computes a one-shot SHA-256 digest of <paramref name="input"/>; <paramref name="hashFunction"/> is accepted for signature compatibility and unused, since this delegate is always bound to SHA-256.</summary>
    /// <param name="input">The bytes to hash.</param>
    /// <param name="output">Receives the 32-byte digest.</param>
    /// <param name="hashFunction">The requested hash algorithm name; ignored.</param>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        SHA256.HashData(input, output);
    }


    /// <summary>Computes the two-to-one Merkle compression <c>SHA256(left ‖ right)</c>.</summary>
    /// <param name="left">The left digest.</param>
    /// <param name="right">The right digest.</param>
    /// <param name="output">Receives the combined digest.</param>
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[left.Length + right.Length];
        left.CopyTo(combined);
        right.CopyTo(combined[left.Length..]);
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


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
    /// Loads the anchor file at <paramref name="relativePath"/> (resolved from the test binary's output
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
}

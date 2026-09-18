using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using static Lumoin.Veridical.Tests.Algebraic.LongfellowKernelZkTestHarness;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The self-consistent Fp256 end-to-end ZK PROVE + VERIFY gate (the field-generic
/// prover seam). It exercises the FULL prover+verifier over the 32-byte P-256 base field through the
/// field-generic <c>LongfellowZkProver.Prove</c>
/// entry (the prime-field analogue of the GF(2^128) convenience overload), then verifies the produced
/// envelope with <see cref="LongfellowZkVerifier.VerifyFromAbsorbedRoot"/>.
/// </summary>
/// <remarks>
/// <para>
/// This gate does not check byte-for-byte conformance against reference-computed values. It instead
/// proves the two halves are mutually consistent: OUR prover's Fp256 proof verifies in OUR verifier
/// over the 32-byte field, and any tamper (a flipped proof byte or a flipped public input) is rejected.
/// </para>
/// <para>
/// The circuit is the same small field-satisfiable relation the GF(2^128) anchor compiles
/// (<c>w == (x + y)·(x + z)·x</c>, <c>logc = 0</c>, <c>nl = 3</c>, per-layer <c>logw</c> of 2/3/3): the
/// Quad wiring (<c>g</c>/<c>h0</c>/<c>h1</c>/<c>v</c>) is shared because every coefficient <c>v</c> is the
/// field ONE, valid in both fields, and the gate indices are field-independent. Only the witness changes:
/// over Fp256 the satisfying column is <c>[1, x, y, z, w]</c> with <c>x</c> public, <c>y</c>/<c>z</c>/<c>w</c>
/// private and <c>w = (x + y)·(x + z)·x</c> computed with the P-256 base-field delegates. The arithmetic
/// uses <see cref="P256BaseFieldReference"/> (the BigInteger-backed base field); the pad/commit random
/// source draws below <c>p</c> (the established <c>NewBelowModulusSource</c> pattern) so every
/// <c>of_bytes_field</c> draw is accepted, and the transcript is baked at the 32-byte Fp256 width so the
/// prover and the verifier derive the identical challenge stream.
/// </para>
/// <para>
/// A companion GF(2^128) gate proves the existing hash circuit through the same field-generic entry
/// (with the GF encoding/codec built from the additive-FFT engine) and confirms the envelope is
/// byte-identical to the GF convenience <c>Prove</c>, so the field-generic entry and the convenience
/// overload are interchangeable for the GF(2^128) circuit's wire envelope.
/// </para>
/// <para>
/// The Fp256 base field is BigInteger-backed and slow; the prove+verify is marked
/// <see cref="TestCategoryAttribute"/> <c>Slow</c> (it runs in low single-digit seconds) and
/// is gated out of the default suite. The GF byte-identity check below it is fast and stays in the default
/// suite.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowFp256ZkProveTests: IDisposable
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


    /// <summary>The path, relative to the test project directory, to the GF(2^128) end-to-end ZK anchor file this test cross-checks against.</summary>
    private const string ZkAnchorRelativePath = "TestMaterial/Longfellow/zk-anchor-output.txt";

    /// <summary>The canonical scalar width in bytes, shared by both fields' witness columns.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The on-wire element width, in bytes, for the P-256 base field.</summary>
    private const int Fp256ElementBytes = 32;

    /// <summary>The on-wire element width, in bytes, for the GF(2^128) field.</summary>
    private const int GfElementBytes = 16;

    /// <summary>The SHA-256 digest width in bytes, matching the commitment root size in both proof envelopes.</summary>
    private const int DigestSize = 32;

    /// <summary>The transcript wire-format version (6, the deployed mdoc flow's value) the prover and verifier must agree on to derive the identical challenge stream.</summary>
    private const int TranscriptVersion = 6;

    /// <summary>The Ligero code's inverse rate, fixed the same for both the GF and the Fp256 gates so the two proofs are structurally comparable.</summary>
    private const int InverseRate = 4;

    /// <summary>The number of Ligero columns opened per proof, fixed the same for both the GF and the Fp256 gates.</summary>
    private const int OpenedColumnCount = 2;

    /// <summary>The GF(2^128) field element width in bytes, for the binary hash circuit.</summary>
    private const int GfFieldBytes = 16;

    /// <summary>The GF(2^128) subfield element width in bytes that the additive-FFT engine operates over.</summary>
    private const int GfSubFieldBytes = 2;

    /// <summary>The subfield-run boundary (rebased to start at the public-input count) this test's circuit passes to the GF(2^128) entries; zero, so no witness row falls below it.</summary>
    private const int GfSubfieldBoundary = 0;

    /// <summary>The transcript seed for the Fp256 end-to-end gates.</summary>
    private static byte[] Fp256TranscriptSeed { get; } = Encoding.ASCII.GetBytes("fp256-zk-e2e");

    /// <summary>The transcript seed for the GF(2^128) field-generic-vs-convenience byte-identity gate.</summary>
    private static byte[] GfTranscriptSeed { get; } = Encoding.ASCII.GetBytes("zk8");

    /// <summary>The P-256 base field's prime modulus.</summary>
    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    /// <summary>The P-256 base field addition delegate.</summary>
    private static ScalarAddDelegate Fp256Add { get; } = P256BaseFieldReference.GetAdd();

    /// <summary>The P-256 base field subtraction delegate.</summary>
    private static ScalarSubtractDelegate Fp256Subtract { get; } = P256BaseFieldReference.GetSubtract();

    /// <summary>The P-256 base field multiplication delegate.</summary>
    private static ScalarMultiplyDelegate Fp256Multiply { get; } = P256BaseFieldReference.GetMultiply();

    /// <summary>The P-256 base field inversion delegate.</summary>
    private static ScalarInvertDelegate Fp256Invert { get; } = P256BaseFieldReference.GetInvert();

    /// <summary>The GF(2^128) addition delegate (XOR).</summary>
    private static ScalarAddDelegate GfAdd { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) subtraction delegate (coincides with addition).</summary>
    private static ScalarSubtractDelegate GfSubtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) multiplication delegate.</summary>
    private static ScalarMultiplyDelegate GfMultiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) inversion delegate.</summary>
    private static ScalarInvertDelegate GfInvert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>The parsed key/value map loaded from the GF(2^128) end-to-end ZK anchor file.</summary>
    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(ZkAnchorRelativePath);


    /// <summary>Verifies that a genuine Fp256 witness proves through the field-generic prover and is accepted by the field-generic verifier over the 32-byte P-256 base field.</summary>
    [TestMethod]
    public void OurVerifierAcceptsOurFp256Proof()
    {
        //The small nl = 3 relation proves and verifies in well under a second even on the BigInteger-backed
        //P-256 base field, so this end-to-end Fp256 gate stays in the default suite (real-credential-scale
        //Fp256 proves are the Slow gates).
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Fp256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes);

        byte[] witnessColumn = BuildSatisfyingColumn(3, 5, 7);
        using LongfellowZkProofEnvelope proof = ProveFp256(circuit, parameters, witnessColumn, Fp256TranscriptSeed);

        byte[] publicInputs = PublicInputBytes(circuit, witnessColumn);

        AssertFp256Verifies(circuit, parameters, proof.Bytes, publicInputs, Fp256TranscriptSeed, expectedAccept: true);
    }


    /// <summary>Verifies that flipping a byte inside the sumcheck segment of a valid Fp256 proof, or flipping a byte of the public inputs, makes verification fail.</summary>
    [TestMethod]
    public void ATamperedFp256ProofIsRejected()
    {
        //Same small relation; stays in the default suite (sub-second).
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Fp256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes);

        byte[] witnessColumn = BuildSatisfyingColumn(3, 5, 7);
        using LongfellowZkProofEnvelope proof = ProveFp256(circuit, parameters, witnessColumn, Fp256TranscriptSeed);
        byte[] publicInputs = PublicInputBytes(circuit, witnessColumn);

        //A flipped byte inside the sumcheck segment (after the 32-byte root) breaks the replay: the derived
        //challenge stream and the constraint coefficients diverge and the Ligero opening no longer matches.
        using IMemoryOwner<byte> tamperedProofOwner = BaseMemoryPool.Shared.Rent(proof.Length);
        Span<byte> tamperedProof = tamperedProofOwner.Memory.Span[..proof.Length];
        proof.Bytes.CopyTo(tamperedProof);
        tamperedProof[DigestSize + 8] ^= 0x01;
        AssertFp256Verifies(circuit, parameters, tamperedProof, publicInputs, Fp256TranscriptSeed, expectedAccept: false);

        //A flipped public input moves the FS setup and the input-binding constraint, so verification fails.
        byte[] tamperedPublic = (byte[])publicInputs.Clone();
        tamperedPublic[Fp256ElementBytes + 1] ^= 0x01;
        AssertFp256Verifies(circuit, parameters, proof.Bytes, tamperedPublic, Fp256TranscriptSeed, expectedAccept: false);
    }


    /// <summary>Verifies that proving the GF(2^128) hash circuit through the field-generic entry produces the byte-identical envelope the GF convenience <c>Prove</c> overload produces, and that both match the reference's pinned proof bytes.</summary>
    [TestMethod]
    public void TheFieldGenericEntryReproducesTheGfConvenienceBytes()
    {
        //Proving the GF(2^128) hash circuit through the field-generic entry (with the GF encoding,
        //row-encoder factory and subfield-run codec built from the additive-FFT engine) must produce the
        //byte-identical envelope the GF convenience Prove produces. Fast; stays in the default suite.
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, GfFieldBytes, GfSubFieldBytes);

        byte[] witnessColumn = BuildGfWitnessColumn(circuit);

        using LongfellowZkProofEnvelope viaConvenience = ProveGfConvenience(circuit, parameters, witnessColumn, GfTranscriptSeed);
        using LongfellowZkProofEnvelope viaFieldGeneric = ProveGfFieldGeneric(circuit, parameters, witnessColumn, GfTranscriptSeed);

        Assert.IsTrue(viaFieldGeneric.Bytes.SequenceEqual(viaConvenience.Bytes), "The field-generic entry must produce the byte-identical GF envelope the convenience overload produces.");

        //Cross-check against the reference's pinned bytes so the GF path is anchored, not just self-equal.
        byte[] expected = Convert.FromHexString(Anchors["proof_bytes"]);
        Assert.IsTrue(viaFieldGeneric.Bytes.SequenceEqual(expected), "The field-generic GF envelope must equal the reference's pinned proof bytes.");
    }


    /// <summary>
    /// Proves a satisfying Fp256 witness column through the field-generic prover with the Fp256 encoding,
    /// retaining the FFT through every encoder callback.
    /// </summary>
    /// <returns>The pooled proof envelope; the caller disposes it.</returns>
    private static LongfellowZkProofEnvelope ProveFp256(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] witnessColumn, byte[] seed)
    {
        using BaseMemoryPool fftPool = new();
        using Fp256RealFft fft = NewFp256Fft(fftPool);
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
        using LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalarFp256, InRangeFp256, BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp256(profile);

        using LongfellowTranscript transcript = NewTranscript(seed, Fp256ElementBytes);
        LongfellowRandomByteSource random = NewBelowModulusSource();

        return LongfellowZkProver.Prove(
            circuit,
            parameters,
            witnessColumn,
            LongfellowFp256Encoding.SignatureSubfieldBoundary,
            random,
            transcript,
            encoderFactory,
            profile,
            codec,
            Fp256Add,
            Fp256Subtract,
            Fp256Multiply,
            Fp256Invert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Proves the GF circuit through the GF convenience <c>Prove</c> overload, the byte baseline the
    /// field-generic entry's output is checked against.
    /// </summary>
    /// <returns>The pooled proof envelope; the caller disposes it.</returns>
    private static LongfellowZkProofEnvelope ProveGfConvenience(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] witnessColumn, byte[] seed)
    {
        using Lch14AdditiveFft fft = NewGfFft();
        using LongfellowTranscript transcript = NewTranscript(seed, GfElementBytes);
        LongfellowRandomByteSource random = NewCounterSource();

        return LongfellowZkProver.Prove(
            circuit,
            parameters,
            witnessColumn,
            GfSubFieldBytes,
            GfSubfieldBoundary,
            random,
            transcript,
            fft,
            GfAdd,
            GfSubtract,
            GfMultiply,
            GfInvert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Proves the GF circuit through the field-generic <c>Prove</c>, building the GF encoding/codec from
    /// the FFT exactly as the convenience overload does internally.
    /// </summary>
    /// <returns>The pooled proof envelope; the caller disposes it.</returns>
    private static LongfellowZkProofEnvelope ProveGfFieldGeneric(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] witnessColumn, byte[] seed)
    {
        using Lch14AdditiveFft fft = NewGfFft();
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForGf2k128(profile, fft, GfSubFieldBytes, BaseMemoryPool.Shared);

        using LongfellowTranscript transcript = NewTranscript(seed, GfElementBytes);
        LongfellowRandomByteSource random = NewCounterSource();

        return LongfellowZkProver.Prove(
            circuit,
            parameters,
            witnessColumn,
            GfSubfieldBoundary,
            random,
            transcript,
            encoderFactory,
            profile,
            codec,
            GfAdd,
            GfSubtract,
            GfMultiply,
            GfInvert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Reconstructs the circuit shape with its per-layer Quad terms from the anchor's parameters.
    /// The wiring is shared between GF and Fp256 because every coefficient <c>v</c> is the field ONE
    /// (01000...), the same canonical value in both fields, and the gate indices are field-independent.
    /// Circuit owners are released at test cleanup.
    /// </summary>
    /// <returns>The reconstructed circuit, owned by this test's circuit scope.</returns>
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
                byte[] v = ParseCoefficient(Anchors[$"L{i}_t{t}_v"]);
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


    /// <summary>
    /// Builds the GF witness column (all <c>ninputs</c>) as canonical scalars, from the anchor's
    /// <c>input0..input(n-1)</c> values: the reference's fixed satisfying column for the GF byte-identity
    /// check.
    /// </summary>
    /// <param name="circuit">The circuit whose <see cref="LongfellowSumcheckCircuit.InputCount"/> sizes the column.</param>
    /// <returns>The canonical-scalar witness column, one element per input wire.</returns>
    private static byte[] BuildGfWitnessColumn(LongfellowSumcheckCircuit circuit)
    {
        byte[] column = new byte[circuit.InputCount * ScalarSize];
        for(int i = 0; i < circuit.InputCount; i++)
        {
            byte[] element = ParseGfElement(Anchors[$"input{i}"]);
            element.CopyTo(column.AsSpan(i * ScalarSize, ScalarSize));
        }

        return column;
    }


    /// <summary>
    /// Builds a satisfying Fp256 witness column <c>[one, x, y, z, w]</c> for the anchor's three-layer
    /// wiring. Tracing the gates (every coefficient <c>v</c> is one), the circuit output is
    /// <c>out[0] = w + x·(x + y)·(x + z)</c>, so the assert-zero relation requires
    /// <c>w = −x·(x + y)·(x + z) mod p</c>. Over GF(2^128) negation is the identity, so the same column
    /// degenerates to the GF gate's <c>w = x·(x + y)·(x + z)</c>; over Fp256 the negation is genuine.
    /// <c>x</c> is public, <c>y</c>/<c>z</c>/<c>w</c> private; the constant-one wire is the field one.
    /// </summary>
    /// <param name="x">The public witness value.</param>
    /// <param name="y">A private witness value.</param>
    /// <param name="z">A private witness value.</param>
    /// <returns>The five-element canonical-scalar witness column <c>[1, x, y, z, w]</c>.</returns>
    private static byte[] BuildSatisfyingColumn(uint x, uint y, uint z)
    {
        byte[] column = new byte[5 * ScalarSize];

        Span<byte> one = column.AsSpan(0, ScalarSize);
        one.Clear();
        one[ScalarSize - 1] = 0x01;

        OfScalarFp256(x, column.AsSpan(ScalarSize, ScalarSize));
        OfScalarFp256(y, column.AsSpan(2 * ScalarSize, ScalarSize));
        OfScalarFp256(z, column.AsSpan(3 * ScalarSize, ScalarSize));

        //product = x·(x + y)·(x + z) over Fp256.
        Span<byte> xPlusY = stackalloc byte[ScalarSize];
        Span<byte> xPlusZ = stackalloc byte[ScalarSize];
        Fp256Add(column.AsSpan(ScalarSize, ScalarSize), column.AsSpan(2 * ScalarSize, ScalarSize), xPlusY, CurveParameterSet.None);
        Fp256Add(column.AsSpan(ScalarSize, ScalarSize), column.AsSpan(3 * ScalarSize, ScalarSize), xPlusZ, CurveParameterSet.None);

        Span<byte> product = stackalloc byte[ScalarSize];
        Fp256Multiply(xPlusY, xPlusZ, product, CurveParameterSet.None);
        Fp256Multiply(product, column.AsSpan(ScalarSize, ScalarSize), product, CurveParameterSet.None);

        //w = −product = 0 − product mod p (the assert-zero relation out[0] = w + product = 0).
        Span<byte> w = column.AsSpan(4 * ScalarSize, ScalarSize);
        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();
        Fp256Subtract(zero, product, w, CurveParameterSet.None);

        return column;
    }


    /// <summary>
    /// Produces the public-input element bytes (little-endian <c>to_bytes_field</c>): the first
    /// <c>npub_in</c> witness elements, each framed at the Fp256 element width (32 bytes).
    /// </summary>
    /// <param name="circuit">The circuit whose <see cref="LongfellowSumcheckCircuit.PublicInputCount"/> bounds the slice.</param>
    /// <param name="witnessColumn">The full canonical-scalar witness column.</param>
    /// <returns>The public inputs, little-endian and Fp256-element-width framed.</returns>
    private static byte[] PublicInputBytes(LongfellowSumcheckCircuit circuit, byte[] witnessColumn)
    {
        byte[] publicInputs = new byte[circuit.PublicInputCount * Fp256ElementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            ToBytesFieldFp256(witnessColumn.AsSpan(i * ScalarSize, ScalarSize), publicInputs.AsSpan(i * Fp256ElementBytes, Fp256ElementBytes));
        }

        return publicInputs;
    }


    /// <summary>
    /// Creates a fresh deterministic counter source: the k-th byte produced is <c>k &amp; 0xFF</c>,
    /// identical to the GF reference's <c>CounterRandomEngine</c>. Each call returns a new source so a test
    /// restarts the stream at zero.
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


    /// <summary>
    /// Creates a deterministic source whose every 32-byte draw is below <c>p</c>: the most significant
    /// little-endian byte is zeroed, so the integer is <c>&lt; 2^248 &lt; p</c> and <c>of_bytes_field</c>
    /// accepts it every time.
    /// </summary>
    /// <returns>A deterministic random byte source whose draws are always below the P-256 field modulus.</returns>
    private static LongfellowRandomByteSource NewBelowModulusSource()
    {
        ulong counter = 0;

        return destination =>
        {
            for(int i = 0; i < destination.Length; i++)
            {
                destination[i] = (byte)((counter * 31) + 7);
                counter++;
            }

            if(destination.Length == Fp256ElementBytes)
            {
                destination[^1] = 0;
            }
        };
    }


    /// <summary>Computes <c>of_scalar(u)</c> over Fp256: <paramref name="coordinate"/> reduced mod <c>p</c>, written as a canonical big-endian scalar.</summary>
    /// <param name="coordinate">The integer to reduce.</param>
    /// <param name="destination">Receives the canonical big-endian scalar.</param>
    private static void OfScalarFp256(uint coordinate, Span<byte> destination) =>
        Canonical(new BigInteger(coordinate) % Prime).CopyTo(destination);


    /// <summary>Computes <c>fits(an)</c>: <see langword="true"/> when the canonical big-endian integer is below the P-256 field modulus.</summary>
    /// <param name="canonical">The canonical big-endian scalar to test.</param>
    /// <returns><see langword="true"/> when the value is below the modulus.</returns>
    private static bool InRangeFp256(ReadOnlySpan<byte> canonical) => ReadCanonicalBigEndian(canonical) < Prime;


    /// <summary>Computes <c>to_bytes_field</c> over Fp256: reverses the 32 canonical big-endian bytes into 32 little-endian element bytes.</summary>
    /// <param name="canonical">The canonical big-endian scalar.</param>
    /// <param name="littleEndian">Receives the little-endian element bytes.</param>
    private static void ToBytesFieldFp256(ReadOnlySpan<byte> canonical, Span<byte> littleEndian)
    {
        for(int i = 0; i < Fp256ElementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }


    /// <summary>
    /// Parses a Quad coefficient <c>v</c>, encoded as <c>to_bytes_field</c> little-endian hex, into a
    /// canonical big-endian scalar. Every coefficient in this circuit is the field one, identical in GF
    /// and Fp256.
    /// </summary>
    /// <param name="hex">The little-endian element bytes, hex-encoded.</param>
    /// <returns>The canonical big-endian scalar.</returns>
    private static byte[] ParseCoefficient(string hex)
    {
        byte[] littleEndian = Convert.FromHexString(hex);
        byte[] canonical = new byte[ScalarSize];
        for(int i = 0; i < littleEndian.Length; i++)
        {
            canonical[ScalarSize - 1 - i] = littleEndian[i];
        }

        return canonical;
    }


    /// <summary>Parses a 16-byte little-endian GF element, hex-encoded, into a 32-byte big-endian canonical scalar.</summary>
    /// <param name="hex">The little-endian GF element bytes, hex-encoded.</param>
    /// <returns>The canonical big-endian scalar.</returns>
    private static byte[] ParseGfElement(string hex)
    {
        byte[] littleEndian = Convert.FromHexString(hex);
        byte[] canonical = new byte[ScalarSize];
        for(int i = 0; i < GfElementBytes; i++)
        {
            canonical[ScalarSize - 1 - i] = littleEndian[i];
        }

        return canonical;
    }


    /// <summary>Parses the anchor file's <paramref name="key"/> value as a base-10 integer.</summary>
    /// <param name="key">The anchor key to look up.</param>
    /// <returns>The parsed integer value.</returns>
    private static int Anchor(string key) => int.Parse(Anchors[key], CultureInfo.InvariantCulture);


    /// <summary>Creates a transcript seeded and sized the way the reference seeds the prover's.</summary>
    /// <param name="seed">The transcript seed bytes.</param>
    /// <param name="elementBytes">The field element width the transcript is baked at.</param>
    /// <returns>The new transcript.</returns>
    private static LongfellowTranscript NewTranscript(byte[] seed, int elementBytes) =>
        new(seed, TranscriptVersion, elementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Creates a caller-owned P-256 FFT whose root uses the supplied pool.</summary>
    /// <param name="pool">The caller pool supplying the root until the returned FFT is disposed.</param>
    private static Fp256RealFft NewFp256Fft(BaseMemoryPool pool)
    {
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnity(root);

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, OfScalarFp256, CurveParameterSet.None, pool);
    }


    /// <summary>Creates the LCH14 additive-FFT engine over the GF(2^128) production subfield.</summary>
    /// <returns>The new additive-FFT engine.</returns>
    private static Lch14AdditiveFft NewGfFft() =>
        new(Lch14Subfield.Production16, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>Computes a one-shot SHA-256 digest of <paramref name="input"/>; <paramref name="hashFunction"/> is accepted for signature compatibility and unused, since this delegate is always bound to SHA-256.</summary>
    /// <param name="input">The bytes to hash.</param>
    /// <param name="output">Receives the 32-byte digest.</param>
    /// <param name="hashFunction">The requested hash algorithm name; ignored.</param>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) => SHA256.HashData(input, output);


    /// <summary>Computes the two-to-one Merkle compression <c>SHA256(left ‖ right)</c>.</summary>
    /// <param name="left">The left digest.</param>
    /// <param name="right">The right digest.</param>
    /// <param name="output">Receives the 32-byte combined digest.</param>
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
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


    /// <summary>Writes <paramref name="value"/> as a canonical big-endian, unsigned scalar, left-padding with zero bytes.</summary>
    /// <param name="value">The non-negative integer to encode.</param>
    /// <returns>The canonical big-endian scalar bytes.</returns>
    private static byte[] Canonical(BigInteger value)
    {
        byte[] canonical = new byte[ScalarSize];
        value.TryWriteBytes(canonical, out int written, isUnsigned: true, isBigEndian: true);
        if(written < ScalarSize)
        {
            int shift = ScalarSize - written;
            canonical.AsSpan(0, written).CopyTo(canonical.AsSpan(shift));
            canonical.AsSpan(0, shift).Clear();
        }

        return canonical;
    }


    /// <summary>Reads a canonical big-endian, unsigned scalar as a <see cref="BigInteger"/>.</summary>
    /// <param name="bytes">The canonical big-endian scalar bytes.</param>
    /// <returns>The decoded non-negative integer.</returns>
    private static BigInteger ReadCanonicalBigEndian(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


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

using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The self-consistent Fp256 end-to-end ZK PROVE + VERIFY gate (conformance step C.12, the field-generic
/// prover seam). It exercises the FULL prover+verifier over the 32-byte P-256 base field through the
/// field-generic <c>LongfellowZkProver.Prove</c>
/// entry (the prime-field analogue of the GF(2^128) convenience overload), then verifies the produced
/// envelope with <see cref="LongfellowZkVerifier.VerifyFromAbsorbedRoot"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is NOT a byte-for-byte conformance gate against a reference dump — the byte-exact Fp256 envelope
/// against a reference run lands with the Docker dump harness in a later step. This gate proves the two
/// halves are mutually consistent: OUR prover's Fp256 proof verifies in OUR verifier over the 32-byte
/// field, and any tamper (a flipped proof byte or a flipped public input) is rejected.
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
/// A companion GF(2^128) gate proves the existing hash circuit through the SAME new field-generic entry
/// (with the GF encoding/codec built from the additive-FFT engine) and confirms the envelope is
/// byte-identical to the GF convenience <c>Prove</c> — the proof that splitting the prover left the GF
/// bytes untouched.
/// </para>
/// <para>
/// The Fp256 base field is BigInteger-backed and slow; the prove+verify is marked
/// <see cref="TestCategoryAttribute"/> <c>Slow</c> (it runs in low single-digit seconds on a developer machine) and
/// is gated out of the default suite. The GF byte-identity check below it is fast and stays in the default
/// suite.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowFp256ZkProveTests
{
    private const string ZkDumpRelativePath = "TestMaterial/Longfellow/zk-anchor-output.txt";

    private const int ScalarSize = Scalar.SizeBytes;
    private const int Fp256ElementBytes = 32;
    private const int GfElementBytes = 16;
    private const int DigestSize = 32;
    private const int TranscriptVersion = 6;

    //The Ligero rate / opened-column count the GF anchor flow uses; reused for both fields.
    private const int InverseRate = 4;
    private const int OpenedColumnCount = 2;

    //GF(2^128) full/subfield widths (the binary hash circuit).
    private const int GfFieldBytes = 16;
    private const int GfSubFieldBytes = 2;
    private const int GfSubfieldBoundary = 0;

    private static readonly byte[] Fp256TranscriptSeed = Encoding.ASCII.GetBytes("fp256-zk-e2e");
    private static readonly byte[] GfTranscriptSeed = Encoding.ASCII.GetBytes("zk8");

    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    private static ScalarAddDelegate Fp256Add { get; } = P256BaseFieldReference.GetAdd();

    private static ScalarSubtractDelegate Fp256Subtract { get; } = P256BaseFieldReference.GetSubtract();

    private static ScalarMultiplyDelegate Fp256Multiply { get; } = P256BaseFieldReference.GetMultiply();

    private static ScalarInvertDelegate Fp256Invert { get; } = P256BaseFieldReference.GetInvert();

    private static ScalarAddDelegate GfAdd { get; } = Gf2k128Backend.GetAdd();

    private static ScalarSubtractDelegate GfSubtract { get; } = Gf2k128Backend.GetSubtract();

    private static ScalarMultiplyDelegate GfMultiply { get; } = Gf2k128Backend.GetMultiply();

    private static ScalarInvertDelegate GfInvert { get; } = Gf2k128Backend.GetInvert();

    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(ZkDumpRelativePath);


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
        byte[] proof = ProveFp256(circuit, parameters, witnessColumn, Fp256TranscriptSeed);

        byte[] publicInputs = PublicInputBytes(circuit, witnessColumn);

        AssertFp256Verifies(circuit, parameters, proof, publicInputs, Fp256TranscriptSeed, expectedAccept: true);
    }


    [TestMethod]
    public void ATamperedFp256ProofIsRejected()
    {
        //Same small relation; stays in the default suite (sub-second).
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Fp256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes);

        byte[] witnessColumn = BuildSatisfyingColumn(3, 5, 7);
        byte[] proof = ProveFp256(circuit, parameters, witnessColumn, Fp256TranscriptSeed);
        byte[] publicInputs = PublicInputBytes(circuit, witnessColumn);

        //A flipped byte inside the sumcheck segment (after the 32-byte root) breaks the replay: the derived
        //challenge stream and the constraint coefficients diverge and the Ligero opening no longer matches.
        byte[] tamperedProof = (byte[])proof.Clone();
        tamperedProof[DigestSize + 8] ^= 0x01;
        AssertFp256Verifies(circuit, parameters, tamperedProof, publicInputs, Fp256TranscriptSeed, expectedAccept: false);

        //A flipped public input moves the FS setup and the input-binding constraint, so verification fails.
        byte[] tamperedPublic = (byte[])publicInputs.Clone();
        tamperedPublic[Fp256ElementBytes + 1] ^= 0x01;
        AssertFp256Verifies(circuit, parameters, proof, tamperedPublic, Fp256TranscriptSeed, expectedAccept: false);
    }


    [TestMethod]
    public void TheFieldGenericEntryReproducesTheGfConvenienceBytes()
    {
        //Proving the GF(2^128) hash circuit through the NEW field-generic entry (with the GF encoding,
        //row-encoder factory and subfield-run codec built from the additive-FFT engine) must produce the
        //byte-identical envelope the GF convenience Prove produces — the proof the split did not change the
        //GF bytes. Fast; stays in the default suite.
        LongfellowSumcheckCircuit circuit = BuildCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, GfFieldBytes, GfSubFieldBytes);

        byte[] witnessColumn = BuildGfWitnessColumn(circuit);

        byte[] viaConvenience = ProveGfConvenience(circuit, parameters, witnessColumn, GfTranscriptSeed);
        byte[] viaFieldGeneric = ProveGfFieldGeneric(circuit, parameters, witnessColumn, GfTranscriptSeed);

        Assert.IsTrue(viaFieldGeneric.AsSpan().SequenceEqual(viaConvenience), "The field-generic entry must produce the byte-identical GF envelope the convenience overload produces.");

        //Cross-check against the reference's pinned bytes so the GF path is anchored, not just self-equal.
        byte[] expected = Convert.FromHexString(Anchors["proof_bytes"]);
        Assert.IsTrue(viaFieldGeneric.AsSpan().SequenceEqual(expected), "The field-generic GF envelope must equal the reference's pinned proof bytes.");
    }


    //Proves a satisfying Fp256 witness column through the field-generic prover with the Fp256 encoding.
    private static byte[] ProveFp256(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] witnessColumn, byte[] seed)
    {
        Fp256RealFft fft = NewFp256Fft();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
        LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalarFp256, InRangeFp256);
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


    //Verifies an Fp256 envelope through the field-generic verifier: parse the envelope, absorb the root,
    //then drive VerifyFromAbsorbedRoot with the Fp256 encoder factory and profile.
    private static void AssertFp256Verifies(
        LongfellowSumcheckCircuit circuit,
        LongfellowLigeroParameters parameters,
        byte[] proof,
        byte[] publicInputs,
        byte[] seed,
        bool expectedAccept)
    {
        Fp256RealFft fft = NewFp256Fft();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
        LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalarFp256, InRangeFp256);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp256(profile);

        //Parse the envelope: com (32) || sc || com_proof, the field-generic counterpart of the GF Verify
        //single-call parse (which the GF convenience builds for GF(2^128) only).
        ReadOnlySpan<byte> proofSpan = proof;
        ReadOnlySpan<byte> root = proofSpan[..DigestSize];
        int scSize = LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile);
        ReadOnlySpan<byte> scBytes = proofSpan.Slice(DigestSize, scSize);
        ReadOnlySpan<byte> comProofBytes = proofSpan[(DigestSize + scSize)..];

        using LongfellowSumcheckProof? sumcheckProof = LongfellowSumcheckProofSerializer.Read(circuit, profile, BaseMemoryPool.Shared, scBytes, out _);
        Assert.IsNotNull(sumcheckProof, "The sumcheck segment must parse.");

        using LongfellowLigeroProof? ligeroProof = LongfellowLigeroProofSerializer.Read(parameters, profile, codec, BaseMemoryPool.Shared, comProofBytes, out _);
        Assert.IsNotNull(ligeroProof, "The Ligero segment must parse.");

        using LongfellowTranscript transcript = NewTranscript(seed, Fp256ElementBytes);
        LongfellowZkVerifier.RecvCommitment(root, transcript);

        bool accepted = LongfellowZkVerifier.VerifyFromAbsorbedRoot(
            circuit,
            parameters,
            sumcheckProof,
            ligeroProof,
            root,
            publicInputs,
            transcript,
            encoderFactory,
            profile,
            Fp256Add,
            Fp256Subtract,
            Fp256Multiply,
            Fp256Invert,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared,
            out LongfellowZkVerificationResult result);

        Assert.AreEqual(expectedAccept, accepted, $"The Fp256 verdict must be {(expectedAccept ? "accept" : "reject")} (result {result}).");

        if(!expectedAccept)
        {
            //A soundness reject must surface as a Ligero rejection, not a parse/transcript-shape failure:
            //the tampered byte or public input diverges the challenge stream and the opening no longer
            //matches the commitment. Asserting the specific cause stops a future regression that rejects
            //for a MalformedProof reason from masquerading as a soundness reject.
            Assert.AreEqual(LongfellowZkVerificationResult.LigeroRejected, result, "A tampered Fp256 proof must reject with the Ligero soundness cause.");
        }
    }


    //Proves the GF circuit through the GF convenience Prove (the unchanged signature; the byte baseline).
    private static byte[] ProveGfConvenience(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] witnessColumn, byte[] seed)
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


    //Proves the GF circuit through the field-generic Prove, building the GF encoding/codec from the FFT
    //exactly as the convenience overload does internally.
    private static byte[] ProveGfFieldGeneric(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] witnessColumn, byte[] seed)
    {
        using Lch14AdditiveFft fft = NewGfFft();
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
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


    //Reconstructs the circuit shape with its per-layer Quad terms from the anchor's dumped parameters. The
    //wiring is shared between GF and Fp256 because every coefficient v is the field ONE (01000...), which is
    //the same canonical value in both fields, and the gate indices are field-independent.
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
                byte[] v = ParseCoefficient(Anchors[$"L{i}_t{t}_v"]);
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


    //The GF witness column (all ninputs) as canonical scalars, from the anchor's input0..input(n-1). This is
    //the reference's fixed satisfying column for the GF byte-identity check.
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


    //Builds a satisfying Fp256 witness column [one, x, y, z, w] for the anchor's three-layer wiring. Tracing
    //the gates (every coefficient v is one), the circuit output is out[0] = w + x·(x + y)·(x + z), so the
    //assert-zero relation requires w = −x·(x + y)·(x + z) mod p. Over GF(2^128) negation is the identity, so
    //the same column degenerates to the GF gate's w = x·(x + y)·(x + z); over Fp256 the negation is genuine.
    //x is public, y/z/w private; the constant-one wire is the field one.
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


    //The public input element bytes (little-endian to_bytes_field): the first npub_in witness elements, each
    //framed at the Fp256 element width (32 bytes).
    private static byte[] PublicInputBytes(LongfellowSumcheckCircuit circuit, byte[] witnessColumn)
    {
        byte[] publicInputs = new byte[circuit.PublicInputCount * Fp256ElementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            ToBytesFieldFp256(witnessColumn.AsSpan(i * ScalarSize, ScalarSize), publicInputs.AsSpan(i * Fp256ElementBytes, Fp256ElementBytes));
        }

        return publicInputs;
    }


    //A fresh deterministic counter source: the k-th byte produced is (k & 0xFF), identical to the GF
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


    //A deterministic source whose every 32-byte draw is below p: the most significant little-endian byte is
    //zeroed, so the integer is < 2^248 < p and of_bytes_field accepts it. The established seam-test pattern.
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


    //of_scalar(u) over Fp256: the integer u reduced mod p as a canonical big-endian scalar.
    private static void OfScalarFp256(uint coordinate, Span<byte> destination) =>
        Canonical(new BigInteger(coordinate) % Prime).CopyTo(destination);


    //fits(an): the canonical big-endian integer is below the modulus.
    private static bool InRangeFp256(ReadOnlySpan<byte> canonical) => ReadCanonicalBigEndian(canonical) < Prime;


    //to_bytes_field over Fp256: the 32 canonical big-endian bytes reversed to 32 little-endian element bytes.
    private static void ToBytesFieldFp256(ReadOnlySpan<byte> canonical, Span<byte> littleEndian)
    {
        for(int i = 0; i < Fp256ElementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }


    //The Quad coefficient v, dumped as to_bytes_field little-endian; parse it into a canonical big-endian
    //scalar. Every coefficient in this circuit is the field one, identical in GF and Fp256.
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


    //Parses a 16-byte little-endian GF element into a 32-byte big-endian canonical scalar.
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


    private static int Anchor(string key) => int.Parse(Anchors[key], CultureInfo.InvariantCulture);


    private static LongfellowTranscript NewTranscript(byte[] seed, int elementBytes) =>
        new(seed, TranscriptVersion, elementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    private static Fp256RealFft NewFp256Fft()
    {
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnity(root);

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    private static Lch14AdditiveFft NewGfFft() =>
        new(Lch14Subfield.Production16, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, BaseMemoryPool.Shared);


    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) => SHA256.HashData(input, output);


    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


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


    private static BigInteger ReadCanonicalBigEndian(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


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

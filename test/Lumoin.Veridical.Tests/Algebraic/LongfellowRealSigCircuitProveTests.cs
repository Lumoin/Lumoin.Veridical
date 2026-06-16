using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Mdoc;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The SELF-CONSISTENT real-credential Fp256 SIGNATURE-circuit PROVE -&gt; VERIFY gate (the headline
/// real-credential SIG prove number). It imports the version-7 P-256 signature circuit from the same
/// <c>mdoc-circuit-raw.gz</c> the crown gate parses (field id 1, 32-byte elements), fills the genuine
/// 3739-element witness column with <see cref="MdocSignatureWitnessFiller"/> (the REAL credential's issuer
/// signature plus the synthesized device half, coordinator decision OQ1), then runs OUR field-generic Fp256
/// <see cref="LongfellowZkProver.Prove(LongfellowSumcheckCircuit, LongfellowLigeroParameters, ReadOnlySpan{byte}, int, LongfellowRandomByteSource, LongfellowTranscript, LongfellowRowEncoderFactory, LongfellowFieldProfile, LongfellowSubfieldRunCodec, ScalarAddDelegate, ScalarSubtractDelegate, ScalarMultiplyDelegate, ScalarInvertDelegate, MerkleHashDelegate, FiatShamirHashDelegate, string, CurveParameterSet, BaseMemoryPool)"/>
/// and confirms OUR <see cref="LongfellowZkVerifier.VerifyFromAbsorbedRoot"/> ACCEPTS it; a tamper dual (a
/// flipped proof byte AND a flipped public input) rejects with the Ligero soundness cause.
/// </summary>
/// <remarks>
/// <para>
/// This is the prime-field, real-circuit analogue of <see cref="LongfellowFp256ZkProveTests"/> (which proves
/// a tiny field-satisfiable relation): the same prove-&gt;verify wiring — the <see cref="LongfellowFp256Encoding"/>
/// row-encoder factory and profile over a shared <see cref="Fp256RealFft"/>, the <c>ForFp256</c> subfield-run
/// codec, the transcript baked at the 32-byte Fp256 width, the below-modulus random source, and the
/// <c>RecvCommitment</c> + <c>VerifyFromAbsorbedRoot</c> verify — but over the genuine 21-layer signature
/// circuit (<c>ninputs = 3739</c>, <c>npub_in = 900</c>, the <c>-s</c>/<c>bi_</c> negations and the
/// assert-zero gates the GF(2)-conformant crown gate cannot fully stress per
/// <c>[[gf2-conformance-hides-sign-errors]]</c>). The public inputs are the first 900 witness elements
/// reframed little-endian (the filler already lays the macs/av into the public prefix from the chosen-constant
/// keys, OQ2, so no <c>generate_mac_key</c> splice is needed — this is the self-consistent gate, not the
/// byte-exact crown gate where the macs ride the envelope prefix).
/// </para>
/// <para>
/// The Ligero parameters use the reference v7 sig triple <c>(kLigeroRatev7 = 7, kLigeroNreqv7 = 132)</c> and
/// the pinned <c>block_enc_sig = 4096</c> through the same pinned-<c>block_enc</c>
/// <see cref="LongfellowZkVerifier.DeriveParameters(LongfellowSumcheckCircuit, int, int, int, int, int)"/>
/// overload the crown gate uses, and the SAME parameters object drives both the prove and the verify (so the
/// encoded block length matches). The arithmetic rides the validated
/// <see cref="P256BaseFieldMontgomeryBackend"/> (byte-identical to the BigInteger reference per
/// <c>Fp256FieldBackendAgreementTests</c>, ~2.5x faster), so any genuine Fp256 sign bug surfaces identically
/// to the reference backend while the prove number is representative of the production-intended path.
/// </para>
/// <para>
/// The full prove over the 21-layer circuit is the expensive Ligero-over-the-whole-R1CS path, so the
/// prove-&gt;verify gate is marked <see cref="TestCategory"/> <c>Slow</c>. The cheap pre-check
/// (<see cref="TheWitnessSatisfiesTheImportedSigCircuit"/>) evaluates the circuit on the witness through
/// <c>EvaluateCircuit</c> (the reference's <c>eval_circuit</c>: every layer's quad form, the output-zero
/// assertion and every assert-zero gate) and stays in the default suite to catch filler/sign bugs without
/// paying for the full prove.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowRealSigCircuitProveTests
{
    private const string RawGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-raw.gz";

    private const string CredentialRelativePath = "TestMaterial/Mdoc/mdoc-00.cbor";

    //The reference circuit-stream field id and on-wire element width for the P-256 sig circuit (C.10 reader).
    private const int Point256FieldId = 1;
    private const int Point256ElementBytes = 32;

    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSize = 32;

    //The reference v7 sig Ligero pair (kLigeroRatev7 = 7, kLigeroNreqv7 = 132) and the pinned block_enc_sig
    //(kZkSpecs num_attributes=1, version=7: {1, 7, 4151, 4096}; zk_spec.cc:47-49). The crown gate pins the
    //same trio (mdoc_zk.cc:615-616 prover, 659-662 verifier feed block_enc to both ZkProof and ZkVerifier).
    private const int InverseRate = 7;
    private const int OpenedColumnCount = 132;
    private const int SigBlockEncoded = 4096;

    //The transcript is baked at the 32-byte Fp256 width (the self-consistent sig gate is single-field; there
    //is no GF/a_v side baking 16). Version 7 matches the deployed sig path.
    private const int TranscriptVersion = 7;

    private static readonly byte[] TranscriptSeed = System.Text.Encoding.ASCII.GetBytes("fp256-real-sig-e2e");

    //The decompressed real-circuit bytes (~99 MB); decompress once and share across the imports.
    private static byte[] RawCircuitBytes { get; } = DecompressGzip(ReadFixture(RawGzipRelativePath));

    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    //The validated Montgomery base-field backend (byte-identical to the BigInteger reference, faster); any
    //genuine Fp256 sign bug surfaces identically. Add/Subtract are domain-linear, so the canonical delegates
    //serve both the canonical and the Montgomery working domain unchanged.
    private static ScalarAddDelegate Fp256Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();

    private static ScalarSubtractDelegate Fp256Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();

    //The canonical-domain multiply/invert (2 CIOS per multiply): the EvaluateCircuit pre-check and the canonical
    //leg of the byte-identity gate run on the canonical witness column.
    private static ScalarMultiplyDelegate Fp256Multiply { get; } = P256BaseFieldMontgomeryBackend.GetMultiply();

    private static ScalarInvertDelegate Fp256Invert { get; } = P256BaseFieldMontgomeryBackend.GetInvert();

    //The Montgomery-domain multiply/invert (Perf Increment 1, 1 CIOS per multiply): the production-intended
    //sig prove/verify path runs on these over a Montgomery-lifted witness column, profile and FFT root.
    private static ScalarMultiplyDelegate Fp256MultiplyMontgomery { get; } = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();

    private static ScalarInvertDelegate Fp256InvertMontgomery { get; } = P256BaseFieldMontgomeryBackend.GetInvertMontgomery();


    /// <summary>The MSTest context, used to surface the [Slow] prove/verify wall-clock through the test output.</summary>
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void TheWitnessSatisfiesTheImportedSigCircuit()
    {
        //FAST PRE-CHECK (default suite): evaluate the imported circuit on the real-credential witness column
        //through the reference's eval_circuit (LongfellowSumcheckProver.EvaluateCircuit). It walks all 21
        //layers' quad forms, asserts the circuit output is all-zero (the assert-zero relation the ZK circuit
        //compiles to) and that every assert-zero gate's product vanishes — i.e. it confirms the witness
        //SATISFIES the circuit's constraints (A.w == b at every layer) WITHOUT paying for the full Ligero
        //prove. A filler bug or an Fp256 sign bug surfaces here as a thrown InvalidOperationException naming
        //the divergent layer/gate, cheaply.
        LongfellowSumcheckCircuit circuit = ParseSignatureCircuit();
        byte[] witnessColumn = BuildWitnessColumn();

        Assert.HasCount(circuit.InputCount * ScalarSize, witnessColumn, "The witness column must be ninputs * 32 canonical bytes.");
        Assert.AreEqual(MdocSignatureWitnessFiller.ElementCount, circuit.InputCount, "The filler element count must equal the circuit's ninputs (3739).");
        Assert.AreEqual(MdocSignatureWitnessFiller.PublicInputCount, circuit.PublicInputCount, "The filler public-input count must equal the circuit's npub_in (900).");

        //EvaluateCircuit throws if the output is non-zero or an assert-zero gate is violated; a clean return
        //is the proof the witness satisfies the circuit. The output table is asserted all-zero internally.
        using LongfellowWireTables tables = LongfellowSumcheckProver.EvaluateCircuit(circuit, witnessColumn, Fp256Multiply, Fp256Add, CurveParameterSet.None, BaseMemoryPool.Shared);
        Span<byte> output = tables.OutputTable();
        for(int i = 0; i < circuit.OutputCount; i++)
        {
            Assert.IsTrue(IsZero(output.Slice(i * ScalarSize, ScalarSize)), $"The circuit output wire {i} must be zero (the assert-zero relation).");
        }
    }


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void OurVerifierAcceptsOurRealSigProofAndRejectsATamper()
    {
        LongfellowSumcheckCircuit circuit = ParseSignatureCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Point256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes, SigBlockEncoded);

        byte[] canonicalColumn = BuildWitnessColumn();

        //The sig path runs in the Montgomery working domain (Perf Increment 1): convert the filler's canonical
        //column element-wise to Montgomery once, and extract the public-input template from the Montgomery
        //column through the Montgomery profile's to_bytes_field (from_montgomery + reverse), so the LE wire
        //bytes are byte-identical to the canonical extraction.
        byte[] witnessColumn = MontgomeryColumn(canonicalColumn);
        byte[] publicInputs = MontgomeryPublicInputBytes(circuit, witnessColumn);

        //A warm prove+verify pair first (JIT, the FFT precompute, the field-backend warm-up), then the timed
        //pair, so the reported wall-clock is representative rather than dominated by first-call costs.
        byte[] warm = ProveFp256(circuit, parameters, witnessColumn);
        AssertVerifies(circuit, parameters, warm, publicInputs, expectedAccept: true);

        //Prove the real-credential witness through OUR field-generic Fp256 prover, then verify it through OUR
        //verifier on a fresh transcript: the headline self-consistent accept.
        Stopwatch proveWatch = Stopwatch.StartNew();
        byte[] proof = ProveFp256(circuit, parameters, witnessColumn);
        proveWatch.Stop();

        Stopwatch verifyWatch = Stopwatch.StartNew();
        AssertVerifies(circuit, parameters, proof, publicInputs, expectedAccept: true);
        verifyWatch.Stop();

        TestContext.WriteLine($"Real-credential Fp256 SIG circuit (ninputs=3739, npub_in=900, 21 layers): PROVE {proveWatch.ElapsedMilliseconds} ms, VERIFY {verifyWatch.ElapsedMilliseconds} ms (warm; Montgomery backend; rate=7/nreq=132/block_enc=4096).");

        //The tamper dual: flip a proof byte AND a public input. A flipped byte inside the sumcheck segment
        //(after the 32-byte root) diverges the replayed challenge stream, and a flipped public input moves
        //the FS setup and the input-binding constraint; either alone rejects, both together certainly do.
        byte[] tamperedProof = (byte[])proof.Clone();
        tamperedProof[DigestSize + 8] ^= 0x01;
        byte[] tamperedPublic = (byte[])publicInputs.Clone();
        tamperedPublic[Point256ElementBytes + 1] ^= 0x01;
        AssertVerifies(circuit, parameters, tamperedProof, tamperedPublic, expectedAccept: false);
    }


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void TheMontgomeryProveEmitsAByteIdenticalEnvelopeToTheCanonicalProve()
    {
        //THE KEY GATE (Perf Increment 1): prove the genuine real-sig circuit over the SAME witness BOTH ways —
        //once with the canonical profile/delegates/of_scalar/root over the canonical column, once with the
        //Montgomery ones over the Montgomery-lifted column — under the SAME deterministic random source and
        //transcript seed, and assert the two envelopes are BYTE-IDENTICAL. The wire bytes are domain-independent
        //(to_bytes_field drops Montgomery->canonical), so the only correct outcome is identity; a divergence is
        //a missed seam (a value bypassing the profile / a non-lifted constant / a wrong root coordinate). This
        //is achievable because, within a single invocation with identical entropy, the only difference between
        //the two proves is the working domain — which the wire format erases. (Run-to-run the prove is
        //non-deterministic, so no hardcoded golden exists; the two-leg equality is the byte-identity claim.)
        LongfellowSumcheckCircuit circuit = ParseSignatureCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Point256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes, SigBlockEncoded);

        byte[] canonicalColumn = BuildWitnessColumn();
        byte[] montgomeryColumn = MontgomeryColumn(canonicalColumn);

        byte[] canonicalEnvelope = ProveFp256Canonical(circuit, parameters, canonicalColumn);
        byte[] montgomeryEnvelope = ProveFp256(circuit, parameters, montgomeryColumn);

        string canonicalSha = Convert.ToHexStringLower(SHA256.HashData(canonicalEnvelope));
        string montgomerySha = Convert.ToHexStringLower(SHA256.HashData(montgomeryEnvelope));
        TestContext.WriteLine($"Canonical envelope SHA-256: {canonicalSha} ({canonicalEnvelope.Length} bytes)");
        TestContext.WriteLine($"Montgomery envelope SHA-256: {montgomerySha} ({montgomeryEnvelope.Length} bytes)");
        TestContext.WriteLine($"Byte-identical: {(canonicalSha == montgomerySha ? "yes" : "no")}");

        Assert.IsTrue(canonicalEnvelope.AsSpan().SequenceEqual(montgomeryEnvelope), "The Montgomery-domain prove must emit a byte-identical envelope to the canonical-domain prove over the same witness.");
    }


    [TestMethod]
    public void TheMontgomeryProfileSeamIsWireByteIdenticalToTheCanonicalProfile()
    {
        //DETERMINISTIC BYTE-IDENTITY GATE (Perf Increment 1): the Montgomery-domain Fp profile must emit and
        //read EXACTLY the same little-endian wire bytes as the canonical profile for the genuine real-sig
        //witness — the seam invariant the whole increment rests on. (The full real-sig prove envelope SHA was
        //the spec's intended Gate 1, but that prove is NON-DETERMINISTIC run-to-run on pristine main — see the
        //subagent report's blocking findings — so a hardcoded-envelope golden cannot exist for it. This gate
        //pins the part that IS deterministic and is the actual byte-identity claim the converters make.)
        LongfellowFieldProfile canonical = LongfellowFp256Encoding.CreateProfile(OfScalarFp256, InRangeFp256);
        LongfellowFieldProfile montgomery = LongfellowFp256Encoding.CreateMontgomeryProfile(
            OfScalarFp256, InRangeFp256, P256BaseFieldMontgomeryBackend.ToMontgomery, P256BaseFieldMontgomeryBackend.FromMontgomery);

        byte[] witnessColumn = BuildWitnessColumn();
        Span<byte> canonicalWire = stackalloc byte[Point256ElementBytes];
        Span<byte> montgomeryWire = stackalloc byte[Point256ElementBytes];
        Span<byte> canonicalRead = stackalloc byte[ScalarSize];
        Span<byte> montgomeryRead = stackalloc byte[ScalarSize];
        Span<byte> montgomeryElement = stackalloc byte[ScalarSize];
        Span<byte> recovered = stackalloc byte[ScalarSize];

        for(int i = 0; i < MdocSignatureWitnessFiller.ElementCount; i++)
        {
            ReadOnlySpan<byte> canonicalElement = witnessColumn.AsSpan(i * ScalarSize, ScalarSize);

            //to_bytes_field: the canonical profile emits from the canonical value; the Montgomery profile
            //emits from the Montgomery residue (from_montgomery then reverse). The wire bytes must match.
            P256BaseFieldMontgomeryBackend.ToMontgomery(canonicalElement, montgomeryElement);
            canonical.ToBytesField(canonicalElement, canonicalWire);
            montgomery.ToBytesField(montgomeryElement, montgomeryWire);
            Assert.IsTrue(canonicalWire.SequenceEqual(montgomeryWire), $"to_bytes_field wire bytes must match at element {i}.");

            //of_bytes_field round-trip: reading the wire bytes back, the canonical profile yields the canonical
            //value and the Montgomery profile yields its Montgomery residue; from_montgomery must recover the
            //canonical value bit-for-bit.
            canonical.FromBytesField(canonicalWire, canonicalRead);
            montgomery.FromBytesField(montgomeryWire, montgomeryRead);
            Assert.IsTrue(canonicalRead.SequenceEqual(canonicalElement), $"canonical of_bytes_field must round-trip at element {i}.");

            P256BaseFieldMontgomeryBackend.FromMontgomery(montgomeryRead, recovered);
            Assert.IsTrue(recovered.SequenceEqual(canonicalElement), $"Montgomery of_bytes_field must drop to the canonical value at element {i}.");
        }
    }


    //Proves the real-credential witness column (a MONTGOMERY-domain column) through the field-generic prover
    //with the Montgomery Fp256 encoding (the 1-CIOS path), the v7 rate/nreq and the pinned block_enc carried by
    //the supplied parameters.
    private static byte[] ProveFp256(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] witnessColumn)
    {
        LongfellowFieldProfile profile = NewMontgomeryProfile();
        Fp256RealFft fft = NewMontgomeryFp256Fft();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateMontgomeryEncoderFactory(
            fft, profile, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None, BaseMemoryPool.Shared, Fp256SimdBackend.BatchMultiplyMontgomery());
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp256(profile);

        //The circuit's quad-term coefficients are canonical; lift them to Montgomery so the shared sumcheck
        //multiplies a working-domain constant against the working-domain wires.
        LongfellowSumcheckCircuit montgomeryCircuit = circuit.LiftCoefficientsToWorking(P256BaseFieldMontgomeryBackend.ToMontgomery);

        using LongfellowTranscript transcript = NewTranscript();
        LongfellowRandomByteSource random = NewBelowModulusSource();

        return LongfellowZkProver.Prove(
            montgomeryCircuit,
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
            Fp256MultiplyMontgomery,
            Fp256InvertMontgomery,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared,
            fp256BatchMultiply: Fp256SimdBackend.BatchMultiplyMontgomery());
    }


    //Proves the same witness CANONICALLY (the 2-CIOS path), the byte-identity gate's canonical leg. The witness
    //column is the canonical filler output, the profile/delegates/root are canonical.
    private static byte[] ProveFp256Canonical(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] canonicalColumn)
    {
        Fp256RealFft fft = NewFp256Fft();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
        LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalarFp256, InRangeFp256);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp256(profile);

        using LongfellowTranscript transcript = NewTranscript();
        LongfellowRandomByteSource random = NewBelowModulusSource();

        return LongfellowZkProver.Prove(
            circuit,
            parameters,
            canonicalColumn,
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


    //Verifies an Fp256 envelope through the field-generic verifier: parse com || sc || com_proof, absorb the
    //root, then drive VerifyFromAbsorbedRoot with the Fp256 encoder factory and profile.
    private static void AssertVerifies(
        LongfellowSumcheckCircuit circuit,
        LongfellowLigeroParameters parameters,
        byte[] proof,
        byte[] publicInputs,
        bool expectedAccept)
    {
        LongfellowFieldProfile profile = NewMontgomeryProfile();
        Fp256RealFft fft = NewMontgomeryFp256Fft();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateMontgomeryEncoderFactory(
            fft, profile, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None, BaseMemoryPool.Shared, Fp256SimdBackend.BatchMultiplyMontgomery());
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp256(profile);

        //The circuit's quad-term coefficients are canonical; lift them to Montgomery so the verifier's shared
        //constraint build multiplies a working-domain constant against the working-domain wires.
        LongfellowSumcheckCircuit montgomeryCircuit = circuit.LiftCoefficientsToWorking(P256BaseFieldMontgomeryBackend.ToMontgomery);

        ReadOnlySpan<byte> proofSpan = proof;
        ReadOnlySpan<byte> root = proofSpan[..DigestSize];
        int scSize = LongfellowSumcheckProofSerializer.SerializedSize(montgomeryCircuit, profile);
        ReadOnlySpan<byte> scBytes = proofSpan.Slice(DigestSize, scSize);
        ReadOnlySpan<byte> comProofBytes = proofSpan[(DigestSize + scSize)..];

        using LongfellowSumcheckProof? sumcheckProof = LongfellowSumcheckProofSerializer.Read(montgomeryCircuit, profile, BaseMemoryPool.Shared, scBytes, out _);
        Assert.IsNotNull(sumcheckProof, "The sumcheck segment must parse.");

        using LongfellowLigeroProof? ligeroProof = LongfellowLigeroProofSerializer.Read(parameters, profile, codec, BaseMemoryPool.Shared, comProofBytes, out _);
        Assert.IsNotNull(ligeroProof, "The Ligero segment must parse.");

        using LongfellowTranscript transcript = NewTranscript();
        LongfellowZkVerifier.RecvCommitment(root, transcript);

        bool accepted = LongfellowZkVerifier.VerifyFromAbsorbedRoot(
            montgomeryCircuit,
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
            Fp256MultiplyMontgomery,
            Fp256InvertMontgomery,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            CurveParameterSet.None,
            BaseMemoryPool.Shared,
            out LongfellowZkVerificationResult result,
            fp256BatchMultiply: Fp256SimdBackend.BatchMultiplyMontgomery());

        Assert.AreEqual(expectedAccept, accepted, $"The real-sig Fp256 verdict must be {(expectedAccept ? "accept" : "reject")} (result {result}).");

        if(!expectedAccept)
        {
            //A soundness reject must surface as a Ligero rejection, not a parse/transcript-shape failure.
            Assert.AreEqual(LongfellowZkVerificationResult.LigeroRejected, result, "A tampered real-sig Fp256 proof must reject with the Ligero soundness cause.");
        }
    }


    //Builds the genuine 3739-element SIG witness column: the REAL credential's issuer signature (via
    //MdocDisclosure over mdoc-00.cbor, age_over_18) and the synthesized device half (OQ1).
    private static byte[] BuildWitnessColumn()
    {
        MdocDisclosure issuer = MdocDisclosure.Extract(ReadFixture(CredentialRelativePath), "org.iso.18013.5.1", "age_over_18");
        MdocDeviceSignatureSynth device = MdocDeviceSignatureSynth.Create();
        var filler = new MdocSignatureWitnessFiller();

        return filler.Fill(issuer, device);
    }


    //Lifts a canonical witness column to the Montgomery working domain (Perf Increment 1): each 32-byte element
    //is converted in place through to_montgomery. The wire bytes the prover emits are domain-independent (the
    //Montgomery profile's to_bytes_field drops back to canonical), so this is the only column-side change.
    private static byte[] MontgomeryColumn(byte[] canonicalColumn)
    {
        byte[] montgomery = new byte[canonicalColumn.Length];
        for(int i = 0; i < canonicalColumn.Length / ScalarSize; i++)
        {
            P256BaseFieldMontgomeryBackend.ToMontgomery(canonicalColumn.AsSpan(i * ScalarSize, ScalarSize), montgomery.AsSpan(i * ScalarSize, ScalarSize));
        }

        return montgomery;
    }


    //The public-input element bytes extracted from a MONTGOMERY column through the Montgomery profile's
    //to_bytes_field (from_montgomery + reverse). The resulting LE wire bytes are byte-identical to
    //PublicInputBytes over the canonical column — the seam invariant the increment rests on.
    private static byte[] MontgomeryPublicInputBytes(LongfellowSumcheckCircuit circuit, byte[] montgomeryColumn)
    {
        LongfellowFieldProfile profile = NewMontgomeryProfile();
        byte[] publicInputs = new byte[circuit.PublicInputCount * Point256ElementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            profile.ToBytesField(montgomeryColumn.AsSpan(i * ScalarSize, ScalarSize), publicInputs.AsSpan(i * Point256ElementBytes, Point256ElementBytes));
        }

        return publicInputs;
    }


    //Imports the P-256 signature circuit (the front of the raw circuit stream).
    private static LongfellowSumcheckCircuit ParseSignatureCircuit()
    {
        bool parsed = LongfellowCircuitReader.TryRead(RawCircuitBytes, Point256FieldId, Point256ElementBytes, out LongfellowSumcheckCircuit? signature, out _, out _);
        Assert.IsTrue(parsed, "The signature circuit must parse.");
        Assert.IsNotNull(signature);

        return signature;
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

            if(destination.Length == Point256ElementBytes)
            {
                destination[^1] = 0;
            }
        };
    }


    //of_scalar(u) over Fp256: the integer u reduced mod p as a canonical big-endian scalar.
    private static void OfScalarFp256(uint coordinate, Span<byte> destination)
    {
        destination.Clear();
        BigInteger value = new BigInteger(coordinate) % Prime;
        value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true);
        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    //fits(an): the canonical big-endian integer is below the modulus.
    private static bool InRangeFp256(ReadOnlySpan<byte> canonical) => new BigInteger(canonical, isUnsigned: true, isBigEndian: true) < Prime;


    private static LongfellowTranscript NewTranscript() =>
        new(TranscriptSeed, TranscriptVersion, Point256ElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    private static Fp256RealFft NewFp256Fft()
    {
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnity(root);

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    //The Montgomery-domain Fp256 profile: of_scalar/of_bytes_field lift canonical->Montgomery, to_bytes_field
    //drops Montgomery->canonical, so the wire bytes stay byte-identical to the canonical profile.
    private static LongfellowFieldProfile NewMontgomeryProfile() =>
        LongfellowFp256Encoding.CreateMontgomeryProfile(OfScalarFp256, InRangeFp256, P256BaseFieldMontgomeryBackend.ToMontgomery, P256BaseFieldMontgomeryBackend.FromMontgomery);


    //The Montgomery-domain real-FFT: the production root is lifted per coordinate to its Montgomery residue, so
    //the twiddle multiplies stay 1-CIOS in domain; the multiply/invert are the Montgomery-domain delegates.
    private static Fp256RealFft NewMontgomeryFp256Fft()
    {
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnityWorking(root, P256BaseFieldMontgomeryBackend.ToMontgomery);

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, NewMontgomeryProfile().OfScalar, CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) => SHA256.HashData(input, output);


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


    private static bool IsZero(ReadOnlySpan<byte> scalar) => scalar.IndexOfAnyExcept((byte)0) < 0;


    private static byte[] ReadFixture(string relativePath) => File.ReadAllBytes($"../../../{relativePath}");


    private static byte[] DecompressGzip(byte[] gzip)
    {
        using var input = new MemoryStream(gzip);
        using var gzipStream = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzipStream.CopyTo(output);

        return output.ToArray();
    }
}

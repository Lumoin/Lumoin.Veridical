using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Mdoc;
using System;
using System.Buffers;
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
/// signature plus a synthesized device half standing in for a live device credential), then runs OUR field-generic Fp256
/// <c>LongfellowZkProver.Prove</c>
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
/// assert-zero gates the GF(2)-conformant crown gate cannot fully stress: a missing negation is invisible
/// over GF(2), where <c>-x = x</c>, but surfaces as a genuine sign error over Fp256). The public inputs are
/// the first 900 witness elements reframed little-endian (the filler already lays the macs/av into the
/// public prefix from the chosen-constant keys, so no <c>generate_mac_key</c> splice is needed — this is the self-consistent gate, not the
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
/// prove-&gt;verify gate is marked <see cref="TestCategoryAttribute"/> <c>Slow</c>. The cheap pre-check
/// (<see cref="TheWitnessSatisfiesTheImportedSigCircuit"/>) evaluates the circuit on the witness through
/// <c>EvaluateCircuit</c> (the reference's <c>eval_circuit</c>: every layer's quad form, the output-zero
/// assertion and every assert-zero gate) and stays in the default suite to catch filler/sign bugs without
/// paying for the full prove.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowRealSigCircuitProveTests: IDisposable
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


    /// <summary>The relative path to the compressed real mdoc circuit stream that <see cref="ParseSignatureCircuit"/> imports the P-256 signature circuit from.</summary>
    private const string RawGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-raw.gz";

    /// <summary>The relative path to the real mdoc credential CBOR that <see cref="BuildWitnessColumn"/> extracts the issuer signature disclosure from.</summary>
    private const string CredentialRelativePath = "TestMaterial/Mdoc/mdoc-00.cbor";

    /// <summary>The circuit-stream field id the P-256 signature circuit is imported under, distinguishing it from the GF(2^128) hash circuit sharing the same stream.</summary>
    private const int Point256FieldId = 1;

    /// <summary>The on-wire element width, in bytes, of a P-256 scalar as the circuit-import reader lays it out.</summary>
    private const int Point256ElementBytes = 32;

    /// <summary>The in-memory scalar width in bytes, matching <see cref="Scalar.SizeBytes"/>, used for the witness column's per-element stride.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The width, in bytes, of the commitment root and hash digests this test compares and tampers with.</summary>
    private const int DigestSize = 32;

    /// <summary>The Ligero inverse rate for the deployed version-7 signature circuit, matching the reference implementation's kLigeroRatev7 parameter for that circuit version.</summary>
    private const int InverseRate = 7;

    /// <summary>The number of Ligero columns opened for the deployed version-7 signature circuit, matching the reference implementation's kLigeroNreqv7 parameter for that circuit version.</summary>
    private const int OpenedColumnCount = 132;

    /// <summary>The pinned encoded block length for the deployed version-7 signature circuit (num_attributes=1, version=7 in the reference implementation's zk_spec table), fed to both the prover and the verifier so the encoded block length matches.</summary>
    private const int SigBlockEncoded = 4096;

    /// <summary>The transcript version matching the deployed signature path; the transcript is baked at the 32-byte Fp256 width because this gate is single-field.</summary>
    private const int TranscriptVersion = 7;

    /// <summary>The fixed transcript seed distinguishing this gate's Fiat-Shamir transcript from every other test's.</summary>
    private static byte[] TranscriptSeed { get; } = System.Text.Encoding.ASCII.GetBytes("fp256-real-sig-e2e");

    /// <summary>The decompressed real circuit-stream bytes (~99 MB), decompressed once and shared across every import in this class.</summary>
    private static byte[] RawCircuitBytes { get; } = DecompressGzip(ReadFixture(RawGzipRelativePath));

    /// <summary>The P-256 base-field prime, read from the BigInteger reference backend.</summary>
    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    /// <summary>The validated Montgomery-backend addition delegate; addition is domain-linear, so this same delegate is correct for both the canonical and the Montgomery working domain.</summary>
    private static ScalarAddDelegate Fp256Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();

    /// <summary>The validated Montgomery-backend subtraction delegate; subtraction is domain-linear, so this same delegate is correct for both the canonical and the Montgomery working domain.</summary>
    private static ScalarSubtractDelegate Fp256Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();

    /// <summary>The canonical-domain multiplication delegate (2 CIOS per multiply), used by the circuit-satisfaction pre-check and the canonical leg of the byte-identity gate.</summary>
    private static ScalarMultiplyDelegate Fp256Multiply { get; } = P256BaseFieldMontgomeryBackend.GetMultiply();

    /// <summary>The canonical-domain inversion delegate, used by the circuit-satisfaction pre-check and the canonical leg of the byte-identity gate.</summary>
    private static ScalarInvertDelegate Fp256Invert { get; } = P256BaseFieldMontgomeryBackend.GetInvert();

    /// <summary>The Montgomery-domain multiplication delegate (1 CIOS per multiply), the one the production-intended sig prove/verify path runs over a Montgomery-lifted witness column, profile and FFT root.</summary>
    private static ScalarMultiplyDelegate Fp256MultiplyMontgomery { get; } = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();

    /// <summary>The Montgomery-domain inversion delegate, used alongside <see cref="Fp256MultiplyMontgomery"/> on the production-intended sig prove/verify path.</summary>
    private static ScalarInvertDelegate Fp256InvertMontgomery { get; } = P256BaseFieldMontgomeryBackend.GetInvertMontgomery();


    /// <summary>The MSTest context, used to surface the [Slow] prove/verify wall-clock through the test output.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// Verifies that the genuine real-credential witness column satisfies every layer and assert-zero gate
    /// of the imported P-256 signature circuit, evaluated directly through the circuit evaluator rather than
    /// a full Ligero prove, so a filler or arithmetic bug is caught without paying for the expensive path.
    /// </summary>
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
        using LongfellowSumcheckCircuit circuit = ParseSignatureCircuit();
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


    /// <summary>
    /// Proves the genuine real-credential witness through the field-generic Fp256 prover and confirms the
    /// field-generic verifier accepts the resulting envelope, then confirms that a tamper to both the proof
    /// bytes and the public input together makes the verifier reject with the Ligero soundness cause.
    /// </summary>
    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void OurVerifierAcceptsOurRealSigProofAndRejectsATamper()
    {
        using LongfellowSumcheckCircuit circuit = ParseSignatureCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Point256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes, SigBlockEncoded);

        byte[] canonicalColumn = BuildWitnessColumn();

        //The sig path runs in the Montgomery working domain: convert the filler's canonical
        //column element-wise to Montgomery once, and extract the public-input template from the Montgomery
        //column through the Montgomery profile's to_bytes_field (from_montgomery + reverse), so the LE wire
        //bytes are byte-identical to the canonical extraction.
        byte[] witnessColumn = MontgomeryColumn(canonicalColumn);
        byte[] publicInputs = MontgomeryPublicInputBytes(circuit, witnessColumn);

        //A warm prove+verify pair first (JIT, the FFT precompute, the field-backend warm-up), then the timed
        //pair, so the reported wall-clock is representative rather than dominated by first-call costs.
        using LongfellowZkProofEnvelope warm = ProveFp256(circuit, parameters, witnessColumn);
        AssertVerifies(circuit, parameters, warm.Bytes, publicInputs, expectedAccept: true);

        //Prove the real-credential witness through OUR field-generic Fp256 prover, then verify it through OUR
        //verifier on a fresh transcript: the headline self-consistent accept.
        Stopwatch proveWatch = Stopwatch.StartNew();
        using LongfellowZkProofEnvelope proof = ProveFp256(circuit, parameters, witnessColumn);
        proveWatch.Stop();

        Stopwatch verifyWatch = Stopwatch.StartNew();
        AssertVerifies(circuit, parameters, proof.Bytes, publicInputs, expectedAccept: true);
        verifyWatch.Stop();

        TestContext.WriteLine($"Real-credential Fp256 SIG circuit (ninputs=3739, npub_in=900, 21 layers): PROVE {proveWatch.ElapsedMilliseconds} ms, VERIFY {verifyWatch.ElapsedMilliseconds} ms (warm; Montgomery backend; rate=7/nreq=132/block_enc=4096).");

        //The tamper dual: flip a proof byte AND a public input. A flipped byte inside the sumcheck segment
        //(after the 32-byte root) diverges the replayed challenge stream, and a flipped public input moves
        //the FS setup and the input-binding constraint; either alone rejects, both together certainly do.
        using IMemoryOwner<byte> tamperedProofOwner = BaseMemoryPool.Shared.Rent(proof.Length);
        Span<byte> tamperedProof = tamperedProofOwner.Memory.Span[..proof.Length];
        proof.Bytes.CopyTo(tamperedProof);
        tamperedProof[DigestSize + 8] ^= 0x01;
        byte[] tamperedPublic = (byte[])publicInputs.Clone();
        tamperedPublic[Point256ElementBytes + 1] ^= 0x01;
        AssertVerifies(circuit, parameters, tamperedProof, tamperedPublic, expectedAccept: false);
    }


    /// <summary>
    /// Proves the same genuine real-signature witness twice under identical transcript seed and randomness —
    /// once through the canonical delegates/profile/root and once through the Montgomery ones — and asserts
    /// the two resulting proof envelopes are byte-identical, since the wire format is domain-independent.
    /// </summary>
    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void TheMontgomeryProveEmitsAByteIdenticalEnvelopeToTheCanonicalProve()
    {
        //THE KEY GATE: prove the genuine real-sig circuit over the SAME witness BOTH ways —
        //once with the canonical profile/delegates/of_scalar/root over the canonical column, once with the
        //Montgomery ones over the Montgomery-lifted column — under the SAME deterministic random source and
        //transcript seed, and assert the two envelopes are BYTE-IDENTICAL. The wire bytes are domain-independent
        //(to_bytes_field drops Montgomery->canonical), so the only correct outcome is identity; a divergence is
        //a missed seam (a value bypassing the profile / a non-lifted constant / a wrong root coordinate). This
        //is achievable because, within a single invocation with identical entropy, the only difference between
        //the two proves is the working domain — which the wire format erases. (Run-to-run the prove is
        //non-deterministic, so no hardcoded golden exists; the two-leg equality is the byte-identity claim.)
        using LongfellowSumcheckCircuit circuit = ParseSignatureCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Point256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes, SigBlockEncoded);

        byte[] canonicalColumn = BuildWitnessColumn();
        byte[] montgomeryColumn = MontgomeryColumn(canonicalColumn);

        using LongfellowZkProofEnvelope canonicalEnvelope = ProveFp256Canonical(circuit, parameters, canonicalColumn);
        using LongfellowZkProofEnvelope montgomeryEnvelope = ProveFp256(circuit, parameters, montgomeryColumn);

        string canonicalSha = Convert.ToHexStringLower(SHA256.HashData(canonicalEnvelope.Bytes));
        string montgomerySha = Convert.ToHexStringLower(SHA256.HashData(montgomeryEnvelope.Bytes));
        TestContext.WriteLine($"Canonical envelope SHA-256: {canonicalSha} ({canonicalEnvelope.Length} bytes)");
        TestContext.WriteLine($"Montgomery envelope SHA-256: {montgomerySha} ({montgomeryEnvelope.Length} bytes)");
        TestContext.WriteLine($"Byte-identical: {(canonicalSha == montgomerySha ? "yes" : "no")}");

        Assert.IsTrue(canonicalEnvelope.Bytes.SequenceEqual(montgomeryEnvelope.Bytes), "The Montgomery-domain prove must emit a byte-identical envelope to the canonical-domain prove over the same witness.");
    }


    /// <summary>
    /// Verifies that the Montgomery field profile's wire encode/decode round-trips to exactly the same
    /// little-endian bytes as the canonical profile, for every element of the genuine real-signature witness
    /// column — the byte-identity property the Montgomery/canonical conversion seam depends on.
    /// </summary>
    [TestMethod]
    public void TheMontgomeryProfileSeamIsWireByteIdenticalToTheCanonicalProfile()
    {
        //DETERMINISTIC BYTE-IDENTITY GATE: the Montgomery-domain Fp profile must emit and
        //read EXACTLY the same little-endian wire bytes as the canonical profile for the genuine real-sig
        //witness — the byte-identity property the Montgomery/canonical conversion seam depends on. (The full
        //real-sig prove envelope is not usable as a hardcoded golden because the Ligero prove draws fresh
        //randomness each run and so is non-deterministic run to run; this gate instead pins the part of the
        //pipeline that IS deterministic — the profile's wire encode/decode — which is the actual byte-identity
        //claim the converters make.)
        using LongfellowFieldProfile canonical = LongfellowFp256Encoding.CreateProfile(OfScalarFp256, InRangeFp256, BaseMemoryPool.Shared);
        using LongfellowFieldProfile montgomery = LongfellowFp256Encoding.CreateMontgomeryProfile(
            OfScalarFp256, InRangeFp256, P256BaseFieldMontgomeryBackend.ToMontgomery, P256BaseFieldMontgomeryBackend.FromMontgomery, BaseMemoryPool.Shared);

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


    /// <summary>
    /// Proves the real-credential witness column (a MONTGOMERY-domain column) through the field-generic
    /// prover with the Montgomery Fp256 encoding (the 1-CIOS path), the v7 rate/nreq and the pinned
    /// block_enc carried by the supplied parameters, with circuit owners released at test cleanup.
    /// Returns the pooled proof envelope; the caller disposes it.
    /// </summary>
    private LongfellowZkProofEnvelope ProveFp256(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] witnessColumn)
    {
        using LongfellowFieldProfile profile = NewMontgomeryProfile();
        using BaseMemoryPool fftPool = new();
        using Fp256RealFft fft = NewMontgomeryFp256Fft(fftPool);
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateMontgomeryEncoderFactory(
            fft, profile, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None, BaseMemoryPool.Shared, Fp256SimdBackend.BatchMultiplyMontgomery());
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp256(profile);

        //The circuit's quad-term coefficients are canonical; lift them to Montgomery so the shared sumcheck
        //multiplies a working-domain constant against the working-domain wires.
        LongfellowSumcheckCircuit montgomeryCircuit = CircuitScope.Lift(circuit, P256BaseFieldMontgomeryBackend.ToMontgomery);

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


    /// <summary>
    /// Produces a canonical-domain proof while retaining the FFT through every encoder callback: proves
    /// the same witness CANONICALLY (the 2-CIOS path), the byte-identity gate's canonical leg. The witness
    /// column is the canonical filler output, the profile/delegates/root are canonical. Returns the pooled
    /// proof envelope; the caller disposes it.
    /// </summary>
    private static LongfellowZkProofEnvelope ProveFp256Canonical(LongfellowSumcheckCircuit circuit, LongfellowLigeroParameters parameters, byte[] canonicalColumn)
    {
        using BaseMemoryPool fftPool = new();
        using Fp256RealFft fft = NewFp256Fft(fftPool);
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateEncoderFactory(
            fft, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, OfScalarFp256, CurveParameterSet.None, BaseMemoryPool.Shared);
        using LongfellowFieldProfile profile = LongfellowFp256Encoding.CreateProfile(OfScalarFp256, InRangeFp256, BaseMemoryPool.Shared);
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


    /// <summary>
    /// Verifies an Fp256 envelope through the field-generic verifier: parses com || sc || com_proof, absorbs
    /// the root, then drives VerifyFromAbsorbedRoot with the Fp256 encoder factory and profile, with
    /// circuit owners released at test cleanup.
    /// </summary>
    private void AssertVerifies(
        LongfellowSumcheckCircuit circuit,
        LongfellowLigeroParameters parameters,
        ReadOnlySpan<byte> proof,
        byte[] publicInputs,
        bool expectedAccept)
    {
        using LongfellowFieldProfile profile = NewMontgomeryProfile();
        using BaseMemoryPool fftPool = new();
        using Fp256RealFft fft = NewMontgomeryFp256Fft(fftPool);
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateMontgomeryEncoderFactory(
            fft, profile, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None, BaseMemoryPool.Shared, Fp256SimdBackend.BatchMultiplyMontgomery());
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForFp256(profile);

        //The circuit's quad-term coefficients are canonical; lift them to Montgomery so the verifier's shared
        //constraint build multiplies a working-domain constant against the working-domain wires.
        LongfellowSumcheckCircuit montgomeryCircuit = CircuitScope.Lift(circuit, P256BaseFieldMontgomeryBackend.ToMontgomery);

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


    /// <summary>Builds the genuine 3739-element SIG witness column: the REAL credential's issuer signature (via MdocDisclosure over mdoc-00.cbor, age_over_18) and a synthesized device half standing in for a live device credential.</summary>
    private static byte[] BuildWitnessColumn()
    {
        MdocDisclosure issuer = MdocDisclosure.Extract(ReadFixture(CredentialRelativePath), "org.iso.18013.5.1", "age_over_18");
        MdocDeviceSignatureSynth device = MdocDeviceSignatureSynth.Create();
        var filler = new MdocSignatureWitnessFiller();

        return filler.Fill(issuer, device);
    }


    /// <summary>
    /// Lifts a canonical witness column to the Montgomery working domain: each 32-byte element is converted
    /// in place through to_montgomery. The wire bytes the prover emits are domain-independent (the Montgomery
    /// profile's to_bytes_field drops back to canonical), so this is the only column-side change the
    /// production-intended Montgomery path needs.
    /// </summary>
    /// <param name="canonicalColumn">The canonical-domain witness column to lift.</param>
    /// <returns>A new array of the same length holding the Montgomery-domain witness column.</returns>
    private static byte[] MontgomeryColumn(byte[] canonicalColumn)
    {
        byte[] montgomery = new byte[canonicalColumn.Length];
        for(int i = 0; i < canonicalColumn.Length / ScalarSize; i++)
        {
            P256BaseFieldMontgomeryBackend.ToMontgomery(canonicalColumn.AsSpan(i * ScalarSize, ScalarSize), montgomery.AsSpan(i * ScalarSize, ScalarSize));
        }

        return montgomery;
    }


    /// <summary>
    /// Extracts the public-input element bytes from a Montgomery-domain column through the Montgomery
    /// profile's to_bytes_field (from_montgomery + reverse). The resulting little-endian wire bytes are
    /// byte-identical to the bytes the canonical column would produce, the byte-identity property the
    /// Montgomery conversion seam depends on.
    /// </summary>
    /// <param name="circuit">The circuit whose public-input count bounds how many elements are extracted.</param>
    /// <param name="montgomeryColumn">The Montgomery-domain witness column to extract public inputs from.</param>
    /// <returns>The public-input bytes, one <see cref="Point256ElementBytes"/>-wide little-endian element per public input.</returns>
    private static byte[] MontgomeryPublicInputBytes(LongfellowSumcheckCircuit circuit, byte[] montgomeryColumn)
    {
        using LongfellowFieldProfile profile = NewMontgomeryProfile();
        byte[] publicInputs = new byte[circuit.PublicInputCount * Point256ElementBytes];
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            profile.ToBytesField(montgomeryColumn.AsSpan(i * ScalarSize, ScalarSize), publicInputs.AsSpan(i * Point256ElementBytes, Point256ElementBytes));
        }

        return publicInputs;
    }


    /// <summary>Imports the P-256 signature circuit (the front of the raw circuit stream), with circuit owners released at test cleanup.</summary>
    private LongfellowSumcheckCircuit ParseSignatureCircuit()
    {
        bool parsed = CircuitScope.TryRead(RawCircuitBytes, Point256FieldId, Point256ElementBytes, out LongfellowSumcheckCircuit? signature, out _, out _);
        Assert.IsTrue(parsed, "The signature circuit must parse.");
        Assert.IsNotNull(signature);

        return signature;
    }


    /// <summary>
    /// Creates a deterministic byte source whose every 32-byte draw is below the field modulus: the most
    /// significant little-endian byte is zeroed, so the drawn integer is under 2^248, which is under the
    /// P-256 base-field prime, and so <c>of_bytes_field</c> accepts every draw unconditionally.
    /// </summary>
    /// <returns>A deterministic, reproducible source of below-modulus bytes for the prove/verify calls in this class.</returns>
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


    /// <summary>Computes of_scalar(u) over Fp256: writes the integer <paramref name="coordinate"/> reduced modulo the field prime as a canonical big-endian scalar.</summary>
    /// <param name="coordinate">The small integer coordinate to reduce and encode.</param>
    /// <param name="destination">The buffer receiving the canonical big-endian scalar; its length fixes the scalar width.</param>
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


    /// <summary>Implements fits(an): reports whether the canonical big-endian integer <paramref name="canonical"/> encodes is below the field modulus.</summary>
    /// <param name="canonical">The canonical big-endian scalar bytes to range-check.</param>
    /// <returns><see langword="true"/> when the encoded integer is below the P-256 base-field prime.</returns>
    private static bool InRangeFp256(ReadOnlySpan<byte> canonical) => new BigInteger(canonical, isUnsigned: true, isBigEndian: true) < Prime;


    /// <summary>Creates a fresh Fiat-Shamir transcript baked at the 32-byte Fp256 element width, seeded for this gate.</summary>
    /// <returns>A new transcript ready to absorb the commitment root and drive challenge derivation.</returns>
    private static LongfellowTranscript NewTranscript() =>
        new(TranscriptSeed, TranscriptVersion, Point256ElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Creates a caller-owned P-256 FFT whose root uses the supplied pool.</summary>
    /// <param name="pool">The caller pool supplying the root until the returned FFT is disposed.</param>
    private static Fp256RealFft NewFp256Fft(BaseMemoryPool pool)
    {
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnity(root);

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, OfScalarFp256, CurveParameterSet.None, pool);
    }


    /// <summary>
    /// Creates the Montgomery-domain Fp256 profile: of_scalar/of_bytes_field lift canonical to Montgomery,
    /// to_bytes_field drops Montgomery back to canonical, so the wire bytes stay byte-identical to the
    /// canonical profile.
    /// </summary>
    /// <returns>A new profile; the caller disposes it.</returns>
    private static LongfellowFieldProfile NewMontgomeryProfile() =>
        LongfellowFp256Encoding.CreateMontgomeryProfile(OfScalarFp256, InRangeFp256, P256BaseFieldMontgomeryBackend.ToMontgomery, P256BaseFieldMontgomeryBackend.FromMontgomery, BaseMemoryPool.Shared);


    /// <summary>
    /// Creates a caller-owned Montgomery FFT whose root uses the supplied pool: the production root is
    /// lifted per coordinate to its Montgomery residue, so the twiddle multiplies stay 1-CIOS in domain;
    /// the multiply/invert are the Montgomery-domain delegates.
    /// </summary>
    /// <param name="pool">The caller pool supplying the root until the returned FFT is disposed.</param>
    private static Fp256RealFft NewMontgomeryFp256Fft(BaseMemoryPool pool)
    {
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnityWorking(root, P256BaseFieldMontgomeryBackend.ToMontgomery);

        using LongfellowFieldProfile profile = NewMontgomeryProfile();

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, profile.OfScalar, CurveParameterSet.None, pool);
    }


    /// <summary>Computes a one-shot SHA-256 digest of <paramref name="input"/> into <paramref name="output"/>; <paramref name="hashFunction"/> is unused because this delegate only ever backs SHA-256.</summary>
    /// <param name="input">The bytes to hash.</param>
    /// <param name="output">The buffer receiving the 32-byte digest.</param>
    /// <param name="hashFunction">The requested hash algorithm name, ignored.</param>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) => SHA256.HashData(input, output);


    /// <summary>Concatenates two byte spans and hashes the result with SHA-256, the two-to-one compression this transcript's incremental hashing needs.</summary>
    /// <param name="left">The left operand, placed first in the concatenation.</param>
    /// <param name="right">The right operand, placed after <paramref name="left"/>.</param>
    /// <param name="output">The buffer receiving the 32-byte digest.</param>
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[left.Length + right.Length];
        left.CopyTo(combined);
        right.CopyTo(combined[left.Length..]);
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>Encrypts one block with unpadded AES-256-ECB, the block cipher this transcript's expansion is built from.</summary>
    /// <param name="key">The 256-bit AES key.</param>
    /// <param name="input">The plaintext block to encrypt.</param>
    /// <param name="output">The buffer receiving the ciphertext block.</param>
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    /// <summary>Reports whether every byte of <paramref name="scalar"/> is zero.</summary>
    /// <param name="scalar">The scalar bytes to test.</param>
    /// <returns><see langword="true"/> when no byte in <paramref name="scalar"/> is nonzero.</returns>
    private static bool IsZero(ReadOnlySpan<byte> scalar) => scalar.IndexOfAnyExcept((byte)0) < 0;


    /// <summary>Reads a test fixture file relative to the test project's output directory.</summary>
    /// <param name="relativePath">The fixture's path relative to the test project root.</param>
    /// <returns>The fixture's raw bytes.</returns>
    private static byte[] ReadFixture(string relativePath) => File.ReadAllBytes($"../../../{relativePath}");


    /// <summary>Decompresses a gzip-compressed byte array in full.</summary>
    /// <param name="gzip">The gzip-compressed source bytes.</param>
    /// <returns>The decompressed bytes.</returns>
    private static byte[] DecompressGzip(byte[] gzip)
    {
        using var input = new MemoryStream(gzip);
        using var gzipStream = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzipStream.CopyTo(output);

        return output.ToArray();
    }
}

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
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The dual-field PROVE-driver gate: OUR <see cref="LongfellowMdocProver"/> produces a
/// <c>[6 macs] ‖ [hash ZkProof] ‖ [sig ZkProof]</c> envelope over the REAL credential (mdoc-00) that OUR
/// <see cref="LongfellowMdocVerifier"/> ACCEPTS — the single full-prove number, the prove-side mirror of the
/// crown gate. Both circuits are imported from the same <c>mdoc-circuit-raw.gz</c> the crown gate parses (the
/// P-256 sig circuit field id 1 / 32-byte elements, then the GF(2^128) hash circuit field id 4 / 16-byte
/// elements from the continuation); the Ligero parameters use the reference v7 pinned <c>block_enc</c> pair
/// (hash 4151, sig 4096).
/// </summary>
/// <remarks>
/// <para>
/// The two full witness columns come from the RECONCILED fillers: the hash column from
/// <see cref="MdocHashWitnessFiller"/> (the SHARED chosen <c>ap</c> keys filled at [85112,85118), the public
/// mac/av region [945,952) left zero), and the sig column from
/// <see cref="MdocSignatureWitnessFiller.FillForDriver"/> (the REAL device tuple from
/// <see cref="MdocDeviceSignature"/>, the public mac/av region [4,900) left zero). Both circuits commit the
/// SAME <c>ap</c> and the SAME common values (the issuer hash <c>e_</c> and the real device key
/// <c>dpkx</c>/<c>dpky</c>); the cross-filler common-match pre-check asserts the two fillers agree before the
/// prove. The device-auth hash <c>e2</c> is the crown-gate fixture's <c>sig_template[3]</c> reversed from
/// little-endian to canonical big-endian — the reference's own <c>ne2</c>, which
/// <see cref="MdocDeviceAuthentication"/> reproduces from the session transcript.
/// </para>
/// <para>
/// The driver commits both circuits, absorbs both roots, squeezes the shared <c>a_v</c>, computes the six
/// macs <c>(a_v + ap_i)·m_i</c> over GF(2^128), patches both columns' public regions post-commit, and proves
/// both on the continuing transcript. The verifier's public-input TEMPLATES are the column public prefix
/// MINUS the mac/av tail — the hash template is <c>hashColumn[0..945]</c> as 945·16 little-endian bytes, the
/// sig template is <c>sigColumn[0..4]</c> as 4·32 little-endian bytes — and the driver/verifier append the
/// seven mac/av slots themselves. The end-to-end prove+verify over the genuine ~85k-wire hash circuit and the
/// P-256 sig circuit is the expensive Ligero-over-the-whole-R1CS path, so the accept gate is
/// <see cref="TestCategoryAttribute"/> <c>Slow</c>; the fast pre-checks (common-match, EvaluateCircuit after a
/// simulated patch, macs round-trip) stay in the default suite.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowMdocProveDriverTests: IDisposable
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


    /// <summary>The relative path to the reference anchor file recording the expected mac and template bytes for this dual-field envelope.</summary>
    private const string FixtureRelativePath = "TestMaterial/Longfellow/mdoc-zk-anchor-output.txt";

    /// <summary>The relative path to the gzip-compressed raw circuit stream carrying both the P-256 signature circuit and the GF(2^128) hash circuit.</summary>
    private const string RawGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-raw.gz";

    /// <summary>The relative path to the real mdoc credential this gate proves over.</summary>
    private const string CredentialRelativePath = "TestMaterial/Mdoc/mdoc-00.cbor";

    /// <summary>The field id tagging the P-256 signature circuit inside the imported dual-circuit stream.</summary>
    private const int Point256FieldId = 1;

    /// <summary>The field id tagging the GF(2^128) hash circuit inside the imported dual-circuit stream.</summary>
    private const int Gf2128FieldId = 4;

    /// <summary>The element width, in bytes, of a P-256 base-field scalar on the wire.</summary>
    private const int Point256ElementBytes = 32;

    /// <summary>The element width, in bytes, of a GF(2^128) scalar on the wire.</summary>
    private const int Gf2128ElementBytes = 16;

    /// <summary>The byte width of one scalar in this test's canonical scratch buffers, matching the library-wide scalar size.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The byte width of one mac key element as serialized in the envelope's mac prefix.</summary>
    private const int MacKeyBytes = 16;

    /// <summary>The Ligero code's inverse rate; the reference generation pins it to 7 for this circuit pair.</summary>
    private const int InverseRate = 7;

    /// <summary>The number of Ligero columns opened per proof; the reference generation pins it to 132 for this circuit pair.</summary>
    private const int OpenedColumnCount = 132;

    /// <summary>The encoded block length the hash circuit's Ligero parameters derive to, pinned to the reference's own value.</summary>
    private const int HashBlockEncoded = 4151;

    /// <summary>The encoded block length the signature circuit's Ligero parameters derive to, pinned to the reference's own value.</summary>
    private const int SigBlockEncoded = 4096;

    /// <summary>The full-field element width, in bytes, of the GF(2^128) hash circuit.</summary>
    private const int HashFieldBytes = 16;

    /// <summary>The subfield element width, in bytes, of the GF(2^16) (Production16) subfield the hash circuit's row encoding runs over.</summary>
    private const int HashSubFieldBytes = 2;

    /// <summary>The subfield boundary the hash circuit's row encoding uses, rebased from the wire's <c>npub_in</c> value (952) against the one-attribute column width (85112).</summary>
    private const int HashSubfieldBoundary = 85112 - 952;

    /// <summary>The element index in the hash column where the six macs and the av trailer begin (public input count 952 follows).</summary>
    private const int HashMacIndex = 945;

    /// <summary>The wire index in the signature column where the six macs and the av trailer begin.</summary>
    private const int SigMacIndex = 4;

    /// <summary>The number of leading hash-column elements that form the verifier's hash public-input template, excluding the mac and av trailer.</summary>
    private const int HashTemplateElementCount = 945;

    /// <summary>The number of leading signature-column elements that form the verifier's signature public-input template, excluding the mac and av trailer.</summary>
    private const int SigTemplateElementCount = 4;

    /// <summary>
    /// The element index, inside the version-7 one-attribute hash column's fill order (one at [0], attribute
    /// encoding at [1,785), now at [785,945), mac/av at [945,952), the three mac messages at [952,1720), then
    /// NumBlocks at [1720,1728) and the SHA preimage bits at [1728,22064) covering COSE1 bytes [18,2560)), of
    /// the first hashed COSE1 content byte. The SHA round witnesses are computed for this byte's original
    /// value, so flipping it no longer satisfies the SHA gadget: the disclosed MSO content is cryptographically
    /// bound.
    /// </summary>
    private const int HashedPreimageBitElement = 1728;

    /// <summary>
    /// The element index of the last SHA preimage bit (1728 + (2559-18)*8), which for this credential's short
    /// MSO sits well past the hashed blocks. Version 7 verifies those tail bytes are zero, so flipping this one
    /// non-zero is rejected.
    /// </summary>
    private const int HashedPreimageTailBitElement = 22056;

    /// <summary>The element width, in bytes, the shared transcript is baked at (the GF/a_v width); the sig side passes its own 32-byte profile per operation instead.</summary>
    private const int TranscriptElementBytes = 16;

    /// <summary>The Longfellow transcript wire version this dual-field driver speaks.</summary>
    private const int TranscriptVersion = 7;

    /// <summary>The fixed "current time" this gate proves attribute validity against.</summary>
    private static byte[] Now { get; } = Encoding.ASCII.GetBytes("2024-01-30T09:00:00Z");

    /// <summary>The deterministic dual-field session seed shared by both ends; the driver and verifier each build a fresh transcript from it.</summary>
    private static byte[] SessionSeed { get; } = Encoding.ASCII.GetBytes("mdoc-dual-field-prove-driver");

    /// <summary>The parsed key/value anchor fixture, loaded once and shared across every test in this class.</summary>
    private static System.Collections.Generic.Dictionary<string, string> Fixture { get; } = LoadFixture(FixtureRelativePath);

    /// <summary>The decompressed real-circuit bytes (~99 MB), decompressed once and shared across every circuit import in this class.</summary>
    private static byte[] RawCircuitBytes { get; } = DecompressGzip(ReadFixture(RawGzipRelativePath));

    /// <summary>The P-256 base-field order, used to reduce and range-check canonical scalars in this class's helpers.</summary>
    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    /// <summary>The GF(2^128) addition delegate the hash circuit's prover and verifier evaluate against.</summary>
    private static ScalarAddDelegate GfAdd { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) subtraction delegate the hash circuit's prover and verifier evaluate against.</summary>
    private static ScalarSubtractDelegate GfSubtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) multiplication delegate the hash circuit's prover and verifier evaluate against.</summary>
    private static ScalarMultiplyDelegate GfMultiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) inversion delegate the hash circuit's prover and verifier evaluate against.</summary>
    private static ScalarInvertDelegate GfInvert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>
    /// The P-256 base-field addition delegate from the validated Montgomery backend (byte-identical to the
    /// BigInteger reference, faster), the same backend the crown and real-signature gates use. Addition is
    /// domain-linear, so this canonical delegate also serves the Montgomery working domain unchanged.
    /// </summary>
    private static ScalarAddDelegate Fp256Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();

    /// <summary>
    /// The P-256 base-field subtraction delegate from the validated Montgomery backend. Subtraction is
    /// domain-linear, so this canonical delegate also serves the Montgomery working domain unchanged.
    /// </summary>
    private static ScalarSubtractDelegate Fp256Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();

    /// <summary>The canonical-domain P-256 multiplication delegate (2 CIOS); the EvaluateCircuit fast pre-check runs over the canonical sig column with it.</summary>
    private static ScalarMultiplyDelegate Fp256Multiply { get; } = P256BaseFieldMontgomeryBackend.GetMultiply();

    /// <summary>The canonical-domain P-256 inversion delegate (2 CIOS); the EvaluateCircuit fast pre-check runs over the canonical sig column with it.</summary>
    private static ScalarInvertDelegate Fp256Invert { get; } = P256BaseFieldMontgomeryBackend.GetInvert();

    /// <summary>The Montgomery-domain P-256 multiplication delegate (1 CIOS); the production-intended prove/verify path runs over a Montgomery-lifted sig column, profile and FFT root with it.</summary>
    private static ScalarMultiplyDelegate Fp256MultiplyMontgomery { get; } = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();

    /// <summary>The Montgomery-domain P-256 inversion delegate (1 CIOS); the production-intended prove/verify path runs over a Montgomery-lifted sig column, profile and FFT root with it.</summary>
    private static ScalarInvertDelegate Fp256InvertMontgomery { get; } = P256BaseFieldMontgomeryBackend.GetInvertMontgomery();


    /// <summary>The MSTest context, used to surface the [Slow] prove/verify wall-clock through the test output.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Verifies that the hash filler's little-endian common values and the signature filler's canonical big-endian common values agree byte-for-byte, and that the extracted device tuple recovers a genuine nonce point.</summary>
    [TestMethod]
    public void TheTwoFillersAgreeOnTheCommonValues()
    {
        //FAST PRE-CHECK (default suite): the cross-field MAC binding requires the hash and the sig columns to
        //commit the SAME three common values. The hash filler carries them as MacMessageE/Dpkx/Dpky
        //(to_bytes_field little-endian); the sig filler carries them as canonical big-endian. After the shared
        //convention they must be byte-identical, otherwise the macs bind different messages and the verify
        //fails deep in the Ligero check.
        byte[] credential = ReadFixture(CredentialRelativePath);
        MdocParsedDocument parsed = MdocParsedDocument.Parse(credential);
        MdocHashWitnessState state = MdocHashWitnessState.Compute(parsed, MdocRequestedAttribute.AgeOver18);

        MdocDisclosure issuer = MdocDisclosure.Extract(credential, "org.iso.18013.5.1", "age_over_18");
        MdocDeviceSignature device = MdocDeviceSignature.Extract(credential, DeviceHash());
        byte[] common = MdocSignatureWitnessFiller.CommonValues(issuer, device);

        //The sig common values are canonical big-endian; to_bytes_field (reverse to little-endian) must equal
        //the hash filler's MAC messages.
        AssertReversedEquals(state.MacMessageE, common.AsSpan(0, ScalarSize), "common e_ must match across fillers.");
        AssertReversedEquals(state.MacMessageDpkx, common.AsSpan(ScalarSize, ScalarSize), "common dpkx must match across fillers.");
        AssertReversedEquals(state.MacMessageDpky, common.AsSpan(2 * ScalarSize, ScalarSize), "common dpky must match across fillers.");

        //The extracted device tuple must be a genuine nonce point (RecoveredNoncePointMatches is the independent
        //oracle), otherwise the device VerifyWitness3 column would not close.
        Assert.IsTrue(device.RecoveredNoncePointMatches(), "The real device tuple must recover R2.x mod n == r2.");
    }


    /// <summary>Verifies that after simulating the driver's post-commit mac/av patch on both columns, the hash and signature circuits each evaluate to an all-zero output.</summary>
    [TestMethod]
    public void TheDriverColumnsSatisfyTheirCircuitsAfterASimulatedPatch()
    {
        //FAST PRE-CHECK (default suite): the driver's commit input columns have the public mac/av region
        //zeroed; the driver patches them post-commit from the transcript-squeezed a_v. Here we SIMULATE that
        //patch with a fixed a_v, compute the macs, patch both columns, and evaluate each circuit through the
        //reference's eval_circuit. A clean return proves the witness SATISFIES the circuit (A.w == b at every
        //layer) WITHOUT paying for the full Ligero prove — a filler/sign/extractor bug surfaces here cheaply.
        using LongfellowSumcheckCircuit hashCircuit = ParseHashCircuit(out _);
        using LongfellowSumcheckCircuit sigCircuit = ParseSignatureCircuit();

        byte[] hashColumn = BuildHashColumn();
        byte[] sigColumn = BuildSigColumn();

        Assert.AreEqual(hashCircuit.InputCount, hashColumn.Length / ScalarSize, "The hash column width must equal the hash circuit input count.");
        Assert.AreEqual(sigCircuit.InputCount, sigColumn.Length / ScalarSize, "The sig column width must equal the sig circuit input count.");
        Assert.AreEqual(MdocSignatureWitnessFiller.ElementCount, sigCircuit.InputCount, "The sig filler element count must equal the sig circuit ninputs.");
        Assert.AreEqual(MdocSignatureWitnessFiller.PublicInputCount, sigCircuit.PublicInputCount, "The sig filler public-input count must equal the sig circuit npub_in.");

        //A fixed a_v stands in for the squeezed key. Compute the macs from the SHARED common/ap, then patch.
        byte[] av = FixedAv();
        byte[] common = DriverCommonValues();
        byte[] ap = MdocSignatureWitnessFiller.ApKeyBytes();
        byte[] macs = new byte[6 * ScalarSize];
        byte[] macsBytes = new byte[6 * MacKeyBytes];
        LongfellowMdocProver.ComputeMacs(common, ap, av, GfAdd, GfMultiply, macs, macsBytes);

        PatchHashColumn(hashColumn, macs, av);
        PatchSigColumn(sigColumn, macs, av);

        using LongfellowWireTables hashTables = LongfellowSumcheckProver.EvaluateCircuit(hashCircuit, hashColumn, GfMultiply, GfAdd, CurveParameterSet.None, BaseMemoryPool.Shared);
        AssertOutputZero(hashTables, hashCircuit, "hash");

        using LongfellowWireTables sigTables = LongfellowSumcheckProver.EvaluateCircuit(sigCircuit, sigColumn, Fp256Multiply, Fp256Add, CurveParameterSet.None, BaseMemoryPool.Shared);
        AssertOutputZero(sigTables, sigCircuit, "sig");
    }


    /// <summary>Verifies that flipping a single bit in a private-witness element — a hashed MSO content byte, or a zero-padded SHA tail byte past the hashed blocks — makes the imported version-7 hash circuit reject the witness.</summary>
    [TestMethod]
    public void AForgingPrivateWitnessBreaksTheImportedVersion7HashCircuit()
    {
        //SOUNDNESS PROBE (default suite) for the mdoc attribute-forgery finding family the upstream security
        //reviews raised: Trail of Bits TOB-LIBZK-10 (assert_attribute compared only the first `len` bytes,
        //`len` a prover-controlled secret witness — set it small and forge any attribute) and the circuit-v6
        //under-constraint (the CBOR indices into the MSO and the MSO bytes past the correctly-hashed SHA block
        //were unconstrained — point the indices into that region and substitute values). Both are fixed IN the
        //circuit: version 6 added the SHA block-length range checks and the zero-padding check, version 7 is
        //the current generation this stack imports. Because this stack imports the fixed version-7 circuit
        //verbatim (mdoc-circuit-raw.gz, raw_rawsha pinned) rather than building circuits, the fix rides in the
        //imported constraints: a witness that alters a hashed MSO byte, a CBOR key index, or the
        //prover-controlled attribute compare-length no longer satisfies the circuit. The positive dual is
        //TheDriverColumnsSatisfyTheirCircuitsAfterASimulatedPatch (the clean witness evaluates to zero); here
        //each single-bit corruption of a PRIVATE witness element must drive at least one output wire off zero.
        using LongfellowSumcheckCircuit hashCircuit = ParseHashCircuit(out _);

        byte[] av = FixedAv();
        byte[] common = DriverCommonValues();
        byte[] ap = MdocSignatureWitnessFiller.ApKeyBytes();
        byte[] macs = new byte[6 * ScalarSize];
        byte[] macsBytes = new byte[6 * MacKeyBytes];
        LongfellowMdocProver.ComputeMacs(common, ap, av, GfAdd, GfMultiply, macs, macsBytes);

        //The private-witness corruption sites, as element indices into the version-7 one-attribute hash
        //column (past npub_in = 952, so private witness — public-input tampering is the crown gate's separate
        //probe): a hashed MSO content byte (the disclosed content is bound to the signed SHA digest, so a
        //prover cannot substitute MSO bytes to forge an attribute — the defense TOB-LIBZK-10 and the
        //circuit-v6 under-constraint fix protect) and a preimage tail byte past the hashed blocks (version 7's
        //zero-check on the SHA tail, the concrete circuit-v6 fix).
        (int element, string finding)[] sites =
        [
            (HashedPreimageBitElement, "a hashed MSO content byte (attribute-forgery defense, TOB-LIBZK-10)"),
            (HashedPreimageTailBitElement, "a non-zero SHA tail byte past the hashed blocks (circuit-v6 tail zero-check)"),
        ];

        foreach((int element, string finding) in sites)
        {
            byte[] forged = BuildHashColumn();
            PatchHashColumn(forged, macs, av);
            FlipBitWitness(forged, element);

            AssertForgeryRejected(hashCircuit, forged, $"A forged witness at {finding} must not satisfy the imported version-7 hash circuit.");
        }
    }


    /// <summary>Verifies that the 96-byte mac prefix the driver serializes round-trips through the envelope reader back to the canonical macs the driver computed.</summary>
    [TestMethod]
    public void TheMacsRoundTripThroughTheEnvelopeSplit()
    {
        //FAST PRE-CHECK (default suite): the 96-byte mac prefix the driver serializes (to_bytes_field of each
        //mac) must round-trip through the envelope reader's of_bytes_field back to the canonical macs the
        //driver computed — the prefix the verifier consumes is the prefix the prover wrote.
        byte[] av = FixedAv();
        byte[] common = DriverCommonValues();
        byte[] ap = MdocSignatureWitnessFiller.ApKeyBytes();
        byte[] macs = new byte[6 * ScalarSize];
        byte[] macsBytes = new byte[6 * MacKeyBytes];
        LongfellowMdocProver.ComputeMacs(common, ap, av, GfAdd, GfMultiply, macs, macsBytes);

        //A minimal envelope: the 96-byte mac prefix is enough for ReadMacs (it only touches the prefix).
        byte[] envelope = new byte[LongfellowMdocEnvelope.MacRegionBytes];
        macsBytes.CopyTo(envelope.AsSpan());

        byte[] readBack = new byte[6 * ScalarSize];
        LongfellowMdocEnvelope.ReadMacs(envelope, readBack);

        Assert.IsTrue(readBack.AsSpan().SequenceEqual(macs), "The envelope's mac prefix must round-trip to the canonical macs the driver computed.");
    }


    /// <summary>
    /// Verifies the full dual-field prove/verify gate: our driver proves a real credential envelope that our
    /// verifier accepts, and that flipping a byte in either the hash region or the signature region of the
    /// envelope makes the corresponding circuit's verification reject it.
    /// </summary>
    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void OurDriverProvesARealCredentialEnvelopeOurVerifierAccepts()
    {
        byte[] hashColumn = BuildHashColumn();

        //The sig path runs in the Montgomery working domain: lift the canonical sig column
        //element-wise to Montgomery once (the prover commits/patches it in domain), and extract the sig
        //public-input template from the Montgomery column through the Montgomery profile's to_bytes_field so the
        //LE wire bytes stay byte-identical to the canonical extraction. The hash side stays canonical.
        byte[] sigColumn = MontgomerySigColumn(BuildSigColumn());
        byte[] common = DriverCommonValues();
        byte[] ap = MdocSignatureWitnessFiller.ApKeyBytes();

        byte[] hashTemplate = HashTemplate(hashColumn);
        byte[] sigTemplate = MontgomerySigTemplate(sigColumn);

        //A warm prove first (JIT, the FFT precompute, the field-backend warm-up), then the timed prove, so the
        //reported wall-clock is representative rather than dominated by first-call costs.
        using LongfellowZkProofEnvelope warm = Prove(hashColumn, sigColumn, common, ap);
        AssertAccepts(warm.Bytes, hashTemplate, sigTemplate);

        Stopwatch proveWatch = Stopwatch.StartNew();
        using LongfellowZkProofEnvelope envelope = Prove(hashColumn, sigColumn, common, ap);
        proveWatch.Stop();

        Stopwatch verifyWatch = Stopwatch.StartNew();
        LongfellowMdocVerificationResult result = VerifyOnce(envelope.Bytes, hashTemplate, sigTemplate);
        verifyWatch.Stop();

        TestContext.WriteLine($"Dual-field mdoc PROVE->VERIFY over the real credential (hash ~85k wires, sig 3739/21 layers): PROVE {proveWatch.ElapsedMilliseconds} ms, VERIFY {verifyWatch.ElapsedMilliseconds} ms (warm; Montgomery sig backend; rate=7/nreq=132).");

        Assert.AreEqual(LongfellowMdocVerificationResult.Accepted, result, "Our verifier must accept our dual-field prove over the real credential.");

        //The tamper dual: a flipped byte well inside the hash ZkProof region must be HashRejected; a flipped
        //byte in the sig region must be SigRejected — proving each circuit's proof is actually checked.
        using IMemoryOwner<byte> hashTamperedOwner = BaseMemoryPool.Shared.Rent(envelope.Length);
        Span<byte> hashTampered = hashTamperedOwner.Memory.Span[..envelope.Length];
        envelope.Bytes.CopyTo(hashTampered);
        hashTampered[LongfellowMdocEnvelope.MacRegionBytes + 5000] ^= 0x01;
        Assert.AreEqual(LongfellowMdocVerificationResult.HashRejected, VerifyOnce(hashTampered, hashTemplate, sigTemplate), "A flipped hash-region byte must be rejected by the hash circuit verify.");

        using IMemoryOwner<byte> sigTamperedOwner = BaseMemoryPool.Shared.Rent(envelope.Length);
        Span<byte> sigTampered = sigTamperedOwner.Memory.Span[..envelope.Length];
        envelope.Bytes.CopyTo(sigTampered);
        sigTampered[envelope.Length - 5000] ^= 0x01;
        Assert.AreEqual(LongfellowMdocVerificationResult.SigRejected, VerifyOnce(sigTampered, hashTemplate, sigTemplate), "A flipped sig-region byte must be rejected by the sig circuit verify.");
    }


    /// <summary>
    /// Proves the dual-field envelope through our driver with a fresh transcript. This self-consistent
    /// prove-then-verify path uses the default test seed unless <paramref name="transcriptSeed"/> is supplied,
    /// in which case it uses the real ISO session transcript so a reference verifier deriving its own
    /// challenges from that same transcript accepts. Returns the pooled proof envelope; the caller disposes it.
    /// </summary>
    private LongfellowZkProofEnvelope Prove(byte[] hashColumn, byte[] sigColumn, byte[] common, byte[] ap, byte[]? transcriptSeed = null)
    {
        using Lch14AdditiveFft hashFft = NewGfFft();
        using LongfellowFieldProfile hashProfile = LongfellowGf2k128Encoding.CreateProfile(hashFft, BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec hashCodec = LongfellowSubfieldRunCodec.ForGf2k128(
            hashProfile, hashFft, HashSubFieldBytes, BaseMemoryPool.Shared);
        using BaseMemoryPool sigFftPool = new();
        using Fp256RealFft sigFft = NewFp256Fft(sigFftPool);
        using LongfellowFieldProfile sigProfile = NewMontgomerySigProfile();
        using LongfellowSubfieldRunCodec sigCodec = LongfellowSubfieldRunCodec.ForFp256(sigProfile);

        LongfellowMdocFieldProver hash = BuildHashProver(hashFft, hashProfile, hashCodec);
        LongfellowMdocFieldProver sig = BuildSigProver(sigFft, sigProfile, sigCodec);

        using LongfellowTranscript transcript = NewTranscript(transcriptSeed);

        return LongfellowMdocProver.Prove(
            hash, sig, hashColumn, sigColumn, NewCounterSource(), NewBelowModulusSource(), common, ap,
            HashMacIndex, SigMacIndex, transcript, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, BaseMemoryPool.Shared);
    }


    /// <summary>Asserts that the envelope verifies as accepted, releasing all circuit owners this verify allocates before returning.</summary>
    private void AssertAccepts(ReadOnlySpan<byte> envelope, byte[] hashTemplate, byte[] sigTemplate) =>
        Assert.AreEqual(LongfellowMdocVerificationResult.Accepted, VerifyOnce(envelope, hashTemplate, sigTemplate), "The driver envelope must be accepted.");


    /// <summary>Runs one full dual-field verify over the envelope with a fresh transcript and freshly built prover/verifier bundles, releasing all circuit owners before returning.</summary>
    private LongfellowMdocVerificationResult VerifyOnce(ReadOnlySpan<byte> envelope, byte[] hashTemplate, byte[] sigTemplate)
    {
        using Lch14AdditiveFft hashFft = NewGfFft();
        using LongfellowFieldProfile hashProfile = LongfellowGf2k128Encoding.CreateProfile(hashFft, BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec hashCodec = LongfellowSubfieldRunCodec.ForGf2k128(
            hashProfile, hashFft, HashSubFieldBytes, BaseMemoryPool.Shared);
        using BaseMemoryPool sigFftPool = new();
        using Fp256RealFft sigFft = NewFp256Fft(sigFftPool);
        using LongfellowFieldProfile sigProfile = NewMontgomerySigProfile();
        using LongfellowSubfieldRunCodec sigCodec = LongfellowSubfieldRunCodec.ForFp256(sigProfile);

        LongfellowMdocFieldVerifier hash = BuildHashVerifier(hashFft, hashProfile, hashCodec);
        LongfellowMdocFieldVerifier sig = BuildSigVerifier(sigFft, sigProfile, sigCodec);

        using LongfellowTranscript transcript = NewTranscript();

        LongfellowMdocVerifier.Verify(
            envelope, hash, sig, hashTemplate, sigTemplate, transcript,
            Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, BaseMemoryPool.Shared,
            out LongfellowMdocVerificationResult result);

        return result;
    }


    /// <summary>Builds the hash-circuit prover bundle over a freshly parsed circuit, releasing that circuit's ownership to this test's scope before returning.</summary>
    private LongfellowMdocFieldProver BuildHashProver(Lch14AdditiveFft fft, LongfellowFieldProfile profile, LongfellowSubfieldRunCodec codec)
    {
        LongfellowSumcheckCircuit? circuit = null;
        try
        {
            circuit = ParseHashCircuit(out _);
            LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, HashFieldBytes, HashSubFieldBytes, HashBlockEncoded);
            LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);

            var result = new LongfellowMdocFieldProver(circuit, parameters, encoderFactory, profile, codec, GfAdd, GfSubtract, GfMultiply, GfInvert, HashSubfieldBoundary, CurveParameterSet.None, Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate(), Gf2k128BatchBackend.GetBindQuadReduce(), Gf2k128BatchBackend.GetGatherMultiplyAccumulate());
            //The returned bundle borrows the circuit retained by this test's scope.
            circuit = null;

            return result;
        }
        finally
        {
            circuit?.Dispose();
        }
    }


    /// <summary>Builds the signature-circuit prover bundle, lifting the circuit's coefficients to the Montgomery domain to match the Montgomery-domain backends the prover uses.</summary>
    private LongfellowMdocFieldProver BuildSigProver(Fp256RealFft fft, LongfellowFieldProfile profile, LongfellowSubfieldRunCodec codec)
    {
        using LongfellowSumcheckCircuit circuit = ParseSignatureCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Point256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes, SigBlockEncoded);
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateMontgomeryEncoderFactory(
            fft, profile, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None, BaseMemoryPool.Shared, Fp256SimdBackend.BatchMultiplyMontgomery());

        //Lift the circuit's canonical quad-term coefficients to Montgomery form, matching the
        //Montgomery-domain backends the prover uses below.
        LongfellowSumcheckCircuit montgomeryCircuit = CircuitScope.Lift(circuit, P256BaseFieldMontgomeryBackend.ToMontgomery);

        return new LongfellowMdocFieldProver(montgomeryCircuit, parameters, encoderFactory, profile, codec, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, LongfellowFp256Encoding.SignatureSubfieldBoundary, CurveParameterSet.None, Fp256BatchMultiply: Fp256SimdBackend.BatchMultiplyMontgomery());
    }


    /// <summary>Builds the hash-circuit verifier bundle over a freshly parsed circuit, releasing that circuit's ownership to this test's scope before returning.</summary>
    private LongfellowMdocFieldVerifier BuildHashVerifier(Lch14AdditiveFft fft, LongfellowFieldProfile profile, LongfellowSubfieldRunCodec codec)
    {
        LongfellowSumcheckCircuit? circuit = null;
        try
        {
            circuit = ParseHashCircuit(out _);
            LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, HashFieldBytes, HashSubFieldBytes, HashBlockEncoded);
            LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);

            var result = new LongfellowMdocFieldVerifier(circuit, parameters, encoderFactory, profile, codec, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, Gf2k128BatchBackend.GetBindQuadReduce(), Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate());
            //The returned bundle borrows the circuit retained by this test's scope.
            circuit = null;

            return result;
        }
        finally
        {
            circuit?.Dispose();
        }
    }


    /// <summary>Builds the signature-circuit verifier bundle, lifting the circuit's coefficients to the Montgomery domain to match the Montgomery-domain backends the verifier uses.</summary>
    private LongfellowMdocFieldVerifier BuildSigVerifier(Fp256RealFft fft, LongfellowFieldProfile profile, LongfellowSubfieldRunCodec codec)
    {
        using LongfellowSumcheckCircuit circuit = ParseSignatureCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Point256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes, SigBlockEncoded);
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateMontgomeryEncoderFactory(
            fft, profile, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None, BaseMemoryPool.Shared, Fp256SimdBackend.BatchMultiplyMontgomery());

        //Lift the circuit's canonical quad-term coefficients to Montgomery form, matching the
        //Montgomery-domain backends the verifier uses below.
        LongfellowSumcheckCircuit montgomeryCircuit = CircuitScope.Lift(circuit, P256BaseFieldMontgomeryBackend.ToMontgomery);

        return new LongfellowMdocFieldVerifier(montgomeryCircuit, parameters, encoderFactory, profile, codec, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None, Fp256BatchMultiply: Fp256SimdBackend.BatchMultiplyMontgomery());
    }


    /// <summary>Builds the hash column from the shared filler: the chosen ap at [85112,85118) and the zeroed public mac/av region [945,952), exactly as the driver's commit input.</summary>
    private static byte[] BuildHashColumn()
    {
        byte[] credential = ReadFixture(CredentialRelativePath);
        using Lch14AdditiveFft fft = NewGfFft();
        var filler = new MdocHashWitnessFiller(fft, GfAdd);

        return filler.Fill(credential, MdocRequestedAttribute.AgeOver18, Now);
    }


    /// <summary>Builds the signature column from the shared filler: the real device tuple and the zeroed public mac/av region.</summary>
    private static byte[] BuildSigColumn()
    {
        byte[] credential = ReadFixture(CredentialRelativePath);
        MdocDisclosure issuer = MdocDisclosure.Extract(credential, "org.iso.18013.5.1", "age_over_18");
        MdocDeviceSignature device = MdocDeviceSignature.Extract(credential, DeviceHash());
        var filler = new MdocSignatureWitnessFiller();

        return filler.FillForDriver(issuer, device);
    }


    /// <summary>Returns the driver's three common values (e_, dpkx, dpky) as canonical big-endian scalars.</summary>
    private static byte[] DriverCommonValues()
    {
        byte[] credential = ReadFixture(CredentialRelativePath);
        MdocDisclosure issuer = MdocDisclosure.Extract(credential, "org.iso.18013.5.1", "age_over_18");
        MdocDeviceSignature device = MdocDeviceSignature.Extract(credential, DeviceHash());

        return MdocSignatureWitnessFiller.CommonValues(issuer, device);
    }


    /// <summary>Extracts the hash public-input template — hashColumn[0..945] as 945 little-endian 16-byte elements.</summary>
    private static byte[] HashTemplate(byte[] hashColumn)
    {
        byte[] template = new byte[HashTemplateElementCount * Gf2128ElementBytes];
        for(int i = 0; i < HashTemplateElementCount; i++)
        {
            ToBytesField(hashColumn.AsSpan(i * ScalarSize, ScalarSize), template.AsSpan(i * Gf2128ElementBytes, Gf2128ElementBytes), Gf2128ElementBytes);
        }

        return template;
    }


    /// <summary>Writes the simulated post-commit patch into the hash column: the six macs then av as canonical GF(2^128) elements at [945,952).</summary>
    private static void PatchHashColumn(byte[] hashColumn, byte[] macs, byte[] av)
    {
        for(int i = 0; i < 6; i++)
        {
            macs.AsSpan(i * ScalarSize, ScalarSize).CopyTo(hashColumn.AsSpan((HashMacIndex + i) * ScalarSize, ScalarSize));
        }

        av.CopyTo(hashColumn.AsSpan((HashMacIndex + 6) * ScalarSize, ScalarSize));
    }


    /// <summary>Writes the simulated post-commit patch into the signature column: each mac then av expanded to 128 one/zero wires starting at wire 4.</summary>
    private static void PatchSigColumn(byte[] sigColumn, byte[] macs, byte[] av)
    {
        byte[] one = new byte[ScalarSize];
        one[ScalarSize - 1] = 0x01;
        byte[] zero = new byte[ScalarSize];

        int si = SigMacIndex;
        for(int i = 0; i < 6; i++)
        {
            si = ExpandGfBits(macs.AsSpan(i * ScalarSize, ScalarSize), one, zero, sigColumn, si);
        }

        ExpandGfBits(av, one, zero, sigColumn, si);
    }


    /// <summary>Expands one GF(2^128) element into 128 one/zero wires (big-endian bit order) written into the signature column starting at <paramref name="wireIndex"/>, returning the next free wire index.</summary>
    private static int ExpandGfBits(ReadOnlySpan<byte> element, byte[] one, byte[] zero, byte[] sigColumn, int wireIndex)
    {
        for(int j = 0; j < 128; j++)
        {
            int bit = (element[ScalarSize - 1 - (j / 8)] >> (j % 8)) & 1;
            (bit == 1 ? one : zero).CopyTo(sigColumn.AsSpan(wireIndex * ScalarSize, ScalarSize));
            wireIndex++;
        }

        return wireIndex;
    }


    /// <summary>
    /// <c>e2</c> (<c>ne2</c>): the crown-gate fixture's <c>sig_template[3]</c> reversed from little-endian to
    /// canonical big-endian — the reference's own value, which <see cref="MdocDeviceAuthentication"/> reproduces
    /// from the session transcript.
    /// </summary>
    private static BigInteger DeviceHash()
    {
        byte[] sigTemplate = Convert.FromHexString(Fixture["sig_template"]);
        ReadOnlySpan<byte> littleEndian = sigTemplate.AsSpan(3 * Point256ElementBytes, Point256ElementBytes);
        byte[] canonical = new byte[ScalarSize];
        for(int i = 0; i < Point256ElementBytes; i++)
        {
            canonical[i] = littleEndian[Point256ElementBytes - 1 - i];
        }

        return new BigInteger(canonical, isUnsigned: true, isBigEndian: true);
    }


    /// <summary>Returns a fixed a_v standing in for the squeezed key in the EvaluateCircuit pre-check: a GF(2^128) constant in the canonical low 16 big-endian bytes.</summary>
    private static byte[] FixedAv()
    {
        byte[] littleEndian = Convert.FromHexString("a3f10e5572c4901bd6883f2147ac55e0");
        byte[] av = new byte[ScalarSize];
        for(int j = 0; j < MacKeyBytes; j++)
        {
            av[ScalarSize - 1 - j] = littleEndian[j];
        }

        return av;
    }


    /// <summary>Asserts that every output wire of the evaluated circuit is zero, the assert-zero relation a satisfying witness must produce.</summary>
    private static void AssertOutputZero(LongfellowWireTables tables, LongfellowSumcheckCircuit circuit, string side)
    {
        Span<byte> output = tables.OutputTable();
        for(int i = 0; i < circuit.OutputCount; i++)
        {
            Assert.IsTrue(IsZero(output.Slice(i * ScalarSize, ScalarSize)), $"The {side} circuit output wire {i} must be zero (the assert-zero relation).");
        }
    }


    /// <summary>
    /// Asserts that a forging witness is rejected, however the reference evaluator surfaces it: the assert-zero
    /// relation A·w == b is checked at every layer, so an inconsistent witness either raises an
    /// <see cref="InvalidOperationException"/> from an internal consistency check, or leaves an output wire
    /// non-zero. Both are valid rejection signals; only a clean evaluation with every output wire zero means
    /// the forgery satisfied the circuit.
    /// </summary>
    private static void AssertForgeryRejected(LongfellowSumcheckCircuit circuit, byte[] forgedColumn, string message)
    {
        try
        {
            using LongfellowWireTables tables = LongfellowSumcheckProver.EvaluateCircuit(circuit, forgedColumn, GfMultiply, GfAdd, CurveParameterSet.None, BaseMemoryPool.Shared);
            Span<byte> output = tables.OutputTable();
            for(int i = 0; i < circuit.OutputCount; i++)
            {
                if(!IsZero(output.Slice(i * ScalarSize, ScalarSize)))
                {
                    return;
                }
            }

            Assert.Fail(message);
        }
        catch(InvalidOperationException)
        {
        }
    }


    /// <summary>Flips one bit-decomposition witness element between the GF(2^128) one and zero the fillers push (one has the low byte set, zero is all-zero), a genuine value change at that column position.</summary>
    private static void FlipBitWitness(byte[] column, int element)
    {
        Span<byte> slot = column.AsSpan(element * ScalarSize, ScalarSize);
        bool wasZero = IsZero(slot);
        slot.Clear();
        if(wasZero)
        {
            slot[ScalarSize - 1] = 0x01;
        }
    }


    /// <summary>Returns whether every byte of the scalar is zero.</summary>
    private static bool IsZero(ReadOnlySpan<byte> scalar) => scalar.IndexOfAnyExcept((byte)0) < 0;


    /// <summary>Asserts that <paramref name="littleEndian"/> equals <paramref name="canonicalBigEndian"/> read back to front, failing with <paramref name="message"/> otherwise.</summary>
    private static void AssertReversedEquals(ReadOnlySpan<byte> littleEndian, ReadOnlySpan<byte> canonicalBigEndian, string message)
    {
        byte[] reversed = new byte[ScalarSize];
        for(int i = 0; i < ScalarSize; i++)
        {
            reversed[i] = canonicalBigEndian[ScalarSize - 1 - i];
        }

        Assert.IsTrue(littleEndian.SequenceEqual(reversed), message);
    }


    /// <summary>Parses the P-256 signature circuit from the raw circuit bytes, retaining its ownership in this test's circuit scope.</summary>
    private LongfellowSumcheckCircuit ParseSignatureCircuit()
    {
        bool parsed = CircuitScope.TryRead(RawCircuitBytes, Point256FieldId, Point256ElementBytes, out LongfellowSumcheckCircuit? signature, out _, out _);
        Assert.IsTrue(parsed, "The signature circuit must parse.");
        Assert.IsNotNull(signature);

        return signature;
    }


    /// <summary>Parses the GF(2^128) hash circuit from the continuation span following the signature circuit, retaining its ownership in this test's circuit scope.</summary>
    /// <param name="subfieldBoundary">Receives the hash circuit's subfield boundary as parsed from the stream.</param>
    private LongfellowSumcheckCircuit ParseHashCircuit(out int subfieldBoundary)
    {
        bool signatureParsed = CircuitScope.TryRead(RawCircuitBytes, Point256FieldId, Point256ElementBytes, out _, out _, out int signatureBytes);
        Assert.IsTrue(signatureParsed, "The signature circuit must parse before the hash circuit.");

        bool hashParsed = CircuitScope.TryRead(RawCircuitBytes.AsSpan(signatureBytes), Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? hash, out subfieldBoundary, out _);
        Assert.IsTrue(hashParsed, "The hash circuit must parse from the continuation span.");
        Assert.IsNotNull(hash);

        return hash;
    }


    /// <summary>Reverses a canonical big-endian scalar into its little-endian wire encoding, truncated to <paramref name="elementBytes"/>.</summary>
    private static void ToBytesField(ReadOnlySpan<byte> canonical, Span<byte> littleEndian, int elementBytes)
    {
        for(int i = 0; i < elementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }


    /// <summary>Reduces a small unsigned coordinate modulo the P-256 base-field order and writes it as a canonical big-endian scalar.</summary>
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


    /// <summary>Returns whether a canonical big-endian scalar is strictly less than the P-256 base-field order.</summary>
    private static bool InRangeFp256(ReadOnlySpan<byte> canonical) => new BigInteger(canonical, isUnsigned: true, isBigEndian: true) < Prime;


    /// <summary>Creates a deterministic byte source that fills its destination with an incrementing counter, wrapping modulo 256.</summary>
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


    /// <summary>Creates a deterministic byte source producing values that stay below the P-256 base-field order when read as a big-endian scalar, by zeroing the final byte of a 32-byte draw.</summary>
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


    /// <summary>Creates a fresh transcript seeded with <paramref name="seed"/>, or the default session seed when none is supplied.</summary>
    private static LongfellowTranscript NewTranscript(byte[]? seed = null) =>
        new(seed ?? SessionSeed, TranscriptVersion, TranscriptElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Creates a fresh GF(2^128) additive FFT over the Production16 subfield.</summary>
    private static Lch14AdditiveFft NewGfFft() =>
        new(Lch14Subfield.Production16, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>Creates the Montgomery-domain Fp256 profile: of_scalar/of_bytes_field lift canonical to Montgomery, to_bytes_field drops back, so the wire bytes stay byte-identical to the canonical profile. The caller disposes it.</summary>
    private static LongfellowFieldProfile NewMontgomerySigProfile() =>
        LongfellowFp256Encoding.CreateMontgomeryProfile(OfScalarFp256, InRangeFp256, P256BaseFieldMontgomeryBackend.ToMontgomery, P256BaseFieldMontgomeryBackend.FromMontgomery, BaseMemoryPool.Shared);


    /// <summary>
    /// Creates a caller-owned P-256 FFT whose root uses the supplied pool. The production root is lifted per
    /// coordinate to its Montgomery residue, and the multiply/invert are the Montgomery-domain delegates, so
    /// the twiddle multiplies stay 1-CIOS in domain.
    /// </summary>
    /// <param name="pool">The caller pool supplying the root until the returned FFT is disposed.</param>
    private static Fp256RealFft NewFp256Fft(BaseMemoryPool pool)
    {
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnityWorking(root, P256BaseFieldMontgomeryBackend.ToMontgomery);

        using LongfellowFieldProfile profile = NewMontgomerySigProfile();

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, profile.OfScalar, CurveParameterSet.None, pool);
    }


    /// <summary>
    /// Lifts a canonical signature column to the Montgomery working domain, element by element. The prover
    /// commits and patches the column in this domain; the verifier reads its template back through the
    /// Montgomery profile, so the emitted wire bytes stay domain-independent.
    /// </summary>
    private static byte[] MontgomerySigColumn(byte[] canonicalColumn)
    {
        byte[] montgomery = new byte[canonicalColumn.Length];
        for(int i = 0; i < canonicalColumn.Length / ScalarSize; i++)
        {
            P256BaseFieldMontgomeryBackend.ToMontgomery(canonicalColumn.AsSpan(i * ScalarSize, ScalarSize), montgomery.AsSpan(i * ScalarSize, ScalarSize));
        }

        return montgomery;
    }


    /// <summary>
    /// Extracts the signature public-input template from a Montgomery-domain column through the Montgomery
    /// profile's to_bytes_field (from_montgomery, then reversed to little-endian), so the wire bytes are
    /// byte-identical to extracting the same template over the canonical column.
    /// </summary>
    private static byte[] MontgomerySigTemplate(byte[] montgomeryColumn)
    {
        using LongfellowFieldProfile profile = NewMontgomerySigProfile();
        byte[] template = new byte[SigTemplateElementCount * Point256ElementBytes];
        for(int i = 0; i < SigTemplateElementCount; i++)
        {
            profile.ToBytesField(montgomeryColumn.AsSpan(i * ScalarSize, ScalarSize), template.AsSpan(i * Point256ElementBytes, Point256ElementBytes));
        }

        return template;
    }


    /// <summary>Computes a one-shot SHA-256 digest of <paramref name="input"/> into <paramref name="output"/>, ignoring the caller-supplied hash-function label.</summary>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) => SHA256.HashData(input, output);


    /// <summary>Computes the SHA-256 digest of <paramref name="left"/> concatenated with <paramref name="right"/>, the two-to-one compression the Merkle layers use.</summary>
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[left.Length + right.Length];
        left.CopyTo(combined);
        right.CopyTo(combined[left.Length..]);
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>Encrypts one AES-256 ECB block under <paramref name="key"/>, the transcript's Fiat-Shamir expansion primitive.</summary>
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    /// <summary>Reads a test-material fixture file's raw bytes, resolved relative to the test's output directory.</summary>
    private static byte[] ReadFixture(string relativePath) => File.ReadAllBytes($"../../../{relativePath}");


    /// <summary>Decompresses a gzip-compressed byte array in full.</summary>
    private static byte[] DecompressGzip(byte[] gzip)
    {
        using var input = new MemoryStream(gzip);
        using var gzipStream = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzipStream.CopyTo(output);

        return output.ToArray();
    }


    /// <summary>Loads a <c>key=value</c> anchor fixture file into a dictionary, skipping blank lines and lines without a separator.</summary>
    private static System.Collections.Generic.Dictionary<string, string> LoadFixture(string relativePath)
    {
        string path = $"../../../{relativePath}";
        var map = new System.Collections.Generic.Dictionary<string, string>(StringComparer.Ordinal);
        foreach(string line in File.ReadAllLines(path))
        {
            if(line.Length == 0)
            {
                continue;
            }

            int separator = line.IndexOf('=', StringComparison.Ordinal);
            if(separator < 0)
            {
                continue;
            }

            map[line[..separator]] = line[(separator + 1)..];
        }

        return map;
    }
}

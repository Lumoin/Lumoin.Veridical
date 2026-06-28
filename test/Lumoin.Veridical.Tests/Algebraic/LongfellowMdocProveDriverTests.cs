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
/// little-endian to canonical big-endian (the spike's <c>ne2</c>; the byte-exact transcript-hash CBOR walk is
/// the reference's, captured in that fixture).
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
internal sealed class LongfellowMdocProveDriverTests
{
    private const string FixtureRelativePath = "TestMaterial/Longfellow/mdoc-zk-anchor-output.txt";
    private const string RawGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-raw.gz";
    private const string CredentialRelativePath = "TestMaterial/Mdoc/mdoc-00.cbor";

    private const int Point256FieldId = 1;
    private const int Gf2128FieldId = 4;
    private const int Point256ElementBytes = 32;
    private const int Gf2128ElementBytes = 16;

    private const int ScalarSize = Scalar.SizeBytes;
    private const int MacKeyBytes = 16;

    //The reference v7 Ligero pair and the pinned block_enc (hash 4151, sig 4096).
    private const int InverseRate = 7;
    private const int OpenedColumnCount = 132;
    private const int HashBlockEncoded = 4151;
    private const int SigBlockEncoded = 4096;

    //GF(2^128) hash circuit: 16-byte full field, GF(2^16) = Production16 subfield (2 bytes).
    private const int HashFieldBytes = 16;
    private const int HashSubFieldBytes = 2;

    //The reference's ZkProver rebases subfield_boundary by npub_in: hash 85112 - 952.
    private const int HashSubfieldBoundary = 85112 - 952;

    //The public mac/av region: hash macs at 945 (six macs then av, npub_in = 952); sig macs at wire 4.
    private const int HashMacIndex = 945;
    private const int SigMacIndex = 4;
    private const int HashTemplateElementCount = 945;
    private const int SigTemplateElementCount = 4;

    //The transcript is baked at the GF/a_v width 16 (the sig side passes its 32-byte profile per-op).
    private const int TranscriptElementBytes = 16;
    private const int TranscriptVersion = 7;

    private static readonly byte[] Now = Encoding.ASCII.GetBytes("2024-01-30T09:00:00Z");

    //A deterministic dual-field session seed (the same seed both ends; the driver and verifier each build a
    //fresh transcript from it).
    private static readonly byte[] SessionSeed = Encoding.ASCII.GetBytes("mdoc-dual-field-prove-driver");

    private static System.Collections.Generic.Dictionary<string, string> Fixture { get; } = LoadFixture(FixtureRelativePath);

    //The decompressed real-circuit bytes (~99 MB); decompress once and share across the imports.
    private static byte[] RawCircuitBytes { get; } = DecompressGzip(ReadFixture(RawGzipRelativePath));

    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    private static ScalarAddDelegate GfAdd { get; } = Gf2k128Backend.GetAdd();

    private static ScalarSubtractDelegate GfSubtract { get; } = Gf2k128Backend.GetSubtract();

    private static ScalarMultiplyDelegate GfMultiply { get; } = Gf2k128Backend.GetMultiply();

    private static ScalarInvertDelegate GfInvert { get; } = Gf2k128Backend.GetInvert();

    //The Fp256 sig path rides the validated Montgomery base-field backend (byte-identical to the BigInteger
    //reference, faster), the same backend the crown/real-sig gates use. Add/Subtract are domain-linear, so the
    //canonical delegates serve both the canonical and the Montgomery working domain unchanged.
    private static ScalarAddDelegate Fp256Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();

    private static ScalarSubtractDelegate Fp256Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();

    //The canonical-domain multiply/invert (2 CIOS): the EvaluateCircuit fast pre-check runs over the canonical
    //sig column.
    private static ScalarMultiplyDelegate Fp256Multiply { get; } = P256BaseFieldMontgomeryBackend.GetMultiply();

    private static ScalarInvertDelegate Fp256Invert { get; } = P256BaseFieldMontgomeryBackend.GetInvert();

    //The Montgomery-domain multiply/invert (Perf Increment 1, 1 CIOS): the production-intended prove/verify path
    //runs over a Montgomery-lifted sig column, profile and FFT root.
    private static ScalarMultiplyDelegate Fp256MultiplyMontgomery { get; } = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();

    private static ScalarInvertDelegate Fp256InvertMontgomery { get; } = P256BaseFieldMontgomeryBackend.GetInvertMontgomery();


    /// <summary>The MSTest context, used to surface the [Slow] prove/verify wall-clock through the test output.</summary>
    public TestContext TestContext { get; set; } = null!;


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

        //The extracted device tuple must be a genuine nonce point (the spike's independent oracle), otherwise
        //the device VerifyWitness3 column would not close.
        Assert.IsTrue(device.RecoveredNoncePointMatches(), "The real device tuple must recover R2.x mod n == r2.");
    }


    [TestMethod]
    public void TheDriverColumnsSatisfyTheirCircuitsAfterASimulatedPatch()
    {
        //FAST PRE-CHECK (default suite): the driver's commit input columns have the public mac/av region
        //zeroed; the driver patches them post-commit from the transcript-squeezed a_v. Here we SIMULATE that
        //patch with a fixed a_v, compute the macs, patch both columns, and evaluate each circuit through the
        //reference's eval_circuit. A clean return proves the witness SATISFIES the circuit (A.w == b at every
        //layer) WITHOUT paying for the full Ligero prove — a filler/sign/extractor bug surfaces here cheaply.
        LongfellowSumcheckCircuit hashCircuit = ParseHashCircuit(out _);
        LongfellowSumcheckCircuit sigCircuit = ParseSignatureCircuit();

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


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void OurDriverProvesARealCredentialEnvelopeOurVerifierAccepts()
    {
        byte[] hashColumn = BuildHashColumn();

        //The sig path runs in the Montgomery working domain (Perf Increment 1): lift the canonical sig column
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
        byte[] warm = Prove(hashColumn, sigColumn, common, ap);
        AssertAccepts(warm, hashTemplate, sigTemplate);

        Stopwatch proveWatch = Stopwatch.StartNew();
        byte[] envelope = Prove(hashColumn, sigColumn, common, ap);
        proveWatch.Stop();

        Stopwatch verifyWatch = Stopwatch.StartNew();
        LongfellowMdocVerificationResult result = VerifyOnce(envelope, hashTemplate, sigTemplate);
        verifyWatch.Stop();

        TestContext.WriteLine($"Dual-field mdoc PROVE->VERIFY over the real credential (hash ~85k wires, sig 3739/21 layers): PROVE {proveWatch.ElapsedMilliseconds} ms, VERIFY {verifyWatch.ElapsedMilliseconds} ms (warm; Montgomery sig backend; rate=7/nreq=132).");

        Assert.AreEqual(LongfellowMdocVerificationResult.Accepted, result, "Our verifier must accept our dual-field prove over the real credential.");

        //The tamper dual: a flipped byte well inside the hash ZkProof region must be HashRejected; a flipped
        //byte in the sig region must be SigRejected — proving each circuit's proof is actually checked.
        byte[] hashTampered = (byte[])envelope.Clone();
        hashTampered[LongfellowMdocEnvelope.MacRegionBytes + 5000] ^= 0x01;
        Assert.AreEqual(LongfellowMdocVerificationResult.HashRejected, VerifyOnce(hashTampered, hashTemplate, sigTemplate), "A flipped hash-region byte must be rejected by the hash circuit verify.");

        byte[] sigTampered = (byte[])envelope.Clone();
        sigTampered[envelope.Length - 5000] ^= 0x01;
        Assert.AreEqual(LongfellowMdocVerificationResult.SigRejected, VerifyOnce(sigTampered, hashTemplate, sigTemplate), "A flipped sig-region byte must be rejected by the sig circuit verify.");
    }


    //Proves the dual-field envelope through OUR driver with a fresh transcript from the session seed. The
    //reverse Docker gate passes the REAL ISO session transcript (the crown fixture's "transcript" blob) so the
    //reference's run_mdoc_verifier — which derives its challenges from that same session transcript — accepts;
    //the prove-driver's self-consistent prove->verify uses the default test seed.
    private static byte[] Prove(byte[] hashColumn, byte[] sigColumn, byte[] common, byte[] ap, byte[]? transcriptSeed = null)
    {
        using Lch14AdditiveFft hashFft = NewGfFft();
        using LongfellowSubfieldRunCodec hashCodec = LongfellowSubfieldRunCodec.ForGf2k128(
            LongfellowGf2k128Encoding.CreateProfile(hashFft), hashFft, HashSubFieldBytes, BaseMemoryPool.Shared);
        Fp256RealFft sigFft = NewFp256Fft();
        using LongfellowSubfieldRunCodec sigCodec = LongfellowSubfieldRunCodec.ForFp256(NewMontgomerySigProfile());

        LongfellowMdocFieldProver hash = BuildHashProver(hashFft, hashCodec);
        LongfellowMdocFieldProver sig = BuildSigProver(sigFft, sigCodec);

        using LongfellowTranscript transcript = NewTranscript(transcriptSeed);

        return LongfellowMdocProver.Prove(
            hash, sig, hashColumn, sigColumn, NewCounterSource(), NewBelowModulusSource(), common, ap,
            HashMacIndex, SigMacIndex, transcript, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, BaseMemoryPool.Shared);
    }


    //Produces the validated dual-field envelope over the real credential for the REVERSE Docker interop gate
    //(ours -> Google's run_mdoc_verifier). PURE: it builds the columns + proves and RETURNS the bytes — the IO
    //(writing the dump file the C++ harness reads) lives in the Benchmarks console driver, never in the test
    //project (the no-IO-in-tests discipline). The bytes are the same envelope
    //OurDriverProvesARealCredentialEnvelopeOurVerifierAccepts proves and OUR verifier accepts.
    internal static byte[] ReverseGateEnvelope()
    {
        byte[] hashColumn = BuildHashColumn();
        byte[] sigColumn = MontgomerySigColumn(BuildSigColumn());
        byte[] common = DriverCommonValues();
        byte[] ap = MdocSignatureWitnessFiller.ApKeyBytes();

        //Seed with the REAL ISO session transcript (the crown fixture's "transcript" blob, the same seed the
        //crown gate verifies the reference's proof under) so the reference's run_mdoc_verifier — which derives its
        //challenges from that session transcript — opens the same Ligero columns and accepts.
        byte[] sessionTranscript = Convert.FromHexString(Fixture["transcript"]);

        return Prove(hashColumn, sigColumn, common, ap, sessionTranscript);
    }


    private static void AssertAccepts(byte[] envelope, byte[] hashTemplate, byte[] sigTemplate) =>
        Assert.AreEqual(LongfellowMdocVerificationResult.Accepted, VerifyOnce(envelope, hashTemplate, sigTemplate), "The driver envelope must be accepted.");


    //Runs one full dual-field verify over the envelope with a fresh transcript and fresh bundles.
    private static LongfellowMdocVerificationResult VerifyOnce(byte[] envelope, byte[] hashTemplate, byte[] sigTemplate)
    {
        using Lch14AdditiveFft hashFft = NewGfFft();
        using LongfellowSubfieldRunCodec hashCodec = LongfellowSubfieldRunCodec.ForGf2k128(
            LongfellowGf2k128Encoding.CreateProfile(hashFft), hashFft, HashSubFieldBytes, BaseMemoryPool.Shared);
        Fp256RealFft sigFft = NewFp256Fft();
        using LongfellowSubfieldRunCodec sigCodec = LongfellowSubfieldRunCodec.ForFp256(NewMontgomerySigProfile());

        LongfellowMdocFieldVerifier hash = BuildHashVerifier(hashFft, hashCodec);
        LongfellowMdocFieldVerifier sig = BuildSigVerifier(sigFft, sigCodec);

        using LongfellowTranscript transcript = NewTranscript();

        LongfellowMdocVerifier.Verify(
            envelope, hash, sig, hashTemplate, sigTemplate, transcript,
            Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, BaseMemoryPool.Shared,
            out LongfellowMdocVerificationResult result);

        return result;
    }


    private static LongfellowMdocFieldProver BuildHashProver(Lch14AdditiveFft fft, LongfellowSubfieldRunCodec codec)
    {
        LongfellowSumcheckCircuit circuit = ParseHashCircuit(out _);
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, HashFieldBytes, HashSubFieldBytes, HashBlockEncoded);
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);

        return new LongfellowMdocFieldProver(circuit, parameters, encoderFactory, profile, codec, GfAdd, GfSubtract, GfMultiply, GfInvert, HashSubfieldBoundary, CurveParameterSet.None, Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate(), Gf2k128BatchBackend.GetBindQuadReduce(), Gf2k128BatchBackend.GetGatherMultiplyAccumulate());
    }


    private static LongfellowMdocFieldProver BuildSigProver(Fp256RealFft fft, LongfellowSubfieldRunCodec codec)
    {
        LongfellowSumcheckCircuit circuit = ParseSignatureCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Point256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes, SigBlockEncoded);
        LongfellowFieldProfile profile = NewMontgomerySigProfile();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateMontgomeryEncoderFactory(
            fft, profile, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None, BaseMemoryPool.Shared, Fp256SimdBackend.BatchMultiplyMontgomery());

        //Lift the circuit's canonical quad-term coefficients to Montgomery (Perf Increment 1).
        LongfellowSumcheckCircuit montgomeryCircuit = circuit.LiftCoefficientsToWorking(P256BaseFieldMontgomeryBackend.ToMontgomery);

        return new LongfellowMdocFieldProver(montgomeryCircuit, parameters, encoderFactory, profile, codec, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, LongfellowFp256Encoding.SignatureSubfieldBoundary, CurveParameterSet.None, Fp256BatchMultiply: Fp256SimdBackend.BatchMultiplyMontgomery());
    }


    private static LongfellowMdocFieldVerifier BuildHashVerifier(Lch14AdditiveFft fft, LongfellowSubfieldRunCodec codec)
    {
        LongfellowSumcheckCircuit circuit = ParseHashCircuit(out _);
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, HashFieldBytes, HashSubFieldBytes, HashBlockEncoded);
        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);

        return new LongfellowMdocFieldVerifier(circuit, parameters, encoderFactory, profile, codec, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, Gf2k128BatchBackend.GetBindQuadReduce(), Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate());
    }


    private static LongfellowMdocFieldVerifier BuildSigVerifier(Fp256RealFft fft, LongfellowSubfieldRunCodec codec)
    {
        LongfellowSumcheckCircuit circuit = ParseSignatureCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Point256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes, SigBlockEncoded);
        LongfellowFieldProfile profile = NewMontgomerySigProfile();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateMontgomeryEncoderFactory(
            fft, profile, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None, BaseMemoryPool.Shared, Fp256SimdBackend.BatchMultiplyMontgomery());

        //Lift the circuit's canonical quad-term coefficients to Montgomery (Perf Increment 1).
        LongfellowSumcheckCircuit montgomeryCircuit = circuit.LiftCoefficientsToWorking(P256BaseFieldMontgomeryBackend.ToMontgomery);

        return new LongfellowMdocFieldVerifier(montgomeryCircuit, parameters, encoderFactory, profile, codec, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, CurveParameterSet.None, Fp256BatchMultiply: Fp256SimdBackend.BatchMultiplyMontgomery());
    }


    //The hash column from the reconciled filler: the SHARED chosen ap at [85112,85118) and the zeroed public
    //mac/av region [945,952) — the driver's commit input (NO dump splice).
    private static byte[] BuildHashColumn()
    {
        byte[] credential = ReadFixture(CredentialRelativePath);
        using Lch14AdditiveFft fft = NewGfFft();
        var filler = new MdocHashWitnessFiller(fft, GfAdd);

        return filler.Fill(credential, MdocRequestedAttribute.AgeOver18, Now);
    }


    //The sig column from the reconciled filler: the REAL device tuple and the zeroed public mac/av region.
    private static byte[] BuildSigColumn()
    {
        byte[] credential = ReadFixture(CredentialRelativePath);
        MdocDisclosure issuer = MdocDisclosure.Extract(credential, "org.iso.18013.5.1", "age_over_18");
        MdocDeviceSignature device = MdocDeviceSignature.Extract(credential, DeviceHash());
        var filler = new MdocSignatureWitnessFiller();

        return filler.FillForDriver(issuer, device);
    }


    //The driver's three common values (e_, dpkx, dpky) as canonical big-endian scalars.
    private static byte[] DriverCommonValues()
    {
        byte[] credential = ReadFixture(CredentialRelativePath);
        MdocDisclosure issuer = MdocDisclosure.Extract(credential, "org.iso.18013.5.1", "age_over_18");
        MdocDeviceSignature device = MdocDeviceSignature.Extract(credential, DeviceHash());

        return MdocSignatureWitnessFiller.CommonValues(issuer, device);
    }


    //The hash public-input template: hashColumn[0..945] as 945 * 16 little-endian element bytes.
    private static byte[] HashTemplate(byte[] hashColumn)
    {
        byte[] template = new byte[HashTemplateElementCount * Gf2128ElementBytes];
        for(int i = 0; i < HashTemplateElementCount; i++)
        {
            ToBytesField(hashColumn.AsSpan(i * ScalarSize, ScalarSize), template.AsSpan(i * Gf2128ElementBytes, Gf2128ElementBytes), Gf2128ElementBytes);
        }

        return template;
    }


    //The simulated-patch hash region write: macs then av as canonical GF elements at [945,952).
    private static void PatchHashColumn(byte[] hashColumn, byte[] macs, byte[] av)
    {
        for(int i = 0; i < 6; i++)
        {
            macs.AsSpan(i * ScalarSize, ScalarSize).CopyTo(hashColumn.AsSpan((HashMacIndex + i) * ScalarSize, ScalarSize));
        }

        av.CopyTo(hashColumn.AsSpan((HashMacIndex + 6) * ScalarSize, ScalarSize));
    }


    //The simulated-patch sig region write: each mac then av as 128 one/zero wires at wire 4.
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


    //e2 (ne2): the crown-gate fixture's sig_template[3] reversed from little-endian to canonical big-endian
    //(the spike's recipe). The byte-exact transcript-hash CBOR walk is the reference's, captured in the fixture.
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


    //A fixed a_v standing in for the squeezed key in the EvaluateCircuit pre-check: a GF(2^128) constant in
    //the canonical low 16 big-endian bytes.
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


    private static void AssertOutputZero(LongfellowWireTables tables, LongfellowSumcheckCircuit circuit, string side)
    {
        Span<byte> output = tables.OutputTable();
        for(int i = 0; i < circuit.OutputCount; i++)
        {
            Assert.IsTrue(IsZero(output.Slice(i * ScalarSize, ScalarSize)), $"The {side} circuit output wire {i} must be zero (the assert-zero relation).");
        }
    }


    private static bool IsZero(ReadOnlySpan<byte> scalar) => scalar.IndexOfAnyExcept((byte)0) < 0;


    private static void AssertReversedEquals(ReadOnlySpan<byte> littleEndian, ReadOnlySpan<byte> canonicalBigEndian, string message)
    {
        byte[] reversed = new byte[ScalarSize];
        for(int i = 0; i < ScalarSize; i++)
        {
            reversed[i] = canonicalBigEndian[ScalarSize - 1 - i];
        }

        Assert.IsTrue(littleEndian.SequenceEqual(reversed), message);
    }


    private static LongfellowSumcheckCircuit ParseSignatureCircuit()
    {
        bool parsed = LongfellowCircuitReader.TryRead(RawCircuitBytes, Point256FieldId, Point256ElementBytes, out LongfellowSumcheckCircuit? signature, out _, out _);
        Assert.IsTrue(parsed, "The signature circuit must parse.");
        Assert.IsNotNull(signature);

        return signature;
    }


    private static LongfellowSumcheckCircuit ParseHashCircuit(out int subfieldBoundary)
    {
        bool signatureParsed = LongfellowCircuitReader.TryRead(RawCircuitBytes, Point256FieldId, Point256ElementBytes, out _, out _, out int signatureBytes);
        Assert.IsTrue(signatureParsed, "The signature circuit must parse before the hash circuit.");

        bool hashParsed = LongfellowCircuitReader.TryRead(RawCircuitBytes.AsSpan(signatureBytes), Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? hash, out subfieldBoundary, out _);
        Assert.IsTrue(hashParsed, "The hash circuit must parse from the continuation span.");
        Assert.IsNotNull(hash);

        return hash;
    }


    private static void ToBytesField(ReadOnlySpan<byte> canonical, Span<byte> littleEndian, int elementBytes)
    {
        for(int i = 0; i < elementBytes; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }


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


    private static bool InRangeFp256(ReadOnlySpan<byte> canonical) => new BigInteger(canonical, isUnsigned: true, isBigEndian: true) < Prime;


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


    private static LongfellowTranscript NewTranscript(byte[]? seed = null) =>
        new(seed ?? SessionSeed, TranscriptVersion, TranscriptElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    private static Lch14AdditiveFft NewGfFft() =>
        new(Lch14Subfield.Production16, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, BaseMemoryPool.Shared);


    //The Montgomery-domain Fp256 profile (Perf Increment 1): of_scalar/of_bytes_field lift canonical->Montgomery,
    //to_bytes_field drops back, so the wire bytes are byte-identical to the canonical profile.
    private static LongfellowFieldProfile NewMontgomerySigProfile() =>
        LongfellowFp256Encoding.CreateMontgomeryProfile(OfScalarFp256, InRangeFp256, P256BaseFieldMontgomeryBackend.ToMontgomery, P256BaseFieldMontgomeryBackend.FromMontgomery);


    //The Montgomery-domain real-FFT: the production root is lifted per coordinate to its Montgomery residue and
    //the multiply/invert are the Montgomery-domain delegates, so the twiddle multiplies stay 1-CIOS in domain.
    private static Fp256RealFft NewFp256Fft()
    {
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnityWorking(root, P256BaseFieldMontgomeryBackend.ToMontgomery);

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Fp256Add, Fp256Subtract, Fp256MultiplyMontgomery, Fp256InvertMontgomery, NewMontgomerySigProfile().OfScalar, CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    //Lifts a canonical sig column to the Montgomery working domain (each 32-byte element through to_montgomery):
    //the prover commits and patches it in domain, the verifier reads its template back through the Montgomery
    //profile, and the emitted wire bytes are domain-independent.
    private static byte[] MontgomerySigColumn(byte[] canonicalColumn)
    {
        byte[] montgomery = new byte[canonicalColumn.Length];
        for(int i = 0; i < canonicalColumn.Length / ScalarSize; i++)
        {
            P256BaseFieldMontgomeryBackend.ToMontgomery(canonicalColumn.AsSpan(i * ScalarSize, ScalarSize), montgomery.AsSpan(i * ScalarSize, ScalarSize));
        }

        return montgomery;
    }


    //The sig public-input template extracted from a MONTGOMERY column through the Montgomery profile's
    //to_bytes_field (from_montgomery + reverse): the LE wire bytes are byte-identical to SigTemplate over the
    //canonical column.
    private static byte[] MontgomerySigTemplate(byte[] montgomeryColumn)
    {
        LongfellowFieldProfile profile = NewMontgomerySigProfile();
        byte[] template = new byte[SigTemplateElementCount * Point256ElementBytes];
        for(int i = 0; i < SigTemplateElementCount; i++)
        {
            profile.ToBytesField(montgomeryColumn.AsSpan(i * ScalarSize, ScalarSize), template.AsSpan(i * Point256ElementBytes, Point256ElementBytes));
        }

        return template;
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


    private static byte[] ReadFixture(string relativePath) => File.ReadAllBytes($"../../../{relativePath}");


    private static byte[] DecompressGzip(byte[] gzip)
    {
        using var input = new MemoryStream(gzip);
        using var gzipStream = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzipStream.CopyTo(output);

        return output.ToArray();
    }


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

using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The CROWN GATE — the end-to-end proof that our dual-field
/// <see cref="LongfellowMdocVerifier"/> ACCEPTS the REAL reference mdoc <c>ZkProof</c> envelope. The fixture
/// (<c>mdoc-zk-anchor-output.txt</c>) is a real
/// <c>org.iso.18013.5.1.mDL</c> credential's proof: the version-7 envelope
/// <c>[6 macs] ‖ [hash ZkProof] ‖ [sig ZkProof]</c>, the session transcript seed, and the two public-input
/// templates the reference's <c>fill_attributes</c> / <c>fill_signature_inputs</c> emit (the hash template
/// <c>[one, attrs…, now-bits]</c> = 945 sixteen-byte elements; the sig template <c>[one, pkX, pkY, e2]</c> =
/// 4 thirty-two-byte elements, <c>e2</c> already inside it). The driver appends the six macs and the squeezed
/// <c>a_v</c> to each template, runs the size guard, and verifies both circuits on one shared transcript.
/// </summary>
/// <remarks>
/// <para>
/// Both circuits are imported from the same <c>mdoc-circuit-raw.gz</c> the circuit-import reader gate parses: the P-256
/// signature circuit first (field id 1, 32-byte elements), then the GF(2^128) hash circuit from the
/// continuation span (field id 4, 16-byte elements). The Ligero parameters use the reference v7 pair
/// (<c>kLigeroRatev7 = 7</c>, <c>kLigeroNreqv7 = 132</c>) for both circuits. The hash side rides the
/// GF(2^128) additive-FFT encoding (16-byte framing, 2-byte GF(2^16) subfield); the sig side rides the Fp256
/// real-FFT encoding (32-byte framing, the prime field as its own subfield). The transcript is seeded with
/// the reference's transcript blob at version 7 and the GF/<c>a_v</c> baked width of 16; the sig side passes
/// its 32-byte profile per operation (the cross-field driver's per-call field-width parameter).
/// </para>
/// <para>
/// The end-to-end verify over the genuine ~85k-wire hash circuit and the P-256 signature circuit is the
/// expensive Ligero-over-the-whole-R1CS path, so the accept gate is marked <see cref="TestCategoryAttribute"/>
/// <c>Slow</c>. The tamper dual flips one byte in the hash-proof region and (separately) one byte in the
/// sig-proof region of the envelope and asserts the verdict is not Accepted, with a fresh
/// transcript per call.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowMdocCrownGateTests: IDisposable
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


    /// <summary>The repository-relative path to the reference mdoc envelope, transcript seed, and public-input template fixture this test verifies against.</summary>
    private const string FixtureRelativePath = "TestMaterial/Longfellow/mdoc-zk-anchor-output.txt";

    /// <summary>The repository-relative path to the gzip-compressed dual-circuit stream (signature circuit followed by hash circuit) this test imports.</summary>
    private const string RawGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-raw.gz";

    /// <summary>The field id tagging the P-256 signature circuit inside the imported circuit stream.</summary>
    private const int Point256FieldId = 1;

    /// <summary>The field id tagging the GF(2^128) hash circuit inside the imported circuit stream.</summary>
    private const int Gf2128FieldId = 4;

    /// <summary>The on-wire element width, in bytes, of a P-256 base-field element.</summary>
    private const int Point256ElementBytes = 32;

    /// <summary>The on-wire element width, in bytes, of a GF(2^128) element.</summary>
    private const int Gf2128ElementBytes = 16;

    /// <summary>The Ligero code's inverse rate (the reference implementation's <c>kLigeroRatev7</c>), shared by both circuits.</summary>
    private const int InverseRate = 7;

    /// <summary>The number of Ligero columns opened per proof (the reference implementation's <c>kLigeroNreqv7</c>), shared by both circuits.</summary>
    private const int OpenedColumnCount = 132;

    /// <summary>The reference implementation's pinned <c>block_enc</c> value for the hash circuit (<c>kZkSpecs</c>, num_attributes=1, version=7). The reference implementation stores this value in its <c>ZkSpecStruct</c> and feeds it to both its prover and verifier rather than deriving it at runtime (zk_spec.cc lines 47-49 give <c>{1, 7, 4151, 4096}</c>; mdoc_zk.cc lines 615-616 in the prover and 659-662 in the verifier).</summary>
    private const int HashBlockEncoded = 4151;

    /// <summary>The reference implementation's pinned <c>block_enc</c> value for the signature circuit, precomputed and distributed the same way as <see cref="HashBlockEncoded"/>.</summary>
    private const int SigBlockEncoded = 4096;

    /// <summary>The byte width of a full GF(2^128) field element in the hash circuit.</summary>
    private const int HashFieldBytes = 16;

    /// <summary>The byte width of the GF(2^16) (<c>Production16</c>) subfield element used by the hash circuit's Ligero encoding.</summary>
    private const int HashSubFieldBytes = 2;

    /// <summary>The element width, in bytes, the shared transcript is constructed with (the GF(2^128) side's width; the signature side instead passes its own 32-byte profile per operation).</summary>
    private const int TranscriptElementBytes = 16;

    /// <summary>The reference transcript format version this fixture's seed was produced under.</summary>
    private const int TranscriptVersion = 7;

    /// <summary>The expected byte length of the fixture's transcript seed.</summary>
    private const int TranscriptBytes = 117;

    /// <summary>The expected byte length of the fixture's <c>ZkProof</c> envelope.</summary>
    private const int EnvelopeBytes = 359924;

    /// <summary>The expected element count of the fixture's hash public-input template.</summary>
    private const int HashTemplateElementCount = 945;

    /// <summary>The expected element count of the fixture's signature public-input template.</summary>
    private const int SigTemplateElementCount = 4;

    /// <summary>The key/value fixture data loaded from <see cref="FixtureRelativePath"/>: the envelope, transcript seed, and public-input templates, each keyed by name and hex-encoded.</summary>
    private static Dictionary<string, string> Fixture { get; } = LoadFixture(FixtureRelativePath);

    /// <summary>The decompressed dual-circuit stream (signature circuit followed by hash circuit), roughly 99 MB; decompressed once and shared by every import in this test class.</summary>
    private static byte[] RawCircuitBytes { get; } = DecompressGzip(ReadFixture(RawGzipRelativePath));

    /// <summary>The P-256 base-field order, used to reduce values into the field's canonical range.</summary>
    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    /// <summary>The GF(2^128) field addition delegate the hash circuit's arithmetic uses.</summary>
    private static ScalarAddDelegate GfAdd { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) field subtraction delegate the hash circuit's arithmetic uses.</summary>
    private static ScalarSubtractDelegate GfSubtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) field multiplication delegate the hash circuit's arithmetic uses.</summary>
    private static ScalarMultiplyDelegate GfMultiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) field inversion delegate the hash circuit's arithmetic uses.</summary>
    private static ScalarInvertDelegate GfInvert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>The P-256 base-field addition delegate from the Montgomery backend: the base-field backend validated byte-identical to the BigInteger reference and the one production code uses. Addition is domain-linear, so this same delegate serves both the canonical and the Montgomery-encoded call sites. This test's <c>[Slow]</c> category runs it in isolation rather than in the parallel gadget suites that stay on the reference backend, so an Accept verdict here is itself proof that the Montgomery arithmetic is byte-identical to the canonical reference.</summary>
    private static ScalarAddDelegate Fp256Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();

    /// <summary>The P-256 base-field subtraction delegate from the Montgomery backend; like <see cref="Fp256Add"/>, subtraction is domain-linear and shared unchanged between the canonical and Montgomery-encoded paths.</summary>
    private static ScalarSubtractDelegate Fp256Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();

    /// <summary>The P-256 base-field Montgomery multiplication delegate (one CIOS reduction per multiply): the sig path runs entirely in the Montgomery working domain, so this is the multiply that runs on every constraint. The verifier lifts the reference proof and the signature template's canonical little-endian wire bytes into this domain via the profile's <c>of_bytes_field</c> conversion; the verdict must still be Accept while operating in Montgomery, which is the byte-anchored gate this test exercises.</summary>
    private static ScalarMultiplyDelegate Fp256Multiply { get; } = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();

    /// <summary>The P-256 base-field Montgomery inversion delegate, used wherever the signature circuit's constraints require a field inverse in the Montgomery working domain.</summary>
    private static ScalarInvertDelegate Fp256Invert { get; } = P256BaseFieldMontgomeryBackend.GetInvertMontgomery();


    /// <summary>Verifies that <see cref="LongfellowMdocVerifier"/> accepts the genuine reference mdoc <c>ZkProof</c> envelope end to end, checking both the GF(2^128) hash circuit and the P-256 signature circuit against the fixture's pinned region sizes.</summary>
    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void OurVerifierAcceptsTheRealReferenceMdocProof()
    {
        byte[] envelope = HexBlob("envelope");
        byte[] transcriptSeed = HexBlob("transcript");
        byte[] hashTemplate = HexBlob("hash_template");
        byte[] sigTemplate = HexBlob("sig_template");

        //Pin the fixture's region sizes so a corrupted fixture fails loudly here, not deep in the verifier.
        Assert.HasCount(EnvelopeBytes, envelope, "The envelope must be the reference's proof_len bytes.");
        Assert.HasCount(TranscriptBytes, transcriptSeed, "The transcript seed must be 117 bytes.");
        Assert.HasCount(HashTemplateElementCount * Gf2128ElementBytes, hashTemplate, "The hash template is 945 * 16 element bytes.");
        Assert.HasCount(SigTemplateElementCount * Point256ElementBytes, sigTemplate, "The sig template is 4 * 32 element bytes.");

        //One shared FFT/profile/codec lifetime per side, held for the whole verify.
        using Lch14AdditiveFft hashFft = NewGfFft();
        using LongfellowFieldProfile hashProfile = LongfellowGf2k128Encoding.CreateProfile(hashFft, BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec hashCodec = LongfellowSubfieldRunCodec.ForGf2k128(
            hashProfile, hashFft, HashSubFieldBytes, BaseMemoryPool.Shared);

        using BaseMemoryPool sigFftPool = new();

        using Fp256RealFft sigFft = NewFp256Fft(sigFftPool);
        using LongfellowFieldProfile sigProfile = NewMontgomerySigProfile();
        using LongfellowSubfieldRunCodec sigCodec = LongfellowSubfieldRunCodec.ForFp256(sigProfile);

        LongfellowMdocFieldVerifier hash = BuildHashBundle(hashFft, hashProfile, hashCodec, out _);
        LongfellowMdocFieldVerifier sig = BuildSigBundle(sigFft, sigProfile, sigCodec);

        using LongfellowTranscript transcript = NewTranscript(transcriptSeed);

        bool ok = LongfellowMdocVerifier.Verify(
            envelope,
            hash,
            sig,
            hashTemplate,
            sigTemplate,
            transcript,
            Sha256TwoToOne,
            Sha256OneShot,
            WellKnownHashAlgorithms.Sha256,
            BaseMemoryPool.Shared,
            out LongfellowMdocVerificationResult result);

        Assert.AreEqual(LongfellowMdocVerificationResult.Accepted, result, "Our verifier must accept the real reference mdoc proof.");
        Assert.IsTrue(ok, "The verdict must be true on the real reference mdoc proof.");
    }


    /// <summary>Verifies that flipping one byte in the hash-proof region, the sig-proof region, the hash public input, or the sig public input each causes the corresponding circuit's verify to reject, while the unmodified envelope establishes the accepted baseline those rejections are compared against.</summary>
    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void ATamperedRealReferenceMdocProofIsRejected()
    {
        byte[] envelope = HexBlob("envelope");
        byte[] transcriptSeed = HexBlob("transcript");
        byte[] hashTemplate = HexBlob("hash_template");
        byte[] sigTemplate = HexBlob("sig_template");

        //Establish the untampered verdict for this envelope so the tamper assertions compare against it: a
        //tampered envelope must never verify (and must never produce a "better" verdict than the original).
        //The baseline MUST be Accepted, otherwise the tamper rejections below would be vacuous (a verdict
        //that already rejects the clean envelope proves nothing about the tamper).
        LongfellowMdocVerificationResult baseline = VerifyOnce(envelope, transcriptSeed, hashTemplate, sigTemplate);
        Assert.AreEqual(LongfellowMdocVerificationResult.Accepted, baseline, "The clean envelope must be accepted, otherwise the tamper assertions are vacuous.");

        //A flipped byte well inside the hash ZkProof region ([6 macs] = 96, then the 32-byte hash root and
        //the hash sumcheck/Ligero segment) must be rejected BY THE HASH CIRCUIT VERIFY (not a parse-stop or
        //a guard-stop): the flip lands squarely in the hash circuit's bytes, so the verdict must be the
        //hash circuit's own rejection — proving the GF(2^128) hash proof is actually checked.
        const int MacRegionBytes = 96;
        byte[] hashTampered = (byte[])envelope.Clone();
        hashTampered[MacRegionBytes + 5000] ^= 0x01;
        LongfellowMdocVerificationResult hashResult = VerifyOnce(hashTampered, transcriptSeed, hashTemplate, sigTemplate);
        Assert.AreEqual(LongfellowMdocVerificationResult.HashRejected, hashResult, "A flipped hash-region byte must be rejected by the hash circuit verify.");

        //A flipped byte in the back portion of the envelope (the sig ZkProof region) must be rejected BY THE
        //SIG CIRCUIT VERIFY — proving the Fp256 signature proof is actually checked (and reached: the sig
        //verify runs only after the hash verify passes on the shared transcript).
        byte[] sigTampered = (byte[])envelope.Clone();
        sigTampered[envelope.Length - 5000] ^= 0x01;
        LongfellowMdocVerificationResult sigResult = VerifyOnce(sigTampered, transcriptSeed, hashTemplate, sigTemplate);
        Assert.AreEqual(LongfellowMdocVerificationResult.SigRejected, sigResult, "A flipped sig-region byte must be rejected by the sig circuit verify.");

        //A flipped PUBLIC INPUT in the hash template (an attribute element, past the leading 'one' element)
        //must be rejected by the hash circuit verify: the proof is bound to the claimed attributes, so a
        //changed attribute breaks the binding even with a genuine proof. This is the soundness property that
        //matters — the proof cannot be reused against a different claim.
        byte[] hashPubTampered = (byte[])hashTemplate.Clone();
        hashPubTampered[Gf2128ElementBytes + 3] ^= 0x01;
        LongfellowMdocVerificationResult hashPubResult = VerifyOnce(envelope, transcriptSeed, hashPubTampered, sigTemplate);
        Assert.AreEqual(LongfellowMdocVerificationResult.HashRejected, hashPubResult, "A flipped hash public input must be rejected by the hash circuit verify.");

        //A flipped PUBLIC INPUT in the sig template (the pkX element, past the leading 'one' element) must be
        //rejected by the sig circuit verify: the signature proof is bound to the claimed public key.
        byte[] sigPubTampered = (byte[])sigTemplate.Clone();
        sigPubTampered[Point256ElementBytes + 3] ^= 0x01;
        LongfellowMdocVerificationResult sigPubResult = VerifyOnce(envelope, transcriptSeed, hashTemplate, sigPubTampered);
        Assert.AreEqual(LongfellowMdocVerificationResult.SigRejected, sigPubResult, "A flipped sig public input must be rejected by the sig circuit verify.");
    }


    /// <summary>Runs one full dual-field verify over the given envelope with a fresh transcript and fresh bundles, with circuit owners released at test cleanup.</summary>
    private LongfellowMdocVerificationResult VerifyOnce(byte[] envelope, byte[] transcriptSeed, byte[] hashTemplate, byte[] sigTemplate)
    {
        using Lch14AdditiveFft hashFft = NewGfFft();
        using LongfellowFieldProfile hashProfile = LongfellowGf2k128Encoding.CreateProfile(hashFft, BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec hashCodec = LongfellowSubfieldRunCodec.ForGf2k128(
            hashProfile, hashFft, HashSubFieldBytes, BaseMemoryPool.Shared);

        using BaseMemoryPool sigFftPool = new();

        using Fp256RealFft sigFft = NewFp256Fft(sigFftPool);
        using LongfellowFieldProfile sigProfile = NewMontgomerySigProfile();
        using LongfellowSubfieldRunCodec sigCodec = LongfellowSubfieldRunCodec.ForFp256(sigProfile);

        LongfellowMdocFieldVerifier hash = BuildHashBundle(hashFft, hashProfile, hashCodec, out _);
        LongfellowMdocFieldVerifier sig = BuildSigBundle(sigFft, sigProfile, sigCodec);

        using LongfellowTranscript transcript = NewTranscript(transcriptSeed);

        LongfellowMdocVerifier.Verify(
            envelope, hash, sig, hashTemplate, sigTemplate, transcript,
            Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, BaseMemoryPool.Shared,
            out LongfellowMdocVerificationResult result);

        return result;
    }


    /// <summary>
    /// Builds the GF(2^128) hash bundle: the imported hash circuit, the v7 Ligero parameters, the GF
    /// encoding, and the borrowed field profile and subfield-run codec (both owned and disposed by the
    /// caller), with circuit owners released at test cleanup.
    /// </summary>
    private LongfellowMdocFieldVerifier BuildHashBundle(Lch14AdditiveFft fft, LongfellowFieldProfile profile, LongfellowSubfieldRunCodec codec, out int subfieldBoundary)
    {
        LongfellowSumcheckCircuit? circuit = null;
        try
        {
            circuit = ParseHashCircuit(out subfieldBoundary);
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


    /// <summary>
    /// Builds the P-256 base-field signature bundle: the imported signature circuit, the v7 Ligero
    /// parameters, the Fp256 encoding, and the borrowed field profile and subfield-run codec (both owned
    /// and disposed by the caller), with circuit owners released at test cleanup.
    /// </summary>
    private LongfellowMdocFieldVerifier BuildSigBundle(Fp256RealFft fft, LongfellowFieldProfile profile, LongfellowSubfieldRunCodec codec)
    {
        using LongfellowSumcheckCircuit circuit = ParseSignatureCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Point256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes, SigBlockEncoded);

        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateMontgomeryEncoderFactory(
            fft, profile, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, CurveParameterSet.None, BaseMemoryPool.Shared, Fp256SimdBackend.BatchMultiplyMontgomery());

        //The circuit's quad-term coefficients are canonical; lift them to Montgomery so the verifier's shared
        //constraint build multiplies a working-domain constant against the working-domain wires.
        LongfellowSumcheckCircuit montgomeryCircuit = CircuitScope.Lift(circuit, P256BaseFieldMontgomeryBackend.ToMontgomery);

        return new LongfellowMdocFieldVerifier(montgomeryCircuit, parameters, encoderFactory, profile, codec, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, CurveParameterSet.None, Fp256BatchMultiply: Fp256SimdBackend.BatchMultiplyMontgomery());
    }


    /// <summary>Imports the P-256 signature circuit (the front of the raw circuit stream), with circuit owners released at test cleanup.</summary>
    private LongfellowSumcheckCircuit ParseSignatureCircuit()
    {
        bool parsed = CircuitScope.TryRead(RawCircuitBytes, Point256FieldId, Point256ElementBytes, out LongfellowSumcheckCircuit? signature, out _, out _);
        Assert.IsTrue(parsed, "The signature circuit must parse.");
        Assert.IsNotNull(signature);

        return signature;
    }


    /// <summary>Imports the GF(2^128) hash circuit, discarding the subfield boundary the overload with an <c>out int</c> parameter reports.</summary>
    private LongfellowSumcheckCircuit ParseHashCircuit() => ParseHashCircuit(out _);


    /// <summary>Imports the GF(2^128) hash circuit from the continuation of the raw circuit stream (after the sig circuit), capturing its subfield boundary, with circuit owners released at test cleanup.</summary>
    private LongfellowSumcheckCircuit ParseHashCircuit(out int subfieldBoundary)
    {
        bool signatureParsed = CircuitScope.TryRead(RawCircuitBytes, Point256FieldId, Point256ElementBytes, out _, out _, out int signatureBytes);
        Assert.IsTrue(signatureParsed, "The signature circuit must parse before the hash circuit.");

        bool hashParsed = CircuitScope.TryRead(RawCircuitBytes.AsSpan(signatureBytes), Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? hash, out subfieldBoundary, out _);
        Assert.IsTrue(hashParsed, "The hash circuit must parse from the continuation span.");
        Assert.IsNotNull(hash);

        return hash;
    }


    /// <summary>Computes <c>of_scalar(u)</c> over the P-256 base field: reduces the integer <paramref name="coordinate"/> modulo the field prime and writes it to <paramref name="destination"/> as a canonical big-endian scalar.</summary>
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


    /// <summary>Reports whether the canonical big-endian integer in <paramref name="canonical"/> is strictly below the field prime, i.e. already in reduced form.</summary>
    private static bool InRangeFp256(ReadOnlySpan<byte> canonical) => new BigInteger(canonical, isUnsigned: true, isBigEndian: true) < Prime;


    /// <summary>Decodes the fixture value stored under <paramref name="key"/> from hexadecimal into raw bytes.</summary>
    private static byte[] HexBlob(string key) => Convert.FromHexString(Fixture[key]);


    /// <summary>Creates the GF(2^128) additive FFT used by the hash circuit's Ligero encoding, over the shared memory pool.</summary>
    private static Lch14AdditiveFft NewGfFft() =>
        new(Lch14Subfield.Production16, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>Creates the Montgomery-domain P-256 field profile: its <c>of_scalar</c>/<c>of_bytes_field</c> conversions lift canonical values into the Montgomery domain and <c>to_bytes_field</c> drops back, so the wire bytes it produces are byte-identical to the canonical profile's. The caller owns and disposes the returned profile.</summary>
    private static LongfellowFieldProfile NewMontgomerySigProfile() =>
        LongfellowFp256Encoding.CreateMontgomeryProfile(OfScalarFp256, InRangeFp256, P256BaseFieldMontgomeryBackend.ToMontgomery, P256BaseFieldMontgomeryBackend.FromMontgomery, BaseMemoryPool.Shared);


    /// <summary>
    /// Creates a caller-owned P-256 FFT whose root uses the supplied pool: the production root is lifted
    /// per coordinate to its Montgomery residue, and the multiply/invert are the Montgomery-domain
    /// delegates, so the twiddle multiplies stay 1-CIOS in domain.
    /// </summary>
    /// <param name="pool">The caller pool supplying the root until the returned FFT is disposed.</param>
    private static Fp256RealFft NewFp256Fft(BaseMemoryPool pool)
    {
        byte[] root = new byte[Fp256QuadraticExtension.ElementSize];
        LongfellowFp256Encoding.RootOfUnityWorking(root, P256BaseFieldMontgomeryBackend.ToMontgomery);

        using LongfellowFieldProfile profile = NewMontgomerySigProfile();

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, profile.OfScalar, CurveParameterSet.None, pool);
    }


    /// <summary>Creates the shared transcript seeded with the fixture's transcript bytes, baked at the GF(2^128) element width, using AES-256-ECB post-processing and the SHA-256 sponge backend.</summary>
    private static LongfellowTranscript NewTranscript(byte[] seed) =>
        new(seed, TranscriptVersion, TranscriptElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Computes a one-shot SHA-256 digest of <paramref name="input"/> into <paramref name="output"/>; the named-algorithm parameter is accepted to match the transcript's hash-selection delegate shape, but this backend always uses SHA-256.</summary>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) => SHA256.HashData(input, output);


    /// <summary>Computes the two-to-one Merkle compression of <paramref name="left"/> and <paramref name="right"/> as <c>SHA256(left ‖ right)</c>.</summary>
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[left.Length + right.Length];
        left.CopyTo(combined);
        right.CopyTo(combined[left.Length..]);
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>Encrypts <paramref name="input"/> under AES-256 in ECB mode with the given <paramref name="key"/> and no padding, matching the transcript's block-cipher squeeze step.</summary>
    private static void Aes256Ecb(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    /// <summary>Reads the raw bytes of the fixture file at the given repository-relative path.</summary>
    private static byte[] ReadFixture(string relativePath) => File.ReadAllBytes($"../../../{relativePath}");


    /// <summary>Decompresses a gzip-compressed byte array in memory.</summary>
    private static byte[] DecompressGzip(byte[] gzip)
    {
        using var input = new MemoryStream(gzip);
        using var gzipStream = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzipStream.CopyTo(output);

        return output.ToArray();
    }


    /// <summary>Parses a fixture file's <c>key=value</c> lines into a dictionary, skipping blank lines and any line without an <c>=</c> separator.</summary>
    private static Dictionary<string, string> LoadFixture(string relativePath)
    {
        string path = $"../../../{relativePath}";
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
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

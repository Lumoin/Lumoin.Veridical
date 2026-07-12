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
/// The CROWN GATE (conformance step C.12, stage 4) — the end-to-end proof that our dual-field
/// <see cref="LongfellowMdocVerifier"/> ACCEPTS the REAL reference mdoc <c>ZkProof</c> envelope. The fixture
/// (<c>mdoc-zk-anchor-output.txt</c>) is produced by the Docker reference prover over a real
/// <c>org.iso.18013.5.1.mDL</c> credential: the version-7 envelope
/// <c>[6 macs] ‖ [hash ZkProof] ‖ [sig ZkProof]</c>, the session transcript seed, and the two public-input
/// templates the reference's <c>fill_attributes</c> / <c>fill_signature_inputs</c> emit (the hash template
/// <c>[one, attrs…, now-bits]</c> = 945 sixteen-byte elements; the sig template <c>[one, pkX, pkY, e2]</c> =
/// 4 thirty-two-byte elements, <c>e2</c> already inside it). The driver appends the six macs and the squeezed
/// <c>a_v</c> to each template, runs the size guard, and verifies both circuits on one shared transcript.
/// </summary>
/// <remarks>
/// <para>
/// Both circuits are imported from the same <c>mdoc-circuit-raw.gz</c> the C.10 reader gate parses: the P-256
/// signature circuit first (field id 1, 32-byte elements), then the GF(2^128) hash circuit from the
/// continuation span (field id 4, 16-byte elements). The Ligero parameters use the reference v7 pair
/// (<c>kLigeroRatev7 = 7</c>, <c>kLigeroNreqv7 = 132</c>) for both circuits. The hash side rides the
/// GF(2^128) additive-FFT encoding (16-byte framing, 2-byte GF(2^16) subfield); the sig side rides the Fp256
/// real-FFT encoding (32-byte framing, the prime field as its own subfield). The transcript is seeded with
/// the reference's transcript blob at version 7 and the GF/<c>a_v</c> baked width of 16; the sig side passes
/// its 32-byte profile per operation (the step-3 cross-field design).
/// </para>
/// <para>
/// The end-to-end verify over the genuine ~85k-wire hash circuit and the P-256 signature circuit is the
/// expensive Ligero-over-the-whole-R1CS path, so the accept gate is marked <see cref="TestCategoryAttribute"/>
/// <c>Slow</c>. The tamper dual flips one byte in the hash-proof region and (separately) one byte in the
/// sig-proof region of the envelope and asserts the verdict is no longer <c>Accepted</c>, with a fresh
/// transcript per call.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowMdocCrownGateTests
{
    private const string FixtureRelativePath = "TestMaterial/Longfellow/mdoc-zk-anchor-output.txt";
    private const string RawGzipRelativePath = "TestMaterial/Longfellow/mdoc-circuit-raw.gz";

    //The reference circuit-stream field ids and on-wire element widths (CircuitReader gate, C.10).
    private const int Point256FieldId = 1;
    private const int Gf2128FieldId = 4;
    private const int Point256ElementBytes = 32;
    private const int Gf2128ElementBytes = 16;

    //The reference v7 Ligero pair: kLigeroRatev7 = 7, kLigeroNreqv7 = 132 (both circuits).
    private const int InverseRate = 7;
    private const int OpenedColumnCount = 132;

    //The reference v7 pinned block_enc (kZkSpecs, num_attributes=1, version=7): the deployed path stores
    //block_enc in the ZkSpecStruct and feeds it to ZkProof AND ZkVerifier rather than optimizing it
    //online (zk_spec.cc:47-49 -> {1, 7, 4151, 4096}; mdoc_zk.cc:615-616 prover, 659-662 verifier).
    private const int HashBlockEncoded = 4151;
    private const int SigBlockEncoded = 4096;

    //GF(2^128) hash circuit: 16-byte full field, GF(2^16) = Production16 subfield (2 bytes).
    private const int HashFieldBytes = 16;
    private const int HashSubFieldBytes = 2;

    //The transcript is baked at the GF/a_v width 16 (the sig side passes its 32-byte profile per-op).
    private const int TranscriptElementBytes = 16;
    private const int TranscriptVersion = 7;

    //Expected fixture region sizes (the reference dump's pinned lengths).
    private const int TranscriptBytes = 117;
    private const int EnvelopeBytes = 359924;
    private const int HashTemplateElementCount = 945;
    private const int SigTemplateElementCount = 4;

    private static Dictionary<string, string> Fixture { get; } = LoadFixture(FixtureRelativePath);

    //The decompressed real-circuit bytes (~99 MB); decompress once and share across the import.
    private static byte[] RawCircuitBytes { get; } = DecompressGzip(ReadFixture(RawGzipRelativePath));

    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    private static ScalarAddDelegate GfAdd { get; } = Gf2k128Backend.GetAdd();

    private static ScalarSubtractDelegate GfSubtract { get; } = Gf2k128Backend.GetSubtract();

    private static ScalarMultiplyDelegate GfMultiply { get; } = Gf2k128Backend.GetMultiply();

    private static ScalarInvertDelegate GfInvert { get; } = Gf2k128Backend.GetInvert();

    //The Fp256 sig path runs on the Montgomery backend — the validated faster base-field backend
    //(byte-identical to the BigInteger reference per Fp256FieldBackendAgreementTests). This is the
    //production-intended Fp256 backend; the crown gate is a [Slow] gate that runs in isolation, so it
    //does not hit the parallel-suite throttle that keeps the broad gadget suites on the reference
    //backend. The crown-gate Accept is itself the byte-identity proof. Measured warm-to-warm on this
    //x86 box: the dual-field Accept drops ~11.1s -> ~9.3s (the GF hash side is unchanged, so the sig
    //slice itself drops ~26%); the first cold run pays extra JIT and is not representative.
    private static ScalarAddDelegate Fp256Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();

    private static ScalarSubtractDelegate Fp256Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();

    //Perf Increment 1: the sig path runs in the Montgomery working domain (1 CIOS per multiply). The verifier
    //reads Google's REAL reference proof and the sig template (canonical-LE wire bytes) through the Montgomery
    //profile's of_bytes_field, which lifts them to Montgomery; working in Montgomery it must still ACCEPT (the
    //byte-anchored gate). Add/Subtract are domain-linear and shared with the canonical path.
    private static ScalarMultiplyDelegate Fp256Multiply { get; } = P256BaseFieldMontgomeryBackend.GetMultiplyMontgomery();

    private static ScalarInvertDelegate Fp256Invert { get; } = P256BaseFieldMontgomeryBackend.GetInvertMontgomery();


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void OurVerifierAcceptsTheRealReferenceMdocProof()
    {
        byte[] envelope = HexBlob("envelope");
        byte[] transcriptSeed = HexBlob("transcript");
        byte[] hashTemplate = HexBlob("hash_template");
        byte[] sigTemplate = HexBlob("sig_template");

        //Pin the fixture's region sizes so a corrupted dump fails loudly here, not deep in the verifier.
        Assert.HasCount(EnvelopeBytes, envelope, "The envelope must be the reference's proof_len bytes.");
        Assert.HasCount(TranscriptBytes, transcriptSeed, "The transcript seed must be 117 bytes.");
        Assert.HasCount(HashTemplateElementCount * Gf2128ElementBytes, hashTemplate, "The hash template is 945 * 16 element bytes.");
        Assert.HasCount(SigTemplateElementCount * Point256ElementBytes, sigTemplate, "The sig template is 4 * 32 element bytes.");

        //One shared FFT/codec lifetime per side, held for the whole verify.
        using Lch14AdditiveFft hashFft = NewGfFft();
        using LongfellowSubfieldRunCodec hashCodec = LongfellowSubfieldRunCodec.ForGf2k128(
            LongfellowGf2k128Encoding.CreateProfile(hashFft), hashFft, HashSubFieldBytes, BaseMemoryPool.Shared);

        Fp256RealFft sigFft = NewFp256Fft();
        using LongfellowSubfieldRunCodec sigCodec = LongfellowSubfieldRunCodec.ForFp256(NewMontgomerySigProfile());

        LongfellowMdocFieldVerifier hash = BuildHashBundle(hashFft, hashCodec, out _);
        LongfellowMdocFieldVerifier sig = BuildSigBundle(sigFft, sigCodec);

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


    //Runs one full dual-field verify over the given envelope with a fresh transcript and fresh bundles.
    private static LongfellowMdocVerificationResult VerifyOnce(byte[] envelope, byte[] transcriptSeed, byte[] hashTemplate, byte[] sigTemplate)
    {
        using Lch14AdditiveFft hashFft = NewGfFft();
        using LongfellowSubfieldRunCodec hashCodec = LongfellowSubfieldRunCodec.ForGf2k128(
            LongfellowGf2k128Encoding.CreateProfile(hashFft), hashFft, HashSubFieldBytes, BaseMemoryPool.Shared);

        Fp256RealFft sigFft = NewFp256Fft();
        using LongfellowSubfieldRunCodec sigCodec = LongfellowSubfieldRunCodec.ForFp256(NewMontgomerySigProfile());

        LongfellowMdocFieldVerifier hash = BuildHashBundle(hashFft, hashCodec, out _);
        LongfellowMdocFieldVerifier sig = BuildSigBundle(sigFft, sigCodec);

        using LongfellowTranscript transcript = NewTranscript(transcriptSeed);

        LongfellowMdocVerifier.Verify(
            envelope, hash, sig, hashTemplate, sigTemplate, transcript,
            Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, BaseMemoryPool.Shared,
            out LongfellowMdocVerificationResult result);

        return result;
    }


    //The GF(2^128) hash bundle: the imported hash circuit, the v7 Ligero parameters, the GF encoding and
    //the borrowed subfield-run codec.
    private static LongfellowMdocFieldVerifier BuildHashBundle(Lch14AdditiveFft fft, LongfellowSubfieldRunCodec codec, out int subfieldBoundary)
    {
        LongfellowSumcheckCircuit circuit = ParseHashCircuit(out subfieldBoundary);
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, HashFieldBytes, HashSubFieldBytes, HashBlockEncoded);

        LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft);
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);

        return new LongfellowMdocFieldVerifier(circuit, parameters, encoderFactory, profile, codec, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, Gf2k128BatchBackend.GetBindQuadReduce(), Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate());
    }


    //The P-256 base-field signature bundle: the imported signature circuit, the v7 Ligero parameters, the
    //Fp256 encoding and the borrowed subfield-run codec.
    private static LongfellowMdocFieldVerifier BuildSigBundle(Fp256RealFft fft, LongfellowSubfieldRunCodec codec)
    {
        LongfellowSumcheckCircuit circuit = ParseSignatureCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(
            circuit, InverseRate, OpenedColumnCount, Point256ElementBytes, LongfellowFp256Encoding.SignatureSubFieldBytes, SigBlockEncoded);

        LongfellowFieldProfile profile = NewMontgomerySigProfile();
        LongfellowRowEncoderFactory encoderFactory = LongfellowFp256Encoding.CreateMontgomeryEncoderFactory(
            fft, profile, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, CurveParameterSet.None, BaseMemoryPool.Shared, Fp256SimdBackend.BatchMultiplyMontgomery());

        //The circuit's quad-term coefficients are canonical; lift them to Montgomery so the verifier's shared
        //constraint build multiplies a working-domain constant against the working-domain wires (Perf Increment 1).
        LongfellowSumcheckCircuit montgomeryCircuit = circuit.LiftCoefficientsToWorking(P256BaseFieldMontgomeryBackend.ToMontgomery);

        return new LongfellowMdocFieldVerifier(montgomeryCircuit, parameters, encoderFactory, profile, codec, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, CurveParameterSet.None, Fp256BatchMultiply: Fp256SimdBackend.BatchMultiplyMontgomery());
    }


    //Imports the P-256 signature circuit (the front of the raw circuit stream).
    private static LongfellowSumcheckCircuit ParseSignatureCircuit()
    {
        bool parsed = LongfellowCircuitReader.TryRead(RawCircuitBytes, Point256FieldId, Point256ElementBytes, out LongfellowSumcheckCircuit? signature, out _, out _);
        Assert.IsTrue(parsed, "The signature circuit must parse.");
        Assert.IsNotNull(signature);

        return signature;
    }


    private static LongfellowSumcheckCircuit ParseHashCircuit() => ParseHashCircuit(out _);


    //Imports the GF(2^128) hash circuit from the continuation of the raw circuit stream (after the sig
    //circuit), capturing its subfield boundary.
    private static LongfellowSumcheckCircuit ParseHashCircuit(out int subfieldBoundary)
    {
        bool signatureParsed = LongfellowCircuitReader.TryRead(RawCircuitBytes, Point256FieldId, Point256ElementBytes, out _, out _, out int signatureBytes);
        Assert.IsTrue(signatureParsed, "The signature circuit must parse before the hash circuit.");

        bool hashParsed = LongfellowCircuitReader.TryRead(RawCircuitBytes.AsSpan(signatureBytes), Gf2128FieldId, Gf2128ElementBytes, out LongfellowSumcheckCircuit? hash, out subfieldBoundary, out _);
        Assert.IsTrue(hashParsed, "The hash circuit must parse from the continuation span.");
        Assert.IsNotNull(hash);

        return hash;
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


    private static byte[] HexBlob(string key) => Convert.FromHexString(Fixture[key]);


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

        return new Fp256RealFft(root, LongfellowFp256Encoding.OmegaOrder, Fp256Add, Fp256Subtract, Fp256Multiply, Fp256Invert, NewMontgomerySigProfile().OfScalar, CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    private static LongfellowTranscript NewTranscript(byte[] seed) =>
        new(seed, TranscriptVersion, TranscriptElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


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

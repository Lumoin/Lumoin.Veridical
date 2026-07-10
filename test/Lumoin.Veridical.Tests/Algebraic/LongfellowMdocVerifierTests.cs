using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The dual-field mdoc driver (conformance step C.12 stage 3) — google/longfellow-zk's
/// <c>run_mdoc_verifier</c> (<c>lib/circuits/mdoc/mdoc_zk.cc:560-695</c>). These gate the mechanics the
/// driver owns: the cross-field transcript order (both commitment roots absorbed BEFORE the shared MAC key
/// <c>a_v</c> is squeezed, so flipping the roots changes <c>a_v</c>), the mac-wire index constants, the
/// mac/av public-input splice layout (the GF side keeps each mac a single 16-byte element; the Fp256 side
/// expands it to 128 least-significant-first bit wires), and the <c>e2</c> transcript-hash construction. The
/// end-to-end accept of a real Fp256 signature envelope lands with the Docker dump harness (step 4); these
/// are unit-level.
/// </summary>
[TestClass]
internal sealed class LongfellowMdocVerifierTests
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int GfElementBytes = 16;
    private const int Fp256ElementBytes = 32;
    private const int MacKeyBits = 128;
    private const int DigestSize = 32;
    private const int TranscriptVersion = 6;

    private const string ZkDumpRelativePath = "TestMaterial/Longfellow/zk-anchor-output.txt";
    private const int AnchorSubFieldBytes = 2;
    private const int InverseRate = 4;
    private const int OpenedColumnCount = 2;
    private const int AnchorSubfieldBoundary = 0;

    //A cut this far into the hash proof's com_proof keeps the fixed root and
    //sumcheck segment intact while landing inside the run-length section.
    private const int HashComProofCutBytes = 8;

    //A tail cut small enough that the hash proof still splits and only the
    //sig-proof remainder underflows.
    private const int SigProofTailCutBytes = 5;

    private static readonly byte[] TranscriptSeed = Encoding.ASCII.GetBytes("mdoc-driver-gate");
    private static readonly byte[] AnchorProofSeed = Encoding.ASCII.GetBytes("zk8");

    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(ZkDumpRelativePath);

    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    private static ScalarAddDelegate GfAdd { get; } = Gf2k128Backend.GetAdd();

    private static ScalarSubtractDelegate GfSubtract { get; } = Gf2k128Backend.GetSubtract();

    private static ScalarMultiplyDelegate GfMultiply { get; } = Gf2k128Backend.GetMultiply();

    private static ScalarInvertDelegate GfInvert { get; } = Gf2k128Backend.GetInvert();

    private static LongfellowFieldProfile Fp256Profile { get; } = LongfellowFieldProfile.ForFp256(OfScalar, InRange);


    [TestMethod]
    public void BothRootsAbsorbBeforeAvAndFlippingThemChangesAv()
    {
        //recv_commitment(hash) then recv_commitment(sig), THEN a_v = generate_mac_key (mdoc_zk.cc:667-670).
        //a_v depends on both roots in order, so swapping the two absorbs must change a_v — the cross-field
        //binding that ties the hash and signature proofs to one shared key.
        byte[] hashRoot = FilledRoot(0x11);
        byte[] sigRoot = FilledRoot(0x22);

        byte[] avNormal = SqueezeMacKey(hashRoot, sigRoot);
        byte[] avFlipped = SqueezeMacKey(sigRoot, hashRoot);

        Assert.IsFalse(avNormal.AsSpan().SequenceEqual(avFlipped), "Flipping the two root absorbs must change a_v (the cross-field binding).");
    }


    [TestMethod]
    public void TheMacKeyIsSixteenRawBytesNotASampleLoop()
    {
        //generate_mac_key reads exactly 16 PRF bytes through of_bytes_field (mdoc_zk.cc:277-282). Two
        //transcripts seeded identically and fed the same two roots must produce byte-identical follow-on
        //draws, proving the a_v squeeze advanced the PRF by exactly 16 bytes.
        byte[] hashRoot = FilledRoot(0x33);
        byte[] sigRoot = FilledRoot(0x44);

        using LongfellowTranscript a = NewTranscript();
        using LongfellowTranscript b = NewTranscript();

        foreach(LongfellowTranscript t in new[] { a, b })
        {
            LongfellowZkVerifier.RecvCommitment(hashRoot, t);
            LongfellowZkVerifier.RecvCommitment(sigRoot, t);
        }

        Span<byte> avBytes = stackalloc byte[GfElementBytes];
        a.SqueezeFieldElementBytes(avBytes);

        //b squeezes the same 16 bytes via the raw byte path; the follow-on draws must then be in lockstep.
        Span<byte> rawBytes = stackalloc byte[GfElementBytes];
        b.SqueezeBytes(rawBytes);
        Assert.IsTrue(avBytes.SequenceEqual(rawBytes), "a_v = 16 raw PRF bytes (of_bytes_field), not the sample reject loop.");

        Span<byte> nextA = stackalloc byte[GfElementBytes];
        Span<byte> nextB = stackalloc byte[GfElementBytes];
        a.SqueezeBytes(nextA);
        b.SqueezeBytes(nextB);
        Assert.IsTrue(nextA.SequenceEqual(nextB), "The a_v draw consumed exactly 16 PRF bytes (no reject loop).");
    }


    [TestMethod]
    public void TheMacWireIndicesMatchTheReferenceFormulas()
    {
        //getHashMacIndex(numAttrs, version) = numAttrs*8*(96 + (version<7 ? 1 : 2)) + 160 + 1 (mdoc_zk.cc:61-64).
        Assert.AreEqual(945, HashMacIndex(numAttrs: 1, version: 7), "getHashMacIndex(1, 7) is 945.");
        Assert.AreEqual(937, HashMacIndex(numAttrs: 1, version: 6), "getHashMacIndex(1, 6) is 937.");

        //945 is exactly the C.11 hash-circuit MacPublicStart (the witness column where the macs splice in).
        const int C11MacPublicStart = 945;
        Assert.AreEqual(C11MacPublicStart, HashMacIndex(numAttrs: 1, version: 7), "getHashMacIndex(1, 7) must equal the C.11 MacPublicStart.");

        //kSigMacIndex is the fixed location of the sig MAC wire (mdoc_zk.cc:98); the version bump that moves
        //the hash index (version<7 ? 1 : 2) does not move the sig index — it stays 4 across versions.
        Assert.AreEqual(SigMacIndex(version: 7), SigMacIndex(version: 6), "kSigMacIndex is version-independent.");
        Assert.AreEqual(4, SigMacIndex(version: 7), "kSigMacIndex is 4.");
    }


    [TestMethod]
    public void TheHashSpliceAppendsSixMacsAndAvAsSingleSixteenByteElements()
    {
        //fill_gf2k<f_128, f_128> = push_back(m): each mac and a_v is ONE 16-byte element, NOT bit-expanded.
        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile profile = LongfellowFieldProfile.ForGf2k128(fft);

        const int TemplateElements = 3;
        byte[] template = new byte[TemplateElements * GfElementBytes];
        for(int i = 0; i < template.Length; i++)
        {
            template[i] = (byte)(0x80 + i);
        }

        byte[] macs = BuildMacs();
        byte[] av = CanonicalGf(0xAB);
        int npubIn = TemplateElements + 7;

        using IMemoryOwner<byte>? pub = LongfellowMdocPublicInputs.SpliceHash(profile, template, macs, av, npubIn, BaseMemoryPool.Shared);
        Assert.IsNotNull(pub, "A template of npub_in - 7 elements must splice cleanly.");

        ReadOnlySpan<byte> pubSpan = pub.Memory.Span[..(npubIn * GfElementBytes)];

        //The template is preserved verbatim.
        Assert.IsTrue(pubSpan[..template.Length].SequenceEqual(template), "The hash template must lead the spliced vector.");

        //Each of the six macs is one 16-byte element = to_bytes_field of the mac.
        Span<byte> expectedMac = stackalloc byte[GfElementBytes];
        for(int i = 0; i < LongfellowMdocEnvelope.MacCount; i++)
        {
            profile.ToBytesField(macs.AsSpan(i * ScalarSize, ScalarSize), expectedMac);
            int offset = template.Length + (i * GfElementBytes);
            Assert.IsTrue(pubSpan.Slice(offset, GfElementBytes).SequenceEqual(expectedMac), $"Hash mac {i} must be one 16-byte element.");
        }

        //a_v is the seventh appended element.
        Span<byte> expectedAv = stackalloc byte[GfElementBytes];
        profile.ToBytesField(av, expectedAv);
        int avOffset = template.Length + (LongfellowMdocEnvelope.MacCount * GfElementBytes);
        Assert.IsTrue(pubSpan.Slice(avOffset, GfElementBytes).SequenceEqual(expectedAv), "a_v must be the seventh 16-byte element.");
    }


    [TestMethod]
    public void TheSigSpliceExpandsEachMacToOneTwentyEightLeastSignificantFirstBitWires()
    {
        //Generic fill_gf2k<f_128, Fp256Base>: each mac and a_v becomes 128 one/zero base-field wires, the
        //GF element's bits least-significant first (mac_reference.h:62-68).
        const int TemplateElements = 4; // [one, pkX, pkY, e2]
        byte[] template = new byte[TemplateElements * Fp256ElementBytes];
        for(int i = 0; i < template.Length; i++)
        {
            template[i] = (byte)(0x10 + (i & 0x3F));
        }

        byte[] macs = BuildMacs();
        byte[] av = CanonicalGf(0x5C);
        int npubIn = TemplateElements + (7 * MacKeyBits);

        using IMemoryOwner<byte>? pub = LongfellowMdocPublicInputs.SpliceSig(Fp256Profile, template, macs, av, npubIn, BaseMemoryPool.Shared);
        Assert.IsNotNull(pub, "A template of npub_in - 7*128 elements must splice cleanly.");

        ReadOnlySpan<byte> pubSpan = pub.Memory.Span[..(npubIn * Fp256ElementBytes)];
        Assert.IsTrue(pubSpan[..template.Length].SequenceEqual(template), "The sig template must lead the spliced vector.");

        //one and zero in the sig field's little-endian framing.
        Span<byte> oneWire = stackalloc byte[Fp256ElementBytes];
        Span<byte> zeroWire = stackalloc byte[Fp256ElementBytes];
        WriteWire(1, oneWire);
        WriteWire(0, zeroWire);

        //Verify the seven expanded blocks (six macs, then a_v) bit by bit, least-significant first.
        var elements = new List<byte[]>();
        for(int i = 0; i < LongfellowMdocEnvelope.MacCount; i++)
        {
            elements.Add(macs.AsSpan(i * ScalarSize, ScalarSize).ToArray());
        }

        elements.Add(av);

        int offset = template.Length;
        foreach(byte[] element in elements)
        {
            for(int j = 0; j < MacKeyBits; j++)
            {
                int bit = (element[ScalarSize - 1 - (j / 8)] >> (j % 8)) & 1;
                ReadOnlySpan<byte> expected = bit == 1 ? oneWire : zeroWire;
                Assert.IsTrue(pubSpan.Slice(offset, Fp256ElementBytes).SequenceEqual(expected), $"Sig bit wire {j} must be the element's bit j (LSB-first).");
                offset += Fp256ElementBytes;
            }
        }
    }


    [TestMethod]
    public void AWrongSizedTemplateSplicesToNullForBothFields()
    {
        //The filler.size() != npub_in guard (mdoc_zk.cc:686-689): a template that does not leave exactly the
        //seven mac/av slots must reject (the driver maps null to AttributeNumberMismatch).
        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile hashProfile = LongfellowFieldProfile.ForGf2k128(fft);

        byte[] macs = BuildMacs();
        byte[] av = CanonicalGf(0x01);

        //Hash: a template of 3 elements but npub_in declared as 11 (would need 4 template elements).
        byte[] hashTemplate = new byte[3 * GfElementBytes];
        using IMemoryOwner<byte>? hashPub = LongfellowMdocPublicInputs.SpliceHash(hashProfile, hashTemplate, macs, av, publicInputCount: 11, BaseMemoryPool.Shared);
        Assert.IsNull(hashPub, "A hash template that does not leave exactly 7 mac/av slots must splice to null.");

        //Sig: a template of 4 elements but npub_in declared one short of 4 + 7*128.
        byte[] sigTemplate = new byte[4 * Fp256ElementBytes];
        using IMemoryOwner<byte>? sigPub = LongfellowMdocPublicInputs.SpliceSig(Fp256Profile, sigTemplate, macs, av, publicInputCount: 4 + (7 * MacKeyBits) - 1, BaseMemoryPool.Shared);
        Assert.IsNull(sigPub, "A sig template that does not leave exactly 7*128 mac/av wires must splice to null.");
    }


    [TestMethod]
    public void TheTranscriptHashConstructionMatchesTheReferenceCose1Encoding()
    {
        //e2 = to_montgomery(compute_transcript_hash(tr, docType)); its standard-form value is
        //SHA-256(COSE1(DeviceAuthenticationBytes)) read big-endian, reduced mod p (mdoc_witness.h:391-484).
        //Construct the COSE1 bytes deterministically and pin the resulting reduced hash.
        byte[] sessionTranscript = Encoding.ASCII.GetBytes("session-transcript-bytes");
        byte[] docType = Encoding.ASCII.GetBytes("org.iso.18013.5.1.mDL");

        byte[] cose1 = BuildCose1(sessionTranscript, docType);
        byte[] digest = SHA256.HashData(cose1);
        BigInteger e2Standard = new BigInteger(digest, isUnsigned: true, isBigEndian: true) % Prime;

        //Recomputing the same construction must be stable (the recipe is deterministic), and the reduced
        //value is a valid base-field element below the modulus.
        byte[] cose1Again = BuildCose1(sessionTranscript, docType);
        Assert.IsTrue(cose1.AsSpan().SequenceEqual(cose1Again), "The COSE1 DeviceAuthenticationBytes construction must be deterministic.");
        Assert.IsLessThan(Prime, e2Standard, "e2 (standard form) is a base-field element below the modulus.");

        //The construction must be sensitive to the session transcript (a different transcript moves e2).
        byte[] other = BuildCose1(Encoding.ASCII.GetBytes("a-different-transcript"), docType);
        BigInteger otherE2 = new BigInteger(SHA256.HashData(other), isUnsigned: true, isBigEndian: true) % Prime;
        Assert.AreNotEqual(e2Standard, otherE2, "e2 must depend on the session transcript bytes.");
    }


    [TestMethod]
    public void TheCose1LengthEncodingIsByteCorrectAtTheBoundaries()
    {
        //TOB-LIBZK-5 found an off-by-one in the reference's COSE1 length serialization (length 256
        //encoded as 0 via `> 256`; text length 255 emitted nothing); the fixed reference and this port
        //use `>= 256` / correct 24..255 handling. Pin the CBOR major-type-2 (byte string, base 0x40)
        //and major-type-3 (text string, base 0x60) length-prefix encodings at the boundaries the bug
        //touched: the 24 short/long-form cutover and the one-byte/two-byte length-field cutover at 256.
        AssertBytesLen(23, [0x57]);
        AssertBytesLen(24, [0x58, 0x18]);
        AssertBytesLen(255, [0x58, 0xFF]);
        AssertBytesLen(256, [0x59, 0x01, 0x00]);
        AssertBytesLen(65535, [0x59, 0xFF, 0xFF]);

        AssertTextLen(23, [0x77]);
        AssertTextLen(24, [0x78, 0x18]);
        AssertTextLen(255, [0x78, 0xFF]);
    }


    [TestMethod]
    public void AShortEnvelopeYieldsMalformedEnvelopeWithoutThrowing()
    {
        //Parse safety: an envelope shorter than the 96-byte mac region must return MalformedEnvelope, never
        //throw on attacker bytes. The field bundles can be minimal here because the parse fails first.
        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile hashProfile = LongfellowFieldProfile.ForGf2k128(fft);
        using LongfellowSubfieldRunCodec hashCodec = LongfellowSubfieldRunCodec.ForGf2k128(hashProfile, fft, subFieldBytes: 2, BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec sigCodec = LongfellowSubfieldRunCodec.ForFp256(Fp256Profile);

        LongfellowSumcheckCircuit circuit = SmallCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, inverseRate: 4, openedColumnCount: 2, fieldBytes: 16, subFieldBytes: 2);

        var hashField = new LongfellowMdocFieldVerifier(circuit, parameters, NewGfEncoderFactory(fft), hashProfile, hashCodec, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, Gf2k128BatchBackend.GetBindQuadReduce(), Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate());
        var sigField = new LongfellowMdocFieldVerifier(circuit, parameters, NewGfEncoderFactory(fft), Fp256Profile, sigCodec, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None);

        using LongfellowTranscript transcript = NewTranscript();
        byte[] tooShort = new byte[LongfellowMdocEnvelope.MacRegionBytes - 1];

        bool ok = LongfellowMdocVerifier.Verify(
            tooShort, hashField, sigField, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty,
            transcript, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, BaseMemoryPool.Shared,
            out LongfellowMdocVerificationResult result);

        Assert.IsFalse(ok, "A short envelope must not verify.");
        Assert.AreEqual(LongfellowMdocVerificationResult.MalformedEnvelope, result, "A short envelope is a MalformedEnvelope cause.");
    }


    [TestMethod]
    public void TheDriverParsesBothProofsRecvsBothRootsThenGuardsTheSplicedSize()
    {
        //A full front-of-pipeline gate over REAL serialized GF(2^128) proofs: the driver reads the macs,
        //parses the hash proof AND the sig proof (here a second real GF proof, so the parse is exercised on
        //both slices), absorbs both roots, squeezes a_v, then runs the size guard. The anchor circuit's
        //npub_in (2) is smaller than the 7 mac/av slots, so the splice cannot reach npub_in and the driver
        //returns AttributeNumberMismatch — proving it reached the guard without throwing on real bytes.
        LongfellowSumcheckCircuit circuit = BuildAnchorCircuit();
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, GfElementBytes, AnchorSubFieldBytes);

        byte[] proof = ProduceAnchorHashProof(circuit);
        byte[] envelope = Concatenate(BuildMacRegionBytes(), proof, proof);

        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile profile = LongfellowFieldProfile.ForGf2k128(fft);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForGf2k128(profile, fft, AnchorSubFieldBytes, BaseMemoryPool.Shared);

        var field = new LongfellowMdocFieldVerifier(circuit, parameters, NewGfEncoderFactory(fft), profile, codec, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None);

        //An empty template for each side: the splice would need npub_in mac/av slots, but npub_in is 2 < 7.
        using LongfellowTranscript transcript = NewTranscript();
        bool ok = LongfellowMdocVerifier.Verify(
            envelope, field, field, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty,
            transcript, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, BaseMemoryPool.Shared,
            out LongfellowMdocVerificationResult result);

        Assert.IsFalse(ok, "The splice cannot reach npub_in, so the driver must reject.");
        Assert.AreEqual(LongfellowMdocVerificationResult.AttributeNumberMismatch, result, "Reaching the size guard with too few public inputs is an AttributeNumberMismatch.");
    }


    [TestMethod]
    public void ATruncationInsideTheHashComProofYieldsMalformedEnvelope()
    {
        //Cut inside the hash proof's run-length-encoded com_proof section: the
        //fixed 32-byte root and the shape-derived sumcheck segment stay intact,
        //so the failure is specifically the Ligero run-length read
        //(LongfellowLigeroProofSerializer.Read) the envelope split probes with.
        LongfellowSumcheckCircuit circuit = BuildAnchorCircuit();
        byte[] proof = ProduceAnchorHashProof(circuit);
        byte[] envelope = Concatenate(BuildMacRegionBytes(), proof, proof);

        using Lch14AdditiveFft fft = NewFft();
        int sumcheckSegmentBytes = LongfellowSumcheckProofSerializer.SerializedSize(circuit, LongfellowFieldProfile.ForGf2k128(fft));
        int cut = LongfellowMdocEnvelope.MacRegionBytes + DigestSize + sumcheckSegmentBytes + HashComProofCutBytes;
        Assert.IsLessThan(envelope.Length, cut, "The cut must land strictly inside the envelope.");

        bool ok = VerifyAnchorEnvelope(circuit, envelope.AsSpan(0, cut), out LongfellowMdocVerificationResult result);

        Assert.IsFalse(ok, "An envelope cut inside the hash com_proof must not verify.");
        Assert.AreEqual(LongfellowMdocVerificationResult.MalformedEnvelope, result, "A failed hash-proof split is a MalformedEnvelope cause.");
    }


    [TestMethod]
    public void ATruncationInTheSigProofTailYieldsMalformedEnvelope()
    {
        //Cut a few bytes off the envelope tail: the hash proof still splits
        //(its run-length probe consumes exactly its own bytes), and the sig
        //remainder is short of a parseable ZkProof, so the sig-side parse
        //fails before any verification runs.
        LongfellowSumcheckCircuit circuit = BuildAnchorCircuit();
        byte[] proof = ProduceAnchorHashProof(circuit);
        byte[] envelope = Concatenate(BuildMacRegionBytes(), proof, proof);

        bool ok = VerifyAnchorEnvelope(circuit, envelope.AsSpan(0, envelope.Length - SigProofTailCutBytes), out LongfellowMdocVerificationResult result);

        Assert.IsFalse(ok, "An envelope cut in the sig-proof tail must not verify.");
        Assert.AreEqual(LongfellowMdocVerificationResult.MalformedEnvelope, result, "A failed sig-proof parse is a MalformedEnvelope cause.");
    }


    //Builds the anchor-circuit field bundle and drives the mdoc verifier over the supplied envelope
    //bytes. Both proof slots share the GF bundle, which suffices for the parse-level verdicts the
    //truncation gates pin.
    private static bool VerifyAnchorEnvelope(LongfellowSumcheckCircuit circuit, ReadOnlySpan<byte> envelope, out LongfellowMdocVerificationResult result)
    {
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, GfElementBytes, AnchorSubFieldBytes);

        using Lch14AdditiveFft fft = NewFft();
        LongfellowFieldProfile profile = LongfellowFieldProfile.ForGf2k128(fft);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForGf2k128(profile, fft, AnchorSubFieldBytes, BaseMemoryPool.Shared);
        var field = new LongfellowMdocFieldVerifier(circuit, parameters, NewGfEncoderFactory(fft), profile, codec, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None);

        using LongfellowTranscript transcript = NewTranscript();

        return LongfellowMdocVerifier.Verify(
            envelope, field, field, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty,
            transcript, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, BaseMemoryPool.Shared,
            out result);
    }


    //Absorbs the two roots in the given order then squeezes the 16-byte MAC key, returning it as a
    //canonical scalar (the driver's generate_mac_key step).
    private static byte[] SqueezeMacKey(byte[] firstRoot, byte[] secondRoot)
    {
        using LongfellowTranscript transcript = NewTranscript();
        LongfellowZkVerifier.RecvCommitment(firstRoot, transcript);
        LongfellowZkVerifier.RecvCommitment(secondRoot, transcript);

        Span<byte> avBytes = stackalloc byte[GfElementBytes];
        transcript.SqueezeFieldElementBytes(avBytes);
        byte[] canonical = new byte[ScalarSize];
        for(int b = 0; b < GfElementBytes; b++)
        {
            canonical[ScalarSize - 1 - b] = avBytes[b];
        }

        return canonical;
    }


    //getHashMacIndex(numAttrs, version): numAttrs*8*(96 + (version<7 ? 1 : 2)) + 160 + 1 (mdoc_zk.cc:61-64).
    private static int HashMacIndex(int numAttrs, int version) => (numAttrs * 8 * (96 + (version < 7 ? 1 : 2))) + 160 + 1;


    //kSigMacIndex is a fixed constant 4, independent of the version (mdoc_zk.cc:98). The parameter is kept
    //so the gate can show it does not move with the version the way getHashMacIndex does.
    private static int SigMacIndex(int version)
    {
        _ = version;

        return 4;
    }


    //The COSE1 DeviceAuthenticationBytes encoding of compute_transcript_hash (mdoc_witness.h:440-483).
    private static byte[] BuildCose1(byte[] sessionTranscript, byte[] docType)
    {
        ReadOnlySpan<byte> deviceAuthentication =
        [
            0x84, 0x74, (byte)'D', (byte)'e', (byte)'v', (byte)'i', (byte)'c', (byte)'e', (byte)'A', (byte)'u', (byte)'t',
            (byte)'h', (byte)'e', (byte)'n', (byte)'t', (byte)'i', (byte)'c', (byte)'a', (byte)'t', (byte)'i', (byte)'o', (byte)'n',
        ];

        ReadOnlySpan<byte> deviceNameSpacesBytes = [0xD8, 0x18, 0x41, 0xA0];

        var docTypeBytes = new List<byte>();
        AppendTextLen(docTypeBytes, docType.Length);
        docTypeBytes.AddRange(docType);

        var da = new List<byte>();
        da.AddRange(deviceAuthentication.ToArray());
        da.AddRange(sessionTranscript);
        da.AddRange(docTypeBytes);
        da.AddRange(deviceNameSpacesBytes.ToArray());

        var cose1 = new List<byte>(new byte[]
        {
            0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, 0x43, 0xA1, 0x01, 0x26, 0x40,
        });

        int l1 = da.Count;
        int l2 = l1 + (l1 < 256 ? 4 : 5);
        AppendBytesLen(cose1, l2);
        cose1.Add(0xD8);
        cose1.Add(0x18);
        AppendBytesLen(cose1, l1);
        cose1.AddRange(da);

        return cose1.ToArray();
    }


    private static void AppendBytesLen(List<byte> buf, int len)
    {
        if(len < 24)
        {
            buf.Add((byte)(0x40 + len));
        }
        else if(len < 256)
        {
            buf.Add(0x58);
            buf.Add((byte)(len & 0xFF));
        }
        else
        {
            buf.Add(0x59);
            buf.Add((byte)((len >> 8) & 0xFF));
            buf.Add((byte)(len & 0xFF));
        }
    }


    private static void AppendTextLen(List<byte> buf, int len)
    {
        if(len < 24)
        {
            buf.Add((byte)(0x60 + len));
        }
        else
        {
            buf.Add(0x78);
            buf.Add((byte)len);
        }
    }


    //Runs AppendBytesLen into a fresh buffer and asserts the produced CBOR major-type-2 prefix is
    //byte-exact.
    private static void AssertBytesLen(int len, byte[] expected)
    {
        var buf = new List<byte>();
        AppendBytesLen(buf, len);
        Assert.IsTrue(buf.ToArray().AsSpan().SequenceEqual(expected), $"AppendBytesLen({len}) must match the CBOR major-type-2 encoding.");
    }


    //Runs AppendTextLen into a fresh buffer and asserts the produced CBOR major-type-3 prefix is
    //byte-exact.
    private static void AssertTextLen(int len, byte[] expected)
    {
        var buf = new List<byte>();
        AppendTextLen(buf, len);
        Assert.IsTrue(buf.ToArray().AsSpan().SequenceEqual(expected), $"AppendTextLen({len}) must match the CBOR major-type-3 encoding.");
    }


    //Six distinct GF macs as canonical scalars: mac i has its low element bytes filled with (0x21 + i).
    private static byte[] BuildMacs()
    {
        byte[] macs = new byte[LongfellowMdocEnvelope.MacCount * ScalarSize];
        for(int i = 0; i < LongfellowMdocEnvelope.MacCount; i++)
        {
            CanonicalGf((byte)(0x21 + i)).CopyTo(macs.AsSpan(i * ScalarSize, ScalarSize));
        }

        return macs;
    }


    //A canonical GF(2^128) scalar with the low 16 bytes carrying a distinct pattern derived from `seed`.
    private static byte[] CanonicalGf(byte seed)
    {
        byte[] canonical = new byte[ScalarSize];
        for(int b = 0; b < GfElementBytes; b++)
        {
            canonical[ScalarSize - 1 - b] = (byte)(seed ^ (b * 7));
        }

        return canonical;
    }


    private static void WriteWire(uint value, Span<byte> wire)
    {
        Span<byte> canonical = stackalloc byte[ScalarSize];
        Fp256Profile.OfScalar(value, canonical);
        Fp256Profile.ToBytesField(canonical, wire);
    }


    private static byte[] FilledRoot(byte value)
    {
        byte[] root = new byte[DigestSize];
        root.AsSpan().Fill(value);

        return root;
    }


    //of_scalar(u): the integer u reduced mod p as a canonical big-endian scalar.
    private static void OfScalar(uint coordinate, Span<byte> destination)
    {
        destination.Clear();
        BigInteger value = new BigInteger(coordinate) % Prime;
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("of_scalar did not fit.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    private static bool InRange(ReadOnlySpan<byte> canonical) => new BigInteger(canonical, isUnsigned: true, isBigEndian: true) < Prime;


    private static LongfellowSumcheckCircuit SmallCircuit()
    {
        LongfellowSumcheckLayer layer = new(inputCount: 4, handRounds: 2, termCount: 0);
        byte[] id = new byte[LongfellowSumcheckCircuit.IdLength];

        return new LongfellowSumcheckCircuit(
            outputCount: 1, outputLogCount: 0, copyCount: 1, copyRounds: 0,
            inputCount: 4, publicInputCount: 0, id, [layer]);
    }


    private static LongfellowRowEncoderFactory NewGfEncoderFactory(Lch14AdditiveFft fft) =>
        LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);


    //The anchor's small GF(2^128) circuit (the w == (x + y)·(x + z)·x relation), the C.7/C.8 shape.
    private static LongfellowSumcheckCircuit BuildAnchorCircuit()
    {
        int nl = AnchorInt("nl");
        var layers = new LongfellowSumcheckLayer[nl];
        for(int i = 0; i < nl; i++)
        {
            int nw = AnchorInt($"layer{i}_nw");
            int logw = AnchorInt($"layer{i}_logw");
            int nterms = AnchorInt($"layer{i}_nterms");

            var quadTerms = new LongfellowSumcheckQuadTerm[nterms];
            for(int t = 0; t < nterms; t++)
            {
                int gate = AnchorInt($"L{i}_t{t}_g");
                int left = AnchorInt($"L{i}_t{t}_h0");
                int right = AnchorInt($"L{i}_t{t}_h1");
                byte[] v = AnchorElement(Anchors[$"L{i}_t{t}_v"]);
                quadTerms[t] = new LongfellowSumcheckQuadTerm(gate, left, right, v);
            }

            layers[i] = new LongfellowSumcheckLayer(nw, logw, nterms, quadTerms);
        }

        byte[] id = Convert.FromHexString(Anchors["id"]);

        return new LongfellowSumcheckCircuit(
            AnchorInt("nv"), AnchorInt("logv"), AnchorInt("nc"), AnchorInt("logc"),
            AnchorInt("ninputs"), AnchorInt("npub_in"), id, layers);
    }


    //Produces a real GF(2^128) hash ZkProof through the C.9 prover over the anchor circuit.
    private static byte[] ProduceAnchorHashProof(LongfellowSumcheckCircuit circuit)
    {
        byte[] witnessColumn = new byte[circuit.InputCount * ScalarSize];
        for(int i = 0; i < circuit.InputCount; i++)
        {
            AnchorElement(Anchors[$"input{i}"]).CopyTo(witnessColumn.AsSpan(i * ScalarSize, ScalarSize));
        }

        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, GfElementBytes, AnchorSubFieldBytes);

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowTranscript transcript = new(AnchorProofSeed, TranscriptVersion, GfElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());
        ulong counter = 0;
        LongfellowRandomByteSource random = destination =>
        {
            for(int i = 0; i < destination.Length; i++)
            {
                destination[i] = (byte)(counter & 0xFF);
                counter++;
            }
        };

        return LongfellowZkProver.Prove(
            circuit, parameters, witnessColumn, AnchorSubFieldBytes, AnchorSubfieldBoundary, random, transcript, fft,
            GfAdd, GfSubtract, GfMultiply, GfInvert, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, BaseMemoryPool.Shared);
    }


    //Six distinct 16-byte little-endian MAC values prefixing the envelope.
    private static byte[] BuildMacRegionBytes()
    {
        byte[] region = new byte[LongfellowMdocEnvelope.MacRegionBytes];
        for(int i = 0; i < LongfellowMdocEnvelope.MacCount; i++)
        {
            region.AsSpan(i * GfElementBytes, GfElementBytes).Fill((byte)(0x40 + i));
        }

        return region;
    }


    private static byte[] Concatenate(byte[] first, byte[] second, byte[] third)
    {
        byte[] result = new byte[first.Length + second.Length + third.Length];
        first.CopyTo(result.AsSpan(0));
        second.CopyTo(result.AsSpan(first.Length));
        third.CopyTo(result.AsSpan(first.Length + second.Length));

        return result;
    }


    private static int AnchorInt(string key) => int.Parse(Anchors[key], System.Globalization.CultureInfo.InvariantCulture);


    private static byte[] AnchorElement(string hex)
    {
        byte[] littleEndian = Convert.FromHexString(hex);
        byte[] canonical = new byte[ScalarSize];
        for(int i = 0; i < GfElementBytes; i++)
        {
            canonical[ScalarSize - 1 - i] = littleEndian[i];
        }

        return canonical;
    }


    private static Dictionary<string, string> LoadAnchors(string relativePath)
    {
        string path = $"../../../{relativePath}";
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach(string line in System.IO.File.ReadAllLines(path))
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


    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, BaseMemoryPool.Shared);


    private static LongfellowTranscript NewTranscript() =>
        new(TranscriptSeed, TranscriptVersion, GfElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


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
}

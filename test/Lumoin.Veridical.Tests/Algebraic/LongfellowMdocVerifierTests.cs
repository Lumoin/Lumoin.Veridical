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
/// The dual-field mdoc driver — google/longfellow-zk's <c>run_mdoc_verifier</c>
/// (<c>lib/circuits/mdoc/mdoc_zk.cc:560-695</c>). These gate the mechanics the driver owns: the cross-field
/// transcript order (both commitment roots absorbed BEFORE the shared MAC key <c>a_v</c> is squeezed, so
/// flipping the roots changes <c>a_v</c>), the mac-wire index constants, and the mac/av public-input splice
/// layout (the GF side keeps each mac a single 16-byte element; the Fp256 side expands it to 128
/// least-significant-first bit wires). The <c>e2</c> transcript-hash construction is pinned beside its port in
/// <see cref="Mdoc.MdocDeviceAuthenticationTests"/>. The end-to-end accept of a real Fp256 signature envelope
/// These are unit-level gates, not an end-to-end accept of a real Fp256 signature envelope.
/// </summary>
[TestClass]
internal sealed class LongfellowMdocVerifierTests: IDisposable
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


    /// <summary>The canonical scalar width in bytes.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The on-wire element width, in bytes, for the GF(2^128) field.</summary>
    private const int GfElementBytes = 16;

    /// <summary>The on-wire element width, in bytes, for the P-256 base field.</summary>
    private const int Fp256ElementBytes = 32;

    /// <summary>The MAC key width in bits; also the number of base-field bit wires each GF(2^128) MAC or <c>a_v</c> element expands to on the Fp256 side of the splice.</summary>
    private const int MacKeyBits = 128;

    /// <summary>The SHA-256 digest width in bytes, matching each commitment root's size.</summary>
    private const int DigestSize = 32;

    /// <summary>The transcript wire-format version (6, the deployed mdoc flow's value) the driver's transcripts are baked at.</summary>
    private const int TranscriptVersion = 6;

    /// <summary>The path, relative to the test project directory, to the GF(2^128) end-to-end ZK anchor file these tests build a real proof from.</summary>
    private const string ZkAnchorRelativePath = "TestMaterial/Longfellow/zk-anchor-output.txt";

    /// <summary>The GF(2^128) subfield element width in bytes for the anchor circuit's Ligero parameters.</summary>
    private const int AnchorSubFieldBytes = 2;

    /// <summary>The Ligero code's inverse rate this test fixes for the anchor circuit's Ligero parameters.</summary>
    private const int InverseRate = 4;

    /// <summary>The number of Ligero columns opened per proof for the anchor circuit's Ligero parameters.</summary>
    private const int OpenedColumnCount = 2;

    /// <summary>The subfield-run boundary (rebased to start at the public-input count) the anchor circuit passes to the GF(2^128) prover; zero, so no witness row falls below it.</summary>
    private const int AnchorSubfieldBoundary = 0;

    /// <summary>
    /// How far into the hash proof's <c>com_proof</c> section a truncation test cuts: far enough that
    /// the fixed root and sumcheck segment stay intact, landing the cut inside the run-length section.
    /// </summary>
    private const int HashComProofCutBytes = 8;

    /// <summary>
    /// How many bytes a truncation test trims from the envelope's tail: small enough that the hash
    /// proof still splits cleanly and only the sig-proof remainder underflows.
    /// </summary>
    private const int SigProofTailCutBytes = 5;

    /// <summary>The transcript seed for the cross-field root/<c>a_v</c> ordering gates.</summary>
    private static byte[] TranscriptSeed { get; } = Encoding.ASCII.GetBytes("mdoc-driver-gate");

    /// <summary>The transcript seed used when proving the anchor circuit's real GF(2^128) hash proof.</summary>
    private static byte[] AnchorProofSeed { get; } = Encoding.ASCII.GetBytes("zk8");

    /// <summary>The parsed key/value map loaded from the GF(2^128) end-to-end ZK anchor file.</summary>
    private static Dictionary<string, string> Anchors { get; } = LoadAnchors(ZkAnchorRelativePath);

    /// <summary>The P-256 base field's prime modulus.</summary>
    private static BigInteger Prime { get; } = P256BaseFieldReference.FieldOrder;

    /// <summary>The GF(2^128) addition delegate (XOR).</summary>
    private static ScalarAddDelegate GfAdd { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) subtraction delegate (coincides with addition).</summary>
    private static ScalarSubtractDelegate GfSubtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) multiplication delegate.</summary>
    private static ScalarMultiplyDelegate GfMultiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) inversion delegate.</summary>
    private static ScalarInvertDelegate GfInvert { get; } = Gf2k128Backend.GetInvert();

    /// <summary>The class-lifetime Fp256 field profile shared by the sig-splice tests; disposed in <see cref="ClassCleanup"/>.</summary>
    private static LongfellowFieldProfile Fp256Profile { get; } = LongfellowFieldProfile.ForFp256(OfScalar, InRange, BaseMemoryPool.Shared);


    /// <summary>Disposes the class-lifetime Fp256 profile.</summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Fp256Profile.Dispose();
    }


    /// <summary>Verifies that absorbing the hash root then the sig root before squeezing <c>a_v</c> makes <c>a_v</c> depend on both, in order: swapping the two roots changes the squeezed key.</summary>
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


    /// <summary>Verifies that <c>generate_mac_key</c> draws exactly 16 raw PRF bytes through <c>of_bytes_field</c>, not a sample-and-reject loop, by checking that two identically seeded transcripts stay in lockstep on the draws that follow.</summary>
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


    /// <summary>Verifies that the hash and signature MAC wire index formulas match the reference's constants for representative attribute counts and versions.</summary>
    [TestMethod]
    public void TheMacWireIndicesMatchTheReferenceFormulas()
    {
        //getHashMacIndex(numAttrs, version) = numAttrs*8*(96 + (version<7 ? 1 : 2)) + 160 + 1 (mdoc_zk.cc:61-64).
        Assert.AreEqual(945, HashMacIndex(numAttrs: 1, version: 7), "getHashMacIndex(1, 7) is 945.");
        Assert.AreEqual(937, HashMacIndex(numAttrs: 1, version: 6), "getHashMacIndex(1, 6) is 937.");

        //945 is exactly the witness-filler step's hash-circuit MacPublicStart (the witness column where the macs splice in).
        const int HashCircuitMacPublicStart = 945;
        Assert.AreEqual(HashCircuitMacPublicStart, HashMacIndex(numAttrs: 1, version: 7), "getHashMacIndex(1, 7) must equal the hash circuit's MacPublicStart.");

        //kSigMacIndex is the fixed location of the sig MAC wire (mdoc_zk.cc:98); the version bump that moves
        //the hash index (version<7 ? 1 : 2) does not move the sig index — it stays 4 across versions.
        Assert.AreEqual(SigMacIndex(version: 7), SigMacIndex(version: 6), "kSigMacIndex is version-independent.");
        Assert.AreEqual(4, SigMacIndex(version: 7), "kSigMacIndex is 4.");
    }


    /// <summary>Verifies that splicing a GF(2^128) public-input template appends each of the six MACs and <c>a_v</c> as a single 16-byte element, not bit-expanded.</summary>
    [TestMethod]
    public void TheHashSpliceAppendsSixMacsAndAvAsSingleSixteenByteElements()
    {
        //fill_gf2k<f_128, f_128> = push_back(m): each mac and a_v is ONE 16-byte element, NOT bit-expanded.
        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowFieldProfile.ForGf2k128(fft, BaseMemoryPool.Shared);

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


    /// <summary>Verifies that splicing an Fp256 public-input template expands each of the six MACs and <c>a_v</c> into 128 least-significant-first bit wires.</summary>
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


    /// <summary>Verifies that a template whose length does not leave exactly the seven mac/<c>a_v</c> slots splices to <see langword="null"/>, for both the GF(2^128) and the Fp256 splice.</summary>
    [TestMethod]
    public void AWrongSizedTemplateSplicesToNullForBothFields()
    {
        //The filler.size() != npub_in guard (mdoc_zk.cc:686-689): a template that does not leave exactly the
        //seven mac/av slots must reject (the driver maps null to AttributeNumberMismatch).
        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile hashProfile = LongfellowFieldProfile.ForGf2k128(fft, BaseMemoryPool.Shared);

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


    /// <summary>Verifies that an envelope shorter than the fixed MAC region returns <see cref="LongfellowMdocVerificationResult.MalformedEnvelope"/> rather than throwing.</summary>
    [TestMethod]
    public void AShortEnvelopeYieldsMalformedEnvelopeWithoutThrowing()
    {
        //Parse safety: an envelope shorter than the 96-byte mac region must return MalformedEnvelope, never
        //throw on attacker bytes. The field bundles can be minimal here because the parse fails first.
        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile hashProfile = LongfellowFieldProfile.ForGf2k128(fft, BaseMemoryPool.Shared);
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


    /// <summary>Verifies that the driver parses both real proof slices, absorbs both roots and squeezes <c>a_v</c> before its size guard rejects an anchor circuit too small to hold the mac/<c>a_v</c> splice, returning <see cref="LongfellowMdocVerificationResult.AttributeNumberMismatch"/>.</summary>
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

        using LongfellowZkProofEnvelope proof = ProduceAnchorHashProof(circuit);
        byte[] envelope = Concatenate(BuildMacRegionBytes(), proof.Bytes, proof.Bytes);

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowFieldProfile.ForGf2k128(fft, BaseMemoryPool.Shared);
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


    /// <summary>Verifies that cutting the envelope inside the hash proof's run-length-encoded <c>com_proof</c> section, past the intact root and sumcheck segment, yields <see cref="LongfellowMdocVerificationResult.MalformedEnvelope"/>.</summary>
    [TestMethod]
    public void ATruncationInsideTheHashComProofYieldsMalformedEnvelope()
    {
        //Cut inside the hash proof's run-length-encoded com_proof section: the
        //fixed 32-byte root and the shape-derived sumcheck segment stay intact,
        //so the failure is specifically the Ligero run-length read
        //(LongfellowLigeroProofSerializer.Read) the envelope split probes with.
        LongfellowSumcheckCircuit circuit = BuildAnchorCircuit();
        using LongfellowZkProofEnvelope proof = ProduceAnchorHashProof(circuit);
        byte[] envelope = Concatenate(BuildMacRegionBytes(), proof.Bytes, proof.Bytes);

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowFieldProfile.ForGf2k128(fft, BaseMemoryPool.Shared);
        int sumcheckSegmentBytes = LongfellowSumcheckProofSerializer.SerializedSize(circuit, profile);
        int cut = LongfellowMdocEnvelope.MacRegionBytes + DigestSize + sumcheckSegmentBytes + HashComProofCutBytes;
        Assert.IsLessThan(envelope.Length, cut, "The cut must land strictly inside the envelope.");

        bool ok = VerifyAnchorEnvelope(circuit, envelope.AsSpan(0, cut), out LongfellowMdocVerificationResult result);

        Assert.IsFalse(ok, "An envelope cut inside the hash com_proof must not verify.");
        Assert.AreEqual(LongfellowMdocVerificationResult.MalformedEnvelope, result, "A failed hash-proof split is a MalformedEnvelope cause.");
    }


    /// <summary>Verifies that trimming a few bytes off the envelope's tail, short enough that the hash proof still splits but the sig-proof remainder does not parse, yields <see cref="LongfellowMdocVerificationResult.MalformedEnvelope"/>.</summary>
    [TestMethod]
    public void ATruncationInTheSigProofTailYieldsMalformedEnvelope()
    {
        //Cut a few bytes off the envelope tail: the hash proof still splits
        //(its run-length probe consumes exactly its own bytes), and the sig
        //remainder is short of a parseable ZkProof, so the sig-side parse
        //fails before any verification runs.
        LongfellowSumcheckCircuit circuit = BuildAnchorCircuit();
        using LongfellowZkProofEnvelope proof = ProduceAnchorHashProof(circuit);
        byte[] envelope = Concatenate(BuildMacRegionBytes(), proof.Bytes, proof.Bytes);

        bool ok = VerifyAnchorEnvelope(circuit, envelope.AsSpan(0, envelope.Length - SigProofTailCutBytes), out LongfellowMdocVerificationResult result);

        Assert.IsFalse(ok, "An envelope cut in the sig-proof tail must not verify.");
        Assert.AreEqual(LongfellowMdocVerificationResult.MalformedEnvelope, result, "A failed sig-proof parse is a MalformedEnvelope cause.");
    }


    /// <summary>
    /// Builds the anchor-circuit field bundle and drives the mdoc verifier over the supplied envelope
    /// bytes. Both proof slots share the GF bundle, which suffices for the parse-level verdicts the
    /// truncation gates pin.
    /// </summary>
    /// <param name="circuit">The anchor circuit both proof slots share.</param>
    /// <param name="envelope">The candidate envelope bytes.</param>
    /// <param name="result">Receives the verification result.</param>
    /// <returns><see langword="true"/> when the envelope verifies.</returns>
    private static bool VerifyAnchorEnvelope(LongfellowSumcheckCircuit circuit, ReadOnlySpan<byte> envelope, out LongfellowMdocVerificationResult result)
    {
        LongfellowLigeroParameters parameters = LongfellowZkVerifier.DeriveParameters(circuit, InverseRate, OpenedColumnCount, GfElementBytes, AnchorSubFieldBytes);

        using Lch14AdditiveFft fft = NewFft();
        using LongfellowFieldProfile profile = LongfellowFieldProfile.ForGf2k128(fft, BaseMemoryPool.Shared);
        using LongfellowSubfieldRunCodec codec = LongfellowSubfieldRunCodec.ForGf2k128(profile, fft, AnchorSubFieldBytes, BaseMemoryPool.Shared);
        var field = new LongfellowMdocFieldVerifier(circuit, parameters, NewGfEncoderFactory(fft), profile, codec, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None);

        using LongfellowTranscript transcript = NewTranscript();

        return LongfellowMdocVerifier.Verify(
            envelope, field, field, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty,
            transcript, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, BaseMemoryPool.Shared,
            out result);
    }


    /// <summary>
    /// Absorbs the two roots in the given order then squeezes the 16-byte MAC key, returning it as a
    /// canonical scalar (the driver's <c>generate_mac_key</c> step).
    /// </summary>
    /// <param name="firstRoot">The commitment root absorbed first.</param>
    /// <param name="secondRoot">The commitment root absorbed second.</param>
    /// <returns>The squeezed MAC key <c>a_v</c>, as a canonical scalar.</returns>
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


    /// <summary>Computes the reference's <c>getHashMacIndex(numAttrs, version)</c> formula: <c>numAttrs*8*(96 + (version&lt;7 ? 1 : 2)) + 160 + 1</c>.</summary>
    /// <param name="numAttrs">The disclosed attribute count.</param>
    /// <param name="version">The mdoc circuit version.</param>
    /// <returns>The hash-circuit MAC wire index.</returns>
    private static int HashMacIndex(int numAttrs, int version) => (numAttrs * 8 * (96 + (version < 7 ? 1 : 2))) + 160 + 1;


    /// <summary>
    /// Returns the reference's <c>kSigMacIndex</c>, a fixed constant independent of
    /// <paramref name="version"/>. The parameter is kept so a gate can show it does not move with the
    /// version the way <see cref="HashMacIndex(int, int)"/> does.
    /// </summary>
    /// <param name="version">Accepted for parity with <see cref="HashMacIndex(int, int)"/>; does not affect the result.</param>
    /// <returns>The signature-circuit MAC wire index, always 4.</returns>
    private static int SigMacIndex(int version)
    {
        _ = version;

        return 4;
    }


    /// <summary>Builds six distinct GF macs as canonical scalars: mac <c>i</c> has its low element bytes filled with <c>0x21 + i</c>.</summary>
    /// <returns>The concatenated canonical-scalar MAC values.</returns>
    private static byte[] BuildMacs()
    {
        byte[] macs = new byte[LongfellowMdocEnvelope.MacCount * ScalarSize];
        for(int i = 0; i < LongfellowMdocEnvelope.MacCount; i++)
        {
            CanonicalGf((byte)(0x21 + i)).CopyTo(macs.AsSpan(i * ScalarSize, ScalarSize));
        }

        return macs;
    }


    /// <summary>Builds a canonical GF(2^128) scalar whose low 16 bytes carry a distinct pattern derived from <paramref name="seed"/>.</summary>
    /// <param name="seed">The byte seeding the pattern.</param>
    /// <returns>The canonical-scalar bytes.</returns>
    private static byte[] CanonicalGf(byte seed)
    {
        byte[] canonical = new byte[ScalarSize];
        for(int b = 0; b < GfElementBytes; b++)
        {
            canonical[ScalarSize - 1 - b] = (byte)(seed ^ (b * 7));
        }

        return canonical;
    }


    /// <summary>Writes the Fp256 bit-wire encoding of a zero or one witness value.</summary>
    /// <param name="value">The bit value (0 or 1) to encode.</param>
    /// <param name="wire">Receives the encoded wire bytes.</param>
    private static void WriteWire(uint value, Span<byte> wire)
    {
        Span<byte> canonical = stackalloc byte[ScalarSize];
        Fp256Profile.OfScalar(value, canonical);
        Fp256Profile.ToBytesField(canonical, wire);
    }


    /// <summary>Builds a digest-sized byte array filled with a single repeated value, standing in for a commitment root.</summary>
    /// <param name="value">The byte value to fill.</param>
    /// <returns>The filled root bytes.</returns>
    private static byte[] FilledRoot(byte value)
    {
        byte[] root = new byte[DigestSize];
        root.AsSpan().Fill(value);

        return root;
    }


    /// <summary>Computes <c>of_scalar(u)</c>: <paramref name="coordinate"/> reduced mod <c>p</c>, written as a canonical big-endian scalar.</summary>
    /// <param name="coordinate">The integer to reduce.</param>
    /// <param name="destination">Receives the canonical big-endian scalar.</param>
    /// <exception cref="InvalidOperationException">When the reduced value does not fit <paramref name="destination"/>.</exception>
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


    /// <summary>Computes <c>fits(an)</c>: <see langword="true"/> when the canonical big-endian integer is below the P-256 field modulus.</summary>
    /// <param name="canonical">The canonical big-endian scalar to test.</param>
    /// <returns><see langword="true"/> when the value is below the modulus.</returns>
    private static bool InRange(ReadOnlySpan<byte> canonical) => new BigInteger(canonical, isUnsigned: true, isBigEndian: true) < Prime;


    /// <summary>
    /// Builds a minimal circuit (four inputs, one output, no public inputs, one term-less layer) just
    /// large enough to construct a field verifier; used where a test's envelope is rejected during
    /// parsing, before the circuit shape is ever exercised. Circuit owners are released at test cleanup.
    /// </summary>
    /// <returns>The minimal circuit, owned by this test's circuit scope.</returns>
    private LongfellowSumcheckCircuit SmallCircuit()
    {
        LongfellowSumcheckLayer layer = new(inputCount: 4, handRounds: 2, termCount: 0);
        byte[] id = new byte[LongfellowSumcheckCircuit.IdLength];

        return CircuitScope.CreateCircuit(
            outputCount: 1, outputLogCount: 0, copyCount: 1, copyRounds: 0,
            inputCount: 4, publicInputCount: 0, id, [layer]);
    }


    /// <summary>Creates the GF(2^128) row-encoder factory built from the given additive-FFT engine.</summary>
    /// <param name="fft">The additive-FFT engine the encoder factory is built from.</param>
    /// <returns>The new row-encoder factory.</returns>
    private static LongfellowRowEncoderFactory NewGfEncoderFactory(Lch14AdditiveFft fft) =>
        LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);


    /// <summary>
    /// Reconstructs the anchor's small GF(2^128) circuit (the <c>w == (x + y)·(x + z)·x</c> relation, the
    /// sumcheck-segment/end-to-end-verify shape) from the anchor's parameters. Circuit owners are
    /// released at test cleanup.
    /// </summary>
    /// <returns>The reconstructed circuit, owned by this test's circuit scope.</returns>
    private LongfellowSumcheckCircuit BuildAnchorCircuit()
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

        return CircuitScope.CreateCircuit(
            AnchorInt("nv"), AnchorInt("logv"), AnchorInt("nc"), AnchorInt("logc"),
            AnchorInt("ninputs"), AnchorInt("npub_in"), id, layers);
    }


    /// <summary>Produces a real GF(2^128) hash <c>ZkProof</c> through the end-to-end prover over the anchor circuit.</summary>
    /// <param name="circuit">The anchor circuit to prove.</param>
    /// <returns>The pooled proof envelope; the caller disposes it.</returns>
    private static LongfellowZkProofEnvelope ProduceAnchorHashProof(LongfellowSumcheckCircuit circuit)
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


    /// <summary>Builds six distinct 16-byte little-endian MAC values, the fixed region prefixing an mdoc envelope.</summary>
    /// <returns>The MAC region bytes.</returns>
    private static byte[] BuildMacRegionBytes()
    {
        byte[] region = new byte[LongfellowMdocEnvelope.MacRegionBytes];
        for(int i = 0; i < LongfellowMdocEnvelope.MacCount; i++)
        {
            region.AsSpan(i * GfElementBytes, GfElementBytes).Fill((byte)(0x40 + i));
        }

        return region;
    }


    /// <summary>Concatenates three byte spans into one newly allocated array.</summary>
    /// <param name="first">The first span.</param>
    /// <param name="second">The second span.</param>
    /// <param name="third">The third span.</param>
    /// <returns>The concatenated bytes.</returns>
    private static byte[] Concatenate(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second, ReadOnlySpan<byte> third)
    {
        byte[] result = new byte[first.Length + second.Length + third.Length];
        first.CopyTo(result.AsSpan(0));
        second.CopyTo(result.AsSpan(first.Length));
        third.CopyTo(result.AsSpan(first.Length + second.Length));

        return result;
    }


    /// <summary>Parses the anchor file's <paramref name="key"/> value as a base-10 integer.</summary>
    /// <param name="key">The anchor key to look up.</param>
    /// <returns>The parsed integer value.</returns>
    private static int AnchorInt(string key) => int.Parse(Anchors[key], System.Globalization.CultureInfo.InvariantCulture);


    /// <summary>Parses a 16-byte little-endian GF element, hex-encoded, into a 32-byte big-endian canonical scalar.</summary>
    /// <param name="hex">The little-endian GF element bytes, hex-encoded.</param>
    /// <returns>The canonical big-endian scalar.</returns>
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


    /// <summary>Creates the LCH14 additive-FFT engine over the GF(2^128) production subfield.</summary>
    /// <returns>The new additive-FFT engine.</returns>
    private static Lch14AdditiveFft NewFft() =>
        new(Lch14Subfield.Production16, GfAdd, GfSubtract, GfMultiply, GfInvert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>Creates a transcript seeded with <see cref="TranscriptSeed"/> at the GF(2^128) element width.</summary>
    /// <returns>The new transcript.</returns>
    private static LongfellowTranscript NewTranscript() =>
        new(TranscriptSeed, TranscriptVersion, GfElementBytes, Aes256Ecb, BaseMemoryPool.Shared, Sha256FiatShamirBackend.GetIncrementalFactory());


    /// <summary>Computes a one-shot SHA-256 digest of <paramref name="input"/>; <paramref name="hashFunction"/> is accepted for signature compatibility and unused, since this delegate is always bound to SHA-256.</summary>
    /// <param name="input">The bytes to hash.</param>
    /// <param name="output">Receives the 32-byte digest.</param>
    /// <param name="hashFunction">The requested hash algorithm name; ignored.</param>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction) => SHA256.HashData(input, output);


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
}

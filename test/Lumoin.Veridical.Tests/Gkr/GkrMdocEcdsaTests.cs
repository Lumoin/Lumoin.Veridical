using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Ligero.Gadgets;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.Mdoc;
using System;
using System.Buffers;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The issuer's real ES256 signature verified in-circuit against the SAME committed digest
/// bits that the digest-only binding (<see cref="GkrMdocDigestTests"/>) MAC-binds. The 256 message
/// bits of the cross-field MAC region (<see cref="GkrCrossFieldMacSupport"/>) are real Fp256 wires
/// 0..41471 of the ECDSA gadget's builder; the ECDSA verifier consumes those exact wires as its
/// <c>e·G</c> ladder scalar through
/// <see cref="EcdsaVerificationGadgetExtensions.AssertVerifiesDigestBits"/>. So ONE Fp256
/// commitment proves both "these bits satisfy the cross-field MAC of the GF-side SHA-256" and "the
/// issuer's ES256 signature verifies for e = these bits". The binding is by wire identity, not by
/// glue constraints. The GF side is the digest-only binding (<see cref="GkrMdocDigestTests"/>)
/// verbatim, shared through <see cref="GkrMdocSupport"/>.
/// </summary>
[TestClass]
internal sealed class GkrMdocEcdsaTests
{
    /// <summary>The byte width of one Fp256/GF(2^128) scalar wire, matching <see cref="GkrGf2kShaSupport.ScalarSize"/>.</summary>
    private const int ScalarSize = GkrGf2kShaSupport.ScalarSize;

    /// <summary>The number of polynomial bits per MAC half, matching <see cref="GkrGf2kMacSupport.HalfBits"/>.</summary>
    private const int HalfBits = GkrGf2kMacSupport.HalfBits;

    /// <summary>The number of MAC halves (verifier-key copies) the cross-field MAC commits, matching <see cref="GkrGf2kMacSupport.CopyCount"/>.</summary>
    private const int Halves = GkrGf2kMacSupport.CopyCount;

    /// <summary>The SHA-256 digest width in bytes, matching <see cref="GkrShaRoundSupport.DigestBytes"/>.</summary>
    private const int DigestBytes = GkrShaRoundSupport.DigestBytes;

    /// <summary>The SHA-256 digest width in bits, the number of MAC message wires the ECDSA gadget consumes as its <c>e</c> scalar.</summary>
    private const int DigestBits = DigestBytes * GkrShaRoundSupport.BitsPerByte;

    /// <summary>The number of Fp256 wires the cross-field MAC region occupies, matching <see cref="GkrCrossFieldMacSupport.FpWitnessCount"/>.</summary>
    private const int FpWitnessCount = GkrCrossFieldMacSupport.FpWitnessCount;

    /// <summary>The Ligero inverse rate this test's constraint-system builder uses.</summary>
    private const int InverseRate = 4;

    /// <summary>The number of Ligero columns opened by this test's constraint-system builder.</summary>
    private const int OpenedColumns = 4;

    /// <summary>The Ligero encoded block length this test's constraint-system builder uses.</summary>
    private const int Block = 64;

    /// <summary>The seed for the deterministic masking randomness the cross-field MAC witness packing draws from.</summary>
    private static byte[] MaskSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.mdoc.ecdsa.mask.v1");

    /// <summary>The two fixed MAC verifier-key shares, one per half, held constant across every test in this class.</summary>
    private static byte[][] KeyShares { get; } =
    [
        GkrCrossFieldMacSupport.Element(0x243f6a8885a308d3UL, 0x13198a2e03707344UL),
        GkrCrossFieldMacSupport.Element(0xa4093822299f31d0UL, 0x082efa98ec4e6c89UL),
    ];

    /// <summary>The real mdoc credential's disclosed <c>age_over_18</c> claim, loaded once and shared across every test in this class.</summary>
    private static MdocDisclosure Disclosure { get; } = LoadDisclosure();

    /// <summary>The disclosure's signed COSE <c>Sig_structure</c> bytes, the exact bytes the issuer's ES256 signature covers.</summary>
    private static byte[] SignedStructure { get; } = Disclosure.SignedStructure;

    /// <summary>The shared GKR support wrapping the signed structure and MAC key shares for every test's digest and MAC computations.</summary>
    private static GkrMdocSupport Support { get; } = new(SignedStructure, KeyShares);

    /// <summary>The P-256 short-Weierstrass curve coefficient <c>a</c>.</summary>
    private static BigInteger A { get; } = P256BigIntegerG1Reference.CurveA;

    /// <summary>The P-256 short-Weierstrass curve coefficient <c>b</c>.</summary>
    private static BigInteger B { get; } = P256BigIntegerG1Reference.CurveB;

    /// <summary>The canonical scalar encoding of <see cref="A"/>, fed to the in-circuit curve gadget.</summary>
    private static byte[] CurveABytes { get; } = EcdsaNonceRecovery.Bytes(A);

    /// <summary>The canonical scalar encoding of <see cref="B"/>, fed to the in-circuit curve gadget.</summary>
    private static byte[] CurveBBytes { get; } = EcdsaNonceRecovery.Bytes(B);


    /// <summary>Verifies that the MAC region's (half, polynomial-bit) index mapping reassembles exactly the real SHA-256 digest bytes, before any circuit trusts that mapping.</summary>
    [TestMethod]
    public void TheDigestBitMappingReassemblesTheRealDigest()
    {
        //The eBits mapping must read the MAC region's message bits as exactly the big-endian
        //digest bytes. Reassemble the digest from GkrGf2kMacSupport.HalfBit through the same
        //(half, polynomial-bit) decomposition the eBits indices use, before any circuit trusts it.
        Span<byte> digest = stackalloc byte[DigestBytes];
        Support.ComputeDigest(digest);

        Span<byte> reassembled = stackalloc byte[DigestBytes];
        reassembled.Clear();
        for(int j = 0; j < DigestBits; j++)
        {
            int b = j >> 3;
            int k = 7 - (j & 7);
            int h = b / 16;
            int i = ((15 - (b % 16)) * 8) + k;
            int bit = GkrGf2kMacSupport.HalfBit(digest, h, i);
            reassembled[b] |= (byte)(bit << k);
        }

        Assert.IsTrue(reassembled.SequenceEqual(digest), "The eBits mapping must reassemble the real digest bytes.");
    }


    /// <summary>Checks the ECDSA and MAC constraints over an owned pooled witness snapshot.</summary>
    [TestMethod]
    public void TheMacBoundDigestBitsSatisfyTheEcdsaVerifierInCircuit()
    {
        //The combined builder over the real credential: the MAC region holds the genuine digest
        //bits, and the ECDSA gadget consumes them as its e·G scalar. The gadget constraints
        //(IsSatisfied) check the signature side; the MAC quadratics/parity live outside the
        //builder and are checked directly here.
        Span<byte> digest = stackalloc byte[DigestBytes];
        Support.ComputeDigest(digest);
        Assert.IsTrue(digest.SequenceEqual(SHA256.HashData(SignedStructure)), "The in-circuit digest must be SHA256.HashData of the real Sig_structure.");

        using IMemoryOwner<byte> fpWitnessOwner = BaseMemoryPool.Shared.Rent(GkrCrossFieldMacSupport.FpWitnessBytes);
        Span<byte> fpWitness = fpWitnessOwner.Memory.Span[..GkrCrossFieldMacSupport.FpWitnessBytes];
        GkrCrossFieldMacSupport.PackFpWitness(fpWitness, digest, KeyShares, MaskSeed);

        using LigeroConstraintSystemBuilder builder = BuildEcdsaBuilder(fpWitness, digest);

        //The gadget side: the ECDSA identity vanishes on the committed digest bits.
        Assert.IsTrue(LigeroConstraintEvaluator.IsSatisfied(builder), "The real credential's ECDSA signature must verify on the committed digest bits.");

        //The MAC quadratics: every product triple and bitness over the packed MAC bytes (the MAC
        //region is wires 0..FpWitnessCount-1, so the indices line up with the builder witness).
        using IMemoryOwner<byte>? witnessOwner = builder.WitnessBytes();
        ReadOnlySpan<byte> witnessBytes = (witnessOwner?.Memory ?? Memory<byte>.Empty).Span;
        Assert.IsTrue(QuadraticsSatisfied(GkrCrossFieldMacSupport.BuildFpQuadratics(), witnessBytes), "Every MAC product and bitness quadratic must hold over the packed witness.");

        //The parity statement reproduces: the masked quotients from the witness make every parity
        //target hold against the macs of the real digest.
        Span<byte> verifierKey = stackalloc byte[ScalarSize];
        verifierKey[ScalarSize - 1] = 0x2A;
        Span<byte> macs = stackalloc byte[Halves * ScalarSize];
        GkrGf2kMacSupport.ComputeMacs(digest, KeyShares, verifierKey, macs);
        ulong[] maskedQuotients = new ulong[Halves * HalfBits];
        GkrCrossFieldMacSupport.ComputeMaskedQuotients(fpWitness, verifierKey, macs, maskedQuotients);
        Assert.IsTrue(ParityStatementSatisfied(verifierKey, macs, maskedQuotients, witnessBytes), "The MAC parity statement must hold over the packed witness.");

        //A perturbed masked quotient must break its parity target: the published V_c no longer
        //equals (T_c−mac_c)/2 + R_c, so Σ coefficient·W ≠ target for that constraint.
        maskedQuotients[0] += 1;
        Assert.IsFalse(ParityStatementSatisfied(verifierKey, macs, maskedQuotients, witnessBytes), "A perturbed masked quotient must break the MAC parity statement.");
    }


    /// <summary>Verifies that flipping one digest bit in the MAC region, leaving the signature components untouched, breaks the in-circuit ECDSA identity — evidence that the verifier consumes the committed MAC bits and not a separate copy.</summary>
    [TestMethod]
    public void AFlippedDigestBitBreaksTheEcdsaVerifier()
    {
        //THE BINDING GATE: flip ONE digest bit in the MAC region of the witness, leave r/s/Q/R
        //unmodified. The ladder then computes e·G for the wrong e, the identity does not vanish,
        //and IsSatisfied is false. This shows the ECDSA verifier really consumes the committed MAC
        //bits — not a separate copy.
        Span<byte> digest = stackalloc byte[DigestBytes];
        Support.ComputeDigest(digest);

        byte[] tamperedDigest = new byte[DigestBytes];
        digest.CopyTo(tamperedDigest);
        tamperedDigest[5] ^= 0x08;

        using IMemoryOwner<byte> fpWitnessOwner = BaseMemoryPool.Shared.Rent(GkrCrossFieldMacSupport.FpWitnessBytes);
        Span<byte> fpWitness = fpWitnessOwner.Memory.Span[..GkrCrossFieldMacSupport.FpWitnessBytes];
        //The MAC region carries the tampered digest, but R/Q/r/s are recovered for the real one.
        GkrCrossFieldMacSupport.PackFpWitness(fpWitness, tamperedDigest, KeyShares, MaskSeed);

        using LigeroConstraintSystemBuilder builder = BuildEcdsaBuilder(fpWitness, digest);

        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), "A flipped digest bit in the MAC region must break the ECDSA identity.");
    }


    /// <summary>Verifies that tampering with either signature component (<c>r</c> or <c>s</c>), while keeping the real digest bits and recovered nonce point, breaks the in-circuit ECDSA identity.</summary>
    [TestMethod]
    public void ATamperedSignatureComponentBreaksTheEcdsaVerifier()
    {
        //The MAC region holds the genuine digest bits and R is recovered from the REAL (Q, e, r, s),
        //so R = k·G of the real signature. Feeding a tampered public signature component to the
        //gadget (the recovered R no longer satisfies u1·G + u2·Q = R for the tampered values) must
        //break the identity. This is the surface this composition introduced and otherwise leaves
        //untested: the gadget really consumes the disclosure's r and s.
        Span<byte> digest = stackalloc byte[DigestBytes];
        Support.ComputeDigest(digest);

        using IMemoryOwner<byte> fpWitnessOwner = BaseMemoryPool.Shared.Rent(GkrCrossFieldMacSupport.FpWitnessBytes);
        Span<byte> fpWitness = fpWitnessOwner.Memory.Span[..GkrCrossFieldMacSupport.FpWitnessBytes];
        GkrCrossFieldMacSupport.PackFpWitness(fpWitness, digest, KeyShares, MaskSeed);

        BigInteger qx = EcdsaNonceRecovery.ToInteger(Disclosure.IssuerKeyX);
        BigInteger qy = EcdsaNonceRecovery.ToInteger(Disclosure.IssuerKeyY);
        BigInteger r = EcdsaNonceRecovery.ToInteger(Disclosure.SignatureR);
        BigInteger s = EcdsaNonceRecovery.ToInteger(Disclosure.SignatureS);

        //A tampered s' = (s+1) mod n with the real eBits/R/Q/r.
        using LigeroConstraintSystemBuilder tamperedS = BuildEcdsaBuilder(fpWitness, digest, qx, qy, r, EcdsaNonceRecovery.ModN(s + 1));
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(tamperedS), "A tampered signature s must break the ECDSA identity on the real credential.");

        //A tampered r' = (r+1) mod n with the real eBits/R/Q/s.
        using LigeroConstraintSystemBuilder tamperedR = BuildEcdsaBuilder(fpWitness, digest, qx, qy, EcdsaNonceRecovery.ModN(r + 1), s);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(tamperedR), "A tampered signature r must break the ECDSA identity on the real credential.");
    }


    /// <summary>Verifies that swapping the issuer's public key for a different valid P-256 point, while keeping the real digest bits and signature, breaks the in-circuit ECDSA identity.</summary>
    [TestMethod]
    public void AWrongIssuerKeyBreaksTheEcdsaVerifier()
    {
        //Swap the issuer key Q for a different valid P-256 point (the generator G, on-curve) while
        //keeping eBits/r/s and the recovered R real. R is recovered from the REAL (Q, e, r, s), so
        //with Q' = G the identity u1·G + u2·Q' = R cannot vanish. A signature must not verify under
        //a different public key.
        Span<byte> digest = stackalloc byte[DigestBytes];
        Support.ComputeDigest(digest);

        using IMemoryOwner<byte> fpWitnessOwner = BaseMemoryPool.Shared.Rent(GkrCrossFieldMacSupport.FpWitnessBytes);
        Span<byte> fpWitness = fpWitnessOwner.Memory.Span[..GkrCrossFieldMacSupport.FpWitnessBytes];
        GkrCrossFieldMacSupport.PackFpWitness(fpWitness, digest, KeyShares, MaskSeed);

        BigInteger r = EcdsaNonceRecovery.ToInteger(Disclosure.SignatureR);
        BigInteger s = EcdsaNonceRecovery.ToInteger(Disclosure.SignatureS);

        using LigeroConstraintSystemBuilder builder = BuildEcdsaBuilder(fpWitness, digest, EcdsaNonceRecovery.Gx, EcdsaNonceRecovery.Gy, r, s);
        Assert.IsFalse(LigeroConstraintEvaluator.IsSatisfied(builder), "The real signature must not verify under a different issuer key.");
    }


    /// <summary>Builds the combined Fp builder over the real credential's own signature: the public key and signature components come straight from <see cref="Disclosure"/>.</summary>
    /// <param name="fpWitness">The packed cross-field MAC witness bytes occupying the first <see cref="FpWitnessCount"/> wires.</param>
    /// <param name="digest">The digest whose full integer value becomes the ECDSA gadget's <c>e</c> scalar.</param>
    /// <returns>A new constraint-system builder with the MAC region and the ECDSA gadget both asserted; the caller disposes it.</returns>
    private static LigeroConstraintSystemBuilder BuildEcdsaBuilder(ReadOnlySpan<byte> fpWitness, ReadOnlySpan<byte> digest) =>
        BuildEcdsaBuilder(
            fpWitness, digest,
            EcdsaNonceRecovery.ToInteger(Disclosure.IssuerKeyX), EcdsaNonceRecovery.ToInteger(Disclosure.IssuerKeyY),
            EcdsaNonceRecovery.ToInteger(Disclosure.SignatureR), EcdsaNonceRecovery.ToInteger(Disclosure.SignatureS));


    /// <summary>
    /// Builds the combined Fp builder: the MAC region as the first <see cref="FpWitnessCount"/> wires (in
    /// <c>PackFpWitness</c> order, so the MAC indices resolve to those wires), then the ECDSA gadget over the
    /// same builder with the digest bits — at their MAC message wires — as the <c>e·G</c> scalar. The nonce
    /// point <c>R</c> is recovered from the real public <c>(Q, e, r, s)</c>, so a caller can pass a tampered
    /// <paramref name="qx"/>/<paramref name="qy"/>/<paramref name="r"/>/<paramref name="s"/> while <c>R</c>
    /// stays the point the real signature determines; a tampered component then makes the recovered <c>R</c>
    /// fail the gadget identity.
    /// </summary>
    /// <param name="fpWitness">The packed cross-field MAC witness bytes occupying the first <see cref="FpWitnessCount"/> wires.</param>
    /// <param name="digest">The digest whose full integer value becomes the ECDSA gadget's <c>e</c> scalar.</param>
    /// <param name="qx">The issuer public key's <c>x</c> coordinate to feed the gadget, real or tampered.</param>
    /// <param name="qy">The issuer public key's <c>y</c> coordinate to feed the gadget, real or tampered.</param>
    /// <param name="r">The signature's <c>r</c> component to feed the gadget, real or tampered.</param>
    /// <param name="s">The signature's <c>s</c> component to feed the gadget, real or tampered.</param>
    /// <returns>A new constraint-system builder with the MAC region and the ECDSA gadget both asserted; the caller disposes it.</returns>
    private static LigeroConstraintSystemBuilder BuildEcdsaBuilder(
        ReadOnlySpan<byte> fpWitness, ReadOnlySpan<byte> digest, BigInteger qx, BigInteger qy, BigInteger r, BigInteger s)
    {
        var builder = new LigeroConstraintSystemBuilder(
            Montgomery.Add, Montgomery.Subtract, Montgomery.Multiply, Montgomery.Invert, Montgomery.Reduce,
            CurveParameterSet.None, InverseRate, OpenedColumns, Block, BaseMemoryPool.Shared);

        //The MAC region: each of the FpWitnessCount scalars as a dense wire from index 0.
        int last = -1;
        for(int i = 0; i < FpWitnessCount; i++)
        {
            last = builder.AddWire(fpWitness.Slice(i * ScalarSize, ScalarSize));
        }

        Assert.AreEqual(FpWitnessCount - 1, last, "The MAC region must occupy wires 0..FpWitnessCount-1 densely.");

        //The eBits: the committed MAC message wires, most-significant digest bit first.
        int[] eBits = DigestBitWires();

        var curve = new EcdsaCurve(
            WeierstrassCurve.Create(builder, CurveABytes, CurveBBytes),
            EcdsaNonceRecovery.Bytes(EcdsaNonceRecovery.Gx), EcdsaNonceRecovery.Bytes(EcdsaNonceRecovery.Gy), EcdsaNonceRecovery.Bytes(EcdsaNonceRecovery.N));

        BigInteger qxReal = EcdsaNonceRecovery.ToInteger(Disclosure.IssuerKeyX);
        BigInteger qyReal = EcdsaNonceRecovery.ToInteger(Disclosure.IssuerKeyY);
        BigInteger rReal = EcdsaNonceRecovery.ToInteger(Disclosure.SignatureR);
        BigInteger sReal = EcdsaNonceRecovery.ToInteger(Disclosure.SignatureS);
        BigInteger e = EcdsaNonceRecovery.ToInteger(digest);
        (BigInteger rx, BigInteger ry) = EcdsaNonceRecovery.RecoverNoncePoint(qxReal, qyReal, e, rReal, sReal);

        builder.AssertVerifiesDigestBits(
            curve,
            new EcdsaHashedPublicInputs(EcdsaNonceRecovery.Bytes(qx), EcdsaNonceRecovery.Bytes(qy), EcdsaNonceRecovery.Bytes(r), EcdsaNonceRecovery.Bytes(s)),
            new EcdsaWitness(EcdsaNonceRecovery.Bytes(rx), EcdsaNonceRecovery.Bytes(ry)),
            eBits);

        return builder;
    }


    /// <summary>
    /// Computes the 256 MAC message wires that hold the digest, most-significant digest bit first: digest
    /// bit <c>j</c> (<c>j=0</c> the MSB of byte 0) lives at <c>MessageIndex(half b/16, polynomial bit
    /// (15−b%16)·8+k)</c>, with byte <c>b = j&gt;&gt;3</c> and within-byte bit <c>k = 7−(j&amp;7)</c>.
    /// </summary>
    /// <returns>The 256 MAC message wire indices, most-significant digest bit first.</returns>
    private static int[] DigestBitWires()
    {
        int[] eBits = new int[DigestBits];
        for(int j = 0; j < DigestBits; j++)
        {
            int b = j >> 3;
            int k = 7 - (j & 7);
            int h = b / 16;
            int i = ((15 - (b % 16)) * 8) + k;
            eBits[j] = GkrCrossFieldMacSupport.MessageIndex(h, i);
        }

        return eBits;
    }


    /// <summary>Checks every quadratic constraint <c>W[z] = W[x]·W[y]</c> over the packed witness bytes (borrowed, not owned), in the MAC index space.</summary>
    private static bool QuadraticsSatisfied(LigeroQuadraticConstraint[] quadratics, ReadOnlySpan<byte> witness)
    {
        Span<byte> product = stackalloc byte[ScalarSize];
        foreach(LigeroQuadraticConstraint q in quadratics)
        {
            GkrTestSupport.Multiply(witness.Slice(q.XIndex * ScalarSize, ScalarSize), witness.Slice(q.YIndex * ScalarSize, ScalarSize), product, CurveParameterSet.None);
            if(!product.SequenceEqual(witness.Slice(q.ZIndex * ScalarSize, ScalarSize)))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>Checks every parity constraint <c>Σ coefficient·W = target</c> over the packed witness bytes (borrowed, not owned).</summary>
    private static bool ParityStatementSatisfied(ReadOnlySpan<byte> verifierKey, ReadOnlySpan<byte> macs, ulong[] maskedQuotients, ReadOnlySpan<byte> witness)
    {
        (LigeroLinearConstraint[] constraints, byte[] targets) = GkrCrossFieldMacSupport.BuildParityStatement(verifierKey, macs, maskedQuotients);
        int constraintCount = targets.Length / ScalarSize;
        byte[] sums = new byte[constraintCount * ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> next = stackalloc byte[ScalarSize];
        foreach(LigeroLinearConstraint term in constraints)
        {
            Span<byte> slot = sums.AsSpan(term.ConstraintIndex * ScalarSize, ScalarSize);
            GkrTestSupport.Multiply(term.Coefficient.Span, witness.Slice(term.WitnessIndex * ScalarSize, ScalarSize), product, CurveParameterSet.None);
            GkrTestSupport.Add(slot, product, next, CurveParameterSet.None);
            next.CopyTo(slot);
        }

        for(int c = 0; c < constraintCount; c++)
        {
            if(!sums.AsSpan(c * ScalarSize, ScalarSize).SequenceEqual(targets.AsSpan(c * ScalarSize, ScalarSize)))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>Loads the real mdoc credential fixture and extracts its disclosed <c>age_over_18</c> claim.</summary>
    /// <returns>The disclosure carrying the signed structure, issuer key and signature this class's tests exercise.</returns>
    private static MdocDisclosure LoadDisclosure()
    {
        //A static initializer feeds this, so the read stays synchronous (it cannot await).
        byte[] credential = File.ReadAllBytes("../../../TestMaterial/Mdoc/mdoc-00.cbor");

        return MdocDisclosure.Extract(credential, "org.iso.18013.5.1", "age_over_18");
    }


    /// <summary>The validated Montgomery Fp256 backend delegates, byte-identical to the BigInteger reference and faster, used for the large real-credential Fp commitment.</summary>
    private static class Montgomery
    {
        /// <summary>The validated Montgomery-backend addition delegate.</summary>
        public static ScalarAddDelegate Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();

        /// <summary>The validated Montgomery-backend subtraction delegate.</summary>
        public static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();

        /// <summary>The validated Montgomery-backend multiplication delegate.</summary>
        public static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldMontgomeryBackend.GetMultiply();

        /// <summary>The validated Montgomery-backend inversion delegate.</summary>
        public static ScalarInvertDelegate Invert { get; } = P256BaseFieldMontgomeryBackend.GetInvert();

        /// <summary>The validated Montgomery-backend scalar-reduction delegate.</summary>
        public static ScalarReduceDelegate Reduce { get; } = P256BaseFieldMontgomeryBackend.GetReduce();
    }
}

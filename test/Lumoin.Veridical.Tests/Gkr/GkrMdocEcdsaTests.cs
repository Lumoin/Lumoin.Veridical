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
/// E2E.2 — the issuer's real ES256 signature verified in-circuit against the SAME committed digest
/// bits that E2E.1 MAC-binds. The 256 message bits of the cross-field MAC region
/// (<see cref="GkrCrossFieldMacSupport"/>) are real Fp256 wires 0..41471 of the ECDSA gadget's
/// builder; the LF.5 ECDSA verifier consumes those exact wires as its <c>e·G</c> ladder scalar
/// through <see cref="EcdsaVerificationGadgetExtensions.AssertVerifiesDigestBits"/>. So ONE Fp256
/// commitment proves both "these bits satisfy the cross-field MAC of the GF-side SHA-256" and "the
/// issuer's ES256 signature verifies for e = these bits". The binding is by wire identity, not by
/// glue constraints. The GF side is E2E.1 verbatim, shared through <see cref="GkrMdocSupport"/>.
/// </summary>
[TestClass]
internal sealed class GkrMdocEcdsaTests
{
    private const int ScalarSize = GkrGf2kShaSupport.ScalarSize;
    private const int HalfBits = GkrGf2kMacSupport.HalfBits;
    private const int Halves = GkrGf2kMacSupport.CopyCount;
    private const int DigestBytes = GkrShaRoundSupport.DigestBytes;
    private const int DigestBits = DigestBytes * GkrShaRoundSupport.BitsPerByte;
    private const int FpWitnessCount = GkrCrossFieldMacSupport.FpWitnessCount;

    private const int InverseRate = 4;
    private const int OpenedColumns = 4;
    private const int Block = 64;

    private static byte[] MaskSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.mdoc.ecdsa.mask.v1");

    private static byte[][] KeyShares { get; } =
    [
        GkrCrossFieldMacSupport.Element(0x243f6a8885a308d3UL, 0x13198a2e03707344UL),
        GkrCrossFieldMacSupport.Element(0xa4093822299f31d0UL, 0x082efa98ec4e6c89UL),
    ];

    private static MdocDisclosure Disclosure { get; } = LoadDisclosure();

    private static byte[] SignedStructure { get; } = Disclosure.SignedStructure;

    private static GkrMdocSupport Support { get; } = new(SignedStructure, KeyShares);

    private static BigInteger A { get; } = P256BigIntegerG1Reference.CurveA;

    private static BigInteger B { get; } = P256BigIntegerG1Reference.CurveB;

    private static byte[] CurveABytes { get; } = EcdsaNonceRecovery.Bytes(A);

    private static byte[] CurveBBytes { get; } = EcdsaNonceRecovery.Bytes(B);


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
        byte[] witnessBytes = builder.WitnessBytes();
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


    //Builds the combined Fp builder over the REAL credential's signature: the public key and
    //signature components come straight from the disclosure.
    private static LigeroConstraintSystemBuilder BuildEcdsaBuilder(ReadOnlySpan<byte> fpWitness, ReadOnlySpan<byte> digest) =>
        BuildEcdsaBuilder(
            fpWitness, digest,
            EcdsaNonceRecovery.ToInteger(Disclosure.IssuerKeyX), EcdsaNonceRecovery.ToInteger(Disclosure.IssuerKeyY),
            EcdsaNonceRecovery.ToInteger(Disclosure.SignatureR), EcdsaNonceRecovery.ToInteger(Disclosure.SignatureS));


    //Builds the combined Fp builder: the MAC region as the first FpWitnessCount wires (in
    //PackFpWitness order so the MAC indices resolve to those wires), then the ECDSA gadget over
    //the same builder with the digest bits — at their MAC message wires — as the e·G scalar. The
    //nonce point R is recovered from the REAL public (Q, e, r, s) so the negative gates can feed a
    //tampered Q/r/s while R stays the one the real signature determines; e is the full digest
    //integer. With a tampered component the recovered R no longer satisfies the gadget identity.
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


    //The 256 MAC message wires that hold the digest, most-significant digest bit first: digest bit
    //j (j=0 the MSB of byte 0) lives at MessageIndex(half b/16, polynomial bit (15−b%16)·8+k),
    //with byte b = j>>3 and within-byte bit k = 7−(j&7).
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


    //Every quadratic W[z] = W[x]·W[y] over the packed witness bytes, in the MAC index space.
    private static bool QuadraticsSatisfied(LigeroQuadraticConstraint[] quadratics, byte[] witness)
    {
        Span<byte> product = stackalloc byte[ScalarSize];
        foreach(LigeroQuadraticConstraint q in quadratics)
        {
            GkrTestSupport.Multiply(witness.AsSpan(q.XIndex * ScalarSize, ScalarSize), witness.AsSpan(q.YIndex * ScalarSize, ScalarSize), product, CurveParameterSet.None);
            if(!product.SequenceEqual(witness.AsSpan(q.ZIndex * ScalarSize, ScalarSize)))
            {
                return false;
            }
        }

        return true;
    }


    //Every parity constraint Σ coefficient·W = target over the packed witness bytes.
    private static bool ParityStatementSatisfied(ReadOnlySpan<byte> verifierKey, ReadOnlySpan<byte> macs, ulong[] maskedQuotients, byte[] witness)
    {
        (LigeroLinearConstraint[] constraints, byte[] targets) = GkrCrossFieldMacSupport.BuildParityStatement(verifierKey, macs, maskedQuotients);
        int constraintCount = targets.Length / ScalarSize;
        byte[] sums = new byte[constraintCount * ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> next = stackalloc byte[ScalarSize];
        foreach(LigeroLinearConstraint term in constraints)
        {
            Span<byte> slot = sums.AsSpan(term.ConstraintIndex * ScalarSize, ScalarSize);
            GkrTestSupport.Multiply(term.Coefficient.Span, witness.AsSpan(term.WitnessIndex * ScalarSize, ScalarSize), product, CurveParameterSet.None);
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


    private static MdocDisclosure LoadDisclosure()
    {
        //A static initializer feeds this, so the read stays synchronous (it cannot await).
        byte[] credential = File.ReadAllBytes("../../../TestMaterial/Mdoc/mdoc-00.cbor");

        return MdocDisclosure.Extract(credential, "org.iso.18013.5.1", "age_over_18");
    }


    //The production Montgomery Fp256 backend delegates (the validated faster encoder path),
    //byte-identical to the reference — used for the large real-credential Fp commitment.
    private static class Montgomery
    {
        public static ScalarAddDelegate Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();

        public static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();

        public static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldMontgomeryBackend.GetMultiply();

        public static ScalarInvertDelegate Invert { get; } = P256BaseFieldMontgomeryBackend.GetInvert();

        public static ScalarReduceDelegate Reduce { get; } = P256BaseFieldMontgomeryBackend.GetReduce();
    }
}

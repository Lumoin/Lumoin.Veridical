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
/// E2E.3 — the full mdoc disclosure chain, entirely on the GF(2^128) side: the disclosed
/// <c>IssuerSignedItem</c> is hashed in-circuit as a SECOND SHA-256 preimage on the SAME
/// commitment that carries the Sig_structure hash, the item's digest is glued to the signed
/// Sig_structure bytes at the public <c>ItemDigestOffset</c> (this is how "the signed MSO holds
/// SHA-256(item)" is proven), and the item's bytes at the public <c>AttributeOffset</c> are pinned
/// to the public disclosure pattern (the <c>age_over_18</c> claim). Combined with E2E.2's MAC and
/// ECDSA binding this closes the Longfellow statement: a holder proves the issuer signed a
/// Sig_structure whose MSO commits to an item that discloses the named attribute, the item's
/// non-disclosed bytes staying private behind the schedule virtual predecessors.
/// <para>
/// TRADEOFF: the item-digest offset, the attribute offset and the disclosure pattern are PUBLIC by
/// design. Cost calibration rejected a private-offset one-hot selection (~300k extra quadratics)
/// and the disclosed attribute is public anyway; but the offsets reveal credential-structural
/// positions (a correlatable value across presentations of the same credential layout). A
/// private-offset refinement is future work.
/// </para>
/// </summary>
[TestClass]
internal sealed class GkrMdocDisclosureTests
{
    private const int ScalarSize = GkrGf2kShaSupport.ScalarSize;
    private const int HalfBits = GkrGf2kMacSupport.HalfBits;
    private const int Halves = GkrGf2kMacSupport.CopyCount;
    private const int FpWitnessCount = GkrCrossFieldMacSupport.FpWitnessCount;
    private const int DigestBytes = GkrShaRoundSupport.DigestBytes;
    private const int DigestBits = DigestBytes * GkrShaRoundSupport.BitsPerByte;

    private const int InverseRate = 4;
    private const int OpenedColumns = 4;
    private const int Block = 64;

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.mdoc.disclosure.test");

    private static FiatShamirOperationLabel FpSeedLabel { get; } = new("veridical.gkr.mdoc.disclosure.fp.seed");

    private static byte[] FpRandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.mdoc.disclosure.fp.rng.v1");

    private static byte[] GfRandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.mdoc.disclosure.gf.rng.v1");

    private static byte[] MaskSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.mdoc.disclosure.mask.v1");

    private static byte[][] KeyShares { get; } =
    [
        GkrCrossFieldMacSupport.Element(0x243f6a8885a308d3UL, 0x13198a2e03707344UL),
        GkrCrossFieldMacSupport.Element(0xa4093822299f31d0UL, 0x082efa98ec4e6c89UL),
    ];

    private static MdocDisclosure Disclosure { get; } = LoadDisclosure();

    private static byte[] SignedStructure { get; } = Disclosure.SignedStructure;

    private static GkrMdocSupport Support { get; } =
        new(Disclosure.SignedStructure, Disclosure.IssuerSignedItem, Disclosure.Attribute, Disclosure.AttributeOffset, KeyShares);

    private static BigInteger A { get; } = P256BigIntegerG1Reference.CurveA;

    private static BigInteger B { get; } = P256BigIntegerG1Reference.CurveB;

    private static byte[] CurveABytes { get; } = EcdsaNonceRecovery.Bytes(A);

    private static byte[] CurveBBytes { get; } = EcdsaNonceRecovery.Bytes(B);


    [TestMethod]
    public void TheRealCredentialSatisfiesTheClaimedDisclosureStructure()
    {
        //Out of circuit, on the genuine bytes: the MSO holds SHA-256 of the item at the located
        //offset, and the disclosure pattern is the item's bytes at the attribute offset.
        byte[] itemDigest = SHA256.HashData(Disclosure.IssuerSignedItem);
        Assert.IsTrue(
            SignedStructure.AsSpan(Disclosure.ItemDigestOffset, DigestBytes).SequenceEqual(itemDigest),
            "The signed Sig_structure must hold SHA-256(IssuerSignedItem) at ItemDigestOffset.");
        Assert.IsTrue(
            Disclosure.IssuerSignedItem.AsSpan(Disclosure.AttributeOffset, Disclosure.Attribute.Length).SequenceEqual(Disclosure.Attribute),
            "The item must carry the disclosure pattern at AttributeOffset.");
    }


    [TestMethod]
    public void TheWireMappingReadsTheItemDigestAndAttributeBackFromTheWitness()
    {
        //The packed witness, read back through the byte→wire mapping, must reproduce both the
        //item's real SHA-256 digest (the addition-sum wires of the item's last block) and the
        //disclosure pattern (the item's schedule words) — the falsifiable gate on the mapping.
        Span<byte> digest = stackalloc byte[DigestBytes];
        Support.ComputeDigest(digest);

        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(Support.WitnessBytes);
        Span<byte> witness = witnessOwner.Memory.Span[..Support.WitnessBytes];
        Support.PackGfWitness(witness, digest);

        Span<byte> itemDigest = stackalloc byte[DigestBytes];
        for(int d = 0; d < DigestBytes; d++)
        {
            itemDigest[d] = ReadByte(witness, k => Support.ItemDigestWire(d, k));
        }

        Assert.IsTrue(itemDigest.SequenceEqual(SHA256.HashData(Disclosure.IssuerSignedItem)), "The digest-wire mapping must read SHA-256(item) from the witness.");

        Span<byte> attribute = stackalloc byte[Disclosure.Attribute.Length];
        for(int idx = 0; idx < attribute.Length; idx++)
        {
            int offset = Support.AttributeOffset + idx;
            attribute[idx] = ReadByte(witness, k => Support.ItemAttributeWire(offset, k));
        }

        Assert.IsTrue(attribute.SequenceEqual(Disclosure.Attribute), "The attribute-wire mapping must read the disclosure pattern from the witness.");
    }


    [TestMethod]
    public void EveryInstanceClosesOnTheRealPackedWitness()
    {
        //Every SHA instance (the message's components and the item's) evaluates to all-zero
        //outputs, and the MAC instance to the macs of the real digest, on the flat witness.
        Span<byte> digest = stackalloc byte[DigestBytes];
        Support.ComputeDigest(digest);

        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(Support.WitnessBytes);
        Span<byte> witness = witnessOwner.Memory.Span[..Support.WitnessBytes];
        Support.PackGfWitness(witness, digest);

        byte[] probeKey = GkrCrossFieldMacSupport.Element(0x452821e638d01377UL, 0xbe5466cf34e90c6cUL);
        Span<byte> macs = stackalloc byte[Halves * ScalarSize];
        GkrGf2kMacSupport.ComputeMacs(digest, KeyShares, probeKey, macs);

        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(Support.OutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..Support.OutputBytes];
        Support.EvaluateInstances(witness, probeKey, outputs);

        using IMemoryOwner<byte> expectedOwner = BaseMemoryPool.Shared.Rent(Support.OutputBytes);
        Span<byte> expected = expectedOwner.Memory.Span[..Support.OutputBytes];
        Support.ExpectedOutputs(macs, expected);

        Assert.IsTrue(outputs.SequenceEqual(expected), "Every instance (message and item) must close on the honest witness.");
    }


    [TestMethod]
    public void TheFullStatementIsSatisfiedAndTheDisclosureDualsBreakIt()
    {
        Span<byte> digest = stackalloc byte[DigestBytes];
        Support.ComputeDigest(digest);

        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(Support.WitnessBytes);
        Span<byte> witness = witnessOwner.Memory.Span[..Support.WitnessBytes];
        Support.PackGfWitness(witness, digest);

        //The full statement (round chain, both preimages' glue, the digest-to-MAC glue, the item
        //digest glue and the attribute pins) holds over the honest witness.
        (LigeroLinearConstraint[] statement, byte[] targets) = Support.BuildStatement();
        Assert.IsTrue(StatementSatisfied(statement, targets, witness), "The full disclosure statement must hold over the honest packed witness.");

        //(a) A tampered attribute: flip one public pattern byte and rebuild the statement; the
        //pins now demand the wrong value, so the same witness fails.
        byte[] tamperedAttribute = (byte[])Disclosure.Attribute.Clone();
        tamperedAttribute[0] ^= 0x01;
        (LigeroLinearConstraint[] tamperedAttrStatement, byte[] tamperedAttrTargets) = Support.BuildStatement(tamperedAttribute, null);
        Assert.IsFalse(StatementSatisfied(tamperedAttrStatement, tamperedAttrTargets, witness), "A flipped attribute pattern byte must break the statement over the honest witness.");

        //(b) A shifted ItemDigestOffset (+1): the digest glue grabs the wrong Sig_structure window,
        //so the item's digest no longer equals the bytes the glue reads.
        (LigeroLinearConstraint[] shiftedStatement, byte[] shiftedTargets) = Support.BuildStatement(null, Support.ItemDigestOffset + 1);
        Assert.IsFalse(StatementSatisfied(shiftedStatement, shiftedTargets, witness), "A shifted item-digest offset must break the digest glue.");
    }


    [TestMethod]
    public void ATamperedItemByteBreaksTheDisclosureStatement()
    {
        //A one-byte-different item, packed into the item region against the real layout: the item
        //still hashes consistently to ITS OWN digest, so the item's in-circuit instances close,
        //but that digest no longer equals the MSO bytes at ItemDigestOffset — the digest glue
        //fails — and the flipped disclosed byte no longer matches the attribute pins. The cheapest
        //demonstration that the item's bytes really drive both the in-circuit hash and the
        //disclosure. The tampered byte is the first attribute byte (a real item byte, not padding).
        Span<byte> digest = stackalloc byte[DigestBytes];
        Support.ComputeDigest(digest);

        byte[] tamperedItem = (byte[])Disclosure.IssuerSignedItem.Clone();
        tamperedItem[Disclosure.AttributeOffset] ^= 0x01;

        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(Support.WitnessBytes);
        Span<byte> witness = witnessOwner.Memory.Span[..Support.WitnessBytes];
        //The Sig_structure region and the MAC digest stay real; the item region holds the tampered item.
        Support.PackGfWitness(witness, digest, tamperedItem);

        byte[] probeKey = GkrCrossFieldMacSupport.Element(0x452821e638d01377UL, 0xbe5466cf34e90c6cUL);
        Span<byte> macs = stackalloc byte[Halves * ScalarSize];
        GkrGf2kMacSupport.ComputeMacs(digest, KeyShares, probeKey, macs);

        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(Support.OutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..Support.OutputBytes];
        Support.EvaluateInstances(witness, probeKey, outputs);

        using IMemoryOwner<byte> expectedOwner = BaseMemoryPool.Shared.Rent(Support.OutputBytes);
        Span<byte> expected = expectedOwner.Memory.Span[..Support.OutputBytes];
        Support.ExpectedOutputs(macs, expected);

        //The instances close — a tampered item still hashes consistently — so the disclosure binds
        //through the statement: the digest glue and the attribute pins fail on this witness.
        (LigeroLinearConstraint[] statement, byte[] targets) = Support.BuildStatement();
        Assert.IsTrue(outputs.SequenceEqual(expected), "The tampered item still hashes consistently; the disclosure binds through the statement, not the instances.");
        Assert.IsFalse(StatementSatisfied(statement, targets, witness), "A tampered disclosed item byte must break the disclosure statement over its witness.");
    }


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void TheFullMdocStatementProvesAndVerifiesOnOneCommitment()
    {
        //THE FULL MDOC CAPSTONE: one Fp256 commitment carries the MAC region and the ECDSA gadget
        //(E2E.2, unchanged), one GF commitment carries the Sig_structure hash, the item hash and
        //the disclosure statement. The shared transcript binds both. Verify true, then a flipped
        //mac is rejected on both sides, then a verifier-side tampered attribute is rejected by
        //rebuilding the verifier's statement with one flipped pattern byte.
        //On the order of an hour or two, hardware-dependent. The default-suite gates above
        //verify the same statement and instances cheaply by direct evaluation, so this gate
        //adds the end-to-end proving, not the logic coverage.
        Span<byte> digest = stackalloc byte[DigestBytes];
        Support.ComputeDigest(digest);

        using IMemoryOwner<byte> gfWitnessOwner = BaseMemoryPool.Shared.Rent(Support.WitnessBytes);
        Span<byte> gfWitness = gfWitnessOwner.Memory.Span[..Support.WitnessBytes];
        Support.PackGfWitness(gfWitness, digest);

        using IMemoryOwner<byte> fpWitnessOwner = BaseMemoryPool.Shared.Rent(GkrCrossFieldMacSupport.FpWitnessBytes);
        Span<byte> fpWitness = fpWitnessOwner.Memory.Span[..GkrCrossFieldMacSupport.FpWitnessBytes];
        GkrCrossFieldMacSupport.PackFpWitness(fpWitness, digest, KeyShares, MaskSeed);

        using LigeroConstraintSystemBuilder builder = BuildEcdsaBuilder(fpWitness, digest);

        Span<byte> verifierKey = stackalloc byte[ScalarSize];
        Span<byte> macs = stackalloc byte[Halves * ScalarSize];
        ulong[] maskedQuotients = new ulong[Halves * HalfBits];
        (LigeroProof fpProof, GkrCommittedProof gfProof) = ProveCrossField(builder, fpWitness, gfWitness, digest, verifierKey, macs, maskedQuotients);
        using LigeroProof fp = fpProof;
        using GkrCommittedProof gf = gfProof;

        (LigeroLinearConstraint[] statement, byte[] targets) = Support.BuildStatement();
        Assert.IsTrue(VerifyCrossField(builder, fp, gf, macs, maskedQuotients, statement, targets), "The full mdoc disclosure statement must prove and verify on one commitment pair.");

        Span<byte> wrongMacs = stackalloc byte[Halves * ScalarSize];
        macs.CopyTo(wrongMacs);
        wrongMacs[ScalarSize - 1] ^= 0x01;
        Assert.IsFalse(VerifyCrossField(builder, fp, gf, wrongMacs, maskedQuotients, statement, targets), "A mac differing in one byte must be rejected.");

        //The verifier rebuilds its statement with one flipped public pattern byte; the GF proof's
        //openings no longer satisfy the moved attribute pins, so verification fails. No re-prove.
        byte[] tamperedAttribute = (byte[])Disclosure.Attribute.Clone();
        tamperedAttribute[0] ^= 0x01;
        (LigeroLinearConstraint[] tamperedStatement, byte[] tamperedTargets) = Support.BuildStatement(tamperedAttribute, null);
        Assert.IsFalse(VerifyCrossField(builder, fp, gf, macs, maskedQuotients, tamperedStatement, tamperedTargets), "A verifier-side tampered attribute must be rejected.");
    }


    //The full prover protocol, E2E.2's transcript order with the disclosure GF support: commit the
    //combined Fp system (MAC region + ECDSA gadget), commit GF (both roots absorbed), squeeze the
    //verifier key, compute the macs, prove all GF instances under the disclosure statement, then
    //prove the Fp linear statement over the Montgomery backend.
    private static (LigeroProof FpProof, GkrCommittedProof GfProof) ProveCrossField(
        LigeroConstraintSystemBuilder builder,
        ReadOnlySpan<byte> fpWitness,
        ReadOnlySpan<byte> gfWitness,
        ReadOnlySpan<byte> digest,
        Span<byte> verifierKey,
        Span<byte> macs,
        ulong[] maskedQuotients)
    {
        LigeroQuadraticConstraint[] fpQuadratics = CombinedQuadratics(builder);
        var fpParameters = new LigeroParameters(builder.WireCount, fpQuadratics.Length, InverseRate, OpenedColumns, Block);
        LigeroQuadraticConstraint[] gfBitness = Support.BuildBitnessConstraints();
        var gfParameters = new LigeroParameters(Support.WitnessScalars, gfBitness.Length, InverseRate, OpenedColumns, Block, LigeroNodeDomain.BinaryField);
        (LigeroLinearConstraint[] statement, byte[] targets) = Support.BuildStatement();

        using FiatShamirTranscript transcript = NewTranscript();

        using LigeroCommitment fpCommitment = LigeroProver.Commit(
            fpParameters, builder.WitnessBytes(), fpQuadratics, new GkrCrossFieldMacSupport.FpDeterministicRandom(FpRandomnessSeed).AsDelegate(),
            Montgomery.Add, Montgomery.Subtract, Montgomery.Multiply, Montgomery.Invert,
            GkrTestSupport.Hash, WellKnownHashAlgorithms.Blake3, GkrTestSupport.Merkle, CurveParameterSet.None,
            BaseMemoryPool.Shared);
        transcript.AbsorbLigeroTableauRoot(fpCommitment.Root, GkrTestSupport.Hash);

        using LigeroCommitment gfCommitment = GkrCommittedProver.Commit(
            gfWitness, gfParameters, gfBitness,
            () => new GkrCrossFieldMacSupport.GfDeterministicRandom(GfRandomnessSeed).AsDelegate(),
            GkrGf2kTestSupport.Add, GkrGf2kTestSupport.Subtract, GkrGf2kTestSupport.Multiply, GkrGf2kTestSupport.Invert, CurveParameterSet.None,
            transcript, GkrGf2kTestSupport.Hash, GkrGf2kTestSupport.Hash, GkrTestSupport.Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared);

        GkrGf2kMacSupport.SqueezeVerifierKey(transcript, verifierKey);
        GkrGf2kMacSupport.ComputeMacs(digest, KeyShares, verifierKey, macs);

        GkrCommittedProof gfProof = GkrCommittedProver.Prove(
            gfCommitment, Support.Instances(verifierKey), statement, targets,
            GkrGf2kTestSupport.Add, GkrGf2kTestSupport.Subtract, GkrGf2kTestSupport.Multiply, GkrGf2kTestSupport.Invert, GkrGf2kTestSupport.Reduce, CurveParameterSet.None,
            transcript, GkrGf2kTestSupport.Squeeze, GkrGf2kTestSupport.Hash,
            BaseMemoryPool.Shared);

        GkrCrossFieldMacSupport.ComputeMaskedQuotients(fpWitness, verifierKey, macs, maskedQuotients);
        (int linearCount, LigeroLinearConstraint[] combined, byte[] combinedTargets) =
            CombinedLinear(builder, verifierKey, macs, maskedQuotients);

        Span<byte> fpSeed = stackalloc byte[ScalarSize];
        transcript.SqueezeBytes(FpSeedLabel, fpSeed, GkrTestSupport.Squeeze, GkrTestSupport.Hash);

        LigeroProof fpProof;
        try
        {
            fpProof = LigeroProver.Prove(
                fpCommitment, linearCount, combined, combinedTargets, fpSeed,
                Montgomery.Add, Montgomery.Subtract, Montgomery.Multiply, Montgomery.Invert, Montgomery.Reduce,
                GkrTestSupport.Hash, GkrTestSupport.Squeeze, CurveParameterSet.None,
                BaseMemoryPool.Shared);
        }
        catch
        {
            gfProof.Dispose();
            throw;
        }

        return (fpProof, gfProof);
    }


    //The full verifier protocol, mirroring the prover's transcript order exactly. The GF statement
    //and targets are passed so the tampered-attribute dual can move the verifier's pins without a
    //re-prove. As in E2E.2 the verifier reuses the prover's builder for the gadget structure.
    private static bool VerifyCrossField(
        LigeroConstraintSystemBuilder builder, LigeroProof fpProof, GkrCommittedProof gfProof, ReadOnlySpan<byte> macs, ulong[] maskedQuotients,
        LigeroLinearConstraint[] statement, byte[] targets)
    {
        LigeroQuadraticConstraint[] fpQuadratics = CombinedQuadratics(builder);
        var fpParameters = new LigeroParameters(builder.WireCount, fpQuadratics.Length, InverseRate, OpenedColumns, Block);
        LigeroQuadraticConstraint[] gfBitness = Support.BuildBitnessConstraints();
        var gfParameters = new LigeroParameters(Support.WitnessScalars, gfBitness.Length, InverseRate, OpenedColumns, Block, LigeroNodeDomain.BinaryField);

        using FiatShamirTranscript transcript = NewTranscript();
        transcript.AbsorbLigeroTableauRoot(fpProof.Root, GkrTestSupport.Hash);
        GkrCommittedVerifier.AbsorbCommitmentRoot(gfProof, transcript, GkrGf2kTestSupport.Hash);

        Span<byte> verifierKey = stackalloc byte[ScalarSize];
        GkrGf2kMacSupport.SqueezeVerifierKey(transcript, verifierKey);

        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(Support.OutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..Support.OutputBytes];
        Support.ExpectedOutputs(macs, outputs);

        if(!GkrCommittedVerifier.VerifyFromAbsorbedRoot(
            Support.Instances(verifierKey), outputs, gfProof, gfParameters, statement, targets, gfBitness,
            GkrGf2kTestSupport.Add, GkrGf2kTestSupport.Subtract, GkrGf2kTestSupport.Multiply, GkrGf2kTestSupport.Invert, GkrGf2kTestSupport.Reduce, CurveParameterSet.None,
            transcript, GkrGf2kTestSupport.Squeeze, GkrGf2kTestSupport.Hash, GkrGf2kTestSupport.Hash, GkrTestSupport.Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared))
        {
            return false;
        }

        (int linearCount, LigeroLinearConstraint[] combined, byte[] combinedTargets) =
            CombinedLinear(builder, verifierKey, macs, maskedQuotients);

        Span<byte> fpSeed = stackalloc byte[ScalarSize];
        transcript.SqueezeBytes(FpSeedLabel, fpSeed, GkrTestSupport.Squeeze, GkrTestSupport.Hash);

        return LigeroVerifier.Verify(
            fpParameters, fpProof, linearCount, combined, combinedTargets, fpQuadratics, fpSeed,
            Montgomery.Add, Montgomery.Subtract, Montgomery.Multiply, Montgomery.Invert, Montgomery.Reduce,
            GkrTestSupport.Hash, GkrTestSupport.Squeeze, GkrTestSupport.Hash, GkrTestSupport.Merkle, WellKnownHashAlgorithms.Blake3, CurveParameterSet.None,
            BaseMemoryPool.Shared);
    }


    //The combined Fp system's quadratics: the ECDSA gadget's own quadratics followed by the MAC
    //product and bitness triples (E2E.2's structure verbatim).
    private static LigeroQuadraticConstraint[] CombinedQuadratics(LigeroConstraintSystemBuilder builder)
    {
        LigeroQuadraticConstraint[] gadget = builder.QuadraticConstraints();
        LigeroQuadraticConstraint[] mac = GkrCrossFieldMacSupport.BuildFpQuadratics();
        var combined = new LigeroQuadraticConstraint[gadget.Length + mac.Length];
        gadget.CopyTo(combined, 0);
        mac.CopyTo(combined, gadget.Length);

        return combined;
    }


    //The combined Fp linear statement: the builder's gadget constraints, then the MAC parity
    //statement re-indexed past them (E2E.2's structure verbatim).
    private static (int LinearCount, LigeroLinearConstraint[] Constraints, byte[] Targets) CombinedLinear(
        LigeroConstraintSystemBuilder builder, ReadOnlySpan<byte> verifierKey, ReadOnlySpan<byte> macs, ulong[] maskedQuotients)
    {
        int gadgetCount = builder.LinearConstraintCount;
        LigeroLinearConstraint[] gadget = builder.LinearConstraints();
        byte[] gadgetTargets = builder.TargetBytes();
        (LigeroLinearConstraint[] parity, byte[] parityTargets) = GkrCrossFieldMacSupport.BuildParityStatement(verifierKey, macs, maskedQuotients);

        int linearCount = gadgetCount + (Halves * HalfBits);
        var combined = new LigeroLinearConstraint[gadget.Length + parity.Length];
        gadget.CopyTo(combined, 0);
        for(int i = 0; i < parity.Length; i++)
        {
            LigeroLinearConstraint term = parity[i];
            combined[gadget.Length + i] = new LigeroLinearConstraint(gadgetCount + term.ConstraintIndex, term.WitnessIndex, term.Coefficient);
        }

        byte[] combinedTargets = new byte[gadgetTargets.Length + parityTargets.Length];
        gadgetTargets.CopyTo(combinedTargets, 0);
        parityTargets.CopyTo(combinedTargets, gadgetTargets.Length);

        return (linearCount, combined, combinedTargets);
    }


    //Builds the combined Fp builder over the real credential's signature, the MAC region first
    //then the ECDSA gadget consuming the committed digest bits as its e·G scalar — E2E.2's
    //construction verbatim (the disclosure changes nothing on the Fp side).
    private static LigeroConstraintSystemBuilder BuildEcdsaBuilder(ReadOnlySpan<byte> fpWitness, ReadOnlySpan<byte> digest)
    {
        var builder = new LigeroConstraintSystemBuilder(
            Montgomery.Add, Montgomery.Subtract, Montgomery.Multiply, Montgomery.Invert, Montgomery.Reduce,
            CurveParameterSet.None, InverseRate, OpenedColumns, Block, BaseMemoryPool.Shared);

        int last = -1;
        for(int i = 0; i < FpWitnessCount; i++)
        {
            last = builder.AddWire(fpWitness.Slice(i * ScalarSize, ScalarSize));
        }

        Assert.AreEqual(FpWitnessCount - 1, last, "The MAC region must occupy wires 0..FpWitnessCount-1 densely.");

        int[] eBits = DigestBitWires();

        var curve = new EcdsaCurve(
            WeierstrassCurve.Create(builder, CurveABytes, CurveBBytes),
            EcdsaNonceRecovery.Bytes(EcdsaNonceRecovery.Gx), EcdsaNonceRecovery.Bytes(EcdsaNonceRecovery.Gy), EcdsaNonceRecovery.Bytes(EcdsaNonceRecovery.N));

        BigInteger qx = EcdsaNonceRecovery.ToInteger(Disclosure.IssuerKeyX);
        BigInteger qy = EcdsaNonceRecovery.ToInteger(Disclosure.IssuerKeyY);
        BigInteger r = EcdsaNonceRecovery.ToInteger(Disclosure.SignatureR);
        BigInteger s = EcdsaNonceRecovery.ToInteger(Disclosure.SignatureS);
        BigInteger e = EcdsaNonceRecovery.ToInteger(digest);
        (BigInteger rx, BigInteger ry) = EcdsaNonceRecovery.RecoverNoncePoint(qx, qy, e, r, s);

        builder.AssertVerifiesDigestBits(
            curve,
            new EcdsaHashedPublicInputs(EcdsaNonceRecovery.Bytes(qx), EcdsaNonceRecovery.Bytes(qy), EcdsaNonceRecovery.Bytes(r), EcdsaNonceRecovery.Bytes(s)),
            new EcdsaWitness(EcdsaNonceRecovery.Bytes(rx), EcdsaNonceRecovery.Bytes(ry)),
            eBits);

        return builder;
    }


    //The 256 MAC message wires that hold the digest, most-significant digest bit first — E2E.2's
    //mapping verbatim.
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


    //The byte assembled from value-bit k (k = 0 the least-significant) of the witness at the given
    //wire — the bit lives in the last byte of the scalar.
    private static byte ReadByte(ReadOnlySpan<byte> witness, Func<int, int> wireOfBit)
    {
        int value = 0;
        for(int k = 0; k < 8; k++)
        {
            value |= (witness[(wireOfBit(k) * ScalarSize) + ScalarSize - 1] & 1) << k;
        }

        return (byte)value;
    }


    //Σ coefficient·W per constraint over GF(2^128) (addition is XOR, multiply the field multiply),
    //each compared to its target.
    private static bool StatementSatisfied(LigeroLinearConstraint[] constraints, byte[] targets, ReadOnlySpan<byte> witness)
    {
        int constraintCount = targets.Length / ScalarSize;
        byte[] sums = new byte[constraintCount * ScalarSize];
        Span<byte> product = stackalloc byte[ScalarSize];
        Span<byte> next = stackalloc byte[ScalarSize];
        foreach(LigeroLinearConstraint term in constraints)
        {
            Span<byte> slot = sums.AsSpan(term.ConstraintIndex * ScalarSize, ScalarSize);
            GkrGf2kTestSupport.Multiply(term.Coefficient.Span, witness.Slice(term.WitnessIndex * ScalarSize, ScalarSize), product, CurveParameterSet.None);
            GkrGf2kTestSupport.Add(slot, product, next, CurveParameterSet.None);
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


    private static FiatShamirTranscript NewTranscript() =>
        GkrGf2kTestSupport.NewTranscript(Domain, "veridical.gkr.mdoc.disclosure.seed"u8, []);


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

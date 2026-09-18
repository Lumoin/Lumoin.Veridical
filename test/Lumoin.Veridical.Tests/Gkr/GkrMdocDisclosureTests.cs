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
/// The full mdoc disclosure chain, entirely on the GF(2^128) side: the disclosed
/// <c>IssuerSignedItem</c> is hashed in-circuit as a SECOND SHA-256 preimage on the SAME
/// commitment that carries the Sig_structure hash, the item's digest is glued to the signed
/// Sig_structure bytes at the public <c>ItemDigestOffset</c> (this is how "the signed MSO holds
/// SHA-256(item)" is proven), and the item's bytes at the public <c>AttributeOffset</c> are pinned
/// to the public disclosure pattern (the <c>age_over_18</c> claim). Combined with the MAC and
/// ECDSA binding proven in <see cref="GkrMdocEcdsaTests"/> this closes the Longfellow statement: a
/// holder proves the issuer signed a Sig_structure whose MSO commits to an item that discloses the
/// named attribute, the item's non-disclosed bytes staying private behind the schedule virtual
/// predecessors.
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
    /// <summary>The byte width of one GF(2^128) scalar.</summary>
    private const int ScalarSize = GkrGf2kShaSupport.ScalarSize;

    /// <summary>The bit width of one half of a split MAC value.</summary>
    private const int HalfBits = GkrGf2kMacSupport.HalfBits;

    /// <summary>The number of halves a MAC value is split into.</summary>
    private const int Halves = GkrGf2kMacSupport.CopyCount;

    /// <summary>The number of Fp witness scalars the MAC region and ECDSA gadget together occupy.</summary>
    private const int FpWitnessCount = GkrCrossFieldMacSupport.FpWitnessCount;

    /// <summary>The byte width of a SHA-256 digest.</summary>
    private const int DigestBytes = GkrShaRoundSupport.DigestBytes;

    /// <summary>The bit width of a SHA-256 digest.</summary>
    private const int DigestBits = DigestBytes * GkrShaRoundSupport.BitsPerByte;

    /// <summary>The Reed-Solomon code rate's inverse used by the test Ligero parameters.</summary>
    private const int InverseRate = 4;

    /// <summary>The number of columns the Ligero verifier opens per proof.</summary>
    private const int OpenedColumns = 4;

    /// <summary>The Ligero block size shared by the Fp and GF parameter sets.</summary>
    private const int Block = 64;

    /// <summary>The Fiat-Shamir domain label that scopes every transcript this file builds.</summary>
    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.mdoc.disclosure.test");

    /// <summary>The Fiat-Shamir label under which the Fp proving seed is squeezed from the shared transcript.</summary>
    private static FiatShamirOperationLabel FpSeedLabel { get; } = new("veridical.gkr.mdoc.disclosure.fp.seed");

    /// <summary>The fixed seed for the Fp commitment's deterministic randomness source.</summary>
    private static byte[] FpRandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.mdoc.disclosure.fp.rng.v1");

    /// <summary>The fixed seed for the GF commitment's deterministic randomness source.</summary>
    private static byte[] GfRandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.mdoc.disclosure.gf.rng.v1");

    /// <summary>The fixed seed for the ECDSA gadget's masking randomness.</summary>
    private static byte[] MaskSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.mdoc.disclosure.mask.v1");

    /// <summary>The two fixed MAC key shares the tests combine into the verifier's probe key.</summary>
    private static byte[][] KeyShares { get; } =
    [
        GkrCrossFieldMacSupport.Element(0x243f6a8885a308d3UL, 0x13198a2e03707344UL),
        GkrCrossFieldMacSupport.Element(0xa4093822299f31d0UL, 0x082efa98ec4e6c89UL),
    ];

    /// <summary>The real mdoc disclosure fixture (signed structure, issuer-signed item, disclosed attribute and its offset) loaded once for every test.</summary>
    private static MdocDisclosure Disclosure { get; } = LoadDisclosure();

    /// <summary>The disclosed credential's signed Sig_structure bytes, the base for the item-digest and MAC glue.</summary>
    private static byte[] SignedStructure { get; } = Disclosure.SignedStructure;

    /// <summary>The GF(2^128) circuit support built over the real disclosure fixture and key shares, shared by every test.</summary>
    private static GkrMdocSupport Support { get; } =
        new(Disclosure.SignedStructure, Disclosure.IssuerSignedItem, Disclosure.Attribute, Disclosure.AttributeOffset, KeyShares);

    /// <summary>The P-256 curve coefficient <c>a</c>, read from the reference curve constants.</summary>
    private static BigInteger A { get; } = P256BigIntegerG1Reference.CurveA;

    /// <summary>The P-256 curve coefficient <c>b</c>, read from the reference curve constants.</summary>
    private static BigInteger B { get; } = P256BigIntegerG1Reference.CurveB;

    /// <summary>The curve coefficient <c>a</c>, encoded to canonical bytes for the ECDSA gadget.</summary>
    private static byte[] CurveABytes { get; } = EcdsaNonceRecovery.Bytes(A);

    /// <summary>The curve coefficient <c>b</c>, encoded to canonical bytes for the ECDSA gadget.</summary>
    private static byte[] CurveBBytes { get; } = EcdsaNonceRecovery.Bytes(B);


    /// <summary>
    /// Verifies out of circuit, on the genuine credential bytes, that the signed Sig_structure holds
    /// SHA-256 of the item at the located digest offset and that the item's bytes at the attribute
    /// offset equal the disclosure pattern.
    /// </summary>
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


    /// <summary>
    /// Verifies that reading the packed witness back through the byte-to-wire mapping reproduces
    /// both the item's real SHA-256 digest and the disclosure pattern, the falsifiable gate on the
    /// mapping itself.
    /// </summary>
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


    /// <summary>
    /// Verifies that every SHA instance (for the message's components and the item) evaluates to an
    /// all-zero output and the MAC instance evaluates to the macs of the real digest, all on the flat
    /// honest witness.
    /// </summary>
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


    /// <summary>
    /// Verifies that the full disclosure statement holds over the honest witness, then that it
    /// breaks under two duals: a tampered public attribute byte, and an item-digest offset shifted
    /// by one.
    /// </summary>
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


    /// <summary>
    /// Verifies that a one-byte-tampered item still hashes consistently to its own digest, so its
    /// SHA instances close, but the disclosure statement itself rejects it because that digest no
    /// longer matches the signed Sig_structure and the flipped byte no longer matches the attribute
    /// pins.
    /// </summary>
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


    /// <summary>
    /// Verifies the full mdoc statement end to end: one Fp256 commitment carries the MAC region and
    /// the ECDSA gadget while one GF commitment carries the Sig_structure hash, the item hash and
    /// the disclosure statement, bound by a shared transcript; a genuine proof verifies, a flipped
    /// mac is rejected, and a verifier-side tampered attribute is rejected without a re-prove.
    /// </summary>
    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void TheFullMdocStatementProvesAndVerifiesOnOneCommitment()
    {
        //THE FULL MDOC CAPSTONE: one Fp256 commitment carries the MAC region and the ECDSA gadget
        //(the digest-plus-ECDSA binding GkrMdocEcdsaTests proves standalone), one GF commitment carries the Sig_structure hash, the item hash and
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


    /// <summary>
    /// Runs the full prover protocol: commits the combined Fp system (MAC region plus ECDSA
    /// gadget), commits GF with both roots absorbed, squeezes the verifier key, computes the macs,
    /// proves every GF instance under the disclosure statement, then proves the Fp linear statement
    /// over the Montgomery backend, retaining its pooled builder witness snapshot. The transcript
    /// order matches <see cref="GkrMdocEcdsaTests"/>'s combined MAC-and-ECDSA binding.
    /// </summary>
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

        using IMemoryOwner<byte>? witnessOwner = builder.WitnessBytes();
        using LigeroCommitment fpCommitment = LigeroProver.Commit(
            fpParameters, (witnessOwner?.Memory ?? Memory<byte>.Empty).Span, fpQuadratics, new GkrCrossFieldMacSupport.FpDeterministicRandom(FpRandomnessSeed).AsDelegate(),
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


    /// <summary>
    /// Runs the full verifier protocol, mirroring the prover's transcript order exactly and reusing
    /// the prover's builder for the gadget structure. The GF statement and targets are passed
    /// separately so the tampered-attribute dual can move the verifier's pins without a re-prove.
    /// </summary>
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


    /// <summary>
    /// Builds the combined Fp system's quadratics: the ECDSA gadget's own quadratics followed by the
    /// MAC product and bitness triples.
    /// </summary>
    private static LigeroQuadraticConstraint[] CombinedQuadratics(LigeroConstraintSystemBuilder builder)
    {
        LigeroQuadraticConstraint[] gadget = builder.QuadraticConstraints();
        LigeroQuadraticConstraint[] mac = GkrCrossFieldMacSupport.BuildFpQuadratics();
        var combined = new LigeroQuadraticConstraint[gadget.Length + mac.Length];
        gadget.CopyTo(combined, 0);
        mac.CopyTo(combined, gadget.Length);

        return combined;
    }


    /// <summary>
    /// Builds the combined Fp linear statement: the builder's gadget constraints, then the MAC
    /// parity statement re-indexed past them, copying the gadget targets before returning their
    /// owner.
    /// </summary>
    private static (int LinearCount, LigeroLinearConstraint[] Constraints, byte[] Targets) CombinedLinear(
        LigeroConstraintSystemBuilder builder, ReadOnlySpan<byte> verifierKey, ReadOnlySpan<byte> macs, ulong[] maskedQuotients)
    {
        int gadgetCount = builder.LinearConstraintCount;
        LigeroLinearConstraint[] gadget = builder.LinearConstraints();
        using IMemoryOwner<byte>? gadgetTargetsOwner = builder.TargetBytes();
        ReadOnlySpan<byte> gadgetTargets = (gadgetTargetsOwner?.Memory ?? Memory<byte>.Empty).Span;
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
        gadgetTargets.CopyTo(combinedTargets);
        parityTargets.CopyTo(combinedTargets, gadgetTargets.Length);

        return (linearCount, combined, combinedTargets);
    }


    /// <summary>
    /// Builds the combined Fp builder over the real credential's signature: the MAC region first,
    /// then the ECDSA gadget consuming the committed digest bits as its e·G scalar. The disclosure
    /// statement changes nothing on the Fp side.
    /// </summary>
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


    /// <summary>
    /// Returns the 256 MAC message wires that hold the digest, most-significant digest bit first.
    /// </summary>
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


    /// <summary>
    /// Assembles one byte from value-bit k (k = 0 the least-significant) of the witness at the wire
    /// the given selector names for that bit; the bit lives in the last byte of the scalar.
    /// </summary>
    private static byte ReadByte(ReadOnlySpan<byte> witness, Func<int, int> wireOfBit)
    {
        int value = 0;
        for(int k = 0; k < 8; k++)
        {
            value |= (witness[(wireOfBit(k) * ScalarSize) + ScalarSize - 1] & 1) << k;
        }

        return (byte)value;
    }


    /// <summary>
    /// Sums coefficient·W per constraint over GF(2^128), where addition is XOR and multiply is the
    /// field multiply, and returns whether every sum equals its target.
    /// </summary>
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


    /// <summary>
    /// Reads the real mdoc credential fixture from disk and extracts its signed structure, issuer-
    /// signed item and the disclosed <c>age_over_18</c> attribute. A static initializer feeds this,
    /// so the read stays synchronous and cannot await.
    /// </summary>
    private static MdocDisclosure LoadDisclosure()
    {
        byte[] credential = File.ReadAllBytes("../../../TestMaterial/Mdoc/mdoc-00.cbor");

        return MdocDisclosure.Extract(credential, "org.iso.18013.5.1", "age_over_18");
    }


    /// <summary>
    /// Builds a fresh Fiat-Shamir transcript scoped to this file's fixed domain and seed.
    /// </summary>
    private static FiatShamirTranscript NewTranscript() =>
        GkrGf2kTestSupport.NewTranscript(Domain, "veridical.gkr.mdoc.disclosure.seed"u8, []);


    /// <summary>
    /// The production Montgomery Fp256 backend delegates, byte-identical to the reference
    /// implementation, used for the large real-credential Fp commitment.
    /// </summary>
    private static class Montgomery
    {
        /// <summary>The Montgomery-domain Fp256 addition delegate.</summary>
        public static ScalarAddDelegate Add { get; } = P256BaseFieldMontgomeryBackend.GetAdd();

        /// <summary>The Montgomery-domain Fp256 subtraction delegate.</summary>
        public static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldMontgomeryBackend.GetSubtract();

        /// <summary>The Montgomery-domain Fp256 multiplication delegate.</summary>
        public static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldMontgomeryBackend.GetMultiply();

        /// <summary>The Montgomery-domain Fp256 inversion delegate.</summary>
        public static ScalarInvertDelegate Invert { get; } = P256BaseFieldMontgomeryBackend.GetInvert();

        /// <summary>The delegate that reduces an Fp256 accumulator back into the Montgomery domain.</summary>
        public static ScalarReduceDelegate Reduce { get; } = P256BaseFieldMontgomeryBackend.GetReduce();
    }
}

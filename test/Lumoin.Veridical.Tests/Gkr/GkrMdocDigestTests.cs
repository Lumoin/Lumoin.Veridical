using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Mdoc;
using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The SHA-256 of a REAL ISO 18013-5 credential's COSE <c>Sig_structure</c> proven over
/// <c>GF(2^128)</c> at full multi-block scale, with the private digest MAC-bound into an Fp256
/// commitment. This is the deployed Longfellow shape on genuine bytes: the Sig_structure of
/// <c>mdoc-00.cbor</c> (whose SHA-256 is the <c>e</c> the issuer's ES256 signature verifies
/// against) is hashed in-circuit through the characteristic-two CSA round/schedule/addition
/// instances; the digest is never pinned — its bits glue into the one-layer MAC instance and the
/// cross-field parity statement binds them to the Fp256 commitment the ECDSA side will share.
/// The GF-side machinery (the flat power-of-two-component witness layout, the glue statement, the
/// bitness, the instances and the expected outputs) lives in <see cref="GkrMdocSupport"/>, shared
/// with the digest-plus-ECDSA binding <see cref="GkrMdocEcdsaTests"/>.
/// </summary>
[TestClass]
internal sealed class GkrMdocDigestTests
{
    /// <summary>The byte width of one GF(2^128) scalar.</summary>
    private const int ScalarSize = GkrGf2kShaSupport.ScalarSize;

    /// <summary>The bit width of one half of a split MAC value.</summary>
    private const int HalfBits = GkrGf2kMacSupport.HalfBits;

    /// <summary>The number of halves a MAC value is split into.</summary>
    private const int Halves = GkrGf2kMacSupport.CopyCount;

    /// <summary>The byte width of a SHA-256 digest.</summary>
    private const int DigestBytes = GkrShaRoundSupport.DigestBytes;

    /// <summary>The Reed-Solomon code rate's inverse used by the test Ligero parameters.</summary>
    private const int InverseRate = 4;

    /// <summary>The number of columns the Ligero verifier opens per proof.</summary>
    private const int OpenedColumns = 4;

    /// <summary>The Ligero block size shared by the Fp and GF parameter sets.</summary>
    private const int Block = 64;

    /// <summary>The Fiat-Shamir domain label that scopes every transcript this file builds.</summary>
    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.mdoc.digest.test");

    /// <summary>The Fiat-Shamir label under which the Fp proving seed is squeezed from the shared transcript.</summary>
    private static FiatShamirOperationLabel FpSeedLabel { get; } = new("veridical.gkr.mdoc.fp.seed");

    /// <summary>The fixed seed for the Fp commitment's deterministic randomness source.</summary>
    private static byte[] FpRandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.mdoc.fp.rng.v1");

    /// <summary>The fixed seed for the GF commitment's deterministic randomness source.</summary>
    private static byte[] GfRandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.mdoc.gf.rng.v1");

    /// <summary>The fixed seed for the Fp witness's masking randomness.</summary>
    private static byte[] MaskSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.mdoc.mask.v1");

    /// <summary>The two fixed MAC key shares the tests combine into the verifier's probe key.</summary>
    private static byte[][] KeyShares { get; } =
    [
        GkrCrossFieldMacSupport.Element(0x243f6a8885a308d3UL, 0x13198a2e03707344UL),
        GkrCrossFieldMacSupport.Element(0xa4093822299f31d0UL, 0x082efa98ec4e6c89UL),
    ];

    /// <summary>
    /// The real credential's signed payload: the COSE Sig_structure whose SHA-256 the issuer's
    /// ES256 signature verifies against.
    /// </summary>
    private static byte[] SignedStructure { get; } = LoadSignedStructure();

    /// <summary>The GF(2^128) circuit support built over the real signed structure and key shares, shared by every test.</summary>
    private static GkrMdocSupport Support { get; } = new(SignedStructure, KeyShares);


    /// <summary>
    /// Verifies that the in-circuit chained oracle digest of the real Sig_structure matches
    /// .NET's <see cref="SHA256"/>, and that every SHA instance closes to an all-zero output while
    /// the MAC instance closes to the macs of that digest, all on the honest flat witness.
    /// </summary>
    [TestMethod]
    public void TheRealSigStructureClosesEveryInstanceAndMatchesDotNetSha256()
    {
        //The chained oracle digest must equal .NET's hash of the genuine Sig_structure bytes.
        Span<byte> digest = stackalloc byte[DigestBytes];
        Support.ComputeDigest(digest);
        byte[] reference = SHA256.HashData(SignedStructure);
        Assert.IsTrue(digest.SequenceEqual(reference), "The chained oracle digest must match SHA256.HashData of the real Sig_structure.");

        //Every SHA instance evaluates to all-zero outputs on the honest witness, and the MAC
        //instance evaluates to the macs of the real digest, per component, on the flat witness.
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

        Assert.IsTrue(outputs.SequenceEqual(expected), "Every instance must close on the honest witness: zeros for the SHA instances, the macs for the MAC instance.");
    }


    /// <summary>
    /// Verifies end to end that the real Sig_structure's in-circuit digest MAC-binds to the Fp
    /// commitment: a genuine proof pair verifies, and a mac differing by one byte is rejected.
    /// </summary>
    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void TheRealCredentialDigestIsMacBoundAcrossFields()
    {
        //On the order of tens of minutes, hardware-dependent: the real Sig_structure's
        //multi-block GF SHA-256 proves and verifies through the real provers. The
        //default-suite gate above verifies the same circuits and statement cheaply by direct
        //instance evaluation against the oracle, so this gate adds the end-to-end proving, not
        //the logic coverage.
        Span<byte> digest = stackalloc byte[DigestBytes];
        Support.ComputeDigest(digest);

        using IMemoryOwner<byte> gfWitnessOwner = BaseMemoryPool.Shared.Rent(Support.WitnessBytes);
        Span<byte> gfWitness = gfWitnessOwner.Memory.Span[..Support.WitnessBytes];
        Support.PackGfWitness(gfWitness, digest);
        using IMemoryOwner<byte> fpWitnessOwner = BaseMemoryPool.Shared.Rent(GkrCrossFieldMacSupport.FpWitnessBytes);
        Span<byte> fpWitness = fpWitnessOwner.Memory.Span[..GkrCrossFieldMacSupport.FpWitnessBytes];
        GkrCrossFieldMacSupport.PackFpWitness(fpWitness, digest, KeyShares, MaskSeed);

        Span<byte> verifierKey = stackalloc byte[ScalarSize];
        Span<byte> macs = stackalloc byte[Halves * ScalarSize];
        ulong[] maskedQuotients = new ulong[Halves * HalfBits];
        (LigeroProof fpProof, GkrCommittedProof gfProof) = ProveCrossField(fpWitness, gfWitness, digest, verifierKey, macs, maskedQuotients);
        using LigeroProof fp = fpProof;
        using GkrCommittedProof gf = gfProof;

        Assert.IsTrue(VerifyCrossField(fp, gf, macs, maskedQuotients), "The real Sig_structure's digest, hashed in-circuit, must MAC-bind to the Fp commitment.");

        //A flipped mac must be rejected on both sides: the GF walk closes on the wrong outputs
        //and the Fp parity targets move.
        Span<byte> wrongMacs = stackalloc byte[Halves * ScalarSize];
        macs.CopyTo(wrongMacs);
        wrongMacs[ScalarSize - 1] ^= 0x01;
        Assert.IsFalse(VerifyCrossField(fp, gf, wrongMacs, maskedQuotients), "A mac differing in one byte must be rejected.");
    }


    /// <summary>
    /// Runs the full prover protocol with the SHA instance set in place of a bare MAC: commits Fp,
    /// commits GF with both roots absorbed, squeezes the verifier key, computes the macs, proves
    /// every GF instance under the glue statement, then proves the Fp parity statement.
    /// </summary>
    private static (LigeroProof FpProof, GkrCommittedProof GfProof) ProveCrossField(
        ReadOnlySpan<byte> fpWitness,
        ReadOnlySpan<byte> gfWitness,
        ReadOnlySpan<byte> digest,
        Span<byte> verifierKey,
        Span<byte> macs,
        ulong[] maskedQuotients)
    {
        LigeroQuadraticConstraint[] fpQuadratics = GkrCrossFieldMacSupport.BuildFpQuadratics();
        var fpParameters = new LigeroParameters(GkrCrossFieldMacSupport.FpWitnessCount, fpQuadratics.Length, InverseRate, OpenedColumns, Block);
        LigeroQuadraticConstraint[] gfBitness = Support.BuildBitnessConstraints();
        var gfParameters = new LigeroParameters(Support.WitnessScalars, gfBitness.Length, InverseRate, OpenedColumns, Block, LigeroNodeDomain.BinaryField);
        (LigeroLinearConstraint[] statement, byte[] targets) = Support.BuildStatement();

        using FiatShamirTranscript transcript = NewTranscript();

        using LigeroCommitment fpCommitment = LigeroProver.Commit(
            fpParameters, fpWitness, fpQuadratics, new GkrCrossFieldMacSupport.FpDeterministicRandom(FpRandomnessSeed).AsDelegate(),
            GkrTestSupport.Add, GkrTestSupport.Subtract, GkrTestSupport.Multiply, GkrTestSupport.Invert,
            GkrTestSupport.Hash, WellKnownHashAlgorithms.Blake3, GkrTestSupport.Merkle, CurveParameterSet.None,
            BaseMemoryPool.Shared);
        transcript.AbsorbLigeroTableauRoot(fpCommitment.Root, GkrTestSupport.Hash);

        using LigeroCommitment gfCommitment = GkrCommittedProver.Commit(
            gfWitness, gfParameters, gfBitness,
            () => new GkrCrossFieldMacSupport.GfDeterministicRandom(GfRandomnessSeed).AsDelegate(),
            GkrGf2kTestSupport.Add, GkrGf2kTestSupport.Subtract, GkrGf2kTestSupport.Multiply, GkrGf2kTestSupport.Invert, CurveParameterSet.None,
            transcript, GkrGf2kTestSupport.Hash, GkrGf2kTestSupport.Hash, GkrTestSupport.Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared);

        //Both witnesses are fixed; the verifier key and the public macs follow them.
        GkrGf2kMacSupport.SqueezeVerifierKey(transcript, verifierKey);
        GkrGf2kMacSupport.ComputeMacs(digest, KeyShares, verifierKey, macs);

        GkrCommittedProof gfProof = GkrCommittedProver.Prove(
            gfCommitment, Support.Instances(verifierKey), statement, targets,
            GkrGf2kTestSupport.Add, GkrGf2kTestSupport.Subtract, GkrGf2kTestSupport.Multiply, GkrGf2kTestSupport.Invert, GkrGf2kTestSupport.Reduce, CurveParameterSet.None,
            transcript, GkrGf2kTestSupport.Squeeze, GkrGf2kTestSupport.Hash,
            BaseMemoryPool.Shared);

        GkrCrossFieldMacSupport.ComputeMaskedQuotients(fpWitness, verifierKey, macs, maskedQuotients);
        (LigeroLinearConstraint[] parityConstraints, byte[] parityTargets) = GkrCrossFieldMacSupport.BuildParityStatement(verifierKey, macs, maskedQuotients);

        Span<byte> fpSeed = stackalloc byte[ScalarSize];
        transcript.SqueezeBytes(FpSeedLabel, fpSeed, GkrTestSupport.Squeeze, GkrTestSupport.Hash);

        LigeroProof fpProof;
        try
        {
            fpProof = LigeroProver.Prove(
                fpCommitment, Halves * HalfBits, parityConstraints, parityTargets, fpSeed,
                GkrTestSupport.Add, GkrTestSupport.Subtract, GkrTestSupport.Multiply, GkrTestSupport.Invert, GkrTestSupport.Reduce,
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
    /// Runs the full verifier protocol, mirroring the prover's transcript order exactly. The digest
    /// appears nowhere: only the macs and the masked quotients are public.
    /// </summary>
    private static bool VerifyCrossField(LigeroProof fpProof, GkrCommittedProof gfProof, ReadOnlySpan<byte> macs, ulong[] maskedQuotients)
    {
        LigeroQuadraticConstraint[] fpQuadratics = GkrCrossFieldMacSupport.BuildFpQuadratics();
        var fpParameters = new LigeroParameters(GkrCrossFieldMacSupport.FpWitnessCount, fpQuadratics.Length, InverseRate, OpenedColumns, Block);
        LigeroQuadraticConstraint[] gfBitness = Support.BuildBitnessConstraints();
        var gfParameters = new LigeroParameters(Support.WitnessScalars, gfBitness.Length, InverseRate, OpenedColumns, Block, LigeroNodeDomain.BinaryField);
        (LigeroLinearConstraint[] statement, byte[] targets) = Support.BuildStatement();

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

        (LigeroLinearConstraint[] parityConstraints, byte[] parityTargets) = GkrCrossFieldMacSupport.BuildParityStatement(verifierKey, macs, maskedQuotients);

        Span<byte> fpSeed = stackalloc byte[ScalarSize];
        transcript.SqueezeBytes(FpSeedLabel, fpSeed, GkrTestSupport.Squeeze, GkrTestSupport.Hash);

        return LigeroVerifier.Verify(
            fpParameters, fpProof, Halves * HalfBits, parityConstraints, parityTargets, fpQuadratics, fpSeed,
            GkrTestSupport.Add, GkrTestSupport.Subtract, GkrTestSupport.Multiply, GkrTestSupport.Invert, GkrTestSupport.Reduce,
            GkrTestSupport.Hash, GkrTestSupport.Squeeze, GkrTestSupport.Hash, GkrTestSupport.Merkle, WellKnownHashAlgorithms.Blake3, CurveParameterSet.None,
            BaseMemoryPool.Shared);
    }


    /// <summary>Reads the real mdoc credential fixture from disk and extracts its signed Sig_structure bytes.</summary>
    private static byte[] LoadSignedStructure()
    {
        //A static initializer feeds this, so the read stays synchronous (it cannot await).
        byte[] credential = File.ReadAllBytes("../../../TestMaterial/Mdoc/mdoc-00.cbor");
        MdocDisclosure disclosure = MdocDisclosure.Extract(credential, "org.iso.18013.5.1", "age_over_18");

        return disclosure.SignedStructure;
    }


    /// <summary>Builds a fresh Fiat-Shamir transcript scoped to this file's fixed domain and seed.</summary>
    private static FiatShamirTranscript NewTranscript() =>
        GkrGf2kTestSupport.NewTranscript(Domain, "veridical.gkr.mdoc.digest.seed"u8, []);
}

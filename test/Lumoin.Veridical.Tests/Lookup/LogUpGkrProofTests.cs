using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Lookup;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.Spartan;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Lumoin.Veridical.Tests.Lookup;

/// <summary>
/// End-to-end tests for the LogUp-GKR lookup argument — the variant whose
/// only extra commitment is the multiplicity column, with the fractional sum
/// proven by cascaded layer sumchecks over the projective fraction tree.
/// Honest proofs verify over the Ligero, BaseFold and Hyrax providers; a
/// witness-column count one below a power of two and one that exercises a
/// neutral padding slot both round-trip; and tampering with the root values,
/// a layer message, or a claimed evaluation is rejected. Real BLS12-381
/// arithmetic and production BLAKE3 throughout.
/// </summary>
[TestClass]
internal sealed class LogUpGkrProofTests
{
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();
    private static G1HashToCurveDelegate G1HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();

    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    //Eight opened columns / query repetitions keep the fixtures fast;
    //soundness margins are the ledger tests' concern.
    private const int TestQueryCount = 8;

    //Three row variables (eight rows) gives a four-to-five-variable fraction
    //tree, exercising multi-round layers while staying cheap.
    private const int TestVariableCount = 3;

    private const string TranscriptDomain = "veridical.logup.gkr.test.v1";

    //Distinct salts keep the streams independent and reproducible; the
    //offset selects a stream disjoint from the table's for the absent-value
    //case.
    private const int TableFillSalt = 823;
    private const int OutOfTableFillSaltOffset = 991;

    //Coprime-to-the-cube strides walk every witness row and column onto a
    //distinct table position.
    private const int WitnessRowStride = 5;
    private const int WitnessColumnStride = 3;

    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;

    //Domain-separated from the transcript label so the Hyrax Pedersen
    //blinding stream is independent of the Fiat-Shamir stream.
    private static byte[] HyraxBlindSeed { get; } = Encoding.UTF8.GetBytes("veridical.logup.gkr.test.hyrax.blind.v1");


    [TestMethod]
    public void SingleColumnLookupRoundTripsThroughLigero()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpGkrProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "An honest single-column LogUp-GKR proof must verify over Ligero.");
    }


    [TestMethod]
    public void TwoColumnLookupExercisesANeutralPaddingSlot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 2, pool);

        //Two witness columns need two selector variables, leaving one of the
        //four selector slots as the neutral 0/1 padding fraction.
        using LogUpGkrProof proof = Prove(material, TestVariableCount, witnessColumnCount: 2, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "A witness-column count that pads the selector cube must round-trip through the neutral fraction.");
    }


    [TestMethod]
    public void ThreeColumnLookupFillsTheSelectorCube()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 3, pool);

        using LogUpGkrProof proof = Prove(material, TestVariableCount, witnessColumnCount: 3, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "Three witness columns fill the four-slot selector cube exactly and must round-trip.");
    }


    [TestMethod]
    public void SingleColumnLookupRoundTripsThroughBaseFold()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildBaseFoldProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpGkrProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "An honest LogUp-GKR proof must verify over BaseFold — the argument is provider-generic.");
    }


    [TestMethod]
    public void SingleColumnLookupRoundTripsThroughHyrax()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildHyraxProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpGkrProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "An honest LogUp-GKR proof must verify over Hyrax — the homomorphic Pedersen-family backend.");
    }


    [TestMethod]
    public void DuplicateTableEntriesAreAccepted()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);
        int size = 1 << TestVariableCount;
        Span<byte> table = material.Memory.Span[..(size * ScalarSize)];

        table[..ScalarSize].CopyTo(table.Slice(ScalarSize, ScalarSize));
        Span<byte> witness = material.Memory.Span.Slice(size * ScalarSize, size * ScalarSize);
        for(int row = 0; row < size; row++)
        {
            table[..ScalarSize].CopyTo(witness.Slice(row * ScalarSize, ScalarSize));
        }

        using LogUpGkrProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "Duplicate table entries must be harmless: multiplicity weight aggregates on the first occurrence.");
    }


    [TestMethod]
    public void ProvingIsByteForByteDeterministic()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpGkrProof first = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);
        using LogUpGkrProof second = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(first.GetRootValueBytes().SequenceEqual(second.GetRootValueBytes()), "Root values must be deterministic.");
        Assert.IsTrue(first.GetLayerMessageBytes().SequenceEqual(second.GetLayerMessageBytes()), "Layer messages must be deterministic.");
        Assert.IsTrue(first.GetClaimedEvaluationBytes().SequenceEqual(second.GetClaimedEvaluationBytes()), "Claimed evaluations must be deterministic.");
    }


    [TestMethod]
    public void WitnessValueAbsentFromTableIsUnprovable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);
        int size = 1 << TestVariableCount;

        Span<byte> witness = material.Memory.Span.Slice(size * ScalarSize, size * ScalarSize);
        DeterministicScalarFill.FillCanonical(witness.Slice(2 * ScalarSize, ScalarSize), TableFillSalt + OutOfTableFillSaltOffset, Reduce, Curve);

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using LogUpGkrProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);
        }, "A witness value absent from the table makes the statement false; the prover must refuse.");
    }


    [TestMethod]
    public void TamperedRootValueIsRejected()
    {
        AssertTamperRejected(mutateRootByteOffset: ScalarSize - 1, mutateLayerByteOffset: null, mutateClaimedByteOffset: null);
    }


    [TestMethod]
    public void TamperedLayerMessageIsRejected()
    {
        AssertTamperRejected(mutateRootByteOffset: null, mutateLayerByteOffset: ScalarSize - 1, mutateClaimedByteOffset: null);
    }


    [TestMethod]
    public void TamperedClaimedEvaluationIsRejected()
    {
        AssertTamperRejected(mutateRootByteOffset: null, mutateLayerByteOffset: null, mutateClaimedByteOffset: ScalarSize - 1);
    }


    [TestMethod]
    public void HostileShapeIsRejectedAtReconstruction()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpGkrProof honest = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        //The caps run before any part is consumed, so passing the honest
        //proof's live parts is safe: ownership transfers only on success.
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
        {
            using LogUpGkrProof rejected = LogUpGkrProof.FromParts(
                LogUpProver.MaximumVariableCount, honest.WitnessColumnCount, honest.Curve,
                honest.WitnessCommitments, honest.MultiplicityCommitment,
                honest.GetRootValueBytes(), honest.GetLayerMessageBytes(), honest.GetClaimedEvaluationBytes(),
                honest.WitnessOpenings, honest.MultiplicityOpening, pool);
        }, "A row variable count whose tree total exceeds the cap must be rejected at the funnel.");
    }


    [TestMethod]
    public void NonCanonicalRootBytesAreRejectedAtReconstruction()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpGkrProof honest = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using LogUpGkrProof rejected = CloneProof(honest, pcs, pool, mutateRootByteOffset: null, mutateLayerByteOffset: null, mutateClaimedByteOffset: null, forceNonCanonicalRootScalar: true);
        }, "The reconstruction funnel must reject a root scalar at or above the field order.");
    }


    private static void AssertTamperRejected(int? mutateRootByteOffset, int? mutateLayerByteOffset, int? mutateClaimedByteOffset)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpGkrProof honest = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);
        using LogUpGkrProof tampered = CloneProof(honest, pcs, pool, mutateRootByteOffset, mutateLayerByteOffset, mutateClaimedByteOffset);

        Assert.IsFalse(Verify(material, tampered, pcs, pool), "A tampered proof component must be rejected.");
    }


    private static LogUpGkrProof Prove(IMemoryOwner<byte> material, int variableCount, int witnessColumnCount, PolynomialCommitmentProvider pcs, BaseMemoryPool pool)
    {
        int size = 1 << variableCount;
        ReadOnlySpan<byte> table = material.Memory.Span[..(size * ScalarSize)];
        ReadOnlySpan<byte> witness = material.Memory.Span.Slice(size * ScalarSize, witnessColumnCount * size * ScalarSize);
        using FiatShamirTranscript transcript = FreshTranscript();

        return LogUpGkrProver.Prove(
            table, witness, variableCount, witnessColumnCount, pcs, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, MleEvaluate, pool);
    }


    private static bool Verify(IMemoryOwner<byte> material, LogUpGkrProof proof, PolynomialCommitmentProvider pcs, BaseMemoryPool pool)
    {
        int size = 1 << proof.VariableCount;
        ReadOnlySpan<byte> table = material.Memory.Span[..(size * ScalarSize)];
        using FiatShamirTranscript transcript = FreshTranscript();

        return LogUpGkrVerifier.Verify(
            table, proof, pcs, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MleEvaluate, pool);
    }


    //Clones a proof through the public reconstruction funnel, optionally
    //flipping one byte of the root values, the layer messages, or the claimed
    //evaluations.
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the cloned commitments and openings transfers to the proof returned by FromParts; the catch block disposes them when reconstruction throws.")]
    private static LogUpGkrProof CloneProof(
        LogUpGkrProof source,
        PolynomialCommitmentProvider pcs,
        BaseMemoryPool pool,
        int? mutateRootByteOffset,
        int? mutateLayerByteOffset,
        int? mutateClaimedByteOffset,
        bool forceNonCanonicalRootScalar = false)
    {
        int witnessColumnCount = source.WitnessColumnCount;
        var witnessCommitments = new List<PolynomialCommitment>(witnessColumnCount);
        var witnessOpenings = new List<PolynomialOpening>(witnessColumnCount);
        PolynomialCommitment? multiplicityCommitment = null;
        PolynomialOpening? multiplicityOpening = null;
        try
        {
            for(int column = 0; column < witnessColumnCount; column++)
            {
                witnessCommitments.Add(PolynomialCommitment.FromBytes(source.WitnessCommitments[column].AsReadOnlySpan(), source.Curve, pcs.Scheme, pool));
                witnessOpenings.Add(PolynomialOpening.FromBytes(source.WitnessOpenings[column].AsReadOnlySpan(), source.Curve, pcs.Scheme, pool));
            }

            multiplicityCommitment = PolynomialCommitment.FromBytes(source.MultiplicityCommitment.AsReadOnlySpan(), source.Curve, pcs.Scheme, pool);
            multiplicityOpening = PolynomialOpening.FromBytes(source.MultiplicityOpening.AsReadOnlySpan(), source.Curve, pcs.Scheme, pool);

            using IMemoryOwner<byte> rootOwner = pool.Rent(source.GetRootValueBytes().Length);
            Span<byte> rootBytes = rootOwner.Memory.Span[..source.GetRootValueBytes().Length];
            source.GetRootValueBytes().CopyTo(rootBytes);
            if(mutateRootByteOffset is int rootOffset)
            {
                rootBytes[rootOffset] ^= 0x01;
            }

            if(forceNonCanonicalRootScalar)
            {
                rootBytes[..ScalarSize].Fill(0xFF);
            }

            using IMemoryOwner<byte> layersOwner = pool.Rent(source.GetLayerMessageBytes().Length);
            Span<byte> layerBytes = layersOwner.Memory.Span[..source.GetLayerMessageBytes().Length];
            source.GetLayerMessageBytes().CopyTo(layerBytes);
            if(mutateLayerByteOffset is int layerOffset)
            {
                layerBytes[layerOffset] ^= 0x01;
            }

            using IMemoryOwner<byte> claimedOwner = pool.Rent(source.GetClaimedEvaluationBytes().Length);
            Span<byte> claimedBytes = claimedOwner.Memory.Span[..source.GetClaimedEvaluationBytes().Length];
            source.GetClaimedEvaluationBytes().CopyTo(claimedBytes);
            if(mutateClaimedByteOffset is int claimedOffset)
            {
                claimedBytes[claimedOffset] ^= 0x01;
            }

            return LogUpGkrProof.FromParts(
                source.VariableCount,
                witnessColumnCount,
                source.Curve,
                witnessCommitments,
                multiplicityCommitment,
                rootBytes,
                layerBytes,
                claimedBytes,
                witnessOpenings,
                multiplicityOpening,
                pool);
        }
        catch
        {
            foreach(PolynomialCommitment commitment in witnessCommitments)
            {
                commitment.Dispose();
            }
            foreach(PolynomialOpening opening in witnessOpenings)
            {
                opening.Dispose();
            }
            multiplicityCommitment?.Dispose();
            multiplicityOpening?.Dispose();
            throw;
        }
    }


    private static IMemoryOwner<byte> BuildLookupMaterial(int variableCount, int witnessColumnCount, BaseMemoryPool pool)
    {
        int size = 1 << variableCount;
        IMemoryOwner<byte> owner = pool.Rent((1 + witnessColumnCount) * size * ScalarSize);
        Span<byte> material = owner.Memory.Span[..((1 + witnessColumnCount) * size * ScalarSize)];
        Span<byte> table = material[..(size * ScalarSize)];
        DeterministicScalarFill.FillCanonical(table, TableFillSalt, Reduce, Curve);

        for(int column = 0; column < witnessColumnCount; column++)
        {
            Span<byte> witness = material.Slice((1 + column) * size * ScalarSize, size * ScalarSize);
            for(int row = 0; row < size; row++)
            {
                int tableIndex = ((row * WitnessRowStride) + (column * WitnessColumnStride)) % size;
                table.Slice(tableIndex * ScalarSize, ScalarSize).CopyTo(witness.Slice(row * ScalarSize, ScalarSize));
            }
        }

        return owner;
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The Ligero provider holds no disposable key material; callers dispose the provider itself.")]
    private static PolynomialCommitmentProvider BuildLigeroProvider()
    {
        return LigeroPolynomialCommitmentScheme.Create(
            Curve, TestQueryCount, Add, Subtract, Multiply, Invert, Reduce,
            Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3, DigestSizeBytes);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The BaseFold provider holds no disposable key material; callers dispose the provider itself.")]
    private static PolynomialCommitmentProvider BuildBaseFoldProvider()
    {
        ReadOnlySpan<byte> codeSeed = "veridical.logup.gkr.test.basefold.code.v1"u8;

        return BaseFoldPolynomialCommitmentScheme.Create(
            codeSeed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce,
            Add, Subtract, Multiply, Invert, HashToScalar, DigestSizeBytes);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the derived commitment key transfers to the returned provider (ownsKey: true).")]
    private static PolynomialCommitmentProvider BuildHyraxProvider()
    {
        HyraxCommitmentDimensions dimensions = HyraxCommitmentDimensions.ForVariableCount(TestVariableCount);
        HyraxCommitmentKey key = HyraxCommitmentKey.Derive(
            dimensions.ColumnCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, Curve, G1HashToCurve, BaseMemoryPool.Shared);
        ScalarRandomDelegate random = new DeterministicScalarRandom(HyraxBlindSeed).AsDelegate();

        return HyraxPolynomialCommitmentScheme.Create(
            key, Curve, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup, ownsKey: true);
    }


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}

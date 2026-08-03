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
/// End-to-end tests for the LogUp lookup argument: an honest proof that every
/// witness value appears in the public table verifies over the Ligero,
/// BaseFold and Hyrax commitment providers — two hash-based schemes and the
/// homomorphic Pedersen family, so the argument demonstrably depends only on
/// the provider seam; a false statement is unprovable; and every tampered
/// proof component — round messages, claimed evaluations, openings, or a
/// substituted table — is rejected. Real BLS12-381 arithmetic and production
/// BLAKE3 throughout.
/// </summary>
[TestClass]
internal sealed class LogUpProofTests
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

    //Eight opened columns / query repetitions keep the fixtures fast; soundness
    //margins are the ledger tests' concern, not these round-trips'.
    private const int TestQueryCount = 8;

    //Three variables (eight rows) exercises multi-round folding while keeping
    //the degree-(M+3) round computation cheap.
    private const int TestVariableCount = 3;

    private const string TranscriptDomain = "veridical.logup.test.v1";

    //Distinct salts keep the table and each witness-selection stream
    //independent and reproducible; the offsets select streams disjoint from
    //the table's for the absent-value and substituted-table cases.
    private const int TableFillSalt = 811;
    private const int OutOfTableFillSaltOffset = 997;
    private const int SubstituteTableFillSaltOffset = 499;

    //Coprime-to-the-cube strides walk every witness row and column onto a
    //distinct table position, so all columns and rows differ.
    private const int WitnessRowStride = 5;
    private const int WitnessColumnStride = 3;

    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;

    //Domain-separated from the transcript label so the Hyrax Pedersen
    //blinding stream is independent of the Fiat-Shamir stream Hyrax also
    //draws challenges from.
    private static byte[] HyraxBlindSeed { get; } = Encoding.UTF8.GetBytes("veridical.logup.test.hyrax.blind.v1");


    [TestMethod]
    public void SingleColumnLookupRoundTripsThroughLigero()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "An honest single-column LogUp proof must verify over Ligero.");
    }


    [TestMethod]
    public void ThreeColumnLookupRoundTripsThroughLigero()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 3, pool);

        using LogUpProof proof = Prove(material, TestVariableCount, witnessColumnCount: 3, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "An honest three-column LogUp proof must verify over Ligero.");
    }


    [TestMethod]
    public void SingleColumnLookupRoundTripsThroughBaseFold()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildBaseFoldProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "An honest LogUp proof must verify over BaseFold — the argument is provider-generic.");
    }


    [TestMethod]
    public void SingleColumnLookupRoundTripsThroughHyrax()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildHyraxProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "An honest LogUp proof must verify over Hyrax — the argument is provider-generic and Hyrax is the homomorphic Pedersen-family backend.");
    }


    [TestMethod]
    public void DuplicateTableEntriesAreAccepted()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);
        int size = 1 << TestVariableCount;
        Span<byte> table = material.Memory.Span[..(size * ScalarSize)];

        //Duplicate the first table value into the second slot and point every
        //witness row at it: multiplicity aggregates on the first occurrence.
        table[..ScalarSize].CopyTo(table.Slice(ScalarSize, ScalarSize));
        Span<byte> witness = material.Memory.Span.Slice(size * ScalarSize, size * ScalarSize);
        for(int row = 0; row < size; row++)
        {
            table[..ScalarSize].CopyTo(witness.Slice(row * ScalarSize, ScalarSize));
        }

        using LogUpProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "Duplicate table entries must be harmless: multiplicity weight aggregates on the first occurrence.");
    }


    [TestMethod]
    public void ProvingIsByteForByteDeterministic()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpProof first = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);
        using LogUpProof second = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(first.GetRoundEvaluationBytes().SequenceEqual(second.GetRoundEvaluationBytes()), "Round messages must be deterministic.");
        Assert.IsTrue(first.GetClaimedEvaluationBytes().SequenceEqual(second.GetClaimedEvaluationBytes()), "Claimed evaluations must be deterministic.");
        Assert.IsTrue(first.MultiplicityCommitment.AsReadOnlySpan().SequenceEqual(second.MultiplicityCommitment.AsReadOnlySpan()), "The multiplicity commitment must be deterministic.");
        Assert.IsTrue(first.HelperCommitment.AsReadOnlySpan().SequenceEqual(second.HelperCommitment.AsReadOnlySpan()), "The helper commitment must be deterministic.");
    }


    [TestMethod]
    public void WitnessValueAbsentFromTableIsUnprovable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);
        int size = 1 << TestVariableCount;

        //Replace one witness row with a value that is (with overwhelming
        //probability) outside the table: the fill stream at an unused salt.
        Span<byte> witness = material.Memory.Span.Slice(size * ScalarSize, size * ScalarSize);
        DeterministicScalarFill.FillCanonical(witness.Slice(2 * ScalarSize, ScalarSize), TableFillSalt + OutOfTableFillSaltOffset, Reduce, Curve);

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using LogUpProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);
        }, "A witness value absent from the table makes the statement false; the prover must refuse.");
    }


    [TestMethod]
    public void TamperedRoundMessageIsRejected()
    {
        AssertTamperRejected(mutateRoundByteOffset: ScalarSize + (ScalarSize - 1), mutateClaimedByteOffset: null);
    }


    [TestMethod]
    public void TamperedClaimedEvaluationIsRejected()
    {
        AssertTamperRejected(mutateRoundByteOffset: null, mutateClaimedByteOffset: ScalarSize - 1);
    }


    [TestMethod]
    public void TamperedHelperOpeningIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpProof honest = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);
        using LogUpProof tampered = CloneProof(honest, pcs, pool, mutateRoundByteOffset: null, mutateClaimedByteOffset: null, mutateHelperOpeningLastByte: true);

        Assert.IsFalse(Verify(material, tampered, pcs, pool), "A flipped byte in the helper opening must be rejected.");
    }


    [TestMethod]
    public void SubstitutedTableIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        //A verifier holding a different table must land on different
        //challenges and reject.
        int size = 1 << TestVariableCount;
        using IMemoryOwner<byte> otherTableOwner = pool.Rent(size * ScalarSize);
        Span<byte> otherTable = otherTableOwner.Memory.Span[..(size * ScalarSize)];
        DeterministicScalarFill.FillCanonical(otherTable, TableFillSalt + SubstituteTableFillSaltOffset, Reduce, Curve);

        using FiatShamirTranscript transcript = FreshTranscript();
        bool verified = LogUpVerifier.Verify(
            otherTable, proof, pcs, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MleEvaluate, pool);

        Assert.IsFalse(verified, "A proof bound to one table must not verify against another.");
    }


    [TestMethod]
    public void HostileShapeIsRejectedAtReconstruction()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpProof honest = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        //The caps run before any part is consumed, so passing the honest
        //proof's live parts is safe: ownership transfers only on success. A
        //shape past the caps would otherwise reach masked shifts downstream.
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
        {
            using LogUpProof rejected = LogUpProof.FromParts(
                LogUpProver.MaximumVariableCount + 1, honest.WitnessColumnCount, honest.Curve,
                honest.WitnessCommitments, honest.MultiplicityCommitment, honest.HelperCommitment,
                honest.GetRoundEvaluationBytes(), honest.GetClaimedEvaluationBytes(),
                honest.WitnessOpenings, honest.MultiplicityOpening, honest.HelperOpening, pool);
        }, "A variable count above the operational cap must be rejected at the funnel.");

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
        {
            using LogUpProof rejected = LogUpProof.FromParts(
                honest.VariableCount, LogUpProver.MaximumWitnessColumnCount + 1, honest.Curve,
                honest.WitnessCommitments, honest.MultiplicityCommitment, honest.HelperCommitment,
                honest.GetRoundEvaluationBytes(), honest.GetClaimedEvaluationBytes(),
                honest.WitnessOpenings, honest.MultiplicityOpening, honest.HelperOpening, pool);
        }, "A witness-column count above the operational cap must be rejected at the funnel.");
    }


    [TestMethod]
    public void NonCanonicalRoundBytesAreRejectedAtReconstruction()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpProof honest = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using LogUpProof rejected = CloneProof(honest, pcs, pool, mutateRoundByteOffset: null, mutateClaimedByteOffset: null, mutateHelperOpeningLastByte: false, forceNonCanonicalRoundScalar: true);
        }, "The reconstruction funnel must reject a round scalar at or above the field order.");
    }


    private static void AssertTamperRejected(int? mutateRoundByteOffset, int? mutateClaimedByteOffset)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpProof honest = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);
        using LogUpProof tampered = CloneProof(honest, pcs, pool, mutateRoundByteOffset, mutateClaimedByteOffset, mutateHelperOpeningLastByte: false);

        Assert.IsFalse(Verify(material, tampered, pcs, pool), "A tampered proof component must be rejected.");
    }


    private static LogUpProof Prove(IMemoryOwner<byte> material, int variableCount, int witnessColumnCount, PolynomialCommitmentProvider pcs, BaseMemoryPool pool)
    {
        int size = 1 << variableCount;
        ReadOnlySpan<byte> table = material.Memory.Span[..(size * ScalarSize)];
        ReadOnlySpan<byte> witness = material.Memory.Span.Slice(size * ScalarSize, witnessColumnCount * size * ScalarSize);
        using FiatShamirTranscript transcript = FreshTranscript();

        return LogUpProver.Prove(
            table, witness, variableCount, witnessColumnCount, pcs, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, pool);
    }


    private static bool Verify(IMemoryOwner<byte> material, LogUpProof proof, PolynomialCommitmentProvider pcs, BaseMemoryPool pool)
    {
        int size = 1 << proof.VariableCount;
        ReadOnlySpan<byte> table = material.Memory.Span[..(size * ScalarSize)];
        using FiatShamirTranscript transcript = FreshTranscript();

        return LogUpVerifier.Verify(
            table, proof, pcs, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MleEvaluate, pool);
    }


    //Clones a proof through the public reconstruction funnel, optionally
    //flipping one byte of the round messages, the claimed evaluations, or the
    //helper opening — the three tamper surfaces the verifier must catch.
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the cloned commitments and openings transfers to the proof returned by FromParts.")]
    private static LogUpProof CloneProof(
        LogUpProof source,
        PolynomialCommitmentProvider pcs,
        BaseMemoryPool pool,
        int? mutateRoundByteOffset,
        int? mutateClaimedByteOffset,
        bool mutateHelperOpeningLastByte,
        bool forceNonCanonicalRoundScalar = false)
    {
        int witnessColumnCount = source.WitnessColumnCount;
        var witnessCommitments = new List<PolynomialCommitment>(witnessColumnCount);
        var witnessOpenings = new List<PolynomialOpening>(witnessColumnCount);
        PolynomialCommitment? multiplicityCommitment = null;
        PolynomialCommitment? helperCommitment = null;
        PolynomialOpening? multiplicityOpening = null;
        PolynomialOpening? helperOpening = null;
        try
        {
            for(int column = 0; column < witnessColumnCount; column++)
            {
                witnessCommitments.Add(PolynomialCommitment.FromBytes(source.WitnessCommitments[column].AsReadOnlySpan(), source.Curve, pcs.Scheme, pool));
                witnessOpenings.Add(PolynomialOpening.FromBytes(source.WitnessOpenings[column].AsReadOnlySpan(), source.Curve, pcs.Scheme, pool));
            }

            multiplicityCommitment = PolynomialCommitment.FromBytes(source.MultiplicityCommitment.AsReadOnlySpan(), source.Curve, pcs.Scheme, pool);
            helperCommitment = PolynomialCommitment.FromBytes(source.HelperCommitment.AsReadOnlySpan(), source.Curve, pcs.Scheme, pool);
            multiplicityOpening = PolynomialOpening.FromBytes(source.MultiplicityOpening.AsReadOnlySpan(), source.Curve, pcs.Scheme, pool);

            using IMemoryOwner<byte> helperOpeningBytesOwner = pool.Rent(source.HelperOpening.AsReadOnlySpan().Length);
            Span<byte> helperOpeningBytes = helperOpeningBytesOwner.Memory.Span[..source.HelperOpening.AsReadOnlySpan().Length];
            source.HelperOpening.AsReadOnlySpan().CopyTo(helperOpeningBytes);
            if(mutateHelperOpeningLastByte)
            {
                helperOpeningBytes[^1] ^= 0x01;
            }

            helperOpening = PolynomialOpening.FromBytes(helperOpeningBytes, source.Curve, pcs.Scheme, pool);

            using IMemoryOwner<byte> roundOwner = pool.Rent(source.GetRoundEvaluationBytes().Length);
            Span<byte> roundBytes = roundOwner.Memory.Span[..source.GetRoundEvaluationBytes().Length];
            source.GetRoundEvaluationBytes().CopyTo(roundBytes);
            if(mutateRoundByteOffset is int roundOffset)
            {
                roundBytes[roundOffset] ^= 0x01;
            }

            if(forceNonCanonicalRoundScalar)
            {
                roundBytes[..ScalarSize].Fill(0xFF);
            }

            using IMemoryOwner<byte> claimedOwner = pool.Rent(source.GetClaimedEvaluationBytes().Length);
            Span<byte> claimedBytes = claimedOwner.Memory.Span[..source.GetClaimedEvaluationBytes().Length];
            source.GetClaimedEvaluationBytes().CopyTo(claimedBytes);
            if(mutateClaimedByteOffset is int claimedOffset)
            {
                claimedBytes[claimedOffset] ^= 0x01;
            }

            return LogUpProof.FromParts(
                source.VariableCount,
                witnessColumnCount,
                source.Curve,
                witnessCommitments,
                multiplicityCommitment,
                helperCommitment,
                roundBytes,
                claimedBytes,
                witnessOpenings,
                multiplicityOpening,
                helperOpening,
                pool);
        }
        catch
        {
            //FromParts transfers ownership only on success; a validation throw
            //leaves the cloned parts with this helper to release.
            foreach(PolynomialCommitment commitment in witnessCommitments)
            {
                commitment.Dispose();
            }
            foreach(PolynomialOpening opening in witnessOpenings)
            {
                opening.Dispose();
            }
            multiplicityCommitment?.Dispose();
            helperCommitment?.Dispose();
            multiplicityOpening?.Dispose();
            helperOpening?.Dispose();
            throw;
        }
    }


    //Rents one buffer holding [table | witness columns]: the table is a fill
    //stream of distinct canonical scalars, every witness entry a table entry
    //chosen by a fixed stride so all columns and rows differ.
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
        ReadOnlySpan<byte> codeSeed = "veridical.logup.test.basefold.code.v1"u8;

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

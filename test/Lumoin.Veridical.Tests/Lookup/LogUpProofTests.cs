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
    /// <summary>The BLAKE3 Fiat–Shamir hash delegate this test's transcripts and commitment providers share.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    /// <summary>The BLAKE3 Fiat–Shamir squeeze delegate this test's transcripts and commitment providers share.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    /// <summary>The BLS12-381 scalar-field reduction delegate, used to bring fill-stream and tampered bytes back into canonical range.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    /// <summary>The BLS12-381 scalar addition delegate the LogUp prover and verifier use.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    /// <summary>The BLS12-381 scalar subtraction delegate the LogUp prover and verifier use.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    /// <summary>The BLS12-381 scalar multiplication delegate the LogUp prover and verifier use.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    /// <summary>The BLS12-381 scalar inversion delegate the LogUp prover and verifier use.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    /// <summary>The BLS12-381 hash-to-scalar delegate the BaseFold commitment provider uses to derive challenges.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    /// <summary>The multilinear-extension evaluation delegate the LogUp verifier uses to check the round claims.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    /// <summary>The two-to-one Merkle compression function, delegated to <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;
    /// <summary>The BLS12-381 G1 point addition delegate the Hyrax provider's Pedersen commitments use.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    /// <summary>The BLS12-381 G1 scalar multiplication delegate the Hyrax provider's Pedersen commitments use.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    /// <summary>The BLS12-381 G1 multi-scalar multiplication delegate the Hyrax provider uses to combine commitment terms.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    /// <summary>The BLS12-381 G1 on-curve check the Hyrax provider uses to validate commitment key points.</summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();
    /// <summary>The BLS12-381 G1 prime-order-subgroup check the Hyrax provider uses to validate commitment key points.</summary>
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();
    /// <summary>The BLS12-381 G1 hash-to-curve delegate used to derive the Hyrax commitment key's generator points.</summary>
    private static G1HashToCurveDelegate G1HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();

    /// <summary>The byte width of a canonical BLS12-381 scalar.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The byte width of a BLAKE3 digest, as used by the Merkle and Ligero commitments in these tests.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The number of Ligero opened columns (query repetitions) these round-trip fixtures use: eight keeps the fixtures fast, since soundness-margin accounting is the concern of the dedicated soundness tests, not these round-trips.</summary>
    private const int TestQueryCount = 8;

    /// <summary>The number of lookup variables (eight rows) these round-trip fixtures use: enough to exercise multi-round folding while keeping the degree-(M+3) round computation cheap.</summary>
    private const int TestVariableCount = 3;

    /// <summary>The Fiat–Shamir domain-separation label for every transcript this test class creates.</summary>
    private const string TranscriptDomain = "veridical.logup.test.v1";

    /// <summary>The deterministic fill-stream salt for the lookup table, chosen independently and reproducibly from the witness streams.</summary>
    private const int TableFillSalt = 811;

    /// <summary>Added to <see cref="TableFillSalt"/> to select a fill stream disjoint from the table's, producing a witness value that is (with overwhelming probability) absent from the table.</summary>
    private const int OutOfTableFillSaltOffset = 997;

    /// <summary>Added to <see cref="TableFillSalt"/> to select a fill stream disjoint from the table's, producing a substitute table a proof must not verify against.</summary>
    private const int SubstituteTableFillSaltOffset = 499;

    /// <summary>The per-row stride used to map each witness row onto a table position; coprime to the table size so every row lands on a distinct entry.</summary>
    private const int WitnessRowStride = 5;

    /// <summary>The per-column stride used to map each witness column onto a table position; coprime to the table size so every column's rows differ from the others'.</summary>
    private const int WitnessColumnStride = 3;

    /// <summary>The BLS12-381 curve parameters used throughout these tests.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;

    /// <summary>The seed for the Hyrax Pedersen blinding-factor stream, domain-separated from the transcript label so it is independent of the Fiat–Shamir challenge stream Hyrax also draws from.</summary>
    private static byte[] HyraxBlindSeed { get; } = Encoding.UTF8.GetBytes("veridical.logup.test.hyrax.blind.v1");


    /// <summary>Verifies that an honest single-column LogUp proof verifies over the Ligero commitment provider.</summary>
    [TestMethod]
    public void SingleColumnLookupRoundTripsThroughLigero()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "An honest single-column LogUp proof must verify over Ligero.");
    }


    /// <summary>Verifies that an honest three-column LogUp proof verifies over the Ligero commitment provider.</summary>
    [TestMethod]
    public void ThreeColumnLookupRoundTripsThroughLigero()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 3, pool);

        using LogUpProof proof = Prove(material, TestVariableCount, witnessColumnCount: 3, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "An honest three-column LogUp proof must verify over Ligero.");
    }


    /// <summary>Verifies that an honest single-column LogUp proof verifies over the BaseFold commitment provider, showing the argument does not depend on which provider backs it.</summary>
    [TestMethod]
    public void SingleColumnLookupRoundTripsThroughBaseFold()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildBaseFoldProvider(pool);
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "An honest LogUp proof must verify over BaseFold — the argument is provider-generic.");
    }


    /// <summary>Verifies that an honest LogUp proof verifies over the Hyrax commitment provider, the homomorphic Pedersen-family backend, showing the argument is provider-generic across hash-based and homomorphic schemes alike.</summary>
    [TestMethod]
    public void SingleColumnLookupRoundTripsThroughHyrax()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildHyraxProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "An honest LogUp proof must verify over Hyrax — the argument is provider-generic and Hyrax is the homomorphic Pedersen-family backend.");
    }


    /// <summary>Verifies that a table with a duplicated entry, and every witness row pointed at it, still proves and verifies: multiplicity weight aggregates on the entry's first occurrence.</summary>
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


    /// <summary>Verifies that proving the same statement twice produces byte-identical round messages, claimed evaluations, and multiplicity/helper commitments.</summary>
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


    /// <summary>Verifies that the prover throws when a witness row holds a value not present in the table, since the lookup statement is then false.</summary>
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


    /// <summary>Verifies that flipping a byte inside the round messages causes verification to fail.</summary>
    [TestMethod]
    public void TamperedRoundMessageIsRejected()
    {
        AssertTamperRejected(mutateRoundByteOffset: ScalarSize + (ScalarSize - 1), mutateClaimedByteOffset: null);
    }


    /// <summary>Verifies that flipping a byte inside the claimed evaluations causes verification to fail.</summary>
    [TestMethod]
    public void TamperedClaimedEvaluationIsRejected()
    {
        AssertTamperRejected(mutateRoundByteOffset: null, mutateClaimedByteOffset: ScalarSize - 1);
    }


    /// <summary>Verifies that flipping a byte inside the helper opening causes verification to fail.</summary>
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


    /// <summary>Verifies that a proof bound to one table does not verify against a different table, since the verifier's own table drives the challenges the proof must match.</summary>
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


    /// <summary>Verifies that <see cref="LogUpProof"/>'s reconstruction funnel rejects a variable count or witness-column count above its operational cap before any part is consumed.</summary>
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


    /// <summary>Verifies that the reconstruction funnel rejects a round scalar at or above the field order.</summary>
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


    /// <summary>Proves an honest statement, clones the proof with an optional single-byte flip at the given round or claimed-evaluation offset, and asserts the tampered clone fails verification.</summary>
    private static void AssertTamperRejected(int? mutateRoundByteOffset, int? mutateClaimedByteOffset)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpProof honest = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);
        using LogUpProof tampered = CloneProof(honest, pcs, pool, mutateRoundByteOffset, mutateClaimedByteOffset, mutateHelperOpeningLastByte: false);

        Assert.IsFalse(Verify(material, tampered, pcs, pool), "A tampered proof component must be rejected.");
    }


    /// <summary>Builds a fresh transcript and produces a LogUp proof for the given material's table and witness columns.</summary>
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


    /// <summary>Builds a fresh transcript and verifies the given LogUp proof against the material's table.</summary>
    private static bool Verify(IMemoryOwner<byte> material, LogUpProof proof, PolynomialCommitmentProvider pcs, BaseMemoryPool pool)
    {
        int size = 1 << proof.VariableCount;
        ReadOnlySpan<byte> table = material.Memory.Span[..(size * ScalarSize)];
        using FiatShamirTranscript transcript = FreshTranscript();

        return LogUpVerifier.Verify(
            table, proof, pcs, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MleEvaluate, pool);
    }


    /// <summary>Clones a proof through the public reconstruction funnel, optionally flipping one byte of the round messages, the claimed evaluations, or the helper opening — the three tamper surfaces the verifier must catch — or forcing a non-canonical round scalar.</summary>
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


    /// <summary>Rents one buffer holding <c>[table | witness columns]</c>: the table is a fill stream of distinct canonical scalars, and every witness entry is a table entry chosen by a fixed stride so all columns and rows differ.</summary>
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


    /// <summary>Builds the Ligero commitment provider used by most of these round-trip and tamper tests.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The Ligero provider holds no disposable key material; callers dispose the provider itself.")]
    private static PolynomialCommitmentProvider BuildLigeroProvider()
    {
        return LigeroPolynomialCommitmentScheme.Create(
            Curve, TestQueryCount, Add, Subtract, Multiply, Invert, Reduce,
            Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3, DigestSizeBytes);
    }


    /// <summary>Builds the BaseFold commitment provider, seeded with this test class's own code seed, over the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    private static PolynomialCommitmentProvider BuildBaseFoldProvider(BaseMemoryPool pool)
    {
        ReadOnlySpan<byte> codeSeed = "veridical.logup.test.basefold.code.v1"u8;

        return BaseFoldPolynomialCommitmentScheme.Create(
            codeSeed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce,
            Add, Subtract, Multiply, Invert, HashToScalar, pool, DigestSizeBytes);
    }


    /// <summary>Builds the Hyrax commitment provider: derives a Pedersen commitment key sized for <see cref="TestVariableCount"/> and a deterministic blinding-randomness source from <see cref="HyraxBlindSeed"/>.</summary>
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


    /// <summary>Creates a new Fiat–Shamir transcript domain-separated by <see cref="TranscriptDomain"/>.</summary>
    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>Computes the two-to-one Merkle compression of <paramref name="left"/> and <paramref name="right"/> using BLAKE3.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}

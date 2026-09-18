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
    /// <summary>The production BLAKE3 Fiat-Shamir hash delegate every provider's and every proof's transcript is built from.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The production BLAKE3 Fiat-Shamir squeeze delegate every transcript in this class draws challenges through.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The BigInteger reference scalar-reduction delegate for the BLS12-381 scalar field.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The validated BLS12-381 scalar addition delegate this test's lookup arithmetic runs on.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The validated BLS12-381 scalar subtraction delegate this test's lookup arithmetic runs on.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The validated BLS12-381 scalar multiplication delegate this test's lookup arithmetic runs on.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The validated BLS12-381 scalar inversion delegate the LogUp-GKR verifier's fraction arithmetic runs on.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BigInteger reference hash-to-scalar delegate the BaseFold provider derives its challenges through.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    /// <summary>The BigInteger reference multilinear-extension evaluation delegate the prover and verifier evaluate claims with.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The two-to-one Merkle hash delegate backing the Ligero and BaseFold providers, implemented with production BLAKE3 through <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The BigInteger reference G1 point-addition delegate for BLS12-381, used by the Hyrax provider.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();

    /// <summary>The BigInteger reference G1 scalar-multiplication delegate for BLS12-381, used by the Hyrax provider.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>The validated BLS12-381 G1 multi-scalar-multiplication delegate the Hyrax provider's commitments run on.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;

    /// <summary>The BigInteger reference on-curve check the Hyrax provider validates received points with.</summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();

    /// <summary>The BigInteger reference prime-order-subgroup check the Hyrax provider validates received points with.</summary>
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();

    /// <summary>The BigInteger reference hash-to-curve delegate the Hyrax commitment key derives its generators with.</summary>
    private static G1HashToCurveDelegate G1HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();

    /// <summary>The in-memory scalar width in bytes, matching <see cref="Scalar.SizeBytes"/>, used for every table, witness and commitment stride in this class.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The Merkle digest width the Ligero and BaseFold providers and hash delegate use, taken from the library's default Merkle parameters.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The opened-column count every provider in this class uses; small enough to keep the fixtures fast, since soundness margins are exercised elsewhere.</summary>
    private const int TestQueryCount = 8;

    /// <summary>The row-variable count for every fixture in this class: eight rows give a four-to-five-variable fraction tree, exercising multi-round layers while staying cheap.</summary>
    private const int TestVariableCount = 3;

    /// <summary>The Fiat-Shamir domain-separation label for this test's transcript, distinguishing it from every other transcript domain in the suite.</summary>
    private const string TranscriptDomain = "veridical.logup.gkr.test.v1";

    /// <summary>The salt filling the lookup table's scalars; distinct from <see cref="OutOfTableFillSaltOffset"/> so the two fills are independent and reproducible.</summary>
    private const int TableFillSalt = 823;

    /// <summary>The offset added to <see cref="TableFillSalt"/> to fill a scalar guaranteed absent from the table, for the unprovable-witness test.</summary>
    private const int OutOfTableFillSaltOffset = 991;

    /// <summary>A stride coprime to the table size, walking each witness row onto a distinct table position.</summary>
    private const int WitnessRowStride = 5;

    /// <summary>A stride coprime to the table size, offsetting each witness column's walk from every other column's.</summary>
    private const int WitnessColumnStride = 3;

    /// <summary>The BLS12-381 curve parameter set this test's arithmetic and commitments run over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;

    /// <summary>The seed for the Hyrax provider's Pedersen blinding randomness, domain-separated from the transcript label so the blinding stream is independent of the Fiat-Shamir stream.</summary>
    private static byte[] HyraxBlindSeed { get; } = Encoding.UTF8.GetBytes("veridical.logup.gkr.test.hyrax.blind.v1");


    /// <summary>Verifies that an honest single-column LogUp-GKR proof accepts against the Ligero provider.</summary>
    [TestMethod]
    public void SingleColumnLookupRoundTripsThroughLigero()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpGkrProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "An honest single-column LogUp-GKR proof must verify over Ligero.");
    }


    /// <summary>Verifies that a two-column lookup, which leaves one of the four selector slots as neutral 0/1 padding, still round-trips.</summary>
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


    /// <summary>Verifies that a three-column lookup, which fills the four-slot selector cube exactly with no padding, still round-trips.</summary>
    [TestMethod]
    public void ThreeColumnLookupFillsTheSelectorCube()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 3, pool);

        using LogUpGkrProof proof = Prove(material, TestVariableCount, witnessColumnCount: 3, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "Three witness columns fill the four-slot selector cube exactly and must round-trip.");
    }


    /// <summary>Verifies that an honest single-column LogUp-GKR proof accepts against the BaseFold provider, since the argument is provider-generic.</summary>
    [TestMethod]
    public void SingleColumnLookupRoundTripsThroughBaseFold()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildBaseFoldProvider(pool);
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpGkrProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "An honest LogUp-GKR proof must verify over BaseFold — the argument is provider-generic.");
    }


    /// <summary>Verifies that an honest single-column LogUp-GKR proof accepts against the Hyrax provider, the homomorphic Pedersen-family backend.</summary>
    [TestMethod]
    public void SingleColumnLookupRoundTripsThroughHyrax()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildHyraxProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpGkrProof proof = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);

        Assert.IsTrue(Verify(material, proof, pcs, pool), "An honest LogUp-GKR proof must verify over Hyrax — the homomorphic Pedersen-family backend.");
    }


    /// <summary>Verifies that a table with a duplicated entry is harmless: the duplicate's multiplicity weight aggregates onto its first occurrence, and the proof still round-trips.</summary>
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


    /// <summary>Verifies that proving the same material twice yields byte-identical root values, layer messages and claimed evaluations.</summary>
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


    /// <summary>Verifies that the prover refuses a witness value not present in the table, since that makes the lookup statement false.</summary>
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


    /// <summary>Verifies that flipping a byte of the proof's root values makes verification reject.</summary>
    [TestMethod]
    public void TamperedRootValueIsRejected()
    {
        AssertTamperRejected(mutateRootByteOffset: ScalarSize - 1, mutateLayerByteOffset: null, mutateClaimedByteOffset: null);
    }


    /// <summary>Verifies that flipping a byte of the proof's layer messages makes verification reject.</summary>
    [TestMethod]
    public void TamperedLayerMessageIsRejected()
    {
        AssertTamperRejected(mutateRootByteOffset: null, mutateLayerByteOffset: ScalarSize - 1, mutateClaimedByteOffset: null);
    }


    /// <summary>Verifies that flipping a byte of the proof's claimed evaluations makes verification reject.</summary>
    [TestMethod]
    public void TamperedClaimedEvaluationIsRejected()
    {
        AssertTamperRejected(mutateRootByteOffset: null, mutateLayerByteOffset: null, mutateClaimedByteOffset: ScalarSize - 1);
    }


    /// <summary>Verifies that a row-variable count whose fraction-tree total exceeds the reconstruction cap is rejected before any proof part is consumed.</summary>
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


    /// <summary>Verifies that the reconstruction funnel rejects a root scalar at or above the field order.</summary>
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


    /// <summary>Proves honestly, clones the proof with one selected byte flipped, and asserts the tampered clone fails verification.</summary>
    /// <param name="mutateRootByteOffset">The byte offset to flip within the root values, or <see langword="null"/> to leave them untouched.</param>
    /// <param name="mutateLayerByteOffset">The byte offset to flip within the layer messages, or <see langword="null"/> to leave them untouched.</param>
    /// <param name="mutateClaimedByteOffset">The byte offset to flip within the claimed evaluations, or <see langword="null"/> to leave them untouched.</param>
    private static void AssertTamperRejected(int? mutateRootByteOffset, int? mutateLayerByteOffset, int? mutateClaimedByteOffset)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider pcs = BuildLigeroProvider();
        using IMemoryOwner<byte> material = BuildLookupMaterial(TestVariableCount, witnessColumnCount: 1, pool);

        using LogUpGkrProof honest = Prove(material, TestVariableCount, witnessColumnCount: 1, pcs, pool);
        using LogUpGkrProof tampered = CloneProof(honest, pcs, pool, mutateRootByteOffset, mutateLayerByteOffset, mutateClaimedByteOffset);

        Assert.IsFalse(Verify(material, tampered, pcs, pool), "A tampered proof component must be rejected.");
    }


    /// <summary>Proves a LogUp-GKR lookup over the given table/witness material with the supplied commitment provider.</summary>
    /// <param name="material">The rented buffer holding the table followed by the witness columns.</param>
    /// <param name="variableCount">The row-variable count sizing the table and witness columns.</param>
    /// <param name="witnessColumnCount">The number of witness columns packed after the table in <paramref name="material"/>.</param>
    /// <param name="pcs">The commitment provider backing the witness and multiplicity commitments.</param>
    /// <param name="pool">The pool the prover rents its working buffers from.</param>
    /// <returns>The resulting LogUp-GKR proof; the caller disposes it.</returns>
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


    /// <summary>Verifies a LogUp-GKR proof against the table half of the supplied material.</summary>
    /// <param name="material">The rented buffer whose leading table bytes the verifier checks the proof against.</param>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="pcs">The commitment provider the proof's commitments and openings are checked under.</param>
    /// <param name="pool">The pool the verifier rents its working buffers from.</param>
    /// <returns><see langword="true"/> when the proof verifies.</returns>
    private static bool Verify(IMemoryOwner<byte> material, LogUpGkrProof proof, PolynomialCommitmentProvider pcs, BaseMemoryPool pool)
    {
        int size = 1 << proof.VariableCount;
        ReadOnlySpan<byte> table = material.Memory.Span[..(size * ScalarSize)];
        using FiatShamirTranscript transcript = FreshTranscript();

        return LogUpGkrVerifier.Verify(
            table, proof, pcs, transcript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MleEvaluate, pool);
    }


    /// <summary>
    /// Clones a proof through the public reconstruction funnel <see cref="LogUpGkrProof.FromParts"/>, optionally
    /// flipping one byte of the root values, the layer messages, or the claimed evaluations, or forcing the
    /// root scalar to a non-canonical bit pattern.
    /// </summary>
    /// <param name="source">The proof to clone.</param>
    /// <param name="pcs">The commitment provider the cloned commitments and openings are reconstructed under.</param>
    /// <param name="pool">The pool the clone rents its working buffers from.</param>
    /// <param name="mutateRootByteOffset">The byte offset to flip within the root values, or <see langword="null"/> to leave them untouched.</param>
    /// <param name="mutateLayerByteOffset">The byte offset to flip within the layer messages, or <see langword="null"/> to leave them untouched.</param>
    /// <param name="mutateClaimedByteOffset">The byte offset to flip within the claimed evaluations, or <see langword="null"/> to leave them untouched.</param>
    /// <param name="forceNonCanonicalRootScalar">When <see langword="true"/>, overwrites the first root scalar with an all-<c>0xFF</c> pattern at or above the field order.</param>
    /// <returns>The cloned (and possibly tampered) proof; the caller disposes it.</returns>
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


    /// <summary>Builds a deterministic table filled with <see cref="TableFillSalt"/> and one or more witness columns, each a strided permutation of the table's rows.</summary>
    /// <param name="variableCount">The row-variable count sizing the table and each witness column.</param>
    /// <param name="witnessColumnCount">The number of witness columns to build after the table.</param>
    /// <param name="pool">The pool the returned buffer is rented from.</param>
    /// <returns>A rented buffer holding the table followed by <paramref name="witnessColumnCount"/> witness columns; the caller disposes it.</returns>
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


    /// <summary>Builds the Ligero-backed commitment provider shared by most tests in this class.</summary>
    /// <returns>A new Ligero provider; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "The Ligero provider holds no disposable key material; callers dispose the provider itself.")]
    private static PolynomialCommitmentProvider BuildLigeroProvider()
    {
        return LigeroPolynomialCommitmentScheme.Create(
            Curve, TestQueryCount, Add, Subtract, Multiply, Invert, Reduce,
            Hash, Squeeze, Hash, Merkle, WellKnownHashAlgorithms.Blake3, DigestSizeBytes);
    }


    /// <summary>Builds the commitment provider using the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    private static PolynomialCommitmentProvider BuildBaseFoldProvider(BaseMemoryPool pool)
    {
        ReadOnlySpan<byte> codeSeed = "veridical.logup.gkr.test.basefold.code.v1"u8;

        return BaseFoldPolynomialCommitmentScheme.Create(
            codeSeed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce,
            Add, Subtract, Multiply, Invert, HashToScalar, pool, DigestSizeBytes);
    }


    /// <summary>Builds the Hyrax-backed commitment provider, deriving a fresh Pedersen commitment key sized for <see cref="TestVariableCount"/>.</summary>
    /// <returns>A new Hyrax provider owning its derived key; the caller disposes it.</returns>
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


    /// <summary>Creates a fresh Fiat-Shamir transcript under this test's domain label, ready to absorb a prove or verify run.</summary>
    /// <returns>A new transcript backed by the shared pool.</returns>
    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(TranscriptDomain),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>Concatenates two digests and hashes them with production BLAKE3, the two-to-one compression the Merkle-backed providers in this class use.</summary>
    /// <param name="left">The left digest, placed first in the concatenation.</param>
    /// <param name="right">The right digest, placed after <paramref name="left"/>.</param>
    /// <param name="output">The buffer receiving the combined digest.</param>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}

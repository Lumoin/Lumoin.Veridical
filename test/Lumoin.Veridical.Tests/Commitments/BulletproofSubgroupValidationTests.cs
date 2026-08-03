using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// Prime-order-subgroup screening tests for the four Bulletproofs range-proof
/// verify surfaces (<see cref="BulletproofRangeVerifier"/>,
/// <see cref="AggregatedBulletproofRangeVerifier"/>,
/// <see cref="BatchBulletproofRangeVerifier"/>,
/// <see cref="BatchAggregatedBulletproofRangeVerifier"/>): every
/// prover-supplied G1 point (the value commitments, <c>A</c>, <c>S</c>,
/// <c>T1</c>, <c>T2</c>, and every IPA round point) must be rejected before
/// any group arithmetic runs when it lies on the curve but outside the
/// prime-order subgroup. BN254 has cofactor 1, so no wrong-subgroup probe
/// exists there; these tests are BLS12-381 only.
/// </summary>
[TestClass]
internal sealed class BulletproofSubgroupValidationTests
{
    private const string TranscriptDomain = "veridical.test.bulletproofs.subgroup.range.v1";
    private const string BatchDomain = "veridical.test.bulletproofs.subgroup.range.batch.weights.v1";
    private const string KeySeed = "veridical.test.bulletproofs.subgroup.range.key.v1";

    //Keeps the subgroup-screening scalar multiplications cheap: 3 IPA rounds
    //at width 8 rather than the 6+ rounds a realistic width would cost.
    private const int SingleBitWidth = 8;

    //Per-value width for the aggregated and batch-aggregated fixtures.
    private const int AggregatedBitWidth = 8;

    //Minimal aggregation that still exercises the per-value z-power binding.
    private const int AggregatedValueCount = 2;

    //Minimal batch that still exercises whole-batch rejection from one bad proof.
    private const int BatchProofCount = 2;

    private const int ScalarSize = Scalar.SizeBytes;

    //Mirrors RangeProof's own layout constants so offsets are derived rather
    //than duplicated as independent magic numbers.
    private const int LeadingPointCount = 4;
    private const int MidScalarCount = 3;

    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;

    //Pre-calculated wrong-subgroup probe: the BLS12-381 G1 point with x = 0
    //(y^2 = 4, roots +-2) is on the curve but outside the r-order subgroup:
    //[r]P != O while [h1 * r]P == O for the G1 cofactor h1. ZCash-convention
    //encoding: compression flag 0x80 plus y-parity flag 0x20 because the
    //encoded root y = p - 2 is the lexicographically larger one; the x bytes
    //are all zero. Re-derive by walking x upward from 0 and taking the first
    //x whose curve RHS is a quadratic residue and whose point fails [r]P == O.
    private static byte[] WrongSubgroupG1Compressed { get; } = Convert.FromHexString(
        "a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");


    //Which prover-supplied point inside a proof's wire bytes is spliced; the
    //value commitment is not represented here because it lives in a separate
    //buffer, not inside the proof's own bytes.
    internal enum ProofSlot
    {
        BitCommitmentA,
        BlindingCommitmentS,
        PolynomialCommitmentT1,
        PolynomialCommitmentT2,
        IpaRoundZeroL,
        IpaRoundLastR
    }


    /// <summary>
    /// Pins the wrong-subgroup literal itself: on-curve true, prime-order
    /// membership false. Without this pin every rejection test below could
    /// pass for the wrong reason (an off-curve rejection rather than a
    /// subgroup rejection).
    /// </summary>
    [TestMethod]
    public void ProbeIsOnCurveButOutsideSubgroup()
    {
        Assert.IsTrue(G1IsOnCurve(WrongSubgroupG1Compressed, Curve), "The wrong-subgroup probe must lie on the curve.");
        Assert.IsFalse(G1IsInPrimeOrderSubgroup(WrongSubgroupG1Compressed, Curve), "The wrong-subgroup probe must lie outside the prime-order subgroup.");
    }


    /// <summary>
    /// <see cref="BulletproofRangeVerifier.Verify"/> must reject a value
    /// commitment outside the prime-order subgroup before any multi-scalar
    /// multiplication or scalar multiplication runs.
    /// </summary>
    [TestMethod]
    public void VerifyRejectsWrongSubgroupValueCommitment()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(SingleBitWidth, KeySeed, Curve, HashToCurve, pool);
        (RangeProof proof, IMemoryOwner<byte> commitmentOwner) = ProveSingleValue(key, value: 201UL, pool, blindingSeed: 11, proverSeed: 12);
        using IMemoryOwner<byte> ownedCommitment = commitmentOwner;
        using(proof)
        {
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
            Span<byte> tamperedCommitment = commitmentOwner.Memory.Span[..g1Size];
            WrongSubgroupG1Compressed.CopyTo(tamperedCommitment);

            (bool verified, bool subgroupChecked, bool msmCalled, bool scalarMulCalled) = VerifySingleWithRecording(key, tamperedCommitment, proof, pool);

            Assert.IsFalse(verified, "Verify must reject a value commitment outside the prime-order subgroup.");
            Assert.IsTrue(subgroupChecked, "The subgroup delegate must be consulted for the tampered value commitment.");
            Assert.IsFalse(msmCalled, "Rejection of the value commitment must happen before any multi-scalar multiplication.");
            Assert.IsFalse(scalarMulCalled, "Rejection of the value commitment must happen before any scalar multiplication.");
        }
    }


    /// <summary>
    /// <see cref="BulletproofRangeVerifier.Verify"/> must reject every
    /// prover-supplied point inside the proof's own wire bytes — the bit and
    /// blinding commitments, the two polynomial commitments, and both ends of
    /// the IPA round section — before any multi-scalar multiplication or
    /// scalar multiplication runs.
    /// </summary>
    [TestMethod]
    [DataRow(ProofSlot.BitCommitmentA)]
    [DataRow(ProofSlot.BlindingCommitmentS)]
    [DataRow(ProofSlot.PolynomialCommitmentT1)]
    [DataRow(ProofSlot.PolynomialCommitmentT2)]
    [DataRow(ProofSlot.IpaRoundZeroL)]
    [DataRow(ProofSlot.IpaRoundLastR)]
    public void VerifyRejectsWrongSubgroupProofPoint(ProofSlot slot)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(SingleBitWidth, KeySeed, Curve, HashToCurve, pool);
        (RangeProof proof, IMemoryOwner<byte> commitmentOwner) = ProveSingleValue(key, value: 173UL, pool, blindingSeed: 21, proverSeed: 22);
        using IMemoryOwner<byte> ownedCommitment = commitmentOwner;
        using(proof)
        {
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
            ReadOnlySpan<byte> commitment = commitmentOwner.Memory.Span[..g1Size];
            int offset = GetProofPointOffset(slot, proof, g1Size);
            using RangeProof tampered = SpliceProofPoint(proof, offset, g1Size, pool);

            (bool verified, bool subgroupChecked, bool msmCalled, bool scalarMulCalled) = VerifySingleWithRecording(key, commitment, tampered, pool);

            Assert.IsFalse(verified, $"Verify must reject a proof whose {slot} point lies outside the prime-order subgroup.");
            Assert.IsTrue(subgroupChecked, $"The subgroup delegate must be consulted for the tampered {slot} point.");
            Assert.IsFalse(msmCalled, $"Rejection of the {slot} point must happen before any multi-scalar multiplication.");
            Assert.IsFalse(scalarMulCalled, $"Rejection of the {slot} point must happen before any scalar multiplication.");
        }
    }


    /// <summary>
    /// A positive control: the same instrumented delegates over an untouched
    /// proof must accept, proving the screen does not reject everything and
    /// that the recording harness is wired correctly.
    /// </summary>
    [TestMethod]
    public void UntamperedProofPassesScreeningAndVerifies()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(SingleBitWidth, KeySeed, Curve, HashToCurve, pool);
        (RangeProof proof, IMemoryOwner<byte> commitmentOwner) = ProveSingleValue(key, value: 99UL, pool, blindingSeed: 31, proverSeed: 32);
        using IMemoryOwner<byte> ownedCommitment = commitmentOwner;
        using(proof)
        {
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
            ReadOnlySpan<byte> commitment = commitmentOwner.Memory.Span[..g1Size];

            (bool verified, bool subgroupChecked, bool msmCalled, bool scalarMulCalled) = VerifySingleWithRecording(key, commitment, proof, pool);

            Assert.IsTrue(verified, "An untampered proof must verify.");
            Assert.IsTrue(subgroupChecked, "The subgroup delegate must be consulted even when every point is valid.");
            Assert.IsTrue(msmCalled, "A verification that passes screening must reach the multi-scalar multiplication.");
            Assert.IsTrue(scalarMulCalled, "A verification that passes screening must reach the scaled-H-family scalar multiplication.");
        }
    }


    /// <summary>
    /// <see cref="AggregatedBulletproofRangeVerifier.Verify"/> must reject a
    /// wrong-subgroup value commitment among the aggregated proof's <c>m</c>
    /// commitments before any multi-scalar multiplication runs.
    /// </summary>
    [TestMethod]
    public void AggregatedVerifyRejectsWrongSubgroupValueCommitment()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(AggregatedBitWidth * AggregatedValueCount, KeySeed, Curve, HashToCurve, pool);
        ulong[] values = [12UL, 200UL];
        (RangeProof proof, IMemoryOwner<byte> commitmentsOwner) = ProveAggregatedValues(key, values, pool, blindingSeedBase: 41, proverSeed: 42);
        using IMemoryOwner<byte> ownedCommitments = commitmentsOwner;
        using(proof)
        {
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
            Span<byte> commitments = commitmentsOwner.Memory.Span[..(values.Length * g1Size)];
            WrongSubgroupG1Compressed.CopyTo(commitments[..g1Size]);

            bool subgroupChecked = false;
            bool msmCalled = false;
            G1IsInPrimeOrderSubgroupDelegate recordingSubgroup = (point, curve) =>
            {
                subgroupChecked = true;

                return G1IsInPrimeOrderSubgroup(point, curve);
            };
            G1MultiScalarMultiplyDelegate recordingMsm = (points, scalars, count, result, curve) =>
            {
                msmCalled = true;
                G1Msm(points, scalars, count, result, curve);
            };

            using FiatShamirTranscript verifierTx = NewTranscript(TranscriptDomain);
            bool verified = AggregatedBulletproofRangeVerifier.Verify(
                key, AggregatedBitWidth, values.Length, commitments, proof, verifierTx,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
                G1Add, G1ScalarMul, recordingMsm, G1IsOnCurve, recordingSubgroup, pool);

            Assert.IsFalse(verified, "AggregatedBulletproofRangeVerifier.Verify must reject a wrong-subgroup value commitment.");
            Assert.IsTrue(subgroupChecked, "The subgroup delegate must be consulted for the tampered value commitment.");
            Assert.IsFalse(msmCalled, "Rejection of the value commitment must happen before any multi-scalar multiplication.");
        }
    }


    /// <summary>
    /// <see cref="AggregatedBulletproofRangeVerifier.Verify"/> must reject a
    /// wrong-subgroup <c>T1</c> polynomial commitment before any multi-scalar
    /// multiplication runs.
    /// </summary>
    [TestMethod]
    public void AggregatedVerifyRejectsWrongSubgroupPolynomialCommitmentT1()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(AggregatedBitWidth * AggregatedValueCount, KeySeed, Curve, HashToCurve, pool);
        ulong[] values = [7UL, 250UL];
        (RangeProof proof, IMemoryOwner<byte> commitmentsOwner) = ProveAggregatedValues(key, values, pool, blindingSeedBase: 51, proverSeed: 52);
        using IMemoryOwner<byte> ownedCommitments = commitmentsOwner;
        using(proof)
        {
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
            ReadOnlySpan<byte> commitments = commitmentsOwner.Memory.Span[..(values.Length * g1Size)];
            int offset = GetProofPointOffset(ProofSlot.PolynomialCommitmentT1, proof, g1Size);
            using RangeProof tampered = SpliceProofPoint(proof, offset, g1Size, pool);

            bool subgroupChecked = false;
            bool msmCalled = false;
            G1IsInPrimeOrderSubgroupDelegate recordingSubgroup = (point, curve) =>
            {
                subgroupChecked = true;

                return G1IsInPrimeOrderSubgroup(point, curve);
            };
            G1MultiScalarMultiplyDelegate recordingMsm = (points, scalars, count, result, curve) =>
            {
                msmCalled = true;
                G1Msm(points, scalars, count, result, curve);
            };

            using FiatShamirTranscript verifierTx = NewTranscript(TranscriptDomain);
            bool verified = AggregatedBulletproofRangeVerifier.Verify(
                key, AggregatedBitWidth, values.Length, commitments, tampered, verifierTx,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
                G1Add, G1ScalarMul, recordingMsm, G1IsOnCurve, recordingSubgroup, pool);

            Assert.IsFalse(verified, "AggregatedBulletproofRangeVerifier.Verify must reject a wrong-subgroup T1.");
            Assert.IsTrue(subgroupChecked, "The subgroup delegate must be consulted for the tampered T1 point.");
            Assert.IsFalse(msmCalled, "Rejection of the T1 point must happen before any multi-scalar multiplication.");
        }
    }


    /// <summary>
    /// <see cref="BatchBulletproofRangeVerifier.Verify"/> must reject the
    /// whole batch when one proof's blinding commitment <c>S</c> lies outside
    /// the prime-order subgroup, before the combined multi-scalar
    /// multiplication runs.
    /// </summary>
    [TestMethod]
    public void BatchVerifyRejectsWrongSubgroupProofPoint()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(SingleBitWidth, KeySeed, Curve, HashToCurve, pool);
        var proofs = new List<RangeProof>();
        try
        {
            ulong[] values = [50UL, 90UL];
            using IMemoryOwner<byte> commitmentsOwner = ProveBatchOfSingleValues(key, values, proofs, pool);
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
            ReadOnlySpan<byte> commitments = commitmentsOwner.Memory.Span[..(values.Length * g1Size)];

            const int TamperedProofIndex = 1;
            RangeProof tamperedSource = proofs[TamperedProofIndex];
            int offset = GetProofPointOffset(ProofSlot.BlindingCommitmentS, tamperedSource, g1Size);
            RangeProof tampered = SpliceProofPoint(tamperedSource, offset, g1Size, pool);
            tamperedSource.Dispose();
            proofs[TamperedProofIndex] = tampered;

            bool subgroupChecked = false;
            bool msmCalled = false;
            G1IsInPrimeOrderSubgroupDelegate recordingSubgroup = (point, curve) =>
            {
                subgroupChecked = true;

                return G1IsInPrimeOrderSubgroup(point, curve);
            };
            G1MultiScalarMultiplyDelegate recordingMsm = (points, scalars, count, result, curve) =>
            {
                msmCalled = true;
                G1Msm(points, scalars, count, result, curve);
            };

            using FiatShamirTranscript batchTx = NewTranscript(BatchDomain);
            bool verified = BatchBulletproofRangeVerifier.Verify(
                key, commitments, proofs, batchTx, () => NewTranscript(TranscriptDomain),
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, recordingMsm, G1IsOnCurve, recordingSubgroup, pool);

            Assert.IsFalse(verified, "BatchBulletproofRangeVerifier.Verify must reject the whole batch when one proof has a wrong-subgroup point.");
            Assert.IsTrue(subgroupChecked, "The subgroup delegate must be consulted for the tampered proof's point.");
            Assert.IsFalse(msmCalled, "Rejection must happen before the combined multi-scalar multiplication.");
        }
        finally
        {
            foreach(RangeProof proof in proofs)
            {
                proof.Dispose();
            }
        }
    }


    /// <summary>
    /// <see cref="BatchAggregatedBulletproofRangeVerifier.Verify"/> must
    /// reject the whole batch when one proof's value commitment lies outside
    /// the prime-order subgroup, before the combined multi-scalar
    /// multiplication runs.
    /// </summary>
    [TestMethod]
    public void BatchAggregatedVerifyRejectsWrongSubgroupValueCommitment()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(AggregatedBitWidth * AggregatedValueCount, KeySeed, Curve, HashToCurve, pool);
        var proofs = new List<RangeProof>();
        try
        {
            using IMemoryOwner<byte> commitmentsOwner = ProveBatchOfAggregatedValues(key, BatchProofCount, proofs, pool);
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
            int totalBytes = BatchProofCount * AggregatedValueCount * g1Size;
            Span<byte> commitments = commitmentsOwner.Memory.Span[..totalBytes];

            const int TamperedProofIndex = 1;
            int tamperedCommitmentOffset = (TamperedProofIndex * AggregatedValueCount * g1Size);
            WrongSubgroupG1Compressed.CopyTo(commitments.Slice(tamperedCommitmentOffset, g1Size));

            bool subgroupChecked = false;
            bool msmCalled = false;
            G1IsInPrimeOrderSubgroupDelegate recordingSubgroup = (point, curve) =>
            {
                subgroupChecked = true;

                return G1IsInPrimeOrderSubgroup(point, curve);
            };
            G1MultiScalarMultiplyDelegate recordingMsm = (points, scalars, count, result, curve) =>
            {
                msmCalled = true;
                G1Msm(points, scalars, count, result, curve);
            };

            using FiatShamirTranscript batchTx = NewTranscript(BatchDomain);
            bool verified = BatchAggregatedBulletproofRangeVerifier.Verify(
                key, AggregatedBitWidth, AggregatedValueCount, commitments, proofs, batchTx, () => NewTranscript(TranscriptDomain),
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, recordingMsm, G1IsOnCurve, recordingSubgroup, pool);

            Assert.IsFalse(verified, "BatchAggregatedBulletproofRangeVerifier.Verify must reject the whole batch when one proof has a wrong-subgroup value commitment.");
            Assert.IsTrue(subgroupChecked, "The subgroup delegate must be consulted for the tampered value commitment.");
            Assert.IsFalse(msmCalled, "Rejection must happen before the combined multi-scalar multiplication.");
        }
        finally
        {
            foreach(RangeProof proof in proofs)
            {
                proof.Dispose();
            }
        }
    }


    private static (bool Verified, bool SubgroupChecked, bool MsmCalled, bool ScalarMulCalled) VerifySingleWithRecording(
        RangeProofKey key, ReadOnlySpan<byte> commitment, RangeProof proof, BaseMemoryPool pool)
    {
        bool subgroupChecked = false;
        bool msmCalled = false;
        bool scalarMulCalled = false;
        G1IsInPrimeOrderSubgroupDelegate recordingSubgroup = (point, curve) =>
        {
            subgroupChecked = true;

            return G1IsInPrimeOrderSubgroup(point, curve);
        };
        G1MultiScalarMultiplyDelegate recordingMsm = (points, scalars, count, result, curve) =>
        {
            msmCalled = true;
            G1Msm(points, scalars, count, result, curve);
        };
        G1ScalarMultiplyDelegate recordingScalarMul = (point, scalar, result, curve) =>
        {
            scalarMulCalled = true;
            G1ScalarMul(point, scalar, result, curve);
        };

        using FiatShamirTranscript verifierTx = NewTranscript(TranscriptDomain);
        bool verified = BulletproofRangeVerifier.Verify(
            key, commitment, proof, verifierTx,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            G1Add, recordingScalarMul, recordingMsm, G1IsOnCurve, recordingSubgroup, pool);

        return (verified, subgroupChecked, msmCalled, scalarMulCalled);
    }


    private static (RangeProof Proof, IMemoryOwner<byte> Commitment) ProveSingleValue(RangeProofKey key, ulong value, BaseMemoryPool pool, int blindingSeed, int proverSeed)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        IMemoryOwner<byte> commitmentOwner = pool.Rent(g1Size);
        Span<byte> commitment = commitmentOwner.Memory.Span[..g1Size];
        Span<byte> blinding = stackalloc byte[Scalar.SizeBytes];
        MakeFixedRandom(blindingSeed)(blinding, Curve, Tag.Empty);

        using FiatShamirTranscript proverTx = NewTranscript(TranscriptDomain);
        RangeProof proof = BulletproofRangeProver.Prove(
            key, value, blinding, commitment, proverTx,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(proverSeed),
            G1Add, G1ScalarMul, G1Msm, pool);

        return (proof, commitmentOwner);
    }


    private static (RangeProof Proof, IMemoryOwner<byte> Commitments) ProveAggregatedValues(RangeProofKey key, ulong[] values, BaseMemoryPool pool, int blindingSeedBase, int proverSeed)
    {
        int m = values.Length;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        IMemoryOwner<byte> commitmentsOwner = pool.Rent(m * g1Size);
        Span<byte> commitments = commitmentsOwner.Memory.Span[..(m * g1Size)];
        using IMemoryOwner<byte> blindingsOwner = pool.Rent(m * Scalar.SizeBytes);
        Span<byte> blindings = blindingsOwner.Memory.Span[..(m * Scalar.SizeBytes)];
        for(int j = 0; j < m; j++)
        {
            MakeFixedRandom(blindingSeedBase + j)(blindings.Slice(j * Scalar.SizeBytes, Scalar.SizeBytes), Curve, Tag.Empty);
        }

        using FiatShamirTranscript proverTx = NewTranscript(TranscriptDomain);
        RangeProof proof = AggregatedBulletproofRangeProver.Prove(
            key, AggregatedBitWidth, values, blindings, commitments, proverTx,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(proverSeed),
            G1Add, G1ScalarMul, G1Msm, pool);

        return (proof, commitmentsOwner);
    }


    //Returns the rented commitment buffer (one compressed G1 point per
    //proof); the caller owns its disposal.
    private static IMemoryOwner<byte> ProveBatchOfSingleValues(RangeProofKey key, ulong[] values, List<RangeProof> proofs, BaseMemoryPool pool)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        IMemoryOwner<byte> commitmentsOwner = pool.Rent(values.Length * g1Size);
        Span<byte> commitments = commitmentsOwner.Memory.Span[..(values.Length * g1Size)];
        Span<byte> blinding = stackalloc byte[Scalar.SizeBytes];
        for(int i = 0; i < values.Length; i++)
        {
            //Distinct blinding/randomness seeds per proof so the two proofs differ.
            const int BlindingSeedBase = 900;
            const int ProverSeedBase = 950;
            MakeFixedRandom(BlindingSeedBase + i)(blinding, Curve, Tag.Empty);

            using FiatShamirTranscript proverTx = NewTranscript(TranscriptDomain);
            RangeProof proof = BulletproofRangeProver.Prove(
                key, values[i], blinding, commitments.Slice(i * g1Size, g1Size), proverTx,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(ProverSeedBase + i),
                G1Add, G1ScalarMul, G1Msm, pool);
            proofs.Add(proof);
        }

        return commitmentsOwner;
    }


    //Returns the rented commitments buffer (proofCount * AggregatedValueCount
    //compressed G1 points, proof-major order); the caller owns its disposal.
    private static IMemoryOwner<byte> ProveBatchOfAggregatedValues(RangeProofKey key, int proofCount, List<RangeProof> proofs, BaseMemoryPool pool)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        IMemoryOwner<byte> commitmentsOwner = pool.Rent(proofCount * AggregatedValueCount * g1Size);
        Span<byte> commitments = commitmentsOwner.Memory.Span[..(proofCount * AggregatedValueCount * g1Size)];
        using IMemoryOwner<byte> blindingsOwner = pool.Rent(AggregatedValueCount * Scalar.SizeBytes);
        Span<byte> blindings = blindingsOwner.Memory.Span[..(AggregatedValueCount * Scalar.SizeBytes)];

        //Value cap keeps every generated value inside [0, 2^AggregatedBitWidth).
        const int ValueModulus = 1 << AggregatedBitWidth;
        const int BlindingSeedBase = 1000;
        const int ProverSeedBase = 1100;
        for(int p = 0; p < proofCount; p++)
        {
            var values = new ulong[AggregatedValueCount];
            for(int j = 0; j < AggregatedValueCount; j++)
            {
                values[j] = (ulong)(((p * 31) + (j * 17) + 10) % ValueModulus);
                MakeFixedRandom(BlindingSeedBase + (p * AggregatedValueCount) + j)(blindings.Slice(j * Scalar.SizeBytes, Scalar.SizeBytes), Curve, Tag.Empty);
            }

            using FiatShamirTranscript proverTx = NewTranscript(TranscriptDomain);
            RangeProof proof = AggregatedBulletproofRangeProver.Prove(
                key, AggregatedBitWidth, values, blindings, commitments.Slice(p * AggregatedValueCount * g1Size, AggregatedValueCount * g1Size), proverTx,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(ProverSeedBase + p),
                G1Add, G1ScalarMul, G1Msm, pool);
            proofs.Add(proof);
        }

        return commitmentsOwner;
    }


    //Returns the byte offset of the given proof-internal point, derived from
    //RangeProof's own layout arithmetic rather than duplicated as an
    //independent magic number.
    private static int GetProofPointOffset(ProofSlot slot, RangeProof proof, int g1Size)
    {
        int ipaSectionStart = (LeadingPointCount * g1Size) + (MidScalarCount * ScalarSize);

        return slot switch
        {
            ProofSlot.BitCommitmentA => 0,
            ProofSlot.BlindingCommitmentS => g1Size,
            ProofSlot.PolynomialCommitmentT1 => 2 * g1Size,
            ProofSlot.PolynomialCommitmentT2 => 3 * g1Size,
            ProofSlot.IpaRoundZeroL => ipaSectionStart,
            ProofSlot.IpaRoundLastR => ipaSectionStart + ((proof.IpaRoundCount - 1) * 2 * g1Size) + g1Size,
            _ => throw new ArgumentOutOfRangeException(nameof(slot), slot, "Unrecognised proof slot.")
        };
    }


    //Splices the wrong-subgroup probe into a fresh pool-rented copy of the
    //proof's wire bytes at the given offset and rehydrates through
    //RangeProof.FromBytes, which validates length only and never decodes
    //points itself.
    private static RangeProof SpliceProofPoint(RangeProof proof, int offset, int g1Size, BaseMemoryPool pool)
    {
        int length = proof.AsReadOnlySpan().Length;
        using IMemoryOwner<byte> tamperedOwner = pool.Rent(length);
        Span<byte> tampered = tamperedOwner.Memory.Span[..length];
        proof.AsReadOnlySpan().CopyTo(tampered);
        WrongSubgroupG1Compressed.CopyTo(tampered.Slice(offset, g1Size));

        return RangeProof.FromBytes(tampered, proof.BitWidth, Curve, pool);
    }


    private static FiatShamirTranscript NewTranscript(string domain) =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(domain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    private static ScalarRandomDelegate MakeFixedRandom(int seed)
    {
        int counter = 0;
        return Sample;

        Tag Sample(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> hashInput = stackalloc byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hashInput[..4], seed);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(hashInput[4..], counter);
            counter++;

            Span<byte> wide = stackalloc byte[32];
            SHA256.HashData(hashInput, wide);
            Reduce(wide, destination, curve);

            return inboundTag;
        }
    }
}

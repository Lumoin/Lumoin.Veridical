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
/// Tests for batched verification of aggregated range proofs
/// (<see cref="BatchAggregatedBulletproofRangeVerifier"/>): a batch accepts
/// exactly the proofs the per-proof
/// <see cref="AggregatedBulletproofRangeVerifier"/> accepts (the single-proof
/// batch is gated against it, pinning the s-vector orientation under
/// aggregation), and a batch with one forged proof or one wrong commitment is
/// rejected.
/// </summary>
[TestClass]
internal sealed class BatchAggregatedBulletproofRangeProofTests
{
    private const string TranscriptDomain = "veridical.test.bulletproofs.range.aggbatch.v1";
    private const string BatchDomain = "veridical.test.bulletproofs.range.aggbatch.weights.v1";
    private const string KeySeed = "veridical.test.bulletproofs.range.aggbatch.key.v1";
    private const int BitWidth = 8;
    private const int ValueCount = 4;

    private static readonly G1HashToCurveDelegate HashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static readonly G1AddDelegate G1Add = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static readonly G1ScalarMultiplyDelegate G1ScalarMul = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static readonly G1MultiScalarMultiplyDelegate G1Msm = TestG1Backends.Bls12Curve381Msm;
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate Invert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(4)]
    public void BatchOfValidAggregatedProofsVerifies(int proofCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(BitWidth * ValueCount, KeySeed, Curve, HashToCurve, pool);

        var proofs = new List<RangeProof>();
        try
        {
            using IMemoryOwner<byte> commitmentsOwner = ProveBatch(key, proofCount, proofs, pool);
            ReadOnlySpan<byte> commitments = commitmentsOwner.Memory.Span[..(proofCount * ValueCount * WellKnownCurves.GetG1CompressedSizeBytes(Curve))];

            using FiatShamirTranscript batchTx = NewTranscript(BatchDomain);
            Assert.IsTrue(
                BatchAggregatedBulletproofRangeVerifier.Verify(
                    key, BitWidth, ValueCount, commitments, proofs, batchTx, () => NewTranscript(TranscriptDomain),
                    Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Msm, pool),
                $"A batch of {proofCount} valid aggregated proofs must verify.");
        }
        finally
        {
            DisposeAll(proofs);
        }
    }


    [TestMethod]
    public void SingleAggregatedProofBatchAgreesWithThePerProofVerifier()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(BitWidth * ValueCount, KeySeed, Curve, HashToCurve, pool);

        var proofs = new List<RangeProof>();
        try
        {
            using IMemoryOwner<byte> commitmentsOwner = ProveBatch(key, 1, proofs, pool);
            ReadOnlySpan<byte> commitments = commitmentsOwner.Memory.Span[..(1 * ValueCount * WellKnownCurves.GetG1CompressedSizeBytes(Curve))];

            using FiatShamirTranscript perProofTx = NewTranscript(TranscriptDomain);
            bool perProof = AggregatedBulletproofRangeVerifier.Verify(
                key, BitWidth, ValueCount, commitments, proofs[0], perProofTx,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Add, G1ScalarMul, G1Msm, pool);

            using FiatShamirTranscript batchTx = NewTranscript(BatchDomain);
            bool batch = BatchAggregatedBulletproofRangeVerifier.Verify(
                key, BitWidth, ValueCount, commitments, proofs, batchTx, () => NewTranscript(TranscriptDomain),
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Msm, pool);

            Assert.IsTrue(perProof, "The per-proof aggregated verifier must accept the honest proof.");
            Assert.AreEqual(perProof, batch, "The single-proof aggregated batch must agree with the per-proof verifier.");
        }
        finally
        {
            DisposeAll(proofs);
        }
    }


    [TestMethod]
    public void BatchWithOneTamperedAggregatedProofIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(BitWidth * ValueCount, KeySeed, Curve, HashToCurve, pool);

        var proofs = new List<RangeProof>();
        try
        {
            using IMemoryOwner<byte> commitmentsOwner = ProveBatch(key, 3, proofs, pool);
            ReadOnlySpan<byte> commitments = commitmentsOwner.Memory.Span[..(3 * ValueCount * WellKnownCurves.GetG1CompressedSizeBytes(Curve))];
            proofs[1].AsSpan()[^1] ^= 0x01;

            using FiatShamirTranscript batchTx = NewTranscript(BatchDomain);
            Assert.IsFalse(
                BatchAggregatedBulletproofRangeVerifier.Verify(
                    key, BitWidth, ValueCount, commitments, proofs, batchTx, () => NewTranscript(TranscriptDomain),
                    Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Msm, pool),
                "A batch containing one tampered aggregated proof must be rejected.");
        }
        finally
        {
            DisposeAll(proofs);
        }
    }


    [TestMethod]
    public void BatchWithOneSwappedCommitmentIsRejected()
    {
        //Swap two value commitments within one proof's block: the per-value z
        //powers bind slot order, so the batch must fail.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using RangeProofKey key = RangeProofKey.Derive(BitWidth * ValueCount, KeySeed, Curve, HashToCurve, pool);

        var proofs = new List<RangeProof>();
        try
        {
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
            int totalBytes = 2 * ValueCount * g1Size;
            using IMemoryOwner<byte> commitmentsOwner = ProveBatch(key, 2, proofs, pool);
            ReadOnlySpan<byte> commitments = commitmentsOwner.Memory.Span[..totalBytes];
            //Within proof 0's block, swap value slots 0 and 1.
            using IMemoryOwner<byte> swappedOwner = pool.Rent(totalBytes);
            Span<byte> swapped = swappedOwner.Memory.Span[..totalBytes];
            commitments.CopyTo(swapped);
            commitments.Slice(g1Size, g1Size).CopyTo(swapped[..g1Size]);
            commitments[..g1Size].CopyTo(swapped.Slice(g1Size, g1Size));

            using FiatShamirTranscript batchTx = NewTranscript(BatchDomain);
            Assert.IsFalse(
                BatchAggregatedBulletproofRangeVerifier.Verify(
                    key, BitWidth, ValueCount, swapped, proofs, batchTx, () => NewTranscript(TranscriptDomain),
                    Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Msm, pool),
                "A batch with a swapped value commitment must be rejected.");
        }
        finally
        {
            DisposeAll(proofs);
        }
    }


    private static IMemoryOwner<byte> ProveBatch(RangeProofKey key, int proofCount, List<RangeProof> proofs, BaseMemoryPool pool)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        IMemoryOwner<byte> commitmentsOwner = pool.Rent(proofCount * ValueCount * g1Size);
        Span<byte> commitments = commitmentsOwner.Memory.Span[..(proofCount * ValueCount * g1Size)];
        using IMemoryOwner<byte> blindingsOwner = pool.Rent(ValueCount * Scalar.SizeBytes);
        Span<byte> blindings = blindingsOwner.Memory.Span[..(ValueCount * Scalar.SizeBytes)];

        for(int p = 0; p < proofCount; p++)
        {
            var values = new ulong[ValueCount];
            ScalarRandomDelegate blindingRandom = MakeFixedRandom(seed: 1000 + p);
            for(int j = 0; j < ValueCount; j++)
            {
                values[j] = (ulong)(((p * 31) + (j * 9973)) % 256);
                _ = blindingRandom(blindings.Slice(j * Scalar.SizeBytes, Scalar.SizeBytes), Curve, Tag.Empty);
            }

            using FiatShamirTranscript proverTx = NewTranscript(TranscriptDomain);
            RangeProof proof = AggregatedBulletproofRangeProver.Prove(
                key, BitWidth, values, blindings, commitments.Slice(p * ValueCount * g1Size, ValueCount * g1Size), proverTx,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(seed: 2000 + p),
                G1Add, G1ScalarMul, G1Msm, pool);
            proofs.Add(proof);
        }

        return commitmentsOwner;
    }


    private static void DisposeAll(List<RangeProof> proofs)
    {
        foreach(RangeProof proof in proofs)
        {
            proof.Dispose();
        }
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

            return Tag.Empty;
        }
    }
}

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
/// Tests for batched single-value range-proof verification
/// (<see cref="BatchBulletproofRangeVerifier"/>): a batch accepts exactly the
/// proofs the per-proof <see cref="BulletproofRangeVerifier"/> accepts (the
/// single-proof batch is gated against it directly, pinning the s-vector
/// orientation), and a batch containing one forged or mismatched proof is
/// rejected — the random per-proof weights make any single bad proof poison
/// the combined multiexponentiation.
/// </summary>
[TestClass]
internal sealed class BatchBulletproofRangeProofTests
{
    private const string TranscriptDomain = "veridical.test.bulletproofs.range.batch.v1";
    private const string BatchDomain = "veridical.test.bulletproofs.range.batch.weights.v1";
    private const string KeySeed = "veridical.test.bulletproofs.range.batch.key.v1";
    private const int BitWidth = 16;

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
    [DataRow(5)]
    public void BatchOfValidProofsVerifies(int count)
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        using RangeProofKey key = RangeProofKey.Derive(BitWidth, KeySeed, Curve, HashToCurve, pool);

        var proofs = new List<RangeProof>();
        try
        {
            using IMemoryOwner<byte> commitmentsOwner = ProveBatch(key, ValuesFor(count), proofs, pool);
            ReadOnlySpan<byte> commitments = commitmentsOwner.Memory.Span[..(count * WellKnownCurves.GetG1CompressedSizeBytes(Curve))];

            using FiatShamirTranscript batchTx = NewTranscript(BatchDomain);
            Assert.IsTrue(
                BatchBulletproofRangeVerifier.Verify(
                    key, commitments, proofs, batchTx, () => NewTranscript(TranscriptDomain),
                    Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Msm, pool),
                $"A batch of {count} valid proofs must verify.");
        }
        finally
        {
            foreach(RangeProof proof in proofs)
            {
                proof.Dispose();
            }
        }
    }


    [TestMethod]
    public void SingleProofBatchAgreesWithThePerProofVerifier()
    {
        //The orientation gate: the batch's single-MSM form must accept exactly
        //what the fold-based verifier accepts for the same proof.
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        using RangeProofKey key = RangeProofKey.Derive(BitWidth, KeySeed, Curve, HashToCurve, pool);

        var proofs = new List<RangeProof>();
        try
        {
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
            using IMemoryOwner<byte> commitmentsOwner = ProveBatch(key, [40000UL], proofs, pool);
            ReadOnlyMemory<byte> commitments = commitmentsOwner.Memory[..g1Size];

            using FiatShamirTranscript perProofTx = NewTranscript(TranscriptDomain);
            bool perProof = BulletproofRangeVerifier.Verify(
                key, commitments.Span, proofs[0], perProofTx,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Add, G1ScalarMul, G1Msm, pool);

            using FiatShamirTranscript batchTx = NewTranscript(BatchDomain);
            bool batch = BatchBulletproofRangeVerifier.Verify(
                key, commitments.Span, proofs, batchTx, () => NewTranscript(TranscriptDomain),
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Msm, pool);

            Assert.IsTrue(perProof, "The per-proof verifier must accept the honest proof.");
            Assert.AreEqual(perProof, batch, "The single-proof batch must agree with the per-proof verifier.");
        }
        finally
        {
            foreach(RangeProof proof in proofs)
            {
                proof.Dispose();
            }
        }
    }


    [TestMethod]
    public void BatchWithOneTamperedProofIsRejected()
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        using RangeProofKey key = RangeProofKey.Derive(BitWidth, KeySeed, Curve, HashToCurve, pool);

        var proofs = new List<RangeProof>();
        try
        {
            using IMemoryOwner<byte> commitmentsOwner = ProveBatch(key, ValuesFor(4), proofs, pool);
            ReadOnlySpan<byte> commitments = commitmentsOwner.Memory.Span[..(4 * WellKnownCurves.GetG1CompressedSizeBytes(Curve))];

            //Corrupt the third proof's IPA tail; the other three stay honest.
            proofs[2].AsSpan()[^1] ^= 0x01;

            using FiatShamirTranscript batchTx = NewTranscript(BatchDomain);
            Assert.IsFalse(
                BatchBulletproofRangeVerifier.Verify(
                    key, commitments, proofs, batchTx, () => NewTranscript(TranscriptDomain),
                    Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Msm, pool),
                "A batch containing one tampered proof must be rejected.");
        }
        finally
        {
            foreach(RangeProof proof in proofs)
            {
                proof.Dispose();
            }
        }
    }


    [TestMethod]
    public void BatchWithOneWrongCommitmentIsRejected()
    {
        //A valid proof paired with the wrong commitment: the per-proof weights
        //bind each commitment, so the batch must fail.
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        using RangeProofKey key = RangeProofKey.Derive(BitWidth, KeySeed, Curve, HashToCurve, pool);

        var proofs = new List<RangeProof>();
        try
        {
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
            using IMemoryOwner<byte> commitmentsOwner = ProveBatch(key, ValuesFor(3), proofs, pool);
            ReadOnlySpan<byte> commitments = commitmentsOwner.Memory.Span[..(3 * g1Size)];
            //Swap commitments 0 and 1; both are valid points, just mismatched.
            using IMemoryOwner<byte> swappedOwner = pool.Rent(3 * g1Size);
            Span<byte> swapped = swappedOwner.Memory.Span[..(3 * g1Size)];
            commitments.CopyTo(swapped);
            commitments.Slice(g1Size, g1Size).CopyTo(swapped[..g1Size]);
            commitments[..g1Size].CopyTo(swapped.Slice(g1Size, g1Size));

            using FiatShamirTranscript batchTx = NewTranscript(BatchDomain);
            Assert.IsFalse(
                BatchBulletproofRangeVerifier.Verify(
                    key, swapped, proofs, batchTx, () => NewTranscript(TranscriptDomain),
                    Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Msm, pool),
                "A batch with mismatched commitments must be rejected.");
        }
        finally
        {
            foreach(RangeProof proof in proofs)
            {
                proof.Dispose();
            }
        }
    }


    private static ulong[] ValuesFor(int count)
    {
        var values = new ulong[count];
        for(int i = 0; i < count; i++)
        {
            //Distinct in-range values; the 16-bit width caps at 65535.
            values[i] = (ulong)((i * 9973) % 65536);
        }

        return values;
    }


    //Returns the rented commitment buffer (one compressed G1 point per proof);
    //the caller owns its disposal — the production-like pattern, where the
    //prover writes into a caller-rented span.
    private static IMemoryOwner<byte> ProveBatch(RangeProofKey key, ulong[] values, List<RangeProof> proofs, SensitiveMemoryPool<byte> pool)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        IMemoryOwner<byte> commitmentsOwner = pool.Rent(values.Length * g1Size);
        Span<byte> commitments = commitmentsOwner.Memory.Span[..(values.Length * g1Size)];
        Span<byte> blinding = stackalloc byte[Scalar.SizeBytes];
        for(int i = 0; i < values.Length; i++)
        {
            MakeFixedRandom(seed: 100 + i)(blinding, Curve, Tag.Empty);

            using FiatShamirTranscript proverTx = NewTranscript(TranscriptDomain);
            RangeProof proof = BulletproofRangeProver.Prove(
                key, values[i], blinding, commitments.Slice(i * g1Size, g1Size), proverTx,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(seed: 200 + i),
                G1Add, G1ScalarMul, G1Msm, pool);
            proofs.Add(proof);
        }

        return commitmentsOwner;
    }


    private static FiatShamirTranscript NewTranscript(string domain) =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(domain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, SensitiveMemoryPool<byte>.Shared);


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

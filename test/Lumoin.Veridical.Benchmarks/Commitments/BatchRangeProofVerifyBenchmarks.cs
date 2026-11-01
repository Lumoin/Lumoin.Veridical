using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
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

namespace Lumoin.Veridical.Benchmarks.Commitments;

/// <summary>
/// The batch range-proof verification payoff: verifying <c>m</c> proofs in
/// one combined multiexponentiation against verifying them one at a time. The
/// shared generators decode once (caching Pippenger) and the per-proof
/// inner-product fold collapses into the single MSM, so the batch grows far
/// slower than <c>m</c> independent verifications.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput)]
public class BatchRangeProofVerifyBenchmarks
{
    /// <summary>The domain label of the transcript each individual proof is verified against.</summary>
    private const string TranscriptDomain = "veridical.bench.bulletproofs.range.batch.tx";
    /// <summary>The domain label of the transcript that derives the batch combination weights.</summary>
    private const string BatchDomain = "veridical.bench.bulletproofs.range.batch.weights";
    /// <summary>The seed from which the range-proof key is derived.</summary>
    private const string KeySeed = "veridical.bench.bulletproofs.range.batch.key";
    /// <summary>The bit width of each proven range.</summary>
    private const int BitWidth = 32;

    /// <summary>The hash-to-curve used to derive the key generators.</summary>
    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    /// <summary>The G1 point addition.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    /// <summary>The G1 scalar multiplication.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    /// <summary>The G1 multi-scalar multiplication.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    /// <summary>The G1 on-curve check.</summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();
    /// <summary>The G1 prime-order subgroup check.</summary>
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();
    /// <summary>The scalar addition.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    /// <summary>The scalar subtraction.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    /// <summary>The scalar multiplication.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    /// <summary>The scalar inversion.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    /// <summary>The reduction of wide values into canonical scalars.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    /// <summary>The Fiat-Shamir hash.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    /// <summary>The Fiat-Shamir squeeze.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    /// <summary>The curve whose scalar field and G1 group are used.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>The number of proofs verified together.</summary>
    [Params(2, 8, 32)]
    public int Count { get; set; }


    /// <summary>The range-proof key shared by every proof.</summary>
    private RangeProofKey key = null!;
    /// <summary>The pooled buffer holding the concatenated commitments.</summary>
    private IMemoryOwner<byte> commitmentsOwner = null!;
    /// <summary>The number of bytes occupied by the concatenated commitments.</summary>
    private int commitmentBytes;
    /// <summary>The range proofs to verify.</summary>
    private List<RangeProof> proofs = null!;


    /// <summary>Derives the range-proof key and produces the batch of commitments and proofs to verify.</summary>
    [GlobalSetup]
    public void Setup()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        key = RangeProofKey.Derive(BitWidth, KeySeed, Curve, HashToCurve, pool);

        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        commitmentBytes = Count * g1Size;
        commitmentsOwner = BaseMemoryPool.Shared.Rent(commitmentBytes);
        proofs = new List<RangeProof>(Count);
        Span<byte> blinding = stackalloc byte[global::Lumoin.Veridical.Core.Algebraic.Scalar.SizeBytes];
        for(int i = 0; i < Count; i++)
        {
            MakeFixedRandom(100 + i)(blinding, Curve, Tag.Empty);
            using FiatShamirTranscript proverTx = NewTranscript(TranscriptDomain);
            proofs.Add(BulletproofRangeProver.Prove(
                key, (ulong)((i * 100003) % (1L << BitWidth)), blinding, commitmentsOwner.Memory.Span.Slice(i * g1Size, g1Size), proverTx,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, MakeFixedRandom(200 + i),
                G1Add, G1ScalarMul, G1Msm, pool));
        }
    }


    /// <summary>Disposes the proofs, the range-proof key, and the pooled commitments buffer the setup rented.</summary>
    [GlobalCleanup]
    public void Cleanup()
    {
        foreach(RangeProof proof in proofs)
        {
            proof.Dispose();
        }

        key.Dispose();
        commitmentsOwner.Dispose();
    }


    /// <summary>Benchmarks verifying the range proofs one at a time.</summary>
    [Benchmark(Baseline = true)]
    public int IndividualVerify()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(Curve);
        int accepted = 0;
        for(int i = 0; i < Count; i++)
        {
            using FiatShamirTranscript tx = NewTranscript(TranscriptDomain);
            if(BulletproofRangeVerifier.Verify(
                key, commitmentsOwner.Memory.Span.Slice(i * g1Size, g1Size), proofs[i], tx,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup, pool))
            {
                accepted++;
            }
        }

        return accepted;
    }


    /// <summary>Benchmarks verifying all range proofs together in one combined multiexponentiation.</summary>
    [Benchmark]
    public bool BatchVerify()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using FiatShamirTranscript batchTx = NewTranscript(BatchDomain);

        return BatchBulletproofRangeVerifier.Verify(
            key, commitmentsOwner.Memory.Span[..commitmentBytes], proofs, batchTx, () => NewTranscript(TranscriptDomain),
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup, pool);
    }


    /// <summary>Starts a Fiat-Shamir transcript under the given domain label with the BLAKE3 hash.</summary>
    private static FiatShamirTranscript NewTranscript(string domain) =>
        FiatShamirTranscript.Initialise(new FiatShamirDomainLabel(domain), ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    /// <summary>Returns a scalar sampler that derives each output from the seed and a call counter, so a run is reproducible.</summary>
    private static ScalarRandomDelegate MakeFixedRandom(int seed)
    {
        int counter = 0;
        return Sample;

        //Hashes the seed and counter with SHA-256 and reduces the digest into the destination scalar.
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

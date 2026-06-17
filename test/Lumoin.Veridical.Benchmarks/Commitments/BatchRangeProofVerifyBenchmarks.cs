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
    private const string TranscriptDomain = "veridical.bench.bulletproofs.range.batch.tx";
    private const string BatchDomain = "veridical.bench.bulletproofs.range.batch.weights";
    private const string KeySeed = "veridical.bench.bulletproofs.range.batch.key";
    private const int BitWidth = 32;

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


    /// <summary>The number of proofs verified together.</summary>
    [Params(2, 8, 32)]
    public int Count { get; set; }


    private RangeProofKey key = null!;
    private IMemoryOwner<byte> commitmentsOwner = null!;
    private int commitmentBytes;
    private List<RangeProof> proofs = null!;


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
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Add, G1ScalarMul, G1Msm, pool))
            {
                accepted++;
            }
        }

        return accepted;
    }


    [Benchmark]
    public bool BatchVerify()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using FiatShamirTranscript batchTx = NewTranscript(BatchDomain);

        return BatchBulletproofRangeVerifier.Verify(
            key, commitmentsOwner.Memory.Span[..commitmentBytes], proofs, batchTx, () => NewTranscript(TranscriptDomain),
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, G1Msm, pool);
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

using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// The zero-mask (broken-RNG) rejection leg of the ZK BaseFold gate: an entropy
/// delegate that returns identically-zero bytes models the bug class where an
/// RNG wiring failure silently voids the hiding property while every proof
/// still verifies. Both lift providers must refuse to produce such an artifact
/// — <see cref="InvalidOperationException"/> from the generation-site checks —
/// at commit time (the dimension-lift mask block and the salts) and at open
/// time (the CFS sumcheck mask).
/// </summary>
[TestClass]
internal sealed class ZkBaseFoldZeroMaskRejectionTests
{
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate Invert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly ScalarHashToScalarDelegate HashToScalar = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static readonly ScalarRandomDelegate Random = Bls12Curve381BigIntegerScalarReference.GetRandom();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;

    private const int ScalarSize = 32;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int TestQueryCount = 12;

    //The minimal budget-meeting lift for a one-variable witness at
    //TestQueryCount = 12 (GetMinimumExtraVariableCount).
    private const int RealVariableCount = 1;
    private const int ExtraVariableCount = 6;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void ZeroEntropyCommitThrowsForTheLiftProvider()
    {
        //CreateZeroKnowledge's commit draws the dimension-lift mask block (and
        //the top-layer salts) from the provider's entropy delegate; an
        //identically-zero draw must be rejected at generation.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = ZkBaseFoldPolynomialCommitmentScheme.CreateZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            ZeroScalarRandom, HashToScalar, ExtraVariableCount);

        using MultilinearExtension witness = BuildDeterministicMle(RealVariableCount, salt: 11, pool);

        //The throw fires before the commit produces anything, so there is
        //nothing to dispose on the rejection path.
        Assert.ThrowsExactly<InvalidOperationException>(() => _ = provider.Commit(witness, pool));
    }


    [TestMethod]
    public void ZeroEntropyOpenThrowsForTheFullZeroKnowledgeProvider()
    {
        //Commit through a provider with a healthy sampler, then open through a
        //provider that shares the seed and shape but draws zero entropy: the
        //open's first draw is the CFS sumcheck mask, so this exercises the
        //mask-generation check on the open (prove) path specifically.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider healthyProvider = NewFullZeroKnowledgeProvider(Random);
        using PolynomialCommitmentProvider zeroEntropyProvider = NewFullZeroKnowledgeProvider(ZeroScalarRandom);

        using MultilinearExtension witness = BuildDeterministicMle(RealVariableCount, salt: 13, pool);
        Scalar[] point = BuildPoint(RealVariableCount, salt: 17, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = healthyProvider.Commit(witness, pool);

            using(commitment)
            {
                using(blind)
                {
                    //The throw fires at the mask draw before the open produces
                    //anything, so there is nothing to dispose on the rejection
                    //path.
                    using FiatShamirTranscript openTx = NewTranscript();
                    Assert.ThrowsExactly<InvalidOperationException>(
                        () => _ = zeroEntropyProvider.Open(commitment, blind, witness, point, openTx, pool));
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    //An entropy delegate with the production signature that always returns
    //zero bytes — the modelled RNG wiring failure.
    private static Tag ZeroScalarRandom(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
    {
        destination.Clear();

        return inboundTag;
    }


    private static PolynomialCommitmentProvider NewFullZeroKnowledgeProvider(ScalarRandomDelegate scalarRandom)
    {
        return ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            scalarRandom, HashToScalar, ExtraVariableCount);
    }


    private static MultilinearExtension BuildDeterministicMle(int variableCount, int salt, BaseMemoryPool pool)
    {
        int evaluationCount = 1 << variableCount;
        using IMemoryOwner<byte> owner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> evals = owner.Memory.Span[..(evaluationCount * ScalarSize)];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < evaluationCount; i++)
        {
            wide.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 137) + (i * 19) + 1);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 11) + (i * 31) + 3);
            Reduce(wide, evals.Slice(i * ScalarSize, ScalarSize), Curve);
        }

        return MultilinearExtension.FromEvaluations(evals, variableCount, Curve, pool);
    }


    private static Scalar[] BuildPoint(int variableCount, int salt, BaseMemoryPool pool)
    {
        var point = new Scalar[variableCount];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < variableCount; i++)
        {
            wide.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 59) + (i * 23) + 2);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 29) + (i * 43) + 5);
            IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
            Reduce(wide, owner.Memory.Span[..ScalarSize], Curve);
            point[i] = new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
        }

        return point;
    }


    private static void DisposePoint(Scalar[] point)
    {
        foreach(Scalar coordinate in point)
        {
            coordinate.Dispose();
        }
    }


    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
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


    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.ZkBaseFold.W27b.ZeroMaskRejection.Test"u8;
}

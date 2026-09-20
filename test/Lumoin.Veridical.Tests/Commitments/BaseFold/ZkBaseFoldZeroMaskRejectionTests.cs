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
    /// <summary>The BLS12-381 scalar-field addition delegate this test's commitment scheme uses.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;
    /// <summary>The BLS12-381 scalar-field subtraction delegate this test's commitment scheme uses.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;
    /// <summary>The BLS12-381 scalar-field multiplication delegate this test's commitment scheme uses.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;
    /// <summary>The BLS12-381 scalar-field inversion delegate this test's commitment scheme uses.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;
    /// <summary>The BLS12-381 scalar-field canonical-reduction delegate this test uses to build deterministic witness evaluations.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    /// <summary>The BLS12-381 scalar-field hash-to-scalar delegate this test's zero-knowledge providers use.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    /// <summary>The healthy BLS12-381 scalar-field random-sampling delegate, used as the control entropy source contrasted with <see cref="ZeroScalarRandom"/>.</summary>
    private static ScalarRandomDelegate Random { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();
    /// <summary>The Fiat–Shamir hash delegate this test's transcripts use, backed by the BLAKE3 reference.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    /// <summary>The Fiat–Shamir squeeze delegate this test's transcripts use, backed by the BLAKE3 reference.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    /// <summary>The Merkle two-to-one hash delegate this test's commitment scheme uses, backed by <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The byte width of one canonical scalar this test's witness evaluations use.</summary>
    private const int ScalarSize = 32;
    /// <summary>The digest width, in bytes, this test's Merkle hashing uses.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    /// <summary>The IOPP query count this test's providers are configured with.</summary>
    private const int TestQueryCount = 12;

    /// <summary>The witness variable count this test commits, one variable.</summary>
    private const int RealVariableCount = 1;
    /// <summary>The minimal budget-meeting lift for a one-variable witness at <see cref="TestQueryCount"/> = 12, as <see cref="ZkBaseFoldPolynomialCommitmentScheme.GetMinimumExtraVariableCount"/> would compute it.</summary>
    private const int ExtraVariableCount = 6;

    /// <summary>The curve this test's scalars and commitment scheme operate over.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Verifies that committing through the lift provider with an entropy delegate that always returns zero bytes throws an <see cref="InvalidOperationException"/> rather than silently producing a non-hiding commitment.</summary>
    [TestMethod]
    public void ZeroEntropyCommitThrowsForTheLiftProvider()
    {
        //CreateZeroKnowledge's commit draws the dimension-lift mask block (and
        //the top-layer salts) from the provider's entropy delegate; an
        //identically-zero draw must be rejected at generation.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = ZkBaseFoldPolynomialCommitmentScheme.CreateZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            ZeroScalarRandom, HashToScalar, ExtraVariableCount, pool);

        using MultilinearExtension witness = BuildDeterministicMle(RealVariableCount, salt: 11, pool);

        //The throw fires before the commit produces anything, so there is
        //nothing to dispose on the rejection path.
        Assert.ThrowsExactly<InvalidOperationException>(() => _ = provider.Commit(witness, pool));
    }


    /// <summary>Verifies that, after a healthy commit, opening through a full zero-knowledge provider whose entropy delegate always returns zero bytes throws an <see cref="InvalidOperationException"/> at the CFS sumcheck mask draw.</summary>
    [TestMethod]
    public void ZeroEntropyOpenThrowsForTheFullZeroKnowledgeProvider()
    {
        //Commit through a provider with a healthy sampler, then open through a
        //provider that shares the seed and shape but draws zero entropy: the
        //open's first draw is the CFS sumcheck mask, so this exercises the
        //mask-generation check on the open (prove) path specifically.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider healthyProvider = NewFullZeroKnowledgeProvider(pool, Random);
        using PolynomialCommitmentProvider zeroEntropyProvider = NewFullZeroKnowledgeProvider(pool, ZeroScalarRandom);

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


    /// <summary>An entropy delegate with the production signature that always returns zero bytes, modelling an RNG wiring failure.</summary>
    private static Tag ZeroScalarRandom(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
    {
        destination.Clear();

        return inboundTag;
    }


    /// <summary>Builds the commitment provider using the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    /// <param name="scalarRandom">The scalar entropy backend.</param>
    private static PolynomialCommitmentProvider NewFullZeroKnowledgeProvider(BaseMemoryPool pool, ScalarRandomDelegate scalarRandom)
    {
        return ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            scalarRandom, HashToScalar, ExtraVariableCount, pool);
    }


    /// <summary>Builds a multilinear extension over deterministic pseudo-random evaluations derived from a salt, for this test's providers to commit.</summary>
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


    /// <summary>Builds a deterministic pseudo-random evaluation point, one pooled scalar coordinate per variable, for the open test to evaluate at.</summary>
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


    /// <summary>Disposes every pooled coordinate scalar a <see cref="BuildPoint"/> call rented.</summary>
    private static void DisposePoint(Scalar[] point)
    {
        foreach(Scalar coordinate in point)
        {
            coordinate.Dispose();
        }
    }


    /// <summary>Creates a fresh Fiat–Shamir transcript for one open run, seeded with the BaseFold evaluation domain label.</summary>
    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>Computes the BLAKE3 two-to-one Merkle compression of two digests.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>The domain-separation seed this test derives its commitment providers from.</summary>
    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.ZkBaseFold.ZeroMaskRejection.Test"u8;
}

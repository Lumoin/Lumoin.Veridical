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
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// The provider-level weighted-opening path (SM.7b): every scheme that wires
/// <see cref="PolynomialCommitmentProvider.CommitVector"/> /
/// <see cref="PolynomialCommitmentProvider.OpenWeightedSum"/> /
/// <see cref="PolynomialCommitmentProvider.VerifyWeightedSum"/> must round-trip
/// an honest weighted opening at its own
/// <see cref="PolynomialCommitmentProvider.ResolveStatisticalMaskShape"/>
/// resolution and reject a wrong claim — exercised through the broad leaf
/// types exactly as the masked Spartan integration consumes them.
/// </summary>
[TestClass]
internal sealed class PolynomialCommitmentProviderWeightedSumTests
{
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate Invert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly ScalarHashToScalarDelegate HashToScalar = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;
    private static readonly G1HashToCurveDelegate HashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static readonly G1AddDelegate G1Add = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static readonly G1ScalarMultiplyDelegate G1ScalarMul = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static readonly G1MultiScalarMultiplyDelegate G1Msm = TestG1Backends.Bls12Curve381Msm;

    private const int ScalarSize = 32;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int TestQueryCount = 12;

    //The masked-sumcheck shape the masks are resolved for: a small outer cubic.
    private const int SumcheckVariableCount = 3;
    private const int CubicDegree = 3;

    //The full-ZK provider's witness lift at the test query count; the vector
    //commit recomputes its own lift, so this only parameterizes the provider.
    private const int WitnessLiftVariableCount = 4;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void BaseFoldWeightedOpeningRoundtripsAndRejectsWrongClaim()
    {
        using PolynomialCommitmentProvider provider = BaseFoldPolynomialCommitmentScheme.Create(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar);

        RunWeightedRoundtrip(provider);
    }


    [TestMethod]
    public void ZkBaseFoldWeightedOpeningRoundtripsAndRejectsWrongClaim()
    {
        using PolynomialCommitmentProvider provider = ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            MakeFixedRandom(seed: 1111), HashToScalar, WitnessLiftVariableCount);

        RunWeightedRoundtrip(provider);
    }


    [TestMethod]
    public void HyraxWeightedOpeningRoundtripsAndRejectsWrongClaim()
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        //The key must carry one generator per committed vector coordinate.
        StatisticalMaskParameters shape = WellKnownStatisticalMaskParameters.CreatePedersenIpa(SumcheckVariableCount, CubicDegree);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(
            shape.CoefficientCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, Curve, HashToCurve, pool);

        using PolynomialCommitmentProvider provider = HyraxPolynomialCommitmentScheme.Create(
            key, Curve, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            MakeFixedRandom(seed: 2222), G1Add, G1ScalarMul, G1Msm);

        RunWeightedRoundtrip(provider);
    }


    //The shared drive: resolve the scheme's mask shape, commit a vector of that
    //shape, open against arbitrary public weights, check the claim against the
    //direct inner product, verify, and reject a wrong claim.
    private static void RunWeightedRoundtrip(PolynomialCommitmentProvider provider)
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;

        Assert.IsNotNull(provider.CommitVector, "The provider must wire the vector commit.");
        Assert.IsNotNull(provider.OpenWeightedSum, "The provider must wire the weighted opening.");
        Assert.IsNotNull(provider.VerifyWeightedSum, "The provider must wire the weighted verification.");
        Assert.IsNotNull(provider.ResolveStatisticalMaskShape, "The provider must wire the mask-shape resolution.");

        StatisticalMaskParameters shape = provider.ResolveStatisticalMaskShape(SumcheckVariableCount, CubicDegree);

        using MultilinearExtension vector = BuildDeterministicMle(shape.CoefficientVariableCount, salt: 7, pool);
        using MultilinearExtension weights = BuildDeterministicMle(shape.CoefficientVariableCount, salt: 13, pool);

        (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.CommitVector(vector, pool);

        using(commitment)
        using(blind)
        {
            using FiatShamirTranscript openTx = NewTranscript();
            (PolynomialOpening opening, Scalar claimedValue) = provider.OpenWeightedSum(commitment, blind, vector, weights, openTx, pool);

            using(opening)
            using(claimedValue)
            {
                using Scalar expected = ComputeDirectInnerProduct(vector, weights, pool);
                Assert.IsTrue(
                    claimedValue.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan()),
                    "The claimed value must equal the direct inner product over the caller's coordinates.");

                using FiatShamirTranscript verifyTx = NewTranscript();
                bool verified = provider.VerifyWeightedSum(commitment, weights, claimedValue, opening, verifyTx, pool);
                Assert.IsTrue(verified, "An honest weighted opening must verify.");

                using Scalar wrong = AddOne(claimedValue, pool);
                using FiatShamirTranscript rejectTx = NewTranscript();
                bool rejected = provider.VerifyWeightedSum(commitment, weights, wrong, opening, rejectTx, pool);
                Assert.IsFalse(rejected, "A wrong claimed value must be rejected.");
            }
        }
    }


    private static Scalar ComputeDirectInnerProduct(MultilinearExtension vector, MultilinearExtension weights, SensitiveMemoryPool<byte> pool)
    {
        Span<byte> sum = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        sum.Clear();

        ReadOnlySpan<byte> vectorBytes = vector.AsReadOnlySpan();
        ReadOnlySpan<byte> weightBytes = weights.AsReadOnlySpan();
        for(int i = 0; i < vector.EvaluationCount; i++)
        {
            Multiply(vectorBytes.Slice(i * ScalarSize, ScalarSize), weightBytes.Slice(i * ScalarSize, ScalarSize), term, Curve);
            Add(sum, term, sum, Curve);
        }

        return Scalar.FromCanonical(sum, Curve, pool);
    }


    private static MultilinearExtension BuildDeterministicMle(int variableCount, int salt, SensitiveMemoryPool<byte> pool)
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


    private static Scalar AddOne(Scalar value, SensitiveMemoryPool<byte> pool)
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 0x01;

        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        Add(value.AsReadOnlySpan(), one, owner.Memory.Span[..ScalarSize], Curve);

        return new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
    }


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


    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            SensitiveMemoryPool<byte>.Shared);
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.Provider.WeightedSum.SM7b.Test"u8;
}

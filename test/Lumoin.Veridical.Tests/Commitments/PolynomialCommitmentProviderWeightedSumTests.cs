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
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Commitments;

/// <summary>
/// The provider-level weighted-opening path: every scheme that wires
/// <see cref="PolynomialCommitmentProvider.CommitVector"/> /
/// <see cref="PolynomialCommitmentProvider.OpenWeightedSum"/> /
/// <see cref="PolynomialCommitmentProvider.VerifyWeightedSum"/> must round-trip
/// a correctly generated weighted opening at its own
/// <see cref="PolynomialCommitmentProvider.ResolveStatisticalMaskShape"/>
/// resolution and reject a wrong claim — exercised through the broad leaf
/// types exactly as the masked Spartan integration consumes them.
/// </summary>
[TestClass]
internal sealed class PolynomialCommitmentProviderWeightedSumTests
{
    /// <summary>The BLS12-381 scalar field addition delegate, from the reference backend.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The BLS12-381 scalar field subtraction delegate, from the reference backend.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The BLS12-381 scalar field multiplication delegate, from the reference backend.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The BLS12-381 scalar field inversion delegate, from the reference backend.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BLS12-381 scalar reduction delegate (wide bytes to a canonical scalar), from the BigInteger reference.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The BLS12-381 hash-to-scalar delegate, from the BigInteger reference.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    /// <summary>The transcript's fixed-output BLAKE3 hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The transcript's BLAKE3 XOF (squeeze) backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The Merkle two-to-one compression this test's trees use, <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The BLS12-381 G1 hash-to-curve delegate the Hyrax commitment key derives its generators with, from the BigInteger reference.</summary>
    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();

    /// <summary>The BLS12-381 G1 point addition delegate, from the BigInteger reference.</summary>
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();

    /// <summary>The BLS12-381 G1 scalar-multiplication delegate, from the BigInteger reference.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>The BLS12-381 G1 multi-scalar-multiplication delegate, from the test backend.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;

    /// <summary>The BLS12-381 G1 on-curve check delegate, from the BigInteger reference.</summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();

    /// <summary>The BLS12-381 G1 prime-order-subgroup membership delegate, from the BigInteger reference.</summary>
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();

    /// <summary>The width in bytes of one BLS12-381 scalar in its canonical representation.</summary>
    private const int ScalarSize = 32;

    /// <summary>The IOPP query-repetition count the BaseFold-backed providers in this file use.</summary>
    private const int TestQueryCount = 12;

    /// <summary>The masked-sumcheck shape the masks are resolved for: the variable count of a small outer cubic.</summary>
    private const int SumcheckVariableCount = 3;

    /// <summary>The masked-sumcheck shape the masks are resolved for: the degree of a small outer cubic.</summary>
    private const int CubicDegree = 3;

    /// <summary>The full-ZK provider's witness lift at the test query count; the vector commit recomputes its own lift, so this only parameterizes the provider.</summary>
    private const int WitnessLiftVariableCount = 4;

    /// <summary>
    /// The widest digest the Merkle surface admits — twice the scalar width,
    /// so the weighted path's trees run the leaf commitment for real instead
    /// of the verbatim scalar-wide shape.
    /// </summary>
    private const int WideDigestSizeBytes = WellKnownMerkleHashParameters.MaximumDigestSizeBytes;

    /// <summary>The curve every gate in this file runs over: BLS12-381.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Verifies that the plain (non-hiding) BaseFold provider's weighted opening round-trips and rejects a wrong claim, through <see cref="RunWeightedRoundtrip"/>.</summary>
    [TestMethod]
    public void BaseFoldWeightedOpeningRoundtripsAndRejectsWrongClaim()
    {
        using PolynomialCommitmentProvider provider = BaseFoldPolynomialCommitmentScheme.Create(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, BaseMemoryPool.Shared);

        RunWeightedRoundtrip(provider);
    }


    /// <summary>Verifies that the full-zero-knowledge BaseFold provider's weighted opening round-trips and rejects a wrong claim, through <see cref="RunWeightedRoundtrip"/>.</summary>
    [TestMethod]
    public void ZkBaseFoldWeightedOpeningRoundtripsAndRejectsWrongClaim()
    {
        using PolynomialCommitmentProvider provider = ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            MakeFixedRandom(seed: 1111), HashToScalar, WitnessLiftVariableCount, BaseMemoryPool.Shared);

        RunWeightedRoundtrip(provider);
    }


    /// <summary>
    /// The weighted path carries the digest width too: the vector commit, the
    /// nested trees behind the weighted opening and the verification all run
    /// at the widest admissible node width, so the capability holds on the
    /// seam masked Spartan consumes, not only on the plain evaluation path.
    /// </summary>
    [TestMethod]
    public void ZkBaseFoldWeightedOpeningRoundtripsAtAWideDigest()
    {
        using PolynomialCommitmentProvider provider = ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            MakeFixedRandom(seed: 1111), HashToScalar, WitnessLiftVariableCount, BaseMemoryPool.Shared,
            digestSizeBytes: WideDigestSizeBytes);

        RunWeightedRoundtrip(provider);
    }


    /// <summary>Verifies that the Hyrax provider's weighted opening round-trips and rejects a wrong claim, through <see cref="RunWeightedRoundtrip"/>.</summary>
    [TestMethod]
    public void HyraxWeightedOpeningRoundtripsAndRejectsWrongClaim()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //The key must carry one generator per committed vector coordinate.
        StatisticalMaskParameters shape = WellKnownStatisticalMaskParameters.CreatePedersenIpa(SumcheckVariableCount, CubicDegree);
        using HyraxCommitmentKey key = HyraxCommitmentKey.Derive(
            shape.CoefficientCount, WellKnownHyraxDomainLabels.CanonicalSeedV1, Curve, HashToCurve, pool);

        using PolynomialCommitmentProvider provider = HyraxPolynomialCommitmentScheme.Create(
            key, Curve, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            MakeFixedRandom(seed: 2222), G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup);

        RunWeightedRoundtrip(provider);
    }


    /// <summary>
    /// The shared drive every weighted-opening gate in this file runs: resolves the scheme's mask
    /// shape, commits a vector of that shape, opens against arbitrary public weights, checks the
    /// claim against the direct inner product, verifies, and rejects a wrong claim.
    /// </summary>
    private static void RunWeightedRoundtrip(PolynomialCommitmentProvider provider)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

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
                Assert.IsTrue(verified, "A correctly generated weighted opening must verify.");

                using Scalar wrong = AddOne(claimedValue, pool);
                using FiatShamirTranscript rejectTx = NewTranscript();
                bool rejected = provider.VerifyWeightedSum(commitment, weights, wrong, opening, rejectTx, pool);
                Assert.IsFalse(rejected, "A wrong claimed value must be rejected.");
            }
        }
    }


    /// <summary>Computes <c>Σ_i vector[i]·weights[i]</c> directly over the hypercube, the value a correct weighted opening's claim must equal.</summary>
    private static Scalar ComputeDirectInnerProduct(MultilinearExtension vector, MultilinearExtension weights, BaseMemoryPool pool)
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


    /// <summary>Builds a deterministic pseudo-random multilinear extension of <paramref name="variableCount"/> variables, varied by <paramref name="salt"/> so distinct call sites get distinct evaluation tables.</summary>
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


    /// <summary>Adds the field one to <paramref name="value"/>, returning a fresh <see cref="Scalar"/> distinct from any correct claimed value derived from a well-formed weighted opening.</summary>
    private static Scalar AddOne(Scalar value, BaseMemoryPool pool)
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 0x01;

        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        Add(value.AsReadOnlySpan(), one, owner.Memory.Span[..ScalarSize], Curve);

        return new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
    }


    /// <summary>Builds a deterministic <see cref="ScalarRandomDelegate"/> whose successive draws hash an incrementing counter under <paramref name="seed"/>, so a zero-knowledge provider's randomness is reproducible across a test run.</summary>
    private static ScalarRandomDelegate MakeFixedRandom(int seed)
    {
        int counter = 0;
        return Sample;

        //Derives the next deterministic scalar from SHA-256(seed, counter), incrementing the counter each call.
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


    /// <summary>Creates a fresh transcript under this file's fixed domain label, seeded with no extra context bytes.</summary>
    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>Computes the two-to-one BLAKE3 compression of <paramref name="left"/> concatenated with <paramref name="right"/> into <paramref name="output"/>, this file's Merkle node hash for both the default and the wide-digest providers.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        //Buffered for the widest node the Merkle surface admits and sliced to
        //the actual input widths, so the same compression serves the default
        //and the wide-digest providers; BLAKE3 writes exactly output.Length.
        Span<byte> combined = stackalloc byte[2 * WellKnownMerkleHashParameters.MaximumDigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>The fixed domain-separation seed every provider in this file is derived from.</summary>
    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.Provider.WeightedSum.Test"u8;
}

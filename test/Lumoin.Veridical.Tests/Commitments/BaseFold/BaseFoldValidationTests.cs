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
/// AB.6 validation sweep for the BaseFold polynomial-commitment layer: the
/// properties the round-trip and tamper tests do not directly cover. Determinism
/// (no non-determinism leaks into the transparent prover path), the full
/// classical-security query count exercised once, a larger variable count, and a
/// documented end-to-end usage example. Real BLS12-381 arithmetic and production
/// BLAKE3 throughout.
/// </summary>
[TestClass]
internal sealed class BaseFoldValidationTests
{
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate Invert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly ScalarHashToScalarDelegate HashToScalar = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static readonly MleEvaluateDelegate MleEvaluate = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;

    private const int ScalarSize = 32;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int FastQueryCount = 8;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void CommitIsDeterministic()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 1, pool);

        //Two independent providers built from the same seed must reproduce the
        //identical commitment (Merkle root) — the transparent commit has no
        //hidden randomness.
        using PolynomialCommitmentProvider providerA = NewProvider(FastQueryCount);
        using PolynomialCommitmentProvider providerB = NewProvider(FastQueryCount);

        (PolynomialCommitment commitmentA, PolynomialCommitmentBlind blindA) = providerA.Commit(mle, pool);
        (PolynomialCommitment commitmentB, PolynomialCommitmentBlind blindB) = providerB.Commit(mle, pool);

        using(commitmentA)
        using(blindA)
        using(commitmentB)
        using(blindB)
        {
            Assert.IsTrue(
                commitmentA.AsReadOnlySpan().SequenceEqual(commitmentB.AsReadOnlySpan()),
                "Committing the same MLE under the same code seed must produce identical bytes.");
        }
    }


    [TestMethod]
    public void OpenIsDeterministic()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 2, pool);
        Scalar[] point = BuildPoint(VariableCount, 4, pool);

        try
        {
            using PolynomialCommitmentProvider provider = NewProvider(FastQueryCount);
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript transcriptA = NewTranscript();
                (PolynomialOpening openingA, Scalar valueA) = provider.Open(commitment, blind, mle, point, transcriptA, pool);

                using FiatShamirTranscript transcriptB = NewTranscript();
                (PolynomialOpening openingB, Scalar valueB) = provider.Open(commitment, blind, mle, point, transcriptB, pool);

                using(openingA)
                using(valueA)
                using(openingB)
                using(valueB)
                {
                    Assert.IsTrue(
                        valueA.AsReadOnlySpan().SequenceEqual(valueB.AsReadOnlySpan()),
                        "Opening the same evaluation twice must yield the same claimed value.");
                    Assert.IsTrue(
                        openingA.AsReadOnlySpan().SequenceEqual(openingB.AsReadOnlySpan()),
                        "Opening the same evaluation twice with identical transcripts must produce byte-identical proofs (no non-determinism in the prover path).");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void FullClassicalSecurityQueryCountRoundTrips()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 2;

        //The real 128-bit list-decoding query count (≈273), exercised once on a
        //small polynomial. The round-trip tests use a small count for speed; this
        //confirms the protocol holds at the soundness-driven count.
        int queryCount = WellKnownBaseFoldIoppParameters.ClassicalSecurityDefaultQueryCount;

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 5, pool);
        Scalar[] point = BuildPoint(VariableCount, 6, pool);

        try
        {
            Assert.IsTrue(RoundTrips(mle, point, queryCount, pool), $"A round-trip at the full query count ({queryCount}) must verify.");
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void LargerVariableCountRoundTrips()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 8;

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 7, pool);
        Scalar[] point = BuildPoint(VariableCount, 8, pool);

        try
        {
            Assert.IsTrue(RoundTrips(mle, point, FastQueryCount, pool), "A larger-degree (d = 8) round-trip must verify.");
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void UsageExampleCommitOpenVerify()
    {
        //The intended caller flow for the BaseFold PCS, documented as a test.
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //1. Build a provider from a public code seed, the curve, the IOPP query
        //   count, the Merkle hash, and the field/transcript backends.
        using PolynomialCommitmentProvider provider = BaseFoldPolynomialCommitmentScheme.Create(
            Seed, Curve, FastQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, DigestSizeBytes);

        //2. Build the multilinear polynomial to commit (here, three variables).
        using MultilinearExtension polynomial = BuildRandomMle(3, 9, pool);

        //3. Commit. The commitment is a Merkle root; the blind is a placeholder
        //   (BaseFold is not hiding). Keep the blind for the matching open.
        (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(polynomial, pool);

        //4. Choose an evaluation point (one scalar per variable).
        Scalar[] point = BuildPoint(3, 10, pool);

        try
        {
            using(commitment)
            using(blind)
            {
                //5. Open: prove the evaluation at the point on a live transcript.
                //   The claimed value is returned alongside the opening.
                using FiatShamirTranscript proverTranscript = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, polynomial, point, proverTranscript, pool);

                using(opening)
                using(claimedValue)
                {
                    //6. Verify against the commitment, point, and claimed value on
                    //   a fresh, identically-initialised transcript.
                    using FiatShamirTranscript verifierTranscript = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifierTranscript, pool);

                    Assert.IsTrue(verified, "The documented commit→open→verify usage flow must verify.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    private static bool RoundTrips(MultilinearExtension mle, Scalar[] point, int queryCount, BaseMemoryPool pool)
    {
        using PolynomialCommitmentProvider provider = NewProvider(queryCount);
        (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

        using(commitment)
        using(blind)
        {
            using FiatShamirTranscript proverTranscript = NewTranscript();
            (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, proverTranscript, pool);

            using(opening)
            using(claimedValue)
            {
                //The claimed value matches an independent MLE evaluation.
                using Scalar expected = mle.Evaluate(point, MleEvaluate, pool);
                if(!claimedValue.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan()))
                {
                    return false;
                }

                using FiatShamirTranscript verifierTranscript = NewTranscript();
                return provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifierTranscript, pool);
            }
        }
    }


    private static PolynomialCommitmentProvider NewProvider(int queryCount)
    {
        return BaseFoldPolynomialCommitmentScheme.Create(
            Seed, Curve, queryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, DigestSizeBytes);
    }


    private static MultilinearExtension BuildRandomMle(int variableCount, int salt, BaseMemoryPool pool)
    {
        int evaluationCount = 1 << variableCount;
        using IMemoryOwner<byte> owner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> evals = owner.Memory.Span[..(evaluationCount * ScalarSize)];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < evaluationCount; i++)
        {
            wide.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 131) + (i * 17) + 1);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 7) + (i * 29) + 3);
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
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 53) + (i * 19) + 2);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 23) + (i * 41) + 5);
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


    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.BaseFold.AB6.Validation"u8;
}

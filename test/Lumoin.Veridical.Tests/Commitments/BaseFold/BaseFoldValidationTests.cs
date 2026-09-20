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
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// Validation sweep for the BaseFold polynomial-commitment layer: the
/// properties the round-trip and tamper tests do not directly cover. Determinism
/// (no non-determinism leaks into the transparent prover path), the full
/// classical-security query count exercised once, a larger variable count, and a
/// documented end-to-end usage example. Real BLS12-381 arithmetic and production
/// BLAKE3 throughout.
/// </summary>
[TestClass]
internal sealed class BaseFoldValidationTests
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

    /// <summary>The BLS12-381 hash-to-scalar delegate deriving the foldable code's basis, from the BigInteger reference.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    /// <summary>The independent BigInteger-reference multilinear-extension evaluator used to cross-check the prover's claimed value.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The transcript's fixed-output BLAKE3 hash backend.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The transcript's BLAKE3 XOF (squeeze) backend.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The Merkle two-to-one compression this test's trees use, <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The width in bytes of one BLS12-381 scalar in its canonical representation.</summary>
    private const int ScalarSize = 32;

    /// <summary>The Merkle tree's node/digest width in bytes.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The reduced IOPP query-repetition count the determinism, larger-variable-count and usage-example gates use, since they do not exercise soundness.</summary>
    private const int FastQueryCount = 8;

    /// <summary>The curve every gate in this file runs over: BLS12-381.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Checks that repeated commitments use identical bytes.</summary>
    [TestMethod]
    public void CommitIsDeterministic()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 1, pool);

        //Two independent providers built from the same seed must reproduce the
        //identical commitment (Merkle root) — the transparent commit has no
        //hidden randomness.
        using PolynomialCommitmentProvider providerA = NewProvider(pool, FastQueryCount);
        using PolynomialCommitmentProvider providerB = NewProvider(pool, FastQueryCount);

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


    /// <summary>Checks that repeated openings use identical bytes.</summary>
    [TestMethod]
    public void OpenIsDeterministic()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 3;

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 2, pool);
        Scalar[] point = BuildPoint(VariableCount, 4, pool);

        try
        {
            using PolynomialCommitmentProvider provider = NewProvider(pool, FastQueryCount);
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


    /// <summary>Verifies that a round-trip at the real 128-bit list-decoding query count (≈273) verifies, exercised once on a small polynomial since the other round-trip tests use a reduced count for speed.</summary>
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


    /// <summary>Verifies that a round-trip at the 128-bit one-and-a-half-Johnson preset query count (≈205) verifies, since the opt-in reduced count is a distinct parameter set with its own proof sizes.</summary>
    [TestMethod]
    public void OneAndAHalfJohnsonQueryCountRoundTrips()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 2;

        //The 128-bit one-and-a-half-Johnson preset (≈205 queries): the opt-in
        //reduced count is a distinct parameter set with its own proof sizes, so
        //the protocol is exercised end to end at this count like at the wired
        //default.
        int queryCount = WellKnownBaseFoldIoppParameters.ClassicalSecurityOneAndAHalfJohnsonQueryCount;

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 9, pool);
        Scalar[] point = BuildPoint(VariableCount, 10, pool);

        try
        {
            Assert.IsTrue(RoundTrips(mle, point, queryCount, pool), $"A round-trip at the one-and-a-half-Johnson query count ({queryCount}) must verify.");
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>Checks that tampering is rejected at the johnson query count.</summary>
    [TestMethod]
    public void OneAndAHalfJohnsonQueryCountTamperRejects()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        const int VariableCount = 2;

        int queryCount = WellKnownBaseFoldIoppParameters.ClassicalSecurityOneAndAHalfJohnsonQueryCount;

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 11, pool);
        Scalar[] point = BuildPoint(VariableCount, 12, pool);

        try
        {
            using PolynomialCommitmentProvider provider = NewProvider(pool, queryCount);
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTranscript = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTranscript, pool);

                using(opening)
                using(claimedValue)
                {
                    //Flip a byte inside the opening (a round-polynomial coefficient):
                    //the reduced-count parameter set must reject a tampered proof
                    //exactly like the wired default's count does.
                    MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[0] ^= 0x01;

                    using FiatShamirTranscript verifyTranscript = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTranscript, pool);

                    Assert.IsFalse(verified, $"A tampered opening at the one-and-a-half-Johnson query count ({queryCount}) must be rejected.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>Verifies that a round-trip over an eight-variable polynomial, larger than the other gates' small fixtures, verifies.</summary>
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


    /// <summary>Demonstrates the caller-funded commit, open and verify flow.</summary>
    [TestMethod]
    public void UsageExampleCommitOpenVerify()
    {
        //The intended caller flow for the BaseFold PCS, documented as a test.
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //1. Build a provider from a public code seed, the curve, the IOPP query
        //   count, the Merkle hash, and the field/transcript backends.
        using PolynomialCommitmentProvider provider = BaseFoldPolynomialCommitmentScheme.Create(
            Seed, Curve, FastQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, pool, DigestSizeBytes);

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


    /// <summary>Checks a provider commit, opening and verification round trip.</summary>
    private static bool RoundTrips(MultilinearExtension mle, Scalar[] point, int queryCount, BaseMemoryPool pool)
    {
        using PolynomialCommitmentProvider provider = NewProvider(pool, queryCount);
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


    /// <summary>The variable count producing two fold layers, so the priced opening carries the fold roots and paths that a digest width actually sizes.</summary>
    private const int CapVariableCount = 3;


    /// <summary>
    /// Bounds the digest width the opening codec will price. The query phase
    /// recomputes a leaf into a stack buffer reserved at
    /// <see cref="WellKnownMerkleHashParameters.MaximumDigestSizeBytes"/>, so a
    /// length computed for a wider digest describes an opening that could never
    /// be checked. The codec states the bound its sibling codecs state, and
    /// refuses rather than returning a number nothing can use.
    /// </summary>
    [TestMethod]
    public void OpeningLengthRefusesADigestAboveTheVerifierCap()
    {
        FoldableCodeParameters parameters = WellKnownFoldableCodeParameters.CreateClassicalSecurity(CapVariableCount, Curve);

        int atCap = BaseFoldEvaluationProofSerialization.ComputeLength(
            parameters,
            FastQueryCount,
            WellKnownMerkleHashParameters.MaximumDigestSizeBytes,
            BaseFoldOpeningMode.Plain);

        Assert.IsGreaterThan(0, atCap, "The widest digest the verifier reserves for must stay a priceable configuration.");

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => BaseFoldEvaluationProofSerialization.ComputeLength(
                parameters,
                FastQueryCount,
                WellKnownMerkleHashParameters.MaximumDigestSizeBytes + 1,
                BaseFoldOpeningMode.Plain),
            "A digest above the cap must be refused rather than priced into a length nothing can check.");
    }


    /// <summary>Builds the commitment provider using the caller's pool.</summary>
    /// <param name="pool">The pool supplied by the test.</param>
    /// <param name="queryCount">The query repetition count.</param>
    private static PolynomialCommitmentProvider NewProvider(BaseMemoryPool pool, int queryCount)
    {
        return BaseFoldPolynomialCommitmentScheme.Create(
            Seed, Curve, queryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, HashToScalar, pool, DigestSizeBytes);
    }


    /// <summary>Builds a deterministic pseudo-random multilinear extension of <paramref name="variableCount"/> variables, varied by <paramref name="salt"/> so distinct call sites get distinct evaluation tables.</summary>
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


    /// <summary>Builds a deterministic pseudo-random evaluation point of <paramref name="variableCount"/> scalars, varied by <paramref name="salt"/> so distinct call sites get distinct points.</summary>
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


    /// <summary>Disposes every coordinate scalar of a point built by <see cref="BuildPoint"/>.</summary>
    private static void DisposePoint(Scalar[] point)
    {
        foreach(Scalar coordinate in point)
        {
            coordinate.Dispose();
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


    /// <summary>Computes the two-to-one BLAKE3 compression of <paramref name="left"/> concatenated with <paramref name="right"/> into <paramref name="output"/>, this file's Merkle node hash.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>The fixed domain-separation seed the foldable code is derived from in every gate.</summary>
    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.BaseFold.Validation"u8;
}

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
/// Truncation robustness of the serialized full-ZK BaseFold opening: the
/// total-length guard in <c>BaseFoldEvaluationProofSerialization.FromBytes</c>
/// turns every truncated buffer into an <see cref="ArgumentException"/> that
/// the provider's verify delegate maps to a <see langword="false"/> verdict —
/// attacker-supplied bytes must never surface an exception to the caller. Cuts
/// land one byte short of the full length, inside the mask-opening section
/// (com(C*)'s root / σ / σ_F), and inside the nested hiding weighted opening.
/// </summary>
[TestClass]
internal sealed class ZkBaseFoldOpeningTruncationTests
{
    /// <summary>The BLS12-381 scalar-field addition delegate under test.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bls12Curve381.Add;

    /// <summary>The BLS12-381 scalar-field subtraction delegate under test.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bls12Curve381.Subtract;

    /// <summary>The BLS12-381 scalar-field multiplication delegate under test.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bls12Curve381.Multiply;

    /// <summary>The BLS12-381 scalar-field inversion delegate under test.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bls12Curve381.Invert;

    /// <summary>The BLS12-381 scalar-field reduction delegate from the BigInteger-backed reference implementation.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The BLS12-381 hash-to-scalar delegate from the BigInteger-backed reference implementation.</summary>
    private static ScalarHashToScalarDelegate HashToScalar { get; } = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();

    /// <summary>The BLS12-381 scalar-field random-sampling delegate from the BigInteger-backed reference implementation, drawing the zero-knowledge mask's blinding.</summary>
    private static ScalarRandomDelegate Random { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();

    /// <summary>The production BLAKE3 Fiat-Shamir hash delegate driving both the prover's and verifier's transcripts.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The production BLAKE3 Fiat-Shamir squeeze delegate drawing challenges from the transcript.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The Merkle two-to-one compression delegate, backed by <see cref="HashTwoToOne"/>.</summary>
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    /// <summary>The byte width of one BLS12-381 scalar in this test's canonical scratch buffers.</summary>
    private const int ScalarSize = 32;

    /// <summary>The default Merkle digest width these gates hash at.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>The BaseFold query count these truncation gates commit and open at.</summary>
    private const int TestQueryCount = 12;

    /// <summary>The real (unlifted) variable count of the witness these gates commit and open.</summary>
    private const int RealVariableCount = 1;

    /// <summary>The minimal budget-meeting lift width for a one-variable witness at <see cref="TestQueryCount"/> = 12 (GetMinimumExtraVariableCount).</summary>
    private const int ExtraVariableCount = 6;

    /// <summary>The curve parameter set selecting the BLS12-381 instantiation throughout this class.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;


    /// <summary>Verifies that an opening truncated by exactly one byte — everything present except the final byte of the nested weighted opening's last authentication path — is rejected with a false verdict rather than an exception.</summary>
    [TestMethod]
    public void OpeningTruncatedByOneByteIsRejectedWithoutThrowing()
    {
        //The tightest cut: everything present except the final byte of the
        //nested weighted opening's last authentication path.
        AssertTruncatedOpeningRejected(static fullLength => fullLength - 1);
    }


    /// <summary>Verifies that an opening truncated inside the mask section — cut after com(C*)'s root and σ, so σ_F and the whole nested weighted opening are missing — is rejected with a false verdict rather than an exception.</summary>
    [TestMethod]
    public void OpeningTruncatedInsideTheMaskSectionIsRejectedWithoutThrowing()
    {
        //Cut after com(C*)'s root and σ: σ_F and the whole nested weighted
        //opening are missing.
        AssertTruncatedOpeningRejected(static _ => MaskSectionOffset() + DigestSizeBytes + ScalarSize);
    }


    /// <summary>Verifies that an opening truncated halfway into the nested hiding weighted opening that binds the mask's terminal evaluation is rejected with a false verdict rather than an exception.</summary>
    [TestMethod]
    public void OpeningTruncatedInsideTheNestedWeightedOpeningIsRejectedWithoutThrowing()
    {
        //Cut halfway into the nested hiding weighted opening that binds the
        //mask's terminal evaluation.
        AssertTruncatedOpeningRejected(static fullLength =>
        {
            int nestedOpeningOffset = MaskSectionOffset() + DigestSizeBytes + (2 * ScalarSize);

            return nestedOpeningOffset + ((fullLength - nestedOpeningOffset) / 2);
        });
    }


    /// <summary>Computes the truncation length to test, given the full serialized opening's length.</summary>
    private delegate int TruncationLengthSelector(int fullLength);


    /// <summary>
    /// Checks that an opening truncated to the selected length is rejected: commits
    /// and opens correctly, sanity-checks that the intact opening verifies, then
    /// replays verification with the opening cut to the selected length and asserts
    /// a clean false verdict.
    /// </summary>
    private static void AssertTruncatedOpeningRejected(TruncationLengthSelector truncatedLengthSelector)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            Random, HashToScalar, ExtraVariableCount, pool);

        using MultilinearExtension witness = BuildDeterministicMle(RealVariableCount, salt: 41, pool);
        Scalar[] point = BuildPoint(RealVariableCount, salt: 43, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(witness, pool);

            using(commitment)
            {
                using(blind)
                {
                    using FiatShamirTranscript openTx = NewTranscript();
                    (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, witness, point, openTx, pool);

                    using(opening)
                    {
                        using(claimedValue)
                        {
                            using FiatShamirTranscript honestTx = NewTranscript();
                            Assert.IsTrue(
                                provider.VerifyEvaluation(commitment, point, claimedValue, opening, honestTx, pool),
                                "The intact opening must verify (the truncation rejection would otherwise be vacuous).");

                            int fullLength = opening.AsReadOnlySpan().Length;
                            int truncatedLength = truncatedLengthSelector(fullLength);
                            Assert.IsTrue(
                                truncatedLength > 0 && truncatedLength < fullLength,
                                $"The cut ({truncatedLength} of {fullLength} bytes) must remove bytes while leaving a non-empty buffer.");

                            using PolynomialOpening truncated = PolynomialOpening.FromBytes(
                                opening.AsReadOnlySpan()[..truncatedLength], Curve, CommitmentScheme.BaseFold, pool);

                            using FiatShamirTranscript verifyTx = NewTranscript();
                            Assert.IsFalse(
                                provider.VerifyEvaluation(commitment, point, claimedValue, truncated, verifyTx, pool),
                                $"A truncated opening ({truncatedLength} of {fullLength} bytes) must be rejected with a false verdict.");
                        }
                    }
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    /// <summary>Returns the byte offset where the mask section begins: the lift-only hiding proof ends there, and the v3 layout opens with com(C*)'s root, then σ, then σ_F, then the nested hiding weighted opening.</summary>
    private static int MaskSectionOffset()
    {
        return ZkBaseFoldPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
            RealVariableCount, ExtraVariableCount, Curve, TestQueryCount, DigestSizeBytes);
    }


    /// <summary>Builds a deterministic pseudo-random multilinear extension over the given variable count, seeded by <paramref name="salt"/> so different salts produce different but reproducible evaluation tables.</summary>
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


    /// <summary>Builds a deterministic pseudo-random evaluation point over the given variable count, seeded by <paramref name="salt"/> so different salts produce different but reproducible points.</summary>
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


    /// <summary>Disposes every coordinate scalar in a point built by <see cref="BuildPoint"/>.</summary>
    private static void DisposePoint(Scalar[] point)
    {
        foreach(Scalar coordinate in point)
        {
            coordinate.Dispose();
        }
    }


    /// <summary>Initializes a fresh Fiat-Shamir transcript under the BaseFold evaluation domain label, for either a prover's or a verifier's independent run.</summary>
    private static FiatShamirTranscript NewTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownBaseFoldEvaluationParameters.TranscriptDomainLabel),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            BaseMemoryPool.Shared);
    }


    /// <summary>Computes the Merkle two-to-one compression of <paramref name="left"/> and <paramref name="right"/> via BLAKE3.</summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>The domain-separation seed this class's provider is created with.</summary>
    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.ZkBaseFold.OpeningTruncation.Test"u8;
}

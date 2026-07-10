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
    public void OpeningTruncatedByOneByteIsRejectedWithoutThrowing()
    {
        //The tightest cut: everything present except the final byte of the
        //nested weighted opening's last authentication path.
        AssertTruncatedOpeningRejected(static fullLength => fullLength - 1);
    }


    [TestMethod]
    public void OpeningTruncatedInsideTheMaskSectionIsRejectedWithoutThrowing()
    {
        //Cut after com(C*)'s root and σ: σ_F and the whole nested weighted
        //opening are missing.
        AssertTruncatedOpeningRejected(static _ => MaskSectionOffset() + DigestSizeBytes + ScalarSize);
    }


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


    private delegate int TruncationLengthSelector(int fullLength);


    //Commits and opens honestly, sanity-checks the intact opening verifies,
    //then replays the verify with the opening cut to the selected length and
    //asserts a clean false verdict.
    private static void AssertTruncatedOpeningRejected(TruncationLengthSelector truncatedLengthSelector)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
            Random, HashToScalar, ExtraVariableCount);

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


    //The mask section starts where the lift-only hiding proof ends; the v3
    //layout opens with com(C*)'s root, then σ, then σ_F, then the nested
    //hiding weighted opening.
    private static int MaskSectionOffset()
    {
        return ZkBaseFoldPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
            RealVariableCount, ExtraVariableCount, Curve, TestQueryCount, DigestSizeBytes);
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


    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.ZkBaseFold.W27b.OpeningTruncation.Test"u8;
}

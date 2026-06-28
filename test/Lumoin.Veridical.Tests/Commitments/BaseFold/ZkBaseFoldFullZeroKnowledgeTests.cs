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
/// ZK.2b.2 — the full zero-knowledge BaseFold evaluation (the CFS-2017 sumcheck
/// mask on top of the ZK.2b.1 dimension lift), driven end to end through
/// <see cref="ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge"/>.
/// The lift closes the query and base-oracle channels; the sumcheck mask closes
/// the round-polynomial channel, so the opening is genuinely simulatable.
/// </summary>
/// <remarks>
/// <para>
/// These gate correctness — that masking the round polynomials does not perturb
/// the proven value <c>f(z)</c> and that the masked sumcheck still verifies — and
/// the binding of the mask side (a tampered <c>σ</c>, mask root, or mask base
/// oracle, like a tampered witness byte, must be rejected). The
/// bounded-independence hiding budget that makes the revealed positions
/// witness-independent is the separate statistical claim of ZK.4, not asserted
/// here. Real BLS12-381 arithmetic and production BLAKE3 throughout; the BaseFold
/// commitment test surface is uniformly BLS12-381.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ZkBaseFoldFullZeroKnowledgeTests
{
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly ScalarInvertDelegate Invert = TestScalarBackends.Bls12Curve381.Invert;
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static readonly ScalarHashToScalarDelegate HashToScalar = Bls12Curve381BigIntegerScalarReference.GetHashToScalar();
    private static readonly ScalarRandomDelegate Random = Bls12Curve381BigIntegerScalarReference.GetRandom();
    private static readonly MleEvaluateDelegate MleEvaluate = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;

    private const int ScalarSize = 32;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int TestQueryCount = 12;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    //Each (d, t) row is the minimal budget-meeting lift for its witness size at
    //TestQueryCount = 12 (GetMinimumExtraVariableCount; the provider refuses
    //under-budget configurations since the hiding-budget enforcement landed).
    [TestMethod]
    [DataRow(1, 6)]
    [DataRow(2, 5)]
    [DataRow(3, 4)]
    [DataRow(4, 3)]
    public void FullZeroKnowledgeOpeningRecoversWitnessValueAndVerifies(int realVariableCount, int extraVariableCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider(extraVariableCount);

        Assert.IsTrue(provider.IsHiding, "The full ZK BaseFold provider must report itself as hiding.");

        using MultilinearExtension witness = BuildRandomMle(realVariableCount, salt: 21, pool);
        Scalar[] point = BuildPoint(realVariableCount, salt: 23, pool);

        try
        {
            using Scalar expected = witness.Evaluate(point, MleEvaluate, pool);

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
                            //The sumcheck mask must not perturb the proven value: the
                            //lift fixes the extra coordinates to zero and the mask only
                            //blends the round polynomials, so it is still f(z).
                            Assert.IsTrue(
                                claimedValue.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan()),
                                $"The full-ZK opening must recover f(z) for d = {realVariableCount}, t = {extraVariableCount}.");

                            //The serialized opening must match the size helper exactly.
                            int expectedSize = ZkBaseFoldPolynomialCommitmentScheme.GetFullZeroKnowledgeEvaluationProofSizeBytes(
                                realVariableCount, extraVariableCount, Curve, TestQueryCount, DigestSizeBytes);
                            Assert.AreEqual(expectedSize, opening.AsReadOnlySpan().Length, "The full-ZK opening length must match the size helper.");

                            using FiatShamirTranscript verifyTx = NewTranscript();
                            Assert.IsTrue(
                                provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                                $"An honest full-ZK commit→open→verify must round-trip for d = {realVariableCount}, t = {extraVariableCount}.");

                            using Scalar wrong = AddOne(claimedValue, pool);
                            using FiatShamirTranscript rejectTx = NewTranscript();
                            Assert.IsFalse(
                                provider.VerifyEvaluation(commitment, point, wrong, opening, rejectTx, pool),
                                "A wrong claimed value must be rejected.");
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


    [TestMethod]
    public void FullZeroKnowledgeOpeningIsLargerThanTheLiftOnlyOpening()
    {
        //The mask side (σ, mask roots, mask base oracle, mask query openings)
        //roughly doubles the opening; it must be strictly larger than the
        //lift-only hiding opening at the same shape.
        //t = 4 is the minimal budget-meeting lift for d = 3 at TestQueryCount = 12.
        const int RealVariableCount = 3;
        const int ExtraVariableCount = 4;

        int liftOnly = ZkBaseFoldPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
            RealVariableCount, ExtraVariableCount, Curve, TestQueryCount, DigestSizeBytes);
        int full = ZkBaseFoldPolynomialCommitmentScheme.GetFullZeroKnowledgeEvaluationProofSizeBytes(
            RealVariableCount, ExtraVariableCount, Curve, TestQueryCount, DigestSizeBytes);

        Assert.IsGreaterThan(liftOnly, full, "The full-ZK opening must be larger than the lift-only opening (it carries the mask side).");
    }


    [TestMethod]
    public void TamperedMaskSumIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        //t = 4 is the minimal budget-meeting lift for d = 3 at TestQueryCount = 12.
        const int RealVariableCount = 3;
        const int ExtraVariableCount = 4;
        using PolynomialCommitmentProvider provider = NewProvider(ExtraVariableCount);

        using MultilinearExtension witness = BuildRandomMle(RealVariableCount, salt: 31, pool);
        Scalar[] point = BuildPoint(RealVariableCount, salt: 33, pool);

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
                            //The mask side begins immediately after the witness (hiding)
                            //section, whose length is the lift-only opening size; the v3
                            //layout opens with com(C*)'s root, then σ, then σ_F. Flipping
                            //a σ byte changes the verifier's recomputed ρ, breaking the
                            //masked sumcheck chain.
                            int maskOffset = ZkBaseFoldPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
                                RealVariableCount, ExtraVariableCount, Curve, TestQueryCount, DigestSizeBytes);
                            MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[maskOffset + DigestSizeBytes] ^= 0x01;

                            using FiatShamirTranscript verifyTx = NewTranscript();
                            Assert.IsFalse(
                                provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                                "A tampered mask sum σ must be rejected.");
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


    [TestMethod]
    public void TamperedMaskRootIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        //t = 4 is the minimal budget-meeting lift for d = 3 at TestQueryCount = 12.
        const int RealVariableCount = 3;
        const int ExtraVariableCount = 4;
        using PolynomialCommitmentProvider provider = NewProvider(ExtraVariableCount);

        using MultilinearExtension witness = BuildRandomMle(RealVariableCount, salt: 61, pool);
        Scalar[] point = BuildPoint(RealVariableCount, salt: 63, pool);

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
                            //com(C*)'s root is the mask section's first field. Corrupting
                            //it changes the pre-ρ absorb AND fails the nested weighted
                            //opening's authentication against that root.
                            int maskCommitmentRootOffset = ZkBaseFoldPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
                                RealVariableCount, ExtraVariableCount, Curve, TestQueryCount, DigestSizeBytes);
                            MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[maskCommitmentRootOffset] ^= 0x01;

                            using FiatShamirTranscript verifyTx = NewTranscript();
                            Assert.IsFalse(
                                provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                                "A tampered mask commitment root must be rejected.");
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


    [TestMethod]
    public void TamperedFillerSumIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        //t = 4 is the minimal budget-meeting lift for d = 3 at TestQueryCount = 12.
        const int RealVariableCount = 3;
        const int ExtraVariableCount = 4;
        using PolynomialCommitmentProvider provider = NewProvider(ExtraVariableCount);

        using MultilinearExtension witness = BuildRandomMle(RealVariableCount, salt: 71, pool);
        Scalar[] point = BuildPoint(RealVariableCount, salt: 73, pool);

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
                            //σ_F follows com(C*)'s root and σ. Corrupting it shifts the
                            //derived weighted claim s(r) + σ_F (and the pre-ρ absorb), so
                            //the nested weighted opening must fail against it.
                            int maskStart = ZkBaseFoldPolynomialCommitmentScheme.GetZeroKnowledgeEvaluationProofSizeBytes(
                                RealVariableCount, ExtraVariableCount, Curve, TestQueryCount, DigestSizeBytes);
                            int fillerSumOffset = maskStart + DigestSizeBytes + ScalarSize;
                            MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[fillerSumOffset] ^= 0x01;

                            using FiatShamirTranscript verifyTx = NewTranscript();
                            Assert.IsFalse(
                                provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                                "A tampered filler sum σ_F must be rejected.");
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


    [TestMethod]
    public void TamperedNestedWeightedOpeningIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        //t = 4 is the minimal budget-meeting lift for d = 3 at TestQueryCount = 12.
        const int RealVariableCount = 3;
        const int ExtraVariableCount = 4;
        using PolynomialCommitmentProvider provider = NewProvider(ExtraVariableCount);

        using MultilinearExtension witness = BuildRandomMle(RealVariableCount, salt: 81, pool);
        Scalar[] point = BuildPoint(RealVariableCount, salt: 83, pool);

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
                            //The nested weighted opening is the final section; its last
                            //byte sits inside a query authentication path, so flipping it
                            //must fail the nested IOPP authentication.
                            MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[^1] ^= 0x01;

                            using FiatShamirTranscript verifyTx = NewTranscript();
                            Assert.IsFalse(
                                provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                                "A tampered nested weighted opening must be rejected.");
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


    [TestMethod]
    public void TamperedRoundPolynomialIsRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        //t = 4 is the minimal budget-meeting lift for d = 3 at TestQueryCount = 12.
        const int RealVariableCount = 3;
        const int ExtraVariableCount = 4;
        using PolynomialCommitmentProvider provider = NewProvider(ExtraVariableCount);

        using MultilinearExtension witness = BuildRandomMle(RealVariableCount, salt: 41, pool);
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
                            //Flip a byte in the first (blended) round polynomial.
                            MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[0] ^= 0x01;

                            using FiatShamirTranscript verifyTx = NewTranscript();
                            Assert.IsFalse(
                                provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                                "A tampered round polynomial must be rejected.");
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


    [TestMethod]
    public void TwoOpeningsOfTheSameStatementDiffer()
    {
        //The mask multilinear and the fold-layer salts are fresh per open, so two
        //honest openings of the same (commitment, point) are different byte strings
        //— the ZK-flavoured expectation that an opening is not a deterministic
        //function of the witness.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        //t = 4 is the minimal budget-meeting lift for d = 3 at TestQueryCount = 12.
        const int RealVariableCount = 3;
        const int ExtraVariableCount = 4;
        using PolynomialCommitmentProvider provider = NewProvider(ExtraVariableCount);

        using MultilinearExtension witness = BuildRandomMle(RealVariableCount, salt: 51, pool);
        Scalar[] point = BuildPoint(RealVariableCount, salt: 53, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(witness, pool);

            using(commitment)
            {
                using(blind)
                {
                    using FiatShamirTranscript firstTx = NewTranscript();
                    (PolynomialOpening first, Scalar firstValue) = provider.Open(commitment, blind, witness, point, firstTx, pool);

                    using FiatShamirTranscript secondTx = NewTranscript();
                    (PolynomialOpening second, Scalar secondValue) = provider.Open(commitment, blind, witness, point, secondTx, pool);

                    using(first)
                    {
                        using(firstValue)
                        {
                            using(second)
                            {
                                using(secondValue)
                                {
                                    Assert.IsTrue(
                                        firstValue.AsReadOnlySpan().SequenceEqual(secondValue.AsReadOnlySpan()),
                                        "Both openings must still prove the same value f(z).");
                                    Assert.IsFalse(
                                        first.AsReadOnlySpan().SequenceEqual(second.AsReadOnlySpan()),
                                        "Two full-ZK openings of the same statement must differ (fresh mask and salts).");
                                }
                            }
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


    private static PolynomialCommitmentProvider NewProvider(int extraVariableCount)
    {
        return ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random, HashToScalar, extraVariableCount);
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


    private static Scalar AddOne(Scalar value, BaseMemoryPool pool)
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        one.Clear();
        one[^1] = 0x01;

        IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
        Add(value.AsReadOnlySpan(), one, owner.Memory.Span[..ScalarSize], Curve);

        return new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
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


    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.ZkBaseFold.ZK2b2.FullZeroKnowledge.Test"u8;
}

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
/// ZK.2b route-A prototype (the dimension-lift design fork, recorded in
/// <c>BASEFOLD.md</c>, <em>Zero-knowledge BaseFold</em>):
/// de-risks the dimension-lifting realisation of the zero-knowledge BaseFold
/// evaluation. The query/π₀ leakage is closed by committing the real
/// <c>d</c>-variable witness <c>f</c> as the <c>Y = 0</c> slice of a
/// <c>(d + t)</c>-variable polynomial <c>f'</c> whose <c>Y ≠ 0</c> evaluations are
/// pure mask randomness, and always evaluating at the protocol-fixed point
/// <c>(z, 0^t)</c>.
/// </summary>
/// <remarks>
/// <para>
/// The keystone correctness claim this prototype establishes is the
/// <em>evaluation invariance</em>: by the multilinear <c>eq</c> factorisation, a
/// point whose extra-variable coordinates are zero selects exactly the <c>Y = 0</c>
/// slice, so <c>f'(z, 0^t) = f(z)</c> for <em>any</em> mask in the <c>Y ≠ 0</c>
/// block — the mask cannot perturb the proven value. Because the extra coordinates
/// are fixed to zero by the protocol (not chosen after commit), this sidesteps the
/// §3.2 obstruction that masking <c>f</c>'s own coefficients is unsound for a
/// commit-then-open PCS.
/// </para>
/// <para>
/// Crucially this needs <strong>no</strong> change to <see cref="FoldableCode"/> and
/// <strong>no</strong> new minimum-distance proof: <c>f'</c> is an honest codeword of
/// the same random foldable code at layer count <c>d + t</c>, so BaseFold's
/// knowledge soundness (paper Theorem 4) and the §3 distance bound apply unchanged.
/// The mask randomness in the <c>Y ≠ 0</c> block spreads through the linear encoder
/// to randomise the queried codeword positions; the bounded-independence hiding
/// budget (mask DOF ≥ query count) is a separate, statistical claim validated in
/// ZK.4, not here. This test is the correctness gate the full
/// <c>ProveZeroKnowledge</c> path will build on.
/// </para>
/// <para>
/// The lift is driven end to end through the shipped hiding provider
/// (<see cref="ZkBaseFoldPolynomialCommitmentScheme"/>, ZK.1), so it exercises the
/// salted commitment and the masked codeword together. Real BLS12-381 arithmetic
/// and production BLAKE3 throughout.
/// </para>
/// </remarks>
[TestClass]
internal sealed class ZkBaseFoldEvaluationLiftPrototypeTests
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


    [TestMethod]
    [DataRow(1, 2)]
    [DataRow(2, 3)]
    [DataRow(3, 2)]
    public void LiftedEvaluationRecoversWitnessValueAndVerifies(int realVariableCount, int extraVariableCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider();

        int liftedVariableCount = realVariableCount + extraVariableCount;
        int realEvaluations = 1 << realVariableCount;
        int liftedEvaluations = 1 << liftedVariableCount;

        //f: the real d-variable witness. f': the (d+t)-variable lift whose first
        //2^d evaluations (the Y = 0 slice — extra-variable high bits all zero) are
        //f's, and whose remaining evaluations are pure mask randomness.
        using IMemoryOwner<byte> realOwner = pool.Rent(realEvaluations * ScalarSize);
        Span<byte> realTable = realOwner.Memory.Span[..(realEvaluations * ScalarSize)];
        FillReduced(realTable, realEvaluations, salt: 1);

        using IMemoryOwner<byte> liftedOwner = pool.Rent(liftedEvaluations * ScalarSize);
        Span<byte> liftedTable = liftedOwner.Memory.Span[..(liftedEvaluations * ScalarSize)];
        realTable.CopyTo(liftedTable[..(realEvaluations * ScalarSize)]);
        for(int i = realEvaluations; i < liftedEvaluations; i++)
        {
            //The Y ≠ 0 block: pure entropy mask, the part that randomises the
            //committed codeword's queried positions.
            _ = Random(liftedTable.Slice(i * ScalarSize, ScalarSize), Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
        }

        using MultilinearExtension real = MultilinearExtension.FromEvaluations(realTable, realVariableCount, Curve, pool);
        using MultilinearExtension lifted = MultilinearExtension.FromEvaluations(liftedTable, liftedVariableCount, Curve, pool);

        //z: a random real point. liftedPoint = (z, 0^t): the last t coordinates,
        //which bind the high table bits, are fixed to the field zero, selecting the
        //Y = 0 slice so f'(z, 0^t) = f(z).
        Scalar[] realPoint = BuildPoint(realVariableCount, salt: 5, pool);
        Scalar[] liftedPoint = AppendZeros(realPoint, extraVariableCount, pool);

        try
        {
            using Scalar expected = real.Evaluate(realPoint, MleEvaluate, pool);

            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(lifted, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, lifted, liftedPoint, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    Assert.IsTrue(
                        claimedValue.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan()),
                        $"Lifted evaluation f'(z, 0^{extraVariableCount}) must equal the real witness value f(z) for d = {realVariableCount}.");

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, liftedPoint, claimedValue, opening, verifyTx, pool);

                    Assert.IsTrue(verified, $"The lifted hiding opening must verify for d = {realVariableCount}, t = {extraVariableCount}.");
                }
            }
        }
        finally
        {
            DisposePoint(realPoint);
            DisposePoint(liftedPoint);
        }
    }


    [TestMethod]
    //Each (d, t) row is the minimal budget-meeting lift for its witness size at
    //TestQueryCount = 12: the provider enforces the hiding budget on commit and
    //open, so the rows must clear it (GetMinimumExtraVariableCount).
    [DataRow(1, 6)]
    [DataRow(2, 5)]
    [DataRow(3, 4)]
    public void ProviderInternalLiftRecoversWitnessValueAndVerifies(int realVariableCount, int extraVariableCount)
    {
        //The ZK.2b provider does the lift internally: the consumer commits and
        //opens an ordinary d-variable witness at a d-coordinate point, and the
        //(d + t)-variable masked codeword is entirely behind the surface.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewZeroKnowledgeProvider(extraVariableCount);

        Assert.IsTrue(provider.IsHiding, "The ZK BaseFold provider must report itself as hiding.");

        int realEvaluations = 1 << realVariableCount;
        using IMemoryOwner<byte> realOwner = pool.Rent(realEvaluations * ScalarSize);
        Span<byte> realTable = realOwner.Memory.Span[..(realEvaluations * ScalarSize)];
        FillReduced(realTable, realEvaluations, salt: 13);

        using MultilinearExtension witness = MultilinearExtension.FromEvaluations(realTable, realVariableCount, Curve, pool);
        Scalar[] point = BuildPoint(realVariableCount, salt: 17, pool);

        try
        {
            using Scalar expected = witness.Evaluate(point, MleEvaluate, pool);

            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(witness, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, witness, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    Assert.IsTrue(
                        claimedValue.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan()),
                        $"The internally-lifted opening must recover f(z) for d = {realVariableCount}, t = {extraVariableCount}.");

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    Assert.IsTrue(
                        provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool),
                        $"The internally-lifted hiding opening must verify for d = {realVariableCount}, t = {extraVariableCount}.");

                    using Scalar wrong = AddOne(claimedValue, pool);
                    using FiatShamirTranscript rejectTx = NewTranscript();
                    Assert.IsFalse(
                        provider.VerifyEvaluation(commitment, point, wrong, opening, rejectTx, pool),
                        "A wrong claimed value must be rejected.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    private static PolynomialCommitmentProvider NewProvider()
    {
        return ZkBaseFoldPolynomialCommitmentScheme.Create(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random, HashToScalar);
    }


    private static PolynomialCommitmentProvider NewZeroKnowledgeProvider(int extraVariableCount)
    {
        return ZkBaseFoldPolynomialCommitmentScheme.CreateZeroKnowledge(
            Seed, Curve, TestQueryCount, Merkle, Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random, HashToScalar, extraVariableCount);
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


    private static void FillReduced(Span<byte> table, int count, int salt)
    {
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < count; i++)
        {
            wide.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 137) + (i * 19) + 1);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 11) + (i * 31) + 3);
            Reduce(wide, table.Slice(i * ScalarSize, ScalarSize), Curve);
        }
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


    //Appends extraCount field-zero coordinates after the real point: the lifted
    //evaluation point (z, 0^t). A canonical field zero is the all-zero scalar.
    private static Scalar[] AppendZeros(Scalar[] realPoint, int extraCount, BaseMemoryPool pool)
    {
        var lifted = new Scalar[realPoint.Length + extraCount];
        for(int i = 0; i < realPoint.Length; i++)
        {
            IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
            realPoint[i].AsReadOnlySpan().CopyTo(owner.Memory.Span[..ScalarSize]);
            lifted[i] = new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
        }

        for(int i = 0; i < extraCount; i++)
        {
            IMemoryOwner<byte> owner = pool.Rent(ScalarSize);
            owner.Memory.Span[..ScalarSize].Clear();
            lifted[realPoint.Length + i] = new Scalar(owner, Curve, WellKnownAlgebraicTags.ScalarFor(Curve));
        }

        return lifted;
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


    private static ReadOnlySpan<byte> Seed => "Lumoin.Veridical.ZkBaseFold.ZK2b.LiftPrototype.Test"u8;
}

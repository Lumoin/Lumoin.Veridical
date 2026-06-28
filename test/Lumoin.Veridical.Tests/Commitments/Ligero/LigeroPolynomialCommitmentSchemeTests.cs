using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Commitments.Ligero;

/// <summary>
/// End-to-end gate for <see cref="LigeroPolynomialCommitmentScheme"/> behind the
/// scheme-agnostic <see cref="PolynomialCommitmentProvider"/> surface: commit →
/// open → verify round-trips over real BN254 arithmetic and production BLAKE3,
/// the opened claimed value equals the multilinear extension evaluated at the
/// point (so the proximity/evaluation tensor split is correct), and a tampered
/// opening (in the proximity response, an opened column, or a Merkle path), a
/// tampered commitment, or a wrong claimed value are each rejected.
/// </summary>
[TestClass]
internal sealed class LigeroPolynomialCommitmentSchemeTests
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int TestQueryCount = 12;

    private static readonly CurveParameterSet Curve = CurveParameterSet.Bn254;

    private static readonly ScalarAddDelegate Add = Bn254BigIntegerScalarReference.GetAdd();
    private static readonly ScalarSubtractDelegate Subtract = Bn254BigIntegerScalarReference.GetSubtract();
    private static readonly ScalarMultiplyDelegate Multiply = Bn254BigIntegerScalarReference.GetMultiply();
    private static readonly ScalarInvertDelegate Invert = Bn254BigIntegerScalarReference.GetInvert();
    private static readonly ScalarReduceDelegate Reduce = Bn254BigIntegerScalarReference.GetReduce();
    private static readonly MleEvaluateDelegate MleEvaluate = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static readonly FiatShamirHashDelegate Hash = FiatShamirBlake3Reference.GetHash();
    private static readonly FiatShamirSqueezeDelegate Squeeze = FiatShamirBlake3Reference.GetSqueeze();
    private static readonly MerkleHashDelegate Merkle = HashTwoToOne;


    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    [DataRow(5)]
    public void CommitOpenVerifyRoundTrips(int variableCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider();

        using MultilinearExtension mle = BuildRandomMle(variableCount, 1, pool);
        Scalar[] point = BuildPoint(variableCount, 5, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                Assert.AreEqual(CommitmentScheme.Ligero, commitment.Scheme, "Commitment must be stamped Ligero.");

                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    using Scalar expected = mle.Evaluate(point, MleEvaluate, pool);
                    Assert.IsTrue(
                        claimedValue.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan()),
                        $"Opened claimed value must equal f(z) for n = {variableCount} (tensor split correct).");

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool);

                    Assert.IsTrue(verified, $"An honest commit→open→verify must round-trip for n = {variableCount}.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    [DataRow(0, "proximity response u")]
    [DataRow(256, "opened column")]
    [DataRow(384, "Merkle path")]
    public void TamperedOpeningIsRejected(int byteOffset, string region)
    {
        //n = 4: ColumnCount = RowCount = 4, the opening is
        //[u:128 | v:128 | per-query(column:128 | path:128)], so offset 0 hits u,
        //256 the first opened column, 384 its path.
        const int VariableCount = 4;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider();

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 2, pool);
        Scalar[] point = BuildPoint(VariableCount, 6, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[byteOffset] ^= 0x01;

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool);

                    Assert.IsFalse(verified, $"A tampered opening ({region}) must be rejected.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void TamperedCommitmentIsRejected()
    {
        const int VariableCount = 3;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider();

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 3, pool);
        Scalar[] point = BuildPoint(VariableCount, 7, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    using PolynomialCommitment tampered = TamperFirstByte(commitment, pool);

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(tampered, point, claimedValue, opening, verifyTx, pool);

                    Assert.IsFalse(verified, "A tampered commitment must be rejected.");
                }
            }
        }
        finally
        {
            DisposePoint(point);
        }
    }


    [TestMethod]
    public void WrongClaimedValueIsRejected()
    {
        const int VariableCount = 3;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider();

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 4, pool);
        Scalar[] point = BuildPoint(VariableCount, 8, pool);

        try
        {
            (PolynomialCommitment commitment, PolynomialCommitmentBlind blind) = provider.Commit(mle, pool);

            using(commitment)
            using(blind)
            {
                using FiatShamirTranscript openTx = NewTranscript();
                (PolynomialOpening opening, Scalar claimedValue) = provider.Open(commitment, blind, mle, point, openTx, pool);

                using(opening)
                using(claimedValue)
                {
                    using Scalar wrong = AddOne(claimedValue, pool);

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, wrong, opening, verifyTx, pool);

                    Assert.IsFalse(verified, "A wrong claimed value must be rejected.");
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
        return LigeroPolynomialCommitmentScheme.Create(
            Curve,
            TestQueryCount,
            Add,
            Subtract,
            Multiply,
            Invert,
            Reduce,
            Hash,
            Squeeze,
            Hash,
            Merkle,
            WellKnownHashAlgorithms.Blake3);
    }


    private static PolynomialCommitment TamperFirstByte(PolynomialCommitment commitment, BaseMemoryPool pool)
    {
        Span<byte> bytes = stackalloc byte[commitment.AsReadOnlySpan().Length];
        commitment.AsReadOnlySpan().CopyTo(bytes);
        bytes[0] ^= 0x01;

        return PolynomialCommitment.FromBytes(bytes, Curve, CommitmentScheme.Ligero, pool);
    }


    private static MultilinearExtension BuildRandomMle(int variableCount, int salt, BaseMemoryPool pool)
    {
        int evaluationCount = 1 << variableCount;
        using IMemoryOwner<byte> owner = pool.Rent(evaluationCount * ScalarSize);
        Span<byte> evaluations = owner.Memory.Span[..(evaluationCount * ScalarSize)];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < evaluationCount; i++)
        {
            wide.Clear();
            BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 137) + (i * 19) + 1);
            BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 11) + (i * 31) + 3);
            Reduce(wide, evaluations.Slice(i * ScalarSize, ScalarSize), Curve);
        }

        return MultilinearExtension.FromEvaluations(evaluations, variableCount, Curve, pool);
    }


    private static Scalar[] BuildPoint(int variableCount, int salt, BaseMemoryPool pool)
    {
        var point = new Scalar[variableCount];
        Span<byte> wide = stackalloc byte[ScalarSize];
        for(int i = 0; i < variableCount; i++)
        {
            wide.Clear();
            BinaryPrimitives.WriteInt32BigEndian(wide[..4], (salt * 59) + (i * 23) + 2);
            BinaryPrimitives.WriteInt32BigEndian(wide[^4..], (salt * 29) + (i * 43) + 5);
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
            new FiatShamirDomainLabel(WellKnownLigeroEvaluationLabels.DomainV1),
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
}

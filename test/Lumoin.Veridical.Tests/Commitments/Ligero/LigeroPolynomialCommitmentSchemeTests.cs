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
using System.Numerics;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Commitments.Ligero;

/// <summary>
/// End-to-end gate for <see cref="LigeroPolynomialCommitmentScheme"/> behind the
/// scheme-agnostic <see cref="PolynomialCommitmentProvider"/> surface: commit →
/// open → verify round-trips over real BN254 arithmetic and production BLAKE3,
/// the opened claimed value equals the multilinear extension evaluated at the
/// point (so the proximity/evaluation tensor split is correct), and a tampered
/// opening (in the proximity response, an opened column, or a Merkle path), a
/// tampered commitment, a wrong claimed value, or an arithmetically equivalent
/// but non-canonical spelling of an opening scalar are each rejected.
/// </summary>
[TestClass]
internal sealed class LigeroPolynomialCommitmentSchemeTests
{
    private const int ScalarSize = Scalar.SizeBytes;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;
    private const int TestQueryCount = 12;

    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bn254;

    private static ScalarAddDelegate Add { get; } = Bn254BigIntegerScalarReference.GetAdd();
    private static ScalarSubtractDelegate Subtract { get; } = Bn254BigIntegerScalarReference.GetSubtract();
    private static ScalarMultiplyDelegate Multiply { get; } = Bn254BigIntegerScalarReference.GetMultiply();
    private static ScalarInvertDelegate Invert { get; } = Bn254BigIntegerScalarReference.GetInvert();
    private static ScalarReduceDelegate Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;


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
        Assert.AreEqual(WellKnownLigeroParameters.DefaultInverseRate, provider.InverseRate, "The default-path provider must commit at the wired default inverse rate.");

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

                    Assert.IsTrue(verified, $"A correctly generated commit→open→verify must round-trip for n = {variableCount}.");
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


    /// <summary>
    /// Pins the opening-scalar canonicity gate directly: zero and the largest
    /// reduced value are canonical, the field order itself (a second spelling of
    /// zero) is not, and the stride walk rejects a non-canonical element at any
    /// position, not just the first.
    /// </summary>
    [TestMethod]
    public void NonCanonicalScalarSpellingIsDetectedAtEveryStride()
    {
        Span<byte> orderBytes = stackalloc byte[ScalarSize];
        WriteBigEndian(WellKnownCurves.GetScalarFieldOrder(Curve), orderBytes);

        Span<byte> canonicalMax = stackalloc byte[ScalarSize];
        WriteBigEndian(WellKnownCurves.GetScalarFieldOrder(Curve) - BigInteger.One, canonicalMax);

        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();

        Assert.IsTrue(LigeroEvaluationVerifier.AreCanonicalScalars(zero, Curve), "Zero is a canonical scalar spelling.");
        Assert.IsTrue(LigeroEvaluationVerifier.AreCanonicalScalars(canonicalMax, Curve), "The largest reduced value is a canonical scalar spelling.");
        Assert.IsFalse(LigeroEvaluationVerifier.AreCanonicalScalars(orderBytes, Curve), "The field order is a non-canonical spelling of zero and must be rejected.");

        Span<byte> pair = stackalloc byte[2 * ScalarSize];
        canonicalMax.CopyTo(pair[..ScalarSize]);
        orderBytes.CopyTo(pair[ScalarSize..]);

        Assert.IsFalse(LigeroEvaluationVerifier.AreCanonicalScalars(pair, Curve), "A non-canonical element after a canonical one must still be rejected.");
    }


    /// <summary>
    /// Rejects the malleability shape a bit-flip tamper cannot represent: lifting
    /// an opening scalar by the field order yields byte-distinct bytes that denote
    /// the same residue, the encoding class the verifier's canonicity gate exists
    /// to reject before the bytes reach transcript absorbs or arithmetic.
    /// </summary>
    [TestMethod]
    public void ArithmeticallyEquivalentNonCanonicalOpeningIsRejected()
    {
        const int VariableCount = 4;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider();

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 12, pool);
        Scalar[] point = BuildPoint(VariableCount, 13, pool);

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
                    Span<byte> uFirst = MemoryMarshal.AsMemory(opening.AsReadOnlyMemory()).Span[..ScalarSize];
                    var value = new BigInteger(uFirst, isUnsigned: true, isBigEndian: true);

                    Span<byte> lifted = stackalloc byte[ScalarSize];
                    WriteBigEndian(value + WellKnownCurves.GetScalarFieldOrder(Curve), lifted);

                    Span<byte> reduced = stackalloc byte[ScalarSize];
                    Reduce(lifted, reduced, Curve);
                    Assert.IsTrue(reduced.SequenceEqual(uFirst), "The lifted spelling must denote the same residue as the canonical one.");
                    Assert.IsFalse(WellKnownCurves.IsCanonicalScalar(lifted, Curve), "The lifted spelling must be non-canonical.");

                    lifted.CopyTo(uFirst);

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool);

                    Assert.IsFalse(verified, "An arithmetically equivalent but non-canonical opening-scalar spelling must be rejected.");
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
    public void CommitOpenVerifyRoundTripsAtInverseRateSixteen()
    {
        //The wired CLI shape: rate 1/16 widens the extension so a small circuit still opens the full
        //64-column target (see WellKnownSecurityLevelsTests.SixVariableRateSixteenOpeningRealisesFullTarget).
        const int VariableCount = 6;
        const int InverseRate = 16;
        const int QueryCount = 64;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using PolynomialCommitmentProvider provider = NewProvider(QueryCount, InverseRate);
        Assert.AreEqual(InverseRate, provider.InverseRate);

        using MultilinearExtension mle = BuildRandomMle(VariableCount, 9, pool);
        Scalar[] point = BuildPoint(VariableCount, 11, pool);

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
                    using Scalar expected = mle.Evaluate(point, MleEvaluate, pool);
                    Assert.IsTrue(
                        claimedValue.AsReadOnlySpan().SequenceEqual(expected.AsReadOnlySpan()),
                        "Opened claimed value must equal f(z) at the wired rate-1/16 shape.");

                    using FiatShamirTranscript verifyTx = NewTranscript();
                    bool verified = provider.VerifyEvaluation(commitment, point, claimedValue, opening, verifyTx, pool);

                    Assert.IsTrue(verified, "A correctly generated commit→open→verify must round-trip at inverse rate 16 / query count 64.");
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
        return NewProvider(TestQueryCount, WellKnownLigeroParameters.DefaultInverseRate);
    }


    private static PolynomialCommitmentProvider NewProvider(int queryCount, int inverseRate)
    {
        return LigeroPolynomialCommitmentScheme.Create(
            Curve,
            queryCount,
            Add,
            Subtract,
            Multiply,
            Invert,
            Reduce,
            Hash,
            Squeeze,
            Hash,
            Merkle,
            WellKnownHashAlgorithms.Blake3,
            inverseRate: inverseRate);
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


    /// <summary>
    /// Writes <paramref name="value"/> as unsigned big-endian bytes right-aligned
    /// into <paramref name="destination"/>, zero-padding the leading bytes.
    /// </summary>
    private static void WriteBigEndian(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        int byteCount = value.GetByteCount(isUnsigned: true);
        value.TryWriteBytes(destination[^byteCount..], out _, isUnsigned: true, isBigEndian: true);
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

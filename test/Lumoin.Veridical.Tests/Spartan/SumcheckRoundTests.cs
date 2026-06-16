using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Core.Sumcheck;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Tests for the <see cref="SumcheckRound"/> leaf type: shape, byte
/// layout, slice accessors, materialisation back to leaf-typed inner
/// objects, and tag composition.
/// </summary>
[TestClass]
internal sealed class SumcheckRoundTests
{
    [TestMethod]
    public void CreateRoundtripsCompressedPolynomialAndChallengeBytes()
    {
        int elementSize = Scalar.SizeBytes;
        const int Degree = 3;
        int compressedBufferSize = Degree * elementSize;

        using IMemoryOwner<byte> compressedOwner = BaseMemoryPool.Shared.Rent(compressedBufferSize);
        Span<byte> compressedBytes = compressedOwner.Memory.Span[..compressedBufferSize];
        compressedBytes.Clear();
        WriteCanonical(new BigInteger(11), compressedBytes.Slice(0 * elementSize, elementSize));
        WriteCanonical(new BigInteger(22), compressedBytes.Slice(1 * elementSize, elementSize));
        WriteCanonical(new BigInteger(33), compressedBytes.Slice(2 * elementSize, elementSize));
        using CompressedRoundPolynomial polynomial = CompressedRoundPolynomial.FromCompressedBytes(
            compressedBytes, Degree, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> challengeOwner = BaseMemoryPool.Shared.Rent(elementSize);
        Span<byte> challengeBytes = challengeOwner.Memory.Span[..elementSize];
        challengeBytes.Clear();
        WriteCanonical(new BigInteger(99), challengeBytes);
        using Scalar challenge = Scalar.FromCanonical(challengeBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using SumcheckRound round = SumcheckRound.Create(
            roundIndex: 4,
            polynomial,
            challenge,
            BaseMemoryPool.Shared);

        Assert.AreEqual(4, round.RoundIndex);
        Assert.AreEqual(Degree, round.Degree);
        Assert.AreEqual(elementSize, round.FieldElementSizeBytes);
        Assert.AreEqual(CurveParameterSet.Bls12Curve381.Code, round.Curve.Code);

        //Slice accessors must surface exactly the bytes Create copied in.
        Assert.IsTrue(compressedBytes.SequenceEqual(round.GetCompressedPolynomialBytes()), "Compressed polynomial bytes should round-trip through Create.");
        Assert.IsTrue(challengeBytes.SequenceEqual(round.GetChallengeBytes()), "Challenge bytes should round-trip through Create.");
    }


    [TestMethod]
    public void GetCompressedRoundPolynomialMaterialisesEquivalentLeafType()
    {
        int elementSize = Scalar.SizeBytes;
        const int Degree = 2;
        int compressedBufferSize = Degree * elementSize;

        using IMemoryOwner<byte> compressedOwner = BaseMemoryPool.Shared.Rent(compressedBufferSize);
        Span<byte> compressedBytes = compressedOwner.Memory.Span[..compressedBufferSize];
        compressedBytes.Clear();
        WriteCanonical(new BigInteger(7), compressedBytes.Slice(0 * elementSize, elementSize));
        WriteCanonical(new BigInteger(8), compressedBytes.Slice(1 * elementSize, elementSize));
        using CompressedRoundPolynomial source = CompressedRoundPolynomial.FromCompressedBytes(
            compressedBytes, Degree, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> challengeOwner = BaseMemoryPool.Shared.Rent(elementSize);
        Span<byte> challengeBytes = challengeOwner.Memory.Span[..elementSize];
        challengeBytes.Clear();
        WriteCanonical(new BigInteger(42), challengeBytes);
        using Scalar challenge = Scalar.FromCanonical(challengeBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using SumcheckRound round = SumcheckRound.Create(0, source, challenge, BaseMemoryPool.Shared);

        using CompressedRoundPolynomial materialised = round.GetCompressedRoundPolynomial(BaseMemoryPool.Shared);
        Assert.AreEqual(source.Degree, materialised.Degree, "Materialised polynomial should report the same degree as the source.");
        Assert.IsTrue(source.AsReadOnlySpan().SequenceEqual(materialised.AsReadOnlySpan()), "Materialised polynomial bytes must equal the source bytes.");

        using Scalar materialisedChallenge = round.GetChallenge(BaseMemoryPool.Shared);
        Assert.IsTrue(challenge.AsReadOnlySpan().SequenceEqual(materialisedChallenge.AsReadOnlySpan()), "Materialised challenge bytes must equal the source bytes.");
    }


    [TestMethod]
    public void TagCarriesAlgebraicIdentityAndDimensions()
    {
        int elementSize = Scalar.SizeBytes;
        const int Degree = 3;
        int compressedBufferSize = Degree * elementSize;

        using IMemoryOwner<byte> compressedOwner = BaseMemoryPool.Shared.Rent(compressedBufferSize);
        Span<byte> compressedBytes = compressedOwner.Memory.Span[..compressedBufferSize];
        compressedBytes.Clear();
        WriteCanonical(new BigInteger(1), compressedBytes.Slice(0 * elementSize, elementSize));
        WriteCanonical(new BigInteger(2), compressedBytes.Slice(1 * elementSize, elementSize));
        WriteCanonical(new BigInteger(3), compressedBytes.Slice(2 * elementSize, elementSize));
        using CompressedRoundPolynomial polynomial = CompressedRoundPolynomial.FromCompressedBytes(
            compressedBytes, Degree, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using IMemoryOwner<byte> challengeOwner = BaseMemoryPool.Shared.Rent(elementSize);
        Span<byte> challengeBytes = challengeOwner.Memory.Span[..elementSize];
        challengeBytes.Clear();
        WriteCanonical(new BigInteger(5), challengeBytes);
        using Scalar challenge = Scalar.FromCanonical(challengeBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using SumcheckRound round = SumcheckRound.Create(7, polynomial, challenge, BaseMemoryPool.Shared);

        Assert.AreEqual(AlgebraicRole.SumcheckRound, round.Tag.Get<AlgebraicRole>(), "Tag should carry the SumcheckRound role.");
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, round.Tag.Get<CurveParameterSet>(), "Tag should carry the BLS12-381 curve.");

        var dimensions = round.Tag.Get<SumcheckRoundDimensions>();
        Assert.AreEqual(7, dimensions.RoundIndex);
        Assert.AreEqual(Degree, dimensions.Degree);
    }


    [TestMethod]
    public void CreateRejectsNegativeRoundIndex()
    {
        int elementSize = Scalar.SizeBytes;
        const int Degree = 2;

        byte[] compressedBytes = new byte[Degree * elementSize];
        using CompressedRoundPolynomial polynomial = CompressedRoundPolynomial.FromCompressedBytes(
            compressedBytes, Degree, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        byte[] challengeBytes = new byte[elementSize];
        using Scalar challenge = Scalar.FromCanonical(challengeBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            _ = SumcheckRound.Create(-1, polynomial, challenge, BaseMemoryPool.Shared));
    }


    [TestMethod]
    public void RoundOutlivesInnerObjectsAfterCreate()
    {
        //Create copies the inner objects' bytes into its own buffer. Once
        //the source objects are disposed the round must still expose
        //their original bytes intact.
        int elementSize = Scalar.SizeBytes;
        const int Degree = 2;
        int compressedBufferSize = Degree * elementSize;

        byte[] expectedCompressedBytes = new byte[compressedBufferSize];
        WriteCanonical(new BigInteger(111), expectedCompressedBytes.AsSpan(0, elementSize));
        WriteCanonical(new BigInteger(222), expectedCompressedBytes.AsSpan(elementSize, elementSize));
        byte[] expectedChallengeBytes = new byte[elementSize];
        WriteCanonical(new BigInteger(333), expectedChallengeBytes);

        SumcheckRound round;
        using(CompressedRoundPolynomial polynomial = CompressedRoundPolynomial.FromCompressedBytes(
            expectedCompressedBytes, Degree, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared))
        using(Scalar challenge = Scalar.FromCanonical(expectedChallengeBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared))
        {
            round = SumcheckRound.Create(0, polynomial, challenge, BaseMemoryPool.Shared);
        }

        using(round)
        {
            Assert.IsTrue(round.GetCompressedPolynomialBytes().SequenceEqual(expectedCompressedBytes), "Compressed polynomial bytes must survive disposal of the source.");
            Assert.IsTrue(round.GetChallengeBytes().SequenceEqual(expectedChallengeBytes), "Challenge bytes must survive disposal of the source.");
        }
    }


    [TestMethod]
    public void SumcheckClaimCarriesAllThreeFields()
    {
        byte[] sumBytes = new byte[Scalar.SizeBytes];
        WriteCanonical(new BigInteger(123456), sumBytes);
        using Scalar claimedSum = Scalar.FromCanonical(sumBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        var claim = new SumcheckClaim(claimedSum, NumRounds: 5, DegreeBound: 3);

        Assert.AreSame(claimedSum, claim.ClaimedSum);
        Assert.AreEqual(5, claim.NumRounds);
        Assert.AreEqual(3, claim.DegreeBound);
    }


    [TestMethod]
    public void SumcheckResultVerifiedExposesFinalEvaluationAndChallenges()
    {
        byte[] finalBytes = new byte[Scalar.SizeBytes];
        WriteCanonical(new BigInteger(7), finalBytes);
        Scalar finalEvaluation = Scalar.FromCanonical(finalBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        byte[] c1 = new byte[Scalar.SizeBytes];
        byte[] c2 = new byte[Scalar.SizeBytes];
        WriteCanonical(new BigInteger(11), c1);
        WriteCanonical(new BigInteger(13), c2);
        Scalar challenge1 = Scalar.FromCanonical(c1, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        Scalar challenge2 = Scalar.FromCanonical(c2, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        //Verified takes ownership of finalEvaluation and the challenges via Dispose.
        using SumcheckResult result = new SumcheckResult.Verified(finalEvaluation, [challenge1, challenge2]);

        Assert.IsInstanceOfType<SumcheckResult.Verified>(result);
        var verified = (SumcheckResult.Verified)result;
        Assert.AreSame(finalEvaluation, verified.FinalEvaluation);
        Assert.HasCount(2, verified.Challenges);
        Assert.AreSame(challenge1, verified.Challenges[0]);
        Assert.AreSame(challenge2, verified.Challenges[1]);
    }


    [TestMethod]
    public void SumcheckResultRejectedExposesReasonAndRound()
    {
        using SumcheckResult result = new SumcheckResult.Rejected(SumcheckRejectionReason.DegreeBoundExceeded, RoundIndex: 4);

        Assert.IsInstanceOfType<SumcheckResult.Rejected>(result);
        var rejected = (SumcheckResult.Rejected)result;
        Assert.AreEqual(SumcheckRejectionReason.DegreeBoundExceeded, rejected.Reason);
        Assert.AreEqual(4, rejected.RoundIndex);
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
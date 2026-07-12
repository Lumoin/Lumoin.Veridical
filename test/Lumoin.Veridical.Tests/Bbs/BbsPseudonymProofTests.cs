using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Structural and canonicity gates for
/// <see cref="BbsPseudonymProof.FromCanonical"/>: the same
/// <c>272 + 32 * U</c> layout arithmetic as <see cref="BbsProof"/> (nym
/// -03 Section 8 confirms the nym proof octets ARE the core layout), and
/// the per-verifier-pseudonym Interface tag that keeps the two types from
/// being conflated. Mirrors <see cref="BbsCanonicityTests"/>' assertion
/// style for the sibling <see cref="BbsProof"/> type.
/// </summary>
[TestClass]
internal sealed class BbsPseudonymProofTests
{
    private const int ScalarSize = BbsProof.ScalarSizeBytes;

    private static readonly BbsCiphersuite Suite = BbsCiphersuite.Bls12Curve381Sha256Pseudonym;

    private static ReadOnlySpan<byte> PointFiller =>
        WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.Bls12Curve381);


    [TestMethod]
    public void ComputeSizeBytesMatchesBbsProofFormula()
    {
        Assert.AreEqual(BbsProof.ComputeSizeBytes(0), BbsPseudonymProof.ComputeSizeBytes(0));
        Assert.AreEqual(BbsProof.ComputeSizeBytes(3), BbsPseudonymProof.ComputeSizeBytes(3));
    }


    [TestMethod]
    public void ComponentAccessorsMatchTheBbsProofOffsetTable()
    {
        //BbsNymProofFailureTests' tamper table addresses pseudonym-proof
        //bytes through BbsProof's offset and size constants; this pins the
        //shared layout so any accessor drift away from those constants fails
        //here instead of silently weakening the tamper coverage. Every slot
        //carries distinct content so a shifted offset cannot alias a
        //neighbouring slot.
        const int UndisclosedCount = 2;
        const int ScalarSlotCount = 4 + UndisclosedCount;
        int size = BbsPseudonymProof.ComputeSizeBytes(UndisclosedCount);
        Assert.AreEqual(BbsProof.ComputeSizeBytes(UndisclosedCount), size);

        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(size);
        Memory<byte> buf = owner.Memory[..size];
        BuildProofBuffer(buf.Span, scalarCount: ScalarSlotCount, scalarValue: BigInteger.One);

        //Point bytes are not inspected at intake, so the second body byte of
        //Bbar and D can diverge from Abar's to make the three slots distinct.
        buf.Span[BbsProof.BBarOffset + 1] ^= 0x01;
        buf.Span[BbsProof.DOffset + 1] ^= 0x02;
        for(int i = 0; i < ScalarSlotCount; i++)
        {
            WriteBigEndian(new BigInteger(i + 1), buf.Span.Slice(BbsProof.EHatOffset + (i * ScalarSize), ScalarSize));
        }

        using BbsPseudonymProof proof = BbsPseudonymProof.FromCanonical(buf.Span, Suite, TestSetup.Pool);

        Assert.IsTrue(buf.Span.Slice(BbsProof.ABarOffset, BbsProof.ABarSizeBytes).SequenceEqual(proof.GetABarBytes()));
        Assert.IsTrue(buf.Span.Slice(BbsProof.BBarOffset, BbsProof.BBarSizeBytes).SequenceEqual(proof.GetBBarBytes()));
        Assert.IsTrue(buf.Span.Slice(BbsProof.DOffset, BbsProof.DSizeBytes).SequenceEqual(proof.GetDBytes()));
        Assert.IsTrue(buf.Span.Slice(BbsProof.EHatOffset, ScalarSize).SequenceEqual(proof.GetEHatBytes()));
        Assert.IsTrue(buf.Span.Slice(BbsProof.R1HatOffset, ScalarSize).SequenceEqual(proof.GetR1HatBytes()));
        Assert.IsTrue(buf.Span.Slice(BbsProof.R3HatOffset, ScalarSize).SequenceEqual(proof.GetR3HatBytes()));
        Assert.IsTrue(buf.Span.Slice(BbsProof.CommitmentsOffset, ScalarSize).SequenceEqual(proof.GetCommitmentBytes(0)));
        Assert.IsTrue(buf.Span.Slice(BbsProof.CommitmentsOffset + ScalarSize, ScalarSize).SequenceEqual(proof.GetCommitmentBytes(1)));
        Assert.IsTrue(buf.Span.Slice(BbsProof.CommitmentsOffset + (ScalarSize * UndisclosedCount), ScalarSize).SequenceEqual(proof.GetChallengeBytes()));
    }


    [TestMethod]
    public void FromCanonicalAcceptsMinimalLayoutWithAllScalarSlotsOne()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsProof.MinimumSizeBytes);
        Memory<byte> buf = owner.Memory[..BbsProof.MinimumSizeBytes];
        BuildProofBuffer(buf.Span, scalarCount: 4, scalarValue: BigInteger.One);

        using BbsPseudonymProof proof = BbsPseudonymProof.FromCanonical(buf.Span, Suite, TestSetup.Pool);

        Assert.AreEqual(0, proof.UndisclosedMessageCount);
        Assert.IsTrue(PointFiller.SequenceEqual(proof.GetABarBytes()));
        Assert.IsTrue(PointFiller.SequenceEqual(proof.GetBBarBytes()));
        Assert.IsTrue(PointFiller.SequenceEqual(proof.GetDBytes()));
    }


    [TestMethod]
    public void FromCanonicalAcceptsLayoutWithOneUndisclosedMessage()
    {
        int size = BbsPseudonymProof.ComputeSizeBytes(undisclosedMessageCount: 1);
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(size);
        Memory<byte> buf = owner.Memory[..size];
        BuildProofBuffer(buf.Span, scalarCount: 5, scalarValue: BigInteger.One);

        using BbsPseudonymProof proof = BbsPseudonymProof.FromCanonical(buf.Span, Suite, TestSetup.Pool);

        Assert.AreEqual(1, proof.UndisclosedMessageCount);
    }


    [TestMethod]
    public void FromCanonicalRejectsChallengeAtScalarFieldOrder()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsProof.MinimumSizeBytes);
        Memory<byte> buf = owner.Memory[..BbsProof.MinimumSizeBytes];
        BuildProofBuffer(buf.Span, scalarCount: 4, scalarValue: BigInteger.One);
        WriteBigEndian(FieldOrder(), buf.Span.Slice(BbsProof.CommitmentsOffset, ScalarSize));

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsPseudonymProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
        Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void FromCanonicalRejectsEHatEqualZero()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsProof.MinimumSizeBytes);
        Memory<byte> buf = owner.Memory[..BbsProof.MinimumSizeBytes];
        BuildProofBuffer(buf.Span, scalarCount: 4, scalarValue: BigInteger.One);
        buf.Span.Slice(BbsProof.EHatOffset, ScalarSize).Clear();

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsPseudonymProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
        Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void GetCommitmentBytesThrowsOnOutOfRangeIndex()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsProof.MinimumSizeBytes);
        Memory<byte> buf = owner.Memory[..BbsProof.MinimumSizeBytes];
        BuildProofBuffer(buf.Span, scalarCount: 4, scalarValue: BigInteger.One);
        using BbsPseudonymProof proof = BbsPseudonymProof.FromCanonical(buf.Span, Suite, TestSetup.Pool);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => _ = proof.GetCommitmentBytes(0));
    }


    [TestMethod]
    public void CiphersuiteTagRoundTripsThroughFromCanonical()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsProof.MinimumSizeBytes);
        Memory<byte> buf = owner.Memory[..BbsProof.MinimumSizeBytes];
        BuildProofBuffer(buf.Span, scalarCount: 4, scalarValue: BigInteger.One);

        using BbsPseudonymProof shaProof = BbsPseudonymProof.FromCanonical(buf.Span, BbsCiphersuite.Bls12Curve381Sha256Pseudonym, TestSetup.Pool);
        using BbsPseudonymProof shakeProof = BbsPseudonymProof.FromCanonical(buf.Span, BbsCiphersuite.Bls12Curve381Shake256Pseudonym, TestSetup.Pool);

        Assert.AreEqual(BbsCiphersuite.Bls12Curve381Sha256Pseudonym, shaProof.Ciphersuite);
        Assert.AreEqual(BbsCiphersuite.Bls12Curve381Shake256Pseudonym, shakeProof.Ciphersuite);
    }


    [TestMethod]
    public void GetAlgebraicTagRejectsTheCoreCiphersuite()
    {
        Assert.ThrowsExactly<ArgumentException>(() => _ = BbsPseudonymProof.GetAlgebraicTag(BbsCiphersuite.Bls12Curve381Sha256));
    }


    private static BigInteger FieldOrder() =>
        WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.Bls12Curve381);


    private static void WriteBigEndian(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true);

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    /// <summary>
    /// Fills a proof buffer of any length: <c>PointFiller</c> in the three
    /// point slots and <paramref name="scalarValue"/> in each of the
    /// <paramref name="scalarCount"/> 32-byte scalar slots starting at
    /// <see cref="BbsProof.EHatOffset"/>.
    /// </summary>
    private static void BuildProofBuffer(Span<byte> buf, int scalarCount, BigInteger scalarValue)
    {
        buf.Clear();
        PointFiller.CopyTo(buf.Slice(BbsProof.ABarOffset, BbsProof.ABarSizeBytes));
        PointFiller.CopyTo(buf.Slice(BbsProof.BBarOffset, BbsProof.BBarSizeBytes));
        PointFiller.CopyTo(buf.Slice(BbsProof.DOffset, BbsProof.DSizeBytes));

        for(int i = 0; i < scalarCount; i++)
        {
            WriteBigEndian(scalarValue, buf.Slice(BbsProof.EHatOffset + (i * ScalarSize), ScalarSize));
        }
    }
}

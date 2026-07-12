using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Structural and frame-arithmetic gates for
/// <see cref="BbsBlindProof.FromCanonical"/>: the four length-prefixed
/// frames (<c>bbs_proof_len</c> + core proof, <c>disclosed_indexes_len</c>
/// + indexes, <c>commits_proof_len</c> + commitments/scalars,
/// <c>commits_indexes_len</c> + indexes), cumulative-length truncation,
/// the wrapped core proof's own scalar-canonicity gate, the
/// committed-disclosure response-scalar canonicity gate, <c>N' == N</c>,
/// exact total length, and strictly-ascending index vectors, per IETF
/// <c>draft-irtf-cfrg-bbs-blind-signatures-03</c> Section 5.4.3/5.4.4.
/// </summary>
[TestClass]
internal sealed class BbsBlindProofTests
{
    private static readonly BbsCiphersuite Suite = BbsCiphersuite.Bls12Curve381Sha256Blind;

    private static ReadOnlySpan<byte> PointFiller =>
        WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.Bls12Curve381);


    /// <summary>Named frame-field offsets for a buffer built by <see cref="BuildValidFramedProof"/>, so corruption tests can target a specific field without re-deriving the cursor arithmetic.</summary>
    private readonly record struct FramedProofLayout(
        int DisclosedIndexesLengthFieldOffset,
        int DisclosedIndexesOffset,
        int CommittedDisclosurePointsOffset,
        int CommittedDisclosureScalarsOffset,
        int CommitsIndexesLengthFieldOffset,
        int CommitsIndexesOffset,
        int TotalLength);


    [TestMethod]
    public void ComputeSizeBytesMatchesFrameFormula()
    {
        //32 (four length fields) + 272 (core proof floor) + 8*R + 88*N.
        Assert.AreEqual(304, BbsBlindProof.ComputeSizeBytes(undisclosedMessageCount: 0, disclosedIndexCount: 0, committedDisclosureCount: 0));
        Assert.AreEqual(304 + 32 + 16 + 88, BbsBlindProof.ComputeSizeBytes(undisclosedMessageCount: 1, disclosedIndexCount: 2, committedDisclosureCount: 1));
    }


    [TestMethod]
    public void FromCanonicalAcceptsMinimalLayout()
    {
        (IMemoryOwner<byte> owner, FramedProofLayout layout) = BuildValidFramedProof(undisclosedMessageCount: 0, disclosedIndexes: [], committedDisclosureCount: 0);
        using(owner)
        {
            Memory<byte> buf = owner.Memory[..layout.TotalLength];
            using BbsBlindProof proof = BbsBlindProof.FromCanonical(buf.Span, Suite, TestSetup.Pool);

            Assert.AreEqual(0, proof.UndisclosedMessageCount);
            Assert.AreEqual(0, proof.DisclosedIndexCount);
            Assert.AreEqual(0, proof.CommittedDisclosureCount);
            Assert.AreEqual(BbsProof.MinimumSizeBytes, proof.GetCoreProofBytes().Length);
        }
    }


    [TestMethod]
    public void FromCanonicalAcceptsRichLayoutAndAccessorsReadTheRightSlots()
    {
        (IMemoryOwner<byte> owner, FramedProofLayout layout) = BuildValidFramedProof(undisclosedMessageCount: 1, disclosedIndexes: [0, 2], committedDisclosureCount: 2);
        using(owner)
        {
            Memory<byte> buf = owner.Memory[..layout.TotalLength];
            using BbsBlindProof proof = BbsBlindProof.FromCanonical(buf.Span, Suite, TestSetup.Pool);

            Assert.AreEqual(1, proof.UndisclosedMessageCount);
            Assert.AreEqual(2, proof.DisclosedIndexCount);
            Assert.AreEqual(2, proof.CommittedDisclosureCount);
            Assert.AreEqual(BbsProof.ComputeSizeBytes(1), proof.GetCoreProofBytes().Length);
            Assert.AreEqual(0, proof.GetDisclosedIndex(0));
            Assert.AreEqual(2, proof.GetDisclosedIndex(1));
            Assert.IsTrue(PointFiller.SequenceEqual(proof.GetCommittedDisclosurePointBytes(0)));
            Assert.IsTrue(PointFiller.SequenceEqual(proof.GetCommittedDisclosurePointBytes(1)));
            Assert.AreEqual(BigInteger.One, ReadBigEndian(proof.GetCommittedDisclosureScalarBytes(0)));
            Assert.AreEqual(BigInteger.One, ReadBigEndian(proof.GetCommittedDisclosureScalarBytes(1)));
            Assert.AreEqual(0, proof.GetCommittedDisclosureIndex(0));
            Assert.AreEqual(1, proof.GetCommittedDisclosureIndex(1));
        }
    }


    [TestMethod]
    public void FromCanonicalRejectsTruncatedBbsProofLengthField()
    {
        byte[] tooShortForFirstField = new byte[BbsBlindProof.Int64FieldSizeBytes - 1];

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsBlindProof.FromCanonical(tooShortForFirstField, Suite, TestSetup.Pool));
        Assert.Contains("truncated", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void FromCanonicalRejectsBbsProofLengthThatIsNotAValidCoreProofLength()
    {
        (IMemoryOwner<byte> owner, FramedProofLayout layout) = BuildValidFramedProof(undisclosedMessageCount: 0, disclosedIndexes: [], committedDisclosureCount: 0);
        using(owner)
        {
            Memory<byte> buf = owner.Memory[..layout.TotalLength];
            //272 + 28 is not a multiple of the 32-byte scalar size above the floor.
            BinaryPrimitives.WriteInt64BigEndian(buf.Span.Slice(BbsBlindProof.BbsProofLengthOffset, BbsBlindProof.Int64FieldSizeBytes), BbsProof.MinimumSizeBytes + 28);

            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
                _ = BbsBlindProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
            Assert.Contains("not a valid core BBS+ proof length", ex.Message, StringComparison.Ordinal);
        }
    }


    [TestMethod]
    public void FromCanonicalRejectsNonCanonicalScalarInTheWrappedCoreProof()
    {
        (IMemoryOwner<byte> owner, FramedProofLayout layout) = BuildValidFramedProof(undisclosedMessageCount: 0, disclosedIndexes: [], committedDisclosureCount: 0);
        using(owner)
        {
            Memory<byte> buf = owner.Memory[..layout.TotalLength];
            WriteBigEndian(FieldOrder(), buf.Span.Slice(BbsBlindProof.CoreProofOffset + BbsProof.EHatOffset, BbsProof.ScalarSizeBytes));

            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
                _ = BbsBlindProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
            Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
        }
    }


    [TestMethod]
    public void FromCanonicalRejectsZeroCommittedDisclosureResponseScalar()
    {
        (IMemoryOwner<byte> owner, FramedProofLayout layout) = BuildValidFramedProof(undisclosedMessageCount: 0, disclosedIndexes: [], committedDisclosureCount: 1);
        using(owner)
        {
            Memory<byte> buf = owner.Memory[..layout.TotalLength];
            buf.Span.Slice(layout.CommittedDisclosureScalarsOffset, BbsBlindProof.CommittedDisclosureScalarSizeBytes).Clear();

            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
                _ = BbsBlindProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
            Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
        }
    }


    [TestMethod]
    public void FromCanonicalRejectsCommitsIndexesCountNotEqualToCommitsProofCount()
    {
        (IMemoryOwner<byte> owner, FramedProofLayout layout) = BuildValidFramedProof(undisclosedMessageCount: 0, disclosedIndexes: [], committedDisclosureCount: 1);
        using(owner)
        {
            Memory<byte> buf = owner.Memory[..layout.TotalLength];
            BinaryPrimitives.WriteInt64BigEndian(buf.Span.Slice(layout.CommitsIndexesLengthFieldOffset, BbsBlindProof.Int64FieldSizeBytes), 2);

            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
                _ = BbsBlindProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
            Assert.Contains("commits_indexes_len", ex.Message, StringComparison.Ordinal);
        }
    }


    [TestMethod]
    public void FromCanonicalRejectsTruncatedCommittedDisclosureBlock()
    {
        (IMemoryOwner<byte> owner, FramedProofLayout layout) = BuildValidFramedProof(undisclosedMessageCount: 0, disclosedIndexes: [], committedDisclosureCount: 1);
        using(owner)
        {
            Memory<byte> buf = owner.Memory[..(layout.TotalLength - 1)];

            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
                _ = BbsBlindProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
            Assert.Contains("truncated", ex.Message, StringComparison.Ordinal);
        }
    }


    [TestMethod]
    public void FromCanonicalRejectsTrailingGarbageBeyondTheDeclaredTotalLength()
    {
        (IMemoryOwner<byte> owner, FramedProofLayout layout) = BuildValidFramedProof(undisclosedMessageCount: 0, disclosedIndexes: [], committedDisclosureCount: 0);
        using(owner)
        using(IMemoryOwner<byte> paddedOwner = BaseMemoryPool.Shared.Rent(layout.TotalLength + 1))
        {
            Memory<byte> padded = paddedOwner.Memory[..(layout.TotalLength + 1)];
            owner.Memory.Span[..layout.TotalLength].CopyTo(padded.Span);
            padded.Span[^1] = 0x00;

            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
                _ = BbsBlindProof.FromCanonical(padded.Span, Suite, TestSetup.Pool));
            Assert.Contains("declares a total length", ex.Message, StringComparison.Ordinal);
        }
    }


    [TestMethod]
    public void FromCanonicalRejectsNonAscendingDisclosedIndexes()
    {
        (IMemoryOwner<byte> owner, FramedProofLayout layout) = BuildValidFramedProof(undisclosedMessageCount: 0, disclosedIndexes: [0, 1], committedDisclosureCount: 0);
        using(owner)
        {
            Memory<byte> buf = owner.Memory[..layout.TotalLength];
            //Overwrite the second index with the first index's value: equal, not strictly ascending.
            BinaryPrimitives.WriteInt64BigEndian(buf.Span.Slice(layout.DisclosedIndexesOffset + BbsBlindProof.Int64FieldSizeBytes, BbsBlindProof.Int64FieldSizeBytes), 0);

            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
                _ = BbsBlindProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
            Assert.Contains("strictly ascending", ex.Message, StringComparison.Ordinal);
            Assert.Contains("disclosed_indexes", ex.Message, StringComparison.Ordinal);
        }
    }


    [TestMethod]
    public void FromCanonicalRejectsNonAscendingCommitsIndexes()
    {
        (IMemoryOwner<byte> owner, FramedProofLayout layout) = BuildValidFramedProof(undisclosedMessageCount: 0, disclosedIndexes: [], committedDisclosureCount: 2);
        using(owner)
        {
            Memory<byte> buf = owner.Memory[..layout.TotalLength];
            //Overwrite the second commits_indexes entry with 0: not strictly ascending after index 0.
            BinaryPrimitives.WriteInt64BigEndian(buf.Span.Slice(layout.CommitsIndexesOffset + BbsBlindProof.Int64FieldSizeBytes, BbsBlindProof.Int64FieldSizeBytes), 0);

            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
                _ = BbsBlindProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
            Assert.Contains("strictly ascending", ex.Message, StringComparison.Ordinal);
            Assert.Contains("commits_indexes", ex.Message, StringComparison.Ordinal);
        }
    }


    [TestMethod]
    public void FromCanonicalRejectsDisclosedIndexThatOverflowsInt32()
    {
        (IMemoryOwner<byte> owner, FramedProofLayout layout) = BuildValidFramedProof(undisclosedMessageCount: 0, disclosedIndexes: [0], committedDisclosureCount: 0);
        using(owner)
        {
            Memory<byte> buf = owner.Memory[..layout.TotalLength];
            BinaryPrimitives.WriteUInt64BigEndian(buf.Span.Slice(layout.DisclosedIndexesOffset, BbsBlindProof.Int64FieldSizeBytes), ulong.MaxValue);

            ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
                _ = BbsBlindProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
            Assert.Contains("does not fit a non-negative 32-bit index", ex.Message, StringComparison.Ordinal);
        }
    }


    [TestMethod]
    public void GetDisclosedIndexBytesThrowsOnOutOfRangeIndex()
    {
        (IMemoryOwner<byte> owner, FramedProofLayout layout) = BuildValidFramedProof(undisclosedMessageCount: 0, disclosedIndexes: [0], committedDisclosureCount: 0);
        using(owner)
        {
            Memory<byte> buf = owner.Memory[..layout.TotalLength];
            using BbsBlindProof proof = BbsBlindProof.FromCanonical(buf.Span, Suite, TestSetup.Pool);

            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => _ = proof.GetDisclosedIndexBytes(-1));
            Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => _ = proof.GetDisclosedIndexBytes(1));
        }
    }


    [TestMethod]
    public void ComputeSizeBytesRejectsNegativeCounts()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => _ = BbsBlindProof.ComputeSizeBytes(-1, 0, 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => _ = BbsBlindProof.ComputeSizeBytes(0, -1, 0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => _ = BbsBlindProof.ComputeSizeBytes(0, 0, -1));
    }


    [TestMethod]
    public void CiphersuiteTagRoundTripsThroughFromCanonical()
    {
        (IMemoryOwner<byte> owner, FramedProofLayout layout) = BuildValidFramedProof(undisclosedMessageCount: 0, disclosedIndexes: [], committedDisclosureCount: 0);
        using(owner)
        {
            Memory<byte> buf = owner.Memory[..layout.TotalLength];

            using BbsBlindProof shaProof = BbsBlindProof.FromCanonical(buf.Span, BbsCiphersuite.Bls12Curve381Sha256Blind, TestSetup.Pool);
            using BbsBlindProof shakeProof = BbsBlindProof.FromCanonical(buf.Span, BbsCiphersuite.Bls12Curve381Shake256Blind, TestSetup.Pool);

            Assert.AreEqual(BbsCiphersuite.Bls12Curve381Sha256Blind, shaProof.Ciphersuite);
            Assert.AreEqual(BbsCiphersuite.Bls12Curve381Shake256Blind, shakeProof.Ciphersuite);
        }
    }


    [TestMethod]
    public void GetAlgebraicTagRejectsTheCoreCiphersuite()
    {
        Assert.ThrowsExactly<ArgumentException>(() => _ = BbsBlindProof.GetAlgebraicTag(BbsCiphersuite.Bls12Curve381Sha256));
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


    private static BigInteger ReadBigEndian(ReadOnlySpan<byte> source) =>
        new(source, isUnsigned: true, isBigEndian: true);


    /// <summary>
    /// Builds a well-formed framed blind proof: a core proof with every
    /// scalar slot set to 1, <paramref name="disclosedIndexes"/> (already
    /// strictly ascending), and <paramref name="committedDisclosureCount"/>
    /// committed disclosures at indexes <c>0..N-1</c> with
    /// <c>PointFiller</c> commitments and unit response scalars.
    /// </summary>
    private static (IMemoryOwner<byte> Owner, FramedProofLayout Layout) BuildValidFramedProof(
        int undisclosedMessageCount,
        int[] disclosedIndexes,
        int committedDisclosureCount)
    {
        int coreProofSizeBytes = BbsProof.ComputeSizeBytes(undisclosedMessageCount);
        int totalLength = BbsBlindProof.ComputeSizeBytes(undisclosedMessageCount, disclosedIndexes.Length, committedDisclosureCount);

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(totalLength);
        Span<byte> buf = owner.Memory.Span[..totalLength];

        int cursor = 0;
        BinaryPrimitives.WriteInt64BigEndian(buf.Slice(cursor, BbsBlindProof.Int64FieldSizeBytes), coreProofSizeBytes);
        cursor += BbsBlindProof.Int64FieldSizeBytes;

        PointFiller.CopyTo(buf.Slice(cursor + BbsProof.ABarOffset, BbsProof.ABarSizeBytes));
        PointFiller.CopyTo(buf.Slice(cursor + BbsProof.BBarOffset, BbsProof.BBarSizeBytes));
        PointFiller.CopyTo(buf.Slice(cursor + BbsProof.DOffset, BbsProof.DSizeBytes));
        int coreScalarCount = 4 + undisclosedMessageCount;
        for(int i = 0; i < coreScalarCount; i++)
        {
            WriteBigEndian(BigInteger.One, buf.Slice(cursor + BbsProof.EHatOffset + i * BbsProof.ScalarSizeBytes, BbsProof.ScalarSizeBytes));
        }
        cursor += coreProofSizeBytes;

        BinaryPrimitives.WriteInt64BigEndian(buf.Slice(cursor, BbsBlindProof.Int64FieldSizeBytes), disclosedIndexes.Length);
        int disclosedIndexesLengthFieldOffset = cursor;
        cursor += BbsBlindProof.Int64FieldSizeBytes;
        int disclosedIndexesOffset = cursor;
        foreach(int index in disclosedIndexes)
        {
            BinaryPrimitives.WriteInt64BigEndian(buf.Slice(cursor, BbsBlindProof.Int64FieldSizeBytes), index);
            cursor += BbsBlindProof.Int64FieldSizeBytes;
        }

        BinaryPrimitives.WriteInt64BigEndian(buf.Slice(cursor, BbsBlindProof.Int64FieldSizeBytes), committedDisclosureCount);
        cursor += BbsBlindProof.Int64FieldSizeBytes;
        int committedDisclosurePointsOffset = cursor;
        for(int i = 0; i < committedDisclosureCount; i++)
        {
            PointFiller.CopyTo(buf.Slice(cursor + i * BbsBlindProof.CommittedDisclosurePointSizeBytes, BbsBlindProof.CommittedDisclosurePointSizeBytes));
        }
        cursor += committedDisclosureCount * BbsBlindProof.CommittedDisclosurePointSizeBytes;
        int committedDisclosureScalarsOffset = cursor;
        for(int i = 0; i < committedDisclosureCount; i++)
        {
            WriteBigEndian(BigInteger.One, buf.Slice(cursor + i * BbsBlindProof.CommittedDisclosureScalarSizeBytes, BbsBlindProof.CommittedDisclosureScalarSizeBytes));
        }
        cursor += committedDisclosureCount * BbsBlindProof.CommittedDisclosureScalarSizeBytes;

        BinaryPrimitives.WriteInt64BigEndian(buf.Slice(cursor, BbsBlindProof.Int64FieldSizeBytes), committedDisclosureCount);
        int commitsIndexesLengthFieldOffset = cursor;
        cursor += BbsBlindProof.Int64FieldSizeBytes;
        int commitsIndexesOffset = cursor;
        for(int i = 0; i < committedDisclosureCount; i++)
        {
            BinaryPrimitives.WriteInt64BigEndian(buf.Slice(cursor, BbsBlindProof.Int64FieldSizeBytes), i);
            cursor += BbsBlindProof.Int64FieldSizeBytes;
        }

        Assert.AreEqual(totalLength, cursor, "The builder's own cursor arithmetic must land exactly on the computed total length.");

        FramedProofLayout layout = new(
            disclosedIndexesLengthFieldOffset,
            disclosedIndexesOffset,
            committedDisclosurePointsOffset,
            committedDisclosureScalarsOffset,
            commitsIndexesLengthFieldOffset,
            commitsIndexesOffset,
            totalLength);

        return (owner, layout);
    }
}

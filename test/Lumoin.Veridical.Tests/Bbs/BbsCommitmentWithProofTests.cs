using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Structural and canonicity gates for
/// <see cref="BbsCommitmentWithProof.FromCanonical"/>: the size-recovery
/// arithmetic (<c>48 + 32 * (M + 2)</c>), the offset constants, and the
/// scalar-canonicity loop over every slot after the commitment point
/// <c>C</c> (<c>s^</c>, each <c>m^_i</c>, and the challenge). Mirrors
/// <see cref="BbsCanonicityTests"/>' assertion style for the sibling
/// <see cref="BbsProof"/> type.
/// </summary>
[TestClass]
internal sealed class BbsCommitmentWithProofTests
{
    private const int ScalarSize = BbsCommitmentWithProof.ScalarSizeBytes;

    private static readonly BbsCiphersuite Suite = BbsCiphersuite.Bls12Curve381Sha256Blind;

    //A valid 48-byte G1 point used as inert filler for the C slot. FromCanonical
    //does not validate point geometry (deferred to the operation surfaces), so
    //any 48-byte value is accepted here.
    private static ReadOnlySpan<byte> PointFiller =>
        WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.Bls12Curve381);


    [TestMethod]
    public void ComputeSizeBytesMatchesLayoutFormula()
    {
        Assert.AreEqual(112, BbsCommitmentWithProof.ComputeSizeBytes(committedMessageCount: 0));
        Assert.AreEqual(112 + 3 * ScalarSize, BbsCommitmentWithProof.ComputeSizeBytes(committedMessageCount: 3));
    }


    [TestMethod]
    public void FromCanonicalAcceptsMinimalLayoutWithNoCommittedMessages()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsCommitmentWithProof.MinimumSizeBytes);
        Memory<byte> buf = owner.Memory[..BbsCommitmentWithProof.MinimumSizeBytes];
        BuildBuffer(buf.Span, committedMessageCount: 0, scalarValue: BigInteger.One);

        using BbsCommitmentWithProof commitment = BbsCommitmentWithProof.FromCanonical(buf.Span, Suite, TestSetup.Pool);

        Assert.AreEqual(0, commitment.CommittedMessageCount);
        Assert.IsTrue(PointFiller.SequenceEqual(commitment.GetCBytes()));
    }


    [TestMethod]
    public void FromCanonicalAcceptsLayoutWithCommittedMessages()
    {
        int size = BbsCommitmentWithProof.ComputeSizeBytes(committedMessageCount: 2);
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(size);
        Memory<byte> buf = owner.Memory[..size];
        BuildBuffer(buf.Span, committedMessageCount: 2, scalarValue: BigInteger.One);

        using BbsCommitmentWithProof commitment = BbsCommitmentWithProof.FromCanonical(buf.Span, Suite, TestSetup.Pool);

        Assert.AreEqual(2, commitment.CommittedMessageCount);
        Assert.AreEqual(BigInteger.One, ReadBigEndian(commitment.GetMHatBytes(0)));
        Assert.AreEqual(BigInteger.One, ReadBigEndian(commitment.GetMHatBytes(1)));
        Assert.AreEqual(BigInteger.One, ReadBigEndian(commitment.GetChallengeBytes()));
    }


    [TestMethod]
    public void FromCanonicalRejectsTooShortBuffer()
    {
        byte[] tooShort = new byte[BbsCommitmentWithProof.MinimumSizeBytes - 1];

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsCommitmentWithProof.FromCanonical(tooShort, Suite, TestSetup.Pool));
        Assert.Contains("at least", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void FromCanonicalRejectsLengthNotAMultipleOfScalarSize()
    {
        byte[] misaligned = new byte[BbsCommitmentWithProof.MinimumSizeBytes + 1];

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsCommitmentWithProof.FromCanonical(misaligned, Suite, TestSetup.Pool));
        Assert.Contains("multiple of the scalar length", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void FromCanonicalRejectsSHatAtScalarFieldOrder()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsCommitmentWithProof.MinimumSizeBytes);
        Memory<byte> buf = owner.Memory[..BbsCommitmentWithProof.MinimumSizeBytes];
        BuildBuffer(buf.Span, committedMessageCount: 0, scalarValue: BigInteger.One);
        WriteBigEndian(FieldOrder(), buf.Span.Slice(BbsCommitmentWithProof.SHatOffset, ScalarSize));

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsCommitmentWithProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
        Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void FromCanonicalRejectsSHatEqualZero()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsCommitmentWithProof.MinimumSizeBytes);
        Memory<byte> buf = owner.Memory[..BbsCommitmentWithProof.MinimumSizeBytes];
        BuildBuffer(buf.Span, committedMessageCount: 0, scalarValue: BigInteger.One);
        buf.Span.Slice(BbsCommitmentWithProof.SHatOffset, ScalarSize).Clear();

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsCommitmentWithProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
        Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void FromCanonicalRejectsMHatAtScalarFieldOrder()
    {
        int size = BbsCommitmentWithProof.ComputeSizeBytes(committedMessageCount: 1);
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(size);
        Memory<byte> buf = owner.Memory[..size];
        BuildBuffer(buf.Span, committedMessageCount: 1, scalarValue: BigInteger.One);
        WriteBigEndian(FieldOrder(), buf.Span.Slice(BbsCommitmentWithProof.MessageHatsOffset, ScalarSize));

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsCommitmentWithProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
        Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void FromCanonicalRejectsChallengeEqualZero()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsCommitmentWithProof.MinimumSizeBytes);
        Memory<byte> buf = owner.Memory[..BbsCommitmentWithProof.MinimumSizeBytes];
        BuildBuffer(buf.Span, committedMessageCount: 0, scalarValue: BigInteger.One);
        buf.Span.Slice(BbsCommitmentWithProof.MessageHatsOffset, ScalarSize).Clear();

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsCommitmentWithProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
        Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void GetMHatBytesThrowsOnOutOfRangeIndex()
    {
        int size = BbsCommitmentWithProof.ComputeSizeBytes(committedMessageCount: 1);
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(size);
        Memory<byte> buf = owner.Memory[..size];
        BuildBuffer(buf.Span, committedMessageCount: 1, scalarValue: BigInteger.One);
        using BbsCommitmentWithProof commitment = BbsCommitmentWithProof.FromCanonical(buf.Span, Suite, TestSetup.Pool);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => _ = commitment.GetMHatBytes(-1));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => _ = commitment.GetMHatBytes(1));
    }


    [TestMethod]
    public void CiphersuiteTagRoundTripsThroughFromCanonical()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsCommitmentWithProof.MinimumSizeBytes);
        Memory<byte> buf = owner.Memory[..BbsCommitmentWithProof.MinimumSizeBytes];
        BuildBuffer(buf.Span, committedMessageCount: 0, scalarValue: BigInteger.One);

        using BbsCommitmentWithProof shaCommitment = BbsCommitmentWithProof.FromCanonical(buf.Span, BbsCiphersuite.Bls12Curve381Sha256Blind, TestSetup.Pool);
        using BbsCommitmentWithProof shakeCommitment = BbsCommitmentWithProof.FromCanonical(buf.Span, BbsCiphersuite.Bls12Curve381Shake256Blind, TestSetup.Pool);

        Assert.AreEqual(BbsCiphersuite.Bls12Curve381Sha256Blind, shaCommitment.Ciphersuite);
        Assert.AreEqual(BbsCiphersuite.Bls12Curve381Shake256Blind, shakeCommitment.Ciphersuite);
    }


    [TestMethod]
    public void GetAlgebraicTagRejectsTheCoreCiphersuite()
    {
        //The Blind Interface tag is distinct from the core one: a commitment
        //produced under the core api_id is not a meaningful value (Commit is
        //a Blind-Interface-only operation), so the core ciphersuite must be
        //rejected rather than silently accepted.
        Assert.ThrowsExactly<ArgumentException>(() => _ = BbsCommitmentWithProof.GetAlgebraicTag(BbsCiphersuite.Bls12Curve381Sha256));
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
    /// Fills a commitment-with-proof buffer of any length: <c>PointFiller</c>
    /// in the <c>C</c> slot and <paramref name="scalarValue"/> in every
    /// scalar slot from <see cref="BbsCommitmentWithProof.SHatOffset"/> to
    /// the end (<c>s^</c>, each <c>m^_i</c>, and the challenge).
    /// </summary>
    private static void BuildBuffer(Span<byte> buf, int committedMessageCount, BigInteger scalarValue)
    {
        buf.Clear();
        PointFiller.CopyTo(buf.Slice(BbsCommitmentWithProof.COffset, BbsCommitmentWithProof.CSizeBytes));

        int scalarCount = committedMessageCount + 2;
        for(int i = 0; i < scalarCount; i++)
        {
            WriteBigEndian(scalarValue, buf.Slice(BbsCommitmentWithProof.SHatOffset + i * ScalarSize, ScalarSize));
        }
    }
}

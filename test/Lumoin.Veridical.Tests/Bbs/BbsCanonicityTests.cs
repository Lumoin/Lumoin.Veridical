using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Gates for the canonicity checks added to <see cref="BbsSignature.FromCanonical"/>
/// and <see cref="BbsProof.FromCanonical"/>. The BBS+ spec (octets_to_signature,
/// octets_to_proof) requires every scalar slot to be in [1, r-1]; a value at or
/// above r is the non-canonical second encoding of the same residue (the
/// malleability vector); zero makes the underlying algebraic relations collapse.
/// Both gates reject at deserialisation so the invalid bytes never reach the
/// transcript absorb or the MSM.
/// </summary>
[TestClass]
internal sealed class BbsCanonicityTests
{
    //BLS12-381 scalar field size: 32 bytes.
    private const int ScalarSize = BbsSignature.ESizeBytes;

    //The ciphersuite used throughout; the canonicity checks are independent of
    //the ciphersuite choice (both SHA-256 and SHAKE-256 share the same
    //underlying BLS12-381 scalar field).
    private static readonly BbsCiphersuite Suite = BbsCiphersuite.Bls12Curve381Sha256;

    //A valid 48-byte G1 point used as inert filler for the point slots of the
    //signature and proof. FromCanonical does not validate point geometry (that
    //happens at decode inside the MSM), so any 48-byte value is accepted here.
    private static ReadOnlySpan<byte> PointFiller =>
        WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.Bls12Curve381);


    [TestMethod]
    public void SignatureEAtScalarFieldOrderIsRejected()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsSignature.SizeBytes);
        Memory<byte> buf = owner.Memory[..BbsSignature.SizeBytes];
        BuildSignatureBuffer(buf.Span, eValue: FieldOrder());

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsSignature.FromCanonical(buf.Span, Suite, TestSetup.Pool));
        Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void SignatureEEqualZeroIsRejected()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsSignature.SizeBytes);
        Memory<byte> buf = owner.Memory[..BbsSignature.SizeBytes];
        BuildSignatureBuffer(buf.Span, eValue: BigInteger.Zero);

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsSignature.FromCanonical(buf.Span, Suite, TestSetup.Pool));
        Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void SignatureEAtOrderMinusOneAccepts()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsSignature.SizeBytes);
        Memory<byte> buf = owner.Memory[..BbsSignature.SizeBytes];
        BuildSignatureBuffer(buf.Span, eValue: FieldOrder() - 1);

        using BbsSignature sig = BbsSignature.FromCanonical(buf.Span, Suite, TestSetup.Pool);

        Assert.IsNotNull(sig);
    }


    [TestMethod]
    public void ProofWithAllScalarSlotsOneAccepts()
    {
        //All four fixed scalar slots (e^, r1^, r3^, c) set to 1 — the
        //smallest canonical non-zero value.
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsProof.MinimumSizeBytes);
        Memory<byte> buf = owner.Memory[..BbsProof.MinimumSizeBytes];
        BuildMinimumProofBuffer(buf.Span, scalarValue: BigInteger.One);

        using BbsProof proof = BbsProof.FromCanonical(buf.Span, Suite, TestSetup.Pool);

        Assert.AreEqual(0, proof.UndisclosedMessageCount);
    }


    [TestMethod]
    public void ProofChallengeSlotAtScalarFieldOrderIsRejected()
    {
        //With zero undisclosed messages, the challenge c is the last 32 bytes
        //of the minimum-size proof (offset CommitmentsOffset = 240).
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsProof.MinimumSizeBytes);
        Memory<byte> buf = owner.Memory[..BbsProof.MinimumSizeBytes];
        //Populate all scalar slots with 1, then overwrite c = r.
        BuildMinimumProofBuffer(buf.Span, scalarValue: BigInteger.One);
        WriteBigEndian(FieldOrder(), buf.Span.Slice(BbsProof.CommitmentsOffset, ScalarSize));

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
        Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void ProofEHatSlotZeroIsRejected()
    {
        //e^ is the first scalar slot; zero must be rejected even though 0 < r.
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsProof.MinimumSizeBytes);
        Memory<byte> buf = owner.Memory[..BbsProof.MinimumSizeBytes];
        BuildMinimumProofBuffer(buf.Span, scalarValue: BigInteger.One);
        //Overwrite e^ with zero.
        buf.Span.Slice(BbsProof.EHatOffset, ScalarSize).Clear();

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
        Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void ProofUndisclosedMessageCommitmentAtOrderIsRejected()
    {
        //With one undisclosed message, the layout is:
        //  3×48 (Abar, Bbar, D) + e^ + r1^ + r3^ + m^_1 + c
        //m^_1 sits at CommitmentsOffset; c follows at CommitmentsOffset + ScalarSize.
        int proofSize = BbsProof.ComputeSizeBytes(undisclosedMessageCount: 1);
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(proofSize);
        Memory<byte> buf = owner.Memory[..proofSize];
        //Set all five scalar slots to 1.
        BuildProofBuffer(buf.Span, scalarCount: 5, scalarValue: BigInteger.One);
        //Overwrite m^_1 (= the first commitment) with the field order.
        WriteBigEndian(FieldOrder(), buf.Span.Slice(BbsProof.CommitmentsOffset, ScalarSize));

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsProof.FromCanonical(buf.Span, Suite, TestSetup.Pool));
        Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void ProofWithOneUndisclosedMessageAndAllScalarSlotsOneAccepts()
    {
        //All five scalar slots (e^, r1^, r3^, m^_1, c) set to 1 — the smallest
        //canonical non-zero value. One undisclosed message, so 304-byte proof.
        int proofSize = BbsProof.ComputeSizeBytes(undisclosedMessageCount: 1);
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(proofSize);
        Memory<byte> buf = owner.Memory[..proofSize];
        BuildProofBuffer(buf.Span, scalarCount: 5, scalarValue: BigInteger.One);

        using BbsProof proof = BbsProof.FromCanonical(buf.Span, Suite, TestSetup.Pool);

        Assert.AreEqual(1, proof.UndisclosedMessageCount);
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
    /// Fills an 80-byte buffer with <c>PointFiller</c> in the A slot and
    /// <paramref name="eValue"/> in the e slot.
    /// </summary>
    private static void BuildSignatureBuffer(Span<byte> buf, BigInteger eValue)
    {
        buf.Clear();
        PointFiller.CopyTo(buf.Slice(BbsSignature.AOffset, BbsSignature.ASizeBytes));
        WriteBigEndian(eValue, buf.Slice(BbsSignature.EOffset, ScalarSize));
    }


    /// <summary>
    /// Fills a minimum-size (272-byte) proof buffer with <c>PointFiller</c> in
    /// the three point slots and <paramref name="scalarValue"/> in all four
    /// fixed scalar slots.
    /// </summary>
    private static void BuildMinimumProofBuffer(Span<byte> buf, BigInteger scalarValue)
    {
        BuildProofBuffer(buf, scalarCount: 4, scalarValue);
    }


    /// <summary>
    /// Fills a proof buffer of any length. Writes <c>PointFiller</c> in the three
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

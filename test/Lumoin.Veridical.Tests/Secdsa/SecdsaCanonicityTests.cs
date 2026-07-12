using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Secdsa;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Gates for the canonicity checks added to
/// <see cref="SecdsaSignature.FromCanonical"/> and
/// <see cref="DlEqualityProof.FromCanonical"/>. Both types enforce that the
/// response scalar s is in [1, n-1] (the ECDSA non-malleability invariant).
/// The DL-equality proof's r component is intentionally NOT range-checked —
/// it is the raw full-width Fiat-Shamir hash value which may legitimately
/// exceed the group order n; reducing it before storage would self-verify yet
/// break interoperability. These tests pin that asymmetry.
/// </summary>
[TestClass]
internal sealed class SecdsaCanonicityTests
{
    //P-256 scalar (and hash digest) width: 32 bytes.
    private const int ScalarSize = SecdsaSignature.RSizeBytes;


    [TestMethod]
    public void SignatureRComponentZeroIsRejected()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(SecdsaSignature.SizeBytes);
        Memory<byte> buf = owner.Memory[..SecdsaSignature.SizeBytes];
        buf.Span.Clear();
        //s = n-1 (valid); r = 0 (invalid).
        WriteBigEndian(GroupOrder() - 1, buf.Span.Slice(SecdsaSignature.SOffset, ScalarSize));

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = SecdsaSignature.FromCanonical(buf.Span, BaseMemoryPool.Shared));
        Assert.Contains("[1, n-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void SignatureSComponentZeroIsRejected()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(SecdsaSignature.SizeBytes);
        Memory<byte> buf = owner.Memory[..SecdsaSignature.SizeBytes];
        buf.Span.Clear();
        //r = n-1 (valid); s = 0 (invalid).
        WriteBigEndian(GroupOrder() - 1, buf.Span.Slice(SecdsaSignature.ROffset, ScalarSize));

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = SecdsaSignature.FromCanonical(buf.Span, BaseMemoryPool.Shared));
        Assert.Contains("[1, n-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void SignatureRComponentAtGroupOrderIsRejected()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(SecdsaSignature.SizeBytes);
        Memory<byte> buf = owner.Memory[..SecdsaSignature.SizeBytes];
        buf.Span.Clear();
        //r = n (non-canonical); s = n-1 (valid).
        WriteBigEndian(GroupOrder(), buf.Span.Slice(SecdsaSignature.ROffset, ScalarSize));
        WriteBigEndian(GroupOrder() - 1, buf.Span.Slice(SecdsaSignature.SOffset, ScalarSize));

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = SecdsaSignature.FromCanonical(buf.Span, BaseMemoryPool.Shared));
        Assert.Contains("[1, n-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void SignatureSComponentAtGroupOrderIsRejected()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(SecdsaSignature.SizeBytes);
        Memory<byte> buf = owner.Memory[..SecdsaSignature.SizeBytes];
        buf.Span.Clear();
        //r = n-1 (valid); s = n (non-canonical).
        WriteBigEndian(GroupOrder() - 1, buf.Span.Slice(SecdsaSignature.ROffset, ScalarSize));
        WriteBigEndian(GroupOrder(), buf.Span.Slice(SecdsaSignature.SOffset, ScalarSize));

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = SecdsaSignature.FromCanonical(buf.Span, BaseMemoryPool.Shared));
        Assert.Contains("[1, n-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void SignatureRAndSAtOrderMinusOneAccepts()
    {
        //r = s = n-1: both components are in [1, n-1] → accepted.
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(SecdsaSignature.SizeBytes);
        Memory<byte> buf = owner.Memory[..SecdsaSignature.SizeBytes];
        buf.Span.Clear();
        WriteBigEndian(GroupOrder() - 1, buf.Span.Slice(SecdsaSignature.ROffset, ScalarSize));
        WriteBigEndian(GroupOrder() - 1, buf.Span.Slice(SecdsaSignature.SOffset, ScalarSize));

        using SecdsaSignature sig = SecdsaSignature.FromCanonical(buf.Span, BaseMemoryPool.Shared);

        Assert.IsNotNull(sig);
    }


    [TestMethod]
    public void DlEqualityProofSComponentZeroIsRejected()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(DlEqualityProof.SizeBytes);
        Memory<byte> buf = owner.Memory[..DlEqualityProof.SizeBytes];
        buf.Span.Clear();
        //r = all-0xFF (full-width digest, deliberately unchecked — see type remarks).
        buf.Span.Slice(DlEqualityProof.ROffset, ScalarSize).Fill(0xFF);
        //s = 0 (invalid).

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = DlEqualityProof.FromCanonical(buf.Span, BaseMemoryPool.Shared));
        Assert.Contains("[1, n-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void DlEqualityProofSComponentAtGroupOrderIsRejected()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(DlEqualityProof.SizeBytes);
        Memory<byte> buf = owner.Memory[..DlEqualityProof.SizeBytes];
        buf.Span.Clear();
        //r = all-0xFF (full-width, unchecked).
        buf.Span.Slice(DlEqualityProof.ROffset, ScalarSize).Fill(0xFF);
        //s = n (non-canonical).
        WriteBigEndian(GroupOrder(), buf.Span.Slice(DlEqualityProof.SOffset, ScalarSize));

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = DlEqualityProof.FromCanonical(buf.Span, BaseMemoryPool.Shared));
        Assert.Contains("[1, n-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void DlEqualityProofRComponentFullWidthWithSAtOrderMinusOneAccepts()
    {
        //r is the raw Fiat-Shamir digest — it may legally exceed n and is
        //deliberately NOT range-checked by FromCanonical (see DlEqualityProof
        //remarks). This test pins that asymmetry: all-0xFF in r (> n) is fine;
        //only s is checked.
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(DlEqualityProof.SizeBytes);
        Memory<byte> buf = owner.Memory[..DlEqualityProof.SizeBytes];
        buf.Span.Clear();
        //r = all-0xFF > n: full-width digest, must be stored unreduced.
        buf.Span.Slice(DlEqualityProof.ROffset, ScalarSize).Fill(0xFF);
        //s = n-1: valid canonical scalar.
        WriteBigEndian(GroupOrder() - 1, buf.Span.Slice(DlEqualityProof.SOffset, ScalarSize));

        using DlEqualityProof proof = DlEqualityProof.FromCanonical(buf.Span, BaseMemoryPool.Shared);

        Assert.IsNotNull(proof);
    }


    private static BigInteger GroupOrder() =>
        WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.P256);


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
}

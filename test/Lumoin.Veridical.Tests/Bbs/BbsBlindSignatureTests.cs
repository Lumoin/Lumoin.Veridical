using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Bbs;

/// <summary>
/// Structural and canonicity gates for
/// <see cref="BbsBlindSignature.FromCanonical"/>: the fixed 80-byte
/// <c>(A, e)</c> layout — wire-identical to <see cref="BbsSignature"/> —
/// and the Blind BBS Interface tag that keeps the two types from being
/// conflated. Mirrors <see cref="BbsCanonicityTests"/>' assertion style
/// for the sibling <see cref="BbsSignature"/> type.
/// </summary>
[TestClass]
internal sealed class BbsBlindSignatureTests
{
    private const int ScalarSize = BbsBlindSignature.ESizeBytes;

    private static readonly BbsCiphersuite Suite = BbsCiphersuite.Bls12Curve381Sha256Blind;

    private static ReadOnlySpan<byte> PointFiller =>
        WellKnownCurves.GetG1GeneratorCompressed(CurveParameterSet.Bls12Curve381);


    [TestMethod]
    public void FromCanonicalRejectsWrongLength()
    {
        byte[] tooShort = new byte[BbsBlindSignature.SizeBytes - 1];

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsBlindSignature.FromCanonical(tooShort, Suite, TestSetup.Pool));
        Assert.Contains("exactly", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void FromCanonicalRejectsEAtScalarFieldOrder()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsBlindSignature.SizeBytes);
        Memory<byte> buf = owner.Memory[..BbsBlindSignature.SizeBytes];
        BuildBuffer(buf.Span, eValue: FieldOrder());

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsBlindSignature.FromCanonical(buf.Span, Suite, TestSetup.Pool));
        Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void FromCanonicalRejectsEEqualZero()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsBlindSignature.SizeBytes);
        Memory<byte> buf = owner.Memory[..BbsBlindSignature.SizeBytes];
        BuildBuffer(buf.Span, eValue: BigInteger.Zero);

        ArgumentException ex = Assert.ThrowsExactly<ArgumentException>(() =>
            _ = BbsBlindSignature.FromCanonical(buf.Span, Suite, TestSetup.Pool));
        Assert.Contains("[1, r-1]", ex.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void FromCanonicalAcceptsEAtOrderMinusOne()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsBlindSignature.SizeBytes);
        Memory<byte> buf = owner.Memory[..BbsBlindSignature.SizeBytes];
        BuildBuffer(buf.Span, eValue: FieldOrder() - 1);

        using BbsBlindSignature signature = BbsBlindSignature.FromCanonical(buf.Span, Suite, TestSetup.Pool);

        Assert.IsTrue(PointFiller.SequenceEqual(signature.GetABytes()));
    }


    [TestMethod]
    public void CiphersuiteTagRoundTripsThroughFromCanonical()
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(BbsBlindSignature.SizeBytes);
        Memory<byte> buf = owner.Memory[..BbsBlindSignature.SizeBytes];
        BuildBuffer(buf.Span, eValue: BigInteger.One);

        using BbsBlindSignature shaSignature = BbsBlindSignature.FromCanonical(buf.Span, BbsCiphersuite.Bls12Curve381Sha256Blind, TestSetup.Pool);
        using BbsBlindSignature shakeSignature = BbsBlindSignature.FromCanonical(buf.Span, BbsCiphersuite.Bls12Curve381Shake256Blind, TestSetup.Pool);

        Assert.AreEqual(BbsCiphersuite.Bls12Curve381Sha256Blind, shaSignature.Ciphersuite);
        Assert.AreEqual(BbsCiphersuite.Bls12Curve381Shake256Blind, shakeSignature.Ciphersuite);
    }


    [TestMethod]
    public void GetAlgebraicTagRejectsTheCoreCiphersuite()
    {
        //A blind signature is produced and verified under the Blind
        //Interface api_id; conflating it with the core ciphersuite would
        //silently compute the wrong domain rather than fail loudly, so the
        //core ciphersuite must be rejected here rather than accepted.
        Assert.ThrowsExactly<ArgumentException>(() => _ = BbsBlindSignature.GetAlgebraicTag(BbsCiphersuite.Bls12Curve381Sha256));
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


    private static void BuildBuffer(Span<byte> buf, BigInteger eValue)
    {
        buf.Clear();
        PointFiller.CopyTo(buf.Slice(BbsBlindSignature.AOffset, BbsBlindSignature.ASizeBytes));
        WriteBigEndian(eValue, buf.Slice(BbsBlindSignature.EOffset, ScalarSize));
    }
}

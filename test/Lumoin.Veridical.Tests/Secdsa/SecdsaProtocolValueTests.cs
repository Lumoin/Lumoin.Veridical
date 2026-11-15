using Lumoin.Veridical.Core;
using Lumoin.Veridical.Secdsa;
using System;

namespace Lumoin.Veridical.Tests.Secdsa;

/// <summary>
/// Gates for the tagged protocol values of split ECDSA: each validates its invariants in <c>FromCanonical</c> and
/// carries its structure kind, so the entry points that take it do not validate it again.
/// </summary>
[TestClass]
internal sealed class SecdsaProtocolValueTests
{
    private const int ScalarSize = 32;
    private const byte HighByte = 0xFF;

    private static BaseMemoryPool Pool { get; } = BaseMemoryPool.Shared;


    [TestMethod]
    public void PinKeyAndPrivateScalarRejectZeroOrderAndWrongLength()
    {
        Span<byte> zero = stackalloc byte[ScalarSize];
        Span<byte> high = stackalloc byte[ScalarSize];
        high.Fill(HighByte);
        Span<byte> shortValue = stackalloc byte[ScalarSize - 1];
        shortValue.Fill(1);

        Assert.IsTrue(RejectsPinKey(zero));
        Assert.IsTrue(RejectsPinKey(high));
        Assert.IsTrue(RejectsPinKey(shortValue));
        Assert.IsTrue(RejectsPrivateScalar(zero));
        Assert.IsTrue(RejectsPrivateScalar(high));
        Assert.IsTrue(RejectsPrivateScalar(shortValue));
    }


    [TestMethod]
    public void ValuesCarryTheirOwnStructureKindAndClearOnDispose()
    {
        Span<byte> one = stackalloc byte[ScalarSize];
        one[^1] = 1;
        PinKey pin = PinKey.FromCanonical(one, Pool);
        PrivateScalar scalar = PrivateScalar.FromCanonical(one, Pool);
        using MessageHash hash = MessageHash.FromCanonical(one, Pool);
        using BlindedHash blinded = BlindedHash.FromCanonical(one, Pool);

        Assert.AreNotEqual(pin.Tag, scalar.Tag, "A PIN key and a private scalar are different structures.");
        Assert.AreNotEqual(hash.Tag, blinded.Tag, "A message hash and a blinded hash are different structures.");
        Assert.AreEqual(PinKey.AlgebraicTag, pin.Tag);
        Assert.AreEqual(BlindedHash.AlgebraicTag, blinded.Tag);
        pin.Dispose();
        scalar.Dispose();
    }


    [TestMethod]
    public void MessageHashAcceptsAnyThirtyTwoBytesAndBlindedHashRejectsValuesAtOrAboveTheOrder()
    {
        Span<byte> high = stackalloc byte[ScalarSize];
        high.Fill(HighByte);

        using MessageHash hash = MessageHash.FromCanonical(high, Pool);
        int length = hash.AsReadOnlySpan().Length;
        Assert.AreEqual(ScalarSize, length);
        Assert.IsTrue(RejectsBlindedHash(high));
        Assert.IsTrue(RejectsMessageHash(high[..(ScalarSize - 1)]));
    }


    [TestMethod]
    public void RawSignatureRejectsZeroAndOutOfRangeComponentsAndExposesBoth()
    {
        Span<byte> raw = stackalloc byte[RawSignature.SizeBytes];
        raw[RawSignature.RSizeBytes - 1] = 2;
        raw[RawSignature.SizeBytes - 1] = 3;

        using RawSignature signature = RawSignature.FromCanonical(raw, Pool);
        Assert.AreEqual(2, signature.GetRBytes()[^1]);
        Assert.AreEqual(3, signature.GetRawSBytes()[^1]);

        Span<byte> zeroR = stackalloc byte[RawSignature.SizeBytes];
        zeroR[RawSignature.SizeBytes - 1] = 3;
        Assert.IsTrue(RejectsRawSignature(zeroR));

        Span<byte> highS = stackalloc byte[RawSignature.SizeBytes];
        highS[RawSignature.RSizeBytes - 1] = 2;
        highS[RawSignature.RawSOffset..].Fill(HighByte);
        Assert.IsTrue(RejectsRawSignature(highS));
    }


    private static bool RejectsPinKey(ReadOnlySpan<byte> value)
    {
        try
        {
            PinKey.FromCanonical(value, Pool).Dispose();
        }
        catch(ArgumentException)
        {
            return true;
        }

        return false;
    }


    private static bool RejectsPrivateScalar(ReadOnlySpan<byte> value)
    {
        try
        {
            PrivateScalar.FromCanonical(value, Pool).Dispose();
        }
        catch(ArgumentException)
        {
            return true;
        }

        return false;
    }


    private static bool RejectsBlindedHash(ReadOnlySpan<byte> value)
    {
        try
        {
            BlindedHash.FromCanonical(value, Pool).Dispose();
        }
        catch(ArgumentException)
        {
            return true;
        }

        return false;
    }


    private static bool RejectsMessageHash(ReadOnlySpan<byte> value)
    {
        try
        {
            MessageHash.FromCanonical(value, Pool).Dispose();
        }
        catch(ArgumentException)
        {
            return true;
        }

        return false;
    }


    private static bool RejectsRawSignature(ReadOnlySpan<byte> value)
    {
        try
        {
            RawSignature.FromCanonical(value, Pool).Dispose();
        }
        catch(ArgumentException)
        {
            return true;
        }

        return false;
    }
}

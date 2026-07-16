using Lumoin.Veridical.Core.ConstraintSystems;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Tests for the fixed-point encoding convention. They pin the exact-or-reject
/// policy (no rounding), the non-negative domain, the derived bit width and its
/// field-safe cap, and the decimal round trip — the properties the supply-chain
/// predicates' soundness rests on.
/// </summary>
[TestClass]
internal sealed class FixedPointScaleTests
{
    [TestMethod]
    public void EncodeScalesByTheFractionalDigits()
    {
        FixedPointScale scale = FixedPointScale.OfFractionalDigits(2);

        Assert.AreEqual((BigInteger)1250, scale.Encode(12.50m), "12.50 at two fractional digits encodes to 1250.");
        Assert.AreEqual((BigInteger)0, scale.Encode(0m), "Zero encodes to zero at any scale.");
    }


    [TestMethod]
    public void EncodeAcceptsTrailingZeroForms()
    {
        FixedPointScale scale = FixedPointScale.OfFractionalDigits(2);

        //1.230 and 1.23 denote the same quantity; both encode exactly at two digits.
        Assert.AreEqual((BigInteger)123, scale.Encode(1.230m));
        Assert.AreEqual((BigInteger)123, scale.Encode(1.23m));
    }


    [TestMethod]
    public void EncodeRejectsFinerResolutionThanTheScale()
    {
        FixedPointScale scale = FixedPointScale.OfFractionalDigits(1);

        //32.567 carries three fractional digits; a one-digit scale cannot hold it,
        //and it is rejected rather than rounded.
        Assert.ThrowsExactly<ArgumentException>(() => scale.Encode(32.567m));
        Assert.IsFalse(scale.TryEncode(32.567m, out _), "TryEncode reports the inexact value instead of throwing.");
    }


    [TestMethod]
    public void EncodeRejectsNegativeValues()
    {
        FixedPointScale scale = FixedPointScale.OfFractionalDigits(2);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => scale.Encode(-0.01m));
        Assert.IsFalse(scale.TryEncode(-0.01m, out _));
    }


    [TestMethod]
    public void OfFractionalDigitsRejectsAnExponentOutsideDecimalsCeiling()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => FixedPointScale.OfFractionalDigits(-1));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => FixedPointScale.OfFractionalDigits(FixedPointScale.MaximumFractionalDigits + 1));
    }


    [TestMethod]
    public void RequiredBitsIsTheSmallestWidthHoldingTheValue()
    {
        Assert.AreEqual(1, FixedPointScale.RequiredBits(0), "Zero still needs a one-bit range check (a width below one is rejected).");
        Assert.AreEqual(10, FixedPointScale.RequiredBits(1000), "1000 < 2^10 but not < 2^9.");
        Assert.AreEqual(10, FixedPointScale.RequiredBits(1023), "2^10 - 1 fits in ten bits.");
        Assert.AreEqual(11, FixedPointScale.RequiredBits(1024), "2^10 needs eleven bits.");
    }


    [TestMethod]
    public void RequiredBitsMarksTheFieldSafeBoundaryAtTheCap()
    {
        //The cap is 252: a domain occupying up to 252 bits keeps r >= 2^(bits+1)
        //on both wired curves; 253 does not on BN254.
        //The cap MaximumEncodedBits is 252: the largest field-safe value needs
        //exactly 252 bits, and one past it crosses into 253 (above the cap).
        Assert.AreEqual(FixedPointScale.MaximumEncodedBits, FixedPointScale.RequiredBits((BigInteger.One << 252) - 1), "The largest field-safe value needs exactly the capped bit width.");
        Assert.AreEqual(253, FixedPointScale.RequiredBits(BigInteger.One << 252), "One past it crosses into 253 bits, above the cap.");
    }


    [TestMethod]
    public void DecodeInvertsEncodeForExactValues()
    {
        foreach(int digits in new[] { 0, 1, 2, 4, 6 })
        {
            FixedPointScale scale = FixedPointScale.OfFractionalDigits(digits);
            foreach(decimal value in new[] { 0m, 30.0m, 12.50m, 100.00m, 7.125m })
            {
                if(scale.TryEncode(value, out BigInteger encoded))
                {
                    Assert.AreEqual(value, scale.Decode(encoded), $"Decode(Encode({value})) at {digits} digits round-trips.");
                }
            }
        }
    }


    [TestMethod]
    public void DecodeThrowsWhenTheValueExceedsDecimalsMantissa()
    {
        FixedPointScale scale = FixedPointScale.OfFractionalDigits(0);

        //The 96-bit mantissa boundary: one below fits System.Decimal, one at it does not.
        Assert.AreEqual(decimal.MaxValue, scale.Decode((BigInteger.One << 96) - 1));
        Assert.ThrowsExactly<OverflowException>(() => scale.Decode(BigInteger.One << 96));
        Assert.IsFalse(scale.TryDecode(BigInteger.One << 96, out _));
    }


    [TestMethod]
    public void DomainCreateDerivesTheBitWidthFromTheEncodedMaximum()
    {
        FixedPointDomain recycled = FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(1), 100.0m);
        FixedPointDomain carbon = FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(2), 100.00m);

        Assert.AreEqual((BigInteger)1000, recycled.MaxEncodedValue);
        Assert.AreEqual(10, recycled.Bits, "1000 < 2^10.");
        Assert.AreEqual((BigInteger)10000, carbon.MaxEncodedValue);
        Assert.AreEqual(14, carbon.Bits, "10000 < 2^14.");
    }


    [TestMethod]
    public void DomainCreateRejectsANonPositiveMaximum()
    {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(2), 0m));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(2), -1m));
    }


    [TestMethod]
    public void DomainEncodeRejectsValuesAboveTheMaximum()
    {
        FixedPointDomain domain = FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(1), 100.0m);

        Assert.AreEqual((BigInteger)1000, domain.Encode(100.0m), "The inclusive maximum itself encodes.");
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => domain.Encode(150.0m));
        Assert.IsFalse(domain.TryEncode(150.0m, out _));
    }


    [TestMethod]
    public void DomainEncodeStillRejectsInexactAndNegativeValues()
    {
        FixedPointDomain domain = FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(1), 100.0m);

        Assert.ThrowsExactly<ArgumentException>(() => domain.Encode(30.55m));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => domain.Encode(-1.0m));
    }
}

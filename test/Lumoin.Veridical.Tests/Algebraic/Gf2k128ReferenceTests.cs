using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates for the <see cref="Gf2k128Reference"/> binary field: the longfellow-zk reference's own
/// identities (the documented <c>x^{-1} = x^127 + x^6 + x + 1</c> and the reduction constant
/// <c>x^128 ≡ 0x87</c>), the field axioms over fixed sample elements, and the characteristic-two
/// signatures (<c>a + a = 0</c>, the Frobenius square <c>(a + b)² = a² + b²</c>) the GKR engine's
/// arithmetization relies on.
/// </summary>
[TestClass]
internal sealed class Gf2k128ReferenceTests
{
    private const int ScalarSize = 32;

    private static ScalarAddDelegate Add { get; } = Gf2k128Reference.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Reference.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Reference.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = Gf2k128Reference.GetInvert();

    private static ScalarReduceDelegate Reduce { get; } = Gf2k128Reference.GetReduce();

    //Fixed sample elements with bits spread across both halves.
    private static BigInteger[] Samples { get; } =
    [
        BigInteger.One,
        new BigInteger(2),
        new BigInteger(0x87),
        BigInteger.Parse("0123456789abcdef0fedcba987654321", System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture),
        BigInteger.Parse("0deadbeefcafebabe0123456789abcde", System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture),
        (BigInteger.One << 127) + (BigInteger.One << 64) + (BigInteger.One << 63) + 1,
        (BigInteger.One << 128) - 1,
    ];


    [TestMethod]
    public void TheReferenceInverseOfXChecksOut()
    {
        //The longfellow-zk reference documents x^{-1} = x^127 + x^6 + x + 1; multiplying it back
        //by x must give one, and Invert(x) must produce exactly it.
        Span<byte> x = stackalloc byte[ScalarSize];
        Span<byte> documentedInverse = stackalloc byte[ScalarSize];
        Span<byte> one = stackalloc byte[ScalarSize];
        Span<byte> result = stackalloc byte[ScalarSize];
        Element(2, x);
        Element((BigInteger.One << 127) + (BigInteger.One << 6) + 2 + 1, documentedInverse);
        Element(BigInteger.One, one);

        Multiply(x, documentedInverse, result, CurveParameterSet.None);
        Assert.IsTrue(result.SequenceEqual(one), "x · (x^127 + x^6 + x + 1) must be one.");

        Invert(x, result, CurveParameterSet.None);
        Assert.IsTrue(result.SequenceEqual(documentedInverse), "Invert(x) must reproduce the documented inverse.");
    }


    [TestMethod]
    public void TheReductionConstantChecksOut()
    {
        //x^127 · x = x^128 ≡ x^7 + x^2 + x + 1 = 0x87.
        Span<byte> high = stackalloc byte[ScalarSize];
        Span<byte> x = stackalloc byte[ScalarSize];
        Span<byte> tail = stackalloc byte[ScalarSize];
        Span<byte> result = stackalloc byte[ScalarSize];
        Element(BigInteger.One << 127, high);
        Element(2, x);
        Element(0x87, tail);

        Multiply(high, x, result, CurveParameterSet.None);
        Assert.IsTrue(result.SequenceEqual(tail), "x^128 must reduce to the 0x87 tail.");

        //Reduce of the 17-byte big-endian encoding of x^128 must give the same.
        Span<byte> wide = stackalloc byte[17];
        wide.Clear();
        wide[0] = 0x01;
        Reduce(wide, result, CurveParameterSet.None);
        Assert.IsTrue(result.SequenceEqual(tail), "Reduce(x^128) must give the 0x87 tail.");
    }


    [TestMethod]
    public void FieldAxiomsHoldOnTheSamples()
    {
        Span<byte> a = stackalloc byte[ScalarSize];
        Span<byte> b = stackalloc byte[ScalarSize];
        Span<byte> c = stackalloc byte[ScalarSize];
        Span<byte> left = stackalloc byte[ScalarSize];
        Span<byte> right = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];

        foreach(BigInteger first in Samples)
        {
            Element(first, a);
            foreach(BigInteger second in Samples)
            {
                Element(second, b);

                //Commutativity of multiplication.
                Multiply(a, b, left, CurveParameterSet.None);
                Multiply(b, a, right, CurveParameterSet.None);
                Assert.IsTrue(left.SequenceEqual(right), $"a·b must equal b·a for {first:x}, {second:x}.");

                //Distributivity: a·(b + c) = a·b + a·c.
                foreach(BigInteger third in Samples)
                {
                    Element(third, c);
                    Add(b, c, scratch, CurveParameterSet.None);
                    Multiply(a, scratch, left, CurveParameterSet.None);

                    Multiply(a, b, right, CurveParameterSet.None);
                    Multiply(a, c, scratch, CurveParameterSet.None);
                    Add(right, scratch, right, CurveParameterSet.None);
                    Assert.IsTrue(left.SequenceEqual(right), $"Distributivity must hold for {first:x}, {second:x}, {third:x}.");
                }
            }
        }
    }


    [TestMethod]
    public void CharacteristicTwoSignaturesHold()
    {
        Span<byte> a = stackalloc byte[ScalarSize];
        Span<byte> b = stackalloc byte[ScalarSize];
        Span<byte> zero = stackalloc byte[ScalarSize];
        Span<byte> one = stackalloc byte[ScalarSize];
        Span<byte> result = stackalloc byte[ScalarSize];
        Span<byte> left = stackalloc byte[ScalarSize];
        Span<byte> right = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        zero.Clear();
        Element(BigInteger.One, one);

        foreach(BigInteger first in Samples)
        {
            Element(first, a);

            //a + a = 0, and subtraction is addition.
            Add(a, a, result, CurveParameterSet.None);
            Assert.IsFalse(result.ContainsAnyExcept((byte)0), $"a + a must vanish for {first:x}.");

            Subtract(zero, a, result, CurveParameterSet.None);
            Assert.IsTrue(result.SequenceEqual(a), $"−a must equal a for {first:x}.");

            //a · a^{-1} = 1.
            Invert(a, result, CurveParameterSet.None);
            Multiply(a, result, scratch, CurveParameterSet.None);
            Assert.IsTrue(scratch.SequenceEqual(one), $"a · a^(-1) must be one for {first:x}.");

            foreach(BigInteger second in Samples)
            {
                Element(second, b);

                //The Frobenius square: (a + b)² = a² + b².
                Add(a, b, scratch, CurveParameterSet.None);
                Multiply(scratch, scratch, left, CurveParameterSet.None);

                Multiply(a, a, right, CurveParameterSet.None);
                Multiply(b, b, scratch, CurveParameterSet.None);
                Add(right, scratch, right, CurveParameterSet.None);
                Assert.IsTrue(left.SequenceEqual(right), $"(a + b)² must equal a² + b² for {first:x}, {second:x}.");
            }
        }
    }


    private static void Element(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        Span<byte> little = stackalloc byte[ScalarSize + 1];
        if(value.TryWriteBytes(little, out int written, isUnsigned: true, isBigEndian: false))
        {
            for(int i = 0; i < written && i < ScalarSize; i++)
            {
                destination[ScalarSize - 1 - i] = little[i];
            }
        }
    }
}

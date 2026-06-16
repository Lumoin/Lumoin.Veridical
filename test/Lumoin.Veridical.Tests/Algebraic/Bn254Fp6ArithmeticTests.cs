using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Algebraic-identity property tests for the BN254 (alt_bn128) Fp6 cubic
/// extension field (<see cref="Bn254BigIntegerFp6Reference"/>). The
/// load-bearing structural check is <see cref="VCubedEqualsNonResidue"/>:
/// <c>v³</c> must wrap to <c>ξ = 9 + u</c> (not BLS12-381's <c>1 + u</c>, and
/// not the basis-swapped <c>1 + 9u</c>). Algebraic laws alone do not pin <c>ξ</c>
/// — any non-residue yields a valid field — so this test is the real validator
/// of the most commonly confused BN254 constant.
/// </summary>
[TestClass]
internal sealed class Bn254Fp6ArithmeticTests
{
    private static readonly Fp6AddDelegate Add = Bn254BigIntegerFp6Reference.GetAdd();
    private static readonly Fp6SubtractDelegate Subtract = Bn254BigIntegerFp6Reference.GetSubtract();
    private static readonly Fp6MultiplyDelegate Multiply = Bn254BigIntegerFp6Reference.GetMultiply();
    private static readonly Fp6SquareDelegate Square = Bn254BigIntegerFp6Reference.GetSquare();
    private static readonly Fp6NegateDelegate Negate = Bn254BigIntegerFp6Reference.GetNegate();
    private static readonly Fp6InvertDelegate Invert = Bn254BigIntegerFp6Reference.GetInvert();

    private static readonly BigInteger BaseFieldPrime = Bn254BigIntegerG1Reference.BaseFieldPrime;
    private const int CompSize = WellKnownCurves.Bn254BaseFieldSizeBytes;
    private const int Fp2Size = 2 * WellKnownCurves.Bn254BaseFieldSizeBytes;
    private const int Fp6Size = 6 * WellKnownCurves.Bn254BaseFieldSizeBytes;

    private const long IterationCount = 30;

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void AdditionIsCommutative()
    {
        Gen.Byte.Array[Fp6Size * 2].Sample(raw =>
        {
            using Fp6Element a = ReduceAndWrap(raw.AsSpan(0, Fp6Size));
            using Fp6Element b = ReduceAndWrap(raw.AsSpan(Fp6Size, Fp6Size));
            using Fp6Element ab = a.Add(b, Add, Pool);
            using Fp6Element ba = b.Add(a, Add, Pool);
            return ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsCommutative()
    {
        Gen.Byte.Array[Fp6Size * 2].Sample(raw =>
        {
            using Fp6Element a = ReduceAndWrap(raw.AsSpan(0, Fp6Size));
            using Fp6Element b = ReduceAndWrap(raw.AsSpan(Fp6Size, Fp6Size));
            using Fp6Element ab = a.Multiply(b, Multiply, Pool);
            using Fp6Element ba = b.Multiply(a, Multiply, Pool);
            return ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsAssociative()
    {
        Gen.Byte.Array[Fp6Size * 3].Sample(raw =>
        {
            using Fp6Element a = ReduceAndWrap(raw.AsSpan(0, Fp6Size));
            using Fp6Element b = ReduceAndWrap(raw.AsSpan(Fp6Size, Fp6Size));
            using Fp6Element c = ReduceAndWrap(raw.AsSpan(2 * Fp6Size, Fp6Size));
            using Fp6Element ab = a.Multiply(b, Multiply, Pool);
            using Fp6Element abTimesC = ab.Multiply(c, Multiply, Pool);
            using Fp6Element bc = b.Multiply(c, Multiply, Pool);
            using Fp6Element aTimesBc = a.Multiply(bc, Multiply, Pool);
            return abTimesC.AsReadOnlySpan().SequenceEqual(aTimesBc.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void DistributivityHolds()
    {
        Gen.Byte.Array[Fp6Size * 3].Sample(raw =>
        {
            using Fp6Element a = ReduceAndWrap(raw.AsSpan(0, Fp6Size));
            using Fp6Element b = ReduceAndWrap(raw.AsSpan(Fp6Size, Fp6Size));
            using Fp6Element c = ReduceAndWrap(raw.AsSpan(2 * Fp6Size, Fp6Size));
            using Fp6Element bPlusC = b.Add(c, Add, Pool);
            using Fp6Element left = a.Multiply(bPlusC, Multiply, Pool);
            using Fp6Element ab = a.Multiply(b, Multiply, Pool);
            using Fp6Element ac = a.Multiply(c, Multiply, Pool);
            using Fp6Element right = ab.Add(ac, Add, Pool);
            return left.AsReadOnlySpan().SequenceEqual(right.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void SquareEqualsSelfMultiply()
    {
        Gen.Byte.Array[Fp6Size].Sample(raw =>
        {
            using Fp6Element a = ReduceAndWrap(raw);
            using Fp6Element viaSquare = a.Square(Square, Pool);
            using Fp6Element viaMultiply = a.Multiply(a, Multiply, Pool);
            return viaSquare.AsReadOnlySpan().SequenceEqual(viaMultiply.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void SubtractionEqualsAddNegate()
    {
        Gen.Byte.Array[Fp6Size * 2].Sample(raw =>
        {
            using Fp6Element a = ReduceAndWrap(raw.AsSpan(0, Fp6Size));
            using Fp6Element b = ReduceAndWrap(raw.AsSpan(Fp6Size, Fp6Size));
            using Fp6Element direct = a.Subtract(b, Subtract, Pool);
            using Fp6Element negB = b.Negate(Negate, Pool);
            using Fp6Element viaAdd = a.Add(negB, Add, Pool);
            return direct.AsReadOnlySpan().SequenceEqual(viaAdd.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicativeInverseRoundTrips()
    {
        Gen.Byte.Array[Fp6Size].Sample(raw =>
        {
            using Fp6Element a = ReduceAndWrap(raw);
            if(a.IsZero)
            {
                return true;
            }

            using Fp6Element inverse = a.Invert(Invert, Pool);
            using Fp6Element product = a.Multiply(inverse, Multiply, Pool);
            return product.IsOne;
        }, iter: IterationCount);
    }


    [TestMethod]
    public void OneIsMultiplicativeIdentity()
    {
        using Fp6Element one = Fp6Element.One(CurveParameterSet.Bn254, Pool);
        Gen.Byte.Array[Fp6Size].Sample(raw =>
        {
            using Fp6Element a = ReduceAndWrap(raw);
            using Fp6Element product = a.Multiply(one, Multiply, Pool);
            return product.AsReadOnlySpan().SequenceEqual(a.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void VCubedEqualsNonResidue()
    {
        //v · v · v must equal ξ = 9 + u, i.e. the Fp6 element (9 + u, 0, 0).
        //Construct v = (0, 1, 0): set the c1.real byte to 1.
        Span<byte> vBytes = stackalloc byte[Fp6Size];
        vBytes.Clear();
        vBytes[Fp2Size + CompSize - 1] = 0x01;  //c1.real = 1 → v = (0, 1, 0)
        using Fp6Element v = Fp6Element.FromCanonical(vBytes, CurveParameterSet.Bn254, Pool);

        using Fp6Element vSquared = v.Multiply(v, Multiply, Pool);
        using Fp6Element vCubed = vSquared.Multiply(v, Multiply, Pool);

        //Expected: (9 + u, 0, 0) → c0.real = 9, c0.imag = 1, rest zero.
        Span<byte> expected = stackalloc byte[Fp6Size];
        expected.Clear();
        expected[CompSize - 1] = 0x09;   //c0.real = 9
        expected[Fp2Size - 1] = 0x01;    //c0.imag = 1

        Assert.IsTrue(vCubed.AsReadOnlySpan().SequenceEqual(expected), "v³ must equal ξ = 9 + u.");
    }


    [TestMethod]
    public void MultiplyMatchesIndependentVector()
    {
        //Cross-check the full nine-cross-term Fp6 schoolbook multiply (the
        //ξ-wrap on the c0 and c1 terms in particular) against an independent
        //CPython tower using ξ = 9 + u. Inputs are the Fp6 elements whose six
        //Fp coordinates are 1..6 and 6..1 in nested order.
        Span<byte> aBytes = stackalloc byte[Fp6Size];
        Span<byte> bBytes = stackalloc byte[Fp6Size];
        aBytes.Clear();
        bBytes.Clear();
        ReadOnlySpan<byte> aValues = [1, 2, 3, 4, 5, 6];
        ReadOnlySpan<byte> bValues = [6, 5, 4, 3, 2, 1];
        for(int i = 0; i < 6; i++)
        {
            aBytes[(i * CompSize) + CompSize - 1] = aValues[i];
            bBytes[(i * CompSize) + CompSize - 1] = bValues[i];
        }

        using Fp6Element a = Fp6Element.FromCanonical(aBytes, CurveParameterSet.Bn254, Pool);
        using Fp6Element b = Fp6Element.FromCanonical(bBytes, CurveParameterSet.Bn254, Pool);
        using Fp6Element product = a.Multiply(b, Multiply, Pool);

        const string expectedHex =
            "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd35"
            + "00000000000000000000000000000000000000000000000000000000000001d7"
            + "000000000000000000000000000000000000000000000000000000000000000f"
            + "00000000000000000000000000000000000000000000000000000000000000cf"
            + "0000000000000000000000000000000000000000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000005b";

        Assert.AreEqual(expectedHex, Convert.ToHexStringLower(product.AsReadOnlySpan()));
    }


    [TestMethod]
    public void FromComponentsRoundTripsThroughAccessors()
    {
        Span<byte> c0 = stackalloc byte[Fp2Size];
        Span<byte> c1 = stackalloc byte[Fp2Size];
        Span<byte> c2 = stackalloc byte[Fp2Size];
        c0.Clear();
        c1.Clear();
        c2.Clear();
        c0[^1] = 0x07;
        c1[^1] = 0x0b;
        c2[^1] = 0x0d;

        using Fp6Element element = Fp6Element.FromComponents(c0, c1, c2, CurveParameterSet.Bn254, Pool);

        Assert.IsTrue(element.GetC0ComponentBytes().SequenceEqual(c0));
        Assert.IsTrue(element.GetC1ComponentBytes().SequenceEqual(c1));
        Assert.IsTrue(element.GetC2ComponentBytes().SequenceEqual(c2));
    }


    private static Fp6Element ReduceAndWrap(ReadOnlySpan<byte> raw)
    {
        Span<byte> packed = stackalloc byte[Fp6Size];
        packed.Clear();
        for(int i = 0; i < 3; i++)
        {
            int start = i * Fp2Size;
            ReduceFp2Slot(raw.Slice(start, Fp2Size), packed.Slice(start, Fp2Size));
        }

        return Fp6Element.FromCanonical(packed, CurveParameterSet.Bn254, Pool);
    }


    private static void ReduceFp2Slot(ReadOnlySpan<byte> rawFp2, Span<byte> packedFp2)
    {
        BigInteger c0 = new BigInteger(rawFp2[..CompSize], isUnsigned: true, isBigEndian: true) % BaseFieldPrime;
        BigInteger c1 = new BigInteger(rawFp2.Slice(CompSize, CompSize), isUnsigned: true, isBigEndian: true) % BaseFieldPrime;
        WriteCanonical(c0, packedFp2[..CompSize]);
        WriteCanonical(c1, packedFp2.Slice(CompSize, CompSize));
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced Fp component did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}

using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Algebraic-identity property tests for the BN254 (alt_bn128) Fp2 extension
/// field (<see cref="Bn254BigIntegerFp2Reference"/>). Mirrors the BLS12-381
/// Fp2 suite; the structural checks (conjugate involution, Frobenius equals
/// conjugation) catch a wrong non-residue sign or swapped component.
/// </summary>
[TestClass]
internal sealed class Bn254Fp2ArithmeticTests
{
    private static readonly Fp2AddDelegate Add = Bn254BigIntegerFp2Reference.GetAdd();
    private static readonly Fp2SubtractDelegate Subtract = Bn254BigIntegerFp2Reference.GetSubtract();
    private static readonly Fp2MultiplyDelegate Multiply = Bn254BigIntegerFp2Reference.GetMultiply();
    private static readonly Fp2SquareDelegate Square = Bn254BigIntegerFp2Reference.GetSquare();
    private static readonly Fp2NegateDelegate Negate = Bn254BigIntegerFp2Reference.GetNegate();
    private static readonly Fp2InvertDelegate Invert = Bn254BigIntegerFp2Reference.GetInvert();
    private static readonly Fp2ConjugateDelegate Conjugate = Bn254BigIntegerFp2Reference.GetConjugate();

    private static readonly BigInteger BaseFieldPrime = Bn254BigIntegerG1Reference.BaseFieldPrime;
    private const int CompSize = WellKnownCurves.Bn254BaseFieldSizeBytes;
    private const int Fp2Size = 2 * WellKnownCurves.Bn254BaseFieldSizeBytes;

    private const long IterationCount = 60;

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void AdditionIsCommutative()
    {
        Gen.Byte.Array[Fp2Size * 2].Sample(raw =>
        {
            using Fp2Element a = ReduceAndWrap(raw.AsSpan(0, Fp2Size));
            using Fp2Element b = ReduceAndWrap(raw.AsSpan(Fp2Size, Fp2Size));
            using Fp2Element ab = a.Add(b, Add, Pool);
            using Fp2Element ba = b.Add(a, Add, Pool);
            return ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsCommutative()
    {
        Gen.Byte.Array[Fp2Size * 2].Sample(raw =>
        {
            using Fp2Element a = ReduceAndWrap(raw.AsSpan(0, Fp2Size));
            using Fp2Element b = ReduceAndWrap(raw.AsSpan(Fp2Size, Fp2Size));
            using Fp2Element ab = a.Multiply(b, Multiply, Pool);
            using Fp2Element ba = b.Multiply(a, Multiply, Pool);
            return ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsAssociative()
    {
        Gen.Byte.Array[Fp2Size * 3].Sample(raw =>
        {
            using Fp2Element a = ReduceAndWrap(raw.AsSpan(0, Fp2Size));
            using Fp2Element b = ReduceAndWrap(raw.AsSpan(Fp2Size, Fp2Size));
            using Fp2Element c = ReduceAndWrap(raw.AsSpan(2 * Fp2Size, Fp2Size));
            using Fp2Element ab = a.Multiply(b, Multiply, Pool);
            using Fp2Element abTimesC = ab.Multiply(c, Multiply, Pool);
            using Fp2Element bc = b.Multiply(c, Multiply, Pool);
            using Fp2Element aTimesBc = a.Multiply(bc, Multiply, Pool);
            return abTimesC.AsReadOnlySpan().SequenceEqual(aTimesBc.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void DistributivityHolds()
    {
        Gen.Byte.Array[Fp2Size * 3].Sample(raw =>
        {
            using Fp2Element a = ReduceAndWrap(raw.AsSpan(0, Fp2Size));
            using Fp2Element b = ReduceAndWrap(raw.AsSpan(Fp2Size, Fp2Size));
            using Fp2Element c = ReduceAndWrap(raw.AsSpan(2 * Fp2Size, Fp2Size));
            using Fp2Element bPlusC = b.Add(c, Add, Pool);
            using Fp2Element left = a.Multiply(bPlusC, Multiply, Pool);
            using Fp2Element ab = a.Multiply(b, Multiply, Pool);
            using Fp2Element ac = a.Multiply(c, Multiply, Pool);
            using Fp2Element right = ab.Add(ac, Add, Pool);
            return left.AsReadOnlySpan().SequenceEqual(right.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void SquareEqualsSelfMultiply()
    {
        Gen.Byte.Array[Fp2Size].Sample(raw =>
        {
            using Fp2Element a = ReduceAndWrap(raw);
            using Fp2Element viaSquare = a.Square(Square, Pool);
            using Fp2Element viaMultiply = a.Multiply(a, Multiply, Pool);
            return viaSquare.AsReadOnlySpan().SequenceEqual(viaMultiply.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void SubtractionEqualsAddNegate()
    {
        Gen.Byte.Array[Fp2Size * 2].Sample(raw =>
        {
            using Fp2Element a = ReduceAndWrap(raw.AsSpan(0, Fp2Size));
            using Fp2Element b = ReduceAndWrap(raw.AsSpan(Fp2Size, Fp2Size));
            using Fp2Element direct = a.Subtract(b, Subtract, Pool);
            using Fp2Element negB = b.Negate(Negate, Pool);
            using Fp2Element viaAdd = a.Add(negB, Add, Pool);
            return direct.AsReadOnlySpan().SequenceEqual(viaAdd.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicativeInverseRoundTrips()
    {
        Gen.Byte.Array[Fp2Size].Sample(raw =>
        {
            using Fp2Element a = ReduceAndWrap(raw);
            if(a.IsZero)
            {
                return true;
            }

            using Fp2Element inverse = a.Invert(Invert, Pool);
            using Fp2Element product = a.Multiply(inverse, Multiply, Pool);
            return product.IsOne;
        }, iter: IterationCount);
    }


    [TestMethod]
    public void ConjugateIsInvolutive()
    {
        Gen.Byte.Array[Fp2Size].Sample(raw =>
        {
            using Fp2Element a = ReduceAndWrap(raw);
            using Fp2Element once = a.Conjugate(Conjugate, Pool);
            using Fp2Element twice = once.Conjugate(Conjugate, Pool);
            return a.AsReadOnlySpan().SequenceEqual(twice.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void FrobeniusEqualsConjugate()
    {
        //Over Fp2 with u² = −1 and q ≡ 3 (mod 4), x^q = conj(x): (q−1)/2 is odd,
        //so u^q = −u. A sign mistake on the non-residue would break this.
        Gen.Byte.Array[Fp2Size].Sample(raw =>
        {
            using Fp2Element a = ReduceAndWrap(raw);
            BigInteger c1 = new(a.GetImaginaryComponentBytes(), isUnsigned: true, isBigEndian: true);
            BigInteger expectedC1 = Reduce(-c1);

            using Fp2Element viaConjugate = a.Conjugate(Conjugate, Pool);
            BigInteger gotC0 = new(viaConjugate.GetRealComponentBytes(), isUnsigned: true, isBigEndian: true);
            BigInteger gotC1 = new(viaConjugate.GetImaginaryComponentBytes(), isUnsigned: true, isBigEndian: true);
            BigInteger originalC0 = new(a.GetRealComponentBytes(), isUnsigned: true, isBigEndian: true);

            return gotC0 == originalC0 && gotC1 == expectedC1;
        }, iter: IterationCount);
    }


    [TestMethod]
    public void OneIsMultiplicativeIdentity()
    {
        using Fp2Element one = Fp2Element.One(CurveParameterSet.Bn254, Pool);
        Gen.Byte.Array[Fp2Size].Sample(raw =>
        {
            using Fp2Element a = ReduceAndWrap(raw);
            using Fp2Element product = a.Multiply(one, Multiply, Pool);
            return product.AsReadOnlySpan().SequenceEqual(a.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void FromComponentsRoundTripsThroughAccessors()
    {
        Span<byte> c0 = stackalloc byte[CompSize];
        Span<byte> c1 = stackalloc byte[CompSize];
        c0.Clear();
        c1.Clear();
        c0[^1] = 0x07;
        c1[^1] = 0x0b;

        using Fp2Element element = Fp2Element.FromComponents(c0, c1, CurveParameterSet.Bn254, Pool);

        Assert.IsTrue(element.GetRealComponentBytes().SequenceEqual(c0));
        Assert.IsTrue(element.GetImaginaryComponentBytes().SequenceEqual(c1));
    }


    private static Fp2Element ReduceAndWrap(ReadOnlySpan<byte> raw)
    {
        BigInteger c0 = new BigInteger(raw[..CompSize], isUnsigned: true, isBigEndian: true) % BaseFieldPrime;
        BigInteger c1 = new BigInteger(raw.Slice(CompSize, CompSize), isUnsigned: true, isBigEndian: true) % BaseFieldPrime;

        Span<byte> packed = stackalloc byte[Fp2Size];
        packed.Clear();
        WriteCanonical(c0, packed[..CompSize]);
        WriteCanonical(c1, packed.Slice(CompSize, CompSize));

        return Fp2Element.FromCanonical(packed, CurveParameterSet.Bn254, Pool);
    }


    private static BigInteger Reduce(BigInteger value)
    {
        return ((value % BaseFieldPrime) + BaseFieldPrime) % BaseFieldPrime;
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

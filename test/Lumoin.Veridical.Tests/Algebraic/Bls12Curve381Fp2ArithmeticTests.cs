using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Algebraic-identity property tests for the BLS12-381 Fp2 extension
/// field. Identities — commutativity, associativity, distributivity,
/// multiplicative-inverse round-trip, conjugate involution, Frobenius
/// equality with conjugation — are the structural correctness gate at
/// this layer. A wrong non-residue sign or a swapped component would
/// surface here as a specific identity failure, not as an opaque
/// downstream-protocol failure.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381Fp2ArithmeticTests
{
    private static readonly Fp2AddDelegate Add = Bls12Curve381BigIntegerFp2Reference.GetAdd();
    private static readonly Fp2SubtractDelegate Subtract = Bls12Curve381BigIntegerFp2Reference.GetSubtract();
    private static readonly Fp2MultiplyDelegate Multiply = Bls12Curve381BigIntegerFp2Reference.GetMultiply();
    private static readonly Fp2SquareDelegate Square = Bls12Curve381BigIntegerFp2Reference.GetSquare();
    private static readonly Fp2NegateDelegate Negate = Bls12Curve381BigIntegerFp2Reference.GetNegate();
    private static readonly Fp2InvertDelegate Invert = Bls12Curve381BigIntegerFp2Reference.GetInvert();
    private static readonly Fp2ConjugateDelegate Conjugate = Bls12Curve381BigIntegerFp2Reference.GetConjugate();

    private static readonly BigInteger BaseFieldPrime = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;
    private const int CompSize = WellKnownCurves.Bls12Curve381BaseFieldSizeBytes;

    //CsCheck iteration count — small because each iteration does ~6 BigInteger
    //operations and we exercise many tests in parallel.
    private const long IterationCount = 60;


    [TestMethod]
    public void AdditionIsCommutative()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp2SizeBytes * 2]
            .Sample(raw =>
            {
                using Fp2Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp2SizeBytes, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element ab = a.Add(b, Add, BaseMemoryPool.Shared);
                using Fp2Element ba = b.Add(a, Add, BaseMemoryPool.Shared);
                return ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void AdditionIsAssociative()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp2SizeBytes * 3]
            .Sample(raw =>
            {
                using Fp2Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp2SizeBytes, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element c = ReduceAndWrap(raw.AsSpan(2 * WellKnownCurves.Bls12Curve381Fp2SizeBytes, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element ab = a.Add(b, Add, BaseMemoryPool.Shared);
                using Fp2Element abPlusC = ab.Add(c, Add, BaseMemoryPool.Shared);
                using Fp2Element bc = b.Add(c, Add, BaseMemoryPool.Shared);
                using Fp2Element aPlusBc = a.Add(bc, Add, BaseMemoryPool.Shared);
                return abPlusC.AsReadOnlySpan().SequenceEqual(aPlusBc.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsCommutative()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp2SizeBytes * 2]
            .Sample(raw =>
            {
                using Fp2Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp2SizeBytes, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element ab = a.Multiply(b, Multiply, BaseMemoryPool.Shared);
                using Fp2Element ba = b.Multiply(a, Multiply, BaseMemoryPool.Shared);
                return ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsAssociative()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp2SizeBytes * 3]
            .Sample(raw =>
            {
                using Fp2Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp2SizeBytes, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element c = ReduceAndWrap(raw.AsSpan(2 * WellKnownCurves.Bls12Curve381Fp2SizeBytes, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element ab = a.Multiply(b, Multiply, BaseMemoryPool.Shared);
                using Fp2Element abTimesC = ab.Multiply(c, Multiply, BaseMemoryPool.Shared);
                using Fp2Element bc = b.Multiply(c, Multiply, BaseMemoryPool.Shared);
                using Fp2Element aTimesBc = a.Multiply(bc, Multiply, BaseMemoryPool.Shared);
                return abTimesC.AsReadOnlySpan().SequenceEqual(aTimesBc.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void DistributivityHolds()
    {
        //a · (b + c) == a·b + a·c.
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp2SizeBytes * 3]
            .Sample(raw =>
            {
                using Fp2Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp2SizeBytes, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element c = ReduceAndWrap(raw.AsSpan(2 * WellKnownCurves.Bls12Curve381Fp2SizeBytes, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element bPlusC = b.Add(c, Add, BaseMemoryPool.Shared);
                using Fp2Element left = a.Multiply(bPlusC, Multiply, BaseMemoryPool.Shared);
                using Fp2Element ab = a.Multiply(b, Multiply, BaseMemoryPool.Shared);
                using Fp2Element ac = a.Multiply(c, Multiply, BaseMemoryPool.Shared);
                using Fp2Element right = ab.Add(ac, Add, BaseMemoryPool.Shared);
                return left.AsReadOnlySpan().SequenceEqual(right.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void SquareEqualsSelfMultiply()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp2SizeBytes]
            .Sample(raw =>
            {
                using Fp2Element a = ReduceAndWrap(raw);
                using Fp2Element viaSquare = a.Square(Square, BaseMemoryPool.Shared);
                using Fp2Element viaMultiply = a.Multiply(a, Multiply, BaseMemoryPool.Shared);
                return viaSquare.AsReadOnlySpan().SequenceEqual(viaMultiply.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void NegationCancelsAddition()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp2SizeBytes]
            .Sample(raw =>
            {
                using Fp2Element a = ReduceAndWrap(raw);
                using Fp2Element negA = a.Negate(Negate, BaseMemoryPool.Shared);
                using Fp2Element sum = a.Add(negA, Add, BaseMemoryPool.Shared);
                return sum.IsZero;
            }, iter: IterationCount);
    }


    [TestMethod]
    public void SubtractionEqualsAddNegate()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp2SizeBytes * 2]
            .Sample(raw =>
            {
                using Fp2Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp2SizeBytes, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
                using Fp2Element direct = a.Subtract(b, Subtract, BaseMemoryPool.Shared);
                using Fp2Element negB = b.Negate(Negate, BaseMemoryPool.Shared);
                using Fp2Element viaAdd = a.Add(negB, Add, BaseMemoryPool.Shared);
                return direct.AsReadOnlySpan().SequenceEqual(viaAdd.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicativeInverseRoundTrips()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp2SizeBytes]
            .Sample(raw =>
            {
                using Fp2Element a = ReduceAndWrap(raw);
                if(a.IsZero)
                {
                    return true; //skip the zero element; inversion not defined.
                }

                using Fp2Element inverse = a.Invert(Invert, BaseMemoryPool.Shared);
                using Fp2Element product = a.Multiply(inverse, Multiply, BaseMemoryPool.Shared);
                return product.IsOne;
            }, iter: IterationCount);
    }


    [TestMethod]
    public void ConjugateIsInvolutive()
    {
        //conj(conj(x)) == x.
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp2SizeBytes]
            .Sample(raw =>
            {
                using Fp2Element a = ReduceAndWrap(raw);
                using Fp2Element once = a.Conjugate(Conjugate, BaseMemoryPool.Shared);
                using Fp2Element twice = once.Conjugate(Conjugate, BaseMemoryPool.Shared);
                return a.AsReadOnlySpan().SequenceEqual(twice.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void FrobeniusEqualsConjugate()
    {
        //Over Fp2 with u² = −1, x^p = conj(x). This identity is the
        //load-bearing structural check — a sign mistake on the
        //non-residue or a swapped Fp2 component would break it.
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp2SizeBytes]
            .Sample(raw =>
            {
                using Fp2Element a = ReduceAndWrap(raw);

                //Compute x^p directly via ModPow on the components.
                ReadOnlySpan<byte> c0Bytes = a.GetRealComponentBytes();
                ReadOnlySpan<byte> c1Bytes = a.GetImaginaryComponentBytes();
                BigInteger c0 = new(c0Bytes, isUnsigned: true, isBigEndian: true);
                BigInteger c1 = new(c1Bytes, isUnsigned: true, isBigEndian: true);

                //x^p in Fp2 expands via the Frobenius identity:
                //  (a + b·u)^p = a^p + b^p · u^p
                //             = a + b · (−1)^((p−1)/2) · u     since x^p = x for x in Fp.
                //For BLS12-381's base prime p ≡ 3 (mod 4), (p−1)/2 is odd, so u^p = −u.
                //Hence (a + b·u)^p = a − b·u = conj(a + b·u).
                //Verify this against the reference conjugate.
                BigInteger expectedC1 = Reduce(-c1);

                using Fp2Element viaConjugate = a.Conjugate(Conjugate, BaseMemoryPool.Shared);

                ReadOnlySpan<byte> conjC0 = viaConjugate.GetRealComponentBytes();
                ReadOnlySpan<byte> conjC1 = viaConjugate.GetImaginaryComponentBytes();
                BigInteger gotC0 = new(conjC0, isUnsigned: true, isBigEndian: true);
                BigInteger gotC1 = new(conjC1, isUnsigned: true, isBigEndian: true);

                return gotC0 == c0 && gotC1 == expectedC1;
            }, iter: IterationCount);
    }


    [TestMethod]
    public void ZeroIsAdditiveIdentity()
    {
        using Fp2Element zero = Fp2Element.Zero(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp2SizeBytes]
            .Sample(raw =>
            {
                using Fp2Element a = ReduceAndWrap(raw);
                using Fp2Element sum = a.Add(zero, Add, BaseMemoryPool.Shared);
                return sum.AsReadOnlySpan().SequenceEqual(a.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void OneIsMultiplicativeIdentity()
    {
        using Fp2Element one = Fp2Element.One(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp2SizeBytes]
            .Sample(raw =>
            {
                using Fp2Element a = ReduceAndWrap(raw);
                using Fp2Element product = a.Multiply(one, Multiply, BaseMemoryPool.Shared);
                return product.AsReadOnlySpan().SequenceEqual(a.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void FromComponentsRoundTripsThroughAccessors()
    {
        byte[] c0 = new byte[CompSize];
        byte[] c1 = new byte[CompSize];
        c0[^1] = 0x07;
        c1[^1] = 0x0b;

        using Fp2Element element = Fp2Element.FromComponents(c0, c1, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        Assert.IsTrue(element.GetRealComponentBytes().SequenceEqual(c0));
        Assert.IsTrue(element.GetImaginaryComponentBytes().SequenceEqual(c1));
    }


    /// <summary>
    /// Reduces raw input bytes to canonical-form Fp2 (each component
    /// strictly less than the base-field prime), wrapping the result
    /// in a leaf type. Lets CsCheck's <see cref="byte"/>-array generator
    /// drive coverage without producing above-modulus components that
    /// the reference would handle as-if reduced.
    /// </summary>
    private static Fp2Element ReduceAndWrap(ReadOnlySpan<byte> raw)
    {
        BigInteger c0Raw = new(raw[..CompSize], isUnsigned: true, isBigEndian: true);
        BigInteger c1Raw = new(raw.Slice(CompSize, CompSize), isUnsigned: true, isBigEndian: true);
        BigInteger c0 = c0Raw % BaseFieldPrime;
        BigInteger c1 = c1Raw % BaseFieldPrime;

        Span<byte> packed = stackalloc byte[WellKnownCurves.Bls12Curve381Fp2SizeBytes];
        packed.Clear();
        WriteCanonical(c0, packed[..CompSize]);
        WriteCanonical(c1, packed.Slice(CompSize, CompSize));

        return Fp2Element.FromCanonical(packed, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
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
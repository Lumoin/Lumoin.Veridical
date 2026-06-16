using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Algebraic-identity property tests for the BLS12-381 Fp12 sextic
/// extension field (the pairing target field). The load-bearing
/// structural checks at this layer are: <c>w² = v</c> (tower wrap),
/// inverse round-trip in the full field, and that conjugation is a
/// field homomorphism — <c>conj(a·b) = conj(a)·conj(b)</c> — which
/// would break if the c1 component swapped roles with c0.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381Fp12ArithmeticTests
{
    private static readonly Fp12AddDelegate Add = Bls12Curve381BigIntegerFp12Reference.GetAdd();
    private static readonly Fp12SubtractDelegate Subtract = Bls12Curve381BigIntegerFp12Reference.GetSubtract();
    private static readonly Fp12MultiplyDelegate Multiply = Bls12Curve381BigIntegerFp12Reference.GetMultiply();
    private static readonly Fp12SquareDelegate Square = Bls12Curve381BigIntegerFp12Reference.GetSquare();
    private static readonly Fp12NegateDelegate Negate = Bls12Curve381BigIntegerFp12Reference.GetNegate();
    private static readonly Fp12InvertDelegate Invert = Bls12Curve381BigIntegerFp12Reference.GetInvert();
    private static readonly Fp12ConjugateDelegate Conjugate = Bls12Curve381BigIntegerFp12Reference.GetConjugate();

    private static readonly BigInteger BaseFieldPrime = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;
    private const int CompSize = WellKnownCurves.Bls12Curve381BaseFieldSizeBytes;

    //CsCheck iteration count: small because each Fp12 op does many
    //BigInteger Fp6 ops which in turn each do 9 Fp2 multiplications.
    private const long IterationCount = 15;


    [TestMethod]
    public void AdditionIsCommutative()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp12SizeBytes * 2]
            .Sample(raw =>
            {
                using Fp12Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp12SizeBytes));
                using Fp12Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp12SizeBytes, WellKnownCurves.Bls12Curve381Fp12SizeBytes));
                using Fp12Element ab = a.Add(b, Add, BaseMemoryPool.Shared);
                using Fp12Element ba = b.Add(a, Add, BaseMemoryPool.Shared);
                return ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsCommutative()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp12SizeBytes * 2]
            .Sample(raw =>
            {
                using Fp12Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp12SizeBytes));
                using Fp12Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp12SizeBytes, WellKnownCurves.Bls12Curve381Fp12SizeBytes));
                using Fp12Element ab = a.Multiply(b, Multiply, BaseMemoryPool.Shared);
                using Fp12Element ba = b.Multiply(a, Multiply, BaseMemoryPool.Shared);
                return ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsAssociative()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp12SizeBytes * 3]
            .Sample(raw =>
            {
                using Fp12Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp12SizeBytes));
                using Fp12Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp12SizeBytes, WellKnownCurves.Bls12Curve381Fp12SizeBytes));
                using Fp12Element c = ReduceAndWrap(raw.AsSpan(2 * WellKnownCurves.Bls12Curve381Fp12SizeBytes, WellKnownCurves.Bls12Curve381Fp12SizeBytes));
                using Fp12Element ab = a.Multiply(b, Multiply, BaseMemoryPool.Shared);
                using Fp12Element abTimesC = ab.Multiply(c, Multiply, BaseMemoryPool.Shared);
                using Fp12Element bc = b.Multiply(c, Multiply, BaseMemoryPool.Shared);
                using Fp12Element aTimesBc = a.Multiply(bc, Multiply, BaseMemoryPool.Shared);
                return abTimesC.AsReadOnlySpan().SequenceEqual(aTimesBc.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void DistributivityHolds()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp12SizeBytes * 3]
            .Sample(raw =>
            {
                using Fp12Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp12SizeBytes));
                using Fp12Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp12SizeBytes, WellKnownCurves.Bls12Curve381Fp12SizeBytes));
                using Fp12Element c = ReduceAndWrap(raw.AsSpan(2 * WellKnownCurves.Bls12Curve381Fp12SizeBytes, WellKnownCurves.Bls12Curve381Fp12SizeBytes));
                using Fp12Element bPlusC = b.Add(c, Add, BaseMemoryPool.Shared);
                using Fp12Element left = a.Multiply(bPlusC, Multiply, BaseMemoryPool.Shared);
                using Fp12Element ab = a.Multiply(b, Multiply, BaseMemoryPool.Shared);
                using Fp12Element ac = a.Multiply(c, Multiply, BaseMemoryPool.Shared);
                using Fp12Element right = ab.Add(ac, Add, BaseMemoryPool.Shared);
                return left.AsReadOnlySpan().SequenceEqual(right.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void SquareEqualsSelfMultiply()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp12SizeBytes]
            .Sample(raw =>
            {
                using Fp12Element a = ReduceAndWrap(raw);
                using Fp12Element viaSquare = a.Square(Square, BaseMemoryPool.Shared);
                using Fp12Element viaMultiply = a.Multiply(a, Multiply, BaseMemoryPool.Shared);
                return viaSquare.AsReadOnlySpan().SequenceEqual(viaMultiply.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void NegationCancelsAddition()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp12SizeBytes]
            .Sample(raw =>
            {
                using Fp12Element a = ReduceAndWrap(raw);
                using Fp12Element negA = a.Negate(Negate, BaseMemoryPool.Shared);
                using Fp12Element sum = a.Add(negA, Add, BaseMemoryPool.Shared);
                return sum.IsZero;
            }, iter: IterationCount);
    }


    [TestMethod]
    public void SubtractionEqualsAddNegate()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp12SizeBytes * 2]
            .Sample(raw =>
            {
                using Fp12Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp12SizeBytes));
                using Fp12Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp12SizeBytes, WellKnownCurves.Bls12Curve381Fp12SizeBytes));
                using Fp12Element direct = a.Subtract(b, Subtract, BaseMemoryPool.Shared);
                using Fp12Element negB = b.Negate(Negate, BaseMemoryPool.Shared);
                using Fp12Element viaAdd = a.Add(negB, Add, BaseMemoryPool.Shared);
                return direct.AsReadOnlySpan().SequenceEqual(viaAdd.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicativeInverseRoundTrips()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp12SizeBytes]
            .Sample(raw =>
            {
                using Fp12Element a = ReduceAndWrap(raw);
                if(a.IsZero)
                {
                    return true;
                }

                using Fp12Element inverse = a.Invert(Invert, BaseMemoryPool.Shared);
                using Fp12Element product = a.Multiply(inverse, Multiply, BaseMemoryPool.Shared);
                return product.IsOne;
            }, iter: IterationCount);
    }


    [TestMethod]
    public void ConjugateIsInvolutive()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp12SizeBytes]
            .Sample(raw =>
            {
                using Fp12Element a = ReduceAndWrap(raw);
                using Fp12Element once = a.Conjugate(Conjugate, BaseMemoryPool.Shared);
                using Fp12Element twice = once.Conjugate(Conjugate, BaseMemoryPool.Shared);
                return a.AsReadOnlySpan().SequenceEqual(twice.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void ConjugateIsAHomomorphism()
    {
        //conj(a·b) == conj(a)·conj(b). The non-trivial automorphism
        //fixing Fp6 is a field homomorphism; this would break under a
        //bad sign convention on the w² → v wrap.
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp12SizeBytes * 2]
            .Sample(raw =>
            {
                using Fp12Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp12SizeBytes));
                using Fp12Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp12SizeBytes, WellKnownCurves.Bls12Curve381Fp12SizeBytes));
                using Fp12Element product = a.Multiply(b, Multiply, BaseMemoryPool.Shared);
                using Fp12Element conjOfProduct = product.Conjugate(Conjugate, BaseMemoryPool.Shared);
                using Fp12Element conjA = a.Conjugate(Conjugate, BaseMemoryPool.Shared);
                using Fp12Element conjB = b.Conjugate(Conjugate, BaseMemoryPool.Shared);
                using Fp12Element productOfConj = conjA.Multiply(conjB, Multiply, BaseMemoryPool.Shared);
                return conjOfProduct.AsReadOnlySpan().SequenceEqual(productOfConj.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void ZeroIsAdditiveIdentity()
    {
        using Fp12Element zero = Fp12Element.Zero(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp12SizeBytes]
            .Sample(raw =>
            {
                using Fp12Element a = ReduceAndWrap(raw);
                using Fp12Element sum = a.Add(zero, Add, BaseMemoryPool.Shared);
                return sum.AsReadOnlySpan().SequenceEqual(a.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void OneIsMultiplicativeIdentity()
    {
        using Fp12Element one = Fp12Element.One(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp12SizeBytes]
            .Sample(raw =>
            {
                using Fp12Element a = ReduceAndWrap(raw);
                using Fp12Element product = a.Multiply(one, Multiply, BaseMemoryPool.Shared);
                return product.AsReadOnlySpan().SequenceEqual(a.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void WSquaredEqualsV()
    {
        //The load-bearing tower-wrap check: w² must equal v, the Fp6
        //element (0, 1, 0). A wrong sign or wrong v-component slot would
        //surface here. Construct w = Fp12 element (0, 1) — i.e. c0 = 0
        //and c1 = Fp6 one — then square and check against (v, 0).
        byte[] wBytes = new byte[WellKnownCurves.Bls12Curve381Fp12SizeBytes];
        //c1 starts at offset 288 (the Fp6 size). c1.c0 (Fp2) starts there.
        //c1.c0.c0 (Fp) ends at offset 288 + 48 - 1 = 335. Set that byte to 1.
        wBytes[WellKnownCurves.Bls12Curve381Fp6SizeBytes + WellKnownCurves.Bls12Curve381BaseFieldSizeBytes - 1] = 0x01;
        using Fp12Element w = Fp12Element.FromCanonical(wBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using Fp12Element wSquared = w.Multiply(w, Multiply, BaseMemoryPool.Shared);

        //Expected: Fp12 element (v, 0). v itself is the Fp6 element (0, 1, 0):
        //inside the first 288-byte c0 slot, the c1 (Fp2 v-slot) starts at offset 96,
        //and its real component's last byte sits at offset 96 + 48 - 1 = 143.
        byte[] expectedBytes = new byte[WellKnownCurves.Bls12Curve381Fp12SizeBytes];
        expectedBytes[WellKnownCurves.Bls12Curve381Fp2SizeBytes + WellKnownCurves.Bls12Curve381BaseFieldSizeBytes - 1] = 0x01;

        Assert.IsTrue(wSquared.AsReadOnlySpan().SequenceEqual(expectedBytes), "w² must equal v.");
    }


    [TestMethod]
    public void FromComponentsRoundTripsThroughAccessors()
    {
        byte[] c0 = new byte[WellKnownCurves.Bls12Curve381Fp6SizeBytes];
        byte[] c1 = new byte[WellKnownCurves.Bls12Curve381Fp6SizeBytes];
        c0[^1] = 0x07;
        c1[^1] = 0x0b;

        using Fp12Element element = Fp12Element.FromComponents(c0, c1, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        Assert.IsTrue(element.GetC0ComponentBytes().SequenceEqual(c0));
        Assert.IsTrue(element.GetC1ComponentBytes().SequenceEqual(c1));
    }


    private static Fp12Element ReduceAndWrap(ReadOnlySpan<byte> raw)
    {
        Span<byte> packed = stackalloc byte[WellKnownCurves.Bls12Curve381Fp12SizeBytes];
        packed.Clear();
        for(int i = 0; i < 6; i++)
        {
            int start = i * WellKnownCurves.Bls12Curve381Fp2SizeBytes;
            ReduceFp2Slot(raw.Slice(start, WellKnownCurves.Bls12Curve381Fp2SizeBytes), packed.Slice(start, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
        }

        return Fp12Element.FromCanonical(packed, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static void ReduceFp2Slot(ReadOnlySpan<byte> rawFp2, Span<byte> packedFp2)
    {
        BigInteger c0Raw = new(rawFp2[..CompSize], isUnsigned: true, isBigEndian: true);
        BigInteger c1Raw = new(rawFp2.Slice(CompSize, CompSize), isUnsigned: true, isBigEndian: true);
        BigInteger c0 = c0Raw % BaseFieldPrime;
        BigInteger c1 = c1Raw % BaseFieldPrime;
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
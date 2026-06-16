using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Algebraic-identity property tests for the BN254 (alt_bn128) Fp12 extension
/// field — the pairing target field (<see cref="Bn254BigIntegerFp12Reference"/>).
/// The load-bearing structural checks are <see cref="WSquaredEqualsV"/> (the
/// <c>w² = v</c> tower wrap) and that conjugation is a field homomorphism;
/// inverse round-trip exercises the full quadratic-extension norm. The Fp12
/// multiply is built from the Fp6 multiply that the Fp6 suite cross-checks
/// against an independent reference, so its <c>ξ = 9 + u</c> dependence is
/// covered there and the <c>w² = v</c> check covers the Fp12-level wrap.
/// </summary>
[TestClass]
internal sealed class Bn254Fp12ArithmeticTests
{
    private static readonly Fp12AddDelegate Add = Bn254BigIntegerFp12Reference.GetAdd();
    private static readonly Fp12SubtractDelegate Subtract = Bn254BigIntegerFp12Reference.GetSubtract();
    private static readonly Fp12MultiplyDelegate Multiply = Bn254BigIntegerFp12Reference.GetMultiply();
    private static readonly Fp12SquareDelegate Square = Bn254BigIntegerFp12Reference.GetSquare();
    private static readonly Fp12NegateDelegate Negate = Bn254BigIntegerFp12Reference.GetNegate();
    private static readonly Fp12InvertDelegate Invert = Bn254BigIntegerFp12Reference.GetInvert();
    private static readonly Fp12ConjugateDelegate Conjugate = Bn254BigIntegerFp12Reference.GetConjugate();

    private static readonly BigInteger BaseFieldPrime = Bn254BigIntegerG1Reference.BaseFieldPrime;
    private const int CompSize = WellKnownCurves.Bn254BaseFieldSizeBytes;
    private const int Fp2Size = 2 * WellKnownCurves.Bn254BaseFieldSizeBytes;
    private const int Fp6Size = 6 * WellKnownCurves.Bn254BaseFieldSizeBytes;
    private const int Fp12Size = 12 * WellKnownCurves.Bn254BaseFieldSizeBytes;

    private const long IterationCount = 15;

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void AdditionIsCommutative()
    {
        Gen.Byte.Array[Fp12Size * 2].Sample(raw =>
        {
            using Fp12Element a = ReduceAndWrap(raw.AsSpan(0, Fp12Size));
            using Fp12Element b = ReduceAndWrap(raw.AsSpan(Fp12Size, Fp12Size));
            using Fp12Element ab = a.Add(b, Add, Pool);
            using Fp12Element ba = b.Add(a, Add, Pool);
            return ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsCommutative()
    {
        Gen.Byte.Array[Fp12Size * 2].Sample(raw =>
        {
            using Fp12Element a = ReduceAndWrap(raw.AsSpan(0, Fp12Size));
            using Fp12Element b = ReduceAndWrap(raw.AsSpan(Fp12Size, Fp12Size));
            using Fp12Element ab = a.Multiply(b, Multiply, Pool);
            using Fp12Element ba = b.Multiply(a, Multiply, Pool);
            return ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsAssociative()
    {
        Gen.Byte.Array[Fp12Size * 3].Sample(raw =>
        {
            using Fp12Element a = ReduceAndWrap(raw.AsSpan(0, Fp12Size));
            using Fp12Element b = ReduceAndWrap(raw.AsSpan(Fp12Size, Fp12Size));
            using Fp12Element c = ReduceAndWrap(raw.AsSpan(2 * Fp12Size, Fp12Size));
            using Fp12Element ab = a.Multiply(b, Multiply, Pool);
            using Fp12Element abTimesC = ab.Multiply(c, Multiply, Pool);
            using Fp12Element bc = b.Multiply(c, Multiply, Pool);
            using Fp12Element aTimesBc = a.Multiply(bc, Multiply, Pool);
            return abTimesC.AsReadOnlySpan().SequenceEqual(aTimesBc.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void DistributivityHolds()
    {
        Gen.Byte.Array[Fp12Size * 3].Sample(raw =>
        {
            using Fp12Element a = ReduceAndWrap(raw.AsSpan(0, Fp12Size));
            using Fp12Element b = ReduceAndWrap(raw.AsSpan(Fp12Size, Fp12Size));
            using Fp12Element c = ReduceAndWrap(raw.AsSpan(2 * Fp12Size, Fp12Size));
            using Fp12Element bPlusC = b.Add(c, Add, Pool);
            using Fp12Element left = a.Multiply(bPlusC, Multiply, Pool);
            using Fp12Element ab = a.Multiply(b, Multiply, Pool);
            using Fp12Element ac = a.Multiply(c, Multiply, Pool);
            using Fp12Element right = ab.Add(ac, Add, Pool);
            return left.AsReadOnlySpan().SequenceEqual(right.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void SquareEqualsSelfMultiply()
    {
        Gen.Byte.Array[Fp12Size].Sample(raw =>
        {
            using Fp12Element a = ReduceAndWrap(raw);
            using Fp12Element viaSquare = a.Square(Square, Pool);
            using Fp12Element viaMultiply = a.Multiply(a, Multiply, Pool);
            return viaSquare.AsReadOnlySpan().SequenceEqual(viaMultiply.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void SubtractionEqualsAddNegate()
    {
        Gen.Byte.Array[Fp12Size * 2].Sample(raw =>
        {
            using Fp12Element a = ReduceAndWrap(raw.AsSpan(0, Fp12Size));
            using Fp12Element b = ReduceAndWrap(raw.AsSpan(Fp12Size, Fp12Size));
            using Fp12Element direct = a.Subtract(b, Subtract, Pool);
            using Fp12Element negB = b.Negate(Negate, Pool);
            using Fp12Element viaAdd = a.Add(negB, Add, Pool);
            return direct.AsReadOnlySpan().SequenceEqual(viaAdd.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicativeInverseRoundTrips()
    {
        Gen.Byte.Array[Fp12Size].Sample(raw =>
        {
            using Fp12Element a = ReduceAndWrap(raw);
            if(a.IsZero)
            {
                return true;
            }

            using Fp12Element inverse = a.Invert(Invert, Pool);
            using Fp12Element product = a.Multiply(inverse, Multiply, Pool);
            return product.IsOne;
        }, iter: IterationCount);
    }


    [TestMethod]
    public void ConjugateIsInvolutive()
    {
        Gen.Byte.Array[Fp12Size].Sample(raw =>
        {
            using Fp12Element a = ReduceAndWrap(raw);
            using Fp12Element once = a.Conjugate(Conjugate, Pool);
            using Fp12Element twice = once.Conjugate(Conjugate, Pool);
            return a.AsReadOnlySpan().SequenceEqual(twice.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void ConjugateIsAHomomorphism()
    {
        //conj(a·b) == conj(a)·conj(b) — would break under a bad sign convention
        //on the w² → v wrap.
        Gen.Byte.Array[Fp12Size * 2].Sample(raw =>
        {
            using Fp12Element a = ReduceAndWrap(raw.AsSpan(0, Fp12Size));
            using Fp12Element b = ReduceAndWrap(raw.AsSpan(Fp12Size, Fp12Size));
            using Fp12Element product = a.Multiply(b, Multiply, Pool);
            using Fp12Element conjOfProduct = product.Conjugate(Conjugate, Pool);
            using Fp12Element conjA = a.Conjugate(Conjugate, Pool);
            using Fp12Element conjB = b.Conjugate(Conjugate, Pool);
            using Fp12Element productOfConj = conjA.Multiply(conjB, Multiply, Pool);
            return conjOfProduct.AsReadOnlySpan().SequenceEqual(productOfConj.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void OneIsMultiplicativeIdentity()
    {
        using Fp12Element one = Fp12Element.One(CurveParameterSet.Bn254, Pool);
        Gen.Byte.Array[Fp12Size].Sample(raw =>
        {
            using Fp12Element a = ReduceAndWrap(raw);
            using Fp12Element product = a.Multiply(one, Multiply, Pool);
            return product.AsReadOnlySpan().SequenceEqual(a.AsReadOnlySpan());
        }, iter: IterationCount);
    }


    [TestMethod]
    public void WSquaredEqualsV()
    {
        //w² must equal v, the Fp6 element (0, 1, 0). Construct w = Fp12 (0, 1)
        //by setting the c1.c0.real byte (c1 is the second Fp6 slot, its first
        //Fp2 component's real part).
        Span<byte> wBytes = stackalloc byte[Fp12Size];
        wBytes.Clear();
        wBytes[Fp6Size + CompSize - 1] = 0x01;
        using Fp12Element w = Fp12Element.FromCanonical(wBytes, CurveParameterSet.Bn254, Pool);

        using Fp12Element wSquared = w.Multiply(w, Multiply, Pool);

        //Expected: Fp12 (v, 0) where v = (0, 1, 0) sits in the c0 slot; its
        //c1.real byte is at Fp2Size + CompSize - 1.
        Span<byte> expected = stackalloc byte[Fp12Size];
        expected.Clear();
        expected[Fp2Size + CompSize - 1] = 0x01;

        Assert.IsTrue(wSquared.AsReadOnlySpan().SequenceEqual(expected), "w² must equal v.");
    }


    [TestMethod]
    public void FromComponentsRoundTripsThroughAccessors()
    {
        Span<byte> c0 = stackalloc byte[Fp6Size];
        Span<byte> c1 = stackalloc byte[Fp6Size];
        c0.Clear();
        c1.Clear();
        c0[^1] = 0x07;
        c1[^1] = 0x0b;

        using Fp12Element element = Fp12Element.FromComponents(c0, c1, CurveParameterSet.Bn254, Pool);

        Assert.IsTrue(element.GetC0ComponentBytes().SequenceEqual(c0));
        Assert.IsTrue(element.GetC1ComponentBytes().SequenceEqual(c1));
    }


    private static Fp12Element ReduceAndWrap(ReadOnlySpan<byte> raw)
    {
        Span<byte> packed = stackalloc byte[Fp12Size];
        packed.Clear();
        for(int i = 0; i < 6; i++)
        {
            int start = i * Fp2Size;
            ReduceFp2Slot(raw.Slice(start, Fp2Size), packed.Slice(start, Fp2Size));
        }

        return Fp12Element.FromCanonical(packed, CurveParameterSet.Bn254, Pool);
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

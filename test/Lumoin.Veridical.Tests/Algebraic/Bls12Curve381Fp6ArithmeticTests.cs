using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Algebraic-identity property tests for the BLS12-381 Fp6 cubic
/// extension field. The load-bearing structural check at this layer
/// is the tower-non-residue identity: <c>v³</c> must wrap to <c>ξ = 1 + u</c>,
/// not to any other Fp2 value. A wrong sign on <c>ξ</c> would not show
/// up in additive identities but would break <c>v · v · v = ξ</c> and
/// propagate to wrong pairings.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381Fp6ArithmeticTests
{
    private static readonly Fp6AddDelegate Add = Bls12Curve381BigIntegerFp6Reference.GetAdd();
    private static readonly Fp6SubtractDelegate Subtract = Bls12Curve381BigIntegerFp6Reference.GetSubtract();
    private static readonly Fp6MultiplyDelegate Multiply = Bls12Curve381BigIntegerFp6Reference.GetMultiply();
    private static readonly Fp6SquareDelegate Square = Bls12Curve381BigIntegerFp6Reference.GetSquare();
    private static readonly Fp6NegateDelegate Negate = Bls12Curve381BigIntegerFp6Reference.GetNegate();
    private static readonly Fp6InvertDelegate Invert = Bls12Curve381BigIntegerFp6Reference.GetInvert();

    private static readonly BigInteger BaseFieldPrime = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;
    private const int CompSize = WellKnownCurves.Bls12Curve381BaseFieldSizeBytes;

    //CsCheck iteration count: small because each iteration does many
    //BigInteger operations through the schoolbook 9-mul Fp6 formula.
    private const long IterationCount = 30;


    [TestMethod]
    public void AdditionIsCommutative()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp6SizeBytes * 2]
            .Sample(raw =>
            {
                using Fp6Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp6SizeBytes, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element ab = a.Add(b, Add, BaseMemoryPool.Shared);
                using Fp6Element ba = b.Add(a, Add, BaseMemoryPool.Shared);
                return ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void AdditionIsAssociative()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp6SizeBytes * 3]
            .Sample(raw =>
            {
                using Fp6Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp6SizeBytes, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element c = ReduceAndWrap(raw.AsSpan(2 * WellKnownCurves.Bls12Curve381Fp6SizeBytes, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element ab = a.Add(b, Add, BaseMemoryPool.Shared);
                using Fp6Element abPlusC = ab.Add(c, Add, BaseMemoryPool.Shared);
                using Fp6Element bc = b.Add(c, Add, BaseMemoryPool.Shared);
                using Fp6Element aPlusBc = a.Add(bc, Add, BaseMemoryPool.Shared);
                return abPlusC.AsReadOnlySpan().SequenceEqual(aPlusBc.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsCommutative()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp6SizeBytes * 2]
            .Sample(raw =>
            {
                using Fp6Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp6SizeBytes, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element ab = a.Multiply(b, Multiply, BaseMemoryPool.Shared);
                using Fp6Element ba = b.Multiply(a, Multiply, BaseMemoryPool.Shared);
                return ab.AsReadOnlySpan().SequenceEqual(ba.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationIsAssociative()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp6SizeBytes * 3]
            .Sample(raw =>
            {
                using Fp6Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp6SizeBytes, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element c = ReduceAndWrap(raw.AsSpan(2 * WellKnownCurves.Bls12Curve381Fp6SizeBytes, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element ab = a.Multiply(b, Multiply, BaseMemoryPool.Shared);
                using Fp6Element abTimesC = ab.Multiply(c, Multiply, BaseMemoryPool.Shared);
                using Fp6Element bc = b.Multiply(c, Multiply, BaseMemoryPool.Shared);
                using Fp6Element aTimesBc = a.Multiply(bc, Multiply, BaseMemoryPool.Shared);
                return abTimesC.AsReadOnlySpan().SequenceEqual(aTimesBc.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void DistributivityHolds()
    {
        //a · (b + c) == a·b + a·c.
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp6SizeBytes * 3]
            .Sample(raw =>
            {
                using Fp6Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp6SizeBytes, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element c = ReduceAndWrap(raw.AsSpan(2 * WellKnownCurves.Bls12Curve381Fp6SizeBytes, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element bPlusC = b.Add(c, Add, BaseMemoryPool.Shared);
                using Fp6Element left = a.Multiply(bPlusC, Multiply, BaseMemoryPool.Shared);
                using Fp6Element ab = a.Multiply(b, Multiply, BaseMemoryPool.Shared);
                using Fp6Element ac = a.Multiply(c, Multiply, BaseMemoryPool.Shared);
                using Fp6Element right = ab.Add(ac, Add, BaseMemoryPool.Shared);
                return left.AsReadOnlySpan().SequenceEqual(right.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void SquareEqualsSelfMultiply()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp6SizeBytes]
            .Sample(raw =>
            {
                using Fp6Element a = ReduceAndWrap(raw);
                using Fp6Element viaSquare = a.Square(Square, BaseMemoryPool.Shared);
                using Fp6Element viaMultiply = a.Multiply(a, Multiply, BaseMemoryPool.Shared);
                return viaSquare.AsReadOnlySpan().SequenceEqual(viaMultiply.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void NegationCancelsAddition()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp6SizeBytes]
            .Sample(raw =>
            {
                using Fp6Element a = ReduceAndWrap(raw);
                using Fp6Element negA = a.Negate(Negate, BaseMemoryPool.Shared);
                using Fp6Element sum = a.Add(negA, Add, BaseMemoryPool.Shared);
                return sum.IsZero;
            }, iter: IterationCount);
    }


    [TestMethod]
    public void SubtractionEqualsAddNegate()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp6SizeBytes * 2]
            .Sample(raw =>
            {
                using Fp6Element a = ReduceAndWrap(raw.AsSpan(0, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element b = ReduceAndWrap(raw.AsSpan(WellKnownCurves.Bls12Curve381Fp6SizeBytes, WellKnownCurves.Bls12Curve381Fp6SizeBytes));
                using Fp6Element direct = a.Subtract(b, Subtract, BaseMemoryPool.Shared);
                using Fp6Element negB = b.Negate(Negate, BaseMemoryPool.Shared);
                using Fp6Element viaAdd = a.Add(negB, Add, BaseMemoryPool.Shared);
                return direct.AsReadOnlySpan().SequenceEqual(viaAdd.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicativeInverseRoundTrips()
    {
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp6SizeBytes]
            .Sample(raw =>
            {
                using Fp6Element a = ReduceAndWrap(raw);
                if(a.IsZero)
                {
                    return true;
                }

                using Fp6Element inverse = a.Invert(Invert, BaseMemoryPool.Shared);
                using Fp6Element product = a.Multiply(inverse, Multiply, BaseMemoryPool.Shared);
                return product.IsOne;
            }, iter: IterationCount);
    }


    [TestMethod]
    public void ZeroIsAdditiveIdentity()
    {
        using Fp6Element zero = Fp6Element.Zero(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp6SizeBytes]
            .Sample(raw =>
            {
                using Fp6Element a = ReduceAndWrap(raw);
                using Fp6Element sum = a.Add(zero, Add, BaseMemoryPool.Shared);
                return sum.AsReadOnlySpan().SequenceEqual(a.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void OneIsMultiplicativeIdentity()
    {
        using Fp6Element one = Fp6Element.One(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        Gen.Byte.Array[WellKnownCurves.Bls12Curve381Fp6SizeBytes]
            .Sample(raw =>
            {
                using Fp6Element a = ReduceAndWrap(raw);
                using Fp6Element product = a.Multiply(one, Multiply, BaseMemoryPool.Shared);
                return product.AsReadOnlySpan().SequenceEqual(a.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void VCubedEqualsNonResidue()
    {
        //The load-bearing tower-non-residue check: v · v · v must equal
        //the Fp6 element (1+u, 0, 0). A sign or component mistake on ξ
        //would surface here directly. Compute v = (0, 1, 0) by setting
        //the c1.c0 byte to 0x01 in the canonical encoding.
        byte[] vBytes = new byte[WellKnownCurves.Bls12Curve381Fp6SizeBytes];
        //v lives in the c1 slot; c1.c0's last byte is at offset CompSize + (CompSize/2) - 1.
        //Actually c1.c0 occupies bytes [CompSize, CompSize + 48); its last byte sits at
        //CompSize + 48 - 1 = CompSize + CompSize/2 - 1 (since each Fp component is 48 bytes).
        int c1RealLastByte = WellKnownCurves.Bls12Curve381Fp2SizeBytes + WellKnownCurves.Bls12Curve381BaseFieldSizeBytes - 1;
        vBytes[c1RealLastByte] = 0x01;
        using Fp6Element v = Fp6Element.FromCanonical(vBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using Fp6Element vSquared = v.Multiply(v, Multiply, BaseMemoryPool.Shared);
        using Fp6Element vCubed = vSquared.Multiply(v, Multiply, BaseMemoryPool.Shared);

        //Expected: (ξ, 0, 0) where ξ = 1 + u, i.e. c0.c0 = 1, c0.c1 = 1, rest zero.
        byte[] expectedBytes = new byte[WellKnownCurves.Bls12Curve381Fp6SizeBytes];
        expectedBytes[WellKnownCurves.Bls12Curve381BaseFieldSizeBytes - 1] = 0x01;  //c0.c0 = 1
        expectedBytes[WellKnownCurves.Bls12Curve381Fp2SizeBytes - 1] = 0x01;  //c0.c1 = 1

        Assert.IsTrue(vCubed.AsReadOnlySpan().SequenceEqual(expectedBytes), "v³ must equal ξ = 1 + u.");
    }


    [TestMethod]
    public void FromComponentsRoundTripsThroughAccessors()
    {
        byte[] c0 = new byte[WellKnownCurves.Bls12Curve381Fp2SizeBytes];
        byte[] c1 = new byte[WellKnownCurves.Bls12Curve381Fp2SizeBytes];
        byte[] c2 = new byte[WellKnownCurves.Bls12Curve381Fp2SizeBytes];
        c0[^1] = 0x07;
        c1[^1] = 0x0b;
        c2[^1] = 0x0d;

        using Fp6Element element = Fp6Element.FromComponents(c0, c1, c2, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        Assert.IsTrue(element.GetC0ComponentBytes().SequenceEqual(c0));
        Assert.IsTrue(element.GetC1ComponentBytes().SequenceEqual(c1));
        Assert.IsTrue(element.GetC2ComponentBytes().SequenceEqual(c2));
    }


    private static Fp6Element ReduceAndWrap(ReadOnlySpan<byte> raw)
    {
        Span<byte> packed = stackalloc byte[WellKnownCurves.Bls12Curve381Fp6SizeBytes];
        packed.Clear();
        ReduceFp2Slot(raw[..WellKnownCurves.Bls12Curve381Fp2SizeBytes], packed[..WellKnownCurves.Bls12Curve381Fp2SizeBytes]);
        ReduceFp2Slot(raw.Slice(WellKnownCurves.Bls12Curve381Fp2SizeBytes, WellKnownCurves.Bls12Curve381Fp2SizeBytes), packed.Slice(WellKnownCurves.Bls12Curve381Fp2SizeBytes, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
        ReduceFp2Slot(raw.Slice(2 * WellKnownCurves.Bls12Curve381Fp2SizeBytes, WellKnownCurves.Bls12Curve381Fp2SizeBytes), packed.Slice(2 * WellKnownCurves.Bls12Curve381Fp2SizeBytes, WellKnownCurves.Bls12Curve381Fp2SizeBytes));
        return Fp6Element.FromCanonical(packed, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
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
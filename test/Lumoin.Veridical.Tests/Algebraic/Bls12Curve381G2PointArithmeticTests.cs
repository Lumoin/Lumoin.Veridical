using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Algebraic-identity property tests for the BLS12-381 G2 group. The
/// load-bearing checks here are (a) the canonical generator round-
/// trips through serialise / deserialise, (b) it is on the twist
/// curve, (c) it is in the prime-order subgroup, and (d) the group
/// law's standard identities hold for random scalar multiples of the
/// generator.
/// </summary>
[TestClass]
internal sealed class Bls12Curve381G2PointArithmeticTests
{
    private static readonly G2AddDelegate Add = Bls12Curve381BigIntegerG2Reference.GetAdd();
    private static readonly G2NegateDelegate Negate = Bls12Curve381BigIntegerG2Reference.GetNegate();
    private static readonly G2ScalarMultiplyDelegate ScalarMul = Bls12Curve381BigIntegerG2Reference.GetScalarMultiply();
    private static readonly G2IsOnCurveDelegate IsOnCurve = Bls12Curve381BigIntegerG2Reference.GetIsOnCurve();
    private static readonly G2IsInPrimeOrderSubgroupDelegate IsInPrimeOrderSubgroup = Bls12Curve381BigIntegerG2Reference.GetIsInPrimeOrderSubgroup();
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

    private const long IterationCount = 8; //G2 scalar-mul over a 256-bit scalar is slow in BigInteger.


    [TestMethod]
    public void GeneratorIsOnCurve()
    {
        using G2Point generator = G2Point.Generator(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        Assert.IsTrue(generator.IsOnCurve(IsOnCurve), "BLS12-381 G2 generator must satisfy y² = x³ + 4(1+u) over Fp2.");
    }


    [TestMethod]
    public void GeneratorIsInPrimeOrderSubgroup()
    {
        using G2Point generator = G2Point.Generator(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        Assert.IsTrue(generator.IsInPrimeOrderSubgroup(IsInPrimeOrderSubgroup), "BLS12-381 G2 generator must be in the prime-order subgroup.");
    }


    [TestMethod]
    public void IdentityIsOnCurve()
    {
        using G2Point identity = G2Point.Identity(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        Assert.IsTrue(identity.IsOnCurve(IsOnCurve));
        Assert.IsTrue(identity.IsIdentity);
    }


    [TestMethod]
    public void GeneratorEncodingRoundTrips()
    {
        //Decode the generator and re-encode; the resulting bytes must equal the input.
        //This catches sign-flag and component-order bugs in encode/decode.
        using G2Point generator = G2Point.Generator(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        byte[] expected = generator.AsReadOnlySpan().ToArray();

        //Round-trip via Add(generator, identity) which exercises Decode/Encode.
        using G2Point identity = G2Point.Identity(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        using G2Point sum = generator.Add(identity, Add, SensitiveMemoryPool<byte>.Shared);

        Assert.IsTrue(expected.AsSpan().SequenceEqual(sum.AsReadOnlySpan()), "Decoding and re-encoding the generator (via Add identity) must produce the same bytes.");
    }


    [TestMethod]
    public void NegationIsInvolutive()
    {
        using G2Point generator = G2Point.Generator(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        using G2Point neg = generator.Negate(Negate, SensitiveMemoryPool<byte>.Shared);
        using G2Point negNeg = neg.Negate(Negate, SensitiveMemoryPool<byte>.Shared);

        Assert.IsTrue(generator.AsReadOnlySpan().SequenceEqual(negNeg.AsReadOnlySpan()), "Negating the generator twice should recover the original bytes.");
    }


    [TestMethod]
    public void GeneratorPlusNegativeGeneratorIsIdentity()
    {
        using G2Point generator = G2Point.Generator(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        using G2Point neg = generator.Negate(Negate, SensitiveMemoryPool<byte>.Shared);
        using G2Point sum = generator.Add(neg, Add, SensitiveMemoryPool<byte>.Shared);

        Assert.IsTrue(sum.IsIdentity, "G + (-G) must equal the identity.");
    }


    [TestMethod]
    public void AdditionIsCommutativeOnGeneratorMultiples()
    {
        Gen.Byte.Array[2 * Scalar.SizeBytes]
            .Sample(raw =>
            {
                using G2Point generator = G2Point.Generator(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
                using Scalar k1 = ReduceToScalar(raw.AsSpan(0, Scalar.SizeBytes));
                using Scalar k2 = ReduceToScalar(raw.AsSpan(Scalar.SizeBytes, Scalar.SizeBytes));
                using G2Point p = generator.ScalarMultiply(k1, ScalarMul, SensitiveMemoryPool<byte>.Shared);
                using G2Point q = generator.ScalarMultiply(k2, ScalarMul, SensitiveMemoryPool<byte>.Shared);
                using G2Point pq = p.Add(q, Add, SensitiveMemoryPool<byte>.Shared);
                using G2Point qp = q.Add(p, Add, SensitiveMemoryPool<byte>.Shared);
                return pq.AsReadOnlySpan().SequenceEqual(qp.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void ScalarMultiplyByOneIsIdentity()
    {
        //[1] · G = G.
        using G2Point generator = G2Point.Generator(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        byte[] oneBytes = new byte[Scalar.SizeBytes];
        oneBytes[^1] = 0x01;
        using Scalar one = Scalar.FromCanonical(oneBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        using G2Point product = generator.ScalarMultiply(one, ScalarMul, SensitiveMemoryPool<byte>.Shared);

        Assert.IsTrue(generator.AsReadOnlySpan().SequenceEqual(product.AsReadOnlySpan()), "[1] · G must equal G.");
    }


    [TestMethod]
    public void ScalarMultiplyByZeroIsIdentity()
    {
        using G2Point generator = G2Point.Generator(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        byte[] zeroBytes = new byte[Scalar.SizeBytes];
        using Scalar zero = Scalar.FromCanonical(zeroBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        using G2Point product = generator.ScalarMultiply(zero, ScalarMul, SensitiveMemoryPool<byte>.Shared);

        Assert.IsTrue(product.IsIdentity, "[0] · G must be the identity.");
    }


    [TestMethod]
    public void ScalarMultiplyByOrderIsIdentity()
    {
        //[r] · G = identity (since G is in the prime-order subgroup).
        BigInteger r = Bls12Curve381BigIntegerG2Reference.ScalarFieldOrder;
        byte[] rBytes = new byte[Scalar.SizeBytes];
        WriteCanonical(r, rBytes);
        using Scalar rScalar = Scalar.FromCanonical(rBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        using G2Point generator = G2Point.Generator(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        using G2Point product = generator.ScalarMultiply(rScalar, ScalarMul, SensitiveMemoryPool<byte>.Shared);

        Assert.IsTrue(product.IsIdentity, "[r] · G must be the identity.");
    }


    [TestMethod]
    public void DistributivityHoldsOverGenerator()
    {
        //[a+b] · G = [a] · G + [b] · G.
        Gen.Byte.Array[2 * Scalar.SizeBytes]
            .Sample(raw =>
            {
                using G2Point generator = G2Point.Generator(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

                BigInteger a = new BigInteger(raw.AsSpan(0, Scalar.SizeBytes), isUnsigned: true, isBigEndian: true);
                BigInteger b = new BigInteger(raw.AsSpan(Scalar.SizeBytes, Scalar.SizeBytes), isUnsigned: true, isBigEndian: true);
                BigInteger r = Bls12Curve381BigIntegerG2Reference.ScalarFieldOrder;
                a %= r;
                b %= r;
                BigInteger aPlusB = (a + b) % r;

                using Scalar ka = ScalarFromBigInteger(a);
                using Scalar kb = ScalarFromBigInteger(b);
                using Scalar kSum = ScalarFromBigInteger(aPlusB);

                using G2Point lhs = generator.ScalarMultiply(kSum, ScalarMul, SensitiveMemoryPool<byte>.Shared);
                using G2Point pa = generator.ScalarMultiply(ka, ScalarMul, SensitiveMemoryPool<byte>.Shared);
                using G2Point pb = generator.ScalarMultiply(kb, ScalarMul, SensitiveMemoryPool<byte>.Shared);
                using G2Point rhs = pa.Add(pb, Add, SensitiveMemoryPool<byte>.Shared);

                return lhs.AsReadOnlySpan().SequenceEqual(rhs.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void TamperedFlagBitRejectedByOnCurveCheck()
    {
        //Flip the y-parity flag in the generator's high byte. The resulting
        //bytes represent a different y-coordinate that may or may not be
        //on-curve; if it IS on-curve, it's at minimum a different point.
        //More importantly, flipping the compression flag makes the encoding
        //non-conformant and IsOnCurve must reject.
        using G2Point generator = G2Point.Generator(CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        byte[] tampered = generator.AsReadOnlySpan().ToArray();
        tampered[0] &= 0x7f; //clear compression flag

        using G2Point tamperedPoint = G2Point.FromCanonical(tampered, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        Assert.IsFalse(tamperedPoint.IsOnCurve(IsOnCurve), "Cleared compression flag must cause on-curve check to reject.");
    }


    private static Scalar ReduceToScalar(ReadOnlySpan<byte> raw)
    {
        Span<byte> bytes = stackalloc byte[Scalar.SizeBytes];
        Reduce(raw, bytes, CurveParameterSet.Bls12Curve381);
        return Scalar.FromCanonical(bytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
    }


    private static Scalar ScalarFromBigInteger(BigInteger value)
    {
        byte[] bytes = new byte[Scalar.SizeBytes];
        WriteCanonical(value, bytes);
        return Scalar.FromCanonical(bytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }
        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Commitments.Ligero;

/// <summary>
/// Gates the systematic Reed–Solomon encoder against an independent BigInteger
/// polynomial-evaluation oracle. The message is built as the evaluations at
/// <c>{0, …, k − 1}</c> of a known degree-<c>&lt; k</c> polynomial; the encoder
/// must reproduce that same polynomial's evaluations at the extension points
/// <c>{k, …, n − 1}</c>, and leave the systematic prefix untouched. Run over a
/// tiny Mersenne-prime field (cheap, hand-checkable) and over P-256's scalar
/// field (the real target, no smooth-order roots of unity).
/// </summary>
[TestClass]
internal sealed class LigeroReedSolomonEncoderTests
{
    private const int ScalarSize = Scalar.SizeBytes;

    //RS dimension k and block length n: a degree-<8 polynomial extended to
    //twice its evaluations (inverse rate 2) — small enough to check every
    //extension point against the oracle, large enough to exercise the
    //barycentric weights non-trivially.
    private const int MessageLength = 8;
    private const int CodewordLength = 16;

    //Distinct deterministic-fill salts for the polynomial coefficients.
    private const int SmallFieldCoefficientSalt = 101;
    private const int P256CoefficientSalt = 202;


    [TestMethod]
    public void EncodesByExtendingEvaluationsOverTheSmallPrimeField() =>
        AssertEncoderMatchesOracle(
            SmallPrimeFieldScalars.GetAdd(),
            SmallPrimeFieldScalars.GetSubtract(),
            SmallPrimeFieldScalars.GetMultiply(),
            SmallPrimeFieldScalars.GetInvert(),
            SmallPrimeFieldScalars.GetReduce(),
            CurveParameterSet.None,
            SmallPrimeFieldScalars.FieldOrder,
            SmallFieldCoefficientSalt);


    [TestMethod]
    public void EncodesByExtendingEvaluationsOverTheP256ScalarField() =>
        AssertEncoderMatchesOracle(
            P256BigIntegerScalarReference.GetAdd(),
            P256BigIntegerScalarReference.GetSubtract(),
            P256BigIntegerScalarReference.GetMultiply(),
            P256BigIntegerScalarReference.GetInvert(),
            P256BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.P256,
            P256BigIntegerScalarReference.FieldOrder,
            P256CoefficientSalt);


    [TestMethod]
    public void BarycentricEvaluatesAtScatteredPointsOverTheSmallPrimeField()
    {
        //The verifier path samples non-consecutive points; check a scattered
        //set against the oracle. Points must be ≥ MessageLength (never a node).
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarReduceDelegate reduce = SmallPrimeFieldScalars.GetReduce();
        BigInteger modulus = SmallPrimeFieldScalars.FieldOrder;

        Span<byte> coefficients = stackalloc byte[MessageLength * ScalarSize];
        DeterministicScalarFill.FillCanonical(coefficients, SmallFieldCoefficientSalt, reduce, CurveParameterSet.None);

        Span<byte> message = stackalloc byte[MessageLength * ScalarSize];
        for(int i = 0; i < MessageLength; i++)
        {
            WriteCanonical(EvaluatePolynomial(coefficients, i, modulus), message.Slice(i * ScalarSize, ScalarSize));
        }

        Span<byte> weights = stackalloc byte[MessageLength * ScalarSize];
        BarycentricInterpolation.ComputeConsecutiveNodeWeights(
            MessageLength, weights, SmallPrimeFieldScalars.GetSubtract(), SmallPrimeFieldScalars.GetMultiply(), SmallPrimeFieldScalars.GetInvert(), CurveParameterSet.None, pool);

        ReadOnlySpan<int> points = [11, 8, 31, 17, 200];
        Span<byte> results = stackalloc byte[points.Length * ScalarSize];
        BarycentricInterpolation.EvaluateAtPoints(
            message, weights, MessageLength, points, results,
            SmallPrimeFieldScalars.GetAdd(), SmallPrimeFieldScalars.GetSubtract(), SmallPrimeFieldScalars.GetMultiply(), SmallPrimeFieldScalars.GetInvert(), CurveParameterSet.None, pool);

        Span<byte> expected = stackalloc byte[ScalarSize];
        for(int p = 0; p < points.Length; p++)
        {
            WriteCanonical(EvaluatePolynomial(coefficients, points[p], modulus), expected);
            Assert.IsTrue(expected.SequenceEqual(results.Slice(p * ScalarSize, ScalarSize)), $"Interpolation at point {points[p]} must match the oracle.");
        }
    }


    private static void AssertEncoderMatchesOracle(
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        BigInteger modulus,
        int coefficientSalt)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        //The polynomial: MessageLength coefficients (degree < MessageLength),
        //each a canonical field element below the modulus.
        Span<byte> coefficients = stackalloc byte[MessageLength * ScalarSize];
        DeterministicScalarFill.FillCanonical(coefficients, coefficientSalt, reduce, curve);

        //The message: that polynomial evaluated at the nodes {0, …, k−1}.
        Span<byte> message = stackalloc byte[MessageLength * ScalarSize];
        for(int i = 0; i < MessageLength; i++)
        {
            WriteCanonical(EvaluatePolynomial(coefficients, i, modulus), message.Slice(i * ScalarSize, ScalarSize));
        }

        Span<byte> codeword = stackalloc byte[CodewordLength * ScalarSize];
        LigeroReedSolomonEncoder.Encode(message, MessageLength, codeword, CodewordLength, add, subtract, multiply, invert, curve, pool);

        //Systematic: the prefix is the message verbatim.
        Assert.IsTrue(message.SequenceEqual(codeword[..(MessageLength * ScalarSize)]), "The codeword prefix must equal the message.");

        //Each extension point must equal the polynomial evaluated there.
        Span<byte> expected = stackalloc byte[ScalarSize];
        for(int j = MessageLength; j < CodewordLength; j++)
        {
            WriteCanonical(EvaluatePolynomial(coefficients, j, modulus), expected);
            Assert.IsTrue(expected.SequenceEqual(codeword.Slice(j * ScalarSize, ScalarSize)), $"Codeword position {j} must equal the polynomial evaluated at {j}.");
        }
    }


    //Independent oracle: Horner evaluation of the polynomial whose coefficients
    //(constant term first) are the canonical field elements in `coefficients`,
    //at the integer point, modulo the field order.
    private static BigInteger EvaluatePolynomial(ReadOnlySpan<byte> coefficients, int point, BigInteger modulus)
    {
        BigInteger x = point;
        BigInteger accumulator = BigInteger.Zero;
        for(int t = MessageLength - 1; t >= 0; t--)
        {
            BigInteger coefficient = new(coefficients.Slice(t * ScalarSize, ScalarSize), isUnsigned: true, isBigEndian: true);
            accumulator = ((accumulator * x) + coefficient) % modulus;
        }

        return accumulator;
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true);
        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}

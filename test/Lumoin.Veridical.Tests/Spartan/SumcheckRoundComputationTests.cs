using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Tests for <see cref="SumcheckRoundComputation"/>: the pure round-
/// polynomial computation against hand-built MLE state, validated by
/// the BigInteger reference. The pure-function shape is exercised
/// indirectly by every test (no transcript anywhere in the test wiring).
/// </summary>
[TestClass]
internal sealed class SumcheckRoundComputationTests
{
    private static readonly ScalarAddDelegate Add = TestScalarBackends.Bls12Curve381.Add;
    private static readonly ScalarSubtractDelegate Subtract = TestScalarBackends.Bls12Curve381.Subtract;
    private static readonly ScalarMultiplyDelegate Multiply = TestScalarBackends.Bls12Curve381.Multiply;
    private static readonly BigInteger FieldOrder = Bls12Curve381BigIntegerScalarReference.FieldOrder;


    [TestMethod]
    public void OuterRoundPolynomialSatisfiesSumcheckClaimIdentity()
    {
        //g_i(X) := Σ_j eq_X(j) · (Az_X(j) · Bz_X(j) − Cz_X(j)).
        //The sumcheck claim identity says g_i(0) + g_i(1) equals the
        //sum of eq · (Az·Bz − Cz) over the full current hypercube.
        //
        //Build 2-variable MLEs by hand, pick concrete values, run
        //ComputeOuterRoundPolynomial, then check the identity.
        const int VariableCount = 2;
        int evaluationCount = 1 << VariableCount;
        int elementSize = Scalar.SizeBytes;

        BigInteger[] azValues = [new(3), new(5), new(7), new(11)];
        BigInteger[] bzValues = [new(2), new(4), new(6), new(8)];
        BigInteger[] czValues = [new(6), new(20), new(42), new(88)]; //matches az*bz for satisfaction.
        BigInteger[] eqValues = [new(1), new(3), new(5), new(9)];

        using IMemoryOwner<byte> azOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> bzOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> czOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> eqOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);

        Span<byte> az = azOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> bz = bzOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> cz = czOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> eq = eqOwner.Memory.Span[..(evaluationCount * elementSize)];
        WriteValues(azValues, az);
        WriteValues(bzValues, bz);
        WriteValues(czValues, cz);
        WriteValues(eqValues, eq);

        using Polynomial roundPoly = SumcheckRoundComputation.ComputeOuterRoundPolynomial(
            az, bz, cz, eq, VariableCount, Add, Subtract, Multiply, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        Assert.AreEqual(3, roundPoly.Degree, "Outer round polynomial should be degree 3.");

        //g_i(0) + g_i(1) should equal Σ_k eq[k] · (Az[k]·Bz[k] − Cz[k]).
        BigInteger expectedClaim = BigInteger.Zero;
        for(int k = 0; k < evaluationCount; k++)
        {
            BigInteger inner = (azValues[k] * bzValues[k]) % FieldOrder;
            inner = ((inner - czValues[k]) % FieldOrder + FieldOrder) % FieldOrder;
            BigInteger term = (eqValues[k] * inner) % FieldOrder;
            expectedClaim = (expectedClaim + term) % FieldOrder;
        }

        BigInteger g0 = EvaluatePolynomial(roundPoly, BigInteger.Zero);
        BigInteger g1 = EvaluatePolynomial(roundPoly, BigInteger.One);
        BigInteger sum = (g0 + g1) % FieldOrder;

        Assert.AreEqual(expectedClaim, sum, "g_i(0) + g_i(1) must equal the running sumcheck claim.");
    }


    [TestMethod]
    public void OuterRoundPolynomialEvaluatesCorrectlyAtArbitraryPoint()
    {
        //At any X, g_i(X) = Σ_j eq_X(j) · (Az_X(j) · Bz_X(j) − Cz_X(j))
        //where each P_X(j) = (1 − X)·P[2j] + X·P[2j+1].
        //Compare the polynomial's Horner evaluation against this
        //direct sum at a random-ish X.
        const int VariableCount = 3;
        int evaluationCount = 1 << VariableCount;
        int elementSize = Scalar.SizeBytes;

        BigInteger[] azValues = [new(2), new(5), new(7), new(11), new(13), new(17), new(19), new(23)];
        BigInteger[] bzValues = [new(3), new(6), new(8), new(12), new(14), new(18), new(20), new(24)];
        BigInteger[] czValues = [new(6), new(30), new(56), new(132), new(182), new(306), new(380), new(552)];
        BigInteger[] eqValues = [new(1), new(2), new(4), new(8), new(16), new(32), new(64), new(128)];

        using IMemoryOwner<byte> azOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> bzOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> czOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> eqOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);

        Span<byte> az = azOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> bz = bzOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> cz = czOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> eq = eqOwner.Memory.Span[..(evaluationCount * elementSize)];
        WriteValues(azValues, az);
        WriteValues(bzValues, bz);
        WriteValues(czValues, cz);
        WriteValues(eqValues, eq);

        using Polynomial roundPoly = SumcheckRoundComputation.ComputeOuterRoundPolynomial(
            az, bz, cz, eq, VariableCount, Add, Subtract, Multiply, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        //At X = 7 (random-ish small int), compute expected directly.
        BigInteger x = new(7);
        BigInteger expected = ComputeOuterRoundPolynomialDirect(azValues, bzValues, czValues, eqValues, x, VariableCount);
        BigInteger actual = EvaluatePolynomial(roundPoly, x);

        Assert.AreEqual(expected, actual, "g_i(7) must match the direct sum-of-products computation.");
    }


    [TestMethod]
    public void RelaxedOuterRoundReducesToStandardWhenUOneAndEZero()
    {
        //For u = 1 and E ≡ 0, the relaxed identity Az·Bz − u·Cz − E
        //is exactly the standard identity Az·Bz − Cz, so the relaxed
        //round polynomial must be byte-identical to the standard one.
        const int VariableCount = 3;
        int evaluationCount = 1 << VariableCount;
        int elementSize = Scalar.SizeBytes;

        BigInteger[] azValues = [new(2), new(5), new(7), new(11), new(13), new(17), new(19), new(23)];
        BigInteger[] bzValues = [new(3), new(6), new(8), new(12), new(14), new(18), new(20), new(24)];
        BigInteger[] czValues = [new(6), new(30), new(56), new(132), new(182), new(306), new(380), new(552)];
        BigInteger[] eqValues = [new(1), new(2), new(4), new(8), new(16), new(32), new(64), new(128)];

        using IMemoryOwner<byte> azOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> bzOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> czOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> eqOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> eOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> uOwner = SensitiveMemoryPool<byte>.Shared.Rent(elementSize);

        Span<byte> az = azOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> bz = bzOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> cz = czOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> eq = eqOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> e = eOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> u = uOwner.Memory.Span[..elementSize];
        WriteValues(azValues, az);
        WriteValues(bzValues, bz);
        WriteValues(czValues, cz);
        WriteValues(eqValues, eq);
        e.Clear();                 //E ≡ 0.
        WriteCanonical(BigInteger.One, u); //u = 1.

        using Polynomial standard = SumcheckRoundComputation.ComputeOuterRoundPolynomial(
            az, bz, cz, eq, VariableCount, Add, Subtract, Multiply, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);
        using Polynomial relaxed = SumcheckRoundComputation.ComputeOuterRoundPolynomialRelaxed(
            az, bz, cz, e, eq, u, VariableCount, Add, Subtract, Multiply, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        Assert.AreEqual(standard.Degree, relaxed.Degree);
        Assert.IsTrue(standard.AsReadOnlySpan().SequenceEqual(relaxed.AsReadOnlySpan()),
            "Relaxed round polynomial with u = 1, E = 0 must equal the standard round polynomial byte-for-byte.");
    }


    [TestMethod]
    public void RelaxedOuterRoundEvaluatesCorrectlyAtArbitraryPoint()
    {
        //With u ≠ 1 and E ≠ 0, compare the relaxed polynomial's Horner
        //evaluation at X = 7 against the direct sum
        //Σ_j eq_X(j) · (Az_X(j)·Bz_X(j) − u·Cz_X(j) − E_X(j)).
        const int VariableCount = 3;
        int evaluationCount = 1 << VariableCount;
        int elementSize = Scalar.SizeBytes;

        BigInteger[] azValues = [new(2), new(5), new(7), new(11), new(13), new(17), new(19), new(23)];
        BigInteger[] bzValues = [new(3), new(6), new(8), new(12), new(14), new(18), new(20), new(24)];
        BigInteger[] czValues = [new(9), new(31), new(57), new(133), new(183), new(307), new(381), new(553)];
        BigInteger[] eqValues = [new(1), new(2), new(4), new(8), new(16), new(32), new(64), new(128)];
        BigInteger[] eValues = [new(4), new(8), new(15), new(16), new(23), new(42), new(1), new(2)];
        BigInteger uValue = new(5);

        using IMemoryOwner<byte> azOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> bzOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> czOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> eqOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> eOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> uOwner = SensitiveMemoryPool<byte>.Shared.Rent(elementSize);

        Span<byte> az = azOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> bz = bzOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> cz = czOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> eq = eqOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> e = eOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> u = uOwner.Memory.Span[..elementSize];
        WriteValues(azValues, az);
        WriteValues(bzValues, bz);
        WriteValues(czValues, cz);
        WriteValues(eqValues, eq);
        WriteValues(eValues, e);
        WriteCanonical(uValue, u);

        using Polynomial roundPoly = SumcheckRoundComputation.ComputeOuterRoundPolynomialRelaxed(
            az, bz, cz, e, eq, u, VariableCount, Add, Subtract, Multiply, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        Assert.AreEqual(3, roundPoly.Degree);

        BigInteger x = new(7);
        BigInteger expected = ComputeRelaxedOuterRoundPolynomialDirect(
            azValues, bzValues, czValues, eValues, eqValues, uValue, x, VariableCount);
        BigInteger actual = EvaluatePolynomial(roundPoly, x);
        Assert.AreEqual(expected, actual, "Relaxed g_i(7) must match the direct sum-of-products computation.");
    }


    [TestMethod]
    public void RelaxedOuterRoundSatisfiesSumcheckClaimIdentity()
    {
        //g_i(0) + g_i(1) must equal Σ_k eq[k] · (Az[k]·Bz[k] − u·Cz[k] − E[k]).
        const int VariableCount = 2;
        int evaluationCount = 1 << VariableCount;
        int elementSize = Scalar.SizeBytes;

        BigInteger[] azValues = [new(3), new(5), new(7), new(11)];
        BigInteger[] bzValues = [new(2), new(4), new(6), new(8)];
        BigInteger[] czValues = [new(6), new(20), new(42), new(88)];
        BigInteger[] eqValues = [new(1), new(3), new(5), new(9)];
        BigInteger[] eValues = [new(2), new(7), new(1), new(5)];
        BigInteger uValue = new(3);

        using IMemoryOwner<byte> azOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> bzOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> czOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> eqOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> eOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> uOwner = SensitiveMemoryPool<byte>.Shared.Rent(elementSize);

        Span<byte> az = azOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> bz = bzOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> cz = czOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> eq = eqOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> e = eOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> u = uOwner.Memory.Span[..elementSize];
        WriteValues(azValues, az);
        WriteValues(bzValues, bz);
        WriteValues(czValues, cz);
        WriteValues(eqValues, eq);
        WriteValues(eValues, e);
        WriteCanonical(uValue, u);

        using Polynomial roundPoly = SumcheckRoundComputation.ComputeOuterRoundPolynomialRelaxed(
            az, bz, cz, e, eq, u, VariableCount, Add, Subtract, Multiply, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        BigInteger expectedClaim = BigInteger.Zero;
        for(int k = 0; k < evaluationCount; k++)
        {
            BigInteger prod = (azValues[k] * bzValues[k]) % FieldOrder;
            BigInteger uCz = (uValue * czValues[k]) % FieldOrder;
            BigInteger inner = ((prod - uCz - eValues[k]) % FieldOrder + FieldOrder) % FieldOrder;
            BigInteger term = (eqValues[k] * inner) % FieldOrder;
            expectedClaim = (expectedClaim + term) % FieldOrder;
        }

        BigInteger g0 = EvaluatePolynomial(roundPoly, BigInteger.Zero);
        BigInteger g1 = EvaluatePolynomial(roundPoly, BigInteger.One);
        BigInteger sum = (g0 + g1) % FieldOrder;
        Assert.AreEqual(expectedClaim, sum, "Relaxed g_i(0) + g_i(1) must equal the running relaxed sumcheck claim.");
    }


    [TestMethod]
    public void InnerRoundPolynomialSatisfiesSumcheckClaimIdentity()
    {
        //g_i(X) := Σ_j ABC_X(j) · z_X(j).
        //g_i(0) + g_i(1) = Σ_k ABC[k] · z[k].
        const int VariableCount = 2;
        int evaluationCount = 1 << VariableCount;
        int elementSize = Scalar.SizeBytes;

        BigInteger[] abcValues = [new(3), new(5), new(7), new(11)];
        BigInteger[] zValues = [new(2), new(4), new(6), new(8)];

        using IMemoryOwner<byte> abcOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> zOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        Span<byte> abc = abcOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> z = zOwner.Memory.Span[..(evaluationCount * elementSize)];
        WriteValues(abcValues, abc);
        WriteValues(zValues, z);

        using Polynomial roundPoly = SumcheckRoundComputation.ComputeInnerRoundPolynomial(
            abc, z, VariableCount, Add, Subtract, Multiply, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        Assert.AreEqual(2, roundPoly.Degree, "Inner round polynomial should be degree 2.");

        BigInteger expectedClaim = BigInteger.Zero;
        for(int k = 0; k < evaluationCount; k++)
        {
            BigInteger term = (abcValues[k] * zValues[k]) % FieldOrder;
            expectedClaim = (expectedClaim + term) % FieldOrder;
        }

        BigInteger g0 = EvaluatePolynomial(roundPoly, BigInteger.Zero);
        BigInteger g1 = EvaluatePolynomial(roundPoly, BigInteger.One);
        BigInteger sum = (g0 + g1) % FieldOrder;

        Assert.AreEqual(expectedClaim, sum, "g_i(0) + g_i(1) must equal the running sumcheck claim.");
    }


    [TestMethod]
    public void InnerRoundPolynomialEvaluatesCorrectlyAtArbitraryPoint()
    {
        const int VariableCount = 3;
        int evaluationCount = 1 << VariableCount;
        int elementSize = Scalar.SizeBytes;

        BigInteger[] abcValues = [new(3), new(7), new(11), new(13), new(17), new(19), new(23), new(29)];
        BigInteger[] zValues = [new(2), new(4), new(6), new(8), new(10), new(12), new(14), new(16)];

        using IMemoryOwner<byte> abcOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        using IMemoryOwner<byte> zOwner = SensitiveMemoryPool<byte>.Shared.Rent(evaluationCount * elementSize);
        Span<byte> abc = abcOwner.Memory.Span[..(evaluationCount * elementSize)];
        Span<byte> z = zOwner.Memory.Span[..(evaluationCount * elementSize)];
        WriteValues(abcValues, abc);
        WriteValues(zValues, z);

        using Polynomial roundPoly = SumcheckRoundComputation.ComputeInnerRoundPolynomial(
            abc, z, VariableCount, Add, Subtract, Multiply, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        BigInteger x = new(11);
        BigInteger expected = ComputeInnerRoundPolynomialDirect(abcValues, zValues, x, VariableCount);
        BigInteger actual = EvaluatePolynomial(roundPoly, x);

        Assert.AreEqual(expected, actual);
    }


    private static BigInteger ComputeOuterRoundPolynomialDirect(
        BigInteger[] az,
        BigInteger[] bz,
        BigInteger[] cz,
        BigInteger[] eq,
        BigInteger x,
        int variableCount)
    {
        int pairCount = 1 << (variableCount - 1);
        BigInteger total = BigInteger.Zero;
        for(int j = 0; j < pairCount; j++)
        {
            BigInteger azX = LinearInterpolate(az[2 * j], az[2 * j + 1], x);
            BigInteger bzX = LinearInterpolate(bz[2 * j], bz[2 * j + 1], x);
            BigInteger czX = LinearInterpolate(cz[2 * j], cz[2 * j + 1], x);
            BigInteger eqX = LinearInterpolate(eq[2 * j], eq[2 * j + 1], x);

            BigInteger inner = (azX * bzX) % FieldOrder;
            inner = ((inner - czX) % FieldOrder + FieldOrder) % FieldOrder;
            BigInteger term = (eqX * inner) % FieldOrder;
            total = (total + term) % FieldOrder;
        }

        return total;
    }


    private static BigInteger ComputeRelaxedOuterRoundPolynomialDirect(
        BigInteger[] az,
        BigInteger[] bz,
        BigInteger[] cz,
        BigInteger[] e,
        BigInteger[] eq,
        BigInteger u,
        BigInteger x,
        int variableCount)
    {
        int pairCount = 1 << (variableCount - 1);
        BigInteger total = BigInteger.Zero;
        for(int j = 0; j < pairCount; j++)
        {
            BigInteger azX = LinearInterpolate(az[2 * j], az[2 * j + 1], x);
            BigInteger bzX = LinearInterpolate(bz[2 * j], bz[2 * j + 1], x);
            BigInteger czX = LinearInterpolate(cz[2 * j], cz[2 * j + 1], x);
            BigInteger eX = LinearInterpolate(e[2 * j], e[2 * j + 1], x);
            BigInteger eqX = LinearInterpolate(eq[2 * j], eq[2 * j + 1], x);

            BigInteger prod = (azX * bzX) % FieldOrder;
            BigInteger uCz = (u * czX) % FieldOrder;
            BigInteger inner = ((prod - uCz - eX) % FieldOrder + FieldOrder) % FieldOrder;
            BigInteger term = (eqX * inner) % FieldOrder;
            total = (total + term) % FieldOrder;
        }

        return total;
    }


    private static BigInteger ComputeInnerRoundPolynomialDirect(
        BigInteger[] abc,
        BigInteger[] z,
        BigInteger x,
        int variableCount)
    {
        int pairCount = 1 << (variableCount - 1);
        BigInteger total = BigInteger.Zero;
        for(int j = 0; j < pairCount; j++)
        {
            BigInteger abcX = LinearInterpolate(abc[2 * j], abc[2 * j + 1], x);
            BigInteger zX = LinearInterpolate(z[2 * j], z[2 * j + 1], x);
            BigInteger term = (abcX * zX) % FieldOrder;
            total = (total + term) % FieldOrder;
        }

        return total;
    }


    private static BigInteger LinearInterpolate(BigInteger low, BigInteger high, BigInteger x)
    {
        //(1 - x) * low + x * high.
        BigInteger oneMinusX = ((BigInteger.One - x) % FieldOrder + FieldOrder) % FieldOrder;
        BigInteger left = (oneMinusX * low) % FieldOrder;
        BigInteger right = (x * high) % FieldOrder;
        return (left + right) % FieldOrder;
    }


    private static BigInteger EvaluatePolynomial(Polynomial polynomial, BigInteger x)
    {
        //Horner evaluation in BigInteger arithmetic.
        int elementSize = Scalar.SizeBytes;
        ReadOnlySpan<byte> coefficients = polynomial.AsReadOnlySpan();
        int degree = polynomial.Degree;

        BigInteger result = new(coefficients.Slice(degree * elementSize, elementSize), isUnsigned: true, isBigEndian: true);
        for(int k = degree - 1; k >= 0; k--)
        {
            BigInteger ck = new(coefficients.Slice(k * elementSize, elementSize), isUnsigned: true, isBigEndian: true);
            result = (result * x + ck) % FieldOrder;
        }

        return result;
    }


    private static void WriteValues(BigInteger[] values, Span<byte> destination)
    {
        int elementSize = Scalar.SizeBytes;
        destination.Clear();
        for(int i = 0; i < values.Length; i++)
        {
            WriteCanonical(values[i], destination.Slice(i * elementSize, elementSize));
        }
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Value did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}
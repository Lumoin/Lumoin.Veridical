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
/// Property tests for the <see cref="Polynomial"/> leaf type and its
/// BLS12-381 arithmetic extensions. Every test asserts an algebraic
/// identity against the BigInteger reference rather than a hand-computed
/// value.
/// </summary>
[TestClass]
internal sealed class PolynomialEvaluationTests
{
    private static readonly PolynomialEvaluateDelegate Evaluate = PolynomialBigIntegerReference.GetEvaluate();
    private static readonly PolynomialAddDelegate Add = PolynomialBigIntegerReference.GetAdd();
    private static readonly PolynomialMultiplyDelegate Multiply = PolynomialBigIntegerReference.GetMultiply();
    private static readonly ScalarReduceDelegate Reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

    private const long IterationCount = 30;


    [TestMethod]
    public void HornerEvaluationMatchesDirectSumForDegreeUpToEight()
    {
        //Compute f(x) two ways and assert equality: once via the polynomial
        //Evaluate (Horner) and once via an independent sum-of-c_i·x^i
        //computation built from the per-element scalar Add and Multiply
        //delegates. If the two disagree the bug is either in Horner or in
        //the cross-check; in practice the cross-check uses simpler
        //primitives, so disagreement points the finger at Horner.
        Gen.Int[0, 8]
            .SelectMany(degree => Gen.Select(
                Gen.Const(degree),
                Gen.Byte.Array[Scalar.SizeBytes * (degree + 1)],
                Gen.Byte.Array[Scalar.SizeBytes]))
            .Sample((degree, coefficientsRaw, pointRaw) =>
            {
                int elementSize = Scalar.SizeBytes;
                int totalCoefficientBytes = (degree + 1) * elementSize;

                using IMemoryOwner<byte> coefficientsOwner = BaseMemoryPool.Shared.Rent(totalCoefficientBytes);
                Span<byte> coefficients = coefficientsOwner.Memory.Span[..totalCoefficientBytes];
                ReduceSlots(coefficientsRaw, coefficients, elementSize);

                using IMemoryOwner<byte> pointBytesOwner = BaseMemoryPool.Shared.Rent(elementSize);
                Span<byte> pointBytes = pointBytesOwner.Memory.Span[..elementSize];
                Reduce(pointRaw, pointBytes, CurveParameterSet.Bls12Curve381);

                using Polynomial polynomial = Polynomial.FromCoefficients(coefficients, degree, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
                using Scalar point = Scalar.FromCanonical(pointBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
                using Scalar hornerResult = polynomial.Evaluate(point, Evaluate, BaseMemoryPool.Shared);

                BigInteger fieldOrder = Bls12Curve381BigIntegerScalarReference.FieldOrder;
                BigInteger x = new(pointBytes, isUnsigned: true, isBigEndian: true);
                BigInteger expected = BigInteger.Zero;
                BigInteger xPower = BigInteger.One;
                for(int k = 0; k <= degree; k++)
                {
                    BigInteger coefficient = new(coefficients.Slice(k * elementSize, elementSize), isUnsigned: true, isBigEndian: true);
                    expected = (expected + (coefficient * xPower)) % fieldOrder;
                    xPower = (xPower * x) % fieldOrder;
                }

                BigInteger hornerValue = new(hornerResult.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
                return hornerValue == expected;
            }, iter: IterationCount);
    }


    [TestMethod]
    public void EvaluationAtZeroIsConstantTerm()
    {
        const int Degree = 5;
        int elementSize = Scalar.SizeBytes;

        using IMemoryOwner<byte> coefficientsOwner = BaseMemoryPool.Shared.Rent((Degree + 1) * elementSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..((Degree + 1) * elementSize)];
        BigInteger[] values = [new(7), new(13), new(29), new(41), new(53), new(97)];
        for(int k = 0; k <= Degree; k++)
        {
            WriteCanonical(values[k], coefficients.Slice(k * elementSize, elementSize));
        }

        using Polynomial polynomial = Polynomial.FromCoefficients(coefficients, Degree, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using Scalar zero = MakeScalarFromInt(0);
        using Scalar result = polynomial.Evaluate(zero, Evaluate, BaseMemoryPool.Shared);

        BigInteger resultValue = new(result.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
        Assert.AreEqual(values[0], resultValue, "p(0) should equal the constant term c_0.");
    }


    [TestMethod]
    public void EvaluationAtOneIsCoefficientSum()
    {
        const int Degree = 4;
        int elementSize = Scalar.SizeBytes;
        BigInteger[] values = [new(3), new(11), new(31), new(71), new(89)];
        BigInteger fieldOrder = Bls12Curve381BigIntegerScalarReference.FieldOrder;

        using IMemoryOwner<byte> coefficientsOwner = BaseMemoryPool.Shared.Rent((Degree + 1) * elementSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..((Degree + 1) * elementSize)];
        BigInteger expectedSum = BigInteger.Zero;
        for(int k = 0; k <= Degree; k++)
        {
            WriteCanonical(values[k], coefficients.Slice(k * elementSize, elementSize));
            expectedSum = (expectedSum + values[k]) % fieldOrder;
        }

        using Polynomial polynomial = Polynomial.FromCoefficients(coefficients, Degree, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using Scalar one = MakeScalarFromInt(1);
        using Scalar result = polynomial.Evaluate(one, Evaluate, BaseMemoryPool.Shared);

        BigInteger resultValue = new(result.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
        Assert.AreEqual(expectedSum, resultValue, "p(1) should equal the sum of all coefficients.");
    }


    [TestMethod]
    public void AdditionIsCommutativeForRandomInputs()
    {
        Gen.Int[0, 8]
            .SelectMany(degree => Gen.Select(
                Gen.Const(degree),
                Gen.Byte.Array[Scalar.SizeBytes * (degree + 1)],
                Gen.Byte.Array[Scalar.SizeBytes * (degree + 1)]))
            .Sample((degree, aRaw, bRaw) =>
            {
                int elementSize = Scalar.SizeBytes;
                int total = (degree + 1) * elementSize;

                using IMemoryOwner<byte> aOwner = BaseMemoryPool.Shared.Rent(total);
                using IMemoryOwner<byte> bOwner = BaseMemoryPool.Shared.Rent(total);
                Span<byte> aCoeffs = aOwner.Memory.Span[..total];
                Span<byte> bCoeffs = bOwner.Memory.Span[..total];
                ReduceSlots(aRaw, aCoeffs, elementSize);
                ReduceSlots(bRaw, bCoeffs, elementSize);

                using Polynomial a = Polynomial.FromCoefficients(aCoeffs, degree, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
                using Polynomial b = Polynomial.FromCoefficients(bCoeffs, degree, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

                using Polynomial sumAb = a.Add(b, Add, BaseMemoryPool.Shared);
                using Polynomial sumBa = b.Add(a, Add, BaseMemoryPool.Shared);

                return sumAb.AsReadOnlySpan().SequenceEqual(sumBa.AsReadOnlySpan());
            }, iter: IterationCount);
    }


    [TestMethod]
    public void MultiplicationByZeroIsZero()
    {
        const int Degree = 3;
        int elementSize = Scalar.SizeBytes;
        BigInteger[] values = [new(7), new(11), new(13), new(17)];

        using IMemoryOwner<byte> coefficientsOwner = BaseMemoryPool.Shared.Rent((Degree + 1) * elementSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..((Degree + 1) * elementSize)];
        for(int k = 0; k <= Degree; k++)
        {
            WriteCanonical(values[k], coefficients.Slice(k * elementSize, elementSize));
        }

        using Polynomial p = Polynomial.FromCoefficients(coefficients, Degree, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using Polynomial zero = Polynomial.Zero(Degree, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using Polynomial product = p.Multiply(zero, Multiply, BaseMemoryPool.Shared);

        Assert.IsTrue(product.IsZero, "Product of p · 0 should be the zero polynomial.");
        Assert.AreEqual(Degree + Degree, product.Degree, "Storage degree of the product should equal the sum of the operands' storage degrees.");
    }


    [TestMethod]
    public void StorageDegreeAfterMultiplicationEqualsSum()
    {
        //Choose polynomials with non-zero leading coefficients so the
        //product's algebraic degree equals the storage degree.
        int elementSize = Scalar.SizeBytes;

        using IMemoryOwner<byte> aOwner = BaseMemoryPool.Shared.Rent(3 * elementSize);
        Span<byte> aCoeffs = aOwner.Memory.Span[..(3 * elementSize)];
        WriteCanonical(new(1), aCoeffs.Slice(0, elementSize));
        WriteCanonical(new(2), aCoeffs.Slice(elementSize, elementSize));
        WriteCanonical(new(3), aCoeffs.Slice(2 * elementSize, elementSize));

        using IMemoryOwner<byte> bOwner = BaseMemoryPool.Shared.Rent(2 * elementSize);
        Span<byte> bCoeffs = bOwner.Memory.Span[..(2 * elementSize)];
        WriteCanonical(new(4), bCoeffs.Slice(0, elementSize));
        WriteCanonical(new(5), bCoeffs.Slice(elementSize, elementSize));

        using Polynomial a = Polynomial.FromCoefficients(aCoeffs, 2, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using Polynomial b = Polynomial.FromCoefficients(bCoeffs, 1, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        using Polynomial product = a.Multiply(b, Multiply, BaseMemoryPool.Shared);

        Assert.AreEqual(3, product.Degree, "(2 + 1) = 3 storage degree expected.");

        //(3x^2 + 2x + 1) * (5x + 4) = 15x^3 + 12x^2 + 10x^2 + 8x + 5x + 4
        //                            = 15x^3 + 22x^2 + 13x + 4.
        BigInteger[] expected = [new(4), new(13), new(22), new(15)];
        for(int k = 0; k <= 3; k++)
        {
            ReadOnlySpan<byte> slot = product.AsReadOnlySpan().Slice(k * elementSize, elementSize);
            BigInteger actual = new(slot, isUnsigned: true, isBigEndian: true);
            Assert.AreEqual(expected[k], actual, $"Product coefficient {k} should equal {expected[k]}.");
        }
    }


    private static Scalar MakeScalarFromInt(int value)
    {
        using IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(Scalar.SizeBytes);
        Span<byte> span = owner.Memory.Span[..Scalar.SizeBytes];
        WriteCanonical(new BigInteger(value), span);
        return Scalar.FromCanonical(span, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    private static void ReduceSlots(byte[] rawSource, Span<byte> destination, int elementSize)
    {
        int slotCount = destination.Length / elementSize;
        for(int i = 0; i < slotCount; i++)
        {
            Reduce(
                rawSource.AsSpan(i * elementSize, elementSize),
                destination.Slice(i * elementSize, elementSize),
                CurveParameterSet.Bls12Curve381);
        }
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger nonNegative = ((value % Bls12Curve381BigIntegerScalarReference.FieldOrder) + Bls12Curve381BigIntegerScalarReference.FieldOrder) % Bls12Curve381BigIntegerScalarReference.FieldOrder;
        if(!nonNegative.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
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
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Diagnostics;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Diagnostics;

/// <summary>
/// Tests for the verbose <see cref="PolynomialInspector"/>. Each test
/// constructs a polynomial with known shape and asserts the bundled
/// report reflects every field.
/// </summary>
[TestClass]
internal sealed class PolynomialInspectorTests
{
    [TestMethod]
    public void InspectingZeroPolynomialReportsIsZeroIsConstantNotIsLinear()
    {
        using Polynomial zero = Polynomial.Zero(0, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        PolynomialReport report = PolynomialInspector.Inspect(zero);

        Assert.AreEqual(0, report.Degree);
        Assert.AreEqual(Scalar.SizeBytes, report.FieldElementSizeBytes);
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, report.Curve);
        Assert.IsTrue(report.IsZero);
        Assert.IsTrue(report.IsConstant, "Zero is a constant polynomial.");
        Assert.IsFalse(report.IsLinear, "Storage degree zero is not linear.");
    }


    [TestMethod]
    public void InspectingConstantPolynomialReportsIsConstantButNotIsZero()
    {
        int elementSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> constantOwner = SensitiveMemoryPool<byte>.Shared.Rent(elementSize);
        Span<byte> constantBytes = constantOwner.Memory.Span[..elementSize];
        WriteCanonical(new(42), constantBytes);

        using Polynomial constant = Polynomial.Constant(constantBytes, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        PolynomialReport report = PolynomialInspector.Inspect(constant);

        Assert.AreEqual(0, report.Degree);
        Assert.IsFalse(report.IsZero);
        Assert.IsTrue(report.IsConstant);
        Assert.IsFalse(report.IsLinear);
    }


    [TestMethod]
    public void InspectingLinearPolynomialReportsIsLinear()
    {
        int elementSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> coefficientsOwner = SensitiveMemoryPool<byte>.Shared.Rent(2 * elementSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..(2 * elementSize)];
        WriteCanonical(new(7), coefficients.Slice(0, elementSize));
        WriteCanonical(new(11), coefficients.Slice(elementSize, elementSize));

        using Polynomial linear = Polynomial.FromCoefficients(coefficients, 1, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        PolynomialReport report = PolynomialInspector.Inspect(linear);

        Assert.AreEqual(1, report.Degree);
        Assert.IsTrue(report.IsLinear);
        Assert.IsFalse(report.IsConstant, "Linear polynomial with non-zero slope is not constant.");
        Assert.IsFalse(report.IsZero);
    }


    [TestMethod]
    public void InspectingPolynomialWithZeroLeadingCoefficientsReportsIsConstantWhenAllHighCoefficientsZero()
    {
        //Storage degree 3 polynomial whose coefficients [c_0, 0, 0, 0] →
        //is algebraically constant (only c_0 non-zero) even though storage
        //degree is 3.
        int elementSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> coefficientsOwner = SensitiveMemoryPool<byte>.Shared.Rent(4 * elementSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..(4 * elementSize)];
        coefficients.Clear();
        WriteCanonical(new(99), coefficients.Slice(0, elementSize));

        using Polynomial p = Polynomial.FromCoefficients(coefficients, 3, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        PolynomialReport report = PolynomialInspector.Inspect(p);

        Assert.AreEqual(3, report.Degree);
        Assert.IsTrue(report.IsConstant, "Polynomial with only c_0 non-zero is algebraically constant.");
        Assert.IsFalse(report.IsLinear, "Storage degree 3 is not linear.");
    }


    [TestMethod]
    public void HexSnippetTruncatesAt17Coefficients()
    {
        const int Degree = 20;
        int elementSize = Scalar.SizeBytes;
        using IMemoryOwner<byte> coefficientsOwner = SensitiveMemoryPool<byte>.Shared.Rent((Degree + 1) * elementSize);
        Span<byte> coefficients = coefficientsOwner.Memory.Span[..((Degree + 1) * elementSize)];
        for(int k = 0; k <= Degree; k++)
        {
            WriteCanonical(new(k + 1), coefficients.Slice(k * elementSize, elementSize));
        }

        using Polynomial p = Polynomial.FromCoefficients(coefficients, Degree, CurveParameterSet.Bls12Curve381, SensitiveMemoryPool<byte>.Shared);

        PolynomialReport report = PolynomialInspector.Inspect(p);

        Assert.AreEqual(17, report.CoefficientsRendered);
        //17 coefficients × 32 bytes × 2 hex chars/byte = 1088 chars.
        Assert.AreEqual(1088, report.CoefficientsHex.Length);
    }


    [TestMethod]
    public void InspectThrowsOnNullPolynomial()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => PolynomialInspector.Inspect(null!));
    }


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger r = Bls12Curve381BigIntegerScalarReference.FieldOrder;
        BigInteger nonNegative = ((value % r) + r) % r;
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
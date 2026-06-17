using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Reference implementation of the BLS12-381 univariate-polynomial
/// delegates using <see cref="BigInteger"/> arithmetic modulo the
/// scalar field order <c>r</c>. Serves as ground truth.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="GetEvaluate"/> runs Horner's scheme high-to-low.
/// <see cref="GetAdd"/> walks both coefficient buffers and writes the
/// reduced sum. <see cref="GetMultiply"/> runs the schoolbook
/// <c>O((aDegree + 1)·(bDegree + 1))</c> convolution. Operation
/// counters are bumped at the entry of each delegate so telemetry
/// surfaces see the polynomial-layer cost.
/// </para>
/// </remarks>
internal static class PolynomialBigIntegerReference
{
    private static readonly BigInteger FieldOrder = Bls12Curve381BigIntegerScalarReference.FieldOrder;


    /// <summary>Returns the reference polynomial-evaluate delegate.</summary>
    public static PolynomialEvaluateDelegate GetEvaluate() => Evaluate;

    /// <summary>Returns the reference polynomial-add delegate.</summary>
    public static PolynomialAddDelegate GetAdd() => Add;

    /// <summary>Returns the reference polynomial-multiply delegate.</summary>
    public static PolynomialMultiplyDelegate GetMultiply() => Multiply;


    private static void Evaluate(
        ReadOnlySpan<byte> coefficients,
        ReadOnlySpan<byte> point,
        Span<byte> result,
        int degree,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.PolynomialEvaluate, curve);

        int elementSize = Scalar.SizeBytes;
        ValidatePolynomialBuffer(coefficients, degree, nameof(coefficients), elementSize);
        ValidateSlot(point, elementSize, nameof(point));
        ValidateSlot(result, elementSize, nameof(result));

        BigInteger x = new(point, isUnsigned: true, isBigEndian: true);

        //Horner high-to-low. acc starts at the leading coefficient.
        BigInteger acc = new(coefficients.Slice(degree * elementSize, elementSize), isUnsigned: true, isBigEndian: true);
        for(int k = degree - 1; k >= 0; k--)
        {
            BigInteger coefficient = new(coefficients.Slice(k * elementSize, elementSize), isUnsigned: true, isBigEndian: true);
            acc = ((acc * x) + coefficient) % FieldOrder;
        }

        WriteCanonical(acc, result);
    }


    private static void Add(
        ReadOnlySpan<byte> a,
        ReadOnlySpan<byte> b,
        Span<byte> result,
        int degree,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.PolynomialAdd, curve);

        int elementSize = Scalar.SizeBytes;
        ValidatePolynomialBuffer(a, degree, nameof(a), elementSize);
        ValidatePolynomialBuffer(b, degree, nameof(b), elementSize);
        ValidatePolynomialBuffer(result, degree, nameof(result), elementSize);

        for(int k = 0; k <= degree; k++)
        {
            BigInteger left = new(a.Slice(k * elementSize, elementSize), isUnsigned: true, isBigEndian: true);
            BigInteger right = new(b.Slice(k * elementSize, elementSize), isUnsigned: true, isBigEndian: true);
            BigInteger sum = (left + right) % FieldOrder;
            WriteCanonical(sum, result.Slice(k * elementSize, elementSize));
        }
    }


    private static void Multiply(
        ReadOnlySpan<byte> a,
        int aDegree,
        ReadOnlySpan<byte> b,
        int bDegree,
        Span<byte> result,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.PolynomialMultiply, curve);

        int elementSize = Scalar.SizeBytes;
        ValidatePolynomialBuffer(a, aDegree, nameof(a), elementSize);
        ValidatePolynomialBuffer(b, bDegree, nameof(b), elementSize);
        int productDegree = aDegree + bDegree;
        ValidatePolynomialBuffer(result, productDegree, nameof(result), elementSize);

        //Schoolbook convolution. Accumulate per output coefficient k:
        //  result[k] = sum_{i+j=k} a[i] * b[j] mod r.
        BigInteger[] accumulators = new BigInteger[productDegree + 1];
        for(int i = 0; i <= aDegree; i++)
        {
            BigInteger ai = new(a.Slice(i * elementSize, elementSize), isUnsigned: true, isBigEndian: true);
            for(int j = 0; j <= bDegree; j++)
            {
                BigInteger bj = new(b.Slice(j * elementSize, elementSize), isUnsigned: true, isBigEndian: true);
                accumulators[i + j] = (accumulators[i + j] + (ai * bj)) % FieldOrder;
            }
        }

        for(int k = 0; k <= productDegree; k++)
        {
            WriteCanonical(accumulators[k], result.Slice(k * elementSize, elementSize));
        }
    }


    private static void ValidatePolynomialBuffer(ReadOnlySpan<byte> buffer, int degree, string paramName, int elementSize)
    {
        if(degree < 0)
        {
            throw new ArgumentException(
                $"Polynomial degree must be non-negative; received {degree}.",
                paramName);
        }

        int expected = (degree + 1) * elementSize;
        if(buffer.Length != expected)
        {
            throw new ArgumentException(
                $"Polynomial buffer '{paramName}' must be {expected} bytes for degree {degree}; received {buffer.Length}.",
                paramName);
        }
    }


    private static void ValidatePolynomialBuffer(Span<byte> buffer, int degree, string paramName, int elementSize) =>
        ValidatePolynomialBuffer((ReadOnlySpan<byte>)buffer, degree, paramName, elementSize);


    private static void ValidateSlot(ReadOnlySpan<byte> slot, int elementSize, string paramName)
    {
        if(slot.Length != elementSize)
        {
            throw new ArgumentException(
                $"'{paramName}' must be {elementSize} bytes; received {slot.Length}.",
                paramName);
        }
    }


    private static void ValidateSlot(Span<byte> slot, int elementSize, string paramName) =>
        ValidateSlot((ReadOnlySpan<byte>)slot, elementSize, paramName);


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
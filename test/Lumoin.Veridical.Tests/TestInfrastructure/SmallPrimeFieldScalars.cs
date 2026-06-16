using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// A tiny prime field for exercising field-generic algorithms (the Reed–Solomon
/// encoder, the Ligero argument) with cheap, hand-checkable vectors before
/// running them over the full 256-bit curve fields. Arithmetic is modulo the
/// Mersenne prime <c>2³¹ − 1 = 2147483647</c>, on the shared canonical 32-byte
/// big-endian layout so the same <see cref="ScalarAddDelegate"/> family applies
/// unchanged.
/// </summary>
/// <remarks>
/// <para>
/// This is not a curve: it carries no <see cref="CurveParameterSet"/> identity,
/// and the delegates ignore the <c>curve</c> argument (callers pass
/// <see cref="CurveParameterSet.None"/>). It exists only so a generic algorithm
/// can be validated over a field small enough that a polynomial's evaluations
/// can be checked against a direct BigInteger computation.
/// </para>
/// <para>
/// <c>2³¹ − 1</c> is prime (the eighth Mersenne prime), so Fermat inversion
/// <c>a^(p−2)</c> is valid; it is comfortably larger than any node or column
/// index used in the tests, so the integer domain points embed without
/// reduction.
/// </para>
/// </remarks>
internal static class SmallPrimeFieldScalars
{
    /// <summary>The field modulus <c>2³¹ − 1 = 2147483647</c> (the eighth Mersenne prime).</summary>
    public static BigInteger FieldOrder { get; } = BigInteger.Parse(
        "2147483647",
        NumberStyles.Integer,
        CultureInfo.InvariantCulture);


    /// <summary>Returns the scalar-add delegate (modulo <c>2³¹ − 1</c>).</summary>
    public static ScalarAddDelegate GetAdd() => Add;

    /// <summary>Returns the scalar-subtract delegate.</summary>
    public static ScalarSubtractDelegate GetSubtract() => Subtract;

    /// <summary>Returns the scalar-multiply delegate.</summary>
    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    /// <summary>Returns the scalar-negate delegate.</summary>
    public static ScalarNegateDelegate GetNegate() => Negate;

    /// <summary>Returns the scalar-invert delegate (Fermat <c>a^(p−2)</c>).</summary>
    public static ScalarInvertDelegate GetInvert() => Invert;

    /// <summary>Returns the scalar-reduce delegate.</summary>
    public static ScalarReduceDelegate GetReduce() => Reduce;


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve) =>
        WriteCanonical((ReadCanonical(a) + ReadCanonical(b)) % FieldOrder, result);


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve) =>
        WriteCanonical((((ReadCanonical(a) - ReadCanonical(b)) % FieldOrder) + FieldOrder) % FieldOrder, result);


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve) =>
        WriteCanonical((ReadCanonical(a) * ReadCanonical(b)) % FieldOrder, result);


    private static void Negate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        BigInteger value = ReadCanonical(a);
        WriteCanonical(value.IsZero ? BigInteger.Zero : FieldOrder - value, result);
    }


    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        BigInteger value = ReadCanonical(a);
        if(value.IsZero)
        {
            throw new InvalidOperationException("Zero is not invertible in the small prime field.");
        }

        WriteCanonical(BigInteger.ModPow(value, FieldOrder - 2, FieldOrder), result);
    }


    private static void Reduce(ReadOnlySpan<byte> input, Span<byte> result, CurveParameterSet curve) =>
        WriteCanonical(ReadCanonical(input) % FieldOrder, result);


    private static BigInteger ReadCanonical(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced value did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}

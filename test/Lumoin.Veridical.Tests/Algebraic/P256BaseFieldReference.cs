using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The P-256 <em>base</em> field <c>Fp</c> (the field the curve's point
/// coordinates live in) exposed as the canonical scalar-delegate surface, so a
/// field-generic argument — the Ligero constraint argument / Reed–Solomon
/// encoder — can run natively over <c>Fp256</c>. This is the field Longfellow's
/// ECDSA verification circuit operates in (the sumcheck field is chosen to equal
/// the curve base field), distinct from the P-256 <em>scalar</em> field
/// <c>Fn</c> exposed by <see cref="P256BigIntegerScalarReference"/>.
/// </summary>
/// <remarks>
/// <para>
/// Arithmetic is modulo the base-field prime
/// <see cref="P256BigIntegerG1Reference.BaseFieldPrime"/>
/// (<c>p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1</c>) on the shared canonical 32-byte
/// big-endian layout, so the same <see cref="ScalarAddDelegate"/> family applies
/// unchanged. <c>p</c> is prime, so Fermat inversion <c>a^(p−2)</c> is valid.
/// </para>
/// <para>
/// A correctness-first BigInteger reference oracle (test-only); it carries no
/// curve identity and ignores the <c>curve</c> argument, so callers pass
/// <see cref="CurveParameterSet.None"/>. It pairs with the NTT-free barycentric
/// Reed–Solomon encoder, which needs only these field operations, to give a
/// slow-but-correct way to iterate on Fp256 circuits before any optimized
/// encoder exists.
/// </para>
/// </remarks>
internal static class P256BaseFieldReference
{
    /// <summary>The base-field prime <c>p</c> the coordinates and this field's arithmetic are modulo.</summary>
    public static BigInteger FieldOrder { get; } = P256BigIntegerG1Reference.BaseFieldPrime;


    /// <summary>Returns the scalar-add delegate (modulo <c>p</c>).</summary>
    public static ScalarAddDelegate GetAdd() => Add;

    /// <summary>Returns the scalar-subtract delegate.</summary>
    public static ScalarSubtractDelegate GetSubtract() => Subtract;

    /// <summary>Returns the scalar-multiply delegate.</summary>
    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    /// <summary>Returns the scalar-negate delegate.</summary>
    public static ScalarNegateDelegate GetNegate() => Negate;

    /// <summary>Returns the scalar-invert delegate (Fermat <c>a^(p−2)</c>).</summary>
    public static ScalarInvertDelegate GetInvert() => Invert;

    /// <summary>Returns the scalar-reduce delegate (maps wide bytes to a canonical residue).</summary>
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
            throw new InvalidOperationException("Zero is not invertible in the P-256 base field.");
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

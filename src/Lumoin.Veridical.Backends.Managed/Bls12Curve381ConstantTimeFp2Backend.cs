using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Constant-time arithmetic for the BLS12-381 quadratic extension field
/// <c>Fp2 = Fp[u]/(u² + 1)</c>, exposed as the canonical <see cref="ScalarAddDelegate"/>
/// family over 96-byte elements laid out as <c>[c0 : 48 BE][c1 : 48 BE]</c> — the same
/// element layout as <see cref="Bls12Curve381BigIntegerFp2Reference"/>, which is the
/// agreement oracle. Every component operation runs on the constant-time base field
/// <see cref="Bls12Curve381BaseFieldMontgomeryBackend"/>, and every composite operation
/// is a fixed sequence of those component operations, so at base-field granularity the
/// operation sequence never depends on the operand values.
/// </summary>
/// <remarks>
/// <para>
/// Multiplication is schoolbook — <c>(a0·b0 − a1·b1, a0·b1 + a1·b0)</c>, four base-field
/// multiplications — rather than three-multiplication Karatsuba: correctness-first, and
/// the fixed four-multiply sequence keeps the composition trivially uniform. Inversion
/// uses the norm: <c>(a0 + a1·u)⁻¹ = (a0 − a1·u)/(a0² + a1²)</c>, one base-field Fermat
/// inversion over the public exponent <c>p − 2</c>. The norm <c>a0² + a1²</c> is zero
/// only for the zero element (<c>−1</c> is a non-residue mod <c>p ≡ 3 mod 4</c>), so the
/// zero guard is exact. The <c>curve</c> argument is ignored; callers pass
/// <see cref="CurveParameterSet.None"/>.
/// </para>
/// <para>
/// Delegate targets are alias-safe for whole-element aliasing — a result span that IS one
/// of the operand spans, the only overlap the ladder's in-place variable reuse produces:
/// under identity aliasing every component read of the operand memory a component write
/// overlaps happens before that write. A partially offset overlap (a result starting
/// mid-operand) is outside the contract.
/// </para>
/// </remarks>
internal static class Bls12Curve381ConstantTimeFp2Backend
{
    private const int ComponentSize = Bls12Curve381BaseFieldMontgomeryBackend.ElementSize;

    /// <summary>The canonical byte length of one Fp2 element: two 48-byte components.</summary>
    internal const int ElementSize = 2 * ComponentSize;

    private static ScalarAddDelegate ComponentAdd { get; } = Bls12Curve381BaseFieldMontgomeryBackend.GetAdd();
    private static ScalarSubtractDelegate ComponentSubtract { get; } = Bls12Curve381BaseFieldMontgomeryBackend.GetSubtract();
    private static ScalarMultiplyDelegate ComponentMultiply { get; } = Bls12Curve381BaseFieldMontgomeryBackend.GetMultiply();
    private static ScalarInvertDelegate ComponentInvert { get; } = Bls12Curve381BaseFieldMontgomeryBackend.GetInvert();

    private static byte[] ComponentZero { get; } = new byte[ComponentSize];


    public static ScalarAddDelegate GetAdd() => Add;

    public static ScalarSubtractDelegate GetSubtract() => Subtract;

    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    public static ScalarInvertDelegate GetInvert() => Invert;


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        ComponentAdd(a[..ComponentSize], b[..ComponentSize], result[..ComponentSize], CurveParameterSet.None);
        ComponentAdd(a[ComponentSize..ElementSize], b[ComponentSize..ElementSize], result[ComponentSize..ElementSize], CurveParameterSet.None);
    }


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        ComponentSubtract(a[..ComponentSize], b[..ComponentSize], result[..ComponentSize], CurveParameterSet.None);
        ComponentSubtract(a[ComponentSize..ElementSize], b[ComponentSize..ElementSize], result[ComponentSize..ElementSize], CurveParameterSet.None);
    }


    /// <summary>
    /// (a0 + a1·u)(b0 + b1·u) = (a0·b0 − a1·b1) + (a0·b1 + a1·b0)·u, using u² = −1. All four products
    /// land in scratch before anything is written to result, so result may alias either operand.
    /// </summary>
    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        ReadOnlySpan<byte> a0 = a[..ComponentSize];
        ReadOnlySpan<byte> a1 = a[ComponentSize..ElementSize];
        ReadOnlySpan<byte> b0 = b[..ComponentSize];
        ReadOnlySpan<byte> b1 = b[ComponentSize..ElementSize];

        Span<byte> product00 = stackalloc byte[ComponentSize];
        Span<byte> product11 = stackalloc byte[ComponentSize];
        Span<byte> product01 = stackalloc byte[ComponentSize];
        Span<byte> product10 = stackalloc byte[ComponentSize];
        ComponentMultiply(a0, b0, product00, CurveParameterSet.None);
        ComponentMultiply(a1, b1, product11, CurveParameterSet.None);
        ComponentMultiply(a0, b1, product01, CurveParameterSet.None);
        ComponentMultiply(a1, b0, product10, CurveParameterSet.None);

        ComponentSubtract(product00, product11, result[..ComponentSize], CurveParameterSet.None);
        ComponentAdd(product01, product10, result[ComponentSize..ElementSize], CurveParameterSet.None);
    }


    /// <summary>
    /// (a0 + a1·u)⁻¹ = (a0 − a1·u)/(a0² + a1²): two squarings and an addition form the norm, one
    /// base-field Fermat inversion over the public exponent p − 2 inverts it, and two multiplications
    /// plus a subtraction from zero produce the components. The scaled components land in scratch
    /// before anything is written to result, so result may alias the operand.
    /// </summary>
    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        ReadOnlySpan<byte> a0 = a[..ComponentSize];
        ReadOnlySpan<byte> a1 = a[ComponentSize..ElementSize];

        Span<byte> norm = stackalloc byte[ComponentSize];
        Span<byte> scratch = stackalloc byte[ComponentSize];
        ComponentMultiply(a0, a0, norm, CurveParameterSet.None);
        ComponentMultiply(a1, a1, scratch, CurveParameterSet.None);
        ComponentAdd(norm, scratch, norm, CurveParameterSet.None);
        if(IsZeroComponent(norm))
        {
            throw new InvalidOperationException("Zero is not invertible in the BLS12-381 Fp2 extension field.");
        }

        Span<byte> normInverse = stackalloc byte[ComponentSize];
        ComponentInvert(norm, normInverse, CurveParameterSet.None);

        Span<byte> scaled0 = stackalloc byte[ComponentSize];
        Span<byte> scaled1 = stackalloc byte[ComponentSize];
        ComponentMultiply(a0, normInverse, scaled0, CurveParameterSet.None);
        ComponentMultiply(a1, normInverse, scaled1, CurveParameterSet.None);

        scaled0.CopyTo(result[..ComponentSize]);
        ComponentSubtract(ComponentZero, scaled1, result[ComponentSize..ElementSize], CurveParameterSet.None);
    }


    private static bool IsZeroComponent(ReadOnlySpan<byte> value)
    {
        int accumulated = 0;
        for(int i = 0; i < ComponentSize; i++)
        {
            accumulated |= value[i];
        }

        return accumulated == 0;
    }
}

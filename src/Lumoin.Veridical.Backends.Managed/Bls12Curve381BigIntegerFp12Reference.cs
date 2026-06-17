using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Reference implementation of the BLS12-381 Fp12 quadratic
/// extension-field delegates using <see cref="BigInteger"/> arithmetic
/// over Fp6 element pairs. Serves as ground truth for cross-
/// implementation tests at the pairing target field.
/// </summary>
/// <remarks>
/// <para>
/// Fp12 is represented as <c>c0 + c1·w</c> with <c>w² = v</c>, where
/// <c>v</c> is the Fp6 indeterminate (and <c>v³ = ξ = 1 + u</c>).
/// Multiplication uses the schoolbook formula:
/// </para>
/// <para>
/// <c>(a0 + a1·w)(b0 + b1·w) = (a0·b0 + v·(a1·b1)) + (a0·b1 + a1·b0)·w</c>
/// </para>
/// <para>
/// where the <c>v·(·)</c> step is
/// <see cref="Bls12Curve381BigIntegerFp6Reference.Fp6MulByV"/>.
/// </para>
/// <para>
/// Inversion uses the closed-form quadratic-extension inverse:
/// <c>N(a) = a·ā = c0² − v·c1² ∈ Fp6</c> (with <c>ā = c0 − c1·w</c>),
/// invert in Fp6, then <c>a^(-1) = (c0·N^(-1)) − (c1·N^(-1))·w</c>.
/// </para>
/// <para>
/// Conjugation sends <c>w ↦ −w</c>, i.e. negates the <c>c1</c> Fp6
/// component. Inside the cyclotomic subgroup of <c>Fp12*</c> this
/// equals inversion; outside it does not, so the property tests below
/// use the algebraic-homomorphism identity <c>conj(a·b) = conj(a)·conj(b)</c>
/// rather than <c>a·conj(a) = 1</c>.
/// </para>
/// <para>
/// Byte layout: <c>[c0 : 288 bytes][c1 : 288 bytes]</c>, each component
/// a canonical Fp6 element.
/// </para>
/// </remarks>
internal static class Bls12Curve381BigIntegerFp12Reference
{
    private const int ComponentSize = WellKnownCurves.Bls12Curve381Fp6SizeBytes;
    private const int ElementSize = WellKnownCurves.Bls12Curve381Fp12SizeBytes;


    /// <summary>Returns the reference Fp12 add delegate.</summary>
    public static Fp12AddDelegate GetAdd() => Add;

    /// <summary>Returns the reference Fp12 subtract delegate.</summary>
    public static Fp12SubtractDelegate GetSubtract() => Subtract;

    /// <summary>Returns the reference Fp12 multiply delegate.</summary>
    public static Fp12MultiplyDelegate GetMultiply() => Multiply;

    /// <summary>Returns the reference Fp12 square delegate.</summary>
    public static Fp12SquareDelegate GetSquare() => Square;

    /// <summary>Returns the reference Fp12 negate delegate.</summary>
    public static Fp12NegateDelegate GetNegate() => Negate;

    /// <summary>Returns the reference Fp12 invert delegate.</summary>
    public static Fp12InvertDelegate GetInvert() => Invert;

    /// <summary>Returns the reference Fp12 conjugate delegate.</summary>
    public static Fp12ConjugateDelegate GetConjugate() => Conjugate;


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp12Add, curve);

        Fp12Value pa = Read(a);
        Fp12Value pb = Read(b);
        Write(result, new Fp12Value(
            Bls12Curve381BigIntegerFp6Reference.Fp6Add(pa.C0, pb.C0),
            Bls12Curve381BigIntegerFp6Reference.Fp6Add(pa.C1, pb.C1)));
    }


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp12Subtract, curve);

        Fp12Value pa = Read(a);
        Fp12Value pb = Read(b);
        Write(result, new Fp12Value(
            Bls12Curve381BigIntegerFp6Reference.Fp6Sub(pa.C0, pb.C0),
            Bls12Curve381BigIntegerFp6Reference.Fp6Sub(pa.C1, pb.C1)));
    }


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp12Multiply, curve);

        Fp12Value pa = Read(a);
        Fp12Value pb = Read(b);
        Write(result, Fp12Multiply(pa, pb));
    }


    private static void Square(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp12Square, curve);

        Fp12Value pa = Read(a);
        Write(result, Fp12Multiply(pa, pa));
    }


    private static void Negate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp12Negate, curve);

        Fp12Value pa = Read(a);
        Write(result, new Fp12Value(
            Bls12Curve381BigIntegerFp6Reference.Fp6Neg(pa.C0),
            Bls12Curve381BigIntegerFp6Reference.Fp6Neg(pa.C1)));
    }


    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp12Invert, curve);

        Fp12Value pa = Read(a);
        if(pa.C0.IsZero && pa.C1.IsZero)
        {
            result.Clear();
            return;
        }

        Write(result, Fp12Invert(pa));
    }


    private static void Conjugate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp12Conjugate, curve);

        Fp12Value pa = Read(a);
        Write(result, Fp12Conjugate(pa));
    }


    /// <summary>Schoolbook Fp12 multiplication on tuple values: <c>(a0 + a1·w)(b0 + b1·w) = (a0·b0 + v·a1·b1) + (a0·b1 + a1·b0)·w</c>.</summary>
    internal static Fp12Value Fp12Multiply(Fp12Value a, Fp12Value b)
    {
        Bls12Curve381BigIntegerFp6Reference.Fp6Value a0b0 = Bls12Curve381BigIntegerFp6Reference.Fp6Multiply(a.C0, b.C0);
        Bls12Curve381BigIntegerFp6Reference.Fp6Value a1b1 = Bls12Curve381BigIntegerFp6Reference.Fp6Multiply(a.C1, b.C1);
        Bls12Curve381BigIntegerFp6Reference.Fp6Value a0b1 = Bls12Curve381BigIntegerFp6Reference.Fp6Multiply(a.C0, b.C1);
        Bls12Curve381BigIntegerFp6Reference.Fp6Value a1b0 = Bls12Curve381BigIntegerFp6Reference.Fp6Multiply(a.C1, b.C0);

        Bls12Curve381BigIntegerFp6Reference.Fp6Value c0 = Bls12Curve381BigIntegerFp6Reference.Fp6Add(a0b0, Bls12Curve381BigIntegerFp6Reference.Fp6MulByV(a1b1));
        Bls12Curve381BigIntegerFp6Reference.Fp6Value c1 = Bls12Curve381BigIntegerFp6Reference.Fp6Add(a0b1, a1b0);
        return new Fp12Value(c0, c1);
    }


    /// <summary>Fp12 conjugation on tuple values: <c>(c0, c1) → (c0, −c1)</c> (the non-trivial Fp6-automorphism of Fp12).</summary>
    internal static Fp12Value Fp12Conjugate(Fp12Value a)
    {
        return new Fp12Value(a.C0, Bls12Curve381BigIntegerFp6Reference.Fp6Neg(a.C1));
    }


    /// <summary>Fp12 inversion on tuple values via the norm formula <c>N(a) = c0² − v·c1² ∈ Fp6</c>; returns zero on zero input.</summary>
    internal static Fp12Value Fp12Invert(Fp12Value a)
    {
        if(a.C0.IsZero && a.C1.IsZero)
        {
            return new Fp12Value(Bls12Curve381BigIntegerFp6Reference.Fp6Value.Zero, Bls12Curve381BigIntegerFp6Reference.Fp6Value.Zero);
        }

        Bls12Curve381BigIntegerFp6Reference.Fp6Value c0Squared = Bls12Curve381BigIntegerFp6Reference.Fp6Multiply(a.C0, a.C0);
        Bls12Curve381BigIntegerFp6Reference.Fp6Value c1Squared = Bls12Curve381BigIntegerFp6Reference.Fp6Multiply(a.C1, a.C1);
        Bls12Curve381BigIntegerFp6Reference.Fp6Value vC1Squared = Bls12Curve381BigIntegerFp6Reference.Fp6MulByV(c1Squared);
        Bls12Curve381BigIntegerFp6Reference.Fp6Value norm = Bls12Curve381BigIntegerFp6Reference.Fp6Sub(c0Squared, vC1Squared);
        Bls12Curve381BigIntegerFp6Reference.Fp6Value normInverse = Bls12Curve381BigIntegerFp6Reference.Fp6Invert(norm);

        Bls12Curve381BigIntegerFp6Reference.Fp6Value resultC0 = Bls12Curve381BigIntegerFp6Reference.Fp6Multiply(a.C0, normInverse);
        Bls12Curve381BigIntegerFp6Reference.Fp6Value resultC1 = Bls12Curve381BigIntegerFp6Reference.Fp6Neg(Bls12Curve381BigIntegerFp6Reference.Fp6Multiply(a.C1, normInverse));

        return new Fp12Value(resultC0, resultC1);
    }


    /// <summary>An Fp12 element as two Fp6 components <c>c0 + c1·w</c>.</summary>
    internal readonly record struct Fp12Value(
        Bls12Curve381BigIntegerFp6Reference.Fp6Value C0,
        Bls12Curve381BigIntegerFp6Reference.Fp6Value C1)
    {
        public static Fp12Value Zero { get; } = new(
            Bls12Curve381BigIntegerFp6Reference.Fp6Value.Zero,
            Bls12Curve381BigIntegerFp6Reference.Fp6Value.Zero);

        public static Fp12Value One { get; } = new(
            Bls12Curve381BigIntegerFp6Reference.Fp6Value.One,
            Bls12Curve381BigIntegerFp6Reference.Fp6Value.Zero);
    }


    internal static Fp12Value Read(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length != ElementSize)
        {
            throw new ArgumentException(
                $"Fp12 byte span must be {ElementSize} bytes; received {bytes.Length}.",
                nameof(bytes));
        }


        return new Fp12Value(
            Bls12Curve381BigIntegerFp6Reference.Read(bytes[..ComponentSize]),
            Bls12Curve381BigIntegerFp6Reference.Read(bytes.Slice(ComponentSize, ComponentSize)));
    }


    internal static void Write(Span<byte> destination, Fp12Value value)
    {
        if(destination.Length != ElementSize)
        {
            throw new ArgumentException(
                $"Fp12 byte span must be {ElementSize} bytes; received {destination.Length}.",
                nameof(destination));
        }

        Bls12Curve381BigIntegerFp6Reference.Write(destination[..ComponentSize], value.C0);
        Bls12Curve381BigIntegerFp6Reference.Write(destination.Slice(ComponentSize, ComponentSize), value.C1);
    }
}
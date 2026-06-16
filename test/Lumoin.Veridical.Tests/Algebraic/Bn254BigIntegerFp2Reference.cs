using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Reference implementation of the BN254 (alt_bn128) Fp2 extension-field
/// delegates using <see cref="BigInteger"/> arithmetic. Parallel in shape to
/// <see cref="Bls12Curve381BigIntegerFp2Reference"/>; serves as ground truth
/// for cross-implementation tests.
/// </summary>
/// <remarks>
/// <para>
/// Fp2 is represented as <c>c0 + c1·u</c> with the convention <c>u² = −1</c>,
/// the same quadratic extension as BLS12-381 — only the base field differs.
/// Each component is reduced modulo
/// <see cref="Bn254BigIntegerG1Reference.BaseFieldPrime"/> (the 254-bit prime
/// <c>q</c>).
/// </para>
/// <para>
/// Byte layout: <c>[c0 : 32 bytes BE][c1 : 32 bytes BE]</c>, matching the
/// curve-broad <c>Fp2Element</c> at the BN254 size. The Fp6 non-residue
/// (<c>9 + u</c>) does not appear at this layer — Fp2 multiplication only uses
/// <c>u² = −1</c>; the non-residue enters one level up, in the Fp6 reference.
/// </para>
/// </remarks>
internal static class Bn254BigIntegerFp2Reference
{
    private static readonly BigInteger BaseFieldPrime = Bn254BigIntegerG1Reference.BaseFieldPrime;
    private const int ComponentSize = WellKnownCurves.Bn254BaseFieldSizeBytes;
    private const int ElementSize = 2 * WellKnownCurves.Bn254BaseFieldSizeBytes;


    /// <summary>Returns the reference Fp2 add delegate.</summary>
    public static Fp2AddDelegate GetAdd() => Add;

    /// <summary>Returns the reference Fp2 subtract delegate.</summary>
    public static Fp2SubtractDelegate GetSubtract() => Subtract;

    /// <summary>Returns the reference Fp2 multiply delegate.</summary>
    public static Fp2MultiplyDelegate GetMultiply() => Multiply;

    /// <summary>Returns the reference Fp2 square delegate.</summary>
    public static Fp2SquareDelegate GetSquare() => Square;

    /// <summary>Returns the reference Fp2 negate delegate.</summary>
    public static Fp2NegateDelegate GetNegate() => Negate;

    /// <summary>Returns the reference Fp2 invert delegate.</summary>
    public static Fp2InvertDelegate GetInvert() => Invert;

    /// <summary>Returns the reference Fp2 conjugate delegate.</summary>
    public static Fp2ConjugateDelegate GetConjugate() => Conjugate;


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp2Add, curve);

        (BigInteger a0, BigInteger a1) = Read(a);
        (BigInteger b0, BigInteger b1) = Read(b);

        Write(result, Reduce(a0 + b0), Reduce(a1 + b1));
    }


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp2Subtract, curve);

        (BigInteger a0, BigInteger a1) = Read(a);
        (BigInteger b0, BigInteger b1) = Read(b);

        Write(result, Reduce(a0 - b0), Reduce(a1 - b1));
    }


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp2Multiply, curve);

        (BigInteger a0, BigInteger a1) = Read(a);
        (BigInteger b0, BigInteger b1) = Read(b);

        //(a0 + a1·u)(b0 + b1·u) = (a0·b0 − a1·b1) + (a0·b1 + a1·b0)·u, applying u² = −1.
        Write(result, Reduce((a0 * b0) - (a1 * b1)), Reduce((a0 * b1) + (a1 * b0)));
    }


    private static void Square(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp2Square, curve);

        (BigInteger a0, BigInteger a1) = Read(a);

        Write(result, Reduce((a0 * a0) - (a1 * a1)), Reduce(2 * a0 * a1));
    }


    private static void Negate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp2Negate, curve);

        (BigInteger a0, BigInteger a1) = Read(a);

        Write(result, Reduce(-a0), Reduce(-a1));
    }


    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp2Invert, curve);

        (BigInteger a0, BigInteger a1) = Read(a);

        //norm = c0² + c1² in Fp (u² = −1 turns minus into plus).
        BigInteger norm = Reduce((a0 * a0) + (a1 * a1));
        if(norm.IsZero)
        {
            result.Clear();
            return;
        }

        BigInteger normInverse = BigInteger.ModPow(norm, BaseFieldPrime - 2, BaseFieldPrime);
        Write(result, Reduce(a0 * normInverse), Reduce(-a1 * normInverse));
    }


    private static void Conjugate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp2Conjugate, curve);

        (BigInteger a0, BigInteger a1) = Read(a);

        Write(result, a0, Reduce(-a1));
    }


    private static (BigInteger c0, BigInteger c1) Read(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length != ElementSize)
        {
            throw new ArgumentException(
                $"Fp2 byte span must be {ElementSize} bytes; received {bytes.Length}.",
                nameof(bytes));
        }

        BigInteger c0 = new(bytes[..ComponentSize], isUnsigned: true, isBigEndian: true);
        BigInteger c1 = new(bytes.Slice(ComponentSize, ComponentSize), isUnsigned: true, isBigEndian: true);
        return (c0, c1);
    }


    private static void Write(Span<byte> destination, BigInteger c0, BigInteger c1)
    {
        if(destination.Length != ElementSize)
        {
            throw new ArgumentException(
                $"Fp2 byte span must be {ElementSize} bytes; received {destination.Length}.",
                nameof(destination));
        }

        WriteComponent(c0, destination[..ComponentSize]);
        WriteComponent(c1, destination.Slice(ComponentSize, ComponentSize));
    }


    private static void WriteComponent(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced Fp component did not fit in 32 bytes.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    private static BigInteger Reduce(BigInteger value)
    {
        return ((value % BaseFieldPrime) + BaseFieldPrime) % BaseFieldPrime;
    }
}

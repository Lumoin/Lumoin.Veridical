using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Reference implementation of the BLS12-381 Fp2 extension-field
/// delegates using <see cref="BigInteger"/> arithmetic. Serves as
/// ground truth for cross-implementation tests.
/// </summary>
/// <remarks>
/// <para>
/// Fp2 is represented as <c>c0 + c1·u</c> with the convention
/// <c>u² = −1</c>, the standard BLS12-381 quadratic extension. Each
/// component is reduced modulo
/// <see cref="Bls12Curve381BigIntegerG1Reference.BaseFieldPrime"/>
/// (the 381-bit prime <c>p</c> of the base field).
/// </para>
/// <para>
/// Byte layout: <c>[c0 : 48 bytes BE][c1 : 48 bytes BE]</c>, matching
/// <see cref="Fp2Element"/>. The reference does not
/// constant-time anything; correctness is its only goal.
/// </para>
/// <para>
/// Frobenius identity check: over Fp2 with <c>u² = −1</c> the
/// Frobenius endomorphism <c>x^p</c> coincides with the complex
/// conjugate <c>c0 − c1·u</c>. The conjugate reference implementation
/// is the cheap direct form; the equivalent <c>ModPow(x, p, ...)</c>
/// is provided as a separate property test (in the test class) so a
/// mistaken non-residue sign would surface as a Frobenius mismatch.
/// </para>
/// </remarks>
internal static class Bls12Curve381BigIntegerFp2Reference
{
    private static readonly BigInteger BaseFieldPrime = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;
    private const int ComponentSize = WellKnownCurves.Bls12Curve381BaseFieldSizeBytes;
    private const int ElementSize = WellKnownCurves.Bls12Curve381Fp2SizeBytes;


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

        BigInteger r0 = Reduce(a0 + b0);
        BigInteger r1 = Reduce(a1 + b1);

        Write(result, r0, r1);
    }


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp2Subtract, curve);

        (BigInteger a0, BigInteger a1) = Read(a);
        (BigInteger b0, BigInteger b1) = Read(b);

        BigInteger r0 = Reduce(a0 - b0);
        BigInteger r1 = Reduce(a1 - b1);

        Write(result, r0, r1);
    }


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp2Multiply, curve);

        (BigInteger a0, BigInteger a1) = Read(a);
        (BigInteger b0, BigInteger b1) = Read(b);

        //(a0 + a1·u)(b0 + b1·u) = (a0·b0 − a1·b1) + (a0·b1 + a1·b0)·u, applying u² = −1.
        BigInteger r0 = Reduce((a0 * b0) - (a1 * b1));
        BigInteger r1 = Reduce((a0 * b1) + (a1 * b0));

        Write(result, r0, r1);
    }


    private static void Square(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp2Square, curve);

        (BigInteger a0, BigInteger a1) = Read(a);

        //Reference uses the direct product form; production backends may
        //specialise with the complex-squaring identity for ~25% fewer Fp
        //multiplications. The result must agree.
        BigInteger r0 = Reduce((a0 * a0) - (a1 * a1));
        BigInteger r1 = Reduce(2 * a0 * a1);

        Write(result, r0, r1);
    }


    private static void Negate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp2Negate, curve);

        (BigInteger a0, BigInteger a1) = Read(a);

        BigInteger r0 = Reduce(-a0);
        BigInteger r1 = Reduce(-a1);

        Write(result, r0, r1);
    }


    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp2Invert, curve);

        (BigInteger a0, BigInteger a1) = Read(a);

        //norm = c0² + c1² in Fp (u² = −1 turns minus into plus).
        BigInteger norm = Reduce((a0 * a0) + (a1 * a1));
        if(norm.IsZero)
        {
            //Zero has no inverse; reference returns zero (an arbitrary choice — the
            //caller must avoid inverting zero per the delegate contract).
            result.Clear();
            return;
        }

        //norm^(p − 2) mod p via Fermat's little theorem.
        BigInteger normInverse = BigInteger.ModPow(norm, BaseFieldPrime - 2, BaseFieldPrime);

        //a^(-1) = (c0 − c1·u) / norm = (c0 · normInv) + (−c1 · normInv)·u.
        BigInteger r0 = Reduce(a0 * normInverse);
        BigInteger r1 = Reduce(-a1 * normInverse);

        Write(result, r0, r1);
    }


    private static void Conjugate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp2Conjugate, curve);

        (BigInteger a0, BigInteger a1) = Read(a);

        BigInteger r0 = a0;
        BigInteger r1 = Reduce(-a1);

        Write(result, r0, r1);
    }


    /// <summary>Reads an Fp2 element from <c>[c0 : 48 bytes BE][c1 : 48 bytes BE]</c>.</summary>
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


    /// <summary>Writes an Fp2 element as <c>[c0 : 48 bytes BE][c1 : 48 bytes BE]</c>.</summary>
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
            throw new InvalidOperationException("Reduced Fp component did not fit in 48 bytes.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    /// <summary>Reduces a possibly-negative or possibly-large value to the canonical residue in <c>[0, p)</c>.</summary>
    private static BigInteger Reduce(BigInteger value)
    {
        return ((value % BaseFieldPrime) + BaseFieldPrime) % BaseFieldPrime;
    }
}
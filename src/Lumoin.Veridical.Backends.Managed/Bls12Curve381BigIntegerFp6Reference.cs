using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Reference implementation of the BLS12-381 Fp6 cubic extension-field
/// delegates using <see cref="BigInteger"/> arithmetic over Fp2 element
/// pairs. Serves as ground truth for cross-implementation tests.
/// </summary>
/// <remarks>
/// <para>
/// Fp6 is represented as <c>c0 + c1·v + c2·v²</c> with the convention
/// <c>v³ = ξ = 1 + u</c>, the standard BLS12-381 / EIP-2537 cubic
/// extension. Multiplication wraps <c>v³ → ξ</c> via the schoolbook
/// formula:
/// </para>
/// <para>
/// <c>c0 = a0·b0 + ξ·(a1·b2 + a2·b1)</c><br/>
/// <c>c1 = a0·b1 + a1·b0 + ξ·a2·b2</c><br/>
/// <c>c2 = a0·b2 + a1·b1 + a2·b0</c>
/// </para>
/// <para>
/// Inversion uses the closed-form cubic-extension inverse based on the
/// norm <c>N(a) = a·σ(a)·σ²(a) ∈ Fp2</c>; concretely
/// <c>t0 = a0² − ξ·a1·a2</c>, <c>t1 = ξ·a2² − a0·a1</c>,
/// <c>t2 = a1² − a0·a2</c>, <c>norm = a0·t0 + ξ·(a2·t1 + a1·t2)</c>,
/// then <c>a^(-1) = (t0, t1, t2) / norm</c>.
/// </para>
/// <para>
/// Byte layout: <c>[c0 : 96 bytes][c1 : 96 bytes][c2 : 96 bytes]</c>,
/// each component a canonical Fp2 element <c>[c.c0 : 48 BE][c.c1 : 48 BE]</c>.
/// </para>
/// </remarks>
internal static class Bls12Curve381BigIntegerFp6Reference
{
    private const int ComponentSize = WellKnownCurves.Bls12Curve381Fp2SizeBytes;
    private const int ElementSize = WellKnownCurves.Bls12Curve381Fp6SizeBytes;


    /// <summary>Returns the reference Fp6 add delegate.</summary>
    public static Fp6AddDelegate GetAdd() => Add;

    /// <summary>Returns the reference Fp6 subtract delegate.</summary>
    public static Fp6SubtractDelegate GetSubtract() => Subtract;

    /// <summary>Returns the reference Fp6 multiply delegate.</summary>
    public static Fp6MultiplyDelegate GetMultiply() => Multiply;

    /// <summary>Returns the reference Fp6 square delegate.</summary>
    public static Fp6SquareDelegate GetSquare() => Square;

    /// <summary>Returns the reference Fp6 negate delegate.</summary>
    public static Fp6NegateDelegate GetNegate() => Negate;

    /// <summary>Returns the reference Fp6 invert delegate.</summary>
    public static Fp6InvertDelegate GetInvert() => Invert;


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp6Add, curve);

        Fp6Value pa = Read(a);
        Fp6Value pb = Read(b);
        Write(result, new Fp6Value(Fp2BigInt.Add(pa.C0, pb.C0), Fp2BigInt.Add(pa.C1, pb.C1), Fp2BigInt.Add(pa.C2, pb.C2)));
    }


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp6Subtract, curve);

        Fp6Value pa = Read(a);
        Fp6Value pb = Read(b);
        Write(result, new Fp6Value(Fp2BigInt.Sub(pa.C0, pb.C0), Fp2BigInt.Sub(pa.C1, pb.C1), Fp2BigInt.Sub(pa.C2, pb.C2)));
    }


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp6Multiply, curve);

        Fp6Value pa = Read(a);
        Fp6Value pb = Read(b);
        Write(result, Fp6Multiply(pa, pb));
    }


    private static void Square(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp6Square, curve);

        Fp6Value pa = Read(a);
        Write(result, Fp6Multiply(pa, pa));
    }


    private static void Negate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp6Negate, curve);

        Fp6Value pa = Read(a);
        Write(result, new Fp6Value(Fp2BigInt.Neg(pa.C0), Fp2BigInt.Neg(pa.C1), Fp2BigInt.Neg(pa.C2)));
    }


    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp6Invert, curve);

        Fp6Value pa = Read(a);
        if(pa.IsZero)
        {
            result.Clear();
            return;
        }

        //Closed-form cubic-extension inverse.
        Fp2BigInt.Value xi = Fp2BigInt.NonResidue;
        Fp2BigInt.Value t0 = Fp2BigInt.Sub(Fp2BigInt.Square(pa.C0), Fp2BigInt.Mul(xi, Fp2BigInt.Mul(pa.C1, pa.C2)));
        Fp2BigInt.Value t1 = Fp2BigInt.Sub(Fp2BigInt.Mul(xi, Fp2BigInt.Square(pa.C2)), Fp2BigInt.Mul(pa.C0, pa.C1));
        Fp2BigInt.Value t2 = Fp2BigInt.Sub(Fp2BigInt.Square(pa.C1), Fp2BigInt.Mul(pa.C0, pa.C2));

        Fp2BigInt.Value norm = Fp2BigInt.Add(
            Fp2BigInt.Mul(pa.C0, t0),
            Fp2BigInt.Mul(xi, Fp2BigInt.Add(Fp2BigInt.Mul(pa.C2, t1), Fp2BigInt.Mul(pa.C1, t2))));

        Fp2BigInt.Value normInverse = Fp2BigInt.Invert(norm);

        Write(result, new Fp6Value(
            Fp2BigInt.Mul(t0, normInverse),
            Fp2BigInt.Mul(t1, normInverse),
            Fp2BigInt.Mul(t2, normInverse)));
    }


    /// <summary>Multiplies two Fp6 values via the schoolbook formula with <c>v³ → ξ</c>.</summary>
    internal static Fp6Value Fp6Multiply(Fp6Value a, Fp6Value b)
    {
        Fp2BigInt.Value xi = Fp2BigInt.NonResidue;
        Fp2BigInt.Value a0b0 = Fp2BigInt.Mul(a.C0, b.C0);
        Fp2BigInt.Value a1b1 = Fp2BigInt.Mul(a.C1, b.C1);
        Fp2BigInt.Value a2b2 = Fp2BigInt.Mul(a.C2, b.C2);
        Fp2BigInt.Value a0b1 = Fp2BigInt.Mul(a.C0, b.C1);
        Fp2BigInt.Value a1b0 = Fp2BigInt.Mul(a.C1, b.C0);
        Fp2BigInt.Value a0b2 = Fp2BigInt.Mul(a.C0, b.C2);
        Fp2BigInt.Value a2b0 = Fp2BigInt.Mul(a.C2, b.C0);
        Fp2BigInt.Value a1b2 = Fp2BigInt.Mul(a.C1, b.C2);
        Fp2BigInt.Value a2b1 = Fp2BigInt.Mul(a.C2, b.C1);

        Fp2BigInt.Value c0 = Fp2BigInt.Add(a0b0, Fp2BigInt.Mul(xi, Fp2BigInt.Add(a1b2, a2b1)));
        Fp2BigInt.Value c1 = Fp2BigInt.Add(Fp2BigInt.Add(a0b1, a1b0), Fp2BigInt.Mul(xi, a2b2));
        Fp2BigInt.Value c2 = Fp2BigInt.Add(Fp2BigInt.Add(a0b2, a1b1), a2b0);
        return new Fp6Value(c0, c1, c2);
    }


    /// <summary>
    /// Multiplies an Fp6 value by the indeterminate <c>v</c>:
    /// <c>(x0, x1, x2)·v = (ξ·x2, x0, x1)</c>. Used by the Fp12
    /// reference's <c>w² → v</c> wrap.
    /// </summary>
    internal static Fp6Value Fp6MulByV(Fp6Value a)
    {
        return new Fp6Value(Fp2BigInt.Mul(Fp2BigInt.NonResidue, a.C2), a.C0, a.C1);
    }


    /// <summary>Componentwise Fp6 addition on tuple values.</summary>
    internal static Fp6Value Fp6Add(Fp6Value a, Fp6Value b)
    {
        return new Fp6Value(
            Fp2BigInt.Add(a.C0, b.C0),
            Fp2BigInt.Add(a.C1, b.C1),
            Fp2BigInt.Add(a.C2, b.C2));
    }


    /// <summary>Componentwise Fp6 subtraction on tuple values.</summary>
    internal static Fp6Value Fp6Sub(Fp6Value a, Fp6Value b)
    {
        return new Fp6Value(
            Fp2BigInt.Sub(a.C0, b.C0),
            Fp2BigInt.Sub(a.C1, b.C1),
            Fp2BigInt.Sub(a.C2, b.C2));
    }


    /// <summary>Componentwise Fp6 negation on tuple values.</summary>
    internal static Fp6Value Fp6Neg(Fp6Value a)
    {
        return new Fp6Value(
            Fp2BigInt.Neg(a.C0),
            Fp2BigInt.Neg(a.C1),
            Fp2BigInt.Neg(a.C2));
    }


    /// <summary>Closed-form Fp6 inverse via the cubic-extension norm formula.</summary>
    internal static Fp6Value Fp6Invert(Fp6Value a)
    {
        Fp2BigInt.Value xi = Fp2BigInt.NonResidue;
        Fp2BigInt.Value t0 = Fp2BigInt.Sub(Fp2BigInt.Square(a.C0), Fp2BigInt.Mul(xi, Fp2BigInt.Mul(a.C1, a.C2)));
        Fp2BigInt.Value t1 = Fp2BigInt.Sub(Fp2BigInt.Mul(xi, Fp2BigInt.Square(a.C2)), Fp2BigInt.Mul(a.C0, a.C1));
        Fp2BigInt.Value t2 = Fp2BigInt.Sub(Fp2BigInt.Square(a.C1), Fp2BigInt.Mul(a.C0, a.C2));

        Fp2BigInt.Value norm = Fp2BigInt.Add(
            Fp2BigInt.Mul(a.C0, t0),
            Fp2BigInt.Mul(xi, Fp2BigInt.Add(Fp2BigInt.Mul(a.C2, t1), Fp2BigInt.Mul(a.C1, t2))));

        Fp2BigInt.Value normInverse = Fp2BigInt.Invert(norm);

        return new Fp6Value(
            Fp2BigInt.Mul(t0, normInverse),
            Fp2BigInt.Mul(t1, normInverse),
            Fp2BigInt.Mul(t2, normInverse));
    }


    /// <summary>An Fp6 element as three Fp2 tuples.</summary>
    internal readonly record struct Fp6Value(Fp2BigInt.Value C0, Fp2BigInt.Value C1, Fp2BigInt.Value C2)
    {
        public static Fp6Value Zero { get; } = new(Fp2BigInt.Zero, Fp2BigInt.Zero, Fp2BigInt.Zero);
        public static Fp6Value One { get; } = new(Fp2BigInt.One, Fp2BigInt.Zero, Fp2BigInt.Zero);

        public bool IsZero => Fp2BigInt.IsZero(C0) && Fp2BigInt.IsZero(C1) && Fp2BigInt.IsZero(C2);
    }


    /// <summary>Reads an Fp6 element from <c>[c0 : 96][c1 : 96][c2 : 96]</c>.</summary>
    internal static Fp6Value Read(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length != ElementSize)
        {
            throw new ArgumentException(
                $"Fp6 byte span must be {ElementSize} bytes; received {bytes.Length}.",
                nameof(bytes));
        }

        Fp2BigInt.Value c0 = Fp2BigInt.Read(bytes[..ComponentSize]);
        Fp2BigInt.Value c1 = Fp2BigInt.Read(bytes.Slice(ComponentSize, ComponentSize));
        Fp2BigInt.Value c2 = Fp2BigInt.Read(bytes.Slice(2 * ComponentSize, ComponentSize));
        return new Fp6Value(c0, c1, c2);
    }


    /// <summary>Writes an Fp6 element as <c>[c0 : 96][c1 : 96][c2 : 96]</c>.</summary>
    internal static void Write(Span<byte> destination, Fp6Value value)
    {
        if(destination.Length != ElementSize)
        {
            throw new ArgumentException(
                $"Fp6 byte span must be {ElementSize} bytes; received {destination.Length}.",
                nameof(destination));
        }

        Fp2BigInt.Write(destination[..ComponentSize], value.C0);
        Fp2BigInt.Write(destination.Slice(ComponentSize, ComponentSize), value.C1);
        Fp2BigInt.Write(destination.Slice(2 * ComponentSize, ComponentSize), value.C2);
    }
}


/// <summary>
/// Tuple-based BigInteger Fp2 arithmetic shared by the Fp6 and Fp12
/// reference implementations. Distinct from
/// <c>Bls12Curve381BigIntegerFp2Reference</c>, which operates on the
/// public canonical-byte interface; this helper is the building block
/// for the higher tower references.
/// </summary>
internal static class Fp2BigInt
{
    /// <summary>The BLS12-381 base-field prime <c>p</c>.</summary>
    public static BigInteger Prime { get; } = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;

    /// <summary>The Fp6 non-residue <c>ξ = 1 + u</c>.</summary>
    public static Value NonResidue { get; } = new(BigInteger.One, BigInteger.One);

    /// <summary>The Fp2 zero <c>(0, 0)</c>.</summary>
    public static Value Zero { get; } = new(BigInteger.Zero, BigInteger.Zero);

    /// <summary>The Fp2 one <c>(1, 0)</c>.</summary>
    public static Value One { get; } = new(BigInteger.One, BigInteger.Zero);

    private const int ComponentSize = WellKnownCurves.Bls12Curve381BaseFieldSizeBytes;
    private const int ElementSize = WellKnownCurves.Bls12Curve381Fp2SizeBytes;


    /// <summary>An Fp2 element <c>C0 + C1·u</c> as a BigInteger pair.</summary>
    internal readonly record struct Value(BigInteger C0, BigInteger C1);


    public static bool IsZero(Value a) => a.C0.IsZero && a.C1.IsZero;


    public static Value Add(Value a, Value b)
    {
        return new Value(Reduce(a.C0 + b.C0), Reduce(a.C1 + b.C1));
    }


    public static Value Sub(Value a, Value b)
    {
        return new Value(Reduce(a.C0 - b.C0), Reduce(a.C1 - b.C1));
    }


    public static Value Neg(Value a)
    {
        return new Value(Reduce(-a.C0), Reduce(-a.C1));
    }


    public static Value Mul(Value a, Value b)
    {
        //(a0 + a1·u)(b0 + b1·u) = (a0·b0 − a1·b1) + (a0·b1 + a1·b0)·u, applying u² = −1.
        BigInteger r0 = Reduce((a.C0 * b.C0) - (a.C1 * b.C1));
        BigInteger r1 = Reduce((a.C0 * b.C1) + (a.C1 * b.C0));
        return new Value(r0, r1);
    }


    public static Value Square(Value a)
    {
        BigInteger r0 = Reduce((a.C0 * a.C0) - (a.C1 * a.C1));
        BigInteger r1 = Reduce(2 * a.C0 * a.C1);
        return new Value(r0, r1);
    }


    public static Value Conjugate(Value a)
    {
        return new Value(a.C0, Reduce(-a.C1));
    }


    public static Value Invert(Value a)
    {
        //norm = c0² + c1² in Fp.
        BigInteger norm = Reduce((a.C0 * a.C0) + (a.C1 * a.C1));
        if(norm.IsZero)
        {
            return Zero;
        }
        BigInteger normInverse = BigInteger.ModPow(norm, Prime - 2, Prime);
        BigInteger r0 = Reduce(a.C0 * normInverse);
        BigInteger r1 = Reduce(-a.C1 * normInverse);
        return new Value(r0, r1);
    }


    public static Value Read(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length != ElementSize)
        {
            throw new ArgumentException(
                $"Fp2 byte span must be {ElementSize} bytes; received {bytes.Length}.",
                nameof(bytes));
        }

        BigInteger c0 = new(bytes[..ComponentSize], isUnsigned: true, isBigEndian: true);
        BigInteger c1 = new(bytes.Slice(ComponentSize, ComponentSize), isUnsigned: true, isBigEndian: true);
        return new Value(c0, c1);
    }


    public static void Write(Span<byte> destination, Value value)
    {
        if(destination.Length != ElementSize)
        {
            throw new ArgumentException(
                $"Fp2 byte span must be {ElementSize} bytes; received {destination.Length}.",
                nameof(destination));
        }

        WriteComponent(value.C0, destination[..ComponentSize]);
        WriteComponent(value.C1, destination.Slice(ComponentSize, ComponentSize));
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


    private static BigInteger Reduce(BigInteger value)
    {
        return ((value % Prime) + Prime) % Prime;
    }
}
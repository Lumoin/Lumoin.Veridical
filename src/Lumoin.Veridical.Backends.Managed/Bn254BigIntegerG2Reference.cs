using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Reference implementation of the BN254 (alt_bn128) G2 group delegates using
/// <see cref="BigInteger"/> arithmetic over the Fp2 quadratic extension.
/// Parallel in shape to <see cref="Bls12Curve381BigIntegerG2Reference"/>;
/// serves as ground truth for cross-implementation tests.
/// </summary>
/// <remarks>
/// <para>
/// <b>Twist convention — BN254 uses a D-twist; BLS12-381 uses an M-twist.</b>
/// G2 is the twisted curve <c>y² = x³ + b'</c> over Fp2, where the twist
/// coefficient is <c>b' = b / ξ = 3 / (9 + u)</c> — the base curve's
/// <c>b = 3</c> <em>divided</em> by the Fp6 non-residue <c>ξ = 9 + u</c>. That
/// division is what makes it a D-twist; an M-twist (BLS12-381) would
/// <em>multiply</em> (<c>b · ξ</c>). The two conventions are numerically
/// different curves and, more importantly, embed into Fp12 differently during
/// the pairing: a D-twist maps the G2 line through <c>w⁻¹</c>, an M-twist
/// through <c>w</c>. The G2 group arithmetic here is unaffected by that — it is
/// ordinary elliptic-curve arithmetic over Fp2 with this curve's <c>b'</c> —
/// but the line-evaluation step of the pairing (U.6/U.7) reads the twist
/// convention precisely, so the pairing reference repeats this note.
/// </para>
/// <para>
/// The prime-order subgroup has the same order <c>r</c> as G1, but the full
/// twist has a non-trivial cofactor, so on-curve membership does not imply
/// subgroup membership; <see cref="IsInPrimeOrderSubgroup"/> checks
/// <c>[r]·P = O</c>.
/// </para>
/// <para>
/// Compressed serialization (64 bytes) uses the gnark big-endian convention
/// matching the BN254 G1 backend: the imaginary component <c>x.c1</c> is
/// serialised first (32 bytes big-endian), then the real component <c>x.c0</c>,
/// and the most-significant two bits of byte 0 tag the point — <c>0b10</c>
/// (<c>0x80</c>) compressed with the lexicographically smaller <c>y</c>,
/// <c>0b11</c> (<c>0xC0</c>) the larger, <c>0b01</c> (<c>0x40</c>) the point at
/// infinity. "Larger" compares Fp2 with <c>c1</c> as the more-significant
/// component (<c>2·y.c1 &gt; q</c>, falling back to <c>2·y.c0 &gt; q</c> when
/// <c>y.c1 = 0</c>). Hash-to-G2 is intentionally absent (D3).
/// </para>
/// </remarks>
internal static class Bn254BigIntegerG2Reference
{
    /// <summary>The BN254 base field prime — shared with the G1 reference.</summary>
    public static BigInteger BaseFieldPrime { get; } = Bn254BigIntegerG1Reference.BaseFieldPrime;

    /// <summary>The BN254 prime-order subgroup order <c>r</c>.</summary>
    public static BigInteger ScalarFieldOrder { get; } = Bn254BigIntegerG1Reference.ScalarFieldOrder;


    //Declared before CurveB because CurveB's initializer calls Fp2Invert, which
    //reads this exponent; static initializers run in textual order.
    private static readonly BigInteger ModInverseExponent = BaseFieldPrime - 2;

    /// <summary>
    /// The D-twist coefficient <c>b' = 3 / (9 + u)</c>, computed from the base
    /// <c>b = 3</c> and the non-residue <c>ξ = 9 + u</c> so the D-twist
    /// derivation is explicit rather than transcribed.
    /// </summary>
    public static Fp2Value CurveB { get; } = Fp2Mul(new Fp2Value(new(3), BigInteger.Zero), Fp2Invert(new Fp2Value(new(9), BigInteger.One)));


    private const int ComponentSize = WellKnownCurves.Bn254BaseFieldSizeBytes;
    private const int CompressedSize = WellKnownCurves.Bn254G2CompressedSizeBytes;


    /// <summary>Returns the reference G2-add delegate.</summary>
    public static G2AddDelegate GetAdd() => Add;

    /// <summary>Returns the reference G2-negate delegate.</summary>
    public static G2NegateDelegate GetNegate() => Negate;

    /// <summary>Returns the reference G2-scalar-multiply delegate.</summary>
    public static G2ScalarMultiplyDelegate GetScalarMultiply() => ScalarMultiply;

    /// <summary>Returns the reference G2 on-curve validation delegate.</summary>
    public static G2IsOnCurveDelegate GetIsOnCurve() => IsOnCurve;

    /// <summary>Returns the reference G2 prime-order-subgroup validation delegate.</summary>
    public static G2IsInPrimeOrderSubgroupDelegate GetIsInPrimeOrderSubgroup() => IsInPrimeOrderSubgroup;


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G2Add, curve);

        AffinePoint pa = Decode(a);
        AffinePoint pb = Decode(b);
        AffinePoint sum = PointAdd(pa, pb);
        Encode(sum, result);
    }


    private static void Negate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G2Negate, curve);

        AffinePoint pa = Decode(a);
        AffinePoint negated = PointNegate(pa);
        Encode(negated, result);
    }


    private static void ScalarMultiply(ReadOnlySpan<byte> point, ReadOnlySpan<byte> scalar, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G2ScalarMultiply, curve);

        AffinePoint pa = Decode(point);
        BigInteger k = new(scalar, isUnsigned: true, isBigEndian: true);
        AffinePoint product = ScalarMultiplyPoint(k, pa);
        Encode(product, result);
    }


    private static bool IsOnCurve(ReadOnlySpan<byte> point, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G2IsOnCurve, curve);

        return TryDecode(point, out _);
    }


    private static bool IsInPrimeOrderSubgroup(ReadOnlySpan<byte> point, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G2IsInPrimeOrderSubgroup, curve);

        if(!TryDecode(point, out AffinePoint p))
        {
            return false;
        }

        if(p.IsInfinity)
        {
            return true;
        }

        AffinePoint product = ScalarMultiplyPoint(ScalarFieldOrder, p);
        return product.IsInfinity;
    }


    /// <summary>An Fp2 element represented as a (c0, c1) BigInteger pair.</summary>
    internal readonly record struct Fp2Value(BigInteger C0, BigInteger C1)
    {
        public static Fp2Value Zero { get; } = new(BigInteger.Zero, BigInteger.Zero);
        public static Fp2Value One { get; } = new(BigInteger.One, BigInteger.Zero);

        public bool IsZero => C0.IsZero && C1.IsZero;
    }


    /// <summary>An affine G2 point over Fp2. The identity is represented by <see cref="IsInfinity"/>.</summary>
    private readonly record struct AffinePoint(Fp2Value X, Fp2Value Y, bool IsInfinity)
    {
        public static AffinePoint Identity { get; } = new(Fp2Value.Zero, Fp2Value.Zero, IsInfinity: true);
    }


    private static AffinePoint PointAdd(AffinePoint a, AffinePoint b)
    {
        if(a.IsInfinity)
        {
            return b;
        }
        if(b.IsInfinity)
        {
            return a;
        }

        if(Fp2Equals(a.X, b.X))
        {
            if(Fp2Equals(a.Y, Fp2Negate(b.Y)))
            {
                return AffinePoint.Identity;
            }

            return PointDouble(a);
        }

        Fp2Value dx = Fp2Sub(b.X, a.X);
        Fp2Value dy = Fp2Sub(b.Y, a.Y);
        Fp2Value lambda = Fp2Mul(dy, Fp2Invert(dx));

        Fp2Value lambdaSquared = Fp2Mul(lambda, lambda);
        Fp2Value xResult = Fp2Sub(Fp2Sub(lambdaSquared, a.X), b.X);
        Fp2Value yResult = Fp2Sub(Fp2Mul(lambda, Fp2Sub(a.X, xResult)), a.Y);

        return new AffinePoint(xResult, yResult, IsInfinity: false);
    }


    private static AffinePoint PointDouble(AffinePoint a)
    {
        if(a.IsInfinity || a.Y.IsZero)
        {
            return AffinePoint.Identity;
        }

        //lambda = 3·a.X² / (2·a.Y); curve parameter A = 0 on the twist.
        Fp2Value xSquared = Fp2Mul(a.X, a.X);
        Fp2Value three = new(new(3), BigInteger.Zero);
        Fp2Value numerator = Fp2Mul(three, xSquared);
        Fp2Value two = new(new(2), BigInteger.Zero);
        Fp2Value denominator = Fp2Mul(two, a.Y);
        Fp2Value lambda = Fp2Mul(numerator, Fp2Invert(denominator));

        Fp2Value lambdaSquared = Fp2Mul(lambda, lambda);
        Fp2Value twoX = Fp2Mul(two, a.X);
        Fp2Value xResult = Fp2Sub(lambdaSquared, twoX);
        Fp2Value yResult = Fp2Sub(Fp2Mul(lambda, Fp2Sub(a.X, xResult)), a.Y);

        return new AffinePoint(xResult, yResult, IsInfinity: false);
    }


    private static AffinePoint PointNegate(AffinePoint a)
    {
        if(a.IsInfinity)
        {
            return a;
        }


        return new AffinePoint(a.X, Fp2Negate(a.Y), IsInfinity: false);
    }


    private static AffinePoint ScalarMultiplyPoint(BigInteger scalar, AffinePoint point)
    {
        if(scalar.IsZero || point.IsInfinity)
        {
            return AffinePoint.Identity;
        }

        BigInteger k = scalar;
        AffinePoint basePoint = point;
        if(k.Sign < 0)
        {
            k = -k;
            basePoint = PointNegate(basePoint);
        }

        //Double-and-add in affine form, paying one Fp2 inversion per step. The
        //reference favours correctness and readability over speed.
        AffinePoint result = AffinePoint.Identity;
        byte[] bytes = k.ToByteArray(isUnsigned: true, isBigEndian: true);
        for(int byteIndex = 0; byteIndex < bytes.Length; byteIndex++)
        {
            byte b = bytes[byteIndex];
            for(int bitIndex = 7; bitIndex >= 0; bitIndex--)
            {
                result = PointDouble(result);
                if(((b >> bitIndex) & 1) == 1)
                {
                    result = PointAdd(result, basePoint);
                }
            }
        }


        return result;
    }


    //Fp2 arithmetic over (c0, c1) BigInteger pairs, inlined for compactness with
    //the G2 group law (mirrors the BLS12-381 G2 reference's posture).

    private static Fp2Value Fp2Add(Fp2Value a, Fp2Value b)
    {
        return new(Mod(a.C0 + b.C0), Mod(a.C1 + b.C1));
    }


    private static Fp2Value Fp2Sub(Fp2Value a, Fp2Value b)
    {
        return new(Mod(a.C0 - b.C0), Mod(a.C1 - b.C1));
    }


    private static Fp2Value Fp2Negate(Fp2Value a)
    {
        return new(Mod(-a.C0), Mod(-a.C1));
    }


    private static Fp2Value Fp2Mul(Fp2Value a, Fp2Value b)
    {
        //(a0 + a1·u)(b0 + b1·u) = (a0·b0 − a1·b1) + (a0·b1 + a1·b0)·u, using u² = −1.
        BigInteger c0 = Mod((a.C0 * b.C0) - (a.C1 * b.C1));
        BigInteger c1 = Mod((a.C0 * b.C1) + (a.C1 * b.C0));
        return new(c0, c1);
    }


    private static Fp2Value Fp2Invert(Fp2Value a)
    {
        if(a.IsZero)
        {
            throw new InvalidOperationException("Fp2 inversion of zero is undefined.");
        }

        //norm = c0² + c1² in Fp.
        BigInteger norm = Mod((a.C0 * a.C0) + (a.C1 * a.C1));
        BigInteger normInverse = BigInteger.ModPow(norm, ModInverseExponent, BaseFieldPrime);

        BigInteger c0 = Mod(a.C0 * normInverse);
        BigInteger c1 = Mod(-a.C1 * normInverse);
        return new(c0, c1);
    }


    private static bool Fp2Equals(Fp2Value a, Fp2Value b)
    {
        return a.C0 == b.C0 && a.C1 == b.C1;
    }


    /// <summary>
    /// Tries to compute the Fp2 square root of <paramref name="a"/> via the
    /// complex-sqrt reduction to Fp sqrt. BN254's base prime satisfies
    /// <c>q ≡ 3 (mod 4)</c>, so <c>q² ≡ 1 (mod 4)</c> and the naive
    /// <c>a^((q²+1)/4)</c> form does not apply; the norm-trick is used, exactly
    /// as in the BLS12-381 G2 reference.
    /// </summary>
    private static bool Fp2TrySqrt(Fp2Value a, out Fp2Value root)
    {
        if(a.IsZero)
        {
            root = Fp2Value.Zero;
            return true;
        }

        if(a.C1.IsZero)
        {
            if(TryFpSqrt(a.C0, out BigInteger c0Root))
            {
                root = new(c0Root, BigInteger.Zero);
                return true;
            }
            BigInteger negA0 = Mod(-a.C0);
            if(TryFpSqrt(negA0, out BigInteger c1Root))
            {
                root = new(BigInteger.Zero, c1Root);
                return true;
            }
            root = Fp2Value.Zero;
            return false;
        }

        BigInteger norm = Mod((a.C0 * a.C0) + (a.C1 * a.C1));
        if(!TryFpSqrt(norm, out BigInteger alpha))
        {
            root = Fp2Value.Zero;
            return false;
        }

        BigInteger twoInverse = BigInteger.ModPow(new(2), ModInverseExponent, BaseFieldPrime);
        BigInteger deltaPlus = Mod((a.C0 + alpha) * twoInverse);

        BigInteger x0;
        if(!TryFpSqrt(deltaPlus, out x0))
        {
            BigInteger deltaMinus = Mod((a.C0 - alpha) * twoInverse);
            if(!TryFpSqrt(deltaMinus, out x0))
            {
                root = Fp2Value.Zero;
                return false;
            }
        }

        BigInteger twoX0Inverse = BigInteger.ModPow(Mod(x0 + x0), ModInverseExponent, BaseFieldPrime);
        BigInteger x1 = Mod(a.C1 * twoX0Inverse);

        root = new(x0, x1);
        return true;
    }


    /// <summary>Fp sqrt for BN254's base prime (q ≡ 3 mod 4): <c>candidate = a^((q+1)/4) mod q</c>; verify by squaring.</summary>
    private static bool TryFpSqrt(BigInteger a, out BigInteger root)
    {
        if(a.IsZero)
        {
            root = BigInteger.Zero;
            return true;
        }

        BigInteger candidate = BigInteger.ModPow(a, (BaseFieldPrime + BigInteger.One) >> 2, BaseFieldPrime);
        if(Mod(candidate * candidate) == a)
        {
            root = candidate;
            return true;
        }

        root = BigInteger.Zero;
        return false;
    }


    /// <summary>
    /// Whether <paramref name="y"/> is the lexicographically larger of
    /// <c>(y, −y)</c> in Fp2, comparing <c>c1</c> as the more-significant
    /// component: <c>2·y.c1 &gt; q</c>, falling back to <c>2·y.c0 &gt; q</c>
    /// when <c>y.c1 = 0</c>. Selects the gnark compressed tag (smaller vs larger).
    /// </summary>
    private static bool Fp2IsLarger(Fp2Value y)
    {
        if(y.C1.IsZero)
        {
            return (y.C0 << 1) > BaseFieldPrime;
        }

        return (y.C1 << 1) > BaseFieldPrime;
    }


    private static AffinePoint Decode(ReadOnlySpan<byte> bytes)
    {
        if(!TryDecode(bytes, out AffinePoint result))
        {
            throw new InvalidOperationException("Input bytes do not encode a valid BN254 G2 point.");
        }

        return result;
    }


    private static bool TryDecode(ReadOnlySpan<byte> bytes, out AffinePoint result)
    {
        result = default;
        if(bytes.Length != CompressedSize)
        {
            return false;
        }

        //gnark big-endian tag in the most-significant two bits of byte 0 (the
        //high byte of the imaginary component x.c1).
        int tag = bytes[0] & 0xC0;
        if(tag == 0x40)
        {
            result = AffinePoint.Identity;
            return true;
        }

        if(tag == 0x00)
        {
            return false;
        }

        bool wantLarger = tag == 0xC0;

        //x.c1 (imaginary) from offset 0..31 with tag bits masked, then x.c0 from 32..63.
        Span<byte> c1Bytes = stackalloc byte[ComponentSize];
        bytes[..ComponentSize].CopyTo(c1Bytes);
        c1Bytes[0] &= 0x3f;

        BigInteger xC1 = new(c1Bytes, isUnsigned: true, isBigEndian: true);
        if(xC1 >= BaseFieldPrime)
        {
            return false;
        }

        BigInteger xC0 = new(bytes.Slice(ComponentSize, ComponentSize), isUnsigned: true, isBigEndian: true);
        if(xC0 >= BaseFieldPrime)
        {
            return false;
        }

        Fp2Value x = new(xC0, xC1);

        //y² = x³ + b' on the D-twist.
        Fp2Value xSquared = Fp2Mul(x, x);
        Fp2Value xCubed = Fp2Mul(xSquared, x);
        Fp2Value rhs = Fp2Add(xCubed, CurveB);

        if(!Fp2TrySqrt(rhs, out Fp2Value y))
        {
            return false;
        }

        if(Fp2IsLarger(y) != wantLarger)
        {
            y = Fp2Negate(y);
        }

        result = new AffinePoint(x, y, IsInfinity: false);
        return true;
    }


    private static void Encode(AffinePoint point, Span<byte> destination)
    {
        if(destination.Length != CompressedSize)
        {
            throw new ArgumentException(
                $"Destination must be {CompressedSize} bytes; received {destination.Length}.",
                nameof(destination));
        }

        destination.Clear();
        if(point.IsInfinity)
        {
            destination[0] = 0x40; //gnark compressed-infinity tag
            return;
        }

        //x.c1 (imaginary) to offset 0..31, x.c0 (real) to 32..63.
        WriteBigEndianFixed(point.X.C1, destination[..ComponentSize]);
        WriteBigEndianFixed(point.X.C0, destination.Slice(ComponentSize, ComponentSize));

        destination[0] |= 0x80; //compressed (smaller root)
        if(Fp2IsLarger(point.Y))
        {
            destination[0] |= 0x40; //promote to 0xC0 (larger root)
        }
    }


    private static void WriteBigEndianFixed(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Value did not fit into the destination span.");
        }
        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    private static BigInteger Mod(BigInteger value)
    {
        BigInteger result = value % BaseFieldPrime;
        if(result.Sign < 0)
        {
            result += BaseFieldPrime;
        }

        return result;
    }
}

using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Reference implementation of the BLS12-381 G2 group delegates using
/// <see cref="BigInteger"/> arithmetic over the Fp2 quadratic
/// extension field. Serves as ground truth for cross-implementation
/// tests.
/// </summary>
/// <remarks>
/// <para>
/// G2 is the twisted curve <c>y² = x³ + 4·(1 + u)</c> defined over Fp2,
/// where Fp2 = Fp[u]/(u² + 1). The prime-order subgroup has the same
/// order <c>r</c> as G1 (the scalar field), but the full curve has a
/// non-trivial cofactor (~512 bits). Decode + on-curve does not
/// verify subgroup membership; <see cref="IsInPrimeOrderSubgroup"/>
/// does so by computing <c>[r]·P</c> and checking for the identity.
/// </para>
/// <para>
/// Compressed serialization (96 bytes total) follows the
/// ZCash / EIP-2537 convention: the imaginary component of x
/// (<c>x.c1</c>) is serialised first as 48 bytes big-endian, then
/// the real component (<c>x.c0</c>). Flag bits live in the most-
/// significant byte (offset 0, the high byte of <c>x.c1</c>): bit 7
/// = compression flag, bit 6 = infinity flag, bit 5 = y-parity flag
/// per the Fp2 <c>sgn0</c> rule in RFC 9380 §4.1.
/// </para>
/// <para>
/// Hash-to-curve to G2 is intentionally not implemented in this
/// reference; it ships in a follow-up sub-batch alongside its own
/// RFC 9380 §8.8.2 KAT vectors. BBS+ over BLS12-381 only uses G2 via
/// scalar multiplication of the canonical generator, so the BBS+
/// path does not require hash-to-G2.
/// </para>
/// </remarks>
internal static class Bls12Curve381BigIntegerG2Reference
{
    /// <summary>The BLS12-381 base field prime — shared with the G1 reference.</summary>
    public static BigInteger BaseFieldPrime { get; } = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;

    /// <summary>The BLS12-381 prime-order subgroup order <c>r</c>.</summary>
    public static BigInteger ScalarFieldOrder { get; } = Bls12Curve381BigIntegerG1Reference.ScalarFieldOrder;

    /// <summary>The constant term of the G2 curve equation <c>y² = x³ + 4·(1 + u)</c>, expressed as Fp2 element <c>(4, 4)</c>.</summary>
    public static (BigInteger C0, BigInteger C1) CurveB { get; } = (new(4), new(4));

    /// <summary>The BLS12-381 G2 cofactor <c>h2 = (x⁴ − x² + 1)/3</c> per the standard parameterisation, a ~512-bit integer.</summary>
    public static BigInteger Cofactor { get; } = BigInteger.Parse(
        "05d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    private static readonly BigInteger ModInverseExponent = BaseFieldPrime - 2;

    private const int ComponentSize = WellKnownCurves.Bls12Curve381BaseFieldSizeBytes;
    private const int CompressedSize = WellKnownCurves.Bls12Curve381G2CompressedSizeBytes;


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
    private readonly record struct Fp2Value(BigInteger C0, BigInteger C1)
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

        //lambda = (b.Y − a.Y) / (b.X − a.X)
        Fp2Value dx = Fp2Sub(b.X, a.X);
        Fp2Value dy = Fp2Sub(b.Y, a.Y);
        Fp2Value lambda = Fp2Mul(dy, Fp2Invert(dx));

        //x_r = lambda² − a.X − b.X
        Fp2Value lambdaSquared = Fp2Mul(lambda, lambda);
        Fp2Value xResult = Fp2Sub(Fp2Sub(lambdaSquared, a.X), b.X);

        //y_r = lambda · (a.X − x_r) − a.Y
        Fp2Value yResult = Fp2Sub(Fp2Mul(lambda, Fp2Sub(a.X, xResult)), a.Y);

        return new AffinePoint(xResult, yResult, IsInfinity: false);
    }


    private static AffinePoint PointDouble(AffinePoint a)
    {
        if(a.IsInfinity || a.Y.IsZero)
        {
            return AffinePoint.Identity;
        }

        //lambda = 3·a.X² / (2·a.Y)
        Fp2Value xSquared = Fp2Mul(a.X, a.X);
        Fp2Value three = new(new(3), BigInteger.Zero);
        Fp2Value numerator = Fp2Mul(three, xSquared);
        Fp2Value two = new(new(2), BigInteger.Zero);
        Fp2Value denominator = Fp2Mul(two, a.Y);
        Fp2Value lambda = Fp2Mul(numerator, Fp2Invert(denominator));

        //x_r = lambda² − 2·a.X
        Fp2Value lambdaSquared = Fp2Mul(lambda, lambda);
        Fp2Value twoX = Fp2Mul(two, a.X);
        Fp2Value xResult = Fp2Sub(lambdaSquared, twoX);

        //y_r = lambda · (a.X − x_r) − a.Y
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

        //Double-and-add in affine form. Each iteration costs one Fp2 inversion (via
        //ModPow on each component's inverse path), tolerable for the reference's
        //correctness-over-speed posture.
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


    //Fp2 arithmetic helpers — inlined here over (c0, c1) BigInteger pairs for
    //compactness with the G2 group law. Mirrors the Fp2 reference's algebra; not
    //performance-tuned.

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
    /// Tries to compute the Fp2 square root of <paramref name="a"/>
    /// via the standard "complex sqrt" formula. Returns
    /// <see langword="false"/> when <paramref name="a"/> is not a
    /// quadratic residue in Fp2.
    /// </summary>
    /// <remarks>
    /// <para>
    /// BLS12-381's base prime satisfies <c>p ≡ 3 (mod 4)</c>, so
    /// <c>q = p² ≡ 1 (mod 4)</c>. The naive Fp2 formula
    /// <c>candidate = a^((q + 1) / 4)</c> does not apply at q ≡ 1
    /// mod 4; instead we reduce Fp2 sqrt to Fp sqrt using the
    /// complex-conjugate norm trick:
    /// </para>
    /// <list type="number">
    ///   <item><description>If <c>a.c1 == 0</c>, sqrt reduces to an Fp sqrt of <c>a.c0</c> (or of <c>−a.c0</c> if <c>a.c0</c> is a non-residue, with the result placed on the imaginary axis).</description></item>
    ///   <item><description>Otherwise compute <c>α = sqrt(a.c0² + a.c1²)</c> in Fp; then <c>x0 = sqrt((a.c0 + α) / 2)</c> or <c>sqrt((a.c0 − α) / 2)</c> (whichever is an Fp residue); then <c>x1 = a.c1 / (2·x0)</c>.</description></item>
    /// </list>
    /// </remarks>
    private static bool Fp2TrySqrt(Fp2Value a, out Fp2Value root)
    {
        if(a.IsZero)
        {
            root = Fp2Value.Zero;
            return true;
        }

        if(a.C1.IsZero)
        {
            //Pure-real case. y² = a.c0. Either a.c0 is an Fp residue (y on the real axis)
            //or −a.c0 is (y on the imaginary axis, since (i·c)² = −c² in Fp2 with u² = −1).
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
            //Fall back to the other branch; exactly one of (a.c0 ± α)/2 is an Fp residue
            //for p ≡ 3 mod 4 (because their product is (−a.c1²)/4, a non-residue).
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


    /// <summary>Fp sqrt for BLS12-381's base prime (p ≡ 3 mod 4): <c>candidate = a^((p+1)/4) mod p</c>; verify by squaring.</summary>
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
    /// Computes the y-parity flag bit per the ZCash / EIP-2537 G2
    /// compressed serialisation convention: <c>y</c> is "larger" than
    /// <c>−y</c> by lexicographic comparison on Fp2 components with
    /// <c>c1</c> as the more-significant component. Equivalently, the
    /// flag is set when <c>2·y.c1 &gt; p</c>, falling back to
    /// <c>2·y.c0 &gt; p</c> when <c>y.c1 == 0</c>.
    /// </summary>
    /// <remarks>
    /// This is distinct from the RFC 9380 §4.1 <c>sgn0</c> definition
    /// (which uses <c>x mod 2</c> on each component); ZCash's
    /// compressed form predates RFC 9380 and uses the lex rule. The
    /// existing G1 reference uses the analogous <c>2y &gt; p</c> rule
    /// for its parity flag, so this G2 convention matches the
    /// codebase's overall encoding posture. The RFC 9380 sgn0 will
    /// land separately in the hash-to-curve sub-batch.
    /// </remarks>
    private static int Fp2YParityZcash(Fp2Value a)
    {
        if(a.C1.IsZero)
        {
            return (a.C0 << 1) > BaseFieldPrime ? 1 : 0;
        }

        return (a.C1 << 1) > BaseFieldPrime ? 1 : 0;
    }


    /// <summary>Decodes the canonical compressed bytes into an affine point; throws on malformed input.</summary>
    private static AffinePoint Decode(ReadOnlySpan<byte> bytes)
    {
        if(!TryDecode(bytes, out AffinePoint result))
        {
            throw new InvalidOperationException("Input bytes do not encode a valid BLS12-381 G2 point.");
        }

        return result;
    }


    /// <summary>
    /// Tries to decode <paramref name="bytes"/> into an affine point on
    /// the G2 twist curve. Verifies length, flag-bit consistency, base-
    /// field range, and on-curve membership; does NOT verify subgroup
    /// membership (that is <see cref="IsInPrimeOrderSubgroup"/>'s job).
    /// </summary>
    private static bool TryDecode(ReadOnlySpan<byte> bytes, out AffinePoint result)
    {
        result = default;
        if(bytes.Length != CompressedSize)
        {
            return false;
        }

        byte flagByte = bytes[0];
        bool isCompressed = (flagByte & 0x80) != 0;
        bool isInfinity = (flagByte & 0x40) != 0;
        bool yParityFlag = (flagByte & 0x20) != 0;

        if(!isCompressed)
        {
            return false;
        }
        if(isInfinity)
        {
            result = AffinePoint.Identity;
            return true;
        }

        //Read x.c1 (imaginary part) from offset 0..47 with flags masked, then x.c0 from 48..95.
        Span<byte> c1Bytes = stackalloc byte[ComponentSize];
        bytes[..ComponentSize].CopyTo(c1Bytes);
        c1Bytes[0] &= 0x1f;

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

        //Compute y² = x³ + 4·(1+u) in Fp2 and take the square root.
        Fp2Value xSquared = Fp2Mul(x, x);
        Fp2Value xCubed = Fp2Mul(xSquared, x);
        Fp2Value rhs = Fp2Add(xCubed, new(CurveB.C0, CurveB.C1));

        if(!Fp2TrySqrt(rhs, out Fp2Value y))
        {
            return false;
        }

        //Pick the y matching the parity flag per Fp2 sgn0.
        int sgn = Fp2YParityZcash(y);
        bool sgnFlag = sgn == 1;
        if(sgnFlag != yParityFlag)
        {
            y = Fp2Negate(y);
        }

        result = new AffinePoint(x, y, IsInfinity: false);
        return true;
    }


    /// <summary>Encodes an affine point in the canonical 96-byte compressed form.</summary>
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
            destination[0] = 0xc0; //compression + infinity flags
            return;
        }

        //Write x.c1 to offset 0..47, x.c0 to 48..95.
        WriteBigEndianFixed(point.X.C1, destination[..ComponentSize]);
        WriteBigEndianFixed(point.X.C0, destination.Slice(ComponentSize, ComponentSize));

        destination[0] |= 0x80; //compression flag

        //y-parity flag from sgn0(y).
        if(Fp2YParityZcash(point.Y) == 1)
        {
            destination[0] |= 0x20;
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


    /// <summary>Reduces a possibly-negative or possibly-large value to the canonical residue in [0, p).</summary>
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
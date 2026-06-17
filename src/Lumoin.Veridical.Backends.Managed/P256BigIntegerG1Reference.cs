using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Reference implementation of the NIST P-256 (secp256r1) group delegates
/// using <see cref="BigInteger"/> arithmetic over the base field. P-256 is a
/// short-Weierstrass curve <c>y² = x³ + a·x + b</c> with <c>a = −3</c> — unlike
/// the pairing curves BLS12-381 and BN254, whose G1 has <c>a = 0</c> — so the
/// doubling and on-curve formulas carry the <c>a·x</c> term. Points cross the
/// delegate boundary in the SEC1 compressed encoding (33 bytes: a
/// <c>0x02</c>/<c>0x03</c> parity prefix and the big-endian x, or a single
/// <c>0x00</c> prefix with zero padding for the point at infinity).
/// </summary>
/// <remarks>
/// <para>
/// This is the group ECDSA-P-256 and the in-circuit verification proof build
/// on; the scalar (signature) field lives in
/// <see cref="P256BigIntegerScalarReference"/>. Single-operation point
/// arithmetic uses textbook affine formulas; <see cref="ScalarMultiply"/>
/// runs a double-and-add ladder in Jacobian coordinates (no per-step
/// inversion) and converts back to affine once at the end, the same shape as
/// the pairing-curve references. Hash-to-curve is deliberately absent —
/// neither ECDSA nor the Longfellow construction needs it, and the RFC 9380
/// P-256 SSWU map is a separate concern.
/// </para>
/// <para>
/// Curve constants: NIST SP 800-186 (2023) Curve P-256; SEC 2 v2.0 §2.4.2
/// secp256r1; FIPS 186-4 Appendix D.1.2.3. Cross-checks the platform
/// <c>ECCurve.NamedCurves.nistP256</c>.
/// </para>
/// </remarks>
internal static class P256BigIntegerG1Reference
{
    /// <summary>The P-256 base field prime <c>p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff</c>.</summary>
    /// <remarks>The leading <c>"0"</c> keeps the <c>0xff</c> top byte from parsing negative.</remarks>
    public static BigInteger BaseFieldPrime { get; } = BigInteger.Parse(
        "0ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    /// <summary>The P-256 group order <c>n</c> (cofactor 1, so the order of the whole group).</summary>
    public static BigInteger ScalarFieldOrder { get; } = BigInteger.Parse(
        "0ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    /// <summary>The curve coefficient <c>a = −3 ≡ p − 3 (mod p)</c>.</summary>
    public static BigInteger CurveA { get; } = BaseFieldPrime - 3;

    /// <summary>The curve coefficient <c>b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b</c>.</summary>
    public static BigInteger CurveB { get; } = BigInteger.Parse(
        "05ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    private static BigInteger GeneratorX { get; } = BigInteger.Parse(
        "06b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    private static BigInteger GeneratorY { get; } = BigInteger.Parse(
        "04fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    //p ≡ 3 (mod 4) (the low byte 0xff is 255 ≡ 3), so a quadratic residue's
    //square root is a^((p+1)/4) mod p.
    private static BigInteger SqrtExponent { get; } = (BaseFieldPrime + BigInteger.One) >> 2;
    private static BigInteger ModInverseExponent { get; } = BaseFieldPrime - 2;

    private const int CompressedSize = 33;
    private const int CoordinateSize = 32;


    /// <summary>Returns the reference G1-add delegate.</summary>
    public static G1AddDelegate GetAdd() => Add;

    /// <summary>Returns the reference G1-negate delegate.</summary>
    public static G1NegateDelegate GetNegate() => Negate;

    /// <summary>Returns the reference G1-scalar-multiply delegate.</summary>
    public static G1ScalarMultiplyDelegate GetScalarMultiply() => ScalarMultiply;

    /// <summary>Returns the reference G1 multi-scalar-multiplication delegate (naive accumulate; a Pippenger backend is a later perf item).</summary>
    public static G1MultiScalarMultiplyDelegate GetMultiScalarMultiply() => MultiScalarMultiply;


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1Add, curve);
        Encode(PointAdd(Decode(a), Decode(b)), result);
    }


    private static void Negate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1Negate, curve);
        Encode(PointNegate(Decode(a)), result);
    }


    private static void ScalarMultiply(ReadOnlySpan<byte> point, ReadOnlySpan<byte> scalar, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1ScalarMultiply, curve);
        BigInteger k = new(scalar, isUnsigned: true, isBigEndian: true);
        Encode(ScalarMultiplyPoint(k, Decode(point)), result);
    }


    private static void MultiScalarMultiply(
        ReadOnlySpan<byte> pointsConcatenated,
        ReadOnlySpan<byte> scalarsConcatenated,
        int count,
        Span<byte> result,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1MultiScalarMultiply, curve, count);

        int scalarStride = Scalar.SizeBytes;
        if(pointsConcatenated.Length != count * CompressedSize)
        {
            throw new ArgumentException($"pointsConcatenated must hold {count} compressed P-256 points of {CompressedSize} bytes; received {pointsConcatenated.Length}.", nameof(pointsConcatenated));
        }

        if(scalarsConcatenated.Length != count * scalarStride)
        {
            throw new ArgumentException($"scalarsConcatenated must hold {count} canonical scalars of {scalarStride} bytes; received {scalarsConcatenated.Length}.", nameof(scalarsConcatenated));
        }

        AffinePoint accumulator = AffinePoint.Identity;
        for(int i = 0; i < count; i++)
        {
            BigInteger k = new(scalarsConcatenated.Slice(i * scalarStride, scalarStride), isUnsigned: true, isBigEndian: true);
            accumulator = PointAdd(accumulator, ScalarMultiplyPoint(k, Decode(pointsConcatenated.Slice(i * CompressedSize, CompressedSize))));
        }

        Encode(accumulator, result);
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

        //Double-and-add MSB-first in Jacobian coordinates: each step is a few
        //base-field multiplications, with the single inversion deferred to the
        //affine conversion at the end.
        JacobianPoint result = JacobianPoint.Identity;
        byte[] bytes = k.ToByteArray(isUnsigned: true, isBigEndian: true);
        for(int byteIndex = 0; byteIndex < bytes.Length; byteIndex++)
        {
            byte octet = bytes[byteIndex];
            for(int bitIndex = 7; bitIndex >= 0; bitIndex--)
            {
                result = JacobianDouble(result);
                if(((octet >> bitIndex) & 1) == 1)
                {
                    result = JacobianAddMixed(result, basePoint);
                }
            }
        }

        return JacobianToAffine(result);
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

        if(a.X == b.X)
        {
            //Same x: either a doubling (equal points) or mutually inverse (sum is infinity).
            if((a.Y + b.Y) % BaseFieldPrime == BigInteger.Zero)
            {
                return AffinePoint.Identity;
            }

            return PointDouble(a);
        }

        //slope = (y2 − y1) / (x2 − x1).
        BigInteger slope = Mod((b.Y - a.Y) * ModInverse(Mod(b.X - a.X, BaseFieldPrime)), BaseFieldPrime);
        BigInteger x3 = Mod((slope * slope) - a.X - b.X, BaseFieldPrime);
        BigInteger y3 = Mod((slope * (a.X - x3)) - a.Y, BaseFieldPrime);

        return new AffinePoint(x3, y3, IsInfinity: false);
    }


    private static AffinePoint PointDouble(AffinePoint a)
    {
        if(a.IsInfinity || a.Y.IsZero)
        {
            return AffinePoint.Identity;
        }

        //slope = (3x² + a) / (2y), with a = −3.
        BigInteger numerator = Mod((3 * a.X * a.X) + CurveA, BaseFieldPrime);
        BigInteger slope = Mod(numerator * ModInverse(Mod(2 * a.Y, BaseFieldPrime)), BaseFieldPrime);
        BigInteger x3 = Mod((slope * slope) - (2 * a.X), BaseFieldPrime);
        BigInteger y3 = Mod((slope * (a.X - x3)) - a.Y, BaseFieldPrime);

        return new AffinePoint(x3, y3, IsInfinity: false);
    }


    private static AffinePoint PointNegate(AffinePoint a) =>
        a.IsInfinity ? AffinePoint.Identity : new AffinePoint(a.X, Mod(-a.Y, BaseFieldPrime), IsInfinity: false);


    private static JacobianPoint JacobianDouble(JacobianPoint p)
    {
        //General short-Weierstrass doubling (a ≠ 0): with
        //S = 4XY², M = 3X² + a·Z⁴, X' = M² − 2S, Y' = M(S − X') − 8Y⁴, Z' = 2YZ.
        if(p.IsIdentity || p.Y.IsZero)
        {
            return JacobianPoint.Identity;
        }

        BigInteger ySquared = Mod(p.Y * p.Y, BaseFieldPrime);
        BigInteger zSquared = Mod(p.Z * p.Z, BaseFieldPrime);
        BigInteger s = Mod(4 * p.X * ySquared, BaseFieldPrime);
        BigInteger m = Mod((3 * p.X * p.X) + (CurveA * zSquared * zSquared), BaseFieldPrime);
        BigInteger xResult = Mod((m * m) - (2 * s), BaseFieldPrime);
        BigInteger yResult = Mod((m * (s - xResult)) - (8 * ySquared * ySquared), BaseFieldPrime);
        BigInteger zResult = Mod(2 * p.Y * p.Z, BaseFieldPrime);

        return new JacobianPoint(xResult, yResult, zResult);
    }


    private static JacobianPoint JacobianAddMixed(JacobianPoint p, AffinePoint q)
    {
        //Mixed addition: q is affine (implicit Z = 1), which shortens the
        //formula. Reduces to doubling when p and q coincide; identity when q = −p.
        if(p.IsIdentity)
        {
            return q.IsInfinity ? JacobianPoint.Identity : new JacobianPoint(q.X, q.Y, BigInteger.One);
        }

        if(q.IsInfinity)
        {
            return p;
        }

        BigInteger z1Squared = Mod(p.Z * p.Z, BaseFieldPrime);
        BigInteger u2 = Mod(q.X * z1Squared, BaseFieldPrime);
        BigInteger z1Cubed = Mod(p.Z * z1Squared, BaseFieldPrime);
        BigInteger s2 = Mod(q.Y * z1Cubed, BaseFieldPrime);

        if(p.X == u2)
        {
            return p.Y == s2 ? JacobianDouble(p) : JacobianPoint.Identity;
        }

        BigInteger h = Mod(u2 - p.X, BaseFieldPrime);
        BigInteger hSquared = Mod(h * h, BaseFieldPrime);
        BigInteger hCubed = Mod(h * hSquared, BaseFieldPrime);
        BigInteger r = Mod(s2 - p.Y, BaseFieldPrime);
        BigInteger v = Mod(p.X * hSquared, BaseFieldPrime);
        BigInteger xResult = Mod((r * r) - hCubed - (2 * v), BaseFieldPrime);
        BigInteger yResult = Mod((r * (v - xResult)) - (p.Y * hCubed), BaseFieldPrime);
        BigInteger zResult = Mod(p.Z * h, BaseFieldPrime);

        return new JacobianPoint(xResult, yResult, zResult);
    }


    private static AffinePoint JacobianToAffine(JacobianPoint j)
    {
        if(j.IsIdentity)
        {
            return AffinePoint.Identity;
        }

        BigInteger zInverse = ModInverse(j.Z);
        BigInteger zInverseSquared = Mod(zInverse * zInverse, BaseFieldPrime);
        BigInteger x = Mod(j.X * zInverseSquared, BaseFieldPrime);
        BigInteger y = Mod(j.Y * zInverseSquared * zInverse, BaseFieldPrime);

        return new AffinePoint(x, y, IsInfinity: false);
    }


    /// <summary>Whether <paramref name="point"/> satisfies <c>y² = x³ − 3x + b</c> (or is infinity).</summary>
    public static bool IsOnCurve(AffinePoint point)
    {
        if(point.IsInfinity)
        {
            return true;
        }

        BigInteger left = Mod(point.Y * point.Y, BaseFieldPrime);
        BigInteger right = Mod((point.X * point.X * point.X) + (CurveA * point.X) + CurveB, BaseFieldPrime);

        return left == right;
    }


    internal static AffinePoint Decode(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length != CompressedSize)
        {
            throw new ArgumentException($"A compressed P-256 point must be {CompressedSize} bytes; received {bytes.Length}.", nameof(bytes));
        }

        byte prefix = bytes[0];
        ReadOnlySpan<byte> xBytes = bytes[1..];

        if(prefix == 0x00)
        {
            if(xBytes.IndexOfAnyExcept((byte)0) >= 0)
            {
                throw new InvalidOperationException("The P-256 infinity encoding must have a zero coordinate field.");
            }

            return AffinePoint.Identity;
        }

        if(prefix is not (0x02 or 0x03))
        {
            throw new InvalidOperationException($"Unknown P-256 compressed-point prefix 0x{prefix:x2}; expected 0x00, 0x02, or 0x03.");
        }

        BigInteger x = new(xBytes, isUnsigned: true, isBigEndian: true);
        if(x >= BaseFieldPrime)
        {
            throw new InvalidOperationException("The P-256 x-coordinate is not a canonical field element.");
        }

        //Recover y from y² = x³ − 3x + b, picking the parity the prefix declares.
        BigInteger alpha = Mod((x * x * x) + (CurveA * x) + CurveB, BaseFieldPrime);
        if(!TrySqrt(alpha, out BigInteger y))
        {
            throw new InvalidOperationException("The P-256 x-coordinate has no corresponding point (non-residue).");
        }

        bool wantOdd = prefix == 0x03;
        if(((y & BigInteger.One) == BigInteger.One) != wantOdd)
        {
            y = BaseFieldPrime - y;
        }

        return new AffinePoint(x, y, IsInfinity: false);
    }


    internal static void Encode(AffinePoint point, Span<byte> destination)
    {
        if(destination.Length != CompressedSize)
        {
            throw new ArgumentException($"A compressed P-256 point destination must be {CompressedSize} bytes; received {destination.Length}.", nameof(destination));
        }

        destination.Clear();
        if(point.IsInfinity)
        {
            destination[0] = 0x00;

            return;
        }

        destination[0] = (point.Y & BigInteger.One) == BigInteger.One ? (byte)0x03 : (byte)0x02;
        WriteCoordinate(point.X, destination[1..]);
    }


    internal static BigInteger Mod(BigInteger value, BigInteger modulus)
    {
        BigInteger reduced = value % modulus;

        return reduced.Sign < 0 ? reduced + modulus : reduced;
    }


    private static BigInteger ModInverse(BigInteger value) => BigInteger.ModPow(Mod(value, BaseFieldPrime), ModInverseExponent, BaseFieldPrime);


    private static bool TrySqrt(BigInteger value, out BigInteger root)
    {
        root = BigInteger.ModPow(value, SqrtExponent, BaseFieldPrime);

        return Mod(root * root, BaseFieldPrime) == Mod(value, BaseFieldPrime);
    }


    private static void WriteCoordinate(BigInteger value, Span<byte> destination)
    {
        Span<byte> scratch = stackalloc byte[CoordinateSize];
        scratch.Clear();
        if(!value.TryWriteBytes(scratch, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("P-256 coordinate did not fit in 32 bytes.");
        }

        if(written < CoordinateSize)
        {
            int shift = CoordinateSize - written;
            scratch[..written].CopyTo(scratch[shift..]);
            scratch[..shift].Clear();
        }

        scratch.CopyTo(destination);
    }


    /// <summary>An affine P-256 point, or the point at infinity.</summary>
    internal readonly record struct AffinePoint(BigInteger X, BigInteger Y, bool IsInfinity)
    {
        public static AffinePoint Identity { get; } = new(BigInteger.Zero, BigInteger.Zero, IsInfinity: true);

        /// <summary>The generator <c>G</c>.</summary>
        public static AffinePoint Generator { get; } = new(GeneratorX, GeneratorY, IsInfinity: false);
    }


    /// <summary>A Jacobian-projective P-256 point <c>(X : Y : Z)</c> with affine <c>(X/Z², Y/Z³)</c>.</summary>
    internal readonly record struct JacobianPoint(BigInteger X, BigInteger Y, BigInteger Z)
    {
        public bool IsIdentity => Z.IsZero;

        public static JacobianPoint Identity { get; } = new(BigInteger.One, BigInteger.One, BigInteger.Zero);
    }
}

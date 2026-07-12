using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Provenance;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Globalization;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Reference implementation of the BN254 (alt_bn128) G1 point delegates using
/// <see cref="BigInteger"/> arithmetic over the base field. Parallel in shape
/// to <see cref="Bls12Curve381BigIntegerG1Reference"/>; serves as the ground
/// truth that production backends are validated to match.
/// </summary>
/// <remarks>
/// <para>
/// Internal representation is the affine triple <c>(x, y, isInfinity)</c> over
/// the base field <c>Fp = GF(q)</c> with the BN254 curve equation
/// <c>y² = x³ + 3</c> (curve parameter <c>a = 0</c>, <c>b = 3</c> — note BN254
/// uses <c>+3</c> where BLS12-381 G1 uses <c>+4</c>). The generator is the
/// affine point <c>(1, 2)</c>.
/// </para>
/// <para>
/// Public points cross the delegate boundary as the curve's 32-byte compressed
/// encoding. The convention is the gnark big-endian one (gnark
/// <c>bn254/marshal.go</c>): the most-significant two bits of byte 0 tag the
/// point, and the remaining 254 bits hold the big-endian x-coordinate.
/// <list type="bullet">
/// <item><c>0b10</c> (<c>0x80</c>): compressed, y is the smaller root.</item>
/// <item><c>0b11</c> (<c>0xC0</c>): compressed, y is the larger root (<c>2y &gt; q</c>).</item>
/// <item><c>0b01</c> (<c>0x40</c>): point at infinity.</item>
/// <item><c>0b00</c> (<c>0x00</c>): uncompressed — not valid at the 32-byte boundary.</item>
/// </list>
/// The two spare bits exist because <c>q</c> is 254 bits while the encoding is
/// 256 bits wide, so the top two bits of a canonical x-coordinate are always
/// zero. This deliberately differs from the BLS12-381 <c>0xc0</c>-prefixed
/// identity: the generator is <c>0x80 …00 01</c> and the identity is
/// <c>0x40 …00</c>.
/// </para>
/// <para>
/// Single-operation arithmetic uses the textbook affine formulas with the
/// special cases <c>P + O = P</c>, <c>P + (-P) = O</c>, and <c>P + P = 2P</c>.
/// Scalar multiplication runs its double-and-add inner loop in Jacobian
/// coordinates so the only modular inversion per call is the final conversion
/// back to affine, exactly as the BLS12-381 reference does. The reference is
/// not constant-time and is not intended to be.
/// </para>
/// <para>
/// BN254 G1 has cofactor <c>h = 1</c>: the curve group has prime order
/// <c>r</c>, so every on-curve point is already in the prime-order subgroup and
/// <see cref="IsInPrimeOrderSubgroup"/>'s <c>[r] P == O</c> check holds for all
/// of them. There is no cofactor clearing to perform — a structural difference
/// from BLS12-381, whose G1 cofactor is non-trivial.
/// </para>
/// </remarks>
internal static class Bn254BigIntegerG1Reference
{
    /// <summary>
    /// The BN254 base field prime
    /// <c>q = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47</c>
    /// — a 254-bit prime, the modulus of <c>Fp</c> over which the curve is
    /// defined. Per the U.2 decision this is the single home of the BN254
    /// base-field prime; the Fp2 tower reference reads it from here, mirroring
    /// how the BLS12-381 references share
    /// <see cref="Bls12Curve381BigIntegerG1Reference.BaseFieldPrime"/>.
    /// Its leading hex digit is <c>3</c>, so the literal parses positive
    /// without a leading-zero sign guard.
    /// </summary>
    public static BigInteger BaseFieldPrime { get; } = BigInteger.Parse(
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    /// <summary>
    /// The BN254 prime-order group order
    /// <c>r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001</c>.
    /// Because the cofactor is <c>1</c> this is the order of the whole G1 group.
    /// </summary>
    public static BigInteger ScalarFieldOrder { get; } = BigInteger.Parse(
        "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    /// <summary>The constant term of the curve equation <c>y² = x³ + 3</c>.</summary>
    public static BigInteger CurveB { get; } = new(3);


    /// <summary>
    /// The exponent <c>(q + 1) / 4</c> used for square roots modulo <c>q</c>.
    /// Valid because <c>q ≡ 3 (mod 4)</c> (the low byte of <c>q</c> is
    /// <c>0x47</c>), so a quadratic residue's root is <c>a^((q+1)/4) mod q</c>.
    /// </summary>
    private static readonly BigInteger SqrtExponent = (BaseFieldPrime + BigInteger.One) >> 2;


    /// <summary>The exponent <c>q - 2</c> used for Fermat-style modular inverses.</summary>
    private static readonly BigInteger ModInverseExponent = BaseFieldPrime - 2;


    //RFC 9380 §6.6.1 Shallue–van de Woestijne map constants for BN254 G1
    //(y² = x³ + 3, so A = 0, B = 3). Z = 1 is the value the RFC's find_z_svdw
    //selection (Appendix H.1) returns for this curve; the required square root
    //c3 = sqrt(-g(Z)·(3Z² + 4A)) = sqrt(-12) exists because -12 is a quadratic
    //residue mod q. The constants are derived from the formulas here rather than
    //transcribed, so they cannot drift from the modulus.

    /// <summary>The SvdW parameter <c>Z = 1</c>.</summary>
    private static readonly BigInteger SvdwZ = BigInteger.One;

    /// <summary>The SvdW constant <c>c1 = g(Z) = Z³ + 3</c>.</summary>
    private static readonly BigInteger SvdwGz = Mod((SvdwZ * SvdwZ * SvdwZ) + CurveB, BaseFieldPrime);

    /// <summary>The quantity <c>3Z² + 4A = 3Z²</c> (A = 0), the SvdW denominator term.</summary>
    private static readonly BigInteger SvdwThreeZsquared = Mod(3 * SvdwZ * SvdwZ, BaseFieldPrime);

    /// <summary>The SvdW constant <c>c2 = -Z / 2</c>.</summary>
    private static readonly BigInteger SvdwC2 = Mod(-SvdwZ * ModInverse(2), BaseFieldPrime);

    /// <summary>The SvdW constant <c>c3 = sqrt(-g(Z)·(3Z² + 4A))</c> with <c>sgn0(c3) = 0</c>.</summary>
    private static readonly BigInteger SvdwC3 = ComputeSvdwC3();

    /// <summary>The SvdW constant <c>c4 = -4·g(Z) / (3Z² + 4A)</c>.</summary>
    private static readonly BigInteger SvdwC4 = Mod(-4 * SvdwGz * ModInverse(SvdwThreeZsquared), BaseFieldPrime);


    /// <summary>
    /// The per-field-element byte length for BN254 hash-to-field:
    /// <c>L = ceil((ceil(log2(q)) + k) / 8) = ceil((254 + 128) / 8) = 48</c>
    /// with the curve's <c>k = 128</c>-bit security level (RFC 9380 §5.2).
    /// </summary>
    private const int HashToFieldElementBytes = 48;


    private static readonly ProviderLibrary ProviderLibraryIdentity = new(
        Name: "Lumoin.Veridical.Backends.Managed",
        Version: typeof(Bn254BigIntegerG1Reference).Assembly.GetName().Version?.ToString() ?? "unknown");

    private static readonly CryptoLibrary CryptoLibraryIdentity = new(
        Name: "System.Numerics.BigInteger",
        Version: typeof(BigInteger).Assembly.GetName().Version?.ToString() ?? "unknown");

    private static readonly ProviderClass ProviderClassIdentity = new(
        Name: nameof(Bn254BigIntegerG1Reference));


    private static BigInteger ComputeSvdwC3()
    {
        BigInteger value = Mod(-SvdwGz * SvdwThreeZsquared, BaseFieldPrime);
        if(!TrySqrt(value, out BigInteger root))
        {
            throw new InvalidOperationException(
                "BN254 SvdW constant c3 = sqrt(-g(Z)(3Z² + 4A)) does not exist for Z = 1.");
        }

        //RFC 9380 §6.6.1 requires sgn0(c3) = 0, i.e. the even root.
        if(!(root & BigInteger.One).IsZero)
        {
            root = BaseFieldPrime - root;
        }

        return root;
    }


    /// <summary>Returns the reference G1-add delegate.</summary>
    public static G1AddDelegate GetAdd() => Add;

    /// <summary>Returns the reference G1-negate delegate.</summary>
    public static G1NegateDelegate GetNegate() => Negate;

    /// <summary>Returns the reference G1-scalar-multiply delegate.</summary>
    public static G1ScalarMultiplyDelegate GetScalarMultiply() => ScalarMultiply;

    /// <summary>Returns the reference G1 multi-scalar-multiplication delegate.</summary>
    public static G1MultiScalarMultiplyDelegate GetMultiScalarMultiply() => MultiScalarMultiply;

    /// <summary>Returns the reference G1 on-curve validation delegate.</summary>
    public static G1IsOnCurveDelegate GetIsOnCurve() => IsOnCurve;

    /// <summary>Returns the reference G1 prime-order-subgroup validation delegate.</summary>
    public static G1IsInPrimeOrderSubgroupDelegate GetIsInPrimeOrderSubgroup() => IsInPrimeOrderSubgroup;

    /// <summary>
    /// Returns the reference G1 hash-to-curve delegate: the RFC 9380
    /// random-oracle construction with <c>expand_message_xmd</c> over SHA-256,
    /// the Shallue–van de Woestijne map (BN254 G1 has <c>A = 0</c>, so the
    /// simplified-SWU path does not apply), and no cofactor clearing (the
    /// cofactor is 1).
    /// </summary>
    public static G1HashToCurveDelegate GetHashToCurve() => HashToCurve;


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1Add, curve);

        AffinePoint pa = Decode(a);
        AffinePoint pb = Decode(b);
        AffinePoint sum = PointAdd(pa, pb);
        Encode(sum, result);
    }


    private static void Negate(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1Negate, curve);

        AffinePoint pa = Decode(a);
        AffinePoint negated = PointNegate(pa);
        Encode(negated, result);
    }


    private static void ScalarMultiply(ReadOnlySpan<byte> point, ReadOnlySpan<byte> scalar, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1ScalarMultiply, curve);

        AffinePoint pa = Decode(point);
        BigInteger k = new(scalar, isUnsigned: true, isBigEndian: true);
        AffinePoint product = ScalarMultiplyPoint(k, pa);
        Encode(product, result);
    }


    private static void MultiScalarMultiply(
        ReadOnlySpan<byte> pointsConcatenated,
        ReadOnlySpan<byte> scalarsConcatenated,
        int count,
        Span<byte> result,
        CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1MultiScalarMultiply, curve, count);

        int pointStride = WellKnownCurves.Bn254G1CompressedSizeBytes;
        int scalarStride = Scalar.SizeBytes;

        if(pointsConcatenated.Length != count * pointStride)
        {
            throw new ArgumentException(
                $"pointsConcatenated must hold {count} compressed G1 points of {pointStride} bytes each; received {pointsConcatenated.Length} bytes.",
                nameof(pointsConcatenated));
        }

        if(scalarsConcatenated.Length != count * scalarStride)
        {
            throw new ArgumentException(
                $"scalarsConcatenated must hold {count} canonical scalars of {scalarStride} bytes each; received {scalarsConcatenated.Length} bytes.",
                nameof(scalarsConcatenated));
        }

        AffinePoint acc = AffinePoint.Identity;
        for(int i = 0; i < count; i++)
        {
            AffinePoint pi = Decode(pointsConcatenated.Slice(i * pointStride, pointStride));
            BigInteger ki = new(
                scalarsConcatenated.Slice(i * scalarStride, scalarStride),
                isUnsigned: true,
                isBigEndian: true);

            AffinePoint termI = ScalarMultiplyPoint(ki, pi);
            acc = PointAdd(acc, termI);
        }

        Encode(acc, result);
    }


    private static bool IsOnCurve(ReadOnlySpan<byte> point, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1IsOnCurve, curve);

        return TryDecode(point, out _);
    }


    private static bool IsInPrimeOrderSubgroup(ReadOnlySpan<byte> point, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1IsInPrimeOrderSubgroup, curve);

        if(!TryDecode(point, out AffinePoint p))
        {
            return false;
        }

        if(p.IsInfinity)
        {
            return true;
        }

        //Cofactor is 1, so the curve group has prime order r and [r] P == O for
        //every on-curve P. The explicit multiplication is kept for parity with
        //the BLS12-381 reference and as an honest statement of the membership
        //predicate rather than short-circuiting on the cofactor being trivial.
        AffinePoint product = ScalarMultiplyPoint(ScalarFieldOrder, p);

        return product.IsInfinity;
    }


    private static Tag HashToCurve(
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> domainSeparationTag,
        Span<byte> result,
        CurveParameterSet curve,
        Tag inboundTag)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1HashToCurve, curve);

        //RFC 9380 §3 random-oracle construction: hash_to_field produces two
        //base-field elements (count = 2, m = 1), each from L = 48 uniform bytes,
        //so expand_message_xmd is asked for 96 bytes.
        Span<byte> uniform = stackalloc byte[2 * HashToFieldElementBytes];
        Rfc9380ExpandMessage.ExpandMessageXmdSha256(message, domainSeparationTag, uniform);

        BigInteger u0 = Mod(new BigInteger(uniform[..HashToFieldElementBytes], isUnsigned: true, isBigEndian: true), BaseFieldPrime);
        BigInteger u1 = Mod(new BigInteger(uniform[HashToFieldElementBytes..], isUnsigned: true, isBigEndian: true), BaseFieldPrime);

        AffinePoint q0 = MapToCurveSvdw(u0);
        AffinePoint q1 = MapToCurveSvdw(u1);

        //R = Q0 + Q1; clear_cofactor is the identity because the cofactor is 1,
        //so R is already the prime-order-subgroup output.
        AffinePoint mapped = PointAdd(q0, q1);
        Encode(mapped, result);

        return ProviderInstrumentation.StampTag(
            inboundTag,
            ProviderLibraryIdentity,
            CryptoLibraryIdentity,
            ProviderClassIdentity,
            new ProviderOperation(nameof(HashToCurve)));
    }


    /// <summary>
    /// RFC 9380 §6.6.1 Shallue–van de Woestijne map for BN254 G1
    /// (<c>y² = x³ + 3</c>, <c>A = 0</c>). Returns an affine point on the curve
    /// for any field element <paramref name="u"/>.
    /// </summary>
    private static AffinePoint MapToCurveSvdw(BigInteger u)
    {
        BigInteger tv1 = Mod(u * u, BaseFieldPrime);
        tv1 = Mod(tv1 * SvdwGz, BaseFieldPrime);
        BigInteger tv2 = Mod(BigInteger.One + tv1, BaseFieldPrime);
        tv1 = Mod(BigInteger.One - tv1, BaseFieldPrime);
        BigInteger tv3 = Mod(tv1 * tv2, BaseFieldPrime);
        tv3 = Inv0(tv3);
        BigInteger tv4 = Mod(u * tv1, BaseFieldPrime);
        tv4 = Mod(tv4 * tv3, BaseFieldPrime);
        tv4 = Mod(tv4 * SvdwC3, BaseFieldPrime);

        BigInteger x1 = Mod(SvdwC2 - tv4, BaseFieldPrime);
        BigInteger gx1 = CurveRhs(x1);
        bool gx1IsSquare = IsSquare(gx1);

        BigInteger x2 = Mod(SvdwC2 + tv4, BaseFieldPrime);
        BigInteger gx2 = CurveRhs(x2);

        BigInteger x3 = Mod(tv2 * tv2, BaseFieldPrime);
        x3 = Mod(x3 * tv3, BaseFieldPrime);
        x3 = Mod(x3 * x3, BaseFieldPrime);
        x3 = Mod(x3 * SvdwC4, BaseFieldPrime);
        x3 = Mod(x3 + SvdwZ, BaseFieldPrime);

        //x = gx1 square ? x1 : (gx2 square ? x2 : x3).
        BigInteger x = gx1IsSquare ? x1 : x3;
        if(!gx1IsSquare && IsSquare(gx2))
        {
            x = x2;
        }

        //g(x) is a quadratic residue by construction; take its root and align
        //its sign to u's (sgn0 is the low bit for a single-element field).
        if(!TrySqrt(CurveRhs(x), out BigInteger y))
        {
            throw new InvalidOperationException("SvdW map produced an x whose g(x) is not a quadratic residue (impossible per RFC 9380 §6.6.1).");
        }

        bool uIsOdd = !(u & BigInteger.One).IsZero;
        bool yIsOdd = !(y & BigInteger.One).IsZero;
        if(uIsOdd != yIsOdd)
        {
            y = Mod(-y, BaseFieldPrime);
        }

        return new AffinePoint(x, y, IsInfinity: false);
    }


    /// <summary>Evaluates the curve right-hand side <c>g(x) = x³ + 3</c> (A = 0).</summary>
    private static BigInteger CurveRhs(BigInteger x)
    {
        return Mod((Mod(x * x, BaseFieldPrime) * x) + CurveB, BaseFieldPrime);
    }


    /// <summary>RFC 9380 <c>inv0</c>: the modular inverse, with <c>inv0(0) = 0</c>.</summary>
    private static BigInteger Inv0(BigInteger value)
    {
        return value.IsZero ? BigInteger.Zero : ModInverse(value);
    }


    /// <summary>Determines whether <paramref name="value"/> is a quadratic residue (including zero).</summary>
    private static bool IsSquare(BigInteger value)
    {
        return TrySqrt(value, out _);
    }


    internal readonly record struct AffinePoint(BigInteger X, BigInteger Y, bool IsInfinity)
    {
        public static AffinePoint Identity { get; } = new(BigInteger.Zero, BigInteger.Zero, IsInfinity: true);
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
            if(Mod(a.Y + b.Y, BaseFieldPrime).IsZero)
            {
                return AffinePoint.Identity;
            }


            return PointDouble(a);
        }

        BigInteger dx = Mod(b.X - a.X, BaseFieldPrime);
        BigInteger dy = Mod(b.Y - a.Y, BaseFieldPrime);
        BigInteger lambda = Mod(dy * ModInverse(dx), BaseFieldPrime);
        BigInteger xr = Mod((lambda * lambda) - a.X - b.X, BaseFieldPrime);
        BigInteger yr = Mod((lambda * (a.X - xr)) - a.Y, BaseFieldPrime);

        return new AffinePoint(xr, yr, IsInfinity: false);
    }


    private static AffinePoint PointDouble(AffinePoint a)
    {
        if(a.IsInfinity || a.Y.IsZero)
        {
            return AffinePoint.Identity;
        }

        //Curve parameter a = 0, so the doubling slope is 3x² / 2y.
        BigInteger numerator = Mod(3 * a.X * a.X, BaseFieldPrime);
        BigInteger denominator = Mod(2 * a.Y, BaseFieldPrime);
        BigInteger lambda = Mod(numerator * ModInverse(denominator), BaseFieldPrime);
        BigInteger xr = Mod((lambda * lambda) - (2 * a.X), BaseFieldPrime);
        BigInteger yr = Mod((lambda * (a.X - xr)) - a.Y, BaseFieldPrime);

        return new AffinePoint(xr, yr, IsInfinity: false);
    }


    private static AffinePoint PointNegate(AffinePoint a)
    {
        if(a.IsInfinity)
        {
            return a;
        }


        return new AffinePoint(a.X, Mod(-a.Y, BaseFieldPrime), IsInfinity: false);
    }


    /// <summary>
    /// Jacobian projective coordinates over the BN254 base field. The affine
    /// point <c>(x, y)</c> corresponds to <c>(X, Y, Z)</c> with
    /// <c>x = X / Z²</c> and <c>y = Y / Z³</c>; the identity is <c>Z = 0</c>.
    /// Used only as the inner accumulator for
    /// <see cref="ScalarMultiplyPoint"/>, which keeps the per-call inversion
    /// count at one.
    /// </summary>
    internal readonly record struct JacobianPoint(BigInteger X, BigInteger Y, BigInteger Z)
    {
        public bool IsIdentity => Z.IsZero;

        public static JacobianPoint Identity { get; } = new(BigInteger.One, BigInteger.One, BigInteger.Zero);
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

        JacobianPoint result = JacobianPoint.Identity;
        byte[] bytes = k.ToByteArray(isUnsigned: true, isBigEndian: true);
        for(int byteIndex = 0; byteIndex < bytes.Length; byteIndex++)
        {
            byte b = bytes[byteIndex];
            for(int bitIndex = 7; bitIndex >= 0; bitIndex--)
            {
                result = JacobianDouble(result);
                if(((b >> bitIndex) & 1) == 1)
                {
                    result = JacobianAddMixed(result, basePoint);
                }
            }
        }


        return JacobianToAffine(result);
    }


    internal static JacobianPoint JacobianDouble(JacobianPoint p)
    {
        //For y² = x³ + b with a = 0 (BN254 G1): S = 4 X Y², M = 3 X²,
        //X' = M² - 2S, Y' = M (S - X') - 8 Y⁴, Z' = 2 Y Z. Same 3M + 5S formula
        //as BLS12-381 G1 since both curves have a = 0; only the modulus differs.
        if(p.IsIdentity || p.Y.IsZero)
        {
            return JacobianPoint.Identity;
        }

        BigInteger ySquared = Mod(p.Y * p.Y, BaseFieldPrime);
        BigInteger s = Mod(4 * p.X * ySquared, BaseFieldPrime);
        BigInteger m = Mod(3 * p.X * p.X, BaseFieldPrime);
        BigInteger xResult = Mod((m * m) - (2 * s), BaseFieldPrime);
        BigInteger yResult = Mod((m * (s - xResult)) - (8 * ySquared * ySquared), BaseFieldPrime);
        BigInteger zResult = Mod(2 * p.Y * p.Z, BaseFieldPrime);

        return new JacobianPoint(xResult, yResult, zResult);
    }


    internal static JacobianPoint JacobianAddMixed(JacobianPoint p, AffinePoint q)
    {
        if(p.IsIdentity)
        {
            if(q.IsInfinity)
            {
                return JacobianPoint.Identity;
            }


            return new JacobianPoint(q.X, q.Y, BigInteger.One);
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
            if(p.Y == s2)
            {
                return JacobianDouble(p);
            }


            return JacobianPoint.Identity;
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


    internal static AffinePoint JacobianToAffine(JacobianPoint j)
    {
        if(j.IsIdentity)
        {
            return AffinePoint.Identity;
        }

        BigInteger zInverse = ModInverse(j.Z);
        BigInteger zInverseSquared = Mod(zInverse * zInverse, BaseFieldPrime);
        BigInteger zInverseCubed = Mod(zInverseSquared * zInverse, BaseFieldPrime);
        BigInteger x = Mod(j.X * zInverseSquared, BaseFieldPrime);
        BigInteger y = Mod(j.Y * zInverseCubed, BaseFieldPrime);

        return new AffinePoint(x, y, IsInfinity: false);
    }


    internal static AffinePoint Decode(ReadOnlySpan<byte> bytes)
    {
        if(!TryDecode(bytes, out AffinePoint result))
        {
            throw new InvalidOperationException("Input bytes do not encode a valid BN254 G1 point.");
        }


        return result;
    }


    private static bool TryDecode(ReadOnlySpan<byte> bytes, out AffinePoint result)
    {
        result = default;
        if(bytes.Length != WellKnownCurves.Bn254G1CompressedSizeBytes)
        {
            return false;
        }

        //gnark big-endian tag in the most-significant two bits of byte 0.
        int tag = bytes[0] & 0xC0;
        if(tag == 0x40)
        {
            //The canonical infinity encoding is exactly the infinity tag with every
            //other bit zero. Any other infinity-tagged pattern is non-canonical and
            //rejected rather than aliased onto the identity.
            if(bytes[0] != 0x40 || bytes[1..].IndexOfAnyExcept((byte)0) >= 0)
            {
                return false;
            }

            result = AffinePoint.Identity;

            return true;
        }

        if(tag == 0x00)
        {
            //Uncompressed tag is invalid at the 32-byte compressed boundary.
            return false;
        }

        bool wantLarger = tag == 0xC0;

        Span<byte> xBytes = stackalloc byte[WellKnownCurves.Bn254G1CompressedSizeBytes];
        bytes.CopyTo(xBytes);

        //Clear the two tag bits so the remainder is the canonical x-coordinate.
        xBytes[0] &= 0x3f;

        BigInteger x = new BigInteger(xBytes, isUnsigned: true, isBigEndian: true);
        if(x >= BaseFieldPrime)
        {
            return false;
        }

        BigInteger xSquared = Mod(x * x, BaseFieldPrime);
        BigInteger rhs = Mod((x * xSquared) + CurveB, BaseFieldPrime);
        if(!TrySqrt(rhs, out BigInteger y))
        {
            return false;
        }

        //The square root returns one of the two roots; flip to the requested
        //one. "Larger" is the lexicographically larger of (y, q - y), i.e. 2y > q.
        bool yIsLarger = (y << 1) > BaseFieldPrime;
        if(yIsLarger != wantLarger)
        {
            y = BaseFieldPrime - y;
        }

        result = new AffinePoint(x, y, IsInfinity: false);

        return true;
    }


    internal static void Encode(AffinePoint point, Span<byte> destination)
    {
        if(destination.Length != WellKnownCurves.Bn254G1CompressedSizeBytes)
        {
            throw new ArgumentException(
                $"Destination must be {WellKnownCurves.Bn254G1CompressedSizeBytes} bytes; received {destination.Length}.",
                nameof(destination));
        }

        destination.Clear();
        if(point.IsInfinity)
        {
            //gnark compressed-infinity tag 0b01; remaining bytes zero.
            destination[0] = 0x40;
            return;
        }

        //Write x big-endian, right-aligned into the 32-byte span; x < q < 2^254
        //leaves the top two bits clear for the tag.
        WriteBigEndianFixed(point.X, destination);

        //Compressed tag 0b10 (smaller root); promote to 0b11 (larger root) when
        //y is the lexicographically larger of (y, q - y).
        destination[0] |= 0x80;
        if((point.Y << 1) > BaseFieldPrime)
        {
            destination[0] |= 0x40;
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


    internal static BigInteger Mod(BigInteger value, BigInteger modulus)
    {
        BigInteger result = value % modulus;
        if(result.Sign < 0)
        {
            result += modulus;
        }


        return result;
    }


    private static BigInteger ModInverse(BigInteger value)
    {
        //q is prime, so Fermat's little theorem gives the inverse as
        //value^(q - 2) mod q.
        return BigInteger.ModPow(value, ModInverseExponent, BaseFieldPrime);
    }


    private static bool TrySqrt(BigInteger a, out BigInteger root)
    {
        //q ≡ 3 (mod 4), so a quadratic residue's root is a^((q+1)/4) mod q.
        //Compute the candidate and verify by squaring: this fuses the
        //Legendre-symbol test and the root extraction into one ModPow plus one
        //multiply, the same shape the BLS12-381 reference uses.
        if(a.IsZero)
        {
            root = BigInteger.Zero;

            return true;
        }

        BigInteger candidate = BigInteger.ModPow(a, SqrtExponent, BaseFieldPrime);
        if(Mod(candidate * candidate, BaseFieldPrime) != a)
        {
            root = default;

            return false;
        }

        root = candidate;

        return true;
    }
}

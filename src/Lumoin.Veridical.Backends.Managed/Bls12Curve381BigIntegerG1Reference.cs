using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Provenance;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Globalization;
using System.Linq;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Reference implementation of the BLS12-381 G1 point delegates using
/// <see cref="BigInteger"/> arithmetic over the base field. Exists for the
/// test project to wire against; serves as the ground truth that production
/// backends are validated to match.
/// </summary>
/// <remarks>
/// <para>
/// Internal representation is the affine triple
/// <c>(x, y, isInfinity)</c> over the base field
/// <c>Fp = GF(0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)</c>.
/// All public points cross the delegate boundary as canonical 48-byte
/// compressed encodings (RFC 9380 Appendix M.5.3.1); the helper functions
/// <see cref="TryDecode"/> and <see cref="Encode"/> convert between
/// encodings. Decompression at decode time computes the y-coordinate as a
/// square root of <c>x^3 + 4 mod p</c> and selects the sign indicated by the
/// parity flag bit.
/// </para>
/// <para>
/// Single-operation point arithmetic uses the textbook affine formulas with
/// the three special cases <c>P + O = P</c>, <c>P + (-P) = O</c>, and
/// <c>P + P = 2P</c>. The <c>Add</c> and <c>Negate</c> delegate paths take
/// these directly: each pays one modular inversion per call, which is
/// acceptable when the public boundary is one operation at a time.
/// </para>
/// <para>
/// Scalar multiplication takes a different shape because the double-and-add
/// inner loop runs hundreds of <c>PointDouble</c> and <c>PointAdd</c> calls
/// per invocation; doing them in affine coordinates would mean hundreds of
/// modular inversions on a 381-bit prime, each itself a 381-bit
/// <see cref="BigInteger.ModPow(BigInteger, BigInteger, BigInteger)"/> via
/// Fermat. That total cost is what burned the test suite before this
/// reference moved <see cref="ScalarMultiplyPoint"/> onto Jacobian
/// coordinates internally — Jacobian arithmetic has no inversion in the
/// inner loop, so <c>[r] P</c> pays only a single inversion at the end when
/// converting the accumulator back to affine for the delegate contract.
/// </para>
/// <para>
/// The reference is not constant-time and not intended to be — it is the
/// ground truth, not a production backend. Window-method optimisations,
/// endomorphism-based subgroup checks, and constant-time selectors are
/// deferred to whichever production backend later wires into the same
/// delegates.
/// </para>
/// <para>
/// Hash-to-curve uses RFC 9380 <c>expand_message_xmd</c> with SHA-256 to
/// derive one base-field element, then a try-and-increment scan for the
/// first x whose <c>x^3 + 4</c> is a quadratic residue. The resulting curve
/// point is moved into the prime-order subgroup by scalar multiplication
/// with the BLS12-381 G1 cofactor
/// <c>h = 0x396c8c005555e1568c00aaab0000aaab</c>. The output is therefore
/// always in the prime-order subgroup and always passes
/// <see cref="IsInPrimeOrderSubgroup"/>. This deliberately does not follow
/// the RFC 9380 §8.8.1 simplified-SWU + 11-isogeny construction; the
/// reference favours brevity and direct readability over conformance with
/// the production wire-level path, since its only consumer is the test
/// suite that exercises algebraic laws, on-curve membership, and subgroup
/// membership.
/// </para>
/// <para>
/// The wiring shown in <see cref="GetAdd"/>, <see cref="GetScalarMultiply"/>,
/// and the rest is exactly the wiring an application performs at start-up:
/// it chooses a backend, retrieves the delegates the backend exposes, and
/// passes them into operations. The test project takes the same path with
/// this reference filling the role of the backend.
/// </para>
/// </remarks>
internal static class Bls12Curve381BigIntegerG1Reference
{
    /// <summary>
    /// The BLS12-381 base field prime
    /// <c>p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab</c>
    /// — a 381-bit prime, the modulus of <c>Fp</c> over which the curve is
    /// defined.
    /// </summary>
    public static BigInteger BaseFieldPrime { get; } = BigInteger.Parse(
        "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    /// <summary>
    /// The BLS12-381 G1 prime-order subgroup order
    /// <c>r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001</c>.
    /// </summary>
    public static BigInteger ScalarFieldOrder { get; } = BigInteger.Parse(
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    /// <summary>
    /// The BLS12-381 G1 cofactor
    /// <c>h = 0x396c8c005555e1568c00aaab0000aaab</c>. Multiplying a point on
    /// the curve by <c>h</c> maps it into the prime-order subgroup.
    /// </summary>
    public static BigInteger Cofactor { get; } = BigInteger.Parse(
        "0396c8c005555e1568c00aaab0000aaab",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    /// <summary>The constant term of the curve equation <c>y^2 = x^3 + 4</c>.</summary>
    public static BigInteger CurveB { get; } = new(4);


    /// <summary>
    /// The exponent <c>(p + 1) / 4</c> used for square roots modulo
    /// <c>p</c>. Cached because every <see cref="TryDecode"/>,
    /// <see cref="HashToCurve"/> iteration, and on-curve check would
    /// otherwise recompute it from <see cref="BaseFieldPrime"/> on each
    /// call.
    /// </summary>
    private static readonly BigInteger SqrtExponent = (BaseFieldPrime + BigInteger.One) >> 2;


    /// <summary>
    /// The exponent <c>p - 2</c> used for Fermat-style modular inverses.
    /// Cached for the same reason as <see cref="SqrtExponent"/>: every
    /// <see cref="ModInverse"/> call subtracts two from <c>p</c> and the
    /// inversion sits on the hot path through
    /// <see cref="JacobianToAffine"/> and <see cref="PointAdd"/>.
    /// </summary>
    private static readonly BigInteger ModInverseExponent = BaseFieldPrime - 2;


    private static readonly ProviderLibrary ProviderLibraryIdentity = new(
        Name: "Lumoin.Veridical.Tests",
        Version: "0.0.0");

    private static readonly CryptoLibrary CryptoLibraryIdentity = new(
        Name: "System.Numerics.BigInteger",
        Version: typeof(BigInteger).Assembly.GetName().Version?.ToString() ?? "unknown");

    private static readonly ProviderClass ProviderClassIdentity = new(
        Name: nameof(Bls12Curve381BigIntegerG1Reference));


    /// <summary>Returns the reference G1-add delegate.</summary>
    public static G1AddDelegate GetAdd() => Add;

    /// <summary>Returns the reference G1-negate delegate.</summary>
    public static G1NegateDelegate GetNegate() => Negate;

    /// <summary>Returns the reference G1-scalar-multiply delegate.</summary>
    public static G1ScalarMultiplyDelegate GetScalarMultiply() => ScalarMultiply;

    /// <summary>Returns the reference G1 multi-scalar-multiplication delegate.</summary>
    public static G1MultiScalarMultiplyDelegate GetMultiScalarMultiply() => MultiScalarMultiply;

    /// <summary>Returns the reference G1 hash-to-curve delegate.</summary>
    public static G1HashToCurveDelegate GetHashToCurve() => HashToCurve;

    /// <summary>
    /// Returns the SHAKE-256 hash-to-curve delegate: the
    /// <c>BLS12381G1_XOF:SHAKE-256_SSWU_RO_</c> suite from
    /// Appendix A.1 of IETF <c>draft-irtf-cfrg-bbs-signatures-10</c>.
    /// Identical to the SHA-256 variant in every step except for
    /// <c>expand_message</c>: SHAKE-256-based <c>expand_message_xof</c>
    /// (RFC 9380 §5.3.2) in place of SHA-256-based
    /// <c>expand_message_xmd</c> (RFC 9380 §5.3.1). The SSWU map,
    /// 11-isogeny, and <c>h_eff</c> cofactor multiplier are
    /// curve-only constants and are the same for both ciphersuites.
    /// </summary>
    public static G1HashToCurveDelegate GetHashToCurveShake256() => HashToCurveShake256;

    /// <summary>Returns the reference G1 on-curve validation delegate.</summary>
    public static G1IsOnCurveDelegate GetIsOnCurve() => IsOnCurve;

    /// <summary>Returns the reference G1 prime-order-subgroup validation delegate.</summary>
    public static G1IsInPrimeOrderSubgroupDelegate GetIsInPrimeOrderSubgroup() => IsInPrimeOrderSubgroup;


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

        int pointStride = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;
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


    private static Tag HashToCurve(
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> domainSeparationTag,
        Span<byte> result,
        CurveParameterSet curve,
        Tag inboundTag)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1HashToCurve, curve);

        //RFC 9380 §8.8.1 BLS12381G1_XMD:SHA-256_SSWU_RO_
        //Two L = 64-byte field elements per hash_to_field per RFC 9380 §5.2
        //(m = 1 for G1, count = 2 for the random-oracle construction).
        Span<byte> uniform = stackalloc byte[128];
        Rfc9380ExpandMessage.ExpandMessageXmdSha256(message, domainSeparationTag, uniform);

        MapAndEncode(uniform, result);

        return ProviderInstrumentation.StampTag(
            inboundTag,
            ProviderLibraryIdentity,
            CryptoLibraryIdentity,
            ProviderClassIdentity,
            new ProviderOperation(nameof(HashToCurve)));
    }


    private static Tag HashToCurveShake256(
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> domainSeparationTag,
        Span<byte> result,
        CurveParameterSet curve,
        Tag inboundTag)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.G1HashToCurve, curve);

        //IETF draft-10 Appendix A.1 BLS12381G1_XOF:SHAKE-256_SSWU_RO_
        //L = 64 per field element, same as the SHA-256 suite; only the
        //expand_message variant changes.
        Span<byte> uniform = stackalloc byte[128];
        Rfc9380ExpandMessage.ExpandMessageXofShake256(message, domainSeparationTag, uniform);

        MapAndEncode(uniform, result);

        return ProviderInstrumentation.StampTag(
            inboundTag,
            ProviderLibraryIdentity,
            CryptoLibraryIdentity,
            ProviderClassIdentity,
            new ProviderOperation(nameof(HashToCurveShake256)));
    }


    /// <summary>
    /// Shared mapping back-end for both hash-to-curve variants: takes
    /// the 128 uniform bytes the ciphersuite-specific expand_message
    /// produced and runs the SSWU + isogeny + cofactor-clearing
    /// pipeline (Appendix E.2 / F.2 of RFC 9380 + the BLS12-381
    /// <c>h_eff</c>). The pipeline is identical between the SHA-256
    /// and SHAKE-256 ciphersuites — only the hash differs upstream.
    /// </summary>
    private static void MapAndEncode(ReadOnlySpan<byte> uniform, Span<byte> result)
    {
        BigInteger u0 = new BigInteger(uniform[..64], isUnsigned: true, isBigEndian: true) % BaseFieldPrime;
        BigInteger u1 = new BigInteger(uniform[64..128], isUnsigned: true, isBigEndian: true) % BaseFieldPrime;

        (BigInteger x0Iso, BigInteger y0Iso) = MapToCurveSimpleSwu(u0);
        (BigInteger x1Iso, BigInteger y1Iso) = MapToCurveSimpleSwu(u1);

        //R = Q0 + Q1 on the isogenous curve E'.
        (BigInteger xSumIso, BigInteger ySumIso) = AddPointsOnIsogeny(x0Iso, y0Iso, x1Iso, y1Iso);

        //P_iso → P on the BLS12-381 G1 curve via the 11-isogeny.
        (BigInteger xPreImg, BigInteger yPreImg) = IsogenyMapG1(xSumIso, ySumIso);

        //Clear cofactor by multiplying by h_eff per RFC 9380 §8.8.1
        //(same h_eff for both BLS12-381 G1 ciphersuites).
        AffinePoint preimage = new(xPreImg, yPreImg, IsInfinity: false);
        AffinePoint subgroupPoint = ScalarMultiplyPoint(HashToCurveCofactorHEff, preimage);
        Encode(subgroupPoint, result);
    }


    /// <summary>
    /// RFC 9380 §F.2 simplified SWU map onto the isogenous curve
    /// E': <c>y² = x³ + A'·x + B'</c>. Output is an affine point on E';
    /// the caller applies the 11-isogeny to land back on BLS12-381 G1.
    /// </summary>
    private static (BigInteger X, BigInteger Y) MapToCurveSimpleSwu(BigInteger u)
    {
        BigInteger uSquared = Mod(u * u, BaseFieldPrime);
        BigInteger zuSquared = Mod(SswuZ * uSquared, BaseFieldPrime);
        BigInteger zuFour = Mod(zuSquared * zuSquared, BaseFieldPrime);
        BigInteger tv1 = Mod(zuFour + zuSquared, BaseFieldPrime);

        BigInteger x1;
        if(tv1.IsZero)
        {
            //Special case: x1 = B' / (Z · A').
            BigInteger zAInverse = ModInverse(Mod(SswuZ * SswuIsoA, BaseFieldPrime));
            x1 = Mod(SswuIsoB * zAInverse, BaseFieldPrime);
        }
        else
        {
            //x1 = (-B' / A') · (1 + 1/tv1).
            BigInteger aInverse = ModInverse(SswuIsoA);
            BigInteger negBOverA = Mod(BaseFieldPrime - Mod(SswuIsoB * aInverse, BaseFieldPrime), BaseFieldPrime);
            BigInteger oneOverTv1 = ModInverse(tv1);
            x1 = Mod(negBOverA * Mod(BigInteger.One + oneOverTv1, BaseFieldPrime), BaseFieldPrime);
        }

        BigInteger gx1 = Mod(Mod(x1 * x1, BaseFieldPrime) * x1 + Mod(SswuIsoA * x1, BaseFieldPrime) + SswuIsoB, BaseFieldPrime);
        BigInteger x2 = Mod(zuSquared * x1, BaseFieldPrime);
        BigInteger gx2 = Mod(Mod(x2 * x2, BaseFieldPrime) * x2 + Mod(SswuIsoA * x2, BaseFieldPrime) + SswuIsoB, BaseFieldPrime);

        BigInteger x;
        BigInteger y;
        if(TrySqrt(gx1, out BigInteger y1))
        {
            x = x1;
            y = y1;
        }
        else if(TrySqrt(gx2, out BigInteger y2))
        {
            x = x2;
            y = y2;
        }
        else
        {
            //Should never happen — SSWU guarantees at least one of gx1, gx2 is a QR.
            throw new InvalidOperationException("SSWU map: neither gx1 nor gx2 is a quadratic residue (impossible per RFC 9380 §F.2).");
        }

        //sgn0 alignment per RFC 9380 §F.2 step 9: match y's parity to u's.
        if(((u & BigInteger.One) != BigInteger.Zero) != ((y & BigInteger.One) != BigInteger.Zero))
        {
            y = BaseFieldPrime - y;
        }


        return (x, y);
    }


    /// <summary>
    /// Affine point addition on the isogenous curve
    /// <c>y² = x³ + A'·x + B'</c>. Handles doubling when the inputs
    /// coincide and identity when they are inverses.
    /// </summary>
    private static (BigInteger X, BigInteger Y) AddPointsOnIsogeny(BigInteger x0, BigInteger y0, BigInteger x1, BigInteger y1)
    {
        if(x0 == x1)
        {
            if(y0 == y1)
            {
                BigInteger lambda = Mod(
                    Mod(3 * Mod(x0 * x0, BaseFieldPrime) + SswuIsoA, BaseFieldPrime) * ModInverse(Mod(2 * y0, BaseFieldPrime)),
                    BaseFieldPrime);
                BigInteger xResult = Mod(Mod(lambda * lambda, BaseFieldPrime) - Mod(2 * x0, BaseFieldPrime) + BaseFieldPrime, BaseFieldPrime);
                BigInteger yResult = Mod(lambda * Mod(x0 - xResult + BaseFieldPrime, BaseFieldPrime) - y0 + BaseFieldPrime, BaseFieldPrime);
                return (xResult, yResult);
            }
            //Distinct points with same x: P + (-P) = identity on E'. Vanishingly
            //unlikely for SSWU outputs of independent random u_0 / u_1 inputs.
            throw new InvalidOperationException("SSWU outputs Q_0, Q_1 sum to E' identity; cannot continue isogeny pipeline.");
        }

        BigInteger dx = Mod(x1 - x0 + BaseFieldPrime, BaseFieldPrime);
        BigInteger dy = Mod(y1 - y0 + BaseFieldPrime, BaseFieldPrime);
        BigInteger slope = Mod(dy * ModInverse(dx), BaseFieldPrime);
        BigInteger xSum = Mod(Mod(slope * slope, BaseFieldPrime) - x0 - x1 + 2 * BaseFieldPrime, BaseFieldPrime);
        BigInteger ySum = Mod(slope * Mod(x0 - xSum + BaseFieldPrime, BaseFieldPrime) - y0 + BaseFieldPrime, BaseFieldPrime);
        return (xSum, ySum);
    }


    /// <summary>
    /// 11-isogeny from <c>E'</c> back to BLS12-381 G1 per RFC 9380 §E.2.
    /// The map is rational: <c>x = xNum(x') / xDen(x')</c> and
    /// <c>y = y' · yNum(x') / yDen(x')</c> with the polynomial
    /// coefficients in <see cref="IsogenyXNumCoeffs"/> /
    /// <see cref="IsogenyXDenCoeffs"/> / <see cref="IsogenyYNumCoeffs"/>
    /// / <see cref="IsogenyYDenCoeffs"/>.
    /// </summary>
    private static (BigInteger X, BigInteger Y) IsogenyMapG1(BigInteger xIso, BigInteger yIso)
    {
        BigInteger xNum = HornerEvaluate(IsogenyXNumCoeffs, xIso);
        BigInteger xDen = HornerEvaluate(IsogenyXDenCoeffs, xIso);
        BigInteger yNum = HornerEvaluate(IsogenyYNumCoeffs, xIso);
        BigInteger yDen = HornerEvaluate(IsogenyYDenCoeffs, xIso);

        BigInteger x = Mod(xNum * ModInverse(xDen), BaseFieldPrime);
        BigInteger y = Mod(yIso * Mod(yNum * ModInverse(yDen), BaseFieldPrime), BaseFieldPrime);
        return (x, y);
    }


    /// <summary>Horner-method polynomial evaluation in Fp.</summary>
    private static BigInteger HornerEvaluate(BigInteger[] coefficients, BigInteger x)
    {
        BigInteger acc = BigInteger.Zero;
        for(int i = coefficients.Length - 1; i >= 0; i--)
        {
            acc = Mod(acc * x + coefficients[i], BaseFieldPrime);
        }

        return acc;
    }


    //RFC 9380 §8.8.1 + §E.2 constants for BLS12-381 G1 SSWU + 11-isogeny.

    /// <summary>The simplified-SWU map parameter Z = 11.</summary>
    private static readonly BigInteger SswuZ = new(11);

    /// <summary>The isogenous curve E' coefficient A'.</summary>
    private static readonly BigInteger SswuIsoA = BigInteger.Parse(
        "00144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    /// <summary>The isogenous curve E' coefficient B'.</summary>
    private static readonly BigInteger SswuIsoB = BigInteger.Parse(
        "0012e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    /// <summary>RFC 9380 §8.8.1 cofactor for clear_cofactor on BLS12-381 G1.</summary>
    private static readonly BigInteger HashToCurveCofactorHEff = BigInteger.Parse(
        "0d201000000010001",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);


    private static readonly BigInteger[] IsogenyXNumCoeffs = new[]
    {
        "011a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7",
        "017294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb",
        "00d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0",
        "01778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861",
        "00e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9",
        "01630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983",
        "00d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84",
        "017b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e",
        "0080d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317",
        "0169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e",
        "010321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b",
        "006e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229",
    }.Select(h => BigInteger.Parse(h, NumberStyles.HexNumber, CultureInfo.InvariantCulture)).ToArray();

    private static readonly BigInteger[] IsogenyXDenCoeffs = new[]
    {
        "008ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c",
        "012561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff",
        "00b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19",
        "003425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8",
        "013a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e",
        "00e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5",
        "00772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a",
        "014a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e",
        "00a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641",
        "0095fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
    }.Select(h => BigInteger.Parse(h, NumberStyles.HexNumber, CultureInfo.InvariantCulture)).ToArray();

    private static readonly BigInteger[] IsogenyYNumCoeffs = new[]
    {
        "0090d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33",
        "0134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696",
        "00cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6",
        "01f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb",
        "008cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb",
        "016603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0",
        "004ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2",
        "00987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29",
        "009fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587",
        "00e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30",
        "019713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132",
        "018b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e",
        "00b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8",
        "00245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133",
        "005c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b",
        "015e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604",
    }.Select(h => BigInteger.Parse(h, NumberStyles.HexNumber, CultureInfo.InvariantCulture)).ToArray();

    private static readonly BigInteger[] IsogenyYDenCoeffs = new[]
    {
        "016112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1",
        "01962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d",
        "0058df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2",
        "016b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416",
        "00be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d",
        "008d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac",
        "0166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c",
        "016a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9",
        "01866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a",
        "0167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55",
        "004d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8",
        "00accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092",
        "00ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc",
        "002660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7",
        "00e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
    }.Select(h => BigInteger.Parse(h, NumberStyles.HexNumber, CultureInfo.InvariantCulture)).ToArray();


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

        AffinePoint product = ScalarMultiplyPoint(ScalarFieldOrder, p);

        return product.IsInfinity;
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
    /// Jacobian projective coordinates over the BLS12-381 base field. The
    /// affine point <c>(x, y)</c> corresponds to the Jacobian triple
    /// <c>(X, Y, Z)</c> with <c>x = X / Z^2</c> and <c>y = Y / Z^3</c>; the
    /// identity is represented by <c>Z = 0</c>.
    /// </summary>
    /// <remarks>
    /// Used only as the internal accumulator for
    /// <see cref="ScalarMultiplyPoint"/>. Jacobian arithmetic has no field
    /// inversion in <see cref="JacobianDouble"/> or
    /// <see cref="JacobianAddMixed"/>, so the inner double-and-add loop pays
    /// only multiplications and additions on 381-bit values. One inversion is
    /// then required at the end to convert the result back to the canonical
    /// affine encoding the delegate contract observes.
    /// </remarks>
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

        //Walk the scalar MSB-first in Jacobian coordinates. Each inner-loop step
        //is a few base-field multiplications and additions; an affine variant
        //would instead require one base-field inversion per step (computed via
        //Fermat as a 381-bit BigInteger.ModPow, the dominant cost in this
        //reference). For [r] P with r ~ 256 bits that turns into 256 inversions
        //versus the one inversion the Jacobian path pays at the conversion
        //back to affine.
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
        //For y^2 = x^3 + b with curve parameter a = 0 (BLS12-381 G1):
        //S = 4 X Y^2, M = 3 X^2, X' = M^2 - 2S,
        //Y' = M (S - X') - 8 Y^4, Z' = 2 Y Z.
        //Standard 3M + 5S formula from the explicit-formulas database; here
        //expressed with BigInteger multiplications, no inversions.
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
        //Mixed addition: q is in affine form so its implicit Z is 1, which
        //shortens the formula vs. full Jacobian+Jacobian addition. Reduces to
        //doubling when p and q coincide; returns identity when q is -p.
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
        //The one inversion the Jacobian path pays per scalar multiplication.
        //For the identity case Z = 0 and no inversion is needed; the affine
        //representation is the standard infinity point.
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
            throw new InvalidOperationException("Input bytes do not encode a valid BLS12-381 G1 point.");
        }


        return result;
    }


    private static bool TryDecode(ReadOnlySpan<byte> bytes, out AffinePoint result)
    {
        result = default;
        if(bytes.Length != WellKnownCurves.Bls12Curve381G1CompressedSizeBytes)
        {
            return false;
        }

        byte flagByte = bytes[0];
        bool isCompressed = (flagByte & 0x80) != 0;
        bool isInfinity = (flagByte & 0x40) != 0;
        bool yParityFlag = (flagByte & 0x20) != 0;

        if(!isCompressed)
        {
            //Uncompressed encoding is not supported in batch B.
            return false;
        }

        if(isInfinity)
        {
            result = AffinePoint.Identity;
            return true;
        }

        Span<byte> xBytes = stackalloc byte[WellKnownCurves.Bls12Curve381G1CompressedSizeBytes];
        bytes.CopyTo(xBytes);

        //Mask off the three flag bits so the remainder is the canonical x-coordinate
        //big-endian encoding.
        xBytes[0] &= 0x1f;

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

        bool yIsLarger = (y << 1) > BaseFieldPrime;
        if(yParityFlag != yIsLarger)
        {
            y = BaseFieldPrime - y;
        }

        result = new AffinePoint(x, y, IsInfinity: false);

        return true;
    }


    internal static void Encode(AffinePoint point, Span<byte> destination)
    {
        if(destination.Length != WellKnownCurves.Bls12Curve381G1CompressedSizeBytes)
        {
            throw new ArgumentException(
                $"Destination must be {WellKnownCurves.Bls12Curve381G1CompressedSizeBytes} bytes; received {destination.Length}.",
                nameof(destination));
        }

        destination.Clear();
        if(point.IsInfinity)
        {
            //Compression flag plus infinity flag; remaining bytes are zero.
            destination[0] = 0xc0;
            return;
        }

        //Write x big-endian, right-aligned into the 48-byte span.
        WriteBigEndianFixed(point.X, destination);

        //Compression flag.
        destination[0] |= 0x80;

        //y-parity flag: set when y is the lexicographically larger of (y, p - y),
        //i.e. when 2y > p.
        if((point.Y << 1) > BaseFieldPrime)
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
        //BLS12-381's base field prime is prime, so Fermat's little theorem
        //gives the inverse as value^(p - 2) mod p.
        return BigInteger.ModPow(value, ModInverseExponent, BaseFieldPrime);
    }


    private static bool TrySqrt(BigInteger a, out BigInteger root)
    {
        //The BLS12-381 base field prime satisfies p ≡ 3 mod 4, so when a is a
        //quadratic residue sqrt(a) = a^((p + 1)/4) mod p. Compute that
        //candidate and verify by squaring: if (candidate^2 mod p) == a then a
        //was a QR; otherwise it was not. Fuses what would otherwise be a
        //separate Legendre-symbol ModPow plus a sqrt ModPow into a single
        //ModPow plus one multiplication-mod, halving the dominant cost on the
        //decode path.
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
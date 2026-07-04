using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Globalization;
using System.Numerics;
using Fp12Value = Lumoin.Veridical.Backends.Managed.Bls12Curve381BigIntegerFp12Reference.Fp12Value;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Reference implementation of the BLS12-381 optimal-Ate pairing
/// <c>e : G1 × G2 → GT ⊂ Fp12*</c> using <see cref="BigInteger"/>
/// arithmetic over the Fp tower built up by the H.1-H.3 references.
/// Serves as ground truth for cross-implementation tests of the
/// Miller loop, the final exponentiation, the Fp12 Frobenius, and
/// the cyclotomic squaring delegate.
/// </summary>
/// <remarks>
/// <para>
/// Pairing recipe:
/// </para>
/// <para>
/// 1. <c>f := MillerLoop(P, Q)</c> iterates the Tate-style update
///    <c>f ← f² · ell(T, T or Q, P)</c> over the binary expansion of
///    the BLS12-381 curve parameter <c>|x| = 0xd201000000010000</c>,
///    skipping its top bit (already accounted for by <c>T := Q</c>
///    and <c>f := 1</c>). Because the curve parameter is negative the
///    Miller-loop accumulator is inverted at exit.
/// </para>
/// <para>
/// 2. <c>FinalExponentiation(f)</c> raises <c>f</c> to
///    <c>(p^12 − 1)/r</c>. The decomposition
///    <c>(p^12 − 1)/r = (p^6 − 1) · (p^2 + 1) · ((p^4 − p^2 + 1)/r)</c>
///    splits into a cheap "easy" part (conjugate + invert + Frobenius²
///    + multiply) and an expensive "hard" part. The hard part is
///    computed by binary square-and-multiply with the precomputed
///    BigInteger exponent <c>(p^4 − p^2 + 1)/r</c>; correctness over
///    speed.
/// </para>
/// <para>
/// 3. Line evaluation uses the M-twist embedding for BLS12-381:
///    after multiplying through by <c>w³</c> to clear denominators,
///    <c>ell(P) = yP · 1 − λ·xP · w − ν · w³</c>, which is a "sparse"
///    Fp12 element with five non-zero Fp components. The reference
///    just builds the full Fp12 element and uses the regular Fp12
///    multiply.
/// </para>
/// <para>
/// G1 and G2 decoding helpers are inlined rather than calling the
/// existing G1 / G2 references so this file stays self-contained.
/// The complex-Fp2-sqrt formula is the same one the G2 reference uses.
/// </para>
/// </remarks>
internal static class Bls12Curve381BigIntegerPairingReference
{
    private static readonly BigInteger Prime = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;

    private const int FpComponentSize = WellKnownCurves.Bls12Curve381BaseFieldSizeBytes;
    private const int G1ElementSize = WellKnownCurves.Bls12Curve381BaseFieldSizeBytes;
    private const int G2ElementSize = WellKnownCurves.Bls12Curve381G2CompressedSizeBytes;

    /// <summary>The BLS12-381 curve parameter <c>x = −0xd201000000010000</c>; the Miller loop iterates over <c>|x|</c> and the final inversion compensates for the sign.</summary>
    /// <remarks>
    /// The leading <c>0</c> on the hex literal is load-bearing: under
    /// <see cref="NumberStyles.HexNumber"/>, a high-bit-set leading
    /// nibble (here <c>d = 0b1101</c>) would be read as a sign bit and
    /// the parse would return the two's complement of the literal.
    /// </remarks>
    internal static BigInteger CurveParameter { get; } = -BigInteger.Parse(
        "0d201000000010000",
        NumberStyles.HexNumber,
        CultureInfo.InvariantCulture);

    /// <summary>The G2 curve coefficient <c>b' = 4·(1 + u)</c> for the twist <c>y² = x³ + 4·(1 + u)</c>.</summary>
    private static readonly Fp2BigInt.Value TwistCurveB = new(new BigInteger(4), new BigInteger(4));

    //Frobenius constants — computed at static init via Fp2 exponentiation
    //rather than transcribed, so any sign mistake on ξ surfaces here as a
    //Frobenius-identity-test failure rather than a hand-typed typo.

    /// <summary>ξ^((p-1)/3) ∈ Fp2 — applied to the v-coefficient of an Fp6 Frobenius.</summary>
    private static readonly Fp2BigInt.Value FrobeniusGamma_6_1 = Fp2Pow(Fp2BigInt.NonResidue, (Bls12Curve381BigIntegerG1Reference.BaseFieldPrime - 1) / 3);

    /// <summary>ξ^(2(p-1)/3) ∈ Fp2 — applied to the v²-coefficient.</summary>
    private static readonly Fp2BigInt.Value FrobeniusGamma_6_2 = Fp2Pow(Fp2BigInt.NonResidue, 2 * (Bls12Curve381BigIntegerG1Reference.BaseFieldPrime - 1) / 3);

    /// <summary>ξ^((p-1)/6) ∈ Fp2 — applied to π(c1) · w when raising an Fp12 element to the p-th power.</summary>
    private static readonly Fp2BigInt.Value FrobeniusGamma_12_1 = Fp2Pow(Fp2BigInt.NonResidue, (Bls12Curve381BigIntegerG1Reference.BaseFieldPrime - 1) / 6);

    /// <summary>The hard-part exponent <c>(p^4 − p^2 + 1)/r</c>.</summary>
    private static readonly BigInteger HardPartExponent = ComputeHardPartExponent();


    private static BigInteger ComputeHardPartExponent()
    {
        BigInteger p = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;
        BigInteger r = Bls12Curve381BigIntegerG1Reference.ScalarFieldOrder;
        BigInteger pSquared = p * p;
        BigInteger pFourth = pSquared * pSquared;
        return (pFourth - pSquared + 1) / r;
    }


    /// <summary>Returns the reference Fp12 Frobenius delegate.</summary>
    public static Fp12FrobeniusDelegate GetFrobenius() => Frobenius;

    /// <summary>Returns the reference Fp12 cyclotomic-square delegate (reference simply forwards to generic Fp12 squaring).</summary>
    public static Fp12CyclotomicSquareDelegate GetCyclotomicSquare() => CyclotomicSquare;

    /// <summary>Returns the reference pairing delegate <c>e : G1 × G2 → Fp12</c>.</summary>
    public static PairingDelegate GetPairing() => Pairing;


    private static void Frobenius(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp12Frobenius, curve);

        Fp12Value v = Bls12Curve381BigIntegerFp12Reference.Read(a);
        Bls12Curve381BigIntegerFp12Reference.Write(result, Fp12Frobenius(v));
    }


    private static void CyclotomicSquare(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp12CyclotomicSquare, curve);

        //Reference: cyclotomic-square is identical to generic square in
        //value. Production backends will specialise for ~3× speedup.
        Fp12Value v = Bls12Curve381BigIntegerFp12Reference.Read(a);
        Bls12Curve381BigIntegerFp12Reference.Write(result, Bls12Curve381BigIntegerFp12Reference.Fp12Multiply(v, v));
    }


    private static void Pairing(ReadOnlySpan<byte> p, ReadOnlySpan<byte> q, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Pairing, curve);

        G1Affine pAffine = DecodeG1(p);
        G2Affine qAffine = DecodeG2(q);

        if(pAffine.IsInfinity || qAffine.IsInfinity)
        {
            //e(0, Q) = e(P, 0) = 1.
            Bls12Curve381BigIntegerFp12Reference.Write(result, Fp12Value.One);
            return;
        }

        Fp12Value miller = MillerLoop(pAffine, qAffine);
        Fp12Value finalExp = FinalExponentiation(miller);
        Bls12Curve381BigIntegerFp12Reference.Write(result, finalExp);
    }


    //Fp12 Frobenius — tower-structured x ↦ x^p.
    private static Fp12Value Fp12Frobenius(Fp12Value v)
    {
        Bls12Curve381BigIntegerFp6Reference.Fp6Value c0 = Fp6Frobenius(v.C0);
        Bls12Curve381BigIntegerFp6Reference.Fp6Value c1 = Fp6Frobenius(v.C1);
        //π(c1·w) = π(c1)·π(w) = π(c1) · γ_{12,1} · w; encode γ_{12,1} as an Fp6 with γ in the c0 slot.
        Bls12Curve381BigIntegerFp6Reference.Fp6Value gammaLifted = new(FrobeniusGamma_12_1, Fp2BigInt.Zero, Fp2BigInt.Zero);
        Bls12Curve381BigIntegerFp6Reference.Fp6Value c1Adjusted = Bls12Curve381BigIntegerFp6Reference.Fp6Multiply(c1, gammaLifted);
        return new Fp12Value(c0, c1Adjusted);
    }


    private static Bls12Curve381BigIntegerFp6Reference.Fp6Value Fp6Frobenius(Bls12Curve381BigIntegerFp6Reference.Fp6Value v)
    {
        //π((a0, a1, a2)) = (π(a0), γ_{6,1}·π(a1), γ_{6,2}·π(a2)).
        Fp2BigInt.Value c0 = Fp2BigInt.Conjugate(v.C0);
        Fp2BigInt.Value c1 = Fp2BigInt.Mul(FrobeniusGamma_6_1, Fp2BigInt.Conjugate(v.C1));
        Fp2BigInt.Value c2 = Fp2BigInt.Mul(FrobeniusGamma_6_2, Fp2BigInt.Conjugate(v.C2));
        return new Bls12Curve381BigIntegerFp6Reference.Fp6Value(c0, c1, c2);
    }


    //Miller loop — BLS12-381 over |x| with M-twist line evaluations.
    private static Fp12Value MillerLoop(G1Affine p, G2Affine q)
    {
        G2Affine accumulator = q;
        Fp12Value f = Fp12Value.One;

        BigInteger absX = BigInteger.Abs(CurveParameter);
        int topBit = (int)absX.GetBitLength() - 1;

        for(int i = topBit - 1; i >= 0; i--)
        {
            //Doubling step.
            (Fp2BigInt.Value lambda, G2Affine doubled) = DoubleAffinePoint(accumulator);
            Fp12Value lineDouble = LineEvaluate(accumulator, lambda, p);
            accumulator = doubled;
            f = Bls12Curve381BigIntegerFp12Reference.Fp12Multiply(f, f);
            f = Bls12Curve381BigIntegerFp12Reference.Fp12Multiply(f, lineDouble);

            //Addition step on set bit.
            if((absX & (BigInteger.One << i)) != BigInteger.Zero)
            {
                (Fp2BigInt.Value addLambda, G2Affine added) = AddAffinePoints(accumulator, q);
                Fp12Value lineAdd = LineEvaluate(accumulator, addLambda, p);
                accumulator = added;
                f = Bls12Curve381BigIntegerFp12Reference.Fp12Multiply(f, lineAdd);
            }
        }

        if(CurveParameter.Sign < 0)
        {
            f = Bls12Curve381BigIntegerFp12Reference.Fp12Invert(f);
        }


        return f;
    }


    /// <summary>Returns the slope <c>λ</c> of the tangent at <paramref name="t"/> and the doubled affine point <c>2T</c>.</summary>
    private static (Fp2BigInt.Value Lambda, G2Affine Result) DoubleAffinePoint(G2Affine t)
    {
        //λ = 3·T.x² / (2·T.y); curve coefficient a = 0 on BLS12-381 twist.
        Fp2BigInt.Value xSquared = Fp2BigInt.Square(t.X);
        Fp2BigInt.Value threeXSquared = Fp2BigInt.Add(Fp2BigInt.Add(xSquared, xSquared), xSquared);
        Fp2BigInt.Value twoY = Fp2BigInt.Add(t.Y, t.Y);
        Fp2BigInt.Value lambda = Fp2BigInt.Mul(threeXSquared, Fp2BigInt.Invert(twoY));

        Fp2BigInt.Value lambdaSquared = Fp2BigInt.Square(lambda);
        Fp2BigInt.Value xResult = Fp2BigInt.Sub(lambdaSquared, Fp2BigInt.Add(t.X, t.X));
        Fp2BigInt.Value yResult = Fp2BigInt.Sub(Fp2BigInt.Mul(lambda, Fp2BigInt.Sub(t.X, xResult)), t.Y);
        return (lambda, new G2Affine(xResult, yResult, IsInfinity: false));
    }


    /// <summary>Returns the slope <c>λ</c> of the chord through <paramref name="t"/> and <paramref name="q"/> and the sum <c>T + Q</c>.</summary>
    private static (Fp2BigInt.Value Lambda, G2Affine Result) AddAffinePoints(G2Affine t, G2Affine q)
    {
        //λ = (Q.y − T.y) / (Q.x − T.x).
        Fp2BigInt.Value dx = Fp2BigInt.Sub(q.X, t.X);
        Fp2BigInt.Value dy = Fp2BigInt.Sub(q.Y, t.Y);
        Fp2BigInt.Value lambda = Fp2BigInt.Mul(dy, Fp2BigInt.Invert(dx));

        Fp2BigInt.Value lambdaSquared = Fp2BigInt.Square(lambda);
        Fp2BigInt.Value xResult = Fp2BigInt.Sub(Fp2BigInt.Sub(lambdaSquared, t.X), q.X);
        Fp2BigInt.Value yResult = Fp2BigInt.Sub(Fp2BigInt.Mul(lambda, Fp2BigInt.Sub(t.X, xResult)), t.Y);
        return (lambda, new G2Affine(xResult, yResult, IsInfinity: false));
    }


    /// <summary>
    /// Builds the sparse-but-stored-as-dense Fp12 line value
    /// <c>yP·w³ − λ·xP·w² − ν</c> with <c>ν = T.y − λ·T.x</c>.
    /// </summary>
    /// <remarks>
    /// BLS12-381 uses the M-twist iso <c>ψ(X, Y) = (X/w², Y/w³)</c>;
    /// pulling the twist line <c>Y − λ·X − ν = 0</c> back through
    /// <c>ψ⁻¹(x, y) = (x·w², y·w³)</c> and evaluating at the G1 point
    /// <c>P = (xP, yP) ∈ Fp×Fp</c> yields the formula above. In the
    /// Fp12 = Fp6[w]/(w² − v) basis the three non-zero contributions
    /// sit at the constant-, v-, and v·w-slots respectively, so:
    /// <c>c0 = Fp6(−ν, −λ·xP, 0)</c>, <c>c1 = Fp6(0, yP, 0)</c>.
    /// </remarks>
    private static Fp12Value LineEvaluate(G2Affine t, Fp2BigInt.Value lambda, G1Affine p)
    {
        Fp2BigInt.Value nu = Fp2BigInt.Sub(t.Y, Fp2BigInt.Mul(lambda, t.X));

        //(yP) lifted into Fp2 as (yP, 0).
        Fp2BigInt.Value yPLifted = new(p.Y, BigInteger.Zero);
        //(-λ · xP) ∈ Fp2; xP ∈ Fp scales both Fp2 components of λ.
        Fp2BigInt.Value negLambdaXp = Fp2BigInt.Neg(new Fp2BigInt.Value((lambda.C0 * p.X) % Prime, (lambda.C1 * p.X) % Prime));
        Fp2BigInt.Value negNu = Fp2BigInt.Neg(nu);

        //ell = -ν + (-λ·xP)·w² + yP·w³, in the Fp12 = Fp6[w] basis with w² = v.
        //Slot map: w⁰ → c0.c0, w² → c0.c1, w³ → c1.c1.
        Bls12Curve381BigIntegerFp6Reference.Fp6Value c0 = new(negNu, negLambdaXp, Fp2BigInt.Zero);
        Bls12Curve381BigIntegerFp6Reference.Fp6Value c1 = new(Fp2BigInt.Zero, yPLifted, Fp2BigInt.Zero);
        return new Fp12Value(c0, c1);
    }


    //Final exponentiation — (p^12 − 1)/r as easy · hard.
    private static Fp12Value FinalExponentiation(Fp12Value f)
    {
        //Easy part: f^(p^6 - 1) · (p^2 + 1).
        //f^(p^6 - 1) = f^(p^6) · f^-1 = Conjugate(f) · Invert(f).
        Fp12Value conjF = Bls12Curve381BigIntegerFp12Reference.Fp12Conjugate(f);
        Fp12Value invF = Bls12Curve381BigIntegerFp12Reference.Fp12Invert(f);
        Fp12Value m1 = Bls12Curve381BigIntegerFp12Reference.Fp12Multiply(conjF, invF);

        //f^(p^2 + 1) on m1 = Frobenius²(m1) · m1.
        Fp12Value frobSquared = Fp12Frobenius(Fp12Frobenius(m1));
        Fp12Value m2 = Bls12Curve381BigIntegerFp12Reference.Fp12Multiply(frobSquared, m1);

        //Hard part: m2^((p^4 - p^2 + 1)/r) via square-and-multiply.
        return Fp12Pow(m2, HardPartExponent);
    }


    /// <summary>Binary square-and-multiply over Fp12; exponent is positive in our uses (hard-part final exponentiation).</summary>
    private static Fp12Value Fp12Pow(Fp12Value baseValue, BigInteger exponent)
    {
        Fp12Value result = Fp12Value.One;
        Fp12Value current = baseValue;
        BigInteger e = exponent;
        while(e > BigInteger.Zero)
        {
            if((e & BigInteger.One) == BigInteger.One)
            {
                result = Bls12Curve381BigIntegerFp12Reference.Fp12Multiply(result, current);
            }
            e >>= 1;
            if(e > BigInteger.Zero)
            {
                current = Bls12Curve381BigIntegerFp12Reference.Fp12Multiply(current, current);
            }
        }

        return result;
    }


    //Fp2 exponentiation — for Frobenius-constant computation at init.
    private static Fp2BigInt.Value Fp2Pow(Fp2BigInt.Value baseValue, BigInteger exponent)
    {
        Fp2BigInt.Value result = Fp2BigInt.One;
        Fp2BigInt.Value current = baseValue;
        BigInteger e = exponent;
        while(e > BigInteger.Zero)
        {
            if((e & BigInteger.One) == BigInteger.One)
            {
                result = Fp2BigInt.Mul(result, current);
            }
            e >>= 1;
            if(e > BigInteger.Zero)
            {
                current = Fp2BigInt.Square(current);
            }
        }

        return result;
    }


    //G1 / G2 affine decode (inline, minimal — re-uses the complex Fp2
    //sqrt formula from the H.2 G2 reference).

    /// <summary>An affine G1 point over Fp.</summary>
    internal readonly record struct G1Affine(BigInteger X, BigInteger Y, bool IsInfinity);

    /// <summary>An affine G2 point over Fp2 (on the twist curve).</summary>
    internal readonly record struct G2Affine(Fp2BigInt.Value X, Fp2BigInt.Value Y, bool IsInfinity);


    private static G1Affine DecodeG1(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length != G1ElementSize)
        {
            throw new ArgumentException($"G1 byte span must be {G1ElementSize} bytes; received {bytes.Length}.", nameof(bytes));
        }

        byte headerByte = bytes[0];
        bool isInfinity = (headerByte & 0x40) != 0;
        bool yParity = (headerByte & 0x20) != 0;

        if(isInfinity)
        {
            //The canonical identity encoding is exactly the compression and infinity
            //flags set with every other bit zero. Any other infinity-flagged pattern
            //is non-canonical and rejected rather than aliased onto the identity.
            if(headerByte != 0xC0 || bytes[1..].IndexOfAnyExcept((byte)0) >= 0)
            {
                throw new InvalidOperationException("Non-canonical BLS12-381 G1 infinity encoding.");
            }

            return new G1Affine(BigInteger.Zero, BigInteger.Zero, IsInfinity: true);
        }

        Span<byte> xBytes = stackalloc byte[G1ElementSize];
        bytes.CopyTo(xBytes);
        xBytes[0] &= 0x1f;
        BigInteger x = new(xBytes, isUnsigned: true, isBigEndian: true);
        if(x >= Prime)
        {
            //A masked x at or above the base-field prime is a non-canonical encoding;
            //reject it rather than reduce it, matching the G1 reference TryDecode boundary.
            throw new InvalidOperationException("Non-canonical BLS12-381 G1 x-coordinate.");
        }

        //y = ±sqrt(x³ + 4) in Fp; sign determined by ZCash sgn0 (2y > p ↔ parity = 1).
        BigInteger xCubed = (x * x % Prime) * x % Prime;
        BigInteger rhs = (xCubed + 4) % Prime;
        if(!TryModSqrtFp(rhs, out BigInteger ySqrt))
        {
            //rhs is a quadratic non-residue, so x is not the abscissa of any curve point.
            //ModSqrtFp is the a^((p+1)/4) shortcut that returns a value for every input;
            //verifying the root squares back rejects an off-curve x instead of decoding
            //it to a bogus point that the pairing would then consume.
            throw new InvalidOperationException("BLS12-381 G1 point is not on the curve.");
        }

        BigInteger otherY = (Prime - ySqrt) % Prime;
        bool sqrtParity = (2 * ySqrt) > Prime;
        BigInteger y = (sqrtParity == yParity) ? ySqrt : otherY;

        return new G1Affine(x, y, IsInfinity: false);
    }


    private static G2Affine DecodeG2(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length != G2ElementSize)
        {
            throw new ArgumentException($"G2 byte span must be {G2ElementSize} bytes; received {bytes.Length}.", nameof(bytes));
        }

        byte headerByte = bytes[0];
        bool isInfinity = (headerByte & 0x40) != 0;
        bool yParity = (headerByte & 0x20) != 0;

        if(isInfinity)
        {
            //The canonical identity encoding is exactly the compression and infinity
            //flags set with every other bit zero. Any other infinity-flagged pattern
            //is non-canonical and rejected rather than aliased onto the identity.
            if(headerByte != 0xC0 || bytes[1..].IndexOfAnyExcept((byte)0) >= 0)
            {
                throw new InvalidOperationException("Non-canonical BLS12-381 G2 infinity encoding.");
            }

            return new G2Affine(Fp2BigInt.Zero, Fp2BigInt.Zero, IsInfinity: true);
        }

        //Layout: [x.c1 : 48 BE][x.c0 : 48 BE] with flag bits in byte 0 (top of c1).
        Span<byte> c1Bytes = stackalloc byte[FpComponentSize];
        bytes[..FpComponentSize].CopyTo(c1Bytes);
        c1Bytes[0] &= 0x1f;
        BigInteger xC1 = new(c1Bytes, isUnsigned: true, isBigEndian: true);
        BigInteger xC0 = new(bytes.Slice(FpComponentSize, FpComponentSize), isUnsigned: true, isBigEndian: true);
        if(xC1 >= Prime || xC0 >= Prime)
        {
            //Either Fp2 component at or above the base-field prime is non-canonical;
            //reject rather than reduce, matching the G2 reference TryDecode boundary.
            throw new InvalidOperationException("Non-canonical BLS12-381 G2 x-coordinate.");
        }

        Fp2BigInt.Value x = new(xC0, xC1);

        //y² = x³ + 4·(1 + u).
        Fp2BigInt.Value xSquared = Fp2BigInt.Square(x);
        Fp2BigInt.Value xCubed = Fp2BigInt.Mul(xSquared, x);
        Fp2BigInt.Value rhs = Fp2BigInt.Add(xCubed, TwistCurveB);

        if(!TryModSqrtFp2(rhs, out Fp2BigInt.Value ySqrt))
        {
            //rhs is not a quadratic residue in Fp2, so x is not the abscissa of any
            //twist-curve point. Reject instead of decoding to an off-curve point.
            throw new InvalidOperationException("BLS12-381 G2 point is not on the curve.");
        }

        Fp2BigInt.Value otherY = Fp2BigInt.Neg(ySqrt);

        bool sqrtParity = Fp2YParityZcash(ySqrt);
        Fp2BigInt.Value y = (sqrtParity == yParity) ? ySqrt : otherY;

        return new G2Affine(x, y, IsInfinity: false);
    }


    /// <summary>Square root in Fp using the p ≡ 3 (mod 4) shortcut <c>a^((p+1)/4)</c>.</summary>
    private static BigInteger ModSqrtFp(BigInteger a)
    {
        BigInteger exp = (Prime + 1) >> 2;
        return BigInteger.ModPow(a, exp, Prime);
    }


    /// <summary>
    /// Square root in Fp with square-back verification. Returns <see langword="false"/>
    /// when <paramref name="a"/> is a quadratic non-residue, so a decoder rejects an
    /// off-curve abscissa instead of accepting the a^((p+1)/4) shortcut's bogus output.
    /// </summary>
    private static bool TryModSqrtFp(BigInteger a, out BigInteger root)
    {
        if(a.IsZero)
        {
            root = BigInteger.Zero;

            return true;
        }

        BigInteger candidate = ModSqrtFp(a);
        if(candidate * candidate % Prime != a)
        {
            root = BigInteger.Zero;

            return false;
        }

        root = candidate;

        return true;
    }


    /// <summary>
    /// Square root in Fp2 with square-back verification, mirroring the G2 reference
    /// decode path: the field has q = p² ≡ 1 mod 4 so the simple (q+1)/4 shortcut does
    /// not apply; reduce to Fp square roots via the complex-conjugate norm and return
    /// <see langword="false"/> when <paramref name="a"/> is a non-residue. Handles the
    /// pure-real and pure-imaginary axes the naive complex formula alone mishandles.
    /// </summary>
    private static bool TryModSqrtFp2(Fp2BigInt.Value a, out Fp2BigInt.Value root)
    {
        if(Fp2BigInt.IsZero(a))
        {
            root = Fp2BigInt.Zero;

            return true;
        }

        if(a.C1.IsZero)
        {
            //Pure-real case: y² = a.c0 is either an Fp residue (y on the real axis) or
            //−a.c0 is (y on the imaginary axis, since (i·c)² = −c² with u² = −1).
            if(TryModSqrtFp(a.C0, out BigInteger realRoot))
            {
                root = new Fp2BigInt.Value(realRoot, BigInteger.Zero);

                return true;
            }

            if(TryModSqrtFp(Mod(-a.C0), out BigInteger imaginaryRoot))
            {
                root = new Fp2BigInt.Value(BigInteger.Zero, imaginaryRoot);

                return true;
            }

            root = Fp2BigInt.Zero;

            return false;
        }

        BigInteger norm = Mod((a.C0 * a.C0) + (a.C1 * a.C1));
        if(!TryModSqrtFp(norm, out BigInteger alpha))
        {
            root = Fp2BigInt.Zero;

            return false;
        }

        BigInteger twoInverse = ModInverse(BigInteger.One + BigInteger.One);
        BigInteger x0;
        if(!TryModSqrtFp(Mod((a.C0 + alpha) * twoInverse), out x0))
        {
            //Exactly one of (a.c0 ± α)/2 is an Fp residue for p ≡ 3 mod 4.
            if(!TryModSqrtFp(Mod((a.C0 - alpha) * twoInverse), out x0))
            {
                root = Fp2BigInt.Zero;

                return false;
            }
        }

        BigInteger twoX0Inverse = ModInverse(Mod(x0 + x0));
        BigInteger x1 = Mod(a.C1 * twoX0Inverse);
        root = new Fp2BigInt.Value(x0, x1);

        return true;
    }


    private static BigInteger Mod(BigInteger value)
    {
        BigInteger result = value % Prime;
        if(result.Sign < 0)
        {
            result += Prime;
        }

        return result;
    }


    /// <summary>ZCash-style Fp2 y-parity: <c>2·y > p</c> using the lex test on (c0, c1).</summary>
    private static bool Fp2YParityZcash(Fp2BigInt.Value y)
    {
        if(!y.C1.IsZero)
        {
            return (2 * y.C1) > Prime;
        }

        return (2 * y.C0) > Prime;
    }


    private static BigInteger ModInverse(BigInteger a)
    {
        return BigInteger.ModPow(((a % Prime) + Prime) % Prime, Prime - 2, Prime);
    }


}
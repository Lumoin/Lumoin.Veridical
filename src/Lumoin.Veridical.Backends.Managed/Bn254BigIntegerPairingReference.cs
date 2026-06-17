using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Numerics;
using Fp2 = Lumoin.Veridical.Backends.Managed.Bn254Fp2BigInt.Value;
using Fp6 = Lumoin.Veridical.Backends.Managed.Bn254BigIntegerFp6Reference.Fp6Value;
using Fp12 = Lumoin.Veridical.Backends.Managed.Bn254BigIntegerFp12Reference.Fp12Value;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Reference implementation of the BN254 (alt_bn128) optimal-ate pairing
/// <c>e : G1 × G2 → GT ⊂ Fp12*</c> using <see cref="BigInteger"/> arithmetic
/// over the U.4 field tower. Ground truth for the pairing, the Fp12 Frobenius,
/// and the cyclotomic-square delegate. Parallel in role to
/// <see cref="Bls12Curve381BigIntegerPairingReference"/>; the differences are
/// the ones BN254 forces (see <c>PAIRING.md</c>).
/// </summary>
/// <remarks>
/// <para>
/// <b>Miller loop:</b> the optimal-ate loop runs over <c>6u + 2</c> with the BN
/// parameter <c>u = 4965661367192848881</c> (alt_bn128). <c>6u + 2</c> is
/// positive here, so — unlike BLS12-381's negative <c>x</c> — there is no final
/// inversion and no sign-bit trap on the loop count. After the main loop the
/// two BN-specific Frobenius steps run: <c>f · ℓ(T, π(Q)) · ℓ(T, −π²(Q))</c>.
/// </para>
/// <para>
/// <b>D-twist:</b> BN254 G2 is the D-twist (<c>b' = 3/(9+u)</c>). G2 points are
/// untwisted into <c>E(Fp12)</c> via <c>ψ(x', y') = (w²·x', w³·y')</c> (derived
/// in U.5 and validated against py_ecc) and the Miller loop runs the textbook
/// chord-and-tangent line evaluation entirely in Fp12. This deliberately
/// avoids the sparse-line slot placement that the BLS12-381 reference uses:
/// the slot map is the single most error-prone part of a twisted pairing, and
/// the full-Fp12 line evaluation is unambiguous at the cost of speed
/// (acceptable for a reference). The twist convention is therefore exercised
/// only in <c>ψ</c>, in one place.
/// </para>
/// <para>
/// <b>Final exponentiation:</b> <c>(p¹² − 1)/r = (p⁶ − 1)·(p² + 1)·((p⁴ − p² + 1)/r)</c>.
/// The easy part is conjugate · invert then Frobenius² · self; the hard part is
/// the precomputed BigInteger exponent <c>(p⁴ − p² + 1)/r</c> by
/// square-and-multiply (correctness over the BN addition chain).
/// </para>
/// <para>
/// The Fp12 Frobenius uses the γ-constants <c>ξ^((p−1)/3)</c>,
/// <c>ξ^(2(p−1)/3)</c>, <c>ξ^((p−1)/6)</c>, computed at static init from
/// <c>ξ = 9 + u</c> rather than transcribed, so a wrong ξ surfaces as a
/// Frobenius-identity failure rather than a typo.
/// </para>
/// </remarks>
internal static class Bn254BigIntegerPairingReference
{
    private static readonly BigInteger Prime = Bn254BigIntegerG1Reference.BaseFieldPrime;
    private static readonly BigInteger Order = Bn254BigIntegerG1Reference.ScalarFieldOrder;

    private const int FpComponentSize = WellKnownCurves.Bn254BaseFieldSizeBytes;
    private const int G1CompressedSize = WellKnownCurves.Bn254G1CompressedSizeBytes;
    private const int G2CompressedSize = WellKnownCurves.Bn254G2CompressedSizeBytes;

    /// <summary>The BN parameter <c>u = 4965661367192848881</c>; the optimal-ate loop count is <c>6u + 2</c>.</summary>
    internal static BigInteger BnParameter { get; } = new(4965661367192848881L);

    /// <summary>The optimal-ate Miller-loop count <c>6u + 2</c> — positive, so no final inversion.</summary>
    internal static BigInteger AteLoopCount { get; } = (6 * BnParameter) + 2;

    /// <summary>The D-twist coefficient <c>b' = 3/(9 + u)</c>.</summary>
    private static readonly Fp2 TwistCurveB = Bn254Fp2BigInt.Mul(new Fp2(new BigInteger(3), BigInteger.Zero), Bn254Fp2BigInt.Invert(Bn254Fp2BigInt.NonResidue));

    //Frobenius γ-constants, computed from ξ at static init.
    private static readonly Fp2 FrobeniusGamma61 = Fp2Pow(Bn254Fp2BigInt.NonResidue, (Prime - 1) / 3);
    private static readonly Fp2 FrobeniusGamma62 = Fp2Pow(Bn254Fp2BigInt.NonResidue, 2 * (Prime - 1) / 3);
    private static readonly Fp2 FrobeniusGamma121 = Fp2Pow(Bn254Fp2BigInt.NonResidue, (Prime - 1) / 6);

    private static readonly BigInteger HardPartExponent = ComputeHardPartExponent();

    //w, w², w³ in Fp12 for the D-twist untwist map.
    private static readonly Fp12 W = new(Fp6.Zero, Fp6.One);
    private static readonly Fp12 W2 = Bn254BigIntegerFp12Reference.Fp12Multiply(W, W);
    private static readonly Fp12 W3 = Bn254BigIntegerFp12Reference.Fp12Multiply(W2, W);


    private static BigInteger ComputeHardPartExponent()
    {
        BigInteger pSquared = Prime * Prime;
        BigInteger pFourth = pSquared * pSquared;
        return (pFourth - pSquared + 1) / Order;
    }


    /// <summary>Returns the reference Fp12 Frobenius delegate.</summary>
    public static Fp12FrobeniusDelegate GetFrobenius() => Frobenius;

    /// <summary>Returns the reference Fp12 cyclotomic-square delegate (forwards to generic Fp12 squaring, as the BLS reference does).</summary>
    public static Fp12CyclotomicSquareDelegate GetCyclotomicSquare() => CyclotomicSquare;

    /// <summary>Returns the reference pairing delegate <c>e : G1 × G2 → Fp12</c>.</summary>
    public static PairingDelegate GetPairing() => Pairing;


    private static void Frobenius(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp12Frobenius, curve);

        Fp12 v = Bn254BigIntegerFp12Reference.Read(a);
        Bn254BigIntegerFp12Reference.Write(result, Fp12Frobenius(v));
    }


    private static void CyclotomicSquare(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp12CyclotomicSquare, curve);

        Fp12 v = Bn254BigIntegerFp12Reference.Read(a);
        Bn254BigIntegerFp12Reference.Write(result, Bn254BigIntegerFp12Reference.Fp12Multiply(v, v));
    }


    private static void Pairing(ReadOnlySpan<byte> p, ReadOnlySpan<byte> q, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Pairing, curve);

        (BigInteger px, BigInteger py, bool pInf) = DecodeG1(p);
        (Fp2 qx, Fp2 qy, bool qInf) = DecodeG2(q);

        if(pInf || qInf)
        {
            Bn254BigIntegerFp12Reference.Write(result, Fp12.One);
            return;
        }

        Fp12 miller = MillerLoop(px, py, qx, qy);
        Bn254BigIntegerFp12Reference.Write(result, FinalExponentiation(miller));
    }


    //------------------------------------------------------------------
    //Fp12 Frobenius (γ-constant tower form), and Fp6/Fp2 sub-steps.
    //------------------------------------------------------------------
    private static Fp12 Fp12Frobenius(Fp12 v)
    {
        Fp6 c0 = Fp6Frobenius(v.C0);
        Fp6 c1 = Fp6Frobenius(v.C1);
        Fp6 gammaLifted = new(FrobeniusGamma121, Bn254Fp2BigInt.Zero, Bn254Fp2BigInt.Zero);
        Fp6 c1Adjusted = Bn254BigIntegerFp6Reference.Fp6Multiply(c1, gammaLifted);
        return new Fp12(c0, c1Adjusted);
    }


    private static Fp6 Fp6Frobenius(Fp6 v)
    {
        Fp2 c0 = Fp2Conjugate(v.C0);
        Fp2 c1 = Bn254Fp2BigInt.Mul(FrobeniusGamma61, Fp2Conjugate(v.C1));
        Fp2 c2 = Bn254Fp2BigInt.Mul(FrobeniusGamma62, Fp2Conjugate(v.C2));
        return new Fp6(c0, c1, c2);
    }


    private static Fp2 Fp2Conjugate(Fp2 a) => new(a.C0, Mod(-a.C1));


    //------------------------------------------------------------------
    //Optimal-ate Miller loop in full Fp12.
    //------------------------------------------------------------------
    private readonly record struct Fp12Point(Fp12 X, Fp12 Y);


    private static Fp12 MillerLoop(BigInteger px, BigInteger py, Fp2 qx, Fp2 qy)
    {
        Fp12Point pPoint = new(EmbedFp(px), EmbedFp(py));
        Fp12Point qPoint = new(Bn254BigIntegerFp12Reference.Fp12Multiply(W2, EmbedFp2(qx)), Bn254BigIntegerFp12Reference.Fp12Multiply(W3, EmbedFp2(qy)));

        Fp12 f = Fp12.One;
        Fp12Point t = qPoint;

        int topBit = (int)AteLoopCount.GetBitLength() - 1;
        for(int i = topBit - 1; i >= 0; i--)
        {
            (Fp12 lambda, Fp12Point doubled) = DoublePoint(t);
            f = Fp12Multiply(Fp12Square(f), LineAt(t, lambda, pPoint));
            t = doubled;

            if((AteLoopCount & (BigInteger.One << i)) != BigInteger.Zero)
            {
                (Fp12 addLambda, Fp12Point added) = ChordPoint(t, qPoint);
                f = Fp12Multiply(f, LineAt(t, addLambda, pPoint));
                t = added;
            }
        }

        //BN optimal-ate Frobenius steps: f · ℓ(T, π(Q)) · ℓ(T, −π²(Q)).
        Fp12Point q1 = FrobeniusPoint(qPoint);
        Fp12Point q2 = FrobeniusPoint(q1);

        (Fp12 l1, Fp12Point t1) = ChordPoint(t, q1);
        f = Fp12Multiply(f, LineAt(t, l1, pPoint));
        t = t1;

        Fp12Point negQ2 = new(q2.X, Fp12Negate(q2.Y));
        (Fp12 l2, Fp12Point t2) = ChordPoint(t, negQ2);
        f = Fp12Multiply(f, LineAt(t, l2, pPoint));

        return f;
    }


    private static (Fp12 Lambda, Fp12Point Result) DoublePoint(Fp12Point t)
    {
        //λ = 3X² / 2Y; curve coefficient a = 0.
        Fp12 xSquared = Fp12Square(t.X);
        Fp12 numerator = Fp12Add(Fp12Add(xSquared, xSquared), xSquared);
        Fp12 denominator = Fp12Add(t.Y, t.Y);
        Fp12 lambda = Fp12Multiply(numerator, Bn254BigIntegerFp12Reference.Fp12Invert(denominator));

        Fp12 xResult = Fp12Subtract(Fp12Square(lambda), Fp12Add(t.X, t.X));
        Fp12 yResult = Fp12Subtract(Fp12Multiply(lambda, Fp12Subtract(t.X, xResult)), t.Y);
        return (lambda, new Fp12Point(xResult, yResult));
    }


    private static (Fp12 Lambda, Fp12Point Result) ChordPoint(Fp12Point t, Fp12Point other)
    {
        Fp12 dx = Fp12Subtract(other.X, t.X);
        Fp12 dy = Fp12Subtract(other.Y, t.Y);
        Fp12 lambda = Fp12Multiply(dy, Bn254BigIntegerFp12Reference.Fp12Invert(dx));

        Fp12 xResult = Fp12Subtract(Fp12Subtract(Fp12Square(lambda), t.X), other.X);
        Fp12 yResult = Fp12Subtract(Fp12Multiply(lambda, Fp12Subtract(t.X, xResult)), t.Y);
        return (lambda, new Fp12Point(xResult, yResult));
    }


    /// <summary>The line through <paramref name="t"/> with slope <paramref name="lambda"/> evaluated at <paramref name="p"/>: <c>(yP − yT) − λ(xP − xT)</c>.</summary>
    private static Fp12 LineAt(Fp12Point t, Fp12 lambda, Fp12Point p)
    {
        return Fp12Subtract(Fp12Subtract(p.Y, t.Y), Fp12Multiply(lambda, Fp12Subtract(p.X, t.X)));
    }


    private static Fp12Point FrobeniusPoint(Fp12Point p) => new(Fp12Frobenius(p.X), Fp12Frobenius(p.Y));


    //------------------------------------------------------------------
    //Final exponentiation.
    //------------------------------------------------------------------
    private static Fp12 FinalExponentiation(Fp12 f)
    {
        //Easy part: f^(p^6 - 1) = conj(f) · inv(f), then f^(p^2 + 1) = Frob²·self.
        Fp12 m1 = Bn254BigIntegerFp12Reference.Fp12Multiply(
            Bn254BigIntegerFp12Reference.Fp12Conjugate(f),
            Bn254BigIntegerFp12Reference.Fp12Invert(f));
        Fp12 m2 = Bn254BigIntegerFp12Reference.Fp12Multiply(Fp12Frobenius(Fp12Frobenius(m1)), m1);

        //Hard part by square-and-multiply.
        return Fp12Pow(m2, HardPartExponent);
    }


    private static Fp12 Fp12Pow(Fp12 baseValue, BigInteger exponent)
    {
        Fp12 result = Fp12.One;
        Fp12 current = baseValue;
        BigInteger e = exponent;
        while(e > BigInteger.Zero)
        {
            if((e & BigInteger.One) == BigInteger.One)
            {
                result = Bn254BigIntegerFp12Reference.Fp12Multiply(result, current);
            }
            e >>= 1;
            if(e > BigInteger.Zero)
            {
                current = Bn254BigIntegerFp12Reference.Fp12Multiply(current, current);
            }
        }

        return result;
    }


    private static Fp2 Fp2Pow(Fp2 baseValue, BigInteger exponent)
    {
        Fp2 result = Bn254Fp2BigInt.One;
        Fp2 current = baseValue;
        BigInteger e = exponent;
        while(e > BigInteger.Zero)
        {
            if((e & BigInteger.One) == BigInteger.One)
            {
                result = Bn254Fp2BigInt.Mul(result, current);
            }
            e >>= 1;
            if(e > BigInteger.Zero)
            {
                current = Bn254Fp2BigInt.Square(current);
            }
        }

        return result;
    }


    //------------------------------------------------------------------
    //Fp12 helpers built on the tower references.
    //------------------------------------------------------------------
    private static Fp12 Fp12Multiply(Fp12 a, Fp12 b) => Bn254BigIntegerFp12Reference.Fp12Multiply(a, b);
    private static Fp12 Fp12Square(Fp12 a) => Bn254BigIntegerFp12Reference.Fp12Multiply(a, a);
    private static Fp12 Fp12Add(Fp12 a, Fp12 b) => new(Bn254BigIntegerFp6Reference.Fp6Add(a.C0, b.C0), Bn254BigIntegerFp6Reference.Fp6Add(a.C1, b.C1));
    private static Fp12 Fp12Subtract(Fp12 a, Fp12 b) => new(Bn254BigIntegerFp6Reference.Fp6Sub(a.C0, b.C0), Bn254BigIntegerFp6Reference.Fp6Sub(a.C1, b.C1));
    private static Fp12 Fp12Negate(Fp12 a) => new(Bn254BigIntegerFp6Reference.Fp6Neg(a.C0), Bn254BigIntegerFp6Reference.Fp6Neg(a.C1));


    /// <summary>Lifts an Fp value into Fp12 (constant slot).</summary>
    private static Fp12 EmbedFp(BigInteger a) => new(new Fp6(new Fp2(Mod(a), BigInteger.Zero), Bn254Fp2BigInt.Zero, Bn254Fp2BigInt.Zero), Fp6.Zero);

    /// <summary>Lifts an Fp2 value into Fp12 (constant slot).</summary>
    private static Fp12 EmbedFp2(Fp2 z) => new(new Fp6(z, Bn254Fp2BigInt.Zero, Bn254Fp2BigInt.Zero), Fp6.Zero);


    //------------------------------------------------------------------
    //G1 / G2 decode (gnark big-endian compressed, mirroring U.3/U.5).
    //------------------------------------------------------------------
    private static (BigInteger X, BigInteger Y, bool IsInfinity) DecodeG1(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length != G1CompressedSize)
        {
            throw new ArgumentException($"G1 byte span must be {G1CompressedSize} bytes; received {bytes.Length}.", nameof(bytes));
        }

        int tag = bytes[0] & 0xC0;
        if(tag == 0x40)
        {
            return (BigInteger.Zero, BigInteger.Zero, true);
        }

        bool wantLarger = tag == 0xC0;
        Span<byte> xBytes = stackalloc byte[G1CompressedSize];
        bytes.CopyTo(xBytes);
        xBytes[0] &= 0x3f;
        BigInteger x = new(xBytes, isUnsigned: true, isBigEndian: true);

        BigInteger rhs = Mod((Mod(x * x) * x) + 3);
        BigInteger y = ModSqrtFp(rhs);
        bool yIsLarger = (y << 1) > Prime;
        if(yIsLarger != wantLarger)
        {
            y = Mod(-y);
        }

        return (x, y, false);
    }


    private static (Fp2 X, Fp2 Y, bool IsInfinity) DecodeG2(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length != G2CompressedSize)
        {
            throw new ArgumentException($"G2 byte span must be {G2CompressedSize} bytes; received {bytes.Length}.", nameof(bytes));
        }

        int tag = bytes[0] & 0xC0;
        if(tag == 0x40)
        {
            return (Bn254Fp2BigInt.Zero, Bn254Fp2BigInt.Zero, true);
        }

        bool wantLarger = tag == 0xC0;
        Span<byte> c1Bytes = stackalloc byte[FpComponentSize];
        bytes[..FpComponentSize].CopyTo(c1Bytes);
        c1Bytes[0] &= 0x3f;
        BigInteger xC1 = new(c1Bytes, isUnsigned: true, isBigEndian: true);
        BigInteger xC0 = new(bytes.Slice(FpComponentSize, FpComponentSize), isUnsigned: true, isBigEndian: true);
        Fp2 x = new(xC0, xC1);

        Fp2 rhs = Bn254Fp2BigInt.Add(Bn254Fp2BigInt.Mul(Bn254Fp2BigInt.Square(x), x), TwistCurveB);
        Fp2 y = ModSqrtFp2(rhs);
        if(Fp2IsLarger(y) != wantLarger)
        {
            y = Bn254Fp2BigInt.Neg(y);
        }

        return (x, y, false);
    }


    private static BigInteger ModSqrtFp(BigInteger a) => BigInteger.ModPow(a, (Prime + 1) >> 2, Prime);


    private static Fp2 ModSqrtFp2(Fp2 a)
    {
        if(Bn254Fp2BigInt.IsZero(a))
        {
            return Bn254Fp2BigInt.Zero;
        }

        BigInteger norm = Mod((a.C0 * a.C0) + (a.C1 * a.C1));
        BigInteger alpha = ModSqrtFp(norm);
        BigInteger twoInverse = BigInteger.ModPow(new BigInteger(2), Prime - 2, Prime);
        BigInteger delta = Mod((a.C0 + alpha) * twoInverse);
        if(BigInteger.ModPow(delta, (Prime - 1) / 2, Prime) != BigInteger.One)
        {
            delta = Mod((a.C0 - alpha) * twoInverse);
        }
        BigInteger c0 = ModSqrtFp(delta);
        BigInteger c1 = Mod(a.C1 * BigInteger.ModPow(Mod(c0 + c0), Prime - 2, Prime));
        return new Fp2(c0, c1);
    }


    private static bool Fp2IsLarger(Fp2 y)
    {
        if(y.C1.IsZero)
        {
            return (y.C0 << 1) > Prime;
        }

        return (y.C1 << 1) > Prime;
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
}

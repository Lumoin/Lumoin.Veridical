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
/// over the Fp12 field tower. Ground truth for the pairing, the Fp12 Frobenius,
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
/// and validated against py_ecc) and the Miller loop runs the textbook
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
    /// <summary>The BN254 base-field prime.</summary>
    private static BigInteger Prime { get; } = Bn254BigIntegerG1Reference.BaseFieldPrime;
    /// <summary>The BN254 scalar-field order.</summary>
    private static BigInteger Order { get; } = Bn254BigIntegerG1Reference.ScalarFieldOrder;

    /// <summary>The byte width of one Fp component in the compressed point encodings.</summary>
    private const int FpComponentSize = WellKnownCurves.Bn254BaseFieldSizeBytes;
    /// <summary>The byte length of a compressed BN254 G1 point.</summary>
    private const int G1CompressedSize = WellKnownCurves.Bn254G1CompressedSizeBytes;
    /// <summary>The byte length of a compressed BN254 G2 point.</summary>
    private const int G2CompressedSize = WellKnownCurves.Bn254G2CompressedSizeBytes;

    /// <summary>The BN parameter <c>u = 4965661367192848881</c>; the optimal-ate loop count is <c>6u + 2</c>.</summary>
    internal static BigInteger BnParameter { get; } = new(4965661367192848881L);

    /// <summary>The optimal-ate Miller-loop count <c>6u + 2</c> — positive, so no final inversion.</summary>
    internal static BigInteger AteLoopCount { get; } = (6 * BnParameter) + 2;

    /// <summary>The D-twist coefficient <c>b' = 3/(9 + u)</c>.</summary>
    private static Fp2 TwistCurveB { get; } = Bn254Fp2BigInt.Mul(new Fp2(new BigInteger(3), BigInteger.Zero), Bn254Fp2BigInt.Invert(Bn254Fp2BigInt.NonResidue));

    /// <summary>The Frobenius γ-constant <c>ξ^((p−1)/3)</c> used in the Fp6 Frobenius, computed from ξ at static init rather than transcribed.</summary>
    private static Fp2 FrobeniusGamma61 { get; } = Fp2Pow(Bn254Fp2BigInt.NonResidue, (Prime - 1) / 3);
    /// <summary>The Frobenius γ-constant <c>ξ^(2(p−1)/3)</c> used in the Fp6 Frobenius, computed from ξ at static init rather than transcribed.</summary>
    private static Fp2 FrobeniusGamma62 { get; } = Fp2Pow(Bn254Fp2BigInt.NonResidue, 2 * (Prime - 1) / 3);
    /// <summary>The Frobenius γ-constant <c>ξ^((p−1)/6)</c> used in the Fp12 Frobenius, computed from ξ at static init rather than transcribed.</summary>
    private static Fp2 FrobeniusGamma121 { get; } = Fp2Pow(Bn254Fp2BigInt.NonResidue, (Prime - 1) / 6);

    /// <summary>The precomputed hard-part exponent <c>(p⁴ − p² + 1)/r</c> the final exponentiation raises to by square-and-multiply.</summary>
    private static BigInteger HardPartExponent { get; } = ComputeHardPartExponent();

    /// <summary>The element <c>w</c> in Fp12 (the sextic-twist generator, embedded as <c>(0, 1)</c> in the Fp6 tower), from which <see cref="W2"/> and <see cref="W3"/> are derived for the D-twist untwist map.</summary>
    private static Fp12 W { get; } = new(Fp6.Zero, Fp6.One);
    /// <summary>The element <c>w²</c> in Fp12, used to untwist a D-twist G2 point's x-coordinate into the full Fp12 embedding <c>ψ(x′, y′) = (w²·x′, w³·y′)</c>.</summary>
    private static Fp12 W2 { get; } = Bn254BigIntegerFp12Reference.Fp12Multiply(W, W);
    /// <summary>The element <c>w³</c> in Fp12, used to untwist a D-twist G2 point's y-coordinate into the full Fp12 embedding <c>ψ(x′, y′) = (w²·x′, w³·y′)</c>.</summary>
    private static Fp12 W3 { get; } = Bn254BigIntegerFp12Reference.Fp12Multiply(W2, W);


    /// <summary>Computes the hard-part exponent <c>(p⁴ − p² + 1)/r</c> from the field prime and the scalar-field order.</summary>
    /// <returns>The hard-part exponent.</returns>
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


    /// <summary>Reads an Fp12 element, applies the Frobenius endomorphism, and writes the result, counting the operation for telemetry.</summary>
    private static void Frobenius(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp12Frobenius, curve);

        Fp12 v = Bn254BigIntegerFp12Reference.Read(a);
        Bn254BigIntegerFp12Reference.Write(result, Fp12Frobenius(v));
    }


    /// <summary>Reads an Fp12 element, squares it via generic Fp12 multiplication, and writes the result, counting the operation for telemetry.</summary>
    private static void CyclotomicSquare(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        CryptographicOperationCounters.Increment(CryptographicOperationKind.Fp12CyclotomicSquare, curve);

        Fp12 v = Bn254BigIntegerFp12Reference.Read(a);
        Bn254BigIntegerFp12Reference.Write(result, Bn254BigIntegerFp12Reference.Fp12Multiply(v, v));
    }


    /// <summary>Computes the optimal-ate pairing of a G1 point and a G2 point, writing the identity when either input is the point at infinity.</summary>
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


    /// <summary>Applies the Fp12 Frobenius endomorphism in γ-constant tower form: an Fp6 Frobenius on each coefficient, with the odd coefficient's Fp6 further scaled by the tower's γ-constant.</summary>
    private static Fp12 Fp12Frobenius(Fp12 v)
    {
        Fp6 c0 = Fp6Frobenius(v.C0);
        Fp6 c1 = Fp6Frobenius(v.C1);
        Fp6 gammaLifted = new(FrobeniusGamma121, Bn254Fp2BigInt.Zero, Bn254Fp2BigInt.Zero);
        Fp6 c1Adjusted = Bn254BigIntegerFp6Reference.Fp6Multiply(c1, gammaLifted);
        return new Fp12(c0, c1Adjusted);
    }


    /// <summary>Applies the Fp6 Frobenius endomorphism: componentwise Fp2 conjugation, with the two nonzero-degree components scaled by their γ-constants.</summary>
    private static Fp6 Fp6Frobenius(Fp6 v)
    {
        Fp2 c0 = Fp2Conjugate(v.C0);
        Fp2 c1 = Bn254Fp2BigInt.Mul(FrobeniusGamma61, Fp2Conjugate(v.C1));
        Fp2 c2 = Bn254Fp2BigInt.Mul(FrobeniusGamma62, Fp2Conjugate(v.C2));
        return new Fp6(c0, c1, c2);
    }


    /// <summary>Returns the Fp2 conjugate <c>(a.C0, −a.C1)</c>, the Frobenius endomorphism over Fp2.</summary>
    private static Fp2 Fp2Conjugate(Fp2 a) => new(a.C0, Mod(-a.C1));


    /// <summary>A point on the BN254 twist curve, embedded into full Fp12 via the D-twist untwist map, as consumed by the Miller loop's chord-and-tangent line evaluation.</summary>
    private readonly record struct Fp12Point(Fp12 X, Fp12 Y);


    /// <summary>Runs the optimal-ate Miller loop over <see cref="AteLoopCount"/>, accumulating the line evaluations of each doubling step and of an addition step on every set loop bit, then applying the two BN-specific closing Frobenius steps.</summary>
    /// <param name="px">The G1 point's affine x-coordinate.</param>
    /// <param name="py">The G1 point's affine y-coordinate.</param>
    /// <param name="qx">The G2 point's affine x-coordinate.</param>
    /// <param name="qy">The G2 point's affine y-coordinate.</param>
    /// <returns>The Miller-loop value in Fp12, before final exponentiation.</returns>
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


    /// <summary>Doubles a Miller-loop point using the tangent-line formula <c>λ = 3X² / 2Y</c> (curve coefficient <c>a = 0</c>), returning the line's slope and the doubled point.</summary>
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


    /// <summary>Adds two distinct Miller-loop points using the chord-line formula, returning the line's slope and the sum.</summary>
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


    /// <summary>Applies the Fp12 Frobenius endomorphism to both coordinates of a Miller-loop point, used to derive the BN optimal-ate loop's closing Frobenius twists.</summary>
    private static Fp12Point FrobeniusPoint(Fp12Point p) => new(Fp12Frobenius(p.X), Fp12Frobenius(p.Y));


    /// <summary>Raises an Fp12 element to <c>(p¹² − 1)/r</c>: the easy part (conjugate·invert, then Frobenius²·self) followed by the hard part, exponentiation by the precomputed <see cref="HardPartExponent"/>.</summary>
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


    /// <summary>Raises an Fp12 element to a non-negative integer exponent by square-and-multiply.</summary>
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


    /// <summary>Raises an Fp2 element to a non-negative integer exponent by square-and-multiply.</summary>
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


    /// <summary>Multiplies two Fp12 elements via the Fp12 tower reference.</summary>
    private static Fp12 Fp12Multiply(Fp12 a, Fp12 b) => Bn254BigIntegerFp12Reference.Fp12Multiply(a, b);
    /// <summary>Squares an Fp12 element via the Fp12 tower reference.</summary>
    private static Fp12 Fp12Square(Fp12 a) => Bn254BigIntegerFp12Reference.Fp12Multiply(a, a);
    /// <summary>Adds two Fp12 elements componentwise via the Fp6 tower reference.</summary>
    private static Fp12 Fp12Add(Fp12 a, Fp12 b) => new(Bn254BigIntegerFp6Reference.Fp6Add(a.C0, b.C0), Bn254BigIntegerFp6Reference.Fp6Add(a.C1, b.C1));
    /// <summary>Subtracts two Fp12 elements componentwise via the Fp6 tower reference.</summary>
    private static Fp12 Fp12Subtract(Fp12 a, Fp12 b) => new(Bn254BigIntegerFp6Reference.Fp6Sub(a.C0, b.C0), Bn254BigIntegerFp6Reference.Fp6Sub(a.C1, b.C1));
    /// <summary>Negates an Fp12 element componentwise via the Fp6 tower reference.</summary>
    private static Fp12 Fp12Negate(Fp12 a) => new(Bn254BigIntegerFp6Reference.Fp6Neg(a.C0), Bn254BigIntegerFp6Reference.Fp6Neg(a.C1));


    /// <summary>Lifts an Fp value into Fp12 (constant slot).</summary>
    private static Fp12 EmbedFp(BigInteger a) => new(new Fp6(new Fp2(Mod(a), BigInteger.Zero), Bn254Fp2BigInt.Zero, Bn254Fp2BigInt.Zero), Fp6.Zero);

    /// <summary>Lifts an Fp2 value into Fp12 (constant slot).</summary>
    private static Fp12 EmbedFp2(Fp2 z) => new(new Fp6(z, Bn254Fp2BigInt.Zero, Bn254Fp2BigInt.Zero), Fp6.Zero);


    /// <summary>Decodes a compressed BN254 G1 point using gnark's big-endian compressed encoding.</summary>
    private static (BigInteger X, BigInteger Y, bool IsInfinity) DecodeG1(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length != G1CompressedSize)
        {
            throw new ArgumentException($"G1 byte span must be {G1CompressedSize} bytes; received {bytes.Length}.", nameof(bytes));
        }

        int tag = bytes[0] & 0xC0;
        if(tag == 0x40)
        {
            //The canonical infinity encoding is exactly the infinity tag with every
            //other bit zero. Any other infinity-tagged pattern is non-canonical and
            //rejected rather than aliased onto the identity.
            if(bytes[0] != 0x40 || bytes[1..].IndexOfAnyExcept((byte)0) >= 0)
            {
                throw new InvalidOperationException("Non-canonical BN254 G1 infinity encoding.");
            }

            return (BigInteger.Zero, BigInteger.Zero, true);
        }

        bool wantLarger = tag == 0xC0;
        Span<byte> xBytes = stackalloc byte[G1CompressedSize];
        bytes.CopyTo(xBytes);
        xBytes[0] &= 0x3f;
        BigInteger x = new(xBytes, isUnsigned: true, isBigEndian: true);
        if(x >= Prime)
        {
            //A masked x at or above the base-field prime is a non-canonical encoding;
            //reject it rather than reduce it, matching the G1 reference TryDecode boundary.
            throw new InvalidOperationException("Non-canonical BN254 G1 x-coordinate.");
        }

        BigInteger rhs = Mod((Mod(x * x) * x) + 3);
        if(!TryModSqrtFp(rhs, out BigInteger y))
        {
            //rhs is a quadratic non-residue, so x is not the abscissa of any curve point.
            //Verifying the a^((p+1)/4) root squares back rejects an off-curve x instead of
            //decoding it to a bogus point that the pairing would then consume.
            throw new InvalidOperationException("BN254 G1 point is not on the curve.");
        }

        bool yIsLarger = (y << 1) > Prime;
        if(yIsLarger != wantLarger)
        {
            y = Mod(-y);
        }

        return (x, y, false);
    }


    /// <summary>Decodes a compressed BN254 G2 point using gnark's big-endian compressed encoding.</summary>
    private static (Fp2 X, Fp2 Y, bool IsInfinity) DecodeG2(ReadOnlySpan<byte> bytes)
    {
        if(bytes.Length != G2CompressedSize)
        {
            throw new ArgumentException($"G2 byte span must be {G2CompressedSize} bytes; received {bytes.Length}.", nameof(bytes));
        }

        int tag = bytes[0] & 0xC0;
        if(tag == 0x40)
        {
            //The canonical infinity encoding is exactly the infinity tag with every
            //other bit zero. Any other infinity-tagged pattern is non-canonical and
            //rejected rather than aliased onto the identity.
            if(bytes[0] != 0x40 || bytes[1..].IndexOfAnyExcept((byte)0) >= 0)
            {
                throw new InvalidOperationException("Non-canonical BN254 G2 infinity encoding.");
            }

            return (Bn254Fp2BigInt.Zero, Bn254Fp2BigInt.Zero, true);
        }

        bool wantLarger = tag == 0xC0;
        Span<byte> c1Bytes = stackalloc byte[FpComponentSize];
        bytes[..FpComponentSize].CopyTo(c1Bytes);
        c1Bytes[0] &= 0x3f;
        BigInteger xC1 = new(c1Bytes, isUnsigned: true, isBigEndian: true);
        BigInteger xC0 = new(bytes.Slice(FpComponentSize, FpComponentSize), isUnsigned: true, isBigEndian: true);
        if(xC1 >= Prime || xC0 >= Prime)
        {
            //Either Fp2 component at or above the base-field prime is non-canonical;
            //reject rather than reduce, matching the G2 reference TryDecode boundary.
            throw new InvalidOperationException("Non-canonical BN254 G2 x-coordinate.");
        }

        Fp2 x = new(xC0, xC1);

        Fp2 rhs = Bn254Fp2BigInt.Add(Bn254Fp2BigInt.Mul(Bn254Fp2BigInt.Square(x), x), TwistCurveB);
        if(!TryModSqrtFp2(rhs, out Fp2 y))
        {
            //rhs is not a quadratic residue in Fp2, so x is not the abscissa of any
            //twist-curve point. Reject instead of decoding to an off-curve point.
            throw new InvalidOperationException("BN254 G2 point is not on the curve.");
        }

        if(Fp2IsLarger(y) != wantLarger)
        {
            y = Bn254Fp2BigInt.Neg(y);
        }

        return (x, y, false);
    }


    /// <summary>Computes the candidate square root <c>a^((p+1)/4) mod p</c>, valid only when <paramref name="a"/> is a quadratic residue; callers verify the candidate by squaring it back.</summary>
    private static BigInteger ModSqrtFp(BigInteger a) => BigInteger.ModPow(a, (Prime + 1) >> 2, Prime);


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
        if(Mod(candidate * candidate) != a)
        {
            root = BigInteger.Zero;

            return false;
        }

        root = candidate;

        return true;
    }


    /// <summary>
    /// Square root in Fp2 with square-back verification, mirroring the G2 reference
    /// decode path: reduce to Fp square roots via the complex-conjugate norm and return
    /// <see langword="false"/> when <paramref name="a"/> is a non-residue. Handles the
    /// pure-real and pure-imaginary axes the naive complex formula alone mishandles.
    /// </summary>
    private static bool TryModSqrtFp2(Fp2 a, out Fp2 root)
    {
        if(Bn254Fp2BigInt.IsZero(a))
        {
            root = Bn254Fp2BigInt.Zero;

            return true;
        }

        if(a.C1.IsZero)
        {
            //Pure-real case: y² = a.c0 is either an Fp residue (y on the real axis) or
            //−a.c0 is (y on the imaginary axis, since (i·c)² = −c² with u² = −1).
            if(TryModSqrtFp(a.C0, out BigInteger realRoot))
            {
                root = new Fp2(realRoot, BigInteger.Zero);

                return true;
            }

            if(TryModSqrtFp(Mod(-a.C0), out BigInteger imaginaryRoot))
            {
                root = new Fp2(BigInteger.Zero, imaginaryRoot);

                return true;
            }

            root = Bn254Fp2BigInt.Zero;

            return false;
        }

        BigInteger norm = Mod((a.C0 * a.C0) + (a.C1 * a.C1));
        if(!TryModSqrtFp(norm, out BigInteger alpha))
        {
            root = Bn254Fp2BigInt.Zero;

            return false;
        }

        BigInteger twoInverse = BigInteger.ModPow(new BigInteger(2), Prime - 2, Prime);
        BigInteger x0;
        if(!TryModSqrtFp(Mod((a.C0 + alpha) * twoInverse), out x0))
        {
            //Exactly one of (a.c0 ± α)/2 is an Fp residue for p ≡ 3 mod 4.
            if(!TryModSqrtFp(Mod((a.C0 - alpha) * twoInverse), out x0))
            {
                root = Bn254Fp2BigInt.Zero;

                return false;
            }
        }

        BigInteger twoX0Inverse = BigInteger.ModPow(Mod(x0 + x0), Prime - 2, Prime);
        BigInteger x1 = Mod(a.C1 * twoX0Inverse);
        root = new Fp2(x0, x1);

        return true;
    }


    /// <summary>Determines the BN254 G2 "larger" y-sign convention: the imaginary component decides when it is nonzero, otherwise the real component does.</summary>
    private static bool Fp2IsLarger(Fp2 y)
    {
        if(y.C1.IsZero)
        {
            return (y.C0 << 1) > Prime;
        }

        return (y.C1 << 1) > Prime;
    }


    /// <summary>Reduces a <see cref="BigInteger"/> into the canonical non-negative residue modulo <see cref="Prime"/>.</summary>
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

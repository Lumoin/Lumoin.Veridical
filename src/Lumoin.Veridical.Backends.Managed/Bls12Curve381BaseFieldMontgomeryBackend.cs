using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Allocation-free Montgomery arithmetic for the BLS12-381 base field
/// (<c>p = 0x1a0111ea…aaab</c>, 381 bits), exposed as the canonical
/// <see cref="ScalarAddDelegate"/> family over 48-byte big-endian field elements.
/// It is the six-limb sibling of <see cref="P256BaseFieldMontgomeryBackend"/>,
/// built on the shared <see cref="PrimeField384"/> limb core, and exists so the
/// constant-time G1 ladder has a base field with no secret-dependent branch, no
/// secret-indexed access, and no <see cref="BigInteger"/> on the per-op path.
/// </summary>
/// <remarks>
/// <para>
/// Multiplication is Coarsely Integrated Operand Scanning (CIOS) Montgomery
/// reduction — multiply and reduce fused, the accumulator kept below 2p — and
/// inversion is Fermat (<c>a^(p−2)</c>) over a windowed exponentiation run
/// entirely in the Montgomery domain; the exponent <c>p − 2</c> is public curve
/// data, so the window-value branch inside the exponentiation is not
/// secret-dependent. The Montgomery constants (<c>N' = −p⁻¹ mod 2⁶⁴</c>,
/// <c>R² mod p</c>, <c>R mod p</c>, <c>p − 2</c>) are derived once at static init
/// from <see cref="Bls12Curve381BigIntegerG1Reference.BaseFieldPrime"/>, so the
/// per-op path is BigInteger-free and allocation-free. Unlike the P-256 prime,
/// this modulus has no signed-sparse structure worth specializing, so the generic
/// per-limb <c>m·n[j]</c> reduction is the only reduction. The <c>curve</c>
/// argument is ignored (base-field arithmetic is not curve-routed); callers pass
/// <see cref="CurveParameterSet.None"/>.
/// </para>
/// </remarks>
internal static class Bls12Curve381BaseFieldMontgomeryBackend
{
    private const int LimbCount = PrimeField384.LimbCount;
    private const int ExponentBitCount = LimbCount * 64;

    /// <summary>The number of accumulator limbs in the CIOS window: <see cref="LimbCount"/> plus two headroom limbs.</summary>
    private const int AccumulatorLimbCount = LimbCount + 2;

    /// <summary>The canonical big-endian byte length of a BLS12-381 base-field element.</summary>
    internal const int ElementSize = LimbCount * 8;

    private static ulong[] ModulusLimbValues { get; } = ComputeModulusLimbs();
    private static ulong NPrimeValue { get; } = ComputeNPrime();
    private static ulong[] RSquaredLimbValues { get; } = ComputeRSquared();
    private static ulong[] OneMontgomeryLimbValues { get; } = ComputeOneMontgomery();
    private static ulong[] InversionExponentLimbValues { get; } = ComputeInversionExponent();

    private static ReadOnlySpan<ulong> ModulusLimbs => ModulusLimbValues;


    public static ScalarAddDelegate GetAdd() => Add;

    public static ScalarSubtractDelegate GetSubtract() => Subtract;

    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    public static ScalarInvertDelegate GetInvert() => Invert;


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        PrimeField384.LoadCanonicalToLimbs(a, aLimbs);
        PrimeField384.LoadCanonicalToLimbs(b, bLimbs);

        Span<ulong> sum = stackalloc ulong[LimbCount];
        PrimeField384.AddModP(aLimbs, bLimbs, ModulusLimbs, sum);
        PrimeField384.StoreLimbsToCanonical(sum, result);
    }


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        PrimeField384.LoadCanonicalToLimbs(a, aLimbs);
        PrimeField384.LoadCanonicalToLimbs(b, bLimbs);

        Span<ulong> difference = stackalloc ulong[LimbCount];
        PrimeField384.SubtractModP(aLimbs, bLimbs, ModulusLimbs, difference);
        PrimeField384.StoreLimbsToCanonical(difference, result);
    }


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        PrimeField384.LoadCanonicalToLimbs(a, aLimbs);
        PrimeField384.LoadCanonicalToLimbs(b, bLimbs);

        //Lift a to Montgomery form (aR) via MontMul(a, R²), then MontMul(aR, b) =
        //ab mod p — the Montgomery domain is entered and left within this call.
        Span<ulong> aMontgomery = stackalloc ulong[LimbCount];
        Span<ulong> product = stackalloc ulong[LimbCount];
        MontgomeryMultiply(aLimbs, RSquaredLimbValues, aMontgomery);
        MontgomeryMultiply(aMontgomery, bLimbs, product);
        PrimeField384.StoreLimbsToCanonical(product, result);
    }


    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        PrimeField384.LoadCanonicalToLimbs(a, aLimbs);
        if(PrimeField384.IsZero(aLimbs))
        {
            throw new InvalidOperationException("Zero is not invertible in the BLS12-381 base field.");
        }

        //Windowed square-and-multiply over p − 2, entirely in the Montgomery domain:
        //the base is aR, the identity is R mod p, and base^(p−2) = a^(p−2)·R.
        Span<ulong> baseMontgomery = stackalloc ulong[LimbCount];
        MontgomeryMultiply(aLimbs, RSquaredLimbValues, baseMontgomery);

        Span<ulong> accumulator = stackalloc ulong[LimbCount];
        PrimeField384.WindowedExponentiate(baseMontgomery, OneMontgomeryLimbValues, InversionExponentLimbValues, ExponentBitCount, MontgomeryMultiply, accumulator);

        //Leave the Montgomery domain: MontMul by canonical 1.
        Span<ulong> canonicalOne = stackalloc ulong[LimbCount];
        canonicalOne.Clear();
        canonicalOne[0] = 1UL;

        Span<ulong> canonical = stackalloc ulong[LimbCount];
        MontgomeryMultiply(accumulator, canonicalOne, canonical);
        PrimeField384.StoreLimbsToCanonical(canonical, result);
    }


    /// <summary>
    /// Generic CIOS Montgomery multiply: result = a·b·R⁻¹ mod p; inputs are assumed &lt; p and the output is
    /// reduced by one constant-time conditional subtraction. Each outer step accumulates the a·b[i] column,
    /// then forms the quotient digit m = t[0]·N' and adds m·p through the full per-limb modulus product before
    /// shifting the window down one limb. Mirrors P256BaseFieldMontgomeryBackend.MontgomeryMultiply with six
    /// limbs and a nontrivial N' (the P-256 prime has N' = 1; this one does not).
    /// </summary>
    private static void MontgomeryMultiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result)
    {
        ReadOnlySpan<ulong> n = ModulusLimbs;
        ulong nPrime = NPrimeValue;

        Span<ulong> t = stackalloc ulong[AccumulatorLimbCount];
        t.Clear();

        for(int i = 0; i < LimbCount; i++)
        {
            ulong carry = 0UL;
            for(int j = 0; j < LimbCount; j++)
            {
                UInt128 product = (UInt128)t[j] + ((UInt128)a[j] * b[i]) + carry;
                t[j] = (ulong)product;
                carry = (ulong)(product >> 64);
            }

            UInt128 highSum = (UInt128)t[LimbCount] + carry;
            t[LimbCount] = (ulong)highSum;
            t[LimbCount + 1] = (ulong)(highSum >> 64);

            ulong m = unchecked(t[0] * nPrime);
            UInt128 reduceLow = (UInt128)t[0] + ((UInt128)m * n[0]);
            carry = (ulong)(reduceLow >> 64);
            for(int j = 1; j < LimbCount; j++)
            {
                UInt128 reduceTerm = (UInt128)t[j] + ((UInt128)m * n[j]) + carry;
                t[j - 1] = (ulong)reduceTerm;
                carry = (ulong)(reduceTerm >> 64);
            }

            UInt128 reduceHigh = (UInt128)t[LimbCount] + carry;
            t[LimbCount - 1] = (ulong)reduceHigh;
            t[LimbCount] = t[LimbCount + 1] + (ulong)(reduceHigh >> 64);
        }

        Span<ulong> reduced = stackalloc ulong[LimbCount];
        t[..LimbCount].CopyTo(reduced);
        bool borrow = PrimeField384.SubtractWithBorrow(reduced, n);
        //Branch-free combination of the secret-derived carry and borrow flags.
        PrimeField384.Select(reduced, t[..LimbCount], (t[LimbCount] != 0UL) | !borrow, result);
    }


    //Constant derivation from the base-field prime (static-init only)

    private static ulong[] ComputeModulusLimbs()
    {
        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(Bls12Curve381BigIntegerG1Reference.BaseFieldPrime, limbs);

        return limbs;
    }


    private static ulong ComputeNPrime()
    {
        BigInteger twoTo64 = BigInteger.One << 64;
        BigInteger lowInverse = ModularInverse(ModulusLimbValues[0] % twoTo64, twoTo64);

        return (ulong)((((twoTo64 - lowInverse) % twoTo64) + twoTo64) % twoTo64);
    }


    private static ulong[] ComputeRSquared()
    {
        BigInteger modulus = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;
        BigInteger rSquared = (BigInteger.One << (128 * LimbCount)) % modulus;

        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(rSquared, limbs);

        return limbs;
    }


    private static ulong[] ComputeOneMontgomery()
    {
        BigInteger modulus = Bls12Curve381BigIntegerG1Reference.BaseFieldPrime;
        BigInteger r = (BigInteger.One << (64 * LimbCount)) % modulus;

        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(r, limbs);

        return limbs;
    }


    private static ulong[] ComputeInversionExponent()
    {
        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(Bls12Curve381BigIntegerG1Reference.BaseFieldPrime - 2, limbs);

        return limbs;
    }


    private static void BigIntegerToLimbs(BigInteger value, Span<ulong> limbs)
    {
        BigInteger mask = (BigInteger.One << 64) - 1;
        for(int i = 0; i < limbs.Length; i++)
        {
            limbs[i] = (ulong)((value >> (64 * i)) & mask);
        }
    }


    private static BigInteger ModularInverse(BigInteger value, BigInteger modulus)
    {
        BigInteger t = BigInteger.Zero;
        BigInteger newT = BigInteger.One;
        BigInteger r = modulus;
        BigInteger newR = value;

        while(newR != BigInteger.Zero)
        {
            BigInteger quotient = r / newR;
            (t, newT) = (newT, t - (quotient * newT));
            (r, newR) = (newR, r - (quotient * newR));
        }

        return ((t % modulus) + modulus) % modulus;
    }
}

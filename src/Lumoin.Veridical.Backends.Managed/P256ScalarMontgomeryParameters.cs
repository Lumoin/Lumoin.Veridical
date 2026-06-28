using System;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Montgomery-form constants for the P-256 <em>scalar</em> field — arithmetic
/// modulo the group order
/// <c>n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551</c> —
/// the scalar-field counterpart of <see cref="Fp256MontgomeryParameters"/> (which
/// carries the base-field <c>p</c> constants). It holds the modulus as four
/// little-endian 64-bit limbs, the per-limb Montgomery inverse
/// <c>N' = −n⁻¹ mod 2⁶⁴</c>, <c>R² mod n</c> (the lift constant, with
/// <c>R = 2²⁵⁶</c>), the Montgomery identity <c>R mod n</c>, and the Fermat
/// inversion exponent <c>n − 2</c> as limbs.
/// </summary>
/// <remarks>
/// The constants are derived once at static initialisation from
/// <see cref="P256BigIntegerScalarReference.FieldOrder"/> — the single source of
/// truth for <c>n</c> — so the per-operation path in
/// <see cref="P256ScalarMontgomeryBackend"/> is <see cref="BigInteger"/>-free and
/// there is no hand-typed hex to drift from the modulus. All limb arrays are
/// little-endian: index 0 is the least-significant 64 bits.
/// </remarks>
internal static class P256ScalarMontgomeryParameters
{
    /// <summary>The number of 64-bit limbs in a 256-bit scalar (shared with the base-field limb core).</summary>
    internal const int LimbCount = PrimeField256.LimbCount;

    //All five constants are derived from P256BigIntegerScalarReference.FieldOrder at static init;
    //nothing here is hand-typed, so the Montgomery domain cannot drift from the canonical order n.
    private static readonly ulong[] ModulusLimbValues = ComputeModulusLimbs();
    private static readonly ulong NPrimeValue = ComputeNPrime();
    private static readonly ulong[] RSquaredLimbValues = ComputeRSquared();
    private static readonly ulong[] OneMontgomeryLimbValues = ComputeOneMontgomery();
    private static readonly ulong[] InversionExponentLimbValues = ComputeInversionExponent();


    /// <summary>The group order <c>n</c> as four little-endian 64-bit limbs.</summary>
    internal static ReadOnlySpan<ulong> ModulusLimbs => ModulusLimbValues;

    /// <summary><c>N' = −n⁻¹ mod 2⁶⁴</c> — the Montgomery inverse the CIOS reduction step multiplies the low limb by.</summary>
    internal static ulong NPrime => NPrimeValue;

    /// <summary><c>R² mod n</c> with <c>R = 2²⁵⁶</c> — the single-CIOS lift constant carrying a canonical value into the Montgomery domain.</summary>
    internal static ReadOnlySpan<ulong> RSquaredLimbs => RSquaredLimbValues;

    /// <summary><c>R mod n</c> — the multiplicative identity in the Montgomery domain (the exponentiation ladder's seed).</summary>
    internal static ReadOnlySpan<ulong> OneMontgomeryLimbs => OneMontgomeryLimbValues;

    /// <summary><c>n − 2</c> as four little-endian 64-bit limbs — the fixed public Fermat exponent for inversion.</summary>
    internal static ReadOnlySpan<ulong> InversionExponentLimbs => InversionExponentLimbValues;


    private static ulong[] ComputeModulusLimbs()
    {
        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(P256BigIntegerScalarReference.FieldOrder, limbs);

        return limbs;
    }


    private static ulong ComputeNPrime()
    {
        //N' = −n⁻¹ mod 2⁶⁴ (the CIOS reduction uses only the least-significant limb's inverse).
        BigInteger twoTo64 = BigInteger.One << 64;
        BigInteger lowInverse = ModularInverse(ModulusLimbValues[0] % twoTo64, twoTo64);

        return (ulong)((((twoTo64 - lowInverse) % twoTo64) + twoTo64) % twoTo64);
    }


    private static ulong[] ComputeRSquared()
    {
        //R² mod n with R = 2^(64·LimbCount) = 2²⁵⁶, so R² = 2^(128·LimbCount) = 2⁵¹².
        BigInteger modulus = P256BigIntegerScalarReference.FieldOrder;
        BigInteger rSquared = (BigInteger.One << (128 * LimbCount)) % modulus;

        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(rSquared, limbs);

        return limbs;
    }


    private static ulong[] ComputeOneMontgomery()
    {
        //R mod n with R = 2^(64·LimbCount) = 2²⁵⁶ — the Montgomery-domain representation of canonical 1.
        BigInteger modulus = P256BigIntegerScalarReference.FieldOrder;
        BigInteger r = (BigInteger.One << (64 * LimbCount)) % modulus;

        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(r, limbs);

        return limbs;
    }


    private static ulong[] ComputeInversionExponent()
    {
        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(P256BigIntegerScalarReference.FieldOrder - 2, limbs);

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


    //The modular inverse of value modulo modulus by the extended Euclidean algorithm; value and modulus are
    //coprime here (modulus 2⁶⁴ is a power of two, value is the odd low limb of n), so the inverse exists.
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

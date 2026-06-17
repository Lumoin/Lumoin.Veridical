using System;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Montgomery-form constants for the BN254 scalar field <c>r</c>, the BN254
/// counterpart of <see cref="Bls12Curve381MontgomeryParameters"/>: the modulus
/// limbs, the per-limb Montgomery inverse <c>N' = −r⁻¹ mod 2⁶⁴</c>, <c>R² = 2⁵¹² mod r</c>,
/// the Montgomery form of one (<c>R mod r</c>), and the Fermat inversion exponent
/// <c>r − 2</c>.
/// </summary>
/// <remarks>
/// The constants are derived once at static initialisation from the modulus via
/// <see cref="BigInteger"/>, keeping the per-operation path BigInteger-free while
/// eliminating the transcription risk of hand-copied 256/512-bit hex constants; the
/// end-to-end agreement sweep validates the whole multiply regardless. All limb
/// arrays are little-endian: index 0 is the least-significant 64 bits.
/// </remarks>
internal static class Bn254MontgomeryParameters
{
    private const int LimbCount = 4;

    //BN254 scalar-field modulus r, little-endian 64-bit limbs.
    //r = 0x30644e72e131a029 b85045b68181585d 2833e84879b97091 43e1f593f0000001.
    private static readonly ulong[] ModulusLimbValues =
    [
        0x43e1f593f0000001UL,
        0x2833e84879b97091UL,
        0xb85045b68181585dUL,
        0x30644e72e131a029UL
    ];

    private static readonly ulong NPrimeValue = ComputeNPrime();
    private static readonly ulong[] RSquaredLimbValues = ComputeRSquared();
    private static readonly ulong[] OneMontgomeryLimbValues = ComputeOneMontgomery();
    private static readonly ulong[] InversionExponentLimbValues = ComputeInversionExponent();

    //32-bit-limb forms for the lane-interleaved SIMD batch multiply (one 32×32→64
    //widening multiply per partial product). Eight little-endian 32-bit limbs,
    //and N'32 = −r⁻¹ mod 2³².
    private static readonly uint NPrime32Value = ComputeNPrime32();
    private static readonly uint[] Modulus32LimbValues = Split64To32(ModulusLimbValues);
    private static readonly uint[] RSquared32LimbValues = Split64To32(RSquaredLimbValues);


    private static ulong ComputeNPrime()
    {
        //N' = −r⁻¹ mod 2⁶⁴ (CIOS uses only the least-significant limb's inverse).
        BigInteger twoTo64 = BigInteger.One << 64;
        BigInteger lowInverse = ModularInverse(ModulusLimbValues[0] % twoTo64, twoTo64);

        return (ulong)((((twoTo64 - lowInverse) % twoTo64) + twoTo64) % twoTo64);
    }


    private static ulong[] ComputeRSquared()
    {
        //R² = 2⁵¹² mod r — maps a canonical scalar a to its Montgomery form aR via
        //one Montgomery multiplication MontMul(a, R²).
        BigInteger modulus = LimbsToBigInteger(ModulusLimbValues);
        BigInteger rSquared = (BigInteger.One << (128 * LimbCount)) % modulus;

        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(rSquared, limbs);

        return limbs;
    }


    private static ulong[] ComputeOneMontgomery()
    {
        //R mod r is the Montgomery representation of 1 — the initial accumulator of
        //the Montgomery-domain exponentiation ladder used by inversion.
        BigInteger modulus = LimbsToBigInteger(ModulusLimbValues);
        BigInteger r = (BigInteger.One << (64 * LimbCount)) % modulus;

        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(r, limbs);

        return limbs;
    }


    private static ulong[] ComputeInversionExponent()
    {
        //Fermat inversion raises to r − 2 (r prime): a^(r−2) ≡ a⁻¹ mod r.
        BigInteger modulus = LimbsToBigInteger(ModulusLimbValues);

        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(modulus - 2, limbs);

        return limbs;
    }


    /// <summary>The modulus <c>r</c> as little-endian 64-bit limbs.</summary>
    internal static ReadOnlySpan<ulong> ModulusLimbs => ModulusLimbValues;

    /// <summary><c>R² mod r</c> as little-endian 64-bit limbs.</summary>
    internal static ReadOnlySpan<ulong> RSquaredLimbs => RSquaredLimbValues;

    /// <summary><c>N' = −r⁻¹ mod 2⁶⁴</c>.</summary>
    internal static ulong NPrime => NPrimeValue;

    /// <summary><c>R mod r</c> — the Montgomery representation of 1 — as little-endian 64-bit limbs.</summary>
    internal static ReadOnlySpan<ulong> OneMontgomeryLimbs => OneMontgomeryLimbValues;

    /// <summary>The Fermat inversion exponent <c>r − 2</c> as little-endian 64-bit limbs.</summary>
    internal static ReadOnlySpan<ulong> InversionExponentLimbs => InversionExponentLimbValues;

    /// <summary>The modulus <c>r</c> as eight little-endian 32-bit limbs (for the SIMD batch multiply).</summary>
    internal static ReadOnlySpan<uint> Modulus32Limbs => Modulus32LimbValues;

    /// <summary><c>R² mod r</c> as eight little-endian 32-bit limbs.</summary>
    internal static ReadOnlySpan<uint> RSquared32Limbs => RSquared32LimbValues;

    /// <summary><c>N'32 = −r⁻¹ mod 2³²</c> — the 32-bit Montgomery inverse the CIOS reduction step uses.</summary>
    internal static uint NPrime32 => NPrime32Value;


    private static uint ComputeNPrime32()
    {
        BigInteger twoTo32 = BigInteger.One << 32;
        BigInteger lowInverse = ModularInverse(ModulusLimbValues[0] & 0xFFFFFFFFUL, twoTo32);

        return (uint)((((twoTo32 - lowInverse) % twoTo32) + twoTo32) % twoTo32);
    }


    private static uint[] Split64To32(ReadOnlySpan<ulong> limbs64)
    {
        uint[] limbs32 = new uint[limbs64.Length * 2];
        for(int i = 0; i < limbs64.Length; i++)
        {
            limbs32[2 * i] = (uint)limbs64[i];
            limbs32[(2 * i) + 1] = (uint)(limbs64[i] >> 32);
        }

        return limbs32;
    }


    private static BigInteger LimbsToBigInteger(ReadOnlySpan<ulong> limbs)
    {
        BigInteger value = BigInteger.Zero;
        for(int i = limbs.Length - 1; i >= 0; i--)
        {
            value = (value << 64) | limbs[i];
        }

        return value;
    }


    private static void BigIntegerToLimbs(BigInteger value, Span<ulong> limbs)
    {
        BigInteger mask = (BigInteger.One << 64) - 1;
        for(int i = 0; i < limbs.Length; i++)
        {
            limbs[i] = (ulong)((value >> (64 * i)) & mask);
        }
    }


    //The modular inverse of value modulo modulus by the extended Euclidean
    //algorithm; value and modulus are coprime here (modulus 2^64 is a power of two,
    //value is odd), so the inverse exists.
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

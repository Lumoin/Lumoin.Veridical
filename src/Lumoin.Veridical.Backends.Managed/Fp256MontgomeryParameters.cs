using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Montgomery-form constants for the P-256 base field Fp256
/// (<c>p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1</c>), the Fp256 counterpart of
/// <see cref="Bn254MontgomeryParameters"/>: the modulus as eight little-endian 32-bit
/// limbs and the per-limb Montgomery inverse <c>N'32 = −p⁻¹ mod 2³²</c>, both consumed
/// by the lane-parallel SIMD batch multiply.
/// </summary>
/// <remarks>
/// The constants are derived once at static initialisation from
/// <see cref="P256BigIntegerG1Reference.BaseFieldPrime"/> — the same source and the
/// same formulas the scalar <see cref="P256BaseFieldMontgomeryBackend"/> uses — so the
/// per-operation path is <see cref="BigInteger"/>-free and there is no hand-typed hex to
/// drift from the modulus. All limb arrays are little-endian: index 0 is the
/// least-significant bits. The 32-bit forms exist because the only widening multiply the
/// SIMD kernel has (<c>vpmuludq</c>) is 32×32→64, so the CIOS multiply runs over eight
/// 32-bit limbs rather than four 64-bit ones; <c>R = 2²⁵⁶</c> in both radices, so the
/// Montgomery residue is identical to the scalar backend's.
/// </remarks>
internal static class Fp256MontgomeryParameters
{
    private const int LimbCount = PrimeField256.LimbCount;
    private const ulong Low32Mask = 0xFFFFFFFFUL;

    //The P-256 base-field prime p as little-endian 64-bit limbs, derived from
    //P256BigIntegerG1Reference.BaseFieldPrime exactly as
    //P256BaseFieldMontgomeryBackend.ComputeModulusLimbs does.
    private static readonly ulong[] ModulusLimbValues = ComputeModulusLimbs();

    //32-bit-limb forms for the lane-interleaved SIMD batch multiply (one 32×32→64
    //widening multiply per partial product). Eight little-endian 32-bit limbs,
    //and N'32 = −p⁻¹ mod 2³².
    private static readonly uint NPrime32Value = ComputeNPrime32();
    private static readonly uint[] Modulus32LimbValues = Split64To32(ModulusLimbValues);


    /// <summary>The modulus <c>p</c> as eight little-endian 32-bit limbs (for the SIMD batch multiply).</summary>
    internal static ReadOnlySpan<uint> Modulus32Limbs => Modulus32LimbValues;

    /// <summary><c>N'32 = −p⁻¹ mod 2³²</c> — the 32-bit Montgomery inverse the CIOS reduction step uses.</summary>
    internal static uint NPrime32 => NPrime32Value;


    private static ulong[] ComputeModulusLimbs()
    {
        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(P256BigIntegerG1Reference.BaseFieldPrime, limbs);

        return limbs;
    }


    private static uint ComputeNPrime32()
    {
        //N'32 = −p⁻¹ mod 2³² (the 32-bit CIOS uses only the least-significant limb's inverse).
        BigInteger twoTo32 = BigInteger.One << 32;
        BigInteger lowInverse = ModularInverse(ModulusLimbValues[0] & Low32Mask, twoTo32);

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


    private static void BigIntegerToLimbs(BigInteger value, Span<ulong> limbs)
    {
        BigInteger mask = (BigInteger.One << 64) - 1;
        for(int i = 0; i < limbs.Length; i++)
        {
            limbs[i] = (ulong)((value >> (64 * i)) & mask);
        }
    }


    //The modular inverse of value modulo modulus by the extended Euclidean algorithm;
    //value and modulus are coprime here (modulus 2³² is a power of two, value is odd),
    //so the inverse exists.
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

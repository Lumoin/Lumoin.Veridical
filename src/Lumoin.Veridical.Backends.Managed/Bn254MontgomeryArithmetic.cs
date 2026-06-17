using Lumoin.Veridical.Core;
using System;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// ISA-independent single-element modular multiplication and inversion for the BN254
/// scalar field, the BN254 counterpart of <see cref="Bls12Curve381MontgomeryArithmetic"/>,
/// shared by every BN254 SIMD scalar backend.
/// </summary>
/// <remarks>
/// A single Montgomery multiply is an inherently serial carry chain over the four
/// 64-bit limbs — SIMD lane parallelism accelerates <em>batches</em>, not one
/// multiplication — so this scalar CIOS body is the same for AVX2, AVX-512 and NEON;
/// the per-ISA backends delegate multiply and invert here and own only add/subtract/
/// negate. The contract is canonical-in / canonical-out: the Montgomery form lives
/// only inside these methods. Constants come from
/// <see cref="Bn254MontgomeryParameters"/>.
/// </remarks>
internal static class Bn254MontgomeryArithmetic
{
    private const int LimbCount = 4;
    private const int BytesPerLimb = 8;
    private const int ExponentBitCount = LimbCount * 64;


    /// <summary>Canonical modular multiplication <paramref name="result"/> = <paramref name="a"/> · <paramref name="b"/> mod r.</summary>
    internal static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        Span<ulong> aMontgomery = stackalloc ulong[LimbCount];
        Span<ulong> productLimbs = stackalloc ulong[LimbCount];

        LoadCanonicalToLimbs(a, aLimbs);
        LoadCanonicalToLimbs(b, bLimbs);

        //MontMul(MontMul(a, R²), b) = MontMul(aR, b) = aR·b·R⁻¹ = ab mod r. The
        //Montgomery domain is entered and left within this one call.
        MontgomeryMultiply(aLimbs, Bn254MontgomeryParameters.RSquaredLimbs, aMontgomery);
        MontgomeryMultiply(aMontgomery, bLimbs, productLimbs);

        StoreLimbsToCanonical(productLimbs, result);
    }


    /// <summary>
    /// Canonical modular inversion <paramref name="result"/> = <paramref name="a"/>⁻¹ mod r,
    /// by Fermat's little theorem (a^(r−2) mod r) over a Montgomery-domain
    /// square-and-multiply ladder.
    /// </summary>
    /// <exception cref="InvalidOperationException">When <paramref name="a"/> is zero (not invertible), matching the BigInteger reference.</exception>
    internal static void Invert(ReadOnlySpan<byte> a, Span<byte> result)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        LoadCanonicalToLimbs(a, aLimbs);
        if(IsZero(aLimbs))
        {
            throw new InvalidOperationException("Zero is not invertible in the BN254 scalar field.");
        }

        Span<ulong> baseMontgomery = stackalloc ulong[LimbCount];
        MontgomeryMultiply(aLimbs, Bn254MontgomeryParameters.RSquaredLimbs, baseMontgomery);

        Span<ulong> accumulator = stackalloc ulong[LimbCount];
        Bn254MontgomeryParameters.OneMontgomeryLimbs.CopyTo(accumulator);

        Span<ulong> scratch = stackalloc ulong[LimbCount];
        ReadOnlySpan<ulong> exponent = Bn254MontgomeryParameters.InversionExponentLimbs;
        for(int bitIndex = ExponentBitCount - 1; bitIndex >= 0; bitIndex--)
        {
            MontgomeryMultiply(accumulator, accumulator, scratch);
            scratch.CopyTo(accumulator);

            ulong exponentBit = (exponent[bitIndex >> 6] >> (bitIndex & 63)) & 1UL;
            if(exponentBit != 0UL)
            {
                MontgomeryMultiply(accumulator, baseMontgomery, scratch);
                scratch.CopyTo(accumulator);
            }
        }

        Span<ulong> canonicalOne = stackalloc ulong[LimbCount];
        canonicalOne.Clear();
        canonicalOne[0] = 1UL;

        Span<ulong> canonicalResult = stackalloc ulong[LimbCount];
        MontgomeryMultiply(accumulator, canonicalOne, canonicalResult);
        StoreLimbsToCanonical(canonicalResult, result);
    }


    /// <summary>
    /// Montgomery multiplication of two reduced field elements held as little-endian
    /// 64-bit limbs: <paramref name="result"/> = <paramref name="a"/> · <paramref name="b"/> · R⁻¹ mod r,
    /// by Coarsely Integrated Operand Scanning (CIOS). Inputs are assumed &lt; r; the
    /// output is reduced by one constant-time conditional subtraction.
    /// </summary>
    private static void MontgomeryMultiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result)
    {
        ReadOnlySpan<ulong> n = Bn254MontgomeryParameters.ModulusLimbs;
        ulong nPrime = Bn254MontgomeryParameters.NPrime;

        Span<ulong> t = stackalloc ulong[LimbCount + 2];
        t.Clear();

        for(int i = 0; i < LimbCount; i++)
        {
            //Multiply pass: t += a · b[i].
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

            //Reduction pass: add the multiple m·n that clears the low limb, then
            //shift down by one limb (the division by 2⁶⁴ that builds R⁻¹).
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

        //The full value (t[LimbCount], t[0..LimbCount-1]) is < 2r; one conditional
        //subtraction of r makes it canonical. Select branch-free on whether the value
        //was >= r (overflow word set, or the subtraction did not borrow).
        Span<ulong> reduced = stackalloc ulong[LimbCount];
        t[..LimbCount].CopyTo(reduced);
        bool borrow = SubtractWithBorrow256(reduced, n);
        bool subtractModulus = (t[LimbCount] != 0UL) || !borrow;
        SelectLimbs(reduced, t[..LimbCount], subtractModulus, result);
    }


    private static void LoadCanonicalToLimbs(ReadOnlySpan<byte> canonical, Span<ulong> limbs)
    {
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int offset = (LimbCount - 1 - limbIndex) * BytesPerLimb;
            limbs[limbIndex] = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(offset, BytesPerLimb));
        }
    }


    private static void StoreLimbsToCanonical(ReadOnlySpan<ulong> limbs, Span<byte> canonical)
    {
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int offset = (LimbCount - 1 - limbIndex) * BytesPerLimb;
            BinaryPrimitives.WriteUInt64BigEndian(canonical.Slice(offset, BytesPerLimb), limbs[limbIndex]);
        }
    }


    private static bool SubtractWithBorrow256(Span<ulong> a, ReadOnlySpan<ulong> b)
    {
        ulong borrow = 0UL;
        for(int i = 0; i < LimbCount; i++)
        {
            ulong x = a[i];
            ulong y = b[i];
            ulong diffOut = unchecked(x - y - borrow);
            ulong newBorrow = (x < y) || (x == y && borrow != 0UL) ? 1UL : 0UL;
            a[i] = diffOut;
            borrow = newBorrow;
        }

        return borrow != 0UL;
    }


    /// <summary>Branch-free per-limb blend via a full-width limb mask (only the mask materialisation reads the condition).</summary>
    private static void SelectLimbs(ReadOnlySpan<ulong> onTrue, ReadOnlySpan<ulong> onFalse, bool condition, Span<ulong> destination)
    {
        ulong mask = condition ? ~0UL : 0UL;
        for(int i = 0; i < LimbCount; i++)
        {
            destination[i] = (onTrue[i] & mask) | (onFalse[i] & ~mask);
        }
    }


    private static bool IsZero(ReadOnlySpan<ulong> limbs)
    {
        ulong accumulated = 0UL;
        for(int i = 0; i < LimbCount; i++)
        {
            accumulated |= limbs[i];
        }

        return accumulated == 0UL;
    }
}

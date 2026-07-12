using Lumoin.Veridical.Core;
using System;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// ISA-independent single-element modular multiplication and inversion for the
/// BLS12-381 scalar field, shared by every SIMD scalar backend.
/// </summary>
/// <remarks>
/// <para>
/// A single Montgomery multiply is an inherently serial carry chain over the four
/// 64-bit limbs — SIMD lane parallelism accelerates <em>batches</em> of independent
/// multiplications, not one multiplication — so the scalar CIOS body here is the
/// same for AVX2, AVX-512 and NEON. The per-ISA backends own only the operations
/// whose constant-time selection differs by instruction set (add/subtract/negate
/// via each backend's <c>ConditionalSelect</c>); they delegate multiply and invert
/// here.
/// </para>
/// <para>
/// The contract is canonical-in / canonical-out: inputs and outputs are
/// <see cref="Lumoin.Veridical.Core.Algebraic.Scalar.SizeBytes"/> big-endian bytes and the Montgomery form lives
/// only inside these methods. Constants come from
/// <see cref="Bls12Curve381MontgomeryParameters"/>.
/// </para>
/// </remarks>
internal static class Bls12Curve381MontgomeryArithmetic
{
    private const int LimbCount = 4;
    private const int BytesPerLimb = 8;
    private const int ExponentBitCount = LimbCount * 64;


    /// <summary>
    /// Canonical modular multiplication <paramref name="result"/> = <paramref name="a"/> · <paramref name="b"/> mod r.
    /// </summary>
    internal static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        Span<ulong> aMontgomery = stackalloc ulong[LimbCount];
        Span<ulong> productLimbs = stackalloc ulong[LimbCount];

        LoadCanonicalToLimbs(a, aLimbs);
        LoadCanonicalToLimbs(b, bLimbs);

        //Lift a into Montgomery form (aR mod r) with a single Montgomery multiply by
        //R², then a Montgomery multiply by the canonical b yields the canonical
        //product: MontMul(aR, b) = aR·b·R⁻¹ = ab mod r. The Montgomery domain is
        //entered and left within this one call.
        MontgomeryMultiply(aLimbs, Bls12Curve381MontgomeryParameters.RSquaredLimbs, aMontgomery);
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
            throw new InvalidOperationException("Zero is not invertible in the BLS12-381 scalar field.");
        }

        //Run the ladder entirely in the Montgomery domain: the accumulator starts at
        //the Montgomery form of 1 (R mod r) and the base is a in Montgomery form
        //(aR). MontMul of two Montgomery-form values yields a Montgomery-form
        //product, so after exhausting the exponent bits the accumulator holds
        //(a^(r−2))·R, which the final MontMul by canonical 1 converts back.
        Span<ulong> baseMontgomery = stackalloc ulong[LimbCount];
        MontgomeryMultiply(aLimbs, Bls12Curve381MontgomeryParameters.RSquaredLimbs, baseMontgomery);

        Span<ulong> accumulator = stackalloc ulong[LimbCount];
        Bls12Curve381MontgomeryParameters.OneMontgomeryLimbs.CopyTo(accumulator);

        Span<ulong> scratch = stackalloc ulong[LimbCount];
        ReadOnlySpan<ulong> exponent = Bls12Curve381MontgomeryParameters.InversionExponentLimbs;
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
    /// by Coarsely Integrated Operand Scanning (CIOS). Inputs are assumed &lt; r and
    /// the output is reduced by one constant-time conditional subtraction.
    /// </summary>
    private static void MontgomeryMultiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result)
    {
        ReadOnlySpan<ulong> n = Bls12Curve381MontgomeryParameters.ModulusLimbs;
        ulong nPrime = Bls12Curve381MontgomeryParameters.NPrime;

        //Two guard words above the LimbCount result words hold the running carry-out
        //of each operand-scan pass; CIOS keeps the accumulator below 2r throughout.
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

        //The result candidate is t[0..LimbCount-1]; t[LimbCount] is the overflow word
        //(0 or 1). The full value is < 2r, so a single conditional subtraction of r
        //makes it canonical: subtract speculatively, then select branch-free on
        //whether the value was >= r (overflow set, or the subtraction did not borrow).
        Span<ulong> reduced = stackalloc ulong[LimbCount];
        t[..LimbCount].CopyTo(reduced);
        bool borrow = SubtractWithBorrow256(reduced, n);
        bool subtractModulus = (t[LimbCount] != 0UL) || !borrow;
        SelectLimbs(reduced, t[..LimbCount], subtractModulus, result);
    }


    private static void LoadCanonicalToLimbs(ReadOnlySpan<byte> canonical, Span<ulong> limbs)
    {
        //canonical: Scalar.SizeBytes big-endian bytes, MSB first.
        //limbs: limbs[0] is the least significant 64 bits, limbs[LimbCount - 1] the most.
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

            //New borrow is 1 iff x < y + borrow: either x < y, or x == y with an
            //incoming borrow.
            ulong newBorrow = (x < y) || (x == y && borrow != 0UL) ? 1UL : 0UL;
            a[i] = diffOut;
            borrow = newBorrow;
        }

        return borrow != 0UL;
    }


    /// <summary>
    /// Branch-free per-limb blend: copies <paramref name="onTrue"/> when
    /// <paramref name="condition"/> holds, otherwise <paramref name="onFalse"/>, via
    /// a full-width limb mask (the data blend is branchless; only the mask
    /// materialisation reads the condition).
    /// </summary>
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

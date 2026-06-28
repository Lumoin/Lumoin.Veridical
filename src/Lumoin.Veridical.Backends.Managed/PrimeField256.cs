using Lumoin.Veridical.Core;
using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// Strategy-independent limb arithmetic for a 256-bit prime field, shared by the
/// reduction-strategy backends (Montgomery, Solinas). It holds everything that does
/// not depend on <em>how</em> a product is reduced: the canonical big-endian ↔
/// little-endian-64-bit-limb conversions, addition and subtraction modulo a
/// supplied prime, the single conditional subtraction that canonicalises a value
/// known to be below twice the modulus, and the schoolbook 256×256→512 widening
/// multiply. The modulus is passed in as four little-endian limbs, so the same code
/// serves any 256-bit prime (Fp256 here; the BLS/BN scalar fields on a later
/// migration).
/// </summary>
/// <remarks>
/// The conditional paths are branch-free (a full-width <see cref="Select"/> mask),
/// matching the constant-time discipline of the SIMD backends, so a value-dependent
/// branch never reveals a secret limb. Inputs to <see cref="AddModP"/> /
/// <see cref="SubtractModP"/> are assumed already reduced (&lt; modulus).
/// </remarks>
internal static class PrimeField256
{
    internal const int LimbCount = 4;
    internal const int WideLimbCount = 8;
    private const int BytesPerLimb = 8;


    //32 canonical big-endian bytes (MSB first) → four little-endian 64-bit limbs.
    internal static void LoadCanonicalToLimbs(ReadOnlySpan<byte> canonical, Span<ulong> limbs)
    {
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int offset = (LimbCount - 1 - limbIndex) * BytesPerLimb;
            limbs[limbIndex] = BinaryPrimitives.ReadUInt64BigEndian(canonical.Slice(offset, BytesPerLimb));
        }
    }


    internal static void StoreLimbsToCanonical(ReadOnlySpan<ulong> limbs, Span<byte> canonical)
    {
        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            int offset = (LimbCount - 1 - limbIndex) * BytesPerLimb;
            BinaryPrimitives.WriteUInt64BigEndian(canonical.Slice(offset, BytesPerLimb), limbs[limbIndex]);
        }
    }


    internal static bool IsZero(ReadOnlySpan<ulong> limbs)
    {
        ulong accumulated = 0UL;
        for(int i = 0; i < LimbCount; i++)
        {
            accumulated |= limbs[i];
        }

        return accumulated == 0UL;
    }


    //a += b over four limbs; returns the carry out of the top limb.
    internal static bool AddWithCarry(Span<ulong> a, ReadOnlySpan<ulong> b)
    {
        ulong carry = 0UL;
        for(int i = 0; i < LimbCount; i++)
        {
            UInt128 sum = (UInt128)a[i] + b[i] + carry;
            a[i] = (ulong)sum;
            carry = (ulong)(sum >> 64);
        }

        return carry != 0UL;
    }


    //a −= b over four limbs; returns the borrow out of the top limb. Branchless: the UInt128 difference
    //underflows so its high half is all-ones exactly when a borrow is needed (mirroring AddWithCarry's carry
    //extraction), so the borrow is read off the high bits rather than from a value-dependent comparison.
    internal static bool SubtractWithBorrow(Span<ulong> a, ReadOnlySpan<ulong> b)
    {
        ulong borrow = 0UL;
        for(int i = 0; i < LimbCount; i++)
        {
            UInt128 difference = unchecked((UInt128)a[i] - b[i] - borrow);
            a[i] = (ulong)difference;
            borrow = (ulong)(difference >> 64) & 1UL;
        }

        return borrow != 0UL;
    }


    //Branch-free per-limb blend: onTrue when condition holds, else onFalse.
    internal static void Select(ReadOnlySpan<ulong> onTrue, ReadOnlySpan<ulong> onFalse, bool condition, Span<ulong> destination)
    {
        //Derive the all-ones/zero mask arithmetically, not with a `? :`: a comparison-sourced bool is 0 or 1
        //in memory, so reinterpret it as that byte and negate. This removes the dependence on the JIT lowering
        //a value-selecting ternary to a conditional move (the residual managed-CT caveat in SECURITY.md); the
        //blend itself was already branch-free.
        ulong mask = unchecked(0UL - (ulong)Unsafe.BitCast<bool, byte>(condition));
        for(int i = 0; i < LimbCount; i++)
        {
            destination[i] = (onTrue[i] & mask) | (onFalse[i] & ~mask);
        }
    }


    //(a + b) mod p, inputs assumed < p. Sum is < 2p, so one conditional subtract of
    //p canonicalises it (the carry out of 256 bits forces the subtraction).
    internal static void AddModP(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, ReadOnlySpan<ulong> modulus, Span<ulong> result)
    {
        Span<ulong> sum = stackalloc ulong[LimbCount];
        a.CopyTo(sum);
        bool carry = AddWithCarry(sum, b);

        Span<ulong> reduced = stackalloc ulong[LimbCount];
        sum.CopyTo(reduced);
        bool borrow = SubtractWithBorrow(reduced, modulus);
        Select(reduced, sum, carry || !borrow, result);
    }


    //(a − b) mod p, inputs assumed < p. If the subtraction borrows, add p back.
    internal static void SubtractModP(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, ReadOnlySpan<ulong> modulus, Span<ulong> result)
    {
        Span<ulong> difference = stackalloc ulong[LimbCount];
        a.CopyTo(difference);
        bool borrow = SubtractWithBorrow(difference, b);

        Span<ulong> corrected = stackalloc ulong[LimbCount];
        difference.CopyTo(corrected);
        AddWithCarry(corrected, modulus);
        Select(corrected, difference, borrow, result);
    }


    //value mod p for a value known to be < 2p: subtract p once if value ≥ p.
    internal static void ConditionalSubtractOnce(ReadOnlySpan<ulong> value, ReadOnlySpan<ulong> modulus, Span<ulong> result)
    {
        Span<ulong> reduced = stackalloc ulong[LimbCount];
        value.CopyTo(reduced);
        bool borrow = SubtractWithBorrow(reduced, modulus);
        Select(value, reduced, borrow, result);
    }


    //A field multiply over four limbs, in whatever domain the backend works in
    //(Montgomery in-domain, or Solinas canonical) — the only field-specific operation
    //the shared exponentiation needs.
    internal delegate void LimbMultiply(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result);


    //Fixed 4-bit windowed exponentiation result = base^exponent, using the supplied
    //field <paramref name="multiply"/> and the field's multiplicative identity
    //<paramref name="one"/> (both in the multiply's own domain). The exponent is
    //little-endian limbs and its bit count must be a multiple of four (256 here). This
    //replaces the naive bit-by-bit square-and-multiply (~exponentBits/2 multiplies) with
    //~exponentBits/4 window multiplies plus a 15-entry precompute — fewer field
    //multiplications, the squarings unchanged. Shared by both limb backends' inversion.
    internal static void WindowedExponentiate(
        ReadOnlySpan<ulong> baseElement,
        ReadOnlySpan<ulong> one,
        ReadOnlySpan<ulong> exponent,
        int exponentBitCount,
        LimbMultiply multiply,
        Span<ulong> result)
    {
        const int WindowBits = 4;
        const int TableSize = 1 << WindowBits;

        //table[i] = base^i for i in [0, 16): table[0] = one, table[1] = base, the rest
        //by one multiply each.
        Span<ulong> table = stackalloc ulong[TableSize * LimbCount];
        one.CopyTo(table[..LimbCount]);
        baseElement.CopyTo(table.Slice(LimbCount, LimbCount));
        for(int i = 2; i < TableSize; i++)
        {
            multiply(table.Slice((i - 1) * LimbCount, LimbCount), baseElement, table.Slice(i * LimbCount, LimbCount));
        }

        Span<ulong> accumulator = stackalloc ulong[LimbCount];
        Span<ulong> scratch = stackalloc ulong[LimbCount];
        one.CopyTo(accumulator);

        //Most-significant window first: four squarings, then one multiply by
        //base^(window) unless the window is zero.
        for(int bit = exponentBitCount - WindowBits; bit >= 0; bit -= WindowBits)
        {
            for(int s = 0; s < WindowBits; s++)
            {
                multiply(accumulator, accumulator, scratch);
                scratch.CopyTo(accumulator);
            }

            int window = ExtractWindow(exponent, bit, WindowBits);
            if(window != 0)
            {
                multiply(accumulator, table.Slice(window * LimbCount, LimbCount), scratch);
                scratch.CopyTo(accumulator);
            }
        }

        accumulator.CopyTo(result);
    }


    private static int ExtractWindow(ReadOnlySpan<ulong> value, int startBit, int count)
    {
        int window = 0;
        for(int i = 0; i < count; i++)
        {
            int bit = startBit + i;
            window |= (int)((value[bit >> 6] >> (bit & 63)) & 1UL) << i;
        }

        return window;
    }


    //Schoolbook 256×256 → 512 widening multiply (modulus-independent). result512 is
    //eight little-endian limbs.
    internal static void MultiplyWide(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result512)
    {
        result512.Clear();
        for(int i = 0; i < LimbCount; i++)
        {
            ulong carry = 0UL;
            for(int j = 0; j < LimbCount; j++)
            {
                UInt128 term = ((UInt128)a[i] * b[j]) + result512[i + j] + carry;
                result512[i + j] = (ulong)term;
                carry = (ulong)(term >> 64);
            }

            result512[i + LimbCount] = carry;
        }
    }
}

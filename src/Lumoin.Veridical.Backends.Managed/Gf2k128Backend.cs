using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The fast managed backend for <c>GF(2^128) = GF(2)[x] / (x^128 + x^7 + x^2 + x + 1)</c> — the
/// binary field the Longfellow hash side runs over (the longfellow-zk <c>lib/gf2k</c> modulus,
/// reduction constant <c>0x87</c>, plain polynomial representation). Elements ride in the
/// canonical 32-byte big-endian scalar slots with the high sixteen bytes zero, as two
/// <see cref="ulong"/> limbs. Addition and subtraction are XOR; multiplication is carry-less —
/// the PCLMULQDQ intrinsic on x86, the ARM PMULL (vmull_p64) intrinsic on AArch64, a 4-bit-window
/// software path otherwise — followed by the two-stage <c>0x87</c> fold; inversion is the Fermat
/// exponentiation
/// <c>a^(2^128 − 2)</c> over the fast multiply. Byte-identical to the test reference
/// (<c>Gf2k128Reference</c>), which stays the independent oracle.
/// </summary>
/// <remarks>
/// The reduce delegate — mapping arbitrary-length transcript squeezes into the field — parses
/// through <see cref="BigInteger"/>; it runs a few hundred times per proof against the millions
/// of multiplications the hot paths take, so clarity wins there.
/// </remarks>
public static class Gf2k128Backend
{
    private const int ScalarSize = 32;
    private const int Degree = 128;

    private static readonly BigInteger ElementMask = (BigInteger.One << Degree) - 1;


    /// <summary>Returns the add delegate (XOR).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarAddDelegate GetAdd() => Add;

    /// <summary>Returns the subtract delegate (XOR — characteristic two).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarSubtractDelegate GetSubtract() => Add;

    /// <summary>Returns the carry-less multiply delegate.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    /// <summary>Returns the invert delegate (Fermat <c>a^(2^128 − 2)</c>).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarInvertDelegate GetInvert() => Invert;

    /// <summary>Returns the reduce delegate (polynomial reduction of arbitrary-length input).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarReduceDelegate GetReduce() => Reduce;


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        (ulong leftHigh, ulong leftLow) = ReadElement(a);
        (ulong rightHigh, ulong rightLow) = ReadElement(b);
        WriteElement(leftHigh ^ rightHigh, leftLow ^ rightLow, result);
    }


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        (ulong leftHigh, ulong leftLow) = ReadElement(a);
        (ulong rightHigh, ulong rightLow) = ReadElement(b);
        (ulong high, ulong low) = MultiplyElements(leftHigh, leftLow, rightHigh, rightLow);
        WriteElement(high, low, result);
    }


    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        //Square-and-multiply over the exponent 2^128 − 2 = 0b111…110 (bits 1..127 set).
        (ulong elementHigh, ulong elementLow) = ReadElement(a);
        ulong accumulatorHigh = 0;
        ulong accumulatorLow = 1;
        for(int bit = Degree - 1; bit >= 0; bit--)
        {
            (accumulatorHigh, accumulatorLow) = MultiplyElements(accumulatorHigh, accumulatorLow, accumulatorHigh, accumulatorLow);
            if(bit != 0)
            {
                (accumulatorHigh, accumulatorLow) = MultiplyElements(accumulatorHigh, accumulatorLow, elementHigh, elementLow);
            }
        }

        WriteElement(accumulatorHigh, accumulatorLow, result);
    }


    private static void Reduce(ReadOnlySpan<byte> input, Span<byte> result, CurveParameterSet curve)
    {
        var value = new BigInteger(input, isUnsigned: true, isBigEndian: true);
        while(value > ElementMask)
        {
            BigInteger high = value >> Degree;
            value = (value & ElementMask) ^ high ^ (high << 1) ^ (high << 2) ^ (high << 7);
        }

        result.Clear();
        Span<byte> little = stackalloc byte[ScalarSize + 1];
        if(value.TryWriteBytes(little, out int written, isUnsigned: true, isBigEndian: false))
        {
            for(int i = 0; i < written && i < ScalarSize; i++)
            {
                result[ScalarSize - 1 - i] = little[i];
            }
        }
    }


    //The 128×128 carry-less product as four 64×64 halves, then the 0x87 fold.
    private static (ulong High, ulong Low) MultiplyElements(ulong leftHigh, ulong leftLow, ulong rightHigh, ulong rightLow)
    {
        (ulong r1a, ulong r0) = CarrylessMultiply64(leftLow, rightLow);
        (ulong r2a, ulong r1b) = CarrylessMultiply64(leftLow, rightHigh);
        (ulong r2b, ulong r1c) = CarrylessMultiply64(leftHigh, rightLow);
        (ulong r3, ulong r2c) = CarrylessMultiply64(leftHigh, rightHigh);

        ulong r1 = r1a ^ r1b ^ r1c;
        ulong r2 = r2a ^ r2b ^ r2c;

        return Fold(r3, r2, r1, r0);
    }


    //Folds the 256-bit product (r3 r2 r1 r0) modulo x^128 + x^7 + x^2 + x + 1: with the top
    //half T = (r3 r2) and the bottom half L = (r1 r0), the result is
    //L ⊕ T ⊕ T·x ⊕ T·x² ⊕ T·x⁷, and the up-to-seven bits the shifts push past position 128 go
    //around once more (their second pass cannot overflow).
    private static (ulong High, ulong Low) Fold(ulong r3, ulong r2, ulong r1, ulong r0)
    {
        ulong low = r2;
        ulong high = r3;

        //T<<1, T<<2, T<<7 over the 128-bit lane, spilling past bit 128 into `spill`.
        ulong spill = 0;
        Shifted(r3, r2, 1, ref high, ref low, ref spill);
        Shifted(r3, r2, 2, ref high, ref low, ref spill);
        Shifted(r3, r2, 7, ref high, ref low, ref spill);

        //The spill is at most seven bits: one more 0x87 pass, overflow-free.
        low ^= spill ^ (spill << 1) ^ (spill << 2) ^ (spill << 7);

        return (high ^ r1, low ^ r0);
    }


    private static void Shifted(ulong topHigh, ulong topLow, int amount, ref ulong high, ref ulong low, ref ulong spill)
    {
        low ^= topLow << amount;
        high ^= (topHigh << amount) | (topLow >> (64 - amount));
        spill ^= topHigh >> (64 - amount);
    }


    //One 64×64 carry-less multiply: the PCLMULQDQ instruction on x86, the ARM PMULL (vmull_p64)
    //instruction on AArch64, the 4-bit-window software path otherwise.
    private static (ulong High, ulong Low) CarrylessMultiply64(ulong a, ulong b)
    {
        if(Pclmulqdq.IsSupported)
        {
            Vector128<ulong> product = Pclmulqdq.CarrylessMultiply(Vector128.CreateScalar(a), Vector128.CreateScalar(b), 0x00);

            return (product.GetElement(1), product.GetElement(0));
        }
        else if(System.Runtime.Intrinsics.Arm.Aes.IsSupported)
        {
            //PolynomialMultiplyWideningLower is vmull_p64 (A64 PMULL Vd.1Q, Vn.1D, Vm.1D): the
            //64×64→128-bit carry-less product of the low lanes, the analog of PCLMULQDQ selector
            //0x00. The Vector128<ulong> lane order matches the x86 path — element 0 is the low 64
            //bits, element 1 the high 64 bits — so the (High, Low) mapping is identical.
            Vector128<ulong> product = System.Runtime.Intrinsics.Arm.Aes.PolynomialMultiplyWideningLower(Vector64.CreateScalar(a), Vector64.CreateScalar(b));

            return (product.GetElement(1), product.GetElement(0));
        }

        return SoftwareCarrylessMultiply64(a, b);
    }


    /// <summary>
    /// The portable 64×64 carry-less multiply: 4-bit windows, shift-and-XOR. Window entries are
    /// at most 67 bits and the per-nibble contributions shift by at most 60, so every term fits
    /// the 128-bit accumulator exactly. Public so the agreement tests gate this path on
    /// hardware that would otherwise always take the intrinsic.
    /// </summary>
    public static (ulong High, ulong Low) SoftwareCarrylessMultiply64(ulong a, ulong b)
    {
        Span<ulong> windowLow = stackalloc ulong[16];
        Span<ulong> windowHigh = stackalloc ulong[16];
        windowLow[0] = 0;
        windowHigh[0] = 0;
        windowLow[1] = a;
        windowHigh[1] = 0;
        for(int w = 2; w < 16; w++)
        {
            if((w & 1) == 0)
            {
                int half = w >> 1;
                windowLow[w] = windowLow[half] << 1;
                windowHigh[w] = (windowHigh[half] << 1) | (windowLow[half] >> 63);
            }
            else
            {
                windowLow[w] = windowLow[w - 1] ^ a;
                windowHigh[w] = windowHigh[w - 1];
            }
        }

        ulong low = 0;
        ulong high = 0;
        for(int nibble = 0; nibble < 16; nibble++)
        {
            int digit = (int)((b >> (4 * nibble)) & 0xF);
            if(digit == 0)
            {
                continue;
            }

            int shift = 4 * nibble;
            if(shift == 0)
            {
                low ^= windowLow[digit];
                high ^= windowHigh[digit];
            }
            else
            {
                low ^= windowLow[digit] << shift;
                high ^= (windowHigh[digit] << shift) | (windowLow[digit] >> (64 - shift));
            }
        }

        return (high, low);
    }


    private static (ulong High, ulong Low) ReadElement(ReadOnlySpan<byte> bytes) =>
        (BinaryPrimitives.ReadUInt64BigEndian(bytes.Slice(16, 8)), BinaryPrimitives.ReadUInt64BigEndian(bytes.Slice(24, 8)));


    private static void WriteElement(ulong high, ulong low, Span<byte> destination)
    {
        destination[..16].Clear();
        BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(16, 8), high);
        BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(24, 8), low);
    }
}

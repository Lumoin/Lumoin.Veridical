using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Allocation-free arithmetic for the P-256 base field Fp256 using the curve's
/// special <em>Solinas</em> (generalized-Mersenne) structure
/// <c>p = 2²⁵⁶ − 2²²⁴ + 2¹⁹² + 2⁹⁶ − 1</c>: a 512-bit product is reduced mod p by a
/// fixed table of 32-bit-word shifts, additions and subtractions (NIST FIPS 186-4 /
/// Hankerson–Menezes–Vanstone "Guide to Elliptic Curve Cryptography" Algorithm
/// 2.29) — no Montgomery multiply-based reduction. This is the second
/// reduction-strategy backend over the shared <see cref="PrimeField256"/> limb core
/// (the other is <see cref="P256BaseFieldMontgomeryBackend"/>); both are validated
/// bit-for-bit against <see cref="P256BaseFieldReference"/>.
/// </summary>
/// <remarks>
/// Multiplication is the schoolbook 256×256→512 widening multiply
/// (<see cref="PrimeField256.MultiplyWide"/>) followed by the P-256 fast reduction;
/// inversion is Fermat (<c>a^(p−2)</c>) over a canonical-domain square-and-multiply
/// ladder. The reduction's weighted sum of the nine s-terms is accumulated entirely
/// in <c>[0, p)</c> through the tested <see cref="PrimeField256.AddModP"/> /
/// <see cref="PrimeField256.SubtractModP"/>, which sidesteps signed multi-limb
/// arithmetic. The <c>curve</c> argument is ignored; callers pass
/// <see cref="CurveParameterSet.None"/>.
/// </remarks>
internal static class P256BaseFieldSolinasBackend
{
    private const int LimbCount = PrimeField256.LimbCount;
    private const int ExponentBitCount = LimbCount * 64;
    private const int ZeroWord = 16;

    private static readonly ulong[] ModulusLimbValues = ComputeModulusLimbs();
    private static readonly ulong[] InversionExponentLimbValues = ComputeInversionExponent();

    //δ = 2²⁵⁶ − p = 2²²⁴ − 2¹⁹² − 2⁹⁶ + 1 ≡ 2²⁵⁶ (mod p). Below 2²²⁴, so folding a
    //small (≤ 6) top word as word·δ lands below p with no further reduction.
    private static readonly ulong[] DeltaLimbValues = ComputeDelta();

    private static ReadOnlySpan<ulong> ModulusLimbs => ModulusLimbValues;

    //The P-256 reduction's nine s-terms (HMV Alg. 2.29). Each row lists the eight
    //32-bit-word indices of the product c (least-significant word first; index 16
    //means a zero word), and the coefficient the term enters the sum with:
    //s1,s4,s5 add once; s2,s3 add twice; s6,s7,s8,s9 subtract once.
    private static readonly int[] TermSignedTimes = [1, 2, 2, 1, 1, -1, -1, -1, -1];
    private static readonly int[][] TermWordIndices =
    [
        [0, 1, 2, 3, 4, 5, 6, 7],            //s1 = (c7 c6 c5 c4 c3 c2 c1 c0)
        [16, 16, 16, 11, 12, 13, 14, 15],    //s2 = (c15 c14 c13 c12 c11 0 0 0)
        [16, 16, 16, 12, 13, 14, 15, 16],    //s3 = (0 c15 c14 c13 c12 0 0 0)
        [8, 9, 10, 16, 16, 16, 14, 15],      //s4 = (c15 c14 0 0 0 c10 c9 c8)
        [9, 10, 11, 13, 14, 15, 13, 8],      //s5 = (c8 c13 c15 c14 c13 c11 c10 c9)
        [11, 12, 13, 16, 16, 16, 8, 10],     //s6 = (c10 c8 0 0 0 c13 c12 c11)
        [12, 13, 14, 15, 16, 16, 9, 11],     //s7 = (c11 c9 0 0 c15 c14 c13 c12)
        [13, 14, 15, 8, 9, 10, 16, 12],      //s8 = (c12 0 c10 c9 c8 c15 c14 c13)
        [14, 15, 16, 9, 10, 11, 16, 13]      //s9 = (c13 0 c11 c10 c9 0 c15 c14)
    ];


    public static ScalarAddDelegate GetAdd() => Add;

    public static ScalarSubtractDelegate GetSubtract() => Subtract;

    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    public static ScalarInvertDelegate GetInvert() => Invert;

    public static ScalarReduceDelegate GetReduce() => Reduce;


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);
        PrimeField256.LoadCanonicalToLimbs(b, bLimbs);

        Span<ulong> sum = stackalloc ulong[LimbCount];
        PrimeField256.AddModP(aLimbs, bLimbs, ModulusLimbs, sum);
        PrimeField256.StoreLimbsToCanonical(sum, result);
    }


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);
        PrimeField256.LoadCanonicalToLimbs(b, bLimbs);

        Span<ulong> difference = stackalloc ulong[LimbCount];
        PrimeField256.SubtractModP(aLimbs, bLimbs, ModulusLimbs, difference);
        PrimeField256.StoreLimbsToCanonical(difference, result);
    }


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        Span<ulong> bLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);
        PrimeField256.LoadCanonicalToLimbs(b, bLimbs);

        Span<ulong> product = stackalloc ulong[LimbCount];
        MultiplyLimbs(aLimbs, bLimbs, product);
        PrimeField256.StoreLimbsToCanonical(product, result);
    }


    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        Span<ulong> aLimbs = stackalloc ulong[LimbCount];
        PrimeField256.LoadCanonicalToLimbs(a, aLimbs);
        if(PrimeField256.IsZero(aLimbs))
        {
            throw new InvalidOperationException("Zero is not invertible in the P-256 base field.");
        }

        //Canonical-domain windowed square-and-multiply over p − 2.
        Span<ulong> canonicalOne = stackalloc ulong[LimbCount];
        canonicalOne.Clear();
        canonicalOne[0] = 1UL;

        Span<ulong> accumulator = stackalloc ulong[LimbCount];
        PrimeField256.WindowedExponentiate(aLimbs, canonicalOne, InversionExponentLimbValues, ExponentBitCount, MultiplyLimbs, accumulator);
        PrimeField256.StoreLimbsToCanonical(accumulator, result);
    }


    //Reduces an up-to-512-bit canonical big-endian input mod p directly through the
    //Solinas reduction (which already maps a 512-bit value to its residue).
    private static void Reduce(ReadOnlySpan<byte> input, Span<byte> result, CurveParameterSet curve)
    {
        if(input.Length > PrimeField256.WideLimbCount * 8)
        {
            throw new ArgumentException($"Reduce input must be at most {PrimeField256.WideLimbCount * 8} bytes; received {input.Length}.", nameof(input));
        }

        Span<byte> wide = stackalloc byte[PrimeField256.WideLimbCount * 8];
        wide.Clear();
        input.CopyTo(wide[(wide.Length - input.Length)..]);

        Span<ulong> product = stackalloc ulong[PrimeField256.WideLimbCount];
        for(int i = 0; i < PrimeField256.WideLimbCount; i++)
        {
            int offset = (PrimeField256.WideLimbCount - 1 - i) * 8;
            product[i] = System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(wide.Slice(offset, 8));
        }

        Span<ulong> reduced = stackalloc ulong[LimbCount];
        Reduce512(product, reduced);
        PrimeField256.StoreLimbsToCanonical(reduced, result);
    }


    //result = a·b mod p: schoolbook wide multiply then Solinas reduction.
    private static void MultiplyLimbs(ReadOnlySpan<ulong> a, ReadOnlySpan<ulong> b, Span<ulong> result)
    {
        Span<ulong> product = stackalloc ulong[PrimeField256.WideLimbCount];
        PrimeField256.MultiplyWide(a, b, product);
        Reduce512(product, result);
    }


    //The P-256 fast reduction: result = product512 mod p. The positive terms
    //(s1 + 2·s2 + 2·s3 + s4 + s5) and the negative terms (s6 + s7 + s8 + s9) are each
    //summed without per-term reduction into a five-limb accumulator (the top word
    //stays ≤ 6), then folded mod p and subtracted — a handful of reductions rather
    //than one per term, and the reduction is add-based (no Montgomery multiplies).
    private static void Reduce512(ReadOnlySpan<ulong> product512, Span<ulong> result)
    {
        Span<uint> c = stackalloc uint[ZeroWord + 1];
        for(int k = 0; k < 2 * PrimeField256.WideLimbCount; k++)
        {
            ulong limb = product512[k >> 1];
            c[k] = (k & 1) == 0 ? (uint)limb : (uint)(limb >> 32);
        }

        c[ZeroWord] = 0;

        Span<ulong> positive = stackalloc ulong[LimbCount + 1];
        Span<ulong> negative = stackalloc ulong[LimbCount + 1];
        positive.Clear();
        negative.Clear();

        Span<ulong> term = stackalloc ulong[LimbCount];
        for(int row = 0; row < TermWordIndices.Length; row++)
        {
            int[] index = TermWordIndices[row];
            term[0] = c[index[0]] | ((ulong)c[index[1]] << 32);
            term[1] = c[index[2]] | ((ulong)c[index[3]] << 32);
            term[2] = c[index[4]] | ((ulong)c[index[5]] << 32);
            term[3] = c[index[6]] | ((ulong)c[index[7]] << 32);

            int signedTimes = TermSignedTimes[row];
            Span<ulong> targetAccumulator = signedTimes > 0 ? positive : negative;
            int times = Math.Abs(signedTimes);
            for(int t = 0; t < times; t++)
            {
                AddInto(targetAccumulator, term);
            }
        }

        Span<ulong> positiveReduced = stackalloc ulong[LimbCount];
        Span<ulong> negativeReduced = stackalloc ulong[LimbCount];
        ReduceFiveLimb(positive, positiveReduced);
        ReduceFiveLimb(negative, negativeReduced);
        PrimeField256.SubtractModP(positiveReduced, negativeReduced, ModulusLimbs, result);
    }


    //Adds a four-limb term into a five-limb accumulator (carry into the top word).
    private static void AddInto(Span<ulong> accumulator, ReadOnlySpan<ulong> term)
    {
        ulong carry = 0UL;
        for(int j = 0; j < LimbCount; j++)
        {
            UInt128 sum = (UInt128)accumulator[j] + term[j] + carry;
            accumulator[j] = (ulong)sum;
            carry = (ulong)(sum >> 64);
        }

        accumulator[LimbCount] += carry;
    }


    //Reduces a five-limb value (low 256 bits + a small top word h, value =
    //low + h·2²⁵⁶) mod p: reduce the low 256 bits once, then add h·δ. Since h ≤ 6 and
    //δ < 2²²⁴, h·δ is already below p, so a single modular add finishes it.
    private static void ReduceFiveLimb(ReadOnlySpan<ulong> accumulator, Span<ulong> result)
    {
        Span<ulong> lowReduced = stackalloc ulong[LimbCount];
        PrimeField256.ConditionalSubtractOnce(accumulator[..LimbCount], ModulusLimbs, lowReduced);

        ulong high = accumulator[LimbCount];
        Span<ulong> fold = stackalloc ulong[LimbCount];
        ulong carry = 0UL;
        for(int j = 0; j < LimbCount; j++)
        {
            UInt128 product = ((UInt128)high * DeltaLimbValues[j]) + carry;
            fold[j] = (ulong)product;
            carry = (ulong)(product >> 64);
        }

        PrimeField256.AddModP(lowReduced, fold, ModulusLimbs, result);
    }


    private static ulong[] ComputeModulusLimbs()
    {
        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(P256BigIntegerG1Reference.BaseFieldPrime, limbs);

        return limbs;
    }


    private static ulong[] ComputeInversionExponent()
    {
        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs(P256BigIntegerG1Reference.BaseFieldPrime - 2, limbs);

        return limbs;
    }


    private static ulong[] ComputeDelta()
    {
        ulong[] limbs = new ulong[LimbCount];
        BigIntegerToLimbs((BigInteger.One << 256) - P256BigIntegerG1Reference.BaseFieldPrime, limbs);

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
}

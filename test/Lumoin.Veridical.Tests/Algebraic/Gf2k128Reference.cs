using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// A reference implementation of <c>GF(2^128) = GF(2)[x] / (x^128 + x^7 + x^2 + x + 1)</c> — the
/// binary field the deployed Longfellow runs its hash side over (the longfellow-zk reference's
/// <c>lib/gf2k</c> modulus, reduction constant <c>0x87</c>, plain polynomial representation).
/// Elements ride in the canonical 32-byte big-endian scalar slots with the high sixteen bytes
/// zero: bit <c>i</c> of the trailing 128-bit value is the coefficient of <c>x^i</c>. Addition
/// and subtraction are XOR (characteristic two), multiplication is carry-less polynomial
/// multiplication followed by reduction, inversion is the Fermat exponentiation
/// <c>a^(2^128 − 2)</c>, and reduce maps arbitrary-length big-endian input — read as a GF(2)
/// polynomial — into the field, which is what the transcript squeeze needs. BigInteger-backed
/// and deliberately slow-but-obvious, like the other reference fields.
/// </summary>
internal static class Gf2k128Reference
{
    private const int ScalarSize = 32;
    private const int Degree = 128;

    private static readonly BigInteger ElementMask = (BigInteger.One << Degree) - 1;


    /// <summary>Returns the add delegate (XOR).</summary>
    public static ScalarAddDelegate GetAdd() => Add;

    /// <summary>Returns the subtract delegate (XOR — characteristic two).</summary>
    public static ScalarSubtractDelegate GetSubtract() => Subtract;

    /// <summary>Returns the carry-less multiply delegate.</summary>
    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    /// <summary>Returns the invert delegate (Fermat <c>a^(2^128 − 2)</c>).</summary>
    public static ScalarInvertDelegate GetInvert() => Invert;

    /// <summary>Returns the reduce delegate (polynomial reduction of arbitrary-length input).</summary>
    public static ScalarReduceDelegate GetReduce() => Reduce;


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve) =>
        WriteCanonical(ReadCanonical(a) ^ ReadCanonical(b), result);


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve) =>
        WriteCanonical(ReadCanonical(a) ^ ReadCanonical(b), result);


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve) =>
        WriteCanonical(ReducePolynomial(CarrylessMultiply(ReadCanonical(a), ReadCanonical(b))), result);


    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        //Square-and-multiply over the exponent 2^128 − 2 = 0b111…110 (bits 1..127 set).
        BigInteger element = ReadCanonical(a);
        BigInteger accumulator = BigInteger.One;
        for(int bit = Degree - 1; bit >= 0; bit--)
        {
            accumulator = ReducePolynomial(CarrylessMultiply(accumulator, accumulator));
            if(bit != 0)
            {
                accumulator = ReducePolynomial(CarrylessMultiply(accumulator, element));
            }
        }

        WriteCanonical(accumulator, result);
    }


    private static void Reduce(ReadOnlySpan<byte> input, Span<byte> result, CurveParameterSet curve) =>
        WriteCanonical(ReducePolynomial(new BigInteger(input, isUnsigned: true, isBigEndian: true)), result);


    //The carry-less product via 4-bit windows of the right operand, Horner over its nibbles.
    private static BigInteger CarrylessMultiply(BigInteger a, BigInteger b)
    {
        Span<BigInteger> window = new BigInteger[16];
        for(int w = 1; w < 16; w++)
        {
            BigInteger entry = BigInteger.Zero;
            for(int bit = 0; bit < 4; bit++)
            {
                if((w & (1 << bit)) != 0)
                {
                    entry ^= a << bit;
                }
            }

            window[w] = entry;
        }

        BigInteger accumulator = BigInteger.Zero;
        for(int nibble = (Degree / 4) - 1; nibble >= 0; nibble--)
        {
            accumulator <<= 4;
            int digit = (int)((b >> (4 * nibble)) & 0xF);
            if(digit != 0)
            {
                accumulator ^= window[digit];
            }
        }

        return accumulator;
    }


    //Folds everything of degree 128 and above back down through x^128 ≡ x^7 + x^2 + x + 1.
    private static BigInteger ReducePolynomial(BigInteger value)
    {
        while(value > ElementMask)
        {
            BigInteger high = value >> Degree;
            value = (value & ElementMask) ^ high ^ (high << 1) ^ (high << 2) ^ (high << 7);
        }

        return value;
    }


    private static BigInteger ReadCanonical(ReadOnlySpan<byte> bytes) =>
        new(bytes, isUnsigned: true, isBigEndian: true);


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        Span<byte> little = stackalloc byte[ScalarSize + 1];
        if(value.TryWriteBytes(little, out int written, isUnsigned: true, isBigEndian: false))
        {
            for(int i = 0; i < written && i < ScalarSize; i++)
            {
                destination[ScalarSize - 1 - i] = little[i];
            }
        }
    }
}

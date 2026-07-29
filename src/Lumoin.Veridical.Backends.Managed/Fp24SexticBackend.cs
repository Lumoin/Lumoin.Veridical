using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers.Binary;
using System.Numerics;

namespace Lumoin.Veridical.Backends.Managed;

/// <summary>
/// The managed backend for <c>F_q[x] / (x^6 − 7)</c> over the FIPS 204 prime
/// <c>q = 8380417 = 2^23 − 2^13 + 1</c> — the sextic extension the Longfellow ML-DSA and SHA-3
/// circuits compile over (the longfellow-zk <c>Fp24_6(Fq(), beta = 7)</c> instantiation).
/// Elements ride in the canonical 32-byte big-endian scalar slots with the high eight bytes zero:
/// coefficient <c>e[i]</c> of <c>x^i</c> sits as a big-endian 32-bit value at byte offset
/// <c>28 − 4i</c>, so the container read as one big-endian integer equals
/// <c>Σ e[i] · 2^(32i)</c> and the compiler kernel's little-endian element serialization
/// reproduces the reference's <c>to_bytes_field</c> byte for byte.
/// </summary>
/// <remarks>
/// Multiplication is the reference's schoolbook convolution with the <c>x^6 = 7</c> fold:
/// coefficients stay below 2^23, the eleven 64-bit accumulators peak below 2^53, and each is
/// reduced modulo <c>q</c> once at the end. Inversion is the Fermat exponentiation
/// <c>a^(q^6 − 2)</c> over the fast multiply, which maps zero to zero.
/// </remarks>
public static class Fp24SexticBackend
{
    /// <summary>The FIPS 204 prime modulus <c>q = 2^23 − 2^13 + 1</c>.</summary>
    public const uint Modulus = 8380417;

    /// <summary>The extension residue: <c>x^6 − 7</c> is irreducible over <c>F_q</c> (the reference's <c>beta</c>).</summary>
    public const uint ExtensionResidue = 7;

    /// <summary>The extension degree.</summary>
    public const int LimbCount = 6;

    /// <summary>One coefficient's canonical byte width.</summary>
    public const int LimbBytes = 4;

    /// <summary>The on-wire element width in bytes (the reference's <c>kBytes</c>).</summary>
    public const int ElementBytes = LimbCount * LimbBytes;

    private const int ScalarSize = 32;

    /// <summary>The Fermat inversion exponent <c>q^6 − 2</c>.</summary>
    private static BigInteger InversionExponent { get; } = BigInteger.Pow(Modulus, LimbCount) - 2;


    /// <summary>Returns the add delegate (coefficient-wise addition modulo <c>q</c>).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarAddDelegate GetAdd() => Add;

    /// <summary>Returns the subtract delegate (coefficient-wise subtraction modulo <c>q</c>).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarSubtractDelegate GetSubtract() => Subtract;

    /// <summary>Returns the multiply delegate (schoolbook convolution with the <c>x^6 = 7</c> fold).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarMultiplyDelegate GetMultiply() => Multiply;

    /// <summary>Returns the invert delegate (Fermat <c>a^(q^6 − 2)</c>; zero maps to zero).</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1024", Justification = "Delegate-factory method following the established Get* backend convention.")]
    public static ScalarInvertDelegate GetInvert() => Invert;


    private static void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        Span<uint> left = stackalloc uint[LimbCount];
        Span<uint> right = stackalloc uint[LimbCount];
        ReadLimbs(a, left);
        ReadLimbs(b, right);

        for(int i = 0; i < LimbCount; i++)
        {
            left[i] = (uint)(((ulong)left[i] + right[i]) % Modulus);
        }

        WriteLimbs(left, result);
    }


    private static void Subtract(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        Span<uint> left = stackalloc uint[LimbCount];
        Span<uint> right = stackalloc uint[LimbCount];
        ReadLimbs(a, left);
        ReadLimbs(b, right);

        for(int i = 0; i < LimbCount; i++)
        {
            left[i] = (uint)(((ulong)left[i] + Modulus - right[i]) % Modulus);
        }

        WriteLimbs(left, result);
    }


    private static void Multiply(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
    {
        Span<uint> left = stackalloc uint[LimbCount];
        Span<uint> right = stackalloc uint[LimbCount];
        Span<uint> product = stackalloc uint[LimbCount];
        ReadLimbs(a, left);
        ReadLimbs(b, right);
        MultiplyLimbs(left, right, product);
        WriteLimbs(product, result);
    }


    private static void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
    {
        Span<uint> element = stackalloc uint[LimbCount];
        Span<uint> accumulator = stackalloc uint[LimbCount];
        Span<uint> scratch = stackalloc uint[LimbCount];
        ReadLimbs(a, element);

        //Square-and-multiply from the exponent's most significant bit; the exponent has no
        //special structure worth exploiting at this operand size.
        accumulator.Clear();
        accumulator[0] = 1;
        for(int bit = (int)InversionExponent.GetBitLength() - 1; bit >= 0; bit--)
        {
            MultiplyLimbs(accumulator, accumulator, scratch);
            scratch.CopyTo(accumulator);
            if(!InversionExponent.TestBit(bit))
            {
                continue;
            }

            MultiplyLimbs(accumulator, element, scratch);
            scratch.CopyTo(accumulator);
        }

        WriteLimbs(accumulator, result);
    }


    /// <summary>
    /// The reference's <c>Fp24_6::mul</c>: an eleven-term schoolbook convolution, the
    /// <c>x^6 = 7</c> fold of the upper five terms, then one modular reduction per coefficient.
    /// Inputs must be distinct from <paramref name="destination"/>.
    /// </summary>
    /// <param name="left">The left factor's coefficients.</param>
    /// <param name="right">The right factor's coefficients.</param>
    /// <param name="destination">Receives the product's coefficients.</param>
    private static void MultiplyLimbs(ReadOnlySpan<uint> left, ReadOnlySpan<uint> right, Span<uint> destination)
    {
        Span<ulong> convolution = stackalloc ulong[(2 * LimbCount) - 1];
        convolution.Clear();
        for(int i = 0; i < LimbCount; i++)
        {
            for(int j = 0; j < LimbCount; j++)
            {
                convolution[i + j] += (ulong)left[i] * right[j];
            }
        }

        for(int i = 0; i < LimbCount - 1; i++)
        {
            convolution[i] += convolution[i + LimbCount] * ExtensionResidue;
        }

        for(int i = 0; i < LimbCount; i++)
        {
            destination[i] = (uint)(convolution[i] % Modulus);
        }
    }


    /// <summary>Reads the six coefficients out of a canonical container: <c>e[i]</c> big-endian at byte offset <c>28 − 4i</c>.</summary>
    /// <param name="bytes">The canonical 32-byte element.</param>
    /// <param name="limbs">Receives the coefficients.</param>
    private static void ReadLimbs(ReadOnlySpan<byte> bytes, Span<uint> limbs)
    {
        for(int i = 0; i < LimbCount; i++)
        {
            limbs[i] = BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(ScalarSize - ((i + 1) * LimbBytes), LimbBytes));
        }
    }


    /// <summary>Writes the six coefficients into a canonical container, zeroing the leading pad.</summary>
    /// <param name="limbs">The coefficients.</param>
    /// <param name="destination">Receives the canonical 32-byte element.</param>
    private static void WriteLimbs(ReadOnlySpan<uint> limbs, Span<byte> destination)
    {
        destination[..(ScalarSize - ElementBytes)].Clear();
        for(int i = 0; i < LimbCount; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(ScalarSize - ((i + 1) * LimbBytes), LimbBytes), limbs[i]);
        }
    }


    /// <summary>Whether the given bit of a non-negative <see cref="BigInteger"/> is set.</summary>
    /// <param name="value">The value.</param>
    /// <param name="bit">The bit index.</param>
    /// <returns><see langword="true"/> when set.</returns>
    private static bool TestBit(this BigInteger value, int bit)
    {
        return !(value >> bit).IsEven;
    }
}

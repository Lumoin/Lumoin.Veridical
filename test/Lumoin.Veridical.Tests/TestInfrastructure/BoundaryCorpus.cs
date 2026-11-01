using System;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// The plain boundary data behind <see cref="BoundaryCorpusGen"/>: 32-byte big-endian field
/// elements that sit at algebraic edges of a prime field (zero, one, the modulus's neighbours,
/// limb-boundary bit patterns), with no dependency on a property-testing library so sweeps
/// that draw their own random operands can use the same values.
/// </summary>
/// <remarks>
/// The corpus values are computed once per call from the field modulus via
/// <see cref="BigInteger"/>, so test code never performs its own modular arithmetic to build
/// an edge case.
/// </remarks>
internal static class BoundaryCorpus
{
    /// <summary>The width in bytes of one canonical big-endian field element.</summary>
    private const int ElementSizeBytes = 32;

    /// <summary>The width in bytes of one limb of a limb-wise field implementation.</summary>
    private const int LimbSizeBytes = 8;

    /// <summary>The number of limbs in one element.</summary>
    private const int LimbCount = ElementSizeBytes / LimbSizeBytes;

    /// <summary>The width in bits of one limb.</summary>
    private const int BitsPerLimb = LimbSizeBytes * 8;


    /// <summary>
    /// Values already folded inside the field: 0, 1, 2, the midpoint <c>(p−1)/2</c>, the top
    /// two neighbours <c>p−2</c> and <c>p−1</c>, the all-ones 256-bit pattern, one
    /// single-high-bit pattern per 64-bit limb, and the alternating fills <c>0xAA</c> and
    /// <c>0x55</c>, each pattern folded into the field.
    /// </summary>
    /// <param name="modulus">The field modulus the values are computed against.</param>
    /// <returns>The distinct canonical 32-byte big-endian encodings.</returns>
    public static byte[][] CanonicalValues(BigInteger modulus)
    {
        var values = new List<BigInteger>
        {
            BigInteger.Zero,
            BigInteger.One,
            2,
            (modulus - 1) / 2,
            modulus - 2,
            modulus - 1,
            AllOnesPattern() % modulus,
            AlternatingBytePattern(0xAA) % modulus,
            AlternatingBytePattern(0x55) % modulus,
        };

        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            values.Add(SingleLimbHighBit(limbIndex) % modulus);
        }

        return EncodeDistinct(values);
    }


    /// <summary>
    /// Values that straddle or exceed the modulus without being folded: <c>p−1</c>,
    /// <c>p</c>, <c>p+1</c>, an all-<c>0xFF</c> fill, twice the modulus less one (when that
    /// still fits in 32 bytes), and a single high bit set in each 64-bit limb.
    /// </summary>
    /// <param name="modulus">The field modulus the values are computed against.</param>
    /// <returns>The distinct raw 32-byte big-endian encodings.</returns>
    public static byte[][] RawValues(BigInteger modulus)
    {
        var values = new List<BigInteger>
        {
            modulus - 1,
            modulus,
            modulus + 1,
            AllOnesPattern(),
        };

        BigInteger twiceModulusLessOne = (2 * modulus) - 1;
        if(Fits(twiceModulusLessOne))
        {
            values.Add(twiceModulusLessOne);
        }

        for(int limbIndex = 0; limbIndex < LimbCount; limbIndex++)
        {
            values.Add(SingleLimbHighBit(limbIndex));
        }

        return EncodeDistinct(values);
    }


    /// <summary>
    /// The canonical values followed by the raw values, with duplicates removed.
    /// </summary>
    /// <param name="modulus">The field modulus the values are computed against.</param>
    /// <returns>The distinct 32-byte big-endian encodings of both corpora.</returns>
    public static IReadOnlyList<byte[]> AllValues(BigInteger modulus)
    {
        var all = new List<byte[]>();
        foreach(byte[] candidate in CanonicalValues(modulus).Concat(RawValues(modulus)))
        {
            if(!all.Exists(existing => existing.AsSpan().SequenceEqual(candidate)))
            {
                all.Add(candidate);
            }
        }

        return all;
    }


    /// <summary>The 256-bit value with every bit set.</summary>
    private static BigInteger AllOnesPattern() => (BigInteger.One << (ElementSizeBytes * 8)) - 1;


    /// <summary>The 256-bit value with every byte equal to the fill byte.</summary>
    private static BigInteger AlternatingBytePattern(byte fillByte)
    {
        Span<byte> bytes = stackalloc byte[ElementSizeBytes];
        bytes.Fill(fillByte);

        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
    }


    /// <summary>
    /// The value with only bit 63 of the given big-endian limb set, the top bit of that 64-bit
    /// word and the classic carry-out boundary within a limb-wise adder.
    /// </summary>
    /// <param name="limbIndex">The limb to set, where index 0 is the most significant 8-byte limb.</param>
    private static BigInteger SingleLimbHighBit(int limbIndex)
    {
        int limbIndexFromLeast = LimbCount - 1 - limbIndex;

        return BigInteger.One << ((limbIndexFromLeast * BitsPerLimb) + (BitsPerLimb - 1));
    }


    /// <summary>Whether the value is representable in the canonical element width.</summary>
    private static bool Fits(BigInteger value) =>
        value >= BigInteger.Zero && value < (BigInteger.One << (ElementSizeBytes * 8));


    /// <summary>Encodes the values, dropping duplicates.</summary>
    private static byte[][] EncodeDistinct(List<BigInteger> values)
    {
        var distinct = new List<BigInteger>();
        foreach(BigInteger value in values)
        {
            if(!distinct.Contains(value))
            {
                distinct.Add(value);
            }
        }

        var encoded = new byte[distinct.Count][];
        for(int i = 0; i < distinct.Count; i++)
        {
            encoded[i] = Encode(distinct[i]);
        }

        return encoded;
    }


    /// <summary>
    /// Encodes one value as a right-aligned canonical big-endian element, the layout the
    /// sibling agreement tests use for hand-picked edge values.
    /// </summary>
    private static byte[] Encode(BigInteger value)
    {
        var destination = new byte[ElementSizeBytes];
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("A boundary corpus value did not fit in the canonical element width.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination.AsSpan(0, written).CopyTo(destination.AsSpan(shift));
            destination.AsSpan(0, shift).Clear();
        }

        return destination;
    }
}

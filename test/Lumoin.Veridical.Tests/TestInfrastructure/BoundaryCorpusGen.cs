using CsCheck;
using System;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// CsCheck byte-array generators that blend uniform random draws with a small
/// corpus of algebraically significant boundary values (zero, one, the
/// modulus's neighbours, limb-boundary bit patterns) so property sweeps
/// exercise carry-chain edges that uniform sampling alone essentially never
/// reaches.
/// </summary>
/// <remarks>
/// <para>
/// Every generator returns raw, unreduced 32-byte arrays exactly like a plain
/// <c>Gen.Byte.Array[32]</c> draw: callers canonicalize through a backend's
/// reduce delegate the same way they treat a uniform draw, so the boundary
/// values never require test code to perform its own modular arithmetic. The
/// corpus values are computed once from the field modulus via
/// <see cref="BigInteger"/> — that construction lives here, mirroring the
/// hand-picked edge vectors the agreement tests already build (e.g.
/// <c>Fp256FieldBackendAgreementTests.Bytes</c>), not in the property body.
/// </para>
/// <para>
/// <see cref="CanonicalDomain"/> supplies values already folded inside the
/// field (0, 1, 2, the midpoint, the two top neighbours, and limb patterns
/// reduced modulo the field) for algebraic-law sweeps where the operands
/// should already be meaningful field elements before the test's own
/// reduction step. <see cref="RawReduction"/> supplies values that straddle
/// or exceed the modulus (the modulus itself and its immediate neighbours, an
/// all-<c>0xFF</c> fill, single-bit-high limb patterns) for reduce and
/// round-trip paths that must accept any same-width input.
/// </para>
/// </remarks>
internal static class BoundaryCorpusGen
{
    private const int ElementSizeBytes = 32;
    private const int LimbSizeBytes = 8;
    private const int LimbCount = ElementSizeBytes / LimbSizeBytes;
    private const int BitsPerLimb = LimbSizeBytes * 8;

    //Roughly one boundary draw per six uniform draws: frequent enough that a
    //typical iteration count of a few hundred hits every corpus entry many
    //times over, sparse enough that CsCheck's shrinker still has uniform
    //noise around each failure to work with.
    private const int UniformDrawWeight = 6;
    private const int BoundaryDrawWeight = 1;


    /// <summary>
    /// A generator blending uniform 32-byte draws with boundary values
    /// already folded modulo <paramref name="modulus"/>: 0, 1, 2, the
    /// midpoint <c>(p−1)/2</c>, the top two neighbours <c>p−2</c> and
    /// <c>p−1</c>, the all-ones 256-bit pattern, one single-high-bit pattern
    /// per 64-bit limb, and the alternating fills <c>0xAA</c>/<c>0x55</c> —
    /// each of the limb-pattern entries folded into the field.
    /// </summary>
    /// <param name="modulus">The field modulus the boundary values are computed against.</param>
    public static Gen<byte[]> CanonicalDomain(BigInteger modulus) =>
        Gen.Frequency<byte[]>(
            (UniformDrawWeight, Gen.Byte.Array[ElementSizeBytes]),
            (BoundaryDrawWeight, Gen.OneOfConst(CanonicalCorpus(modulus))));


    /// <summary>
    /// A generator blending uniform 32-byte draws with boundary values that
    /// straddle or exceed <paramref name="modulus"/> without being folded
    /// first: the modulus's immediate neighbours, twice the modulus less one
    /// (when that still fits in 32 bytes), an all-<c>0xFF</c> fill, and a
    /// single high bit set in each 64-bit limb.
    /// </summary>
    /// <param name="modulus">The field modulus the boundary values are computed against.</param>
    public static Gen<byte[]> RawReduction(BigInteger modulus) =>
        Gen.Frequency<byte[]>(
            (UniformDrawWeight, Gen.Byte.Array[ElementSizeBytes]),
            (BoundaryDrawWeight, Gen.OneOfConst(RawCorpus(modulus))));


    private static byte[][] CanonicalCorpus(BigInteger modulus)
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


    private static byte[][] RawCorpus(BigInteger modulus)
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


    private static BigInteger AllOnesPattern() => (BigInteger.One << (ElementSizeBytes * 8)) - 1;


    private static BigInteger AlternatingBytePattern(byte fillByte)
    {
        Span<byte> bytes = stackalloc byte[ElementSizeBytes];
        bytes.Fill(fillByte);

        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
    }


    //The value with only bit 63 of the given big-endian limb set (limbIndex 0
    //is the most significant 8-byte limb), i.e. the top bit of that 64-bit
    //word — the classic carry-out boundary within a limb-wise adder.
    private static BigInteger SingleLimbHighBit(int limbIndex)
    {
        int limbIndexFromLeast = LimbCount - 1 - limbIndex;

        return BigInteger.One << ((limbIndexFromLeast * BitsPerLimb) + (BitsPerLimb - 1));
    }


    private static bool Fits(BigInteger value) =>
        value >= BigInteger.Zero && value < (BigInteger.One << (ElementSizeBytes * 8));


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


    //Mirrors the Bytes()/WriteCanonicalBytes() helpers the sibling agreement
    //tests already use to turn a hand-picked BigInteger edge value into a
    //right-aligned canonical big-endian element.
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

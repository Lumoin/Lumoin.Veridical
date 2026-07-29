using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The FIPS 204 sextic circuit-field binding of the wire-format Ligero seam: the
/// <see cref="LongfellowRowEncoderFactory"/> that builds <see cref="Fp24SexticReedSolomon"/>s (the
/// reference's <c>ReedSolomonExtensionFactory</c> — component-wise base-field encoding over the
/// auxiliary-prime convolution), and the <see cref="LongfellowFieldProfile"/> for
/// <c>F_q[x]/(x^6 − 7)</c>, <c>q = 8380417</c>. The ML-DSA statement callers construct these once and
/// hand them to the field-generic commitment, prover and verifier, exactly as the Fp256 signature
/// circuit does through <see cref="LongfellowFp256Encoding"/>.
/// </summary>
/// <remarks>
/// The canonical container packs coordinate <c>d</c>'s 4 big-endian bytes at offset <c>28 − 4d</c>
/// (the low 24 of the 32 container bytes), so the profile's little-endian wire reversal reproduces the
/// reference's <c>to_bytes_field</c> — six 4-byte little-endian coordinates, limb 0 first. Sampling is
/// the reference's <c>Fp24_6::sample</c>: six independent base-field draws of 3 bytes each, masked to
/// the modulus's 23 exact bits and rejected per coordinate, so the transcript challenge stream consumes
/// PRF bytes in the reference's order.
/// </remarks>
internal static class LongfellowFp24SexticEncoding
{
    /// <summary>The diagnostic tag the sextic row encoders carry.</summary>
    private const string EncoderTag = "Fp24 sextic RS";

    /// <summary>The FIPS 204 prime <c>q = 2^23 − 2^13 + 1</c>: the base field's <c>of_scalar</c>/<c>fits</c> bound.</summary>
    private const uint FieldModulus = 8380417;

    /// <summary>The sextic extension degree: six base-field coordinates per element.</summary>
    private const int LimbCount = 6;

    /// <summary>One base-field coordinate's width in bytes inside the canonical container.</summary>
    private const int LimbBytes = 4;

    /// <summary>The byte offset of coordinate 0 inside the canonical container (the least-significant limb; limb <c>d</c> sits at <c>LimbZeroOffset − d·LimbBytes</c>).</summary>
    private const int LimbZeroOffset = Scalar.SizeBytes - LimbBytes;

    /// <summary>The canonical container's leading zero bytes above the six coordinates.</summary>
    private const int ZeroPrefixBytes = Scalar.SizeBytes - (LimbCount * LimbBytes);

    /// <summary>The bytes one coordinate draw consumes (the reference's <c>total_l = (exact_bits_ + 7) / 8</c> with 23 exact modulus bits).</summary>
    private const int LimbSampleBytes = 3;

    /// <summary>The draw mask keeping the modulus's 23 exact bits (the reference's <c>mask</c> in <c>Fp24::sample</c>).</summary>
    private const uint LimbSampleMask = 0x7FFFFF;

    /// <summary>The reference's <c>subfield_boundary</c> for the ML-DSA and SHA-3 statements: their circuit builders never call <c>begin_full_field()</c>, so no input wire is marked subfield-known and every witness row draws full-field blinding.</summary>
    public static int StatementSubfieldBoundary { get; }

    /// <summary>The sextic on-wire element width (the reference <c>Fp24_6</c>'s <c>kBytes</c>): six 4-byte little-endian coordinates.</summary>
    public static int FieldElementBytes { get; } = LimbCount * LimbBytes;

    /// <summary>The subfield element width (the reference <c>Fp24_6</c>'s <c>kSubFieldBytes</c>): one base-field coordinate.</summary>
    public static int SubFieldBytes { get; } = LimbBytes;


    /// <summary>
    /// Builds the sextic row-encoder factory: each call wraps an <see cref="Fp24SexticReedSolomon"/> for
    /// the requested shape, whose pooled tables travel as the encoder's disposable state.
    /// </summary>
    /// <param name="pool">Pool the encoders' tables and columns rent from.</param>
    /// <returns>The factory; each returned encoder is owned by its caller.</returns>
    /// <exception cref="ArgumentNullException">When the pool is <see langword="null"/>.</exception>
    public static LongfellowRowEncoderFactory CreateEncoderFactory(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return (dimension, blockLength) =>
        {
            Fp24SexticReedSolomon encoder = new(dimension, blockLength, pool);

            return new LongfellowRowEncoder(EncoderTag, dimension, blockLength, encoder.Interpolate, encoder);
        };
    }


    /// <summary>Builds the sextic field profile; the caller owns its disposal.</summary>
    /// <param name="pool">Pool the profile's retained constant scalars rent from.</param>
    /// <returns>The sextic field profile.</returns>
    /// <exception cref="ArgumentNullException">When the pool is <see langword="null"/>.</exception>
    public static LongfellowFieldProfile CreateProfile(BaseMemoryPool pool) => LongfellowFieldProfile.ForFp24Sextic(OfScalar, InRange, SampleElement, pool);


    /// <summary>The sextic <c>of_scalar(u)</c>: the integer reduced mod <c>q</c> into coordinate 0 of the canonical container.</summary>
    /// <param name="coordinate">The coordinate integer.</param>
    /// <param name="destination">Receives the canonical scalar; <see cref="Scalar.SizeBytes"/> bytes.</param>
    public static void OfScalar(uint coordinate, Span<byte> destination)
    {
        destination.Clear();
        BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(LimbZeroOffset, LimbBytes), coordinate % FieldModulus);
    }


    /// <summary>The sextic <c>fits</c> predicate: the container's zero prefix intact and every 4-byte big-endian coordinate below <c>q</c> (the reference's per-coordinate <c>of_bytes_field</c> rejection).</summary>
    /// <param name="canonical">The canonical scalar to test.</param>
    /// <returns><see langword="true"/> when the bytes encode a field element.</returns>
    public static bool InRange(ReadOnlySpan<byte> canonical)
    {
        for(int i = 0; i < ZeroPrefixBytes; i++)
        {
            if(canonical[i] != 0)
            {
                return false;
            }
        }

        for(int limb = 0; limb < LimbCount; limb++)
        {
            uint value = BinaryPrimitives.ReadUInt32BigEndian(canonical.Slice(LimbZeroOffset - (limb * LimbBytes), LimbBytes));
            if(value >= FieldModulus)
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// The sextic <c>sample</c>: six independent base-field rejection draws, coordinate 0 first — the
    /// reference's <c>Fp24_6::sample</c> over <c>Fp24::sample</c>. Each attempt draws
    /// <see cref="LimbSampleBytes"/> bytes, reads them little-endian, masks to the modulus's 23 exact
    /// bits and redraws that coordinate while the value reaches <c>q</c>, so the byte stream consumed
    /// from the PRF matches the reference's draw order exactly.
    /// </summary>
    /// <param name="fillBytes">The raw-byte fill callback (the transcript PRF squeeze or the commit's entropy source).</param>
    /// <param name="working">Receives the canonical scalar; <see cref="Scalar.SizeBytes"/> bytes.</param>
    public static void SampleElement(LongfellowRandomByteSource fillBytes, Span<byte> working)
    {
        working.Clear();
        Span<byte> draw = stackalloc byte[LimbSampleBytes];
        for(int limb = 0; limb < LimbCount; limb++)
        {
            for(;;)
            {
                fillBytes(draw);
                uint value = ((uint)draw[0] | ((uint)draw[1] << 8) | ((uint)draw[2] << 16)) & LimbSampleMask;
                if(value < FieldModulus)
                {
                    BinaryPrimitives.WriteUInt32BigEndian(working.Slice(LimbZeroOffset - (limb * LimbBytes), LimbBytes), value);

                    break;
                }
            }
        }
    }
}

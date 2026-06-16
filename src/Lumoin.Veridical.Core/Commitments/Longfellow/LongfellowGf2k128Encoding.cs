using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The GF(2^128) binding of the wire-format Ligero seam: the <see cref="LongfellowRowEncoderFactory"/> that
/// builds <see cref="Lch14ReedSolomon"/>s over a shared <see cref="Lch14AdditiveFft"/>, and the
/// <see cref="LongfellowFieldProfile"/> for the binary field. The hash-circuit callers construct these once
/// from the additive-FFT engine and hand them to the field-generic commitment, prover and verifier — the
/// values produced are exactly those the binary-only port baked in (the LCH14 encoder, 16-byte framing, the
/// subfield <c>of_scalar</c> via <c>NodeElement</c>, and the <c>g</c> third evaluation point), so routing the
/// GF path through the seam leaves its bytes unchanged.
/// </summary>
internal static class LongfellowGf2k128Encoding
{
    //The diagnostic tag the GF(2^128) row encoders carry.
    private const string EncoderTag = "LCH14 GF(2^128)";


    /// <summary>
    /// Builds the GF(2^128) row-encoder factory over <paramref name="fft"/>: each call wraps an
    /// <see cref="Lch14ReedSolomon"/> for the requested shape (which borrows <paramref name="fft"/> and owns
    /// nothing, so the wrapper holds no disposable state), renting its transient scratch from
    /// <paramref name="pool"/> per row.
    /// </summary>
    /// <param name="fft">The shared LCH14 additive-FFT engine.</param>
    /// <param name="pool">Pool the encoders' per-call scratch rents from.</param>
    public static LongfellowRowEncoderFactory CreateEncoderFactory(Lch14AdditiveFft fft, BaseMemoryPool pool) =>
        (dimension, blockLength) =>
        {
            Lch14ReedSolomon encoder = new(dimension, blockLength, fft, pool);

            return new LongfellowRowEncoder(EncoderTag, dimension, blockLength, encoder.Interpolate);
        };


    /// <summary>Builds the GF(2^128) field profile over <paramref name="fft"/>.</summary>
    /// <param name="fft">The shared LCH14 additive-FFT engine (supplies the subfield <c>of_scalar</c> and the <c>g</c> evaluation point).</param>
    public static LongfellowFieldProfile CreateProfile(Lch14AdditiveFft fft) => LongfellowFieldProfile.ForGf2k128(fft);
}

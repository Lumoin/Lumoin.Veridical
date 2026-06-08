using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Squeeze extensions on <see cref="FiatShamirTranscript"/>: the raw-byte
/// squeeze plus the typed scalar squeeze built on top of it.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class FiatShamirTranscriptSqueezeExtensions
{
    //64 bytes for the scalar squeeze: 32 bytes of the field width plus
    //32 bytes of additional entropy makes the modular-reduction bias
    //bounded by 2^-256 (negligible at 128-bit security per RFC 9380's
    //reasoning for hash-to-field's L = 64).
    private const int SqueezeWideBytes = 64;


    extension(FiatShamirTranscript transcript)
    {
        /// <summary>
        /// Squeezes <c>destination.Length</c> bytes into
        /// <paramref name="destination"/> and updates the transcript
        /// state via the chained <c>state-update</c> hash call.
        /// </summary>
        /// <param name="label">The per-operation label.</param>
        /// <param name="destination">The buffer to fill with the squeezed output. May be any length.</param>
        /// <param name="squeeze">The backend XOF implementation.</param>
        /// <param name="hash">The backend fixed-output hash implementation, used by the post-squeeze state update.</param>
        public void SqueezeBytes(
            FiatShamirOperationLabel label,
            Span<byte> destination,
            FiatShamirSqueezeDelegate squeeze,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            transcript.Squeeze(label, destination, squeeze, hash);
        }


        /// <summary>
        /// Squeezes a wide byte stream from the transcript and reduces
        /// it modulo <paramref name="curve"/>'s scalar field order to produce
        /// a canonical-form scalar.
        /// </summary>
        /// <param name="label">The per-operation label.</param>
        /// <param name="squeeze">The XOF backend.</param>
        /// <param name="hash">The fixed-output hash backend, used by the post-squeeze state update.</param>
        /// <param name="reduce">The scalar-reduce backend that maps wide bytes to a canonical scalar.</param>
        /// <param name="curve">The curve whose scalar field the result belongs to.</param>
        /// <param name="pool">The pool to rent the scratch buffer and the returned scalar's buffer from.</param>
        /// <returns>A canonical scalar over <paramref name="curve"/> derived from the squeeze output.</returns>
        public Scalar SqueezeScalar(
            FiatShamirOperationLabel label,
            FiatShamirSqueezeDelegate squeeze,
            FiatShamirHashDelegate hash,
            ScalarReduceDelegate reduce,
            CurveParameterSet curve,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(reduce);
            ArgumentNullException.ThrowIfNull(pool);

            using IMemoryOwner<byte> wideOwner = pool.Rent(SqueezeWideBytes);
            Span<byte> wide = wideOwner.Memory.Span[..SqueezeWideBytes];
            transcript.SqueezeBytes(label, wide, squeeze, hash);

            return Scalar.FromBytesReduced(wide, reduce, curve, pool);
        }
    }
}
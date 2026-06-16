using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// Fiat-Shamir transcript operations for the Ligero argument: absorbing the
/// tableau's column Merkle root, squeezing a vector of challenge scalars under
/// a pinned operation label, and squeezing the distinct opened-column indices.
/// Prover and verifier call these in the same order so they reach identical
/// transcript states and therefore identical challenges and indices.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class FiatShamirTranscriptLigeroExtensions
{
    private const int ScalarSize = Scalar.SizeBytes;

    //64 bytes per challenge scalar: the field width plus 32 bytes of extra
    //entropy bound the modular-reduction bias by 2^-256, matching the scalar
    //squeeze in FiatShamirTranscriptSqueezeExtensions.
    private const int SqueezeWideBytes = 64;

    //Eight bytes give a 64-bit draw per opened-column index. The extension
    //width is not in general a power of two, so the value is mapped into range
    //by bias-free rejection rather than masking.
    private const int IndexSqueezeBytes = sizeof(ulong);

    //A generous cap on rejection re-squeezes per opened-column index. Bias
    //rejection is astronomically rare (the width is at most 2^31, far below
    //2^64) and duplicate rejection happens with probability below
    //filled/width < 1, so the expected attempt count per index is barely above
    //one; the cap exists only to turn a pathological transcript into a thrown
    //error rather than a hang, and applies identically on both sides.
    private const int MaximumAttemptsPerIndex = 1024;


    extension(FiatShamirTranscript transcript)
    {
        /// <summary>
        /// Absorbs the tableau's column Merkle root under the
        /// <see cref="WellKnownLigeroTranscriptLabels.TableauRoot"/> label —
        /// the commitment that binds every subsequent challenge.
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="root"/> or <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbLigeroTableauRoot(MerkleRoot root, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(root);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownLigeroTranscriptLabels.TableauRoot),
                root.AsReadOnlySpan(),
                hash);
        }


        /// <summary>
        /// Squeezes <paramref name="count"/> canonical challenge scalars over
        /// <paramref name="curve"/> under <paramref name="label"/>, writing them
        /// consecutively into <paramref name="destination"/>. The Ligero
        /// challenge vectors — <c>u_ldt</c>, <c>αl</c>, <c>αq</c>,
        /// <c>u_quad</c> — are each one call with the matching pinned label from
        /// <see cref="WellKnownLigeroTranscriptLabels"/>.
        /// </summary>
        /// <param name="label">The pinned operation label naming this challenge vector.</param>
        /// <param name="count">The number of scalars to squeeze; at least zero.</param>
        /// <param name="destination">Receives <paramref name="count"/> scalars (<c>count · 32</c> bytes).</param>
        /// <param name="squeeze">The XOF backend.</param>
        /// <param name="hash">The fixed-output hash backend, used by the post-squeeze state update.</param>
        /// <param name="reduce">The scalar-reduce backend mapping wide bytes to a canonical scalar.</param>
        /// <param name="curve">The curve whose scalar field the challenges belong to.</param>
        /// <param name="pool">Pool to rent the squeeze scratch from.</param>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">When <paramref name="count"/> is negative.</exception>
        /// <exception cref="ArgumentException">When <paramref name="destination"/> is the wrong length.</exception>
        public void SqueezeLigeroChallengeScalars(
            FiatShamirOperationLabel label,
            int count,
            Span<byte> destination,
            FiatShamirSqueezeDelegate squeeze,
            FiatShamirHashDelegate hash,
            ScalarReduceDelegate reduce,
            CurveParameterSet curve,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(reduce);
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentOutOfRangeException.ThrowIfNegative(count);
            if(destination.Length != count * ScalarSize)
            {
                throw new ArgumentException($"Destination must be {count * ScalarSize} bytes; received {destination.Length}.", nameof(destination));
            }

            using IMemoryOwner<byte> wideOwner = pool.Rent(SqueezeWideBytes);
            Span<byte> wide = wideOwner.Memory.Span[..SqueezeWideBytes];
            for(int i = 0; i < count; i++)
            {
                transcript.SqueezeBytes(label, wide, squeeze, hash);
                reduce(wide, destination.Slice(i * ScalarSize, ScalarSize), curve);
            }
        }


        /// <summary>
        /// Squeezes <paramref name="count"/> distinct opened-column indices in
        /// <c>[0, extensionWidth)</c> under the
        /// <see cref="WellKnownLigeroTranscriptLabels.ColumnIndex"/> label,
        /// writing them in draw order into <paramref name="destination"/>. The
        /// width need not be a power of two: each draw is mapped into range by
        /// bias-free rejection, and a draw equal to an already-chosen index is
        /// rejected and re-squeezed, so the result is sampling without
        /// replacement. Prover and verifier replay the identical rejection loop
        /// and obtain the identical set.
        /// </summary>
        /// <param name="extensionWidth">The number of committed columns to sample from; at least one.</param>
        /// <param name="count">The number of distinct indices to draw; in <c>[0, extensionWidth]</c>.</param>
        /// <param name="destination">Receives the <paramref name="count"/> drawn indices.</param>
        /// <param name="squeeze">The XOF backend.</param>
        /// <param name="hash">The fixed-output hash backend, used by the post-squeeze state update.</param>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">When <paramref name="extensionWidth"/> is non-positive or <paramref name="count"/> is outside <c>[0, extensionWidth]</c>.</exception>
        /// <exception cref="ArgumentException">When <paramref name="destination"/> is the wrong length.</exception>
        /// <exception cref="InvalidOperationException">When the rejection loop fails to find a fresh index within the attempt cap.</exception>
        public void SqueezeLigeroDistinctColumnIndices(
            int extensionWidth,
            int count,
            Span<int> destination,
            FiatShamirSqueezeDelegate squeeze,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(extensionWidth);
            ArgumentOutOfRangeException.ThrowIfNegative(count);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(count, extensionWidth);
            if(destination.Length != count)
            {
                throw new ArgumentException($"Destination must hold {count} indices; received {destination.Length}.", nameof(destination));
            }

            FiatShamirOperationLabel label = new(WellKnownLigeroTranscriptLabels.ColumnIndex);

            //The largest multiple of the width at or below 2^64: draws at or
            //above it are the biased tail and are rejected so the in-range
            //mapping is exactly uniform.
            UInt128 range = (UInt128)(uint)extensionWidth;
            UInt128 acceptanceLimit = ((UInt128)1 << 64) - (((UInt128)1 << 64) % range);

            Span<byte> bytes = stackalloc byte[IndexSqueezeBytes];
            int filled = 0;
            while(filled < count)
            {
                int index = DrawFreshIndex(transcript, label, range, acceptanceLimit, destination[..filled], bytes, squeeze, hash);
                destination[filled] = index;
                filled++;
            }
        }
    }


    //Re-squeezes until a draw is both inside the unbiased range and distinct
    //from every already-chosen index, returning that index.
    private static int DrawFreshIndex(
        FiatShamirTranscript transcript,
        FiatShamirOperationLabel label,
        UInt128 range,
        UInt128 acceptanceLimit,
        ReadOnlySpan<int> chosen,
        Span<byte> bytes,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash)
    {
        for(int attempt = 0; attempt < MaximumAttemptsPerIndex; attempt++)
        {
            transcript.SqueezeBytes(label, bytes, squeeze, hash);
            UInt128 value = BinaryPrimitives.ReadUInt64BigEndian(bytes);
            if(value >= acceptanceLimit)
            {
                continue;
            }

            int index = (int)(value % range);
            if(!chosen.Contains(index))
            {
                return index;
            }
        }

        throw new InvalidOperationException(
            $"Could not draw a fresh opened-column index within {MaximumAttemptsPerIndex} attempts; the transcript is degenerate.");
    }
}

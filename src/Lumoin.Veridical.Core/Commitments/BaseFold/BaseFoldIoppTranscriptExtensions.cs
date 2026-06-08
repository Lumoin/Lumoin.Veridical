using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// Fiat-Shamir transcript operations for the BaseFold IOPP: absorbing each
/// fold-layer Merkle root and the cleartext final oracle, squeezing the
/// per-round fold challenge, and squeezing verifier query indices. Prover and
/// verifier call these in the same order so they reach identical transcript
/// states and therefore identical challenges and query indices.
/// </summary>
/// <remarks>
/// The absorb/squeeze schedule is: absorb the input codeword's root, then for
/// each layer squeeze a fold challenge and absorb the next layer's root, then
/// absorb the cleartext final oracle, then squeeze the query indices. The roots
/// are absorbed under <see cref="WellKnownBaseFoldTranscriptLabels.FoldRoot"/>,
/// the final oracle under <see cref="WellKnownBaseFoldTranscriptLabels.FinalOracle"/>,
/// the challenges squeezed under
/// <see cref="WellKnownBaseFoldTranscriptLabels.FoldChallenge"/>, and the query
/// indices under <see cref="WellKnownBaseFoldTranscriptLabels.QueryIndex"/>.
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BaseFoldIoppTranscriptExtensions
{
    //Bytes squeezed for a query index. Eight bytes give a 64-bit value; the
    //query domain is a power of two, so masking is unbiased regardless of the
    //byte count, but eight bytes comfortably cover any practical domain size.
    private const int QueryIndexSqueezeBytes = sizeof(ulong);


    extension(FiatShamirTranscript transcript)
    {
        /// <summary>
        /// Absorbs a fold-layer codeword's Merkle root under the
        /// <see cref="WellKnownBaseFoldTranscriptLabels.FoldRoot"/> label.
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="root"/> or <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbBaseFoldFoldRoot(MerkleRoot root, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(root);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownBaseFoldTranscriptLabels.FoldRoot),
                root.AsReadOnlySpan(),
                hash);
        }


        /// <summary>
        /// Absorbs the cleartext final (base-layer) codeword under the
        /// <see cref="WellKnownBaseFoldTranscriptLabels.FinalOracle"/> label.
        /// </summary>
        /// <exception cref="ArgumentNullException">When <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbBaseFoldFinalOracle(ReadOnlySpan<byte> finalOracle, FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownBaseFoldTranscriptLabels.FinalOracle),
                finalOracle,
                hash);
        }


        /// <summary>
        /// Squeezes a per-round fold challenge <c>α</c> as a canonical scalar
        /// over <paramref name="curve"/> under the
        /// <see cref="WellKnownBaseFoldTranscriptLabels.FoldChallenge"/> label.
        /// </summary>
        /// <returns>The fold challenge; the caller owns its disposal.</returns>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        public Scalar SqueezeBaseFoldFoldChallenge(
            FiatShamirSqueezeDelegate squeeze,
            FiatShamirHashDelegate hash,
            ScalarReduceDelegate reduce,
            CurveParameterSet curve,
            SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(transcript);

            return transcript.SqueezeScalar(
                new FiatShamirOperationLabel(WellKnownBaseFoldTranscriptLabels.FoldChallenge),
                squeeze,
                hash,
                reduce,
                curve,
                pool);
        }


        /// <summary>
        /// Squeezes a verifier query index in <c>[0, queryDomainSize)</c> under
        /// the <see cref="WellKnownBaseFoldTranscriptLabels.QueryIndex"/> label.
        /// The domain size must be a power of two (every BaseFold fold-layer
        /// length is), so the reduction is an unbiased low-bit mask.
        /// </summary>
        /// <param name="queryDomainSize">The number of distinct query positions; a power of two.</param>
        /// <param name="squeeze">The XOF backend.</param>
        /// <param name="hash">The fixed-output hash backend, used by the post-squeeze state update.</param>
        /// <returns>A query index in <c>[0, queryDomainSize)</c>.</returns>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When <paramref name="queryDomainSize"/> is not a positive power of two.</exception>
        public int SqueezeBaseFoldQueryIndex(
            int queryDomainSize,
            FiatShamirSqueezeDelegate squeeze,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryDomainSize);

            if(!BitOperations.IsPow2((uint)queryDomainSize))
            {
                throw new ArgumentException($"Query domain size must be a power of two; received {queryDomainSize}.", nameof(queryDomainSize));
            }

            Span<byte> bytes = stackalloc byte[QueryIndexSqueezeBytes];
            transcript.SqueezeBytes(
                new FiatShamirOperationLabel(WellKnownBaseFoldTranscriptLabels.QueryIndex),
                bytes,
                squeeze,
                hash);

            ulong value = BinaryPrimitives.ReadUInt64BigEndian(bytes);

            //Power-of-two domain: the low bits are an unbiased uniform sample.
            return (int)(value & (ulong)(queryDomainSize - 1));
        }
    }
}

using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Typed transcript absorbs for Spartan messages over BLS12-381. Each
/// helper writes the message's canonical byte layout under a stable
/// per-message operation label so prover and verifier reach the same
/// transcript state from the same inputs.
/// </summary>
/// <remarks>
/// <para>
/// The compressed-round-polynomial absorb pins the canonical
/// Spartan2 transcript shape: exactly the
/// <c>(c_0, c_2, c_3, ..., c_d)</c> bytes (with no length prefix) are
/// absorbed under the per-round label.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class FiatShamirTranscriptSpartanAbsorbExtensions
{
    extension(FiatShamirTranscript transcript)
    {
        /// <summary>
        /// Absorbs a Spartan compressed sumcheck round polynomial under
        /// the label <see cref="WellKnownSpartanTranscriptLabels.SumcheckRoundPolynomial"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the compressed polynomial is not over BLS12-381.</exception>
        public void AbsorbCompressedRoundPolynomial(
            CompressedRoundPolynomial roundPolynomial,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(roundPolynomial);
            WellKnownCurves.ThrowIfCurveNotWired(roundPolynomial.Curve);

            //Routes through the scheme-neutral sumcheck absorb under the pinned
            //Spartan label; byte-identical to absorbing the compressed bytes
            //directly, so the transcript shape (and proof fixtures) are unchanged.
            transcript.AbsorbRoundPolynomial(
                new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.SumcheckRoundPolynomial),
                roundPolynomial,
                hash);
        }


        /// <summary>
        /// Absorbs a Spartan sumcheck's initial claim header — the
        /// claimed-sum scalar bytes, the round count, and the per-round
        /// degree bound — under the label
        /// <see cref="WellKnownSpartanTranscriptLabels.SumcheckInitialClaim"/>.
        /// </summary>
        /// <remarks>
        /// The claim's two integer fields are concatenated as 4-byte
        /// big-endian after the claimed-sum bytes so the layout is
        /// stable across platforms.
        /// </remarks>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        public void AbsorbSumcheckClaim(
            SumcheckClaim claim,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(claim.ClaimedSum);

            //Layout: [claimed-sum : 32 bytes] [num-rounds : 4 bytes BE] [degree-bound : 4 bytes BE]. The
            //small fixed-size buffer is stack-allocated to avoid a pool
            //allocation in the hot transcript path.
            Span<byte> buffer = stackalloc byte[Scalar.SizeBytes + (2 * sizeof(int))];
            claim.ClaimedSum.AsReadOnlySpan().CopyTo(buffer[..Scalar.SizeBytes]);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(
                buffer.Slice(Scalar.SizeBytes, sizeof(int)),
                claim.NumRounds);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(
                buffer.Slice(Scalar.SizeBytes + sizeof(int), sizeof(int)),
                claim.DegreeBound);

            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.SumcheckInitialClaim),
                buffer,
                hash);
        }
    }
}
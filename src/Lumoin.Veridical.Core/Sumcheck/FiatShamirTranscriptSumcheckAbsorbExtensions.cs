using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Sumcheck;

/// <summary>
/// Scheme-neutral transcript absorb for a sumcheck round polynomial. Any
/// sumcheck-based protocol (Spartan, BaseFold, …) absorbs its per-round
/// compressed polynomial through this verb, supplying its own operation label
/// so the protocols stay transcript-separated while sharing one primitive.
/// </summary>
/// <remarks>
/// The absorbed bytes are exactly the compressed round polynomial's canonical
/// storage — <c>(c_0, c_2, …, c_d)</c>, no length prefix — under the
/// caller-supplied label. A protocol's own typed wrapper (for example Spartan's
/// <c>AbsorbCompressedRoundPolynomial</c>) pins its label and routes here, so
/// the byte sequence written to the transcript is identical to absorbing the
/// bytes directly under that label.
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class FiatShamirTranscriptSumcheckAbsorbExtensions
{
    extension(FiatShamirTranscript transcript)
    {
        /// <summary>
        /// Absorbs a compressed sumcheck round polynomial under
        /// <paramref name="label"/>.
        /// </summary>
        /// <param name="label">The protocol's per-round operation label.</param>
        /// <param name="roundPolynomial">The compressed round polynomial to absorb.</param>
        /// <param name="hash">The Fiat-Shamir hash backend.</param>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        public void AbsorbRoundPolynomial(
            FiatShamirOperationLabel label,
            CompressedRoundPolynomial roundPolynomial,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(roundPolynomial);

            transcript.AbsorbBytes(label, roundPolynomial.AsReadOnlySpan(), hash);
        }
    }
}

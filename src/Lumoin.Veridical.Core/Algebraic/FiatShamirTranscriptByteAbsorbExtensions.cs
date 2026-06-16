using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Lowest-level absorb extension on <see cref="FiatShamirTranscript"/>.
/// Protocols that hold bytes not covered by a curve-specific typed
/// absorb pass them through here.
/// </summary>
/// <remarks>
/// <para>
/// All the typed absorbs in
/// <c>FiatShamirTranscriptAbsorbExtensions</c> ultimately
/// route through this method, so the byte-absorb path is exercised
/// implicitly by every higher-level absorb test.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class FiatShamirTranscriptByteAbsorbExtensions
{
    extension(FiatShamirTranscript transcript)
    {
        /// <summary>
        /// Absorbs the supplied bytes into the transcript under the
        /// given operation label.
        /// </summary>
        /// <param name="label">The per-operation label.</param>
        /// <param name="data">The bytes to absorb.</param>
        /// <param name="hash">The hash backend.</param>
        /// <exception cref="ArgumentNullException">When <paramref name="hash"/> is <see langword="null"/>.</exception>
        public void AbsorbBytes(
            FiatShamirOperationLabel label,
            ReadOnlySpan<byte> data,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            transcript.UpdateState(label, data, hash);
        }
    }
}
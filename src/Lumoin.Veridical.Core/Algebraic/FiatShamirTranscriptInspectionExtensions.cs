using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Read-only inspection verbs on <see cref="FiatShamirTranscript"/>.
/// Useful for debugger displays and protocol-level logging when both
/// prover and verifier sides need to confirm they reached the same
/// state at the same protocol round.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class FiatShamirTranscriptInspectionExtensions
{
    extension(FiatShamirTranscript transcript)
    {
        /// <summary>
        /// Lowercase hex rendering of the current 32-byte hash state.
        /// </summary>
        public string CurrentStateHex
        {
            get
            {
                ArgumentNullException.ThrowIfNull(transcript);

                return Convert.ToHexStringLower(transcript.AsReadOnlySpan());
            }
        }


        /// <summary>The hash function name as supplied at construction.</summary>
        public string HashFunctionName
        {
            get
            {
                ArgumentNullException.ThrowIfNull(transcript);

                return transcript.HashFunction;
            }
        }
    }
}
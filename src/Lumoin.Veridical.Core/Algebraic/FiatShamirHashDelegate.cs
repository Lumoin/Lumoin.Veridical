using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes a fixed-output cryptographic hash of the entire input span,
/// writing exactly the destination span's length of bytes — by contract
/// always <see cref="FiatShamirTranscript.StateSizeBytes"/> (32 bytes)
/// for the transcript's state-update path.
/// </summary>
/// <param name="input">The complete input bytes; the backend treats this as a single message and produces one output.</param>
/// <param name="output">The destination span the backend writes the digest into. Length is fixed at 32 bytes for transcript state updates.</param>
/// <param name="hashFunction">The canonical hash function name from <see cref="WellKnownHashAlgorithms"/>. Backends that do not implement the requested algorithm throw <see cref="NotSupportedException"/> with a message naming the algorithm.</param>
/// <remarks>
/// <para>
/// The delegate is stateless: every call describes the entire
/// computation through <paramref name="input"/>. The backend does not
/// maintain incremental state between calls; that responsibility lives
/// in the transcript itself (its 32-byte state, the squeeze counter).
/// </para>
/// <para>
/// The same delegate is used for the four hash-shaped operations the
/// transcript performs — initialisation, absorption, state-update after
/// squeeze, and (when <paramref name="hashFunction"/> resolves to a
/// fixed-output algorithm) the squeeze itself. The transcript composes
/// the appropriate input prefix for each operation; the delegate just
/// hashes.
/// </para>
/// </remarks>
public delegate void FiatShamirHashDelegate(
    ReadOnlySpan<byte> input,
    Span<byte> output,
    string hashFunction);
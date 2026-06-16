using System;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Computes an extendable-output hash (XOF) of the input and writes
/// the requested number of output bytes. For BLAKE3 this is the native
/// XOF mode; for SHAKE128/SHAKE256 it is the natural fit; for
/// fixed-output algorithms a backend implements this through HKDF-Expand
/// or a similar construction.
/// </summary>
/// <param name="input">The complete input bytes the XOF computation derives from.</param>
/// <param name="output">The destination span; the backend writes <c>output.Length</c> bytes. The transcript uses 64 bytes for the squeeze-to-scalar path so the modular-reduction bias is negligible.</param>
/// <param name="hashFunction">The canonical hash function name. Backends that do not implement the requested algorithm throw <see cref="NotSupportedException"/>.</param>
/// <remarks>
/// <para>
/// The XOF over <c>n</c> bytes is required to be indistinguishable from
/// <c>n</c> independent uniform bytes under the random-oracle
/// assumption. Different output lengths over the same input produce
/// outputs that are prefix-related — calling once with 64 bytes is
/// equivalent to calling once with 32 bytes and getting the first 32
/// bytes of the 64-byte result. Callers of this delegate do not need
/// to assume otherwise; the transcript pairs each squeeze with a fresh
/// state-update.
/// </para>
/// </remarks>
public delegate void FiatShamirSqueezeDelegate(
    ReadOnlySpan<byte> input,
    Span<byte> output,
    string hashFunction);
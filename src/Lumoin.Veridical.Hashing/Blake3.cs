using Lumoin.Veridical.Hashing.Internal;
using System;

namespace Lumoin.Veridical.Hashing;

/// <summary>
/// Top-level static convenience API for BLAKE3. Hashes a byte payload
/// into a caller-provided destination in one call, using the
/// highest-capability backend available on the current CPU.
/// </summary>
/// <remarks>
/// <para>
/// For incremental hashing or backend-explicit wiring, use
/// <see cref="Blake3Hasher"/> directly. The static entry points here
/// are signature-compatible with the xoofx <c>Blake3</c> package's
/// <c>Hash(input, output)</c> overload so consumer call sites can swap
/// the implementation textually.
/// </para>
/// <para>
/// All three modes — hash, keyed_hash, derive_key — are first-class.
/// In hash and keyed_hash modes, the destination length determines
/// whether the standard 32-byte digest or the extendable-output stream
/// is produced. In derive_key mode the destination length is the
/// caller's choice (typically 32 bytes for symmetric keys, longer for
/// keystreams).
/// </para>
/// </remarks>
public static class Blake3
{
    /// <summary>
    /// Computes BLAKE3 of <paramref name="input"/> into
    /// <paramref name="output"/> in the regular hash mode. A 32-byte
    /// destination produces the standard fixed-output digest; any other
    /// length produces the corresponding prefix of the XOF stream.
    /// </summary>
    /// <param name="input">The input bytes to hash.</param>
    /// <param name="output">The destination buffer.</param>
    public static void Hash(ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Blake3Hasher hasher = Blake3Hasher.CreateAutoSelected();
        hasher.Update(input);
        hasher.FinalizeXof(output);
    }


    /// <summary>
    /// Computes BLAKE3 of <paramref name="input"/> into
    /// <paramref name="output"/> in the keyed-hash mode under the
    /// supplied <paramref name="key"/>. A 32-byte destination produces
    /// the standard fixed-output keyed digest; any other length
    /// produces the corresponding prefix of the XOF stream.
    /// </summary>
    /// <param name="key">Exactly 32 bytes of key material.</param>
    /// <param name="input">The input bytes to hash.</param>
    /// <param name="output">The destination buffer.</param>
    /// <exception cref="ArgumentException">When <paramref name="key"/> is not exactly 32 bytes.</exception>
    public static void HashKeyed(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> input,
        Span<byte> output)
    {
        Blake3Backend backend = Blake3BackendSelection.SelectBest();
        using Blake3Hasher hasher = Blake3Hasher.CreateKeyed(key, backend);
        hasher.Update(input);
        hasher.FinalizeXof(output);
    }


    /// <summary>
    /// Derives output bytes from <paramref name="keyMaterial"/> under
    /// the application-specific <paramref name="context"/> string. The
    /// derivation is domain-separated by <paramref name="context"/>: the
    /// same <paramref name="keyMaterial"/> under different contexts
    /// yields independent output streams.
    /// </summary>
    /// <param name="context">A globally unique, application-specific context string, encoded as UTF-8.</param>
    /// <param name="keyMaterial">The input key material to derive from.</param>
    /// <param name="output">The destination buffer of any length.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="context"/> is <see langword="null"/>.</exception>
    public static void DeriveKey(
        string context,
        ReadOnlySpan<byte> keyMaterial,
        Span<byte> output)
    {
        Blake3Backend backend = Blake3BackendSelection.SelectBest();
        using Blake3Hasher hasher = Blake3Hasher.CreateDeriveKey(context, backend);
        hasher.Update(keyMaterial);
        hasher.FinalizeXof(output);
    }
}
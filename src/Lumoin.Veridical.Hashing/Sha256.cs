using System;

namespace Lumoin.Veridical.Hashing;

/// <summary>
/// Top-level static convenience API for SHA-256. Hashes a byte payload into
/// a caller-provided 32-byte destination in one call, using the
/// highest-capability backend available on the current CPU. Mirrors
/// <see cref="Blake3"/>.
/// </summary>
/// <remarks>
/// <para>
/// For incremental hashing or forkable snapshot state, use
/// <see cref="Sha256Hasher"/> directly. This one-shot entry point wraps
/// <see cref="Sha256Hasher.CreateAutoSelected"/> with a single
/// <see cref="Sha256Hasher.Update(System.ReadOnlySpan{byte})"/> and
/// <see cref="Sha256Hasher.Finalize(System.Span{byte})"/>, so its result is
/// byte-identical to <c>System.Security.Cryptography.SHA256.HashData</c>.
/// </para>
/// </remarks>
public static class Sha256
{
    /// <summary>
    /// Computes SHA-256 of <paramref name="input"/> into
    /// <paramref name="output"/>, which must be exactly
    /// <see cref="Sha256Hasher.DigestSizeBytes"/> bytes.
    /// </summary>
    /// <param name="input">The input bytes to hash.</param>
    /// <param name="output">The 32-byte destination buffer.</param>
    /// <exception cref="ArgumentException">When <paramref name="output"/> is not <see cref="Sha256Hasher.DigestSizeBytes"/> bytes.</exception>
    public static void HashData(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Sha256Hasher hasher = Sha256Hasher.CreateAutoSelected();
        hasher.Update(input);
        hasher.Finalize(output);
    }
}

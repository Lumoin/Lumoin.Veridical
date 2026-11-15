using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Authenticated decryption <c>P' = DEC[K, C, T, A]</c> of ECIES (Verheul Annex A.4): verifies the tag over the
/// ciphertext and the additional authenticated data and, only when it is valid, releases the plaintext.
/// </summary>
/// <param name="key">The AEAD key; secret.</param>
/// <param name="iv">The initialisation vector, as the parameter set sizes it.</param>
/// <param name="ciphertext">The ciphertext <c>C</c>.</param>
/// <param name="tag">The authentication tag <c>T</c>.</param>
/// <param name="associatedData">The additional authenticated data <c>A</c>.</param>
/// <param name="plaintext">Receives the plaintext, exactly as long as <paramref name="ciphertext"/>, only when the tag is valid.</param>
/// <returns><see langword="true"/> when the tag is valid and the plaintext was written; <see langword="false"/> on an authentication failure. An authentication failure is an expected outcome and must be reported by the return value, not by an exception that a platform cipher may raise.</returns>
public delegate bool AeadDecryptDelegate(
    ReadOnlySpan<byte> key,
    ReadOnlySpan<byte> iv,
    ReadOnlySpan<byte> ciphertext,
    ReadOnlySpan<byte> tag,
    ReadOnlySpan<byte> associatedData,
    Span<byte> plaintext);

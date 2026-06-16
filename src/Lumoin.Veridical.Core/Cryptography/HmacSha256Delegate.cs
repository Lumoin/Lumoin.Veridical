using System;

namespace Lumoin.Veridical.Core.Cryptography;

/// <summary>
/// Computes HMAC-SHA256 (RFC 2104 / FIPS 198-1) of <paramref name="message"/> under <paramref name="key"/>
/// into <paramref name="mac"/> (exactly 32 bytes). Injected into <see cref="Rfc6979DeterministicNonce"/> so the
/// Core nonce derivation stays free of a concrete hash dependency (Core does not reference the hashing assembly):
/// the implementation (HMAC-SHA256 over the library's SHA-256) is supplied by the caller.
/// </summary>
/// <param name="key">The MAC key.</param>
/// <param name="message">The message to authenticate.</param>
/// <param name="mac">The 32-byte destination for the MAC.</param>
public delegate void HmacSha256Delegate(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, Span<byte> mac);

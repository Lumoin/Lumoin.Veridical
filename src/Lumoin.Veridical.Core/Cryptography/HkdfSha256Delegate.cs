using System;

namespace Lumoin.Veridical.Core.Cryptography;

/// <summary>
/// Derives <paramref name="outputKeyingMaterial"/> from <paramref name="inputKeyingMaterial"/> with
/// HKDF-SHA256 (RFC 5869): PRK = HMAC(<paramref name="salt"/>, IKM), then the counter-chained
/// HMAC expansion over <paramref name="info"/> until <paramref name="outputKeyingMaterial"/> is filled
/// (its length is the RFC's <c>L</c>, at most 255·32 bytes). An empty <paramref name="salt"/> selects the
/// RFC's default salt of 32 zero bytes. Injected into protocol code (ECDH-MAC key derivation) so it stays
/// free of a concrete hash dependency, mirroring <see cref="HmacSha256Delegate"/>: the implementation
/// (HKDF over the library's SHA-256) is supplied by the caller.
/// </summary>
/// <param name="salt">The extraction salt; empty selects the RFC 5869 default (32 zero bytes).</param>
/// <param name="inputKeyingMaterial">The input keying material (for ECDH-MAC, the shared-point x-coordinate <c>Z_AB</c>).</param>
/// <param name="info">The context/application information string (may be empty).</param>
/// <param name="outputKeyingMaterial">The destination; its length selects how much keying material is derived.</param>
public delegate void HkdfSha256Delegate(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> inputKeyingMaterial, ReadOnlySpan<byte> info, Span<byte> outputKeyingMaterial);

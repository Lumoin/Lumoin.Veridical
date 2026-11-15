using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// Fills a buffer with uniformly random bytes. The library never chooses an entropy source: ephemeral scalars,
/// seeds and other randomness enter through this delegate, so a deployment binds the platform random number
/// generator and a test binds a deterministic stream.
/// </summary>
/// <param name="destination">Receives exactly <c>destination.Length</c> random bytes.</param>
/// <remarks>
/// The bytes are used as secret material (an ephemeral private key, a seed), so the delegate must be a
/// cryptographically secure source. The library samples a P-256 scalar from the bytes by rejection, which is
/// unbiased, so the source need only be uniform over bytes.
/// </remarks>
public delegate void SecdsaEntropySource(Span<byte> destination);

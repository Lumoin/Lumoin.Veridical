using Lumoin.Veridical.Core.Cryptography;
using System;

namespace Lumoin.Veridical.Secdsa;

/// <summary>
/// The production binding of <see cref="SecdsaNonceSource"/>: RFC 6979 §3.2 deterministic nonce generation
/// (the SHA-256 ciphersuite) over the curve order. Removes the catastrophic nonce-reuse / weak-RNG failure
/// modes of randomized ECDSA — the nonce is a deterministic function of the signing key and the message
/// representative, so signing needs no random source and is reproducible.
/// </summary>
/// <remarks>
/// The HMAC-SHA256 primitive is injected (<see cref="HmacSha256Delegate"/>) rather than referenced, mirroring
/// how <see cref="Rfc6979DeterministicNonce"/> stays free of a concrete hash dependency: the caller supplies
/// the implementation (the library's <c>Sha256Hmac.Compute</c>), so this package depends on no hashing
/// assembly.
/// </remarks>
public static class Rfc6979SecdsaNonceSource
{
    /// <summary>
    /// Returns a <see cref="SecdsaNonceSource"/> that derives the nonce through
    /// <see cref="Rfc6979DeterministicNonce.GenerateNonce"/> using <paramref name="hmac"/> as the HMAC-SHA256
    /// primitive.
    /// </summary>
    /// <param name="hmac">HMAC-SHA256 (e.g. the library's <c>Sha256Hmac.Compute</c>).</param>
    /// <returns>A deterministic RFC 6979 nonce source.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="hmac"/> is <see langword="null"/>.</exception>
    public static SecdsaNonceSource Create(HmacSha256Delegate hmac)
    {
        ArgumentNullException.ThrowIfNull(hmac);

        return (curve, privateKey, messageHash, nonce) =>
            Rfc6979DeterministicNonce.GenerateNonce(curve, privateKey, messageHash, hmac, nonce);
    }
}

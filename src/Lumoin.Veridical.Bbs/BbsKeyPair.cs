using System;

namespace Lumoin.Veridical.Bbs;

/// <summary>
/// A BBS+ key pair: the secret-key scalar and the corresponding G2
/// public-key point. Disposing the pair disposes both underlying
/// pool-rented buffers.
/// </summary>
/// <param name="SecretKey">The secret-key scalar.</param>
/// <param name="PublicKey">The public-key G2 point.</param>
public sealed record BbsKeyPair(BbsSecretKey SecretKey, BbsPublicKey PublicKey)
    : IDisposable
{
    /// <inheritdoc/>
    public void Dispose()
    {
        SecretKey.Dispose();
        PublicKey.Dispose();
    }
}
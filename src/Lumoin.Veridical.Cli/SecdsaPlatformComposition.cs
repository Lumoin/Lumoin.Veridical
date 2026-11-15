using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Cryptography;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Secdsa;
using System;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The SECDSA delegates the tool composes: the managed P-256 scalar and G1 backends, SHA-256 for the
/// Fiat-Shamir hash, HMAC-SHA-256 and HKDF-SHA-256 for the ECDH-MAC, and RFC 6979 for the nonce source. The
/// library selects none of these; this type is the one place the tool, as composition root, chooses them.
/// The backends are disposed with the composition.
/// </summary>
internal sealed class SecdsaPlatformComposition: IDisposable
{
    private readonly ScalarArithmeticBackend scalar;
    private readonly G1ArithmeticBackend g1;


    /// <summary>Composes the P-256 backends and the platform hash, MAC and key-derivation delegates.</summary>
    public SecdsaPlatformComposition()
    {
        scalar = P256ManagedScalarBackend.Create();
        g1 = P256ManagedG1Backend.Create();
    }


    /// <summary>The RFC 6979 deterministic nonce source over HMAC-SHA-256.</summary>
    public SecdsaNonceSource NonceSource { get; } = Rfc6979SecdsaNonceSource.Create(Sha256Hmac.Compute);

    /// <summary>The SHA-256 Fiat-Shamir hash.</summary>
    public FiatShamirHashDelegate Hash { get; } = ComputeSha256;

    /// <summary>HKDF-SHA-256.</summary>
    public HkdfSha256Delegate Hkdf { get; } = Sha256Hkdf.DeriveKey;

    /// <summary>HMAC-SHA-256.</summary>
    public HmacSha256Delegate Hmac { get; } = Sha256Hmac.Compute;

    /// <summary>Scalar multiplication mod the P-256 order.</summary>
    public ScalarMultiplyDelegate ScalarMultiply => scalar.Multiply;

    /// <summary>Scalar addition mod the P-256 order.</summary>
    public ScalarAddDelegate ScalarAdd => scalar.Add;

    /// <summary>Scalar inversion mod the P-256 order.</summary>
    public ScalarInvertDelegate ScalarInvert => scalar.Invert;

    /// <summary>Reduction mod the P-256 order.</summary>
    public ScalarReduceDelegate ScalarReduce => scalar.Reduce;

    /// <summary>G1 addition.</summary>
    public G1AddDelegate G1Add => g1.Add;

    /// <summary>G1 negation.</summary>
    public G1NegateDelegate G1Negate => g1.Negate;

    /// <summary>G1 scalar multiplication, constant-time.</summary>
    public G1ScalarMultiplyDelegate G1ScalarMultiply => g1.ScalarMultiply;


    /// <inheritdoc/>
    public void Dispose()
    {
        scalar.Dispose();
        g1.Dispose();
    }


    private static void ComputeSha256(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        Sha256.HashData(input, output);
    }
}

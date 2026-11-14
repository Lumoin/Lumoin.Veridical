using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Longfellow;
using System;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// The Longfellow primitive bundles the facade tests share, backed by the platform cryptography
/// provider. The Merkle hash, leaf hash, incremental hash, block cipher and the entropy source are
/// separate members so any one of them can be replaced for a runtime that lacks it without touching
/// the others.
/// </summary>
internal static class TestLongfellowPrimitives
{
    /// <summary>The two-to-one Merkle compression SHA-256(left ‖ right).</summary>
    public static MerkleHashDelegate MerkleHash { get; } = ComputeMerkleHash;

    /// <summary>The one-shot SHA-256 leaf hash.</summary>
    public static FiatShamirHashDelegate LeafHash { get; } = Sha256FiatShamirBackend.GetHash();

    /// <summary>The transcript's incremental SHA-256 factory.</summary>
    public static LongfellowIncrementalHashFactory IncrementalHashFactory { get; } = Sha256FiatShamirBackend.GetIncrementalFactory();

    /// <summary>The transcript's single-block AES-256-ECB permutation.</summary>
    public static LongfellowBlockCipherDelegate BlockCipher { get; } = EncryptBlock;

    /// <summary>The system CSPRNG fill, plain random bytes with no field constraint.</summary>
    public static LongfellowEntropyDelegate Entropy { get; } = FillRandom;

    /// <summary>The mdoc bundle assembled from the members above.</summary>
    public static LongfellowMdocCryptoSuite MdocSuite { get; } = LongfellowMdocCryptoSuite.Create(
        MerkleHash, LeafHash, IncrementalHashFactory, BlockCipher);

    /// <summary>The JWT bundle assembled from the members above.</summary>
    public static LongfellowJwtCryptoSuite JwtSuite { get; } = LongfellowJwtCryptoSuite.Create(
        MerkleHash, LeafHash, IncrementalHashFactory, BlockCipher);


    /// <summary>Creates a fresh single-proof random stream over <see cref="Entropy"/>.</summary>
    /// <returns>A new, unspent stream.</returns>
    public static LongfellowProverRandomness NewProverRandomness() => new(Entropy);


    private static void ComputeMerkleHash(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> concatenated = stackalloc byte[left.Length + right.Length];
        left.CopyTo(concatenated);
        right.CopyTo(concatenated[left.Length..]);
        SHA256.HashData(concatenated, output);
    }


    private static void EncryptBlock(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        TestPlatformCrypto.AesEncryptBlock(key, input, output);
    }


    private static void FillRandom(Span<byte> destination)
    {
        RandomNumberGenerator.Fill(destination);
    }
}

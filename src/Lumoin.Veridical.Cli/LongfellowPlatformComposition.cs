using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Longfellow;
using System;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Cli;

/// <summary>
/// The Longfellow primitives the tool composes from the platform cryptography provider: SHA-256 for the
/// Merkle, leaf and transcript hashes, single-block AES-256-ECB for the transcript permutation, and the
/// operating system random generator for the prover's plain random bytes. The library selects none of
/// these; this type is the one place the tool, as composition root, chooses them.
/// </summary>
internal static class LongfellowPlatformComposition
{
    /// <summary>The two-to-one Merkle compression SHA-256(left || right).</summary>
    public static MerkleHashDelegate MerkleHash { get; } = ComputeMerkleHash;

    /// <summary>The one-shot SHA-256 leaf hash.</summary>
    public static FiatShamirHashDelegate LeafHash { get; } = Sha256FiatShamirBackend.GetHash();

    /// <summary>The transcript's incremental SHA-256 factory.</summary>
    public static LongfellowIncrementalHashFactory IncrementalHashFactory { get; } = Sha256FiatShamirBackend.GetIncrementalFactory();

    /// <summary>The transcript's single-block AES-256-ECB permutation.</summary>
    public static LongfellowBlockCipherDelegate BlockCipher { get; } = EncryptBlock;

    /// <summary>The operating system random generator fill: plain random bytes with no field constraint.</summary>
    public static LongfellowEntropyDelegate Entropy { get; } = FillRandom;

    /// <summary>The JWT crypto suite assembled from the members above.</summary>
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
        using Aes aes = Aes.Create();
        aes.SetKey(key);
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    private static void FillRandom(Span<byte> destination)
    {
        RandomNumberGenerator.Fill(destination);
    }
}

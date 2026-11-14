using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Longfellow;
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.TestInfrastructure;

/// <summary>
/// The Longfellow primitive bundles the facade tests share, backed by the platform cryptography
/// provider. The Merkle hash, leaf hash, incremental hash, block cipher and the two entropy sources are
/// separate members so any one of them can be replaced for a runtime that lacks it without touching
/// the others.
/// </summary>
internal static class TestLongfellowPrimitives
{
    //A P-256 base-field element is 32 big-endian bytes; a full-width signature-side draw is
    //rejection-sampled below the base-field prime so the prover pad stays canonical.
    private const int FieldElementBytes = 32;


    /// <summary>The two-to-one Merkle compression SHA-256(left ‖ right).</summary>
    public static MerkleHashDelegate MerkleHash { get; } = ComputeMerkleHash;

    /// <summary>The one-shot SHA-256 leaf hash.</summary>
    public static FiatShamirHashDelegate LeafHash { get; } = Sha256FiatShamirBackend.GetHash();

    /// <summary>The transcript's incremental SHA-256 factory.</summary>
    public static LongfellowIncrementalHashFactory IncrementalHashFactory { get; } = Sha256FiatShamirBackend.GetIncrementalFactory();

    /// <summary>The transcript's single-block AES-256-ECB permutation.</summary>
    public static LongfellowBlockCipherDelegate BlockCipher { get; } = EncryptBlock;

    /// <summary>The system CSPRNG fill for the hash-side entropy.</summary>
    public static LongfellowEntropyDelegate HashEntropy { get; } = FillRandom;

    /// <summary>The system CSPRNG fill for the signature-side entropy, rejection-sampled below the P-256 base-field prime at full width.</summary>
    public static LongfellowEntropyDelegate SignatureEntropy { get; } = FillBelowPrime;

    /// <summary>The mdoc bundle assembled from the members above.</summary>
    public static LongfellowMdocCryptoSuite MdocSuite { get; } = LongfellowMdocCryptoSuite.Create(
        MerkleHash, LeafHash, IncrementalHashFactory, BlockCipher, HashEntropy, SignatureEntropy);

    /// <summary>The JWT bundle assembled from the members above.</summary>
    public static LongfellowJwtCryptoSuite JwtSuite { get; } = LongfellowJwtCryptoSuite.Create(
        MerkleHash, LeafHash, IncrementalHashFactory, BlockCipher, SignatureEntropy);


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


    private static void FillBelowPrime(Span<byte> destination)
    {
        if(destination.Length != FieldElementBytes)
        {
            RandomNumberGenerator.Fill(destination);

            return;
        }

        BigInteger prime = P256BigIntegerG1Reference.BaseFieldPrime;
        while(true)
        {
            RandomNumberGenerator.Fill(destination);
            BigInteger candidate = new(destination, isUnsigned: true, isBigEndian: true);
            if(candidate < prime)
            {
                return;
            }
        }
    }
}

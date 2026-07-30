using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The swappable cryptographic-primitive bundle the JWT statement facade drives: the Merkle and leaf hashes,
/// the Fiat-Shamir transcript's incremental hash and block cipher, and the prover entropy source. The
/// delegate-per-primitive shape is the backend-swap seam; <see cref="Default"/> is the production
/// instantiation (SHA-256, AES-256-ECB, a system CSPRNG).
/// </summary>
public sealed class LongfellowJwtCryptoSuite
{
    //A P-256 base-field element is 32 big-endian bytes; a full-width draw is rejection-sampled below the
    //base-field prime so the prover pad stays canonical.
    private const int FieldElementBytes = 32;


    private LongfellowJwtCryptoSuite(
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        LongfellowIncrementalHashFactory incrementalHashFactory,
        LongfellowBlockCipherDelegate blockCipher,
        LongfellowEntropyDelegate proverRandom)
    {
        MerkleHash = merkleHash;
        LeafHash = leafHash;
        IncrementalHashFactory = incrementalHashFactory;
        BlockCipher = blockCipher;
        ProverRandom = proverRandom;
    }


    /// <summary>The two-to-one Merkle compression SHA-256(left ‖ right).</summary>
    public MerkleHashDelegate MerkleHash { get; }

    /// <summary>The one-shot SHA-256 leaf hash over a contiguous span.</summary>
    public FiatShamirHashDelegate LeafHash { get; }

    /// <summary>The transcript's incremental SHA-256 factory.</summary>
    public LongfellowIncrementalHashFactory IncrementalHashFactory { get; }

    /// <summary>The transcript's single-block AES-256-ECB pseudo-random permutation.</summary>
    public LongfellowBlockCipherDelegate BlockCipher { get; }

    /// <summary>The P-256 base-field prover entropy source; a full-width 32-byte draw is rejection-sampled below the base-field prime so the prover pad stays canonical.</summary>
    public LongfellowEntropyDelegate ProverRandom { get; }


    /// <summary>The production primitive bundle: SHA-256, AES-256-ECB, a system CSPRNG.</summary>
    public static LongfellowJwtCryptoSuite Default { get; } = new(
        ComputeMerkleHash,
        Sha256FiatShamirBackend.GetHash(),
        Sha256FiatShamirBackend.GetIncrementalFactory(),
        EncryptBlock,
        FillProverRandom);


    /// <summary>
    /// Assembles a custom primitive bundle; every primitive is required.
    /// </summary>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="leafHash">The one-shot leaf hash.</param>
    /// <param name="incrementalHashFactory">The transcript's incremental-hash factory.</param>
    /// <param name="blockCipher">The transcript's single-block cipher.</param>
    /// <param name="proverRandom">The prover entropy source.</param>
    /// <returns>A primitive bundle over the supplied delegates.</returns>
    /// <exception cref="ArgumentNullException">When any delegate is <see langword="null"/>.</exception>
    public static LongfellowJwtCryptoSuite Create(
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        LongfellowIncrementalHashFactory incrementalHashFactory,
        LongfellowBlockCipherDelegate blockCipher,
        LongfellowEntropyDelegate proverRandom)
    {
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(leafHash);
        ArgumentNullException.ThrowIfNull(incrementalHashFactory);
        ArgumentNullException.ThrowIfNull(blockCipher);
        ArgumentNullException.ThrowIfNull(proverRandom);

        return new LongfellowJwtCryptoSuite(merkleHash, leafHash, incrementalHashFactory, blockCipher, proverRandom);
    }


    //SHA-256(left ‖ right): the two-to-one Merkle compression the commit uses.
    private static void ComputeMerkleHash(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> concatenated = stackalloc byte[left.Length + right.Length];
        left.CopyTo(concatenated);
        right.CopyTo(concatenated[left.Length..]);
        SHA256.HashData(concatenated, output);
    }


    //AES-256-ECB, single block, no padding: the transcript's pseudo-random permutation.
    private static void EncryptBlock(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        using Aes aes = Aes.Create();
        aes.Key = key.ToArray();
        aes.EncryptEcb(input, output, PaddingMode.None);
    }


    //Prover entropy: a full-width draw is rejection-sampled below the P-256 base-field prime so the prover
    //pad never exceeds the field; a shorter draw carries no field constraint and is filled directly.
    private static void FillProverRandom(Span<byte> destination)
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

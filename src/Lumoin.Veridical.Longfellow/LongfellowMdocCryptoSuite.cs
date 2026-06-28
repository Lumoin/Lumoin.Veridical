using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The swappable cryptographic-primitive bundle the dual-field mdoc facade drives: the Merkle and leaf hashes,
/// the Fiat-Shamir transcript's incremental hash and block cipher, and the two prover entropy sources. The
/// delegate-per-primitive shape is the backend-swap seam; <see cref="Default"/> is the production
/// instantiation (SHA-256, AES-256-ECB, a system CSPRNG).
/// </summary>
public sealed class LongfellowMdocCryptoSuite
{
    //A P-256 base-field element is 32 big-endian bytes; a full-width signature-side draw is rejection-sampled
    //below the base-field prime so the prover pad stays canonical.
    private const int FieldElementBytes = 32;


    private LongfellowMdocCryptoSuite(
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        LongfellowIncrementalHashFactory incrementalHashFactory,
        LongfellowBlockCipherDelegate blockCipher,
        LongfellowEntropyDelegate hashRandom,
        LongfellowEntropyDelegate signatureRandom)
    {
        MerkleHash = merkleHash;
        LeafHash = leafHash;
        IncrementalHashFactory = incrementalHashFactory;
        BlockCipher = blockCipher;
        HashRandom = hashRandom;
        SignatureRandom = signatureRandom;
    }


    /// <summary>The two-to-one Merkle compression SHA-256(left ‖ right).</summary>
    public MerkleHashDelegate MerkleHash { get; }

    /// <summary>The one-shot SHA-256 leaf hash over a contiguous span.</summary>
    public FiatShamirHashDelegate LeafHash { get; }

    /// <summary>The transcript's incremental SHA-256 factory.</summary>
    public LongfellowIncrementalHashFactory IncrementalHashFactory { get; }

    /// <summary>The transcript's single-block AES-256-ECB pseudo-random permutation.</summary>
    public LongfellowBlockCipherDelegate BlockCipher { get; }

    /// <summary>The GF(2^128) hash-side prover entropy source.</summary>
    public LongfellowEntropyDelegate HashRandom { get; }

    /// <summary>The P-256 signature-side prover entropy source (a full-width draw is rejection-sampled below the base-field prime).</summary>
    public LongfellowEntropyDelegate SignatureRandom { get; }


    /// <summary>The production primitive bundle: SHA-256, AES-256-ECB, a system CSPRNG.</summary>
    public static LongfellowMdocCryptoSuite Default { get; } = new(
        ComputeMerkleHash,
        Sha256FiatShamirBackend.GetHash(),
        Sha256FiatShamirBackend.GetIncrementalFactory(),
        EncryptBlock,
        FillRandom,
        FillSignatureRandom);


    /// <summary>
    /// Assembles a custom primitive bundle; every primitive is required.
    /// </summary>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="leafHash">The one-shot leaf hash.</param>
    /// <param name="incrementalHashFactory">The transcript's incremental-hash factory.</param>
    /// <param name="blockCipher">The transcript's single-block cipher.</param>
    /// <param name="hashRandom">The hash-side prover entropy source.</param>
    /// <param name="signatureRandom">The signature-side prover entropy source.</param>
    /// <returns>A primitive bundle over the supplied delegates.</returns>
    /// <exception cref="ArgumentNullException">When any delegate is <see langword="null"/>.</exception>
    public static LongfellowMdocCryptoSuite Create(
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        LongfellowIncrementalHashFactory incrementalHashFactory,
        LongfellowBlockCipherDelegate blockCipher,
        LongfellowEntropyDelegate hashRandom,
        LongfellowEntropyDelegate signatureRandom)
    {
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(leafHash);
        ArgumentNullException.ThrowIfNull(incrementalHashFactory);
        ArgumentNullException.ThrowIfNull(blockCipher);
        ArgumentNullException.ThrowIfNull(hashRandom);
        ArgumentNullException.ThrowIfNull(signatureRandom);

        return new LongfellowMdocCryptoSuite(merkleHash, leafHash, incrementalHashFactory, blockCipher, hashRandom, signatureRandom);
    }


    //SHA-256(left ‖ right): the two-to-one Merkle compression the dual-field commit uses.
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


    //System CSPRNG fill for the hash-side entropy.
    private static void FillRandom(Span<byte> destination)
    {
        RandomNumberGenerator.Fill(destination);
    }


    //Signature-side entropy: a full-width draw is rejection-sampled below the P-256 base-field prime so the
    //prover pad never exceeds the field; a shorter draw carries no field constraint and is filled directly.
    private static void FillSignatureRandom(Span<byte> destination)
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

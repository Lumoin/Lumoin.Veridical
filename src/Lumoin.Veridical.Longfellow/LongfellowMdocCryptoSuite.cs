using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using System;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The swappable cryptographic-primitive bundle the dual-field mdoc facade drives: the Merkle and leaf hashes,
/// the Fiat-Shamir transcript's incremental hash and block cipher, and the two prover entropy sources. The
/// delegate-per-primitive shape is the backend-swap seam, and the library chooses none of them: the caller
/// supplies every primitive, so the hash, the block cipher and the entropy source are always the caller's
/// decision.
/// </summary>
public sealed class LongfellowMdocCryptoSuite
{
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

}

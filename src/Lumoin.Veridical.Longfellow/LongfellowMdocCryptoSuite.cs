using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using System;

namespace Lumoin.Veridical.Longfellow;

/// <summary>
/// The swappable cryptographic-primitive bundle the dual-field mdoc facade drives: the Merkle and leaf hashes,
/// the Fiat-Shamir transcript's incremental hash and block cipher. The
/// delegate-per-primitive shape is the backend-swap seam, and the library chooses none of them: the caller
/// supplies every primitive, so the hash and the block cipher are always the caller's decision, and the
/// prover's random bytes arrive separately in a <see cref="LongfellowProverRandomness"/>.
/// </summary>
public sealed class LongfellowMdocCryptoSuite
{
    private LongfellowMdocCryptoSuite(
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        LongfellowIncrementalHashFactory incrementalHashFactory,
        LongfellowBlockCipherDelegate blockCipher)
    {
        MerkleHash = merkleHash;
        LeafHash = leafHash;
        IncrementalHashFactory = incrementalHashFactory;
        BlockCipher = blockCipher;
    }


    /// <summary>The two-to-one Merkle compression SHA-256(left ‖ right).</summary>
    public MerkleHashDelegate MerkleHash { get; }

    /// <summary>The one-shot SHA-256 leaf hash over a contiguous span.</summary>
    public FiatShamirHashDelegate LeafHash { get; }

    /// <summary>The transcript's incremental SHA-256 factory.</summary>
    public LongfellowIncrementalHashFactory IncrementalHashFactory { get; }

    /// <summary>The transcript's single-block AES-256-ECB pseudo-random permutation.</summary>
    public LongfellowBlockCipherDelegate BlockCipher { get; }



    /// <summary>
    /// Assembles a custom primitive bundle; every primitive is required.
    /// </summary>
    /// <param name="merkleHash">The two-to-one Merkle compression.</param>
    /// <param name="leafHash">The one-shot leaf hash.</param>
    /// <param name="incrementalHashFactory">The transcript's incremental-hash factory.</param>
    /// <param name="blockCipher">The transcript's single-block cipher.</param>
    /// <returns>A primitive bundle over the supplied delegates.</returns>
    /// <exception cref="ArgumentNullException">When any delegate is <see langword="null"/>.</exception>
    public static LongfellowMdocCryptoSuite Create(
        MerkleHashDelegate merkleHash,
        FiatShamirHashDelegate leafHash,
        LongfellowIncrementalHashFactory incrementalHashFactory,
        LongfellowBlockCipherDelegate blockCipher)
    {
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(leafHash);
        ArgumentNullException.ThrowIfNull(incrementalHashFactory);
        ArgumentNullException.ThrowIfNull(blockCipher);

        return new LongfellowMdocCryptoSuite(merkleHash, leafHash, incrementalHashFactory, blockCipher);
    }

}

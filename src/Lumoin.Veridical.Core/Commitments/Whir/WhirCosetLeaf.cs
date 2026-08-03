using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The WHIR coset-leaf digest: a <c>2^k</c> coset value block is one query
/// symbol, committed as the root of a depth-<c>k</c> binary compression over
/// the block in block order — the same two-to-one hash the oracle tree uses
/// above it, so the whole commitment equals one uniform Merkle tree whose
/// bottom <c>k</c> levels are recomputed by the verifier from the revealed
/// values instead of travelling as path siblings.
/// </summary>
internal static class WhirCosetLeaf
{
    /// <summary>The byte size of one field element, also the digest size.</summary>
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Compresses one coset value block to its leaf digest.
    /// </summary>
    /// <param name="blockValues">The block's <c>2^k</c> values in block order.</param>
    /// <param name="hash">The two-to-one compression.</param>
    /// <param name="digest">Receives the leaf digest, one element.</param>
    /// <param name="scratch">Working space of at least half the block's byte length.</param>
    public static void ComputeLeafDigest(
        ReadOnlySpan<byte> blockValues,
        MerkleHashDelegate hash,
        Span<byte> digest,
        Span<byte> scratch)
    {
        int count = blockValues.Length / ScalarSize;
        if(count == 1)
        {
            blockValues.CopyTo(digest);

            return;
        }

        //First level reads the values, later levels fold the scratch in place.
        Span<byte> current = scratch[..(count / 2 * ScalarSize)];
        for(int pair = 0; pair < count / 2; pair++)
        {
            hash(
                blockValues.Slice(2 * pair * ScalarSize, ScalarSize),
                blockValues.Slice(((2 * pair) + 1) * ScalarSize, ScalarSize),
                current.Slice(pair * ScalarSize, ScalarSize));
        }

        for(int width = count / 2; width > 1; width /= 2)
        {
            for(int pair = 0; pair < width / 2; pair++)
            {
                hash(
                    current.Slice(2 * pair * ScalarSize, ScalarSize),
                    current.Slice(((2 * pair) + 1) * ScalarSize, ScalarSize),
                    current.Slice(pair * ScalarSize, ScalarSize));
            }
        }

        current[..ScalarSize].CopyTo(digest);
    }


    /// <summary>
    /// Compresses every coset block of a coset-contiguous codeword into the
    /// leaf digest vector the oracle's Merkle tree is built over.
    /// </summary>
    /// <param name="cosetLeaves">The codeword in coset-contiguous order.</param>
    /// <param name="blockCount">The number of blocks.</param>
    /// <param name="blockSize">The values per block, <c>2^k</c>.</param>
    /// <param name="hash">The two-to-one compression.</param>
    /// <param name="digests">Receives <paramref name="blockCount"/> digests.</param>
    /// <param name="pool">The pool the per-block scratch rents from.</param>
    public static void ComputeLeafDigests(
        ReadOnlySpan<byte> cosetLeaves,
        int blockCount,
        int blockSize,
        MerkleHashDelegate hash,
        Span<byte> digests,
        BaseMemoryPool pool)
    {
        int scratchLength = Math.Max(1, blockSize / 2 * ScalarSize);
        using IMemoryOwner<byte> scratchOwner = pool.Rent(scratchLength);
        Span<byte> scratch = scratchOwner.Memory.Span[..scratchLength];
        for(int block = 0; block < blockCount; block++)
        {
            ComputeLeafDigest(
                cosetLeaves.Slice(block * blockSize * ScalarSize, blockSize * ScalarSize),
                hash,
                digests.Slice(block * ScalarSize, ScalarSize),
                scratch);
        }
    }
}

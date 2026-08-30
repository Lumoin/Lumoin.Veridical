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
/// values instead of travelling as path siblings. The first level compresses
/// scalar-wide value pairs into node-wide digests and every later level folds
/// node-wide pairs, so the tree carries the configured node width throughout.
/// </summary>
internal static class WhirCosetLeaf
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Compresses one coset value block to its leaf digest. The digest slot's
    /// own length is the node width — the verifier derives it from the root
    /// it authenticates against, the prover from the parameters it builds
    /// with. A single-value block is the value verbatim exactly when the
    /// value is node-wide and the value's commitment <c>hash(value ‖ ε)</c>
    /// otherwise — the same width predicate every leaf commitment in the
    /// library builds with.
    /// </summary>
    /// <param name="blockValues">The block's <c>2^k</c> scalar-wide values in block order.</param>
    /// <param name="hash">The two-to-one compression; writes exactly the output's length.</param>
    /// <param name="digest">Receives the leaf digest, one node wide.</param>
    /// <param name="scratch">Working space of at least half the block's value count times the node width.</param>
    public static void ComputeLeafDigest(
        ReadOnlySpan<byte> blockValues,
        MerkleHashDelegate hash,
        Span<byte> digest,
        Span<byte> scratch)
    {
        int nodeSize = digest.Length;
        int count = blockValues.Length / ScalarSize;
        if(count == 1)
        {
            if(nodeSize == ScalarSize)
            {
                blockValues.CopyTo(digest);

                return;
            }

            hash(blockValues, ReadOnlySpan<byte>.Empty, digest);

            return;
        }

        //First level reads the scalar-wide values, later levels fold the
        //node-wide scratch in place.
        Span<byte> current = scratch[..(count / 2 * nodeSize)];
        for(int pair = 0; pair < count / 2; pair++)
        {
            hash(
                blockValues.Slice(2 * pair * ScalarSize, ScalarSize),
                blockValues.Slice(((2 * pair) + 1) * ScalarSize, ScalarSize),
                current.Slice(pair * nodeSize, nodeSize));
        }

        for(int width = count / 2; width > 1; width /= 2)
        {
            for(int pair = 0; pair < width / 2; pair++)
            {
                hash(
                    current.Slice(2 * pair * nodeSize, nodeSize),
                    current.Slice(((2 * pair) + 1) * nodeSize, nodeSize),
                    current.Slice(pair * nodeSize, nodeSize));
            }
        }

        current[..nodeSize].CopyTo(digest);
    }


    /// <summary>
    /// Compresses every coset block of a coset-contiguous codeword into the
    /// node-wide leaf digest vector the oracle's Merkle tree is built over.
    /// </summary>
    /// <param name="cosetLeaves">The codeword in coset-contiguous order.</param>
    /// <param name="blockCount">The number of blocks.</param>
    /// <param name="blockSize">The values per block, <c>2^k</c>.</param>
    /// <param name="parameters">The compression and the node width it produces.</param>
    /// <param name="digests">Receives <paramref name="blockCount"/> node-wide digests.</param>
    /// <param name="pool">The pool the per-block scratch rents from.</param>
    public static void ComputeLeafDigests(
        ReadOnlySpan<byte> cosetLeaves,
        int blockCount,
        int blockSize,
        MerkleCommitmentParameters parameters,
        Span<byte> digests,
        BaseMemoryPool pool)
    {
        int nodeSize = parameters.NodeSizeBytes;
        int scratchLength = Math.Max(1, blockSize / 2 * nodeSize);
        using IMemoryOwner<byte> scratchOwner = pool.Rent(scratchLength);
        Span<byte> scratch = scratchOwner.Memory.Span[..scratchLength];
        for(int block = 0; block < blockCount; block++)
        {
            ComputeLeafDigest(
                cosetLeaves.Slice(block * blockSize * ScalarSize, blockSize * ScalarSize),
                parameters.Compress,
                digests.Slice(block * nodeSize, nodeSize),
                scratch);
        }
    }
}

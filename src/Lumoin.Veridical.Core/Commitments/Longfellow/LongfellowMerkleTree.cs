using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The wire-format-conformant Merkle tree, a faithful port of google/longfellow-zk's
/// <c>lib/merkle/merkle_tree.h</c> <c>MerkleTree</c>. The tree commits to <c>n</c> leaves laid out in
/// a binary heap of <c>2·n</c> nodes: leaf <c>i</c> sits at heap index <c>n + i</c>, every internal
/// node <c>i</c> in <c>[1, n)</c> is <c>SHA256(node[2·i] ‖ node[2·i+1])</c>, and the root is node 1
/// (node 0 is unused).
/// </summary>
/// <remarks>
/// <para>
/// This is the conformance sibling of <see cref="BaseFold.MerkleTree"/>, kept parallel rather than
/// merged: the BaseFold tree pads the leaf count up to the next power of two and stores its layers
/// bottom-up, whereas the reference uses exactly <c>n</c> leaves in a <c>2·n</c>-node heap and does
/// <em>not</em> pad. For a non-power-of-two leaf count (the common case — <c>block_ext</c> is rarely a
/// power of two) the two trees compute different roots, so the wire-format port carries its own.
/// </para>
/// <para>
/// The heap structure for non-power-of-two <c>n</c> is the reference's exactly: with leaves at
/// <c>[n, 2·n)</c> and the combine loop running <c>i = n−1</c> down to <c>1</c>, an internal node may
/// combine two leaves, two internal nodes, or one of each, depending on where it falls in the heap.
/// The node combine is <c>SHA256(L ‖ R)</c> over the two 32-byte children. Every node — leaf or
/// internal — is one 32-byte digest wide.
/// </para>
/// <para>
/// NOT a general-purpose Merkle tree: it exists solely for byte-level conformance with the
/// Longfellow wire format and is sound only inside that protocol's usage. The combine applies no
/// leaf/node domain separation (a general tree tags leaves and internal nodes differently to
/// preclude second-preimage layer confusion), the leaf digests are produced by the CALLER with the
/// protocol's nonce framing, and the non-padded heap shape is a wire-format choice rather than a
/// recommendation. General commitment needs use <see cref="BaseFold.MerkleTree"/>.
/// </para>
/// <para>
/// Disposable: <see cref="Dispose"/> clears the node buffer and returns it to the pool. The root
/// bytes are copied out via <see cref="Root"/> before disposal. The node hash is delegate-injected
/// (it must be SHA-256 to match the reference) so the construction stays consistent with the
/// library's hash-agnostic commitment infrastructure.
/// </para>
/// </remarks>
internal sealed class LongfellowMerkleTree: IDisposable
{
    //The reference's Digest::kLength: SHA-256 output is 32 bytes; every heap node is one digest.
    private const int DigestLength = 32;

    private IMemoryOwner<byte>? nodes;
    private readonly int leafCount;


    /// <summary>The number of leaves (<c>n</c>); not padded to a power of two.</summary>
    public int LeafCount => leafCount;


    private LongfellowMerkleTree(IMemoryOwner<byte> nodes, int leafCount)
    {
        this.nodes = nodes;
        this.leafCount = leafCount;
    }


    /// <summary>
    /// Builds the tree over <paramref name="leaves"/>, <paramref name="leafCount"/> concatenated
    /// 32-byte leaf digests, by filling the heap leaf range and combining every internal node.
    /// </summary>
    /// <param name="leaves">The concatenated leaf digests; exactly <paramref name="leafCount"/> · 32 bytes.</param>
    /// <param name="leafCount">The number of leaves (<c>n</c>); at least 1.</param>
    /// <param name="merkleHash">The two-to-one <c>SHA256(L ‖ R)</c> compression for internal nodes.</param>
    /// <param name="pool">Pool to rent the heap node buffer from.</param>
    /// <returns>The built tree; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="merkleHash"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="leafCount"/> is below 1.</exception>
    /// <exception cref="ArgumentException">When <paramref name="leaves"/> is not exactly <paramref name="leafCount"/> · 32 bytes.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The node buffer transfers ownership to the returned LongfellowMerkleTree, which releases it through its own Dispose.")]
    public static LongfellowMerkleTree Build(
        ReadOnlySpan<byte> leaves,
        int leafCount,
        MerkleHashDelegate merkleHash,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(leafCount, 1);

        if(leaves.Length != leafCount * DigestLength)
        {
            throw new ArgumentException($"Leaf bytes must be {leafCount * DigestLength} ({leafCount} · {DigestLength}); received {leaves.Length}.", nameof(leaves));
        }

        //The heap holds 2·n nodes: index 0 is unused, leaves at [n, 2·n), internal nodes at [1, n).
        int nodeCount = 2 * leafCount;
        IMemoryOwner<byte> owner = pool.Rent(nodeCount * DigestLength);
        try
        {
            Span<byte> heap = owner.Memory.Span[..(nodeCount * DigestLength)];
            heap.Clear();

            //Place the leaves at [n, 2·n).
            leaves.CopyTo(heap.Slice(leafCount * DigestLength, leafCount * DigestLength));

            //Combine internal nodes i = n−1 down to 1: node[i] = SHA256(node[2·i] ‖ node[2·i+1]).
            for(int i = leafCount - 1; i >= 1; i--)
            {
                ReadOnlySpan<byte> left = NodeAt(heap, 2 * i);
                ReadOnlySpan<byte> right = NodeAt(heap, (2 * i) + 1);
                merkleHash(left, right, MutableNodeAt(heap, i));
            }

            return new LongfellowMerkleTree(owner, leafCount);
        }
        catch
        {
            owner.Memory.Span[..(nodeCount * DigestLength)].Clear();
            owner.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Copies the root digest (heap node 1) into <paramref name="destination"/>.
    /// </summary>
    /// <param name="destination">Receives the 32-byte root.</param>
    /// <exception cref="ObjectDisposedException">When the tree has been disposed.</exception>
    /// <exception cref="ArgumentException">When <paramref name="destination"/> is not 32 bytes.</exception>
    public void CopyRoot(Span<byte> destination)
    {
        IMemoryOwner<byte> local = nodes ?? throw new ObjectDisposedException(nameof(LongfellowMerkleTree));
        if(destination.Length != DigestLength)
        {
            throw new ArgumentException($"The root is {DigestLength} bytes; received {destination.Length}.", nameof(destination));
        }

        NodeAt(local.Memory.Span, 1).CopyTo(destination);
    }


    /// <summary>
    /// Returns the digest of heap node <paramref name="heapIndex"/> for path construction and the
    /// tiny-tree gates. Index 1 is the root, <c>[leafCount, 2·leafCount)</c> are the leaves.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When the tree has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="heapIndex"/> is outside <c>[1, 2·leafCount)</c>.</exception>
    public ReadOnlySpan<byte> GetNode(int heapIndex)
    {
        IMemoryOwner<byte> local = nodes ?? throw new ObjectDisposedException(nameof(LongfellowMerkleTree));
        ArgumentOutOfRangeException.ThrowIfLessThan(heapIndex, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(heapIndex, 2 * leafCount);

        return NodeAt(local.Memory.Span, heapIndex);
    }


    /// <summary>
    /// Generates the compressed multi-leaf proof for the leaf positions <paramref name="positions"/>,
    /// a faithful port of google/longfellow-zk's <c>MerkleTree::generate_compressed_proof</c>. The
    /// proof is the minimal set of sibling digests a verifier needs to recompute the root from the
    /// opened leaves: a node digest is omitted whenever it can be deduced (because it lies on a path
    /// to an opened leaf). The selection order is wire format — it is the order the verifier consumes
    /// the digests in, and so is the serialized order.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The algorithm marks in a <c>2·n</c>-node tree the set of nodes on any root-to-opened-leaf path:
    /// each opened leaf, then every ancestor (a node is in the set when either child is). Then it
    /// walks the inner nodes <c>i = n−1</c> down to <c>1</c>, and for each in-set node emits the child
    /// that is NOT in the set (the first child <c>2·i</c> if it is out, else <c>2·i+1</c> if it is out,
    /// and nothing when both children are in the set). The positions must be distinct and within the
    /// leaf range; duplicates are rejected exactly as the reference rejects them.
    /// </para>
    /// </remarks>
    /// <param name="positions">The distinct leaf positions to open; each in <c>[0, leafCount)</c>, at least one.</param>
    /// <param name="proofDigests">Receives the proof digests, concatenated 32 bytes each, in selection order; must be at least <see cref="CompressedProofLength"/>(positions) · 32 bytes.</param>
    /// <param name="pool">Pool to rent the membership-flag scratch from.</param>
    /// <returns>The number of digests written.</returns>
    /// <exception cref="ObjectDisposedException">When the tree has been disposed.</exception>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="positions"/> is empty, contains a duplicate or an out-of-range position, or <paramref name="proofDigests"/> is too small.</exception>
    public int GenerateCompressedProof(ReadOnlySpan<int> positions, Span<byte> proofDigests, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        IMemoryOwner<byte> local = nodes ?? throw new ObjectDisposedException(nameof(LongfellowMerkleTree));

        if(positions.Length == 0)
        {
            throw new ArgumentException("A Merkle proof with zero leaves is not defined.", nameof(positions));
        }

        ReadOnlySpan<byte> heap = local.Memory.Span;
        int nodeCount = 2 * leafCount;

        using IMemoryOwner<byte> onPathOwner = pool.Rent(nodeCount);
        Span<byte> onPath = onPathOwner.Memory.Span[..nodeCount];
        onPath.Clear();
        try
        {
            //Mark each opened leaf at heap index leafCount + position, rejecting duplicates and
            //out-of-range positions exactly as the reference's compressed_merkle_proof_tree does.
            for(int p = 0; p < positions.Length; p++)
            {
                int position = positions[p];
                if((uint)position >= (uint)leafCount)
                {
                    throw new ArgumentException($"Leaf position {position} is outside [0, {leafCount}).", nameof(positions));
                }

                int leafNode = position + leafCount;
                if(onPath[leafNode] != 0)
                {
                    throw new ArgumentException($"Duplicate leaf position {position} requested.", nameof(positions));
                }

                onPath[leafNode] = 1;
            }

            //A node is on a path when either child is: propagate marks up the heap.
            for(int i = leafCount - 1; i >= 1; i--)
            {
                onPath[i] = (byte)((onPath[2 * i] != 0 || onPath[(2 * i) + 1] != 0) ? 1 : 0);
            }

            //For each on-path inner node, emit the child not on a path, if any. The walk order
            //i = n−1 down to 1 is the wire-format selection order.
            int written = 0;
            for(int i = leafCount - 1; i >= 1; i--)
            {
                if(onPath[i] == 0)
                {
                    continue;
                }

                int child = 2 * i;
                if(onPath[child] != 0)
                {
                    child = (2 * i) + 1;
                }

                if(onPath[child] == 0)
                {
                    int destinationOffset = written * DigestLength;
                    if(destinationOffset + DigestLength > proofDigests.Length)
                    {
                        throw new ArgumentException("The proof-digest buffer is too small for the compressed multi-proof.", nameof(proofDigests));
                    }

                    NodeAt(heap, child).CopyTo(proofDigests.Slice(destinationOffset, DigestLength));
                    written++;
                }
            }

            return written;
        }
        finally
        {
            onPath.Clear();
        }
    }


    /// <summary>
    /// Counts the digests the compressed multi-proof for <paramref name="positions"/> over a tree of
    /// <paramref name="leafCount"/> leaves will contain, without building the tree. Mirrors the
    /// node-selection of <see cref="GenerateCompressedProof"/> so a caller can size the proof buffer.
    /// </summary>
    /// <param name="leafCount">The number of leaves the tree has; at least 1.</param>
    /// <param name="positions">The distinct leaf positions to open; each in <c>[0, leafCount)</c>, at least one.</param>
    /// <param name="pool">Pool to rent the membership-flag scratch from.</param>
    /// <returns>The number of digests the proof will contain.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="positions"/> is empty, contains a duplicate or an out-of-range position.</exception>
    public static int CompressedProofLength(int leafCount, ReadOnlySpan<int> positions, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(leafCount, 1);

        if(positions.Length == 0)
        {
            throw new ArgumentException("A Merkle proof with zero leaves is not defined.", nameof(positions));
        }

        int nodeCount = 2 * leafCount;
        using IMemoryOwner<byte> onPathOwner = pool.Rent(nodeCount);
        Span<byte> onPath = onPathOwner.Memory.Span[..nodeCount];
        onPath.Clear();
        try
        {
            for(int p = 0; p < positions.Length; p++)
            {
                int position = positions[p];
                if((uint)position >= (uint)leafCount)
                {
                    throw new ArgumentException($"Leaf position {position} is outside [0, {leafCount}).", nameof(positions));
                }

                int leafNode = position + leafCount;
                if(onPath[leafNode] != 0)
                {
                    throw new ArgumentException($"Duplicate leaf position {position} requested.", nameof(positions));
                }

                onPath[leafNode] = 1;
            }

            for(int i = leafCount - 1; i >= 1; i--)
            {
                onPath[i] = (byte)((onPath[2 * i] != 0 || onPath[(2 * i) + 1] != 0) ? 1 : 0);
            }

            int count = 0;
            for(int i = leafCount - 1; i >= 1; i--)
            {
                if(onPath[i] == 0)
                {
                    continue;
                }

                int child = 2 * i;
                if(onPath[child] != 0)
                {
                    child = (2 * i) + 1;
                }

                if(onPath[child] == 0)
                {
                    count++;
                }
            }

            return count;
        }
        finally
        {
            onPath.Clear();
        }
    }


    /// <summary>
    /// Verifies a compressed multi-leaf proof against a committed root, a faithful port of
    /// google/longfellow-zk's <c>MerkleTreeVerifier::verify_compressed_proof</c>
    /// (<c>lib/merkle/merkle_tree.h</c>). It reconstructs the heap from the proof digests and the opened
    /// leaves, recomputes every inner node it can, and accepts when node 1 is defined and equals
    /// <paramref name="root"/>. This is the verify side of <see cref="GenerateCompressedProof"/>: it
    /// walks the same on-path node set, reads the proof digests in the same selection order, and so
    /// needs no tree instance.
    /// </summary>
    /// <param name="leafCount">The number of leaves the committed tree has (<c>n</c>); at least 1.</param>
    /// <param name="root">The 32-byte committed root the recomputed node 1 must equal.</param>
    /// <param name="leaves">The opened leaf digests, concatenated 32 bytes each, one per position in <paramref name="positions"/>, in the same order.</param>
    /// <param name="positions">The distinct opened leaf positions, each in <c>[0, leafCount)</c>; at least one.</param>
    /// <param name="proofDigests">The compressed multi-proof digests, concatenated 32 bytes each, in selection order.</param>
    /// <param name="proofLength">The number of digests in <paramref name="proofDigests"/>.</param>
    /// <param name="merkleHash">The two-to-one <c>SHA256(L ‖ R)</c> compression for the recomputed inner nodes.</param>
    /// <param name="pool">Pool to rent the membership/defined/heap scratch from.</param>
    /// <returns><see langword="true"/> when the proof recomputes <paramref name="root"/>, <see langword="false"/> otherwise (including a too-short proof or an unrecoverable root).</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="merkleHash"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="leafCount"/> is below 1.</exception>
    /// <exception cref="ArgumentException">When <paramref name="root"/> is not 32 bytes, <paramref name="positions"/> is empty, contains a duplicate or an out-of-range position, or <paramref name="leaves"/> is not <paramref name="positions"/> · 32 bytes.</exception>
    public static bool VerifyCompressedProof(
        int leafCount,
        ReadOnlySpan<byte> root,
        ReadOnlySpan<byte> leaves,
        ReadOnlySpan<int> positions,
        ReadOnlySpan<byte> proofDigests,
        int proofLength,
        MerkleHashDelegate merkleHash,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(merkleHash);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfLessThan(leafCount, 1);

        if(root.Length != DigestLength)
        {
            throw new ArgumentException($"The root is {DigestLength} bytes; received {root.Length}.", nameof(root));
        }

        if(positions.Length == 0)
        {
            throw new ArgumentException("A Merkle proof with zero leaves is not defined.", nameof(positions));
        }

        if(leaves.Length != positions.Length * DigestLength)
        {
            throw new ArgumentException($"Leaf bytes must be {positions.Length * DigestLength} ({positions.Length} · {DigestLength}); received {leaves.Length}.", nameof(leaves));
        }

        int nodeCount = 2 * leafCount;

        using IMemoryOwner<byte> onPathOwner = pool.Rent(nodeCount);
        using IMemoryOwner<byte> definedOwner = pool.Rent(nodeCount);
        using IMemoryOwner<byte> heapOwner = pool.Rent(nodeCount * DigestLength);
        Span<byte> onPath = onPathOwner.Memory.Span[..nodeCount];
        Span<byte> defined = definedOwner.Memory.Span[..nodeCount];
        Span<byte> heap = heapOwner.Memory.Span[..(nodeCount * DigestLength)];
        onPath.Clear();
        defined.Clear();
        heap.Clear();
        try
        {
            //Mark each opened leaf, rejecting duplicates and out-of-range positions, then propagate the
            //on-path marks up the heap (the same compressed_merkle_proof_tree the prover walks).
            for(int p = 0; p < positions.Length; p++)
            {
                int position = positions[p];
                if((uint)position >= (uint)leafCount)
                {
                    throw new ArgumentException($"Leaf position {position} is outside [0, {leafCount}).", nameof(positions));
                }

                int leafNode = position + leafCount;
                if(onPath[leafNode] != 0)
                {
                    throw new ArgumentException($"Duplicate leaf position {position} requested.", nameof(positions));
                }

                onPath[leafNode] = 1;
            }

            for(int i = leafCount - 1; i >= 1; i--)
            {
                onPath[i] = (byte)((onPath[2 * i] != 0 || onPath[(2 * i) + 1] != 0) ? 1 : 0);
            }

            //Read the proof: for each on-path inner node, the child not on a path is defined from the
            //next proof digest, in the same i = n−1 down to 1 selection order.
            int consumed = 0;
            for(int i = leafCount - 1; i >= 1; i--)
            {
                if(onPath[i] == 0)
                {
                    continue;
                }

                int child = 2 * i;
                if(onPath[child] != 0)
                {
                    child = (2 * i) + 1;
                }

                if(onPath[child] == 0)
                {
                    if(consumed >= proofLength)
                    {
                        return false;
                    }

                    proofDigests.Slice(consumed * DigestLength, DigestLength).CopyTo(MutableNodeAt(heap, child));
                    defined[child] = 1;
                    consumed++;
                }
            }

            //Define the opened leaves.
            for(int p = 0; p < positions.Length; p++)
            {
                int leafNode = positions[p] + leafCount;
                leaves.Slice(p * DigestLength, DigestLength).CopyTo(MutableNodeAt(heap, leafNode));
                defined[leafNode] = 1;
            }

            //Recompute every inner node whose children are both defined.
            for(int i = leafCount - 1; i >= 1; i--)
            {
                if(defined[2 * i] != 0 && defined[(2 * i) + 1] != 0)
                {
                    merkleHash(NodeAt(heap, 2 * i), NodeAt(heap, (2 * i) + 1), MutableNodeAt(heap, i));
                    defined[i] = 1;
                }
            }

            return defined[1] != 0 && root.SequenceEqual(NodeAt(heap, 1));
        }
        finally
        {
            onPath.Clear();
            defined.Clear();
            heap.Clear();
        }
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        IMemoryOwner<byte>? local = nodes;
        if(local is not null)
        {
            nodes = null;
            try
            {
                local.Memory.Span[..(2 * leafCount * DigestLength)].Clear();
                local.Dispose();
            }
            catch
            {
                //Disposal must not throw; an orphaned buffer is preferable to a crash.
            }
        }
    }


    private static ReadOnlySpan<byte> NodeAt(ReadOnlySpan<byte> heap, int index) =>
        heap.Slice(index * DigestLength, DigestLength);


    private static Span<byte> MutableNodeAt(Span<byte> heap, int index) =>
        heap.Slice(index * DigestLength, DigestLength);
}

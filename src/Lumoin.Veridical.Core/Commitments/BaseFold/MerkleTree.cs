using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// A binary Merkle tree over a sequence of equal-size leaves — the vector
/// commitment BaseFold uses to commit to a codeword. The root is the
/// commitment; an individual leaf is opened against the root by a
/// <see cref="MerkleAuthenticationPath"/>.
/// </summary>
/// <remarks>
/// <para>
/// Every node — leaf or internal — is one node width wide, and that width is
/// stated by the <see cref="MerkleCommitmentParameters"/> the tree is built
/// with; the tree never infers it from a buffer. The leaves arrive already
/// node-wide: the tree commits them as layer 0 verbatim and refuses any other
/// shape, so a scheme whose values are not node-wide runs its own leaf
/// commitment before building. Each internal node is the two-to-one
/// <see cref="MerkleHashDelegate"/> compression of its two children, left then
/// right; there is no leaf-versus-node domain separation, matching the binary
/// Merkle commitment BaseFold defines (Zeilberger, Chen, Fisch, CRYPTO 2024,
/// IACR ePrint 2023/1705). Structural inspiration only, no code dependency.
/// </para>
/// <para>
/// The leaf count must be a power of two, which the BaseFold codeword length
/// always is. The layers are stored bottom-up in one pool-rented buffer: layer
/// 0 is the leaves, each subsequent layer halves, and the final layer is the
/// single root node.
/// </para>
/// <para>
/// Disposable: <see cref="Dispose"/> clears the layer buffer (the leaves are
/// codeword values derived from the committed polynomial) and returns it to
/// the pool, and disposes the <see cref="Root"/>. The tree is a prover-side
/// structure; the root bytes are copied out into the wire commitment before
/// the tree is disposed.
/// </para>
/// </remarks>
[DebuggerDisplay("MerkleTree (LeafCount = {LeafCount}, Depth = {Depth}, NodeSizeBytes = {NodeSizeBytes})")]
public sealed class MerkleTree: IDisposable
{
    /// <summary>The pool-rented, bottom-up node buffer holding every layer from the leaves to the root, or <see langword="null"/> once disposed.</summary>
    private IMemoryOwner<byte>? layers;

    /// <summary>The owned root digest, or <see langword="null"/> once disposed.</summary>
    private MerkleRoot? root;

    /// <summary>The node index at which each layer begins within the buffer, indexed from the leaves (level 0) upward.</summary>
    private int[] LayerStartNode { get; }

    /// <summary>The total number of nodes across every layer, leaves through root.</summary>
    private int TotalNodes { get; }


    /// <summary>The number of leaves; a power of two.</summary>
    public int LeafCount { get; }

    /// <summary>The tree depth — the number of levels below the root, equal to <c>log2(LeafCount)</c>.</summary>
    public int Depth { get; }

    /// <summary>The size of every node digest in bytes.</summary>
    public int NodeSizeBytes { get; }

    /// <summary>The root digest — the commitment to the whole leaf sequence. Owned by this tree.</summary>
    /// <exception cref="ObjectDisposedException">When the tree has been disposed.</exception>
    public MerkleRoot Root => root ?? throw new ObjectDisposedException(nameof(MerkleTree));


    /// <summary>Wraps an already-completed layer buffer and its extracted root; both transfer ownership to this tree.</summary>
    private MerkleTree(
        IMemoryOwner<byte> layers,
        MerkleRoot root,
        int leafCount,
        int depth,
        int nodeSizeBytes,
        int[] layerStartNode,
        int totalNodes)
    {
        this.layers = layers;
        this.root = root;
        this.LayerStartNode = layerStartNode;
        this.TotalNodes = totalNodes;
        LeafCount = leafCount;
        Depth = depth;
        NodeSizeBytes = nodeSizeBytes;
    }


    /// <summary>
    /// Builds a Merkle tree over <paramref name="leaves"/>. The leaves are
    /// supplied as one contiguous span of <paramref name="leafCount"/> chunks,
    /// each exactly one node wide: the tree places them in layer 0 verbatim
    /// and never hashes a value down to node width itself, so a caller whose
    /// values are not node-wide runs its own leaf commitment first.
    /// </summary>
    /// <param name="leaves">The concatenated node-wide leaf values; one <see cref="MerkleCommitmentParameters.NodeSizeBytes"/> chunk per leaf.</param>
    /// <param name="leafCount">The number of leaves; must be a power of two.</param>
    /// <param name="parameters">The compression and the node width it produces.</param>
    /// <param name="pool">The pool to rent the layer buffer from.</param>
    /// <returns>The constructed tree; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="parameters"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="leafCount"/> is non-positive.</exception>
    /// <exception cref="ArgumentException">When <paramref name="leafCount"/> is not a power of two, or the leaf bytes are not one node width per leaf.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The layer buffer transfers ownership through CompleteTree to the returned MerkleTree, which releases it through its own Dispose.")]
    public static MerkleTree Build(
        ReadOnlySpan<byte> leaves,
        int leafCount,
        MerkleCommitmentParameters parameters,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(leafCount);
        ThrowIfNotPowerOfTwo(leafCount);

        int nodeSize = parameters.NodeSizeBytes;
        if(leaves.Length != leafCount * nodeSize)
        {
            throw new ArgumentException(
                $"Leaf bytes length {leaves.Length} must be one {nodeSize}-byte node per leaf ({leafCount * nodeSize}); the tree commits leaves verbatim, so a value that is not node-wide needs the scheme's own leaf commitment first.",
                nameof(leaves));
        }

        IMemoryOwner<byte> owner = AllocateLayers(leafCount, nodeSize, pool, out int depth, out int[] layerStart, out int totalNodes);
        Span<byte> buffer = owner.Memory.Span[..(totalNodes * nodeSize)];

        //Layer 0 is the leaves verbatim.
        leaves.CopyTo(buffer[..(leafCount * nodeSize)]);

        return CompleteTree(owner, leafCount, depth, nodeSize, layerStart, totalNodes, parameters.Compress, pool);
    }


    /// <summary>
    /// Builds a Merkle tree whose layer-0 leaves are the salted digests
    /// <c>leaf_i = hash(value_i ‖ salt_i)</c> rather than the values verbatim —
    /// the hiding leaf commitment the ZK BaseFold variant uses. The codeword
    /// values never enter the tree, so the root reveals nothing about them given
    /// secret uniform salts; internal-node compression and the resulting paths
    /// are otherwise identical to <see cref="Build"/>, so the fold-consistency
    /// relation and the IOPP query count are untouched. A path verifier
    /// recomputes the salted leaf from the revealed <c>(value, salt)</c> pair
    /// before authenticating.
    /// </summary>
    /// <param name="leafValues">The concatenated node-wide codeword values; one <see cref="MerkleCommitmentParameters.NodeSizeBytes"/> chunk per leaf.</param>
    /// <param name="salts">The concatenated per-leaf salts, one node-wide salt per leaf.</param>
    /// <param name="leafCount">The number of leaves; must be a power of two.</param>
    /// <param name="parameters">The compression and the node width it produces, used both to salt the leaves and to compress internal nodes.</param>
    /// <param name="pool">The pool to rent the layer buffer from.</param>
    /// <returns>The constructed tree; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="parameters"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="leafCount"/> is non-positive.</exception>
    /// <exception cref="ArgumentException">When <paramref name="leafCount"/> is not a power of two, the value bytes are not one node width per leaf, or the salt length does not match.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The layer buffer transfers ownership through CompleteTree to the returned MerkleTree, which releases it through its own Dispose.")]
    public static MerkleTree BuildSalted(
        ReadOnlySpan<byte> leafValues,
        ReadOnlySpan<byte> salts,
        int leafCount,
        MerkleCommitmentParameters parameters,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(leafCount);
        ThrowIfNotPowerOfTwo(leafCount);

        int nodeSize = parameters.NodeSizeBytes;
        if(leafValues.Length != leafCount * nodeSize)
        {
            throw new ArgumentException(
                $"Leaf value bytes length {leafValues.Length} must be one {nodeSize}-byte node per leaf ({leafCount * nodeSize}).",
                nameof(leafValues));
        }

        if(salts.Length != leafCount * nodeSize)
        {
            throw new ArgumentException(
                $"Salt bytes length {salts.Length} must equal one {nodeSize}-byte salt per leaf ({leafCount * nodeSize}).",
                nameof(salts));
        }

        IMemoryOwner<byte> owner = AllocateLayers(leafCount, nodeSize, pool, out int depth, out int[] layerStart, out int totalNodes);
        Span<byte> buffer = owner.Memory.Span[..(totalNodes * nodeSize)];
        MerkleHashDelegate hash = parameters.Compress;

        //Layer 0 is the salted leaf digests: leaf_i = hash(value_i ‖ salt_i).
        for(int i = 0; i < leafCount; i++)
        {
            ReadOnlySpan<byte> value = leafValues.Slice(i * nodeSize, nodeSize);
            ReadOnlySpan<byte> salt = salts.Slice(i * nodeSize, nodeSize);
            hash(value, salt, buffer.Slice(i * nodeSize, nodeSize));
        }

        return CompleteTree(owner, leafCount, depth, nodeSize, layerStart, totalNodes, hash, pool);
    }


    /// <summary>Throws when the leaf count is not a power of two, the shape every layer-halving step requires.</summary>
    private static void ThrowIfNotPowerOfTwo(int leafCount)
    {
        if(!BitOperations.IsPow2((uint)leafCount))
        {
            throw new ArgumentException($"Merkle leaf count must be a power of two; received {leafCount}.", nameof(leafCount));
        }
    }


    /// <summary>
    /// Rents the bottom-up layer buffer and computes the per-level node-index starts: layer 0 holds
    /// leafCount nodes, each later layer halves, and the last layer holds the single root. The
    /// returned owner's layer 0 is uninitialised; the caller fills it (verbatim leaves or salted
    /// digests) before <see cref="CompleteTree"/>.
    /// </summary>
    private static IMemoryOwner<byte> AllocateLayers(
        int leafCount,
        int nodeSize,
        BaseMemoryPool pool,
        out int depth,
        out int[] layerStart,
        out int totalNodes)
    {
        depth = BitOperations.Log2((uint)leafCount);
        totalNodes = (2 * leafCount) - 1;

        layerStart = new int[depth + 1];
        int nodeAccumulator = 0;
        for(int level = 0; level <= depth; level++)
        {
            layerStart[level] = nodeAccumulator;
            nodeAccumulator += leafCount >> level;
        }

        return pool.Rent(totalNodes * nodeSize);
    }


    /// <summary>
    /// Given an owner whose layer 0 is already populated, compresses every internal node (left
    /// then right) and extracts the root, then wraps both into the returned tree. The owner and
    /// the freshly rented root transfer to it.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The layer buffer and the root both transfer ownership to the returned MerkleTree, which releases them through its own Dispose.")]
    private static MerkleTree CompleteTree(
        IMemoryOwner<byte> owner,
        int leafCount,
        int depth,
        int nodeSize,
        int[] layerStart,
        int totalNodes,
        MerkleHashDelegate hash,
        BaseMemoryPool pool)
    {
        Span<byte> buffer = owner.Memory.Span[..(totalNodes * nodeSize)];

        //Each internal node compresses its two children, left then right.
        for(int level = 1; level <= depth; level++)
        {
            int count = leafCount >> level;
            int childStart = layerStart[level - 1];
            int thisStart = layerStart[level];
            for(int i = 0; i < count; i++)
            {
                ReadOnlySpan<byte> left = buffer.Slice((childStart + (2 * i)) * nodeSize, nodeSize);
                ReadOnlySpan<byte> right = buffer.Slice((childStart + (2 * i) + 1) * nodeSize, nodeSize);
                Span<byte> parent = buffer.Slice((thisStart + i) * nodeSize, nodeSize);
                hash(left, right, parent);
            }
        }

        ReadOnlySpan<byte> rootBytes = buffer.Slice((totalNodes - 1) * nodeSize, nodeSize);
        IMemoryOwner<byte> rootOwner = pool.Rent(nodeSize);
        rootBytes.CopyTo(rootOwner.Memory.Span[..nodeSize]);
        MerkleRoot builtRoot = MerkleRoot.Create(rootOwner);

        return new MerkleTree(owner, builtRoot, leafCount, depth, nodeSize, layerStart, totalNodes);
    }


    /// <summary>
    /// Returns the digest of the node at <paramref name="indexInLevel"/> within
    /// <paramref name="level"/>, counting levels from the leaves (level 0)
    /// upward. Used by path construction.
    /// </summary>
    /// <exception cref="ObjectDisposedException">When the tree has been disposed.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="level"/> or <paramref name="indexInLevel"/> is out of range.</exception>
    internal ReadOnlySpan<byte> GetNode(int level, int indexInLevel)
    {
        IMemoryOwner<byte> local = layers ?? throw new ObjectDisposedException(nameof(MerkleTree));
        ArgumentOutOfRangeException.ThrowIfNegative(level);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(level, Depth);
        ArgumentOutOfRangeException.ThrowIfNegative(indexInLevel);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(indexInLevel, LeafCount >> level);

        int nodeIndex = LayerStartNode[level] + indexInLevel;
        return local.Memory.Span.Slice(nodeIndex * NodeSizeBytes, NodeSizeBytes);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        IMemoryOwner<byte>? local = layers;
        if(local is not null)
        {
            layers = null;
            try
            {
                //The leaves are codeword values derived from the committed
                //polynomial; clear before returning the buffer to the pool.
                local.Memory.Span[..(TotalNodes * NodeSizeBytes)].Clear();
                local.Dispose();
            }
            catch
            {
                //Disposal must not throw; an orphaned buffer is preferable to a crash.
            }
        }

        root?.Dispose();
        root = null;
    }
}

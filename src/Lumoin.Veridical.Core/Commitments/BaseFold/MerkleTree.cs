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
/// Every node — leaf or internal — is one digest wide. The leaves are the
/// codeword position values supplied at construction (for the wired curves a
/// codeword position is a scalar-field element, which is exactly the BLAKE3
/// digest size, so the tree is uniform). Each internal node is the two-to-one
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
[DebuggerDisplay("MerkleTree (LeafCount = {LeafCount}, Depth = {Depth}, DigestSizeBytes = {NodeSizeBytes})")]
public sealed class MerkleTree: IDisposable
{
    private IMemoryOwner<byte>? layers;
    private MerkleRoot? root;
    private readonly int[] layerStartNode;
    private readonly int totalNodes;


    /// <summary>The number of leaves; a power of two.</summary>
    public int LeafCount { get; }

    /// <summary>The tree depth — the number of levels below the root, equal to <c>log2(LeafCount)</c>.</summary>
    public int Depth { get; }

    /// <summary>The size of every node digest in bytes.</summary>
    public int NodeSizeBytes { get; }

    /// <summary>The root digest — the commitment to the whole leaf sequence. Owned by this tree.</summary>
    /// <exception cref="ObjectDisposedException">When the tree has been disposed.</exception>
    public MerkleRoot Root => root ?? throw new ObjectDisposedException(nameof(MerkleTree));


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
        this.layerStartNode = layerStartNode;
        this.totalNodes = totalNodes;
        LeafCount = leafCount;
        Depth = depth;
        NodeSizeBytes = nodeSizeBytes;
    }


    /// <summary>
    /// Builds a Merkle tree over <paramref name="leaves"/>. The leaves are
    /// supplied as one contiguous span of <paramref name="leafCount"/> equal-
    /// size chunks; the per-leaf size is inferred as
    /// <c>leaves.Length / leafCount</c> and is also the node digest size, so
    /// the wired hash must produce digests of that size.
    /// </summary>
    /// <param name="leaves">The concatenated leaf values; length must be a positive multiple of <paramref name="leafCount"/>.</param>
    /// <param name="leafCount">The number of leaves; must be a power of two.</param>
    /// <param name="hash">The two-to-one compression for internal nodes.</param>
    /// <param name="pool">The pool to rent the layer buffer from.</param>
    /// <returns>The constructed tree; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="hash"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="leafCount"/> is non-positive.</exception>
    /// <exception cref="ArgumentException">When <paramref name="leafCount"/> is not a power of two, or the leaf bytes do not divide evenly.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The layer buffer transfers ownership through CompleteTree to the returned MerkleTree, which releases it through its own Dispose.")]
    public static MerkleTree Build(
        ReadOnlySpan<byte> leaves,
        int leafCount,
        MerkleHashDelegate hash,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(leafCount);
        ThrowIfNotPowerOfTwo(leafCount);

        if(leaves.Length == 0 || leaves.Length % leafCount != 0)
        {
            throw new ArgumentException(
                $"Leaf bytes length {leaves.Length} must be a positive multiple of the leaf count {leafCount}.",
                nameof(leaves));
        }

        int nodeSize = leaves.Length / leafCount;
        IMemoryOwner<byte> owner = AllocateLayers(leafCount, nodeSize, pool, out int depth, out int[] layerStart, out int totalNodes);
        Span<byte> buffer = owner.Memory.Span[..(totalNodes * nodeSize)];

        //Layer 0 is the leaves verbatim.
        leaves.CopyTo(buffer[..(leafCount * nodeSize)]);

        return CompleteTree(owner, leafCount, depth, nodeSize, layerStart, totalNodes, hash, pool);
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
    /// <param name="leafValues">The concatenated codeword values; length must be a positive multiple of <paramref name="leafCount"/>. The per-value size is also the node digest size.</param>
    /// <param name="salts">The concatenated per-leaf salts, one digest-wide salt per leaf; length must equal <paramref name="leafCount"/> times the per-value size.</param>
    /// <param name="leafCount">The number of leaves; must be a power of two.</param>
    /// <param name="hash">The two-to-one compression, used both to salt the leaves and to compress internal nodes.</param>
    /// <param name="pool">The pool to rent the layer buffer from.</param>
    /// <returns>The constructed tree; the caller owns its disposal.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="hash"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="leafCount"/> is non-positive.</exception>
    /// <exception cref="ArgumentException">When <paramref name="leafCount"/> is not a power of two, the value bytes do not divide evenly, or the salt length does not match.</exception>
    [SuppressMessage("Reliability", "CA2000", Justification = "The layer buffer transfers ownership through CompleteTree to the returned MerkleTree, which releases it through its own Dispose.")]
    public static MerkleTree BuildSalted(
        ReadOnlySpan<byte> leafValues,
        ReadOnlySpan<byte> salts,
        int leafCount,
        MerkleHashDelegate hash,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(leafCount);
        ThrowIfNotPowerOfTwo(leafCount);

        if(leafValues.Length == 0 || leafValues.Length % leafCount != 0)
        {
            throw new ArgumentException(
                $"Leaf value bytes length {leafValues.Length} must be a positive multiple of the leaf count {leafCount}.",
                nameof(leafValues));
        }

        int nodeSize = leafValues.Length / leafCount;
        if(salts.Length != leafCount * nodeSize)
        {
            throw new ArgumentException(
                $"Salt bytes length {salts.Length} must equal one {nodeSize}-byte salt per leaf ({leafCount * nodeSize}).",
                nameof(salts));
        }

        IMemoryOwner<byte> owner = AllocateLayers(leafCount, nodeSize, pool, out int depth, out int[] layerStart, out int totalNodes);
        Span<byte> buffer = owner.Memory.Span[..(totalNodes * nodeSize)];

        //Layer 0 is the salted leaf digests: leaf_i = hash(value_i ‖ salt_i).
        for(int i = 0; i < leafCount; i++)
        {
            ReadOnlySpan<byte> value = leafValues.Slice(i * nodeSize, nodeSize);
            ReadOnlySpan<byte> salt = salts.Slice(i * nodeSize, nodeSize);
            hash(value, salt, buffer.Slice(i * nodeSize, nodeSize));
        }

        return CompleteTree(owner, leafCount, depth, nodeSize, layerStart, totalNodes, hash, pool);
    }


    private static void ThrowIfNotPowerOfTwo(int leafCount)
    {
        if(!BitOperations.IsPow2((uint)leafCount))
        {
            throw new ArgumentException($"Merkle leaf count must be a power of two; received {leafCount}.", nameof(leafCount));
        }
    }


    //Rents the bottom-up layer buffer and computes the per-level node-index
    //starts: layer 0 holds leafCount nodes, each later layer halves, the last
    //layer holds the single root. The returned owner's layer 0 is uninitialised;
    //the caller fills it (verbatim leaves or salted digests) before CompleteTree.
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


    //Given an owner whose layer 0 is already populated, compresses every
    //internal node (left then right) and extracts the root, then wraps both into
    //the returned tree. The owner and the freshly rented root transfer to it.
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
        MerkleRoot builtRoot = MerkleRoot.Create(rootOwner, nodeSize);

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

        int nodeIndex = layerStartNode[level] + indexInLevel;
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
                local.Memory.Span[..(totalNodes * NodeSizeBytes)].Clear();
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

using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// BaseFold's leaf commitment: turns a scalar-wide codeword layer into the
/// node-wide layer 0 a <see cref="MerkleTree"/> is built over. When the node
/// width equals the scalar width the values are the leaves verbatim — the
/// wired pairing, and the shape every shipped byte was produced under. At any
/// other node width each leaf is committed before the tree is built: a plain
/// leaf as <c>hash(value ‖ ε)</c> and a salted leaf as
/// <c>hash(value ‖ salt)</c>. The verifier recomputes the same commitment
/// under the same width predicate — the value width equals the node width or
/// the leaf is the value's commitment — so the two sides cannot disagree
/// about which shape layer 0 holds.
/// </summary>
internal static class BaseFoldCodewordTree
{
    /// <summary>The byte size of one field element.</summary>
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Builds the tree over a plain codeword layer: the values verbatim when
    /// the node width is the scalar width, each value committed as
    /// <c>hash(value ‖ ε)</c> otherwise.
    /// </summary>
    /// <param name="codeword">The codeword layer, one scalar per position.</param>
    /// <param name="leafCount">The number of positions; a power of two.</param>
    /// <param name="parameters">The compression and the node width it produces.</param>
    /// <param name="pool">The pool the leaf-commitment scratch and the tree rent from.</param>
    /// <returns>The built tree; the caller owns its disposal.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "The returned tree owns its layer buffer; the leaf-commitment scratch is disposed here.")]
    internal static MerkleTree Build(
        ReadOnlySpan<byte> codeword,
        int leafCount,
        MerkleCommitmentParameters parameters,
        BaseMemoryPool pool)
    {
        if(parameters.NodeSizeBytes == ScalarSize)
        {
            return MerkleTree.Build(codeword, leafCount, parameters, pool);
        }

        int nodeSize = parameters.NodeSizeBytes;
        using IMemoryOwner<byte> leavesOwner = pool.Rent(leafCount * nodeSize);
        Span<byte> leaves = leavesOwner.Memory.Span[..(leafCount * nodeSize)];
        for(int position = 0; position < leafCount; position++)
        {
            parameters.Compress(
                codeword.Slice(position * ScalarSize, ScalarSize),
                ReadOnlySpan<byte>.Empty,
                leaves.Slice(position * nodeSize, nodeSize));
        }

        return MerkleTree.Build(leaves, leafCount, parameters, pool);
    }


    /// <summary>
    /// Builds the tree over a salted codeword layer: the leaf is
    /// <c>hash(value ‖ salt)</c> at node width. At the scalar-wide node width
    /// that is exactly <see cref="MerkleTree.BuildSalted"/>; at any other
    /// width the leaves are committed here and the tree is built over them
    /// verbatim, because the tree's own salted path binds value, salt and
    /// node to one width these leaves deliberately do not share.
    /// </summary>
    /// <param name="codeword">The codeword layer, one scalar per position.</param>
    /// <param name="salts">The per-position salts, one scalar-wide salt each.</param>
    /// <param name="leafCount">The number of positions; a power of two.</param>
    /// <param name="parameters">The compression and the node width it produces.</param>
    /// <param name="pool">The pool the leaf-commitment scratch and the tree rent from.</param>
    /// <returns>The built tree; the caller owns its disposal.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "The returned tree owns its layer buffer; the leaf-commitment scratch is disposed here.")]
    internal static MerkleTree BuildSalted(
        ReadOnlySpan<byte> codeword,
        ReadOnlySpan<byte> salts,
        int leafCount,
        MerkleCommitmentParameters parameters,
        BaseMemoryPool pool)
    {
        if(parameters.NodeSizeBytes == ScalarSize)
        {
            return MerkleTree.BuildSalted(codeword, salts, leafCount, parameters, pool);
        }

        int nodeSize = parameters.NodeSizeBytes;
        using IMemoryOwner<byte> leavesOwner = pool.Rent(leafCount * nodeSize);
        Span<byte> leaves = leavesOwner.Memory.Span[..(leafCount * nodeSize)];
        for(int position = 0; position < leafCount; position++)
        {
            parameters.Compress(
                codeword.Slice(position * ScalarSize, ScalarSize),
                salts.Slice(position * ScalarSize, ScalarSize),
                leaves.Slice(position * nodeSize, nodeSize));
        }

        return MerkleTree.Build(leaves, leafCount, parameters, pool);
    }
}

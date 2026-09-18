using System;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// Binds a two-to-one Merkle compression to the node width it produces, so
/// the pair travels as one value and the width a tree is built at cannot
/// drift from the width its hash writes. A Merkle node is the output of a
/// collision-resistant compression function, and its width is what buys the
/// commitment its binding security, so the width belongs to the hash — never
/// to the field the committed values live in and never to the buffer a
/// caller happens to supply.
/// </summary>
public sealed class MerkleCommitmentParameters
{
    /// <summary>The two-to-one compression; writes exactly <see cref="NodeSizeBytes"/> bytes per node.</summary>
    public MerkleHashDelegate Compress { get; }

    /// <summary>The width of every node the compression produces, in bytes.</summary>
    public int NodeSizeBytes { get; }


    /// <summary>
    /// Creates the pairing, bounding the width by the widest digest the
    /// Merkle surface admits — the same bound every verification path's
    /// stack sizing depends on.
    /// </summary>
    /// <param name="compress">The two-to-one compression.</param>
    /// <param name="nodeSizeBytes">The node width <paramref name="compress"/> produces, in <c>[1, 64]</c>.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="compress"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="nodeSizeBytes"/> is out of range.</exception>
    public MerkleCommitmentParameters(MerkleHashDelegate compress, int nodeSizeBytes)
    {
        ArgumentNullException.ThrowIfNull(compress);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(nodeSizeBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(nodeSizeBytes, WellKnownMerkleHashParameters.MaximumDigestSizeBytes);

        Compress = compress;
        NodeSizeBytes = nodeSizeBytes;
    }
}

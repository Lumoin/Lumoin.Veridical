using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// Path-construction extension on <see cref="MerkleTree"/>: extracts the
/// authentication path for one leaf so a verifier holding only the root can
/// confirm that leaf's membership.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class MerkleTreeExtensions
{
    extension(MerkleTree tree)
    {
        /// <summary>
        /// Builds the authentication path for the leaf at
        /// <paramref name="leafIndex"/>: the sibling digest at each level from
        /// the leaf up to the level below the root, in bottom-up order.
        /// </summary>
        /// <param name="leafIndex">The zero-based leaf index; must be in <c>[0, LeafCount)</c>.</param>
        /// <param name="pool">The pool to rent the path buffer from.</param>
        /// <returns>The authentication path; the caller owns its disposal.</returns>
        /// <exception cref="ArgumentNullException">When <paramref name="tree"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">When <paramref name="leafIndex"/> is outside <c>[0, LeafCount)</c>.</exception>
        [SuppressMessage("Reliability", "CA2000", Justification = "The path buffer transfers ownership to the returned MerkleAuthenticationPath, which releases it through its own Dispose.")]
        public MerkleAuthenticationPath BuildPath(int leafIndex, SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(tree);
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentOutOfRangeException.ThrowIfNegative(leafIndex);
            ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(leafIndex, tree.LeafCount);

            int nodeSize = tree.NodeSizeBytes;
            int depth = tree.Depth;
            int pathLength = depth * nodeSize;

            //A single-leaf tree has depth 0 and an empty path; rent at least one
            //byte so the pool call is well-defined, but keep the logical length 0.
            IMemoryOwner<byte> owner = pool.Rent(Math.Max(1, pathLength));
            Span<byte> buffer = owner.Memory.Span[..pathLength];

            for(int level = 0; level < depth; level++)
            {
                //The running node at this level sits at index (leafIndex >> level);
                //its sibling is that index with the low bit flipped.
                int siblingIndex = (leafIndex >> level) ^ 1;
                tree.GetNode(level, siblingIndex).CopyTo(buffer.Slice(level * nodeSize, nodeSize));
            }

            return MerkleAuthenticationPath.Create(owner, pathLength, nodeSize);
        }
    }
}

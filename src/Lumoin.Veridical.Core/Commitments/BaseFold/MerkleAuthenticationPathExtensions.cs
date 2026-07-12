using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// Verification extension on <see cref="MerkleAuthenticationPath"/>: recomputes
/// the root from a claimed leaf value and its path, and compares against the
/// committed root.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class MerkleAuthenticationPathExtensions
{
    extension(MerkleAuthenticationPath path)
    {
        /// <summary>
        /// Recomputes the Merkle root by folding <paramref name="leafBytes"/>
        /// upward with the path's siblings — at each level the running node is
        /// the left or right child according to the corresponding bit of
        /// <paramref name="leafIndex"/> — and returns whether the result equals
        /// <paramref name="root"/>.
        /// </summary>
        /// <param name="root">The committed root to check against.</param>
        /// <param name="leafIndex">The zero-based index of the leaf being authenticated.</param>
        /// <param name="leafBytes">The claimed leaf value; must be one digest wide.</param>
        /// <param name="hash">The two-to-one compression, matching the one the tree was built with.</param>
        /// <returns><see langword="true"/> iff the path authenticates the leaf against the root.</returns>
        /// <exception cref="ArgumentNullException">When <paramref name="path"/>, <paramref name="root"/>, or <paramref name="hash"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentOutOfRangeException">When <paramref name="leafIndex"/> is negative.</exception>
        /// <exception cref="ArgumentException">When the digest size exceeds the supported maximum.</exception>
        public bool Verify(
            MerkleRoot root,
            int leafIndex,
            ReadOnlySpan<byte> leafBytes,
            MerkleHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(path);
            ArgumentNullException.ThrowIfNull(root);
            ArgumentNullException.ThrowIfNull(hash);
            ArgumentOutOfRangeException.ThrowIfNegative(leafIndex);

            int digestSize = root.AsReadOnlySpan().Length;
            if(digestSize > WellKnownMerkleHashParameters.MaximumDigestSizeBytes)
            {
                throw new ArgumentException(
                    $"Digest size {digestSize} exceeds the supported maximum {WellKnownMerkleHashParameters.MaximumDigestSizeBytes}.",
                    nameof(root));
            }

            //A digest-size or leaf-size mismatch is a malformed input, not a
            //caller fault: the verification surface stays exception-safe and
            //reports it as a non-match rather than throwing.
            if(path.DigestSizeBytes != digestSize || leafBytes.Length != digestSize)
            {
                return false;
            }

            //The leaf index addresses a leaf at the tree's fixed depth: each of
            //its low bits selects the left-or-right turn at one level, and the
            //path carries exactly one sibling per level. An index with a set bit
            //at or above the path length names no leaf this path reaches; folding
            //it would silently ignore those bits and authenticate it as the
            //aliased in-range index, collapsing two positions onto one opening.
            //Binding the position to the path's fixed depth is what keeps the
            //commitment position-binding, so an out-of-range index is a non-match.
            if((leafIndex >> path.SiblingCount) != 0)
            {
                return false;
            }

            Span<byte> current = stackalloc byte[WellKnownMerkleHashParameters.MaximumDigestSizeBytes];
            Span<byte> next = stackalloc byte[WellKnownMerkleHashParameters.MaximumDigestSizeBytes];
            current = current[..digestSize];
            next = next[..digestSize];
            leafBytes.CopyTo(current);

            int siblingCount = path.SiblingCount;
            for(int level = 0; level < siblingCount; level++)
            {
                ReadOnlySpan<byte> sibling = path.GetSibling(level);

                //Bit (level) of the leaf index says whether the running node is
                //the left child (0) or the right child (1) at this level.
                if(((leafIndex >> level) & 1) == 0)
                {
                    hash(current, sibling, next);
                }
                else
                {
                    hash(sibling, current, next);
                }

                next.CopyTo(current);
            }

            return current.SequenceEqual(root.AsReadOnlySpan());
        }
    }
}

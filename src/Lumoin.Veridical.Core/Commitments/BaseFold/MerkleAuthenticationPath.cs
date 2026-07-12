using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// A leaf's authentication path in a binary Merkle tree: the sequence of
/// sibling digests, ordered from the leaf level upward, that lets a verifier
/// recompute the root from a claimed leaf value and confirm membership.
/// </summary>
/// <remarks>
/// <para>
/// The path holds one sibling digest per tree level below the root, stored
/// bottom-up: sibling 0 is the leaf's sibling at the leaf level, sibling 1 is
/// the sibling of their parent, and so on up to the level just below the root.
/// A tree of depth <c>k</c> (over <c>2^k</c> leaves) yields a path of <c>k</c>
/// siblings, each one node digest wide.
/// </para>
/// <para>
/// The direction at each level — whether the running node is the left or right
/// child — is not stored: it is the corresponding bit of the leaf index, which
/// the verifier already holds, so storing it would be redundant. This matches
/// the binary Merkle commitment BaseFold uses (Zeilberger, Chen, Fisch, CRYPTO
/// 2024, IACR ePrint 2023/1705); structural inspiration only, no code
/// dependency.
/// </para>
/// <para>
/// The tag carries the <see cref="AlgebraicRole.OpeningProof"/> role; like the
/// root, the path is field-agnostic and carries no curve dimension.
/// </para>
/// </remarks>
[DebuggerDisplay("MerkleAuthenticationPath ({SiblingCount} siblings, {DigestSizeBytes}-byte digests)")]
public sealed class MerkleAuthenticationPath: SensitiveMemory
{
    /// <summary>The node digest size in bytes; each stored sibling is this wide.</summary>
    public int DigestSizeBytes { get; }

    /// <summary>The number of sibling digests in the path; equals the tree depth.</summary>
    public int SiblingCount => DigestSizeBytes == 0 ? 0 : AsReadOnlySpan().Length / DigestSizeBytes;


    internal MerkleAuthenticationPath(IMemoryOwner<byte> owner, int digestSizeBytes, Tag tag)
        : base(owner, tag)
    {
        DigestSizeBytes = digestSizeBytes;
    }


    /// <summary>Builds the identifying tag for a Merkle authentication path.</summary>
    internal static Tag CreateTag()
    {
        return Tag.Create(AlgebraicRole.OpeningProof);
    }


    /// <summary>Wraps a pool-rented buffer holding the bottom-up sibling sequence; takes ownership of <paramref name="owner"/>.</summary>
    internal static MerkleAuthenticationPath Create(IMemoryOwner<byte> owner, int digestSizeBytes)
    {
        return new MerkleAuthenticationPath(owner, digestSizeBytes, CreateTag());
    }


    /// <summary>
    /// Returns the sibling digest at <paramref name="level"/>, counting from
    /// the leaf level (level 0) upward.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="level"/> is outside <c>[0, SiblingCount)</c>.</exception>
    public ReadOnlySpan<byte> GetSibling(int level)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(level);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(level, SiblingCount);

        return AsReadOnlySpan().Slice(level * DigestSizeBytes, DigestSizeBytes);
    }
}

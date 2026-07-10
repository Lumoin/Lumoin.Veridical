using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Hashing;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// Position-binding tests for the BaseFold Merkle commitment, framed by the
/// analysis in "The Billion Dollar Merkle Tree" (Coratger, Khovratovich,
/// Mennink, Wagner, IACR ePrint 2026/089): a binary Merkle tree stays
/// position-binding even without leaf-versus-internal-node domain separation
/// as long as the leaf position is bound to the tree's fixed depth and the
/// two-to-one compression is collision resistant.
/// </summary>
/// <remarks>
/// <para>
/// The wired compression here is the real BLAKE3, which is collision resistant,
/// so the paper's central concern — a non-collision-resistant algebraic
/// compression that only becomes sound because leaves are pre-hashed — does not
/// arise for the default wiring. These tests instead pin the structural
/// properties the paper shows are load bearing: an authentication path reaches
/// exactly one leaf at the fixed depth, an index with bits beyond that depth
/// names no leaf, a path from a shorter tree cannot climb to a taller tree's
/// root, and an internal-node digest cannot be re-presented as a leaf.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MerklePositionBindingTests
{
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;


    private static MerkleHashDelegate Blake3TwoToOne { get; } = HashTwoToOne;


    [TestMethod]
    public void IndexWithBitsBeyondThePathLengthIsRejected()
    {
        const int LeafCount = 8;
        const int OpenedIndex = 2;

        //A depth-3 tree addresses leaves with three index bits; adding 2^3 sets
        //a fourth bit that no level of the path consults. Folding would drop it
        //and authenticate the aliased in-range index 2, so the opening must be
        //rejected to keep the position bound to the depth.
        const int AliasedIndex = OpenedIndex + LeafCount;

        using IMemoryOwner<byte> leavesOwner = BaseMemoryPool.Shared.Rent(LeafCount * DigestSizeBytes);
        Span<byte> leaves = leavesOwner.Memory.Span[..(LeafCount * DigestSizeBytes)];
        FillDistinctLeaves(leaves, LeafCount);

        using MerkleTree tree = MerkleTree.Build(leaves, LeafCount, Blake3TwoToOne, BaseMemoryPool.Shared);
        using MerkleAuthenticationPath path = tree.BuildPath(OpenedIndex, BaseMemoryPool.Shared);
        ReadOnlySpan<byte> openedLeaf = leaves.Slice(OpenedIndex * DigestSizeBytes, DigestSizeBytes);

        Assert.IsFalse(
            path.Verify(tree.Root, AliasedIndex, openedLeaf, Blake3TwoToOne),
            "An index carrying a bit beyond the path length must not authenticate: dropping that bit would alias two positions onto one opening, breaking position binding.");
    }


    [TestMethod]
    public void TheInRangeIndexStillAuthenticates()
    {
        const int LeafCount = 8;
        const int OpenedIndex = 2;

        using IMemoryOwner<byte> leavesOwner = BaseMemoryPool.Shared.Rent(LeafCount * DigestSizeBytes);
        Span<byte> leaves = leavesOwner.Memory.Span[..(LeafCount * DigestSizeBytes)];
        FillDistinctLeaves(leaves, LeafCount);

        using MerkleTree tree = MerkleTree.Build(leaves, LeafCount, Blake3TwoToOne, BaseMemoryPool.Shared);
        using MerkleAuthenticationPath path = tree.BuildPath(OpenedIndex, BaseMemoryPool.Shared);
        ReadOnlySpan<byte> openedLeaf = leaves.Slice(OpenedIndex * DigestSizeBytes, DigestSizeBytes);

        //The out-of-range guard must not disturb the honest opening at the very
        //index it aliases with.
        Assert.IsTrue(
            path.Verify(tree.Root, OpenedIndex, openedLeaf, Blake3TwoToOne),
            "The honest in-range opening must still authenticate.");
    }


    [TestMethod]
    public void AShortPathCannotAuthenticateAgainstATallerRoot()
    {
        const int SmallLeafCount = 8;
        const int LargeLeafCount = 16;
        const int OpenedIndex = 3;

        using IMemoryOwner<byte> smallOwner = BaseMemoryPool.Shared.Rent(SmallLeafCount * DigestSizeBytes);
        Span<byte> smallLeaves = smallOwner.Memory.Span[..(SmallLeafCount * DigestSizeBytes)];
        FillDistinctLeaves(smallLeaves, SmallLeafCount);

        using IMemoryOwner<byte> largeOwner = BaseMemoryPool.Shared.Rent(LargeLeafCount * DigestSizeBytes);
        Span<byte> largeLeaves = largeOwner.Memory.Span[..(LargeLeafCount * DigestSizeBytes)];
        FillDistinctLeaves(largeLeaves, LargeLeafCount);

        using MerkleTree smallTree = MerkleTree.Build(smallLeaves, SmallLeafCount, Blake3TwoToOne, BaseMemoryPool.Shared);
        using MerkleTree largeTree = MerkleTree.Build(largeLeaves, LargeLeafCount, Blake3TwoToOne, BaseMemoryPool.Shared);
        using MerkleAuthenticationPath shortPath = smallTree.BuildPath(OpenedIndex, BaseMemoryPool.Shared);
        ReadOnlySpan<byte> openedLeaf = smallLeaves.Slice(OpenedIndex * DigestSizeBytes, DigestSizeBytes);

        //A depth-3 path folds three levels and stops one level below the taller
        //tree's root, so it can never reproduce it. The depth is implicit in the
        //path length, which is why the height must be agreed out of band.
        Assert.IsFalse(
            shortPath.Verify(largeTree.Root, OpenedIndex, openedLeaf, Blake3TwoToOne),
            "A path from a shorter tree must not authenticate against a taller tree's root.");
    }


    [TestMethod]
    public void AnInternalNodeDigestDoesNotAuthenticateAsALeaf()
    {
        const int LeafCount = 8;
        const int InternalLevel = 1;
        const int InternalIndexInLevel = 0;

        using IMemoryOwner<byte> leavesOwner = BaseMemoryPool.Shared.Rent(LeafCount * DigestSizeBytes);
        Span<byte> leaves = leavesOwner.Memory.Span[..(LeafCount * DigestSizeBytes)];
        FillDistinctLeaves(leaves, LeafCount);

        using MerkleTree tree = MerkleTree.Build(leaves, LeafCount, Blake3TwoToOne, BaseMemoryPool.Shared);

        //The digest of an internal node — the compression of leaves 0 and 1.
        //There is no leaf/internal domain separation, so this value is a
        //well-formed node; position binding must still keep it from opening at a
        //leaf slot. Recompute it rather than reaching into tree internals.
        Span<byte> internalDigest = stackalloc byte[DigestSizeBytes];
        Blake3TwoToOne(
            leaves[..DigestSizeBytes],
            leaves.Slice(DigestSizeBytes, DigestSizeBytes),
            internalDigest);

        //Present that internal digest at every leaf position with that leaf's
        //genuine path; the fixed depth means no leaf slot accepts it.
        for(int leafIndex = 0; leafIndex < LeafCount; leafIndex++)
        {
            using MerkleAuthenticationPath path = tree.BuildPath(leafIndex, BaseMemoryPool.Shared);
            Assert.IsFalse(
                path.Verify(tree.Root, leafIndex, internalDigest, Blake3TwoToOne),
                $"The internal node at level {InternalLevel} index {InternalIndexInLevel} must not authenticate as leaf {leafIndex}.");
        }
    }


    //Fills each leaf with a distinct value so a misrouted path surfaces as a
    //mismatch rather than an accidental collision.
    private static void FillDistinctLeaves(Span<byte> leaves, int leafCount)
    {
        leaves.Clear();
        for(int i = 0; i < leafCount; i++)
        {
            Span<byte> leaf = leaves.Slice(i * DigestSizeBytes, DigestSizeBytes);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(leaf[^4..], i + 1);
        }
    }


    //Wires BLAKE3 as the two-to-one Merkle compression: the fixed 32-byte
    //digest of the left and right child bytes concatenated.
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}

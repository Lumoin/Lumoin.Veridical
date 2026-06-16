using CsCheck;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// Tests for the BaseFold Merkle commitment infrastructure (AB.2): a binary
/// tree over codeword leaves, the root commitment, and per-leaf authentication
/// paths. The hash is the real BLAKE3 from the hashing project wired as a
/// two-to-one compression, so the tests exercise the production hash backend
/// end to end. Correctness here is the membership property: every leaf
/// authenticates against the root, and any single-byte tampering of the leaf,
/// the path, or the root breaks authentication.
/// </summary>
[TestClass]
internal sealed class MerkleTreeTests
{
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    //CsCheck iteration count. Enough random trees to exercise every depth in
    //the sampled range many times over without making the suite slow.
    private const int IterationCount = 200;

    //The largest power-of-two exponent the property tests sample, giving trees
    //of up to 2^6 = 64 leaves.
    private const int MaximumLeafExponent = 6;


    private static readonly MerkleHashDelegate Blake3TwoToOne = HashTwoToOne;


    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(4)]
    [DataRow(8)]
    [DataRow(16)]
    public void RootAuthenticatesEveryLeaf(int leafCount)
    {
        using IMemoryOwner<byte> leavesOwner = BaseMemoryPool.Shared.Rent(leafCount * DigestSizeBytes);
        Span<byte> leaves = leavesOwner.Memory.Span[..(leafCount * DigestSizeBytes)];
        FillDistinctLeaves(leaves, leafCount);

        using MerkleTree tree = MerkleTree.Build(leaves, leafCount, Blake3TwoToOne, BaseMemoryPool.Shared);

        for(int leafIndex = 0; leafIndex < leafCount; leafIndex++)
        {
            using MerkleAuthenticationPath path = tree.BuildPath(leafIndex, BaseMemoryPool.Shared);
            bool authenticated = path.Verify(
                tree.Root, leafIndex, leaves.Slice(leafIndex * DigestSizeBytes, DigestSizeBytes), Blake3TwoToOne);

            Assert.IsTrue(authenticated, $"Leaf {leafIndex} of {leafCount} must authenticate against the root.");
        }
    }


    [TestMethod]
    public void PathDepthEqualsLogOfLeafCount()
    {
        const int LeafCount = 16;
        using IMemoryOwner<byte> leavesOwner = BaseMemoryPool.Shared.Rent(LeafCount * DigestSizeBytes);
        Span<byte> leaves = leavesOwner.Memory.Span[..(LeafCount * DigestSizeBytes)];
        FillDistinctLeaves(leaves, LeafCount);

        using MerkleTree tree = MerkleTree.Build(leaves, LeafCount, Blake3TwoToOne, BaseMemoryPool.Shared);
        using MerkleAuthenticationPath path = tree.BuildPath(0, BaseMemoryPool.Shared);

        //16 leaves is a depth-4 tree, so the path carries four sibling digests.
        Assert.AreEqual(4, tree.Depth, "A 16-leaf tree has depth 4.");
        Assert.AreEqual(4, path.SiblingCount, "The path carries one sibling per level below the root.");
    }


    [TestMethod]
    public void VerifyRejectsCorruptedLeaf()
    {
        const int LeafCount = 8;
        using IMemoryOwner<byte> leavesOwner = BaseMemoryPool.Shared.Rent(LeafCount * DigestSizeBytes);
        Span<byte> leaves = leavesOwner.Memory.Span[..(LeafCount * DigestSizeBytes)];
        FillDistinctLeaves(leaves, LeafCount);

        using MerkleTree tree = MerkleTree.Build(leaves, LeafCount, Blake3TwoToOne, BaseMemoryPool.Shared);
        using MerkleAuthenticationPath path = tree.BuildPath(3, BaseMemoryPool.Shared);

        Span<byte> tamperedLeaf = stackalloc byte[DigestSizeBytes];
        leaves.Slice(3 * DigestSizeBytes, DigestSizeBytes).CopyTo(tamperedLeaf);
        tamperedLeaf[0] ^= 0x01;

        bool authenticated = path.Verify(tree.Root, 3, tamperedLeaf, Blake3TwoToOne);

        Assert.IsFalse(authenticated, "A single-bit change to the claimed leaf value must break authentication.");
    }


    [TestMethod]
    public void VerifyRejectsCorruptedPath()
    {
        const int LeafCount = 8;
        using IMemoryOwner<byte> leavesOwner = BaseMemoryPool.Shared.Rent(LeafCount * DigestSizeBytes);
        Span<byte> leaves = leavesOwner.Memory.Span[..(LeafCount * DigestSizeBytes)];
        FillDistinctLeaves(leaves, LeafCount);

        using MerkleTree tree = MerkleTree.Build(leaves, LeafCount, Blake3TwoToOne, BaseMemoryPool.Shared);
        using MerkleAuthenticationPath path = tree.BuildPath(3, BaseMemoryPool.Shared);

        //Flip one bit in the first stored sibling digest.
        path.AsSpan()[0] ^= 0x01;

        bool authenticated = path.Verify(
            tree.Root, 3, leaves.Slice(3 * DigestSizeBytes, DigestSizeBytes), Blake3TwoToOne);

        Assert.IsFalse(authenticated, "A single-bit change to a path sibling must break authentication.");
    }


    [TestMethod]
    public void VerifyRejectsWrongRoot()
    {
        const int LeafCount = 8;
        using IMemoryOwner<byte> leavesOwner = BaseMemoryPool.Shared.Rent(LeafCount * DigestSizeBytes);
        Span<byte> leaves = leavesOwner.Memory.Span[..(LeafCount * DigestSizeBytes)];
        FillDistinctLeaves(leaves, LeafCount);

        using MerkleTree tree = MerkleTree.Build(leaves, LeafCount, Blake3TwoToOne, BaseMemoryPool.Shared);
        using MerkleAuthenticationPath path = tree.BuildPath(3, BaseMemoryPool.Shared);

        Span<byte> tamperedRoot = stackalloc byte[DigestSizeBytes];
        tree.Root.AsReadOnlySpan().CopyTo(tamperedRoot);
        tamperedRoot[^1] ^= 0x01;
        using MerkleRoot wrongRoot = MerkleRoot.FromBytes(tamperedRoot, BaseMemoryPool.Shared);

        bool authenticated = path.Verify(
            wrongRoot, 3, leaves.Slice(3 * DigestSizeBytes, DigestSizeBytes), Blake3TwoToOne);

        Assert.IsFalse(authenticated, "Authentication against a tampered root must fail.");
    }


    [TestMethod]
    public void VerifyRejectsWrongLeafIndex()
    {
        const int LeafCount = 8;
        using IMemoryOwner<byte> leavesOwner = BaseMemoryPool.Shared.Rent(LeafCount * DigestSizeBytes);
        Span<byte> leaves = leavesOwner.Memory.Span[..(LeafCount * DigestSizeBytes)];
        FillDistinctLeaves(leaves, LeafCount);

        using MerkleTree tree = MerkleTree.Build(leaves, LeafCount, Blake3TwoToOne, BaseMemoryPool.Shared);

        //A path built for leaf 2 presented as if it authenticated leaf 5 folds
        //the leaf along the wrong directions and reaches a different root.
        using MerkleAuthenticationPath path = tree.BuildPath(2, BaseMemoryPool.Shared);

        bool authenticated = path.Verify(
            tree.Root, 5, leaves.Slice(2 * DigestSizeBytes, DigestSizeBytes), Blake3TwoToOne);

        Assert.IsFalse(authenticated, "A path verified at the wrong leaf index must fail.");
    }


    [TestMethod]
    public void RandomTreesAuthenticateEveryLeaf()
    {
        Gen.Int[0, MaximumLeafExponent]
            .SelectMany(exponent =>
            {
                int leafCount = 1 << exponent;
                return Gen.Select(Gen.Const(leafCount), Gen.Byte.Array[leafCount * DigestSizeBytes]);
            })
            .Sample((leafCount, leafBytes) =>
            {
                using MerkleTree tree = MerkleTree.Build(leafBytes, leafCount, Blake3TwoToOne, BaseMemoryPool.Shared);
                for(int leafIndex = 0; leafIndex < leafCount; leafIndex++)
                {
                    using MerkleAuthenticationPath path = tree.BuildPath(leafIndex, BaseMemoryPool.Shared);
                    bool authenticated = path.Verify(
                        tree.Root, leafIndex, leafBytes.AsSpan(leafIndex * DigestSizeBytes, DigestSizeBytes), Blake3TwoToOne);
                    if(!authenticated)
                    {
                        return false;
                    }
                }

                return true;
            }, iter: IterationCount);
    }


    [TestMethod]
    public void RandomPathTamperingIsAlwaysRejected()
    {
        //Trees of at least two leaves so every path has at least one sibling to
        //tamper with.
        Gen.Int[1, MaximumLeafExponent]
            .SelectMany(exponent =>
            {
                int leafCount = 1 << exponent;
                return Gen.Select(
                    Gen.Const(leafCount),
                    Gen.Byte.Array[leafCount * DigestSizeBytes],
                    Gen.Int[0, leafCount - 1]);
            })
            .Sample((leafCount, leafBytes, leafIndex) =>
            {
                using MerkleTree tree = MerkleTree.Build(leafBytes, leafCount, Blake3TwoToOne, BaseMemoryPool.Shared);
                using MerkleAuthenticationPath path = tree.BuildPath(leafIndex, BaseMemoryPool.Shared);

                //Flip the first bit of the first sibling; authentication must fail.
                path.AsSpan()[0] ^= 0x01;
                bool authenticated = path.Verify(
                    tree.Root, leafIndex, leafBytes.AsSpan(leafIndex * DigestSizeBytes, DigestSizeBytes), Blake3TwoToOne);

                return !authenticated;
            }, iter: IterationCount);
    }


    [TestMethod]
    public void BuildRejectsNonPowerOfTwoLeafCount()
    {
        using IMemoryOwner<byte> leavesOwner = BaseMemoryPool.Shared.Rent(3 * DigestSizeBytes);
        Span<byte> leaves = leavesOwner.Memory.Span[..(3 * DigestSizeBytes)];
        FillDistinctLeaves(leaves, 3);

        //Build cannot be called inside a lambda capturing a Span; copy the
        //bytes out so the assertion's delegate is span-free.
        byte[] captured = leaves.ToArray();
        Assert.ThrowsExactly<ArgumentException>(
            () => MerkleTree.Build(captured, 3, Blake3TwoToOne, BaseMemoryPool.Shared).Dispose());
    }


    //Fills each leaf with a distinct value so that a misrouted path or a
    //swapped index surfaces as a mismatch rather than an accidental collision.
    private static void FillDistinctLeaves(Span<byte> leaves, int leafCount)
    {
        leaves.Clear();
        for(int i = 0; i < leafCount; i++)
        {
            //A distinct four-byte big-endian counter at the end of each leaf.
            Span<byte> leaf = leaves.Slice(i * DigestSizeBytes, DigestSizeBytes);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(leaf[^4..], i + 1);
        }
    }


    //Wires BLAKE3 as the two-to-one Merkle compression: hash the left and
    //right child bytes concatenated into the fixed 32-byte digest.
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}

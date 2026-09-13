using CsCheck;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// Tests for the BaseFold Merkle commitment infrastructure: a binary
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

    /// <summary>
    /// The leaf count the byte-length rejection tests pass: a positive power of two, so the
    /// leaf-count guards accept it and the byte-length guard under test is the first to fire.
    /// </summary>
    private const int ShapeCheckLeafCount = 4;

    /// <summary>The byte length of <see cref="ShapeCheckLeafCount"/> leaves, one node width each.</summary>
    private const int ExpectedShapeBytes = ShapeCheckLeafCount * DigestSizeBytes;

    /// <summary>A byte length one node width short of <see cref="ExpectedShapeBytes"/>.</summary>
    private const int OneNodeShortShapeBytes = ExpectedShapeBytes - DigestSizeBytes;


    private static MerkleHashDelegate Blake3TwoToOne { get; } = HashTwoToOne;

    /// <summary>The compression paired with the node width it produces.</summary>
    private static MerkleCommitmentParameters TreeParameters { get; } = new(Blake3TwoToOne, DigestSizeBytes);


    /// <summary>The pooled rentals opened during a test, released together in cleanup.</summary>
    private List<IDisposable> Disposables { get; } = [];


    /// <summary>Disposes every rental the test opened, most recent first.</summary>
    [TestCleanup]
    public void DisposeRentals()
    {
        for(int i = Disposables.Count - 1; i >= 0; i--)
        {
            Disposables[i].Dispose();
        }

        Disposables.Clear();
    }


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

        using MerkleTree tree = MerkleTree.Build(leaves, leafCount, TreeParameters, BaseMemoryPool.Shared);

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

        using MerkleTree tree = MerkleTree.Build(leaves, LeafCount, TreeParameters, BaseMemoryPool.Shared);
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

        using MerkleTree tree = MerkleTree.Build(leaves, LeafCount, TreeParameters, BaseMemoryPool.Shared);
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

        using MerkleTree tree = MerkleTree.Build(leaves, LeafCount, TreeParameters, BaseMemoryPool.Shared);
        using MerkleAuthenticationPath path = tree.BuildPath(3, BaseMemoryPool.Shared);

        //Flip one bit in the first stored sibling digest.
        MemoryMarshal.AsMemory(path.AsReadOnlyMemory()).Span[0] ^= 0x01;

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

        using MerkleTree tree = MerkleTree.Build(leaves, LeafCount, TreeParameters, BaseMemoryPool.Shared);
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

        using MerkleTree tree = MerkleTree.Build(leaves, LeafCount, TreeParameters, BaseMemoryPool.Shared);

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
                using MerkleTree tree = MerkleTree.Build(leafBytes, leafCount, TreeParameters, BaseMemoryPool.Shared);
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
                using MerkleTree tree = MerkleTree.Build(leafBytes, leafCount, TreeParameters, BaseMemoryPool.Shared);
                using MerkleAuthenticationPath path = tree.BuildPath(leafIndex, BaseMemoryPool.Shared);

                //Flip the first bit of the first sibling; authentication must fail.
                MemoryMarshal.AsMemory(path.AsReadOnlyMemory()).Span[0] ^= 0x01;
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
            () => MerkleTree.Build(captured, 3, TreeParameters, BaseMemoryPool.Shared).Dispose());
    }


    /// <summary>
    /// Build refuses leaf bytes one node width short of one node per leaf. The tree commits
    /// layer 0 verbatim, so the refusal names the leaves parameter and states both the received
    /// and the required byte length before any layer is rented.
    /// </summary>
    [TestMethod]
    public void BuildRejectsLeafBytesOneNodeShort()
    {
        Memory<byte> leaves = RentCleared(OneNodeShortShapeBytes);

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => MerkleTree.Build(leaves.Span, ShapeCheckLeafCount, TreeParameters, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual("leaves", thrown.ParamName);
        Assert.Contains(
            $"Leaf bytes length {OneNodeShortShapeBytes} must be one {DigestSizeBytes}-byte node per leaf ({ExpectedShapeBytes});",
            thrown.Message,
            StringComparison.Ordinal);
    }


    /// <summary>
    /// BuildSalted refuses value bytes one node width short of one node per leaf while the salts
    /// are correctly sized, naming the leaf-values parameter and stating both the received and
    /// the required byte length.
    /// </summary>
    [TestMethod]
    public void BuildSaltedRejectsLeafValueBytesOneNodeShort()
    {
        Memory<byte> leafValues = RentCleared(OneNodeShortShapeBytes);
        Memory<byte> salts = RentCleared(ExpectedShapeBytes);

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => MerkleTree.BuildSalted(leafValues.Span, salts.Span, ShapeCheckLeafCount, TreeParameters, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual("leafValues", thrown.ParamName);
        Assert.Contains(
            $"Leaf value bytes length {OneNodeShortShapeBytes} must be one {DigestSizeBytes}-byte node per leaf ({ExpectedShapeBytes}).",
            thrown.Message,
            StringComparison.Ordinal);
    }


    /// <summary>
    /// BuildSalted refuses salt bytes one node width short of one salt per leaf while the values
    /// are correctly sized, naming the salts parameter and stating both the received and the
    /// required byte length.
    /// </summary>
    [TestMethod]
    public void BuildSaltedRejectsSaltBytesOneNodeShort()
    {
        Memory<byte> leafValues = RentCleared(ExpectedShapeBytes);
        Memory<byte> salts = RentCleared(OneNodeShortShapeBytes);

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => MerkleTree.BuildSalted(leafValues.Span, salts.Span, ShapeCheckLeafCount, TreeParameters, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual("salts", thrown.ParamName);
        Assert.Contains(
            $"Salt bytes length {OneNodeShortShapeBytes} must equal one {DigestSizeBytes}-byte salt per leaf ({ExpectedShapeBytes}).",
            thrown.Message,
            StringComparison.Ordinal);
    }


    /// <summary>
    /// Rents a pooled buffer, clears it so every byte a test passes is deterministic, and
    /// registers the rental for release in <see cref="DisposeRentals"/>.
    /// </summary>
    /// <param name="length">The buffer length in bytes.</param>
    /// <returns>The cleared buffer, exactly <paramref name="length"/> bytes long.</returns>
    private Memory<byte> RentCleared(int length)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Disposables.Add(owner);

        Memory<byte> buffer = owner.Memory[..length];
        buffer.Span.Clear();

        return buffer;
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

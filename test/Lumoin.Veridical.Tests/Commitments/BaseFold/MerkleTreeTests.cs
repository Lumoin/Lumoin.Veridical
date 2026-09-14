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
    /// The leaf count the byte-length and null-argument rejection tests pass: a positive power of two,
    /// so the leaf-count guards accept it and only the guard under test fires.
    /// </summary>
    private const int ShapeCheckLeafCount = 4;

    /// <summary>The byte length of <see cref="ShapeCheckLeafCount"/> leaves, one node width each.</summary>
    private const int ExpectedShapeBytes = ShapeCheckLeafCount * DigestSizeBytes;

    /// <summary>A byte length one node width short of <see cref="ExpectedShapeBytes"/>.</summary>
    private const int OneNodeShortShapeBytes = ExpectedShapeBytes - DigestSizeBytes;

    /// <summary>
    /// The leaf count of the tree the sibling-level, node-level and disposal tests read: four leaves
    /// make a depth-two tree, so every path over it holds <see cref="PathDepth"/> siblings.
    /// </summary>
    private const int PathLeafCount = 4;

    /// <summary>The depth of a <see cref="PathLeafCount"/>-leaf tree, which is also the sibling count of its paths.</summary>
    private const int PathDepth = 2;

    /// <summary>The leaf whose authentication path the sibling-level rejection tests read.</summary>
    private const int PathLeafIndex = 0;

    /// <summary>A level below the leaf level, which names no sibling.</summary>
    private const int NegativeLevel = -1;

    /// <summary>The parameter name both range guards of the sibling accessor, and both level guards of the node accessor, report.</summary>
    private const string LevelParameterName = "level";

    /// <summary>A digest width of zero bytes, which leaves a path no room for any sibling.</summary>
    private const int ZeroDigestSizeBytes = 0;

    /// <summary>
    /// The rental length behind the zero-width path: one byte, the same minimum rental path
    /// construction makes for the empty path of a single-leaf tree.
    /// </summary>
    private const int ZeroWidthPathRentBytes = 1;

    /// <summary>The sibling count a zero-width path reports.</summary>
    private const int ExpectedZeroWidthSiblingCount = 0;

    /// <summary>A leaf count of zero, which describes no tree at all.</summary>
    private const int ZeroLeafCount = 0;

    /// <summary>A positive leaf count that is not a power of two, so no complete binary tree has that many leaves.</summary>
    private const int NonPowerOfTwoLeafCount = 3;

    /// <summary>The byte length of <see cref="NonPowerOfTwoLeafCount"/> values or salts, one node width each.</summary>
    private const int NonPowerOfTwoShapeBytes = NonPowerOfTwoLeafCount * DigestSizeBytes;

    /// <summary>The parameter name the null guard on the compression parameters reports.</summary>
    private const string ParametersParameterName = "parameters";

    /// <summary>The parameter name the null guard on the pool reports.</summary>
    private const string PoolParameterName = "pool";

    /// <summary>The parameter name both leaf-count guards of the builders report.</summary>
    private const string LeafCountParameterName = "leafCount";

    /// <summary>The parameter name both index guards of the node accessor report.</summary>
    private const string IndexInLevelParameterName = "indexInLevel";

    /// <summary>The leaf level, which the node accessor counts as level zero.</summary>
    private const int LeafLevel = 0;

    /// <summary>The index of the first node of a level.</summary>
    private const int FirstIndexInLevel = 0;

    /// <summary>An index before the first node of a level, which names no node.</summary>
    private const int NegativeIndexInLevel = -1;

    /// <summary>The level one above the root of a <see cref="PathLeafCount"/>-leaf tree, which holds no node.</summary>
    private const int AboveRootLevel = PathDepth + 1;

    /// <summary>The first level above the leaves of a <see cref="PathLeafCount"/>-leaf tree.</summary>
    private const int FirstInternalLevel = 1;

    /// <summary>
    /// The node count of <see cref="FirstInternalLevel"/>, half the leaf count. As an index it is one past
    /// the last node of that level, yet the slot it would address still lies inside the layer buffer: it
    /// holds the root, which the layers store directly after that level.
    /// </summary>
    private const int FirstInternalLevelNodeCount = PathLeafCount >> FirstInternalLevel;

    /// <summary>
    /// The slabs a private pool reclaims once a <see cref="PathLeafCount"/>-leaf tree built from it is
    /// disposed: the pool keeps one slab per rental length, and the tree rents its layer buffer and its
    /// root at two different lengths.
    /// </summary>
    private const int ExpectedReclaimedSlabCount = 2;


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
    /// A path whose digest width is zero reports no siblings. The sibling count is the buffer
    /// length divided by the digest width, so a zero width is answered as zero siblings before
    /// any division takes place, whatever length the buffer behind the path has.
    /// </summary>
    [TestMethod]
    public void SiblingCountOfAZeroWidthPathIsZero()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(ZeroWidthPathRentBytes);

        //The path takes ownership of the rental and releases it on dispose, so only the path is registered.
        MerkleAuthenticationPath path = MerkleAuthenticationPath.Create(owner, ZeroDigestSizeBytes);
        Disposables.Add(path);

        Assert.AreEqual(ExpectedZeroWidthSiblingCount, path.SiblingCount, "A zero-width path carries no siblings.");
    }


    /// <summary>
    /// GetSibling refuses a level below the leaf level with an <see cref="ArgumentOutOfRangeException"/>
    /// naming <c>level</c> and carrying the refused value. The path holds <see cref="PathDepth"/>
    /// siblings and minus one is below that count, so the upper-bound guard stays silent and only the
    /// non-negative guard answers, before the sibling bytes are addressed.
    /// </summary>
    [TestMethod]
    public void GetSiblingRejectsANegativeLevel()
    {
        MerkleAuthenticationPath path = BuildRegisteredPath();

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = path.GetSibling(NegativeLevel));

        Assert.AreEqual(LevelParameterName, thrown.ParamName);
        Assert.AreEqual(NegativeLevel, thrown.ActualValue);
    }


    /// <summary>
    /// GetSibling refuses the level equal to the sibling count with an
    /// <see cref="ArgumentOutOfRangeException"/> naming <c>level</c> and carrying the refused value.
    /// A <see cref="PathLeafCount"/>-leaf tree has depth <see cref="PathDepth"/>, so that level is the
    /// root, which has no sibling. The level is non-negative, so only the upper-bound guard answers,
    /// before the sibling bytes past the end of the path are addressed.
    /// </summary>
    [TestMethod]
    public void GetSiblingRejectsTheLevelAtTheRoot()
    {
        MerkleAuthenticationPath path = BuildRegisteredPath();

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = path.GetSibling(PathDepth));

        Assert.AreEqual(LevelParameterName, thrown.ParamName);
        Assert.AreEqual(PathDepth, thrown.ActualValue);
    }


    /// <summary>
    /// Build refuses missing compression parameters, naming <c>parameters</c>. The leaf count and the leaf
    /// bytes are well formed, so the parameters would otherwise first be reached where the node width is
    /// read, as a null dereference rather than a caller fault.
    /// </summary>
    [TestMethod]
    public void BuildRejectsNullParameters()
    {
        Memory<byte> leaves = RentCleared(ExpectedShapeBytes);

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => MerkleTree.Build(leaves.Span, ShapeCheckLeafCount, null!, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(ParametersParameterName, thrown.ParamName);
    }


    /// <summary>
    /// Build refuses a missing pool, naming <c>pool</c>. The leaf count and the leaf bytes are well formed,
    /// so the pool would otherwise first be reached where the layer buffer is rented, as a null dereference
    /// rather than a caller fault.
    /// </summary>
    [TestMethod]
    public void BuildRejectsANullPool()
    {
        Memory<byte> leaves = RentCleared(ExpectedShapeBytes);

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => MerkleTree.Build(leaves.Span, ShapeCheckLeafCount, TreeParameters, null!).Dispose());

        Assert.AreEqual(PoolParameterName, thrown.ParamName);
    }


    /// <summary>
    /// Build refuses a leaf count of zero with an <see cref="ArgumentOutOfRangeException"/> naming
    /// <c>leafCount</c> and carrying the refused value. Zero is not a power of two either, but that check
    /// answers with a plain <see cref="ArgumentException"/>, so the exact type shows the positivity guard
    /// answered first.
    /// </summary>
    [TestMethod]
    public void BuildRejectsAZeroLeafCount()
    {
        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => MerkleTree.Build(ReadOnlySpan<byte>.Empty, ZeroLeafCount, TreeParameters, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(LeafCountParameterName, thrown.ParamName);
        Assert.AreEqual(ZeroLeafCount, thrown.ActualValue);
    }


    /// <summary>
    /// BuildSalted refuses missing compression parameters, naming <c>parameters</c>. The leaf count, the
    /// values and the salts are well formed, so the parameters would otherwise first be reached where the
    /// node width is read, as a null dereference rather than a caller fault.
    /// </summary>
    [TestMethod]
    public void BuildSaltedRejectsNullParameters()
    {
        Memory<byte> leafValues = RentCleared(ExpectedShapeBytes);
        Memory<byte> salts = RentCleared(ExpectedShapeBytes);

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => MerkleTree.BuildSalted(leafValues.Span, salts.Span, ShapeCheckLeafCount, null!, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(ParametersParameterName, thrown.ParamName);
    }


    /// <summary>
    /// BuildSalted refuses a missing pool, naming <c>pool</c>. The leaf count, the values and the salts are
    /// well formed, so the pool would otherwise first be reached where the layer buffer is rented, as a null
    /// dereference rather than a caller fault.
    /// </summary>
    [TestMethod]
    public void BuildSaltedRejectsANullPool()
    {
        Memory<byte> leafValues = RentCleared(ExpectedShapeBytes);
        Memory<byte> salts = RentCleared(ExpectedShapeBytes);

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => MerkleTree.BuildSalted(leafValues.Span, salts.Span, ShapeCheckLeafCount, TreeParameters, null!).Dispose());

        Assert.AreEqual(PoolParameterName, thrown.ParamName);
    }


    /// <summary>
    /// BuildSalted refuses a leaf count of zero with an <see cref="ArgumentOutOfRangeException"/> naming
    /// <c>leafCount</c> and carrying the refused value. Zero is not a power of two either, but that check
    /// answers with a plain <see cref="ArgumentException"/>, so the exact type shows the positivity guard
    /// answered first.
    /// </summary>
    [TestMethod]
    public void BuildSaltedRejectsAZeroLeafCount()
    {
        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => MerkleTree.BuildSalted(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ZeroLeafCount, TreeParameters, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(LeafCountParameterName, thrown.ParamName);
        Assert.AreEqual(ZeroLeafCount, thrown.ActualValue);
    }


    /// <summary>
    /// BuildSalted refuses a leaf count that is not a power of two, naming <c>leafCount</c> and stating the
    /// refused count. The values and the salts are sized for that count, so the byte-length guards accept
    /// them. Without the refusal the halving layers would lose a node and the root slot would never be
    /// written, so the tree would commit to whatever the rented buffer held there.
    /// </summary>
    [TestMethod]
    public void BuildSaltedRejectsANonPowerOfTwoLeafCount()
    {
        Memory<byte> leafValues = RentCleared(NonPowerOfTwoShapeBytes);
        Memory<byte> salts = RentCleared(NonPowerOfTwoShapeBytes);

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => MerkleTree.BuildSalted(leafValues.Span, salts.Span, NonPowerOfTwoLeafCount, TreeParameters, BaseMemoryPool.Shared).Dispose());

        Assert.AreEqual(LeafCountParameterName, thrown.ParamName);
        Assert.Contains(
            $"Merkle leaf count must be a power of two; received {NonPowerOfTwoLeafCount}.",
            thrown.Message,
            StringComparison.Ordinal);
    }


    /// <summary>
    /// GetNode refuses a level below the leaf level, naming <c>level</c> and carrying the refused value.
    /// Minus one is below the depth and the index is the first node, so only the non-negative level guard
    /// answers. The index bound shifts the leaf count by the level, and a shift count of minus one is masked
    /// to its low five bits, 31, which leaves a bound of zero, so without this guard the index guard would
    /// misreport the fault.
    /// </summary>
    [TestMethod]
    public void GetNodeRejectsANegativeLevel()
    {
        MerkleTree tree = BuildRegisteredTree();

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = tree.GetNode(NegativeLevel, FirstIndexInLevel));

        Assert.AreEqual(LevelParameterName, thrown.ParamName);
        Assert.AreEqual(NegativeLevel, thrown.ActualValue);
    }


    /// <summary>
    /// GetNode refuses a level above the root, naming <c>level</c> and carrying the refused value. The level
    /// is non-negative and the index is the first node, so only the upper level guard answers. Past the root
    /// the shifted leaf count is zero, so without this guard the index guard would misreport the fault.
    /// </summary>
    [TestMethod]
    public void GetNodeRejectsALevelAboveTheRoot()
    {
        MerkleTree tree = BuildRegisteredTree();

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = tree.GetNode(AboveRootLevel, FirstIndexInLevel));

        Assert.AreEqual(LevelParameterName, thrown.ParamName);
        Assert.AreEqual(AboveRootLevel, thrown.ActualValue);
    }


    /// <summary>
    /// GetNode refuses an index before the first node of a level, naming <c>indexInLevel</c> and carrying the
    /// refused value. The level is the leaf level and minus one is below the level's node count, so only the
    /// non-negative index guard answers, before a byte offset in front of the layer buffer is computed.
    /// </summary>
    [TestMethod]
    public void GetNodeRejectsANegativeIndex()
    {
        MerkleTree tree = BuildRegisteredTree();

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = tree.GetNode(LeafLevel, NegativeIndexInLevel));

        Assert.AreEqual(IndexInLevelParameterName, thrown.ParamName);
        Assert.AreEqual(NegativeIndexInLevel, thrown.ActualValue);
    }


    /// <summary>
    /// GetNode refuses, at the first level above the leaves, the index equal to that level's node count, naming
    /// <c>indexInLevel</c> and carrying the refused value. The bound is the leaf count shifted right by the level,
    /// half the leaf count here. The slot that index would address holds the root, inside the layer buffer, so
    /// without the bound the read would silently return a node from the wrong level.
    /// </summary>
    [TestMethod]
    public void GetNodeRejectsAnIndexPastTheEndOfAnInternalLevel()
    {
        MerkleTree tree = BuildRegisteredTree();

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => _ = tree.GetNode(FirstInternalLevel, FirstInternalLevelNodeCount));

        Assert.AreEqual(IndexInLevelParameterName, thrown.ParamName);
        Assert.AreEqual(FirstInternalLevelNodeCount, thrown.ActualValue);
    }


    /// <summary>
    /// A disposed tree refuses node reads with an <see cref="ObjectDisposedException"/> naming the tree. Dispose
    /// releases the layer buffer and drops the tree's hold on it, so no read can reach bytes the pool may
    /// already have handed to another renter.
    /// </summary>
    [TestMethod]
    public void GetNodeRejectsADisposedTree()
    {
        Memory<byte> leaves = RentCleared(PathLeafCount * DigestSizeBytes);
        MerkleTree tree = MerkleTree.Build(leaves.Span, PathLeafCount, TreeParameters, BaseMemoryPool.Shared);
        tree.Dispose();

        ObjectDisposedException thrown = Assert.ThrowsExactly<ObjectDisposedException>(
            () => _ = tree.GetNode(LeafLevel, FirstIndexInLevel));

        Assert.AreEqual(nameof(MerkleTree), thrown.ObjectName);
    }


    /// <summary>
    /// Disposing a tree disposes the root it owns. A reference to the root taken before disposal refuses to
    /// expose its bytes afterwards, and the refusal names the root's own type, so it comes from the root's
    /// disposed check rather than from the pool rental behind it.
    /// </summary>
    [TestMethod]
    public void DisposeReleasesTheRootTheTreeOwns()
    {
        Memory<byte> leaves = RentCleared(PathLeafCount * DigestSizeBytes);
        MerkleTree tree = MerkleTree.Build(leaves.Span, PathLeafCount, TreeParameters, BaseMemoryPool.Shared);
        MerkleRoot root = tree.Root;
        tree.Dispose();

        ObjectDisposedException thrown = Assert.ThrowsExactly<ObjectDisposedException>(() => _ = root.AsReadOnlySpan());

        Assert.AreEqual(typeof(MerkleRoot).FullName, thrown.ObjectName);
    }


    /// <summary>
    /// Disposing a tree returns both of its rentals, the layer buffer and the root, to the pool it was built
    /// from. The tree is built from a private pool, and <see cref="BaseMemoryPool.TrimExcess"/> reclaims only
    /// slabs with no active rental, so reclaiming <see cref="ExpectedReclaimedSlabCount"/> slabs shows that
    /// neither rental is still held.
    /// </summary>
    [TestMethod]
    public void DisposeReturnsTheLayerBufferAndTheRootToThePool()
    {
        using BaseMemoryPool pool = new();
        Memory<byte> leaves = RentCleared(PathLeafCount * DigestSizeBytes);

        MerkleTree tree = MerkleTree.Build(leaves.Span, PathLeafCount, TreeParameters, pool);
        tree.Dispose();

        Assert.AreEqual(ExpectedReclaimedSlabCount, pool.TrimExcess(), "A disposed tree must hold no rental from the pool it was built from.");
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


    /// <summary>
    /// Builds a tree over <see cref="PathLeafCount"/> cleared leaves and the authentication path of
    /// leaf <see cref="PathLeafIndex"/>, registering the tree and the path for release in
    /// <see cref="DisposeRentals"/>.
    /// </summary>
    /// <returns>A path holding <see cref="PathDepth"/> sibling digests, one node width each.</returns>
    private MerkleAuthenticationPath BuildRegisteredPath()
    {
        MerkleTree tree = BuildRegisteredTree();
        MerkleAuthenticationPath path = tree.BuildPath(PathLeafIndex, BaseMemoryPool.Shared);
        Disposables.Add(path);

        return path;
    }


    /// <summary>
    /// Builds a tree over <see cref="PathLeafCount"/> cleared leaves, registering the leaves and the tree for
    /// release in <see cref="DisposeRentals"/>.
    /// </summary>
    /// <returns>A tree of depth <see cref="PathDepth"/> whose nodes are one digest wide.</returns>
    private MerkleTree BuildRegisteredTree()
    {
        Memory<byte> leaves = RentCleared(PathLeafCount * DigestSizeBytes);
        MerkleTree tree = MerkleTree.Build(leaves.Span, PathLeafCount, TreeParameters, BaseMemoryPool.Shared);
        Disposables.Add(tree);

        return tree;
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

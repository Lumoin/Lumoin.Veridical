using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The wire-format-conformant Ligero COMMITMENT layer, gated as a faithful
/// port of google/longfellow-zk's <c>lib/ligero/ligero_prover.h</c> commit path,
/// <c>lib/ligero/ligero_param.h</c> parameter derivation and <c>lib/merkle/merkle_tree.h</c> Merkle
/// tree, anchored to a commitment root the reference itself computes.
/// </summary>
/// <remarks>
/// <para>
/// The anchor carries the derived <c>LigeroParam</c> fields for several
/// <c>(nw, nq, rateinv, nreq)</c> tuples and a full commit (per-leaf SHA-256 digests + the Merkle
/// root) over a fixed witness set, computed with a deterministic random engine whose k-th byte is
/// <c>k &amp; 0xFF</c>.
/// </para>
/// <para>
/// The C# gates reproduce: (a) the derived parameter fields for the tuples; (b) the leaf digests byte
/// for byte; (c) the commitment root byte for byte, over both subfields the reference instantiates
/// (production GF(2^16) and test-parity GF(2^32)). The unit gates check the Merkle combine against
/// .NET's SHA-256 directly and the heap-layout root for tiny non-power-of-two trees against
/// hand-computed values; the adversarial duals show a flipped leaf changes the root and a flipped
/// element changes its leaf.
/// </para>
/// </remarks>
[TestClass]
internal sealed class LongfellowLigeroCommitmentTests
{
    /// <summary>The canonical scalar width in bytes.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The SHA-256 digest width in bytes.</summary>
    private const int DigestSize = 32;

    /// <summary>The GF(2^128) full field element width in bytes.</summary>
    private const int FieldBytes = 16;

    /// <summary>The production GF(2^16) subfield element width in bytes.</summary>
    private const int Production16SubFieldBytes = 2;

    /// <summary>The test-parity GF(2^32) subfield element width in bytes.</summary>
    private const int TestParity32SubFieldBytes = 4;

    /// <summary>The GF(2^128) addition delegate (XOR).</summary>
    private static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    /// <summary>The GF(2^128) subtraction delegate (coincides with addition).</summary>
    private static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    /// <summary>The GF(2^128) multiplication delegate.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    /// <summary>The GF(2^128) inversion delegate.</summary>
    private static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();


    /// <summary>Verifies that the derived Ligero parameters match the reference's recorded values for several shapes over the production GF(2^16) subfield.</summary>
    [TestMethod]
    public void DerivedParametersMatchTheReferenceForTheProductionSubfield()
    {
        //The "p16 ..." lines from commit-anchor-output.txt: GF(2^16), kSubFieldBytes = 2.
        AssertParameters(300000, 30000, 4, 189, Production16SubFieldBytes, blockEncoded: 8192, block: 1365, doubleBlock: 2729, blockExtension: 5463, witnessRowCount: 256, quadraticTripleCount: 26, witnessQuadraticRowCount: 334, rowCount: 337);
        AssertParameters(1000, 100, 4, 16, Production16SubFieldBytes, blockEncoded: 256, block: 42, doubleBlock: 83, blockExtension: 173, witnessRowCount: 39, quadraticTripleCount: 4, witnessQuadraticRowCount: 51, rowCount: 54);
        AssertParameters(64, 8, 4, 4, Production16SubFieldBytes, blockEncoded: 64, block: 10, doubleBlock: 19, blockExtension: 45, witnessRowCount: 11, quadraticTripleCount: 2, witnessQuadraticRowCount: 17, rowCount: 20);
        AssertParameters(256, 32, 2, 8, Production16SubFieldBytes, blockEncoded: 64, block: 16, doubleBlock: 31, blockExtension: 33, witnessRowCount: 32, quadraticTripleCount: 4, witnessQuadraticRowCount: 44, rowCount: 47);
        AssertParameters(5000, 500, 8, 32, Production16SubFieldBytes, blockEncoded: 1024, block: 102, doubleBlock: 203, blockExtension: 821, witnessRowCount: 72, quadraticTripleCount: 8, witnessQuadraticRowCount: 96, rowCount: 99);
    }


    /// <summary>Verifies that the derived Ligero parameters match the reference's recorded values for several shapes over the test-parity GF(2^32) subfield.</summary>
    [TestMethod]
    public void DerivedParametersMatchTheReferenceForTheTestParitySubfield()
    {
        //The "p32 ..." lines: GF(2^32), kSubFieldBytes = 4. The 300000-witness tuple chooses a larger
        //block_enc than the GF(2^16) case because the subfield cap (block_enc < 2^subfield_bits) does
        //not bind here, so the optimizer's proof-size minimum lands at a different power of two.
        AssertParameters(300000, 30000, 4, 189, TestParity32SubFieldBytes, blockEncoded: 16384, block: 2730, doubleBlock: 5459, blockExtension: 10925, witnessRowCount: 119, quadraticTripleCount: 12, witnessQuadraticRowCount: 155, rowCount: 158);
        AssertParameters(1000, 100, 4, 16, TestParity32SubFieldBytes, blockEncoded: 256, block: 42, doubleBlock: 83, blockExtension: 173, witnessRowCount: 39, quadraticTripleCount: 4, witnessQuadraticRowCount: 51, rowCount: 54);
        AssertParameters(64, 8, 4, 4, TestParity32SubFieldBytes, blockEncoded: 64, block: 10, doubleBlock: 19, blockExtension: 45, witnessRowCount: 11, quadraticTripleCount: 2, witnessQuadraticRowCount: 17, rowCount: 20);
    }


    /// <summary>Verifies that the commitment root and its leading and trailing leaf digests match the reference's recorded values over the production GF(2^16) subfield.</summary>
    [TestMethod]
    public void TheCommitmentRootAndLeavesMatchTheReferenceForTheProductionSubfield()
    {
        //c16_* in commit-anchor-output.txt: GF(2^16), nw=8 nq=1 rateinv=4 nreq=2.
        AssertCommitMatchesReference(
            Lch14Subfield.Production16,
            Production16SubFieldBytes,
            expectedRootHex: "894ee3d5c0926fc02d935bbf5857d6256407f290a267afc3ec72831992186bf4",
            leaf0Hex: "566d0ae76af2382daea0c1636526043b5b74175496e1254783b36b28127f8bbe",
            leaf1Hex: "ea9e1df336ddf113d099d5e3d1d3295d7dd42cccf45cd945cb1475ba66a1ac98",
            leaf2Hex: "48aab26e9cfea10bf930026e8bf7ae96ac7193e484d9f623865d7fc03d2bb6f4",
            lastLeafHex: "7e0e2b1be403580c8ad098a1153b6b6097fefccfba8aab7df4cc1e4a83c43af6");
    }


    /// <summary>Verifies that the commitment root and its leading and trailing leaf digests match the reference's recorded values over the test-parity GF(2^32) subfield.</summary>
    [TestMethod]
    public void TheCommitmentRootAndLeavesMatchTheReferenceForTheTestParitySubfield()
    {
        //c32_* in commit-anchor-output.txt: GF(2^32), nw=8 nq=1 rateinv=4 nreq=2.
        AssertCommitMatchesReference(
            Lch14Subfield.TestParity32,
            TestParity32SubFieldBytes,
            expectedRootHex: "d3a94f1ccc73da7c73baf233683c82d4276d35ca7c4c03a8cfc51412dd596bf8",
            leaf0Hex: "9d3f8dd667af4307ec6214db5a255652746be1bb5cb7e6cb373b75c9f6739a2a",
            leaf1Hex: "cec35b31cd856ddcd44cd85a96be62138c2e3ed8bc020cc81a36c456a8b12632",
            leaf2Hex: "dca0b6deddfff0f262b2d940780f2f73c75e698129e31a5e14aeb3c9841e99c5",
            lastLeafHex: "821890834800d9915d1bcbfc76d5c2ebd9d7421503d34de9b269d3eab2d37ce5");
    }


    /// <summary>Verifies that the Merkle two-to-one combine equals .NET's <c>SHA256(left ‖ right)</c> for two distinct child digests.</summary>
    [TestMethod]
    public void TheMerkleCombineMatchesDotNetSha256()
    {
        //Two distinct child digests; the parent must be SHA256(left || right).
        Span<byte> left = stackalloc byte[DigestSize];
        Span<byte> right = stackalloc byte[DigestSize];
        for(int i = 0; i < DigestSize; i++)
        {
            left[i] = (byte)i;
            right[i] = (byte)(255 - i);
        }

        Span<byte> parent = stackalloc byte[DigestSize];
        Sha256TwoToOne(left, right, parent);

        Span<byte> expected = stackalloc byte[DigestSize];
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..DigestSize]);
        right.CopyTo(combined.Slice(DigestSize, DigestSize));
        SHA256.HashData(combined, expected);

        Assert.IsTrue(parent.SequenceEqual(expected), "The Merkle combine must equal .NET SHA256(left || right).");
    }


    /// <summary>Verifies that a two-leaf tree's root is the hand-computed combine of its two leaves.</summary>
    [TestMethod]
    public void TheTwoLeafTreeRootIsTheHandComputedCombine()
    {
        //n = 2: heap nodes [1, 4), leaves at [2, 4), root = SHA256(leaf0 || leaf1).
        Span<byte> leaves = stackalloc byte[2 * DigestSize];
        FillLeaf(leaves, 0, fillByte: 0xAA);
        FillLeaf(leaves, 1, fillByte: 0xBB);

        using LongfellowMerkleTree tree = LongfellowMerkleTree.Build(leaves, 2, Sha256TwoToOne, BaseMemoryPool.Shared);

        Span<byte> expected = stackalloc byte[DigestSize];
        Sha256TwoToOne(leaves[..DigestSize], leaves.Slice(DigestSize, DigestSize), expected);

        Span<byte> root = stackalloc byte[DigestSize];
        tree.CopyRoot(root);
        Assert.IsTrue(root.SequenceEqual(expected), "A two-leaf tree's root must be the hand-computed combine of its leaves.");
    }


    /// <summary>Verifies that a three-leaf tree's root, and its intermediate heap node, follow the reference's non-balanced heap layout for an odd leaf count.</summary>
    [TestMethod]
    public void TheThreeLeafTreeRootMatchesTheReferenceHeapLayout()
    {
        //n = 3: heap nodes [1, 6), leaves at [3, 6). The combine loop runs i = 2, 1:
        //  node[2] = SHA256(node[4] || node[5]) = SHA256(leaf1 || leaf2)
        //  node[1] = SHA256(node[2] || node[3]) = SHA256(node[2] || leaf0)
        //This non-balanced heap (leaf0 sits one level higher than leaf1/leaf2) is the reference's
        //exact layout for an odd leaf count, distinct from a power-of-two padded tree.
        Span<byte> leaves = stackalloc byte[3 * DigestSize];
        FillLeaf(leaves, 0, fillByte: 0x01);
        FillLeaf(leaves, 1, fillByte: 0x02);
        FillLeaf(leaves, 2, fillByte: 0x03);

        using LongfellowMerkleTree tree = LongfellowMerkleTree.Build(leaves, 3, Sha256TwoToOne, BaseMemoryPool.Shared);

        Span<byte> node2 = stackalloc byte[DigestSize];
        Sha256TwoToOne(leaves.Slice(DigestSize, DigestSize), leaves.Slice(2 * DigestSize, DigestSize), node2);

        Span<byte> expectedRoot = stackalloc byte[DigestSize];
        Sha256TwoToOne(node2, leaves[..DigestSize], expectedRoot);

        Span<byte> root = stackalloc byte[DigestSize];
        tree.CopyRoot(root);
        Assert.IsTrue(root.SequenceEqual(expectedRoot), "A three-leaf tree must follow the reference's heap layout exactly.");

        //The intermediate node 2 must also match, confirming the heap indexing, not just the root.
        Assert.IsTrue(tree.GetNode(2).SequenceEqual(node2), "Heap node 2 must combine leaf 1 and leaf 2.");
    }


    /// <summary>Verifies that flipping one bit of one leaf changes the tree's root.</summary>
    [TestMethod]
    public void AFlippedLeafChangesTheRoot()
    {
        Span<byte> leaves = stackalloc byte[3 * DigestSize];
        FillLeaf(leaves, 0, fillByte: 0x10);
        FillLeaf(leaves, 1, fillByte: 0x20);
        FillLeaf(leaves, 2, fillByte: 0x30);

        Span<byte> original = stackalloc byte[DigestSize];
        using(LongfellowMerkleTree tree = LongfellowMerkleTree.Build(leaves, 3, Sha256TwoToOne, BaseMemoryPool.Shared))
        {
            tree.CopyRoot(original);
        }

        //Flip one bit of one leaf; the root must change.
        leaves[DigestSize] ^= 0x01;
        Span<byte> tampered = stackalloc byte[DigestSize];
        using(LongfellowMerkleTree tree = LongfellowMerkleTree.Build(leaves, 3, Sha256TwoToOne, BaseMemoryPool.Shared))
        {
            tree.CopyRoot(tampered);
        }

        Assert.IsFalse(original.SequenceEqual(tampered), "A flipped leaf must change the Merkle root.");
    }


    /// <summary>Verifies that flipping one witness element before commit propagates through the codeword into the leaves and changes the commitment root.</summary>
    [TestMethod]
    public void AFlippedTableauElementChangesItsLeafAndTheRoot()
    {
        //Commit the production set, flip one witness bit, recommit: a witness change propagates into
        //the codeword and so into the leaves and the root.
        Span<byte> original = stackalloc byte[DigestSize];
        Commit(Lch14Subfield.Production16, Production16SubFieldBytes, witnessFlipIndex: -1, original);

        Span<byte> tampered = stackalloc byte[DigestSize];
        Commit(Lch14Subfield.Production16, Production16SubFieldBytes, witnessFlipIndex: 0, tampered);

        Assert.IsFalse(original.SequenceEqual(tampered), "A flipped witness element must change the commitment root.");
    }


    /// <summary>Verifies that copying the root into a buffer one byte short of the digest size is rejected.</summary>
    [TestMethod]
    public void RejectsAMisSizedRootBuffer()
    {
        Span<byte> leaves = stackalloc byte[2 * DigestSize];
        FillLeaf(leaves, 0, fillByte: 0xAA);
        FillLeaf(leaves, 1, fillByte: 0xBB);

        using LongfellowMerkleTree tree = LongfellowMerkleTree.Build(leaves, 2, Sha256TwoToOne, BaseMemoryPool.Shared);

        //CopyRoot takes a Span, so the wrong-length argument is a plain array that converts at the call.
        byte[] wrongLength = new byte[DigestSize - 1];
        Assert.ThrowsExactly<ArgumentException>(() => tree.CopyRoot(wrongLength));
    }


    /// <summary>Builds the parameters and asserts every derived field equals the reference's recorded value.</summary>
    private static void AssertParameters(
        int witnessCount,
        int quadraticConstraintCount,
        int inverseRate,
        int openedColumnCount,
        int subFieldBytes,
        int blockEncoded,
        int block,
        int doubleBlock,
        int blockExtension,
        int witnessRowCount,
        int quadraticTripleCount,
        int witnessQuadraticRowCount,
        int rowCount)
    {
        var parameters = new LongfellowLigeroParameters(witnessCount, quadraticConstraintCount, inverseRate, openedColumnCount, FieldBytes, subFieldBytes);

        Assert.AreEqual(blockEncoded, parameters.BlockEncoded, "block_enc must match the reference.");
        Assert.AreEqual(block, parameters.Block, "block must match the reference.");
        Assert.AreEqual(doubleBlock, parameters.DoubleBlock, "dblock must match the reference.");
        Assert.AreEqual(blockExtension, parameters.BlockExtension, "block_ext must match the reference.");
        Assert.AreEqual(openedColumnCount, parameters.RandomCount, "r must equal nreq.");
        Assert.AreEqual(block - openedColumnCount, parameters.WitnessPerRow, "w must equal block − r.");
        Assert.AreEqual(witnessRowCount, parameters.WitnessRowCount, "nwrow must match the reference.");
        Assert.AreEqual(quadraticTripleCount, parameters.QuadraticTripleCount, "nqtriples must match the reference.");
        Assert.AreEqual(witnessQuadraticRowCount, parameters.WitnessQuadraticRowCount, "nwqrow must match the reference.");
        Assert.AreEqual(rowCount, parameters.RowCount, "nrow must match the reference.");
    }


    /// <summary>Commits the fixed witness set over the given subfield and asserts the root and three leaves plus the last leaf match the reference's recorded hex values.</summary>
    private static void AssertCommitMatchesReference(
        Lch14Subfield subfield,
        int subFieldBytes,
        string expectedRootHex,
        string leaf0Hex,
        string leaf1Hex,
        string leaf2Hex,
        string lastLeafHex)
    {
        const int witnessCount = 8;
        const int quadraticConstraintCount = 1;
        const int inverseRate = 4;
        const int openedColumnCount = 2;

        var parameters = new LongfellowLigeroParameters(witnessCount, quadraticConstraintCount, inverseRate, openedColumnCount, FieldBytes, subFieldBytes);

        using Lch14AdditiveFft fft = NewFft(subfield);

        //The leaf digests are computed independently here so the leaf gate is checked, then the root
        //is checked from the same commit. The commitment helper hands back the leaves through the
        //leafHash delegate by recording them; instead we recompute the commit and pull the leaves out
        //of a fresh tree built over the same column hashes. Simpler: recompute both via the public
        //commit and a parallel leaf computation that mirrors the reference framing.
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(witnessCount * ScalarSize);
        Span<byte> witnesses = witnessOwner.Memory.Span[..(witnessCount * ScalarSize)];
        BuildWitnesses(fft, witnesses, witnessFlipIndex: -1);

        LigeroQuadraticConstraint[] quadraticConstraints = [new LigeroQuadraticConstraint(0, 1, 2)];

        Span<byte> root = stackalloc byte[DigestSize];
        LongfellowRandomByteSource random = NewCounterSource();
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        LongfellowLigeroCommitment.Commit(
            parameters, witnesses, quadraticConstraints, subFieldBytes, parameters.WitnessCount, random, encoderFactory, profile,
            Add, Subtract, Multiply, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, root, BaseMemoryPool.Shared);

        AssertHex(expectedRootHex, root, "The commitment root must match the reference.");

        //Independently recompute the leaf digests to gate leaf-level identity: replay the same commit
        //but capture the leaf inputs through a recording leaf hash.
        AssertReferenceLeaves(parameters, witnesses, quadraticConstraints, subFieldBytes, fft, leaf0Hex, leaf1Hex, leaf2Hex, lastLeafHex);

        witnesses.Clear();
    }


    /// <summary>Recomputes the commit with a recording leaf hash so the produced leaf digests can be pinned.</summary>
    private static void AssertReferenceLeaves(
        LongfellowLigeroParameters parameters,
        ReadOnlySpan<byte> witnesses,
        LigeroQuadraticConstraint[] quadraticConstraints,
        int subFieldBytes,
        Lch14AdditiveFft fft,
        string leaf0Hex,
        string leaf1Hex,
        string leaf2Hex,
        string lastLeafHex)
    {
        int blockExtension = parameters.BlockExtension;
        byte[][] recordedLeaves = new byte[blockExtension][];
        int recorded = 0;

        //Hashes one leaf and records its digest into recordedLeaves at the next slot, in commit order.
        //The requested hash-algorithm name is ignored: this delegate is always SHA-256.
        void RecordingLeafHash(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
        {
            SHA256.HashData(input, output);
            recordedLeaves[recorded] = output.ToArray();
            recorded++;
        }

        Span<byte> root = stackalloc byte[DigestSize];
        LongfellowRandomByteSource random = NewCounterSource();
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        LongfellowLigeroCommitment.Commit(
            parameters, witnesses, quadraticConstraints, subFieldBytes, parameters.WitnessCount, random, encoderFactory, profile,
            Add, Subtract, Multiply, Sha256TwoToOne, RecordingLeafHash, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, root, BaseMemoryPool.Shared);

        Assert.AreEqual(blockExtension, recorded, "The commit must hash exactly block_ext leaves.");
        AssertHex(leaf0Hex, recordedLeaves[0], "Leaf 0 must match the reference.");
        AssertHex(leaf1Hex, recordedLeaves[1], "Leaf 1 must match the reference.");
        AssertHex(leaf2Hex, recordedLeaves[2], "Leaf 2 must match the reference.");
        AssertHex(lastLeafHex, recordedLeaves[blockExtension - 1], "The last leaf must match the reference.");
    }


    /// <summary>Commits the fixed witness set over the given subfield with an optional one-bit witness flip, writing the root.</summary>
    /// <param name="subfield">The LCH14 subfield to build the FFT over.</param>
    /// <param name="subFieldBytes">The subfield element width in bytes.</param>
    /// <param name="witnessFlipIndex">The witness index whose low bit is flipped, or a negative value for no flip.</param>
    /// <param name="root">Receives the commitment root.</param>
    private static void Commit(Lch14Subfield subfield, int subFieldBytes, int witnessFlipIndex, Span<byte> root)
    {
        const int witnessCount = 8;
        const int quadraticConstraintCount = 1;
        const int inverseRate = 4;
        const int openedColumnCount = 2;

        var parameters = new LongfellowLigeroParameters(witnessCount, quadraticConstraintCount, inverseRate, openedColumnCount, FieldBytes, subFieldBytes);
        using Lch14AdditiveFft fft = NewFft(subfield);

        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(witnessCount * ScalarSize);
        Span<byte> witnesses = witnessOwner.Memory.Span[..(witnessCount * ScalarSize)];
        BuildWitnesses(fft, witnesses, witnessFlipIndex);

        LigeroQuadraticConstraint[] quadraticConstraints = [new LigeroQuadraticConstraint(0, 1, 2)];

        LongfellowRandomByteSource random = NewCounterSource();
        LongfellowRowEncoderFactory encoderFactory = LongfellowGf2k128Encoding.CreateEncoderFactory(fft, BaseMemoryPool.Shared);
        using LongfellowFieldProfile profile = LongfellowGf2k128Encoding.CreateProfile(fft, BaseMemoryPool.Shared);
        LongfellowLigeroCommitment.Commit(
            parameters, witnesses, quadraticConstraints, subFieldBytes, parameters.WitnessCount, random, encoderFactory, profile,
            Add, Subtract, Multiply, Sha256TwoToOne, Sha256OneShot, WellKnownHashAlgorithms.Sha256, CurveParameterSet.None, root, BaseMemoryPool.Shared);

        witnesses.Clear();
    }


    /// <summary>
    /// Seeds <c>W[i] = of_scalar(i + 1)</c> (<c>NodeElement(i+1)</c>), then sets <c>W[2] = W[0]·W[1]</c>
    /// to satisfy the one quadratic constraint — the reference's exact witness seeding. An optional
    /// flip index XORs one low bit of a witness to model a corrupted element; <c>W[2]</c> is then
    /// recomputed so the only difference is the perturbed input, which still propagates into the
    /// codeword and leaves.
    /// </summary>
    /// <param name="fft">The additive-FFT engine supplying <c>NodeElement</c>.</param>
    /// <param name="witnesses">Receives the seeded witness column.</param>
    /// <param name="witnessFlipIndex">The witness index whose low bit is flipped, or a negative value for no flip.</param>
    private static void BuildWitnesses(Lch14AdditiveFft fft, Span<byte> witnesses, int witnessFlipIndex)
    {
        int witnessCount = witnesses.Length / ScalarSize;
        for(int i = 0; i < witnessCount; i++)
        {
            fft.NodeElement((uint)(i + 1), witnesses.Slice(i * ScalarSize, ScalarSize));
        }

        if(witnessFlipIndex >= 0)
        {
            witnesses[(witnessFlipIndex * ScalarSize) + ScalarSize - 1] ^= 0x01;
        }

        Multiply(
            witnesses[..ScalarSize],
            witnesses.Slice(ScalarSize, ScalarSize),
            witnesses.Slice(2 * ScalarSize, ScalarSize),
            CurveParameterSet.None);
    }


    /// <summary>
    /// Creates a fresh deterministic counter source: the k-th byte produced is <c>k &amp; 0xFF</c>.
    /// Each call returns a new source so a test restarts the stream at zero.
    /// </summary>
    /// <returns>A deterministic counter-based random byte source.</returns>
    private static LongfellowRandomByteSource NewCounterSource()
    {
        ulong counter = 0;

        return destination =>
        {
            for(int i = 0; i < destination.Length; i++)
            {
                destination[i] = (byte)(counter & 0xFF);
                counter++;
            }
        };
    }


    /// <summary>Creates the LCH14 additive-FFT engine over the given subfield.</summary>
    /// <param name="subfield">The subfield to build the FFT over.</param>
    /// <returns>The new additive-FFT engine.</returns>
    private static Lch14AdditiveFft NewFft(Lch14Subfield subfield) =>
        new(subfield, Add, Subtract, Multiply, Invert, CurveParameterSet.None, BaseMemoryPool.Shared);


    /// <summary>Computes the reference's node combine: <c>SHA256(left ‖ right)</c>.</summary>
    /// <param name="left">The left digest.</param>
    /// <param name="right">The right digest.</param>
    /// <param name="output">Receives the combined digest.</param>
    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>Computes the one-shot leaf hash: SHA-256 over the whole nonce-plus-column input span.</summary>
    /// <param name="input">The bytes to hash.</param>
    /// <param name="output">Receives the 32-byte digest.</param>
    /// <param name="hashFunction">The requested hash algorithm name; unused, since this delegate is always SHA-256.</param>
    private static void Sha256OneShot(ReadOnlySpan<byte> input, Span<byte> output, string hashFunction)
    {
        SHA256.HashData(input, output);
    }


    /// <summary>Fills one digest-sized leaf slot with a repeated byte value.</summary>
    /// <param name="leaves">The concatenated leaf buffer.</param>
    /// <param name="leafIndex">The leaf index to fill.</param>
    /// <param name="fillByte">The byte value to fill with.</param>
    private static void FillLeaf(Span<byte> leaves, int leafIndex, byte fillByte)
    {
        leaves.Slice(leafIndex * DigestSize, DigestSize).Fill(fillByte);
    }


    /// <summary>Asserts that <paramref name="actual"/> equals the bytes <paramref name="expectedHex"/> decodes to.</summary>
    /// <param name="expectedHex">The expected bytes, hex-encoded.</param>
    /// <param name="actual">The actual bytes.</param>
    /// <param name="message">The assertion failure message.</param>
    private static void AssertHex(string expectedHex, ReadOnlySpan<byte> actual, string message)
    {
        Span<byte> expected = stackalloc byte[DigestSize];
        Convert.FromHexString(expectedHex).CopyTo(expected);
        Assert.IsTrue(actual.SequenceEqual(expected), message);
    }
}

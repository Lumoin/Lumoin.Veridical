using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Pins the compressed-proof verifier's rejection of malformed openings — the family Trail of Bits
/// TOB-LIBZK-4 (path extension / out-of-range position in the removed single-leaf verifier) and
/// TOB-LIBZK-9 (repeated indices) name. This port exposes only the compressed verify path
/// (<see cref="LongfellowMerkleTree.VerifyCompressedProof"/>) and enforces position range and
/// uniqueness at that boundary.
/// </summary>
[TestClass]
internal sealed class LongfellowMerkleTreeSoundnessTests
{
    private const int LeafCount = 6;
    private const int DigestSize = 32;
    private const byte LeafFillBase = 0x10;
    private const int OpenedPositionOne = 1;
    private const int OpenedPositionTwo = 4;


    [TestMethod]
    public void AValidCompressedProofVerifies()
    {
        Span<byte> leaves = stackalloc byte[LeafCount * DigestSize];
        for(int i = 0; i < LeafCount; i++)
        {
            leaves.Slice(i * DigestSize, DigestSize).Fill((byte)(LeafFillBase + i));
        }

        using LongfellowMerkleTree tree = LongfellowMerkleTree.Build(leaves, LeafCount, Sha256TwoToOne, BaseMemoryPool.Shared);

        Span<byte> root = stackalloc byte[DigestSize];
        tree.CopyRoot(root);

        ReadOnlySpan<int> positions = [OpenedPositionOne, OpenedPositionTwo];
        Span<byte> proofBuffer = stackalloc byte[LeafCount * DigestSize];
        int digestCount = tree.GenerateCompressedProof(positions, proofBuffer, BaseMemoryPool.Shared);
        ReadOnlySpan<byte> proof = proofBuffer[..(digestCount * DigestSize)];

        Span<byte> openedLeaves = stackalloc byte[positions.Length * DigestSize];
        leaves.Slice(OpenedPositionOne * DigestSize, DigestSize).CopyTo(openedLeaves[..DigestSize]);
        leaves.Slice(OpenedPositionTwo * DigestSize, DigestSize).CopyTo(openedLeaves.Slice(DigestSize, DigestSize));

        bool ok = LongfellowMerkleTree.VerifyCompressedProof(LeafCount, root, openedLeaves, positions, proof, digestCount, Sha256TwoToOne, BaseMemoryPool.Shared);

        Assert.IsTrue(ok, "A valid compressed proof over its own root must verify.");
    }


    [TestMethod]
    public void ADuplicatePositionIsRejected()
    {
        //The duplicate check fires before proof consumption, so an empty proof exercises it directly.
        //Arrays (not spans) are captured here: a ref struct cannot cross a lambda closure boundary.
        int[] positions = [0, 0];
        byte[] leaves = new byte[positions.Length * DigestSize];
        byte[] root = new byte[DigestSize];

        Assert.ThrowsExactly<ArgumentException>(() =>
            LongfellowMerkleTree.VerifyCompressedProof(LeafCount, root, leaves, positions, ReadOnlySpan<byte>.Empty, proofLength: 0, Sha256TwoToOne, BaseMemoryPool.Shared));
    }


    [TestMethod]
    public void AnOutOfRangePositionIsRejected()
    {
        int[] positions = [LeafCount];
        byte[] leaves = new byte[DigestSize];
        byte[] root = new byte[DigestSize];

        Assert.ThrowsExactly<ArgumentException>(() =>
            LongfellowMerkleTree.VerifyCompressedProof(LeafCount, root, leaves, positions, ReadOnlySpan<byte>.Empty, proofLength: 0, Sha256TwoToOne, BaseMemoryPool.Shared));
    }


    private static void Sha256TwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSize];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        SHA256.HashData(combined[..(left.Length + right.Length)], output);
    }
}

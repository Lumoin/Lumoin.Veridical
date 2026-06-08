using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Commitments.BaseFold;

/// <summary>
/// The canonical key-value set commitment (<see cref="MerkleSetCommitment"/>):
/// deterministic roots over equal sets, membership round-trips including the
/// zero-padded tail boundary, the strict ascending-key refusal, and rejection
/// of wrong values, wrong indices, and foreign roots. BLAKE3 two-to-one
/// throughout — the same delegate seam a Poseidon shadow root would plug.
/// </summary>
[TestClass]
internal sealed class MerkleSetCommitmentTests
{
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    private static readonly MerkleHashDelegate Hash = HashTwoToOne;


    [TestMethod]
    [DataRow(1)]
    [DataRow(4)]
    [DataRow(5)]  //Pads to 8: exercises the zero-padded tail.
    [DataRow(13)] //Pads to 16.
    public void MembershipRoundtripsForEveryEntry(int entryCount)
    {
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        using IMemoryOwner<byte> entriesOwner = pool.Rent(entryCount * 2 * DigestSizeBytes);
        Span<byte> entries = entriesOwner.Memory.Span[..(entryCount * 2 * DigestSizeBytes)];
        FillEntries(entries, entryCount, valueSalt: 7);

        using MerkleTree tree = MerkleSetCommitment.Commit(entries, entryCount, DigestSizeBytes, Hash, pool);

        for(int i = 0; i < entryCount; i++)
        {
            using MerkleAuthenticationPath path = MerkleSetCommitment.ProveMembership(tree, i, pool);
            ReadOnlySpan<byte> key = entries.Slice(i * 2 * DigestSizeBytes, DigestSizeBytes);
            ReadOnlySpan<byte> value = entries.Slice((i * 2 * DigestSizeBytes) + DigestSizeBytes, DigestSizeBytes);

            Assert.IsTrue(
                MerkleSetCommitment.VerifyMembership(tree.Root, i, key, value, path, Hash),
                $"Membership of entry {i} of {entryCount} must verify.");
        }
    }


    [TestMethod]
    public void EqualSetsCommitIdentically()
    {
        const int EntryCount = 6;
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        using IMemoryOwner<byte> entriesOwner = pool.Rent(EntryCount * 2 * DigestSizeBytes);
        Span<byte> entries = entriesOwner.Memory.Span[..(EntryCount * 2 * DigestSizeBytes)];
        FillEntries(entries, EntryCount, valueSalt: 7);

        using MerkleTree first = MerkleSetCommitment.Commit(entries, EntryCount, DigestSizeBytes, Hash, pool);
        using MerkleTree second = MerkleSetCommitment.Commit(entries, EntryCount, DigestSizeBytes, Hash, pool);

        Assert.IsTrue(
            first.Root.AsReadOnlySpan().SequenceEqual(second.Root.AsReadOnlySpan()),
            "The same canonical set must always produce the same root.");
    }


    [TestMethod]
    public void DifferentValueChangesTheRoot()
    {
        const int EntryCount = 6;
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        using IMemoryOwner<byte> entriesOwner = pool.Rent(EntryCount * 2 * DigestSizeBytes);
        Span<byte> entries = entriesOwner.Memory.Span[..(EntryCount * 2 * DigestSizeBytes)];

        FillEntries(entries, EntryCount, valueSalt: 7);
        using MerkleTree first = MerkleSetCommitment.Commit(entries, EntryCount, DigestSizeBytes, Hash, pool);

        FillEntries(entries, EntryCount, valueSalt: 8);
        using MerkleTree second = MerkleSetCommitment.Commit(entries, EntryCount, DigestSizeBytes, Hash, pool);

        Assert.IsFalse(
            first.Root.AsReadOnlySpan().SequenceEqual(second.Root.AsReadOnlySpan()),
            "A different value under the same keys must change the root.");
    }


    [TestMethod]
    public void UnsortedOrDuplicateKeysAreRefused()
    {
        const int EntryCount = 3;
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        using IMemoryOwner<byte> entriesOwner = pool.Rent(EntryCount * 2 * DigestSizeBytes);
        Memory<byte> entriesMemory = entriesOwner.Memory[..(EntryCount * 2 * DigestSizeBytes)];
        FillEntries(entriesMemory.Span, EntryCount, valueSalt: 7);

        //Swap the first two keys: descending order at entry 1.
        Span<byte> swap = stackalloc byte[DigestSizeBytes];
        entriesMemory.Span[..DigestSizeBytes].CopyTo(swap);
        entriesMemory.Span.Slice(2 * DigestSizeBytes, DigestSizeBytes).CopyTo(entriesMemory.Span[..DigestSizeBytes]);
        swap.CopyTo(entriesMemory.Span.Slice(2 * DigestSizeBytes, DigestSizeBytes));

        Assert.ThrowsExactly<ArgumentException>(() =>
            MerkleSetCommitment.Commit(entriesMemory.Span, EntryCount, DigestSizeBytes, Hash, SensitiveMemoryPool<byte>.Shared).Dispose());

        //Duplicate keys: copy entry 0's key into entry 1.
        FillEntries(entriesMemory.Span, EntryCount, valueSalt: 7);
        entriesMemory.Span[..DigestSizeBytes].CopyTo(entriesMemory.Span.Slice(2 * DigestSizeBytes, DigestSizeBytes));

        Assert.ThrowsExactly<ArgumentException>(() =>
            MerkleSetCommitment.Commit(entriesMemory.Span, EntryCount, DigestSizeBytes, Hash, SensitiveMemoryPool<byte>.Shared).Dispose());
    }


    [TestMethod]
    public void WrongValueWrongIndexAndForeignRootAreRejected()
    {
        const int EntryCount = 5;
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        using IMemoryOwner<byte> entriesOwner = pool.Rent(EntryCount * 2 * DigestSizeBytes);
        Span<byte> entries = entriesOwner.Memory.Span[..(EntryCount * 2 * DigestSizeBytes)];
        FillEntries(entries, EntryCount, valueSalt: 7);

        using MerkleTree tree = MerkleSetCommitment.Commit(entries, EntryCount, DigestSizeBytes, Hash, pool);

        const int EntryIndex = 2;
        using MerkleAuthenticationPath path = MerkleSetCommitment.ProveMembership(tree, EntryIndex, pool);
        ReadOnlySpan<byte> key = entries.Slice(EntryIndex * 2 * DigestSizeBytes, DigestSizeBytes);
        Span<byte> wrongValue = stackalloc byte[DigestSizeBytes];
        entries.Slice((EntryIndex * 2 * DigestSizeBytes) + DigestSizeBytes, DigestSizeBytes).CopyTo(wrongValue);
        wrongValue[0] ^= 0x01;

        Assert.IsFalse(
            MerkleSetCommitment.VerifyMembership(tree.Root, EntryIndex, key, wrongValue, path, Hash),
            "A different value under the proven key must be rejected.");

        ReadOnlySpan<byte> value = entries.Slice((EntryIndex * 2 * DigestSizeBytes) + DigestSizeBytes, DigestSizeBytes);
        Assert.IsFalse(
            MerkleSetCommitment.VerifyMembership(tree.Root, EntryIndex + 1, key, value, path, Hash),
            "The proof must be bound to its entry index.");

        //A root over a different set.
        FillEntries(entries, EntryCount, valueSalt: 9);
        using MerkleTree foreign = MerkleSetCommitment.Commit(entries, EntryCount, DigestSizeBytes, Hash, pool);
        Assert.IsFalse(
            MerkleSetCommitment.VerifyMembership(foreign.Root, EntryIndex, key, value, path, Hash),
            "A proof must not verify against a foreign root.");
    }


    //Entries with ascending keys derived from the index and values from a salt;
    //deterministic so equal-set comparisons are exact.
    private static void FillEntries(Span<byte> entries, int entryCount, int valueSalt)
    {
        Span<byte> material = stackalloc byte[8];
        for(int i = 0; i < entryCount; i++)
        {
            Span<byte> key = entries.Slice(i * 2 * DigestSizeBytes, DigestSizeBytes);
            Span<byte> value = entries.Slice((i * 2 * DigestSizeBytes) + DigestSizeBytes, DigestSizeBytes);

            material.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(material[..4], i);
            Blake3.Hash(material, key);
            //Force strict ascending order with an index prefix over the digest.
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(key[..4], i);

            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(material[..4], i);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(material[4..], valueSalt);
            Blake3.Hash(material, value);
        }
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }
}

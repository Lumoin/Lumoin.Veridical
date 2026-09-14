using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using System;
using System.Buffers;
using System.Collections.Generic;

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

    /// <summary>An entry is a key chunk followed by a value chunk, each one digest wide.</summary>
    private const int ChunksPerEntry = 2;

    private static MerkleHashDelegate Hash { get; } = HashTwoToOne;

    /// <summary>The pooled rentals, trees and paths a test opened, released together in cleanup.</summary>
    private List<IDisposable> Disposables { get; } = [];


    /// <summary>Disposes everything the test opened, in reverse order of acquisition.</summary>
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
    [DataRow(4)]
    [DataRow(5)]  //Pads to 8: exercises the zero-padded tail.
    [DataRow(13)] //Pads to 16.
    public void MembershipRoundtripsForEveryEntry(int entryCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> entriesOwner = pool.Rent(EntryCount * 2 * DigestSizeBytes);
        Memory<byte> entriesMemory = entriesOwner.Memory[..(EntryCount * 2 * DigestSizeBytes)];
        FillEntries(entriesMemory.Span, EntryCount, valueSalt: 7);

        //Swap the first two keys: descending order at entry 1.
        Span<byte> swap = stackalloc byte[DigestSizeBytes];
        entriesMemory.Span[..DigestSizeBytes].CopyTo(swap);
        entriesMemory.Span.Slice(2 * DigestSizeBytes, DigestSizeBytes).CopyTo(entriesMemory.Span[..DigestSizeBytes]);
        swap.CopyTo(entriesMemory.Span.Slice(2 * DigestSizeBytes, DigestSizeBytes));

        Assert.ThrowsExactly<ArgumentException>(() =>
            MerkleSetCommitment.Commit(entriesMemory.Span, EntryCount, DigestSizeBytes, Hash, BaseMemoryPool.Shared).Dispose());

        //Duplicate keys: copy entry 0's key into entry 1.
        FillEntries(entriesMemory.Span, EntryCount, valueSalt: 7);
        entriesMemory.Span[..DigestSizeBytes].CopyTo(entriesMemory.Span.Slice(2 * DigestSizeBytes, DigestSizeBytes));

        Assert.ThrowsExactly<ArgumentException>(() =>
            MerkleSetCommitment.Commit(entriesMemory.Span, EntryCount, DigestSizeBytes, Hash, BaseMemoryPool.Shared).Dispose());
    }


    [TestMethod]
    public void WrongValueWrongIndexAndForeignRootAreRejected()
    {
        const int EntryCount = 5;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
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


    /// <summary>
    /// The digest width is bounded by the widest node the Merkle surface can
    /// verify: at the cap a set commits and its tree carries that width; one
    /// byte past the cap the commitment is refused before any entry is read.
    /// Verification sizes its stack buffers against the cap, so a tree the
    /// surface could never authenticate must not be buildable.
    /// </summary>
    [TestMethod]
    public void CommitBoundsTheDigestWidthAtTheMerkleSurfaceCap()
    {
        //Two entries: the smallest set whose tree compresses at least once.
        const int EntryCount = 2;
        const int AtCapDigestSizeBytes = WellKnownMerkleHashParameters.MaximumDigestSizeBytes;
        const int PastCapDigestSizeBytes = WellKnownMerkleHashParameters.MaximumDigestSizeBytes + 1;
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> atCapOwner = pool.Rent(EntryCount * 2 * AtCapDigestSizeBytes);
        Span<byte> atCapEntries = atCapOwner.Memory.Span[..(EntryCount * 2 * AtCapDigestSizeBytes)];
        FillAscendingKeys(atCapEntries, EntryCount, AtCapDigestSizeBytes);

        using(MerkleTree tree = MerkleSetCommitment.Commit(atCapEntries, EntryCount, AtCapDigestSizeBytes, HashTwoToOneAtCap, pool))
        {
            Assert.AreEqual(AtCapDigestSizeBytes, tree.NodeSizeBytes, "An at-cap digest width must commit and carry that width.");
        }

        using IMemoryOwner<byte> pastCapOwner = pool.Rent(EntryCount * 2 * PastCapDigestSizeBytes);
        Memory<byte> pastCapEntries = pastCapOwner.Memory[..(EntryCount * 2 * PastCapDigestSizeBytes)];
        FillAscendingKeys(pastCapEntries.Span, EntryCount, PastCapDigestSizeBytes);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => MerkleSetCommitment.Commit(pastCapEntries.Span, EntryCount, PastCapDigestSizeBytes, HashTwoToOneAtCap, BaseMemoryPool.Shared).Dispose(),
            "A digest width past the Merkle surface's cap must be refused.");
    }


    /// <summary>
    /// An entries span that is not exactly <c>entryCount</c> whole key and value
    /// entries is refused with an <see cref="ArgumentException"/> on the
    /// <c>entries</c> parameter whose message names the received length. One
    /// entry followed by a stray byte is the shape only the length check catches:
    /// a single entry leaves no key pair to order, and the leaf hashing reads just
    /// the first two digests, so no later step would notice the stray byte.
    /// </summary>
    [TestMethod]
    public void CommitRefusesEntriesWhoseLengthIsNotTheEntryShape()
    {
        const int SingleEntryCount = 1;
        const int TrailingByteCount = 1;
        const int EntriesLengthBytes = (SingleEntryCount * ChunksPerEntry * DigestSizeBytes) + TrailingByteCount;
        const string EntriesParameterName = "entries";

        IMemoryOwner<byte> entriesOwner = Track(BaseMemoryPool.Shared.Rent(EntriesLengthBytes));
        Memory<byte> entries = entriesOwner.Memory[..EntriesLengthBytes];
        entries.Span.Clear();

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => MerkleSetCommitment.Commit(entries.Span, SingleEntryCount, DigestSizeBytes, Hash, BaseMemoryPool.Shared).Dispose(),
            "An entries span that is not a whole number of entries must be refused.");

        Assert.AreEqual(EntriesParameterName, thrown.ParamName, "The refusal must name the entries parameter.");
        Assert.Contains($"received {EntriesLengthBytes}.", thrown.Message, StringComparison.Ordinal,
            "The refusal must name the received length.");
    }


    /// <summary>
    /// A negative entry index is a malformed membership claim that the
    /// verification surface reports as a non-match instead of throwing. The same
    /// key, value, path and root verify at the proven index and report
    /// <see langword="false"/> at index <c>-1</c>; the key and value are one root
    /// width each, so the index is the only malformed input.
    /// </summary>
    [TestMethod]
    public void VerifyMembershipReportsANegativeEntryIndexAsANonMatch()
    {
        const int EntryCount = 2;
        const int ProvenIndex = 0;
        const int NegativeEntryIndex = -1;
        const int ValueSalt = 7;
        const int EntriesLengthBytes = EntryCount * ChunksPerEntry * DigestSizeBytes;
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        IMemoryOwner<byte> entriesOwner = Track(pool.Rent(EntriesLengthBytes));
        Span<byte> entries = entriesOwner.Memory.Span[..EntriesLengthBytes];
        FillEntries(entries, EntryCount, ValueSalt);

        MerkleTree tree = Track(MerkleSetCommitment.Commit(entries, EntryCount, DigestSizeBytes, Hash, pool));
        MerkleAuthenticationPath path = Track(MerkleSetCommitment.ProveMembership(tree, ProvenIndex, pool));
        ReadOnlySpan<byte> key = entries.Slice(ProvenIndex * ChunksPerEntry * DigestSizeBytes, DigestSizeBytes);
        ReadOnlySpan<byte> value = entries.Slice((ProvenIndex * ChunksPerEntry * DigestSizeBytes) + DigestSizeBytes, DigestSizeBytes);

        Assert.IsTrue(
            MerkleSetCommitment.VerifyMembership(tree.Root, ProvenIndex, key, value, path, Hash),
            "The claim must verify at the proven index, so only the index differs in the next check.");
        Assert.IsFalse(
            MerkleSetCommitment.VerifyMembership(tree.Root, NegativeEntryIndex, key, value, path, Hash),
            "A negative entry index must report as a non-match, not throw.");
    }


    /// <summary>
    /// A commitment taken without a compression is refused on the <c>hash</c>
    /// parameter. The compression is the first argument the commitment checks,
    /// and it has to be: a single all-zero entry satisfies the pool, the counts,
    /// the digest width, the entry length and the key order alike, so the
    /// compression would first be reached where the leaves are computed — past
    /// the point where a missing one can be reported as a caller fault.
    /// </summary>
    [TestMethod]
    public void CommitRefusesANullHash()
    {
        const int SingleEntryCount = 1;
        const int EntriesLengthBytes = SingleEntryCount * ChunksPerEntry * DigestSizeBytes;
        const string HashParameterName = "hash";

        IMemoryOwner<byte> entriesOwner = Track(BaseMemoryPool.Shared.Rent(EntriesLengthBytes));
        Memory<byte> entries = entriesOwner.Memory[..EntriesLengthBytes];
        entries.Span.Clear();

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => MerkleSetCommitment.Commit(entries.Span, SingleEntryCount, DigestSizeBytes, null!, BaseMemoryPool.Shared).Dispose(),
            "A commitment without a compression must be refused.");

        Assert.AreEqual(HashParameterName, thrown.ParamName, "The refusal must name the hash parameter.");
    }


    /// <summary>
    /// A commitment taken without a pool is refused on the <c>pool</c>
    /// parameter. Every check that follows passes for a single all-zero entry,
    /// so the pool would first be reached where the leaf buffer is rented — past
    /// the point where a missing pool can be reported as a caller fault.
    /// </summary>
    [TestMethod]
    public void CommitRefusesANullPool()
    {
        const int SingleEntryCount = 1;
        const int EntriesLengthBytes = SingleEntryCount * ChunksPerEntry * DigestSizeBytes;
        const string PoolParameterName = "pool";

        IMemoryOwner<byte> entriesOwner = Track(BaseMemoryPool.Shared.Rent(EntriesLengthBytes));
        Memory<byte> entries = entriesOwner.Memory[..EntriesLengthBytes];
        entries.Span.Clear();

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => MerkleSetCommitment.Commit(entries.Span, SingleEntryCount, DigestSizeBytes, Hash, null!).Dispose(),
            "A commitment without a pool must be refused.");

        Assert.AreEqual(PoolParameterName, thrown.ParamName, "The refusal must name the pool parameter.");
    }


    /// <summary>
    /// A set of no entries is refused on the <c>entryCount</c> parameter. An
    /// empty entries span is exactly zero entries wide and a count of zero
    /// leaves no key pair to order, so nothing downstream reports the empty set
    /// as such: the leaf layer comes out empty and the tree builder answers for
    /// its own leaf count instead of the count the caller supplied.
    /// </summary>
    [TestMethod]
    public void CommitRefusesAnEmptySet()
    {
        const int ZeroEntryCount = 0;
        const string EntryCountParameterName = "entryCount";

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => MerkleSetCommitment.Commit(ReadOnlySpan<byte>.Empty, ZeroEntryCount, DigestSizeBytes, Hash, BaseMemoryPool.Shared).Dispose(),
            "A set of no entries must be refused.");

        Assert.AreEqual(EntryCountParameterName, thrown.ParamName, "The refusal must name the entry count parameter.");
        Assert.AreEqual(ZeroEntryCount, thrown.ActualValue, "The refusal must carry the refused entry count.");
    }


    /// <summary>
    /// A zero digest width is refused on the <c>digestSizeBytes</c> parameter.
    /// A zero width makes an entry zero bytes wide, so the entry-length check
    /// accepts an empty span and a lone entry has no key order to violate: the
    /// width would next be answered by the node-width pairing the tree is built
    /// with, which names its own parameter rather than the caller's.
    /// </summary>
    [TestMethod]
    public void CommitRefusesAZeroDigestWidth()
    {
        const int SingleEntryCount = 1;
        const int ZeroDigestSizeBytes = 0;
        const string DigestSizeParameterName = "digestSizeBytes";

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => MerkleSetCommitment.Commit(ReadOnlySpan<byte>.Empty, SingleEntryCount, ZeroDigestSizeBytes, Hash, BaseMemoryPool.Shared).Dispose(),
            "A zero digest width must be refused.");

        Assert.AreEqual(DigestSizeParameterName, thrown.ParamName, "The refusal must name the digest size parameter.");
        Assert.AreEqual(ZeroDigestSizeBytes, thrown.ActualValue, "The refusal must carry the refused digest width.");
    }


    /// <summary>
    /// A digest width one byte past the Merkle surface's cap is refused on the
    /// <c>digestSizeBytes</c> parameter, carrying the width that was refused.
    /// The width has to be named by the width check itself: were the entries
    /// read first, the compression would fault on its own cap-sized buffers and
    /// report a range fault naming nothing the caller passed.
    /// </summary>
    [TestMethod]
    public void CommitRefusalNamesTheDigestWidthPastTheCap()
    {
        const int EntryCount = 2;
        const int PastCapDigestSizeBytes = WellKnownMerkleHashParameters.MaximumDigestSizeBytes + 1;
        const int EntriesLengthBytes = EntryCount * ChunksPerEntry * PastCapDigestSizeBytes;
        const string DigestSizeParameterName = "digestSizeBytes";

        IMemoryOwner<byte> entriesOwner = Track(BaseMemoryPool.Shared.Rent(EntriesLengthBytes));
        Memory<byte> entries = entriesOwner.Memory[..EntriesLengthBytes];
        FillAscendingKeys(entries.Span, EntryCount, PastCapDigestSizeBytes);

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => MerkleSetCommitment.Commit(entries.Span, EntryCount, PastCapDigestSizeBytes, HashTwoToOneAtCap, BaseMemoryPool.Shared).Dispose(),
            "A digest width past the Merkle surface's cap must be refused.");

        Assert.AreEqual(DigestSizeParameterName, thrown.ParamName, "The refusal must name the digest size parameter.");
        Assert.AreEqual(PastCapDigestSizeBytes, thrown.ActualValue, "The refusal must carry the refused digest width.");
    }


    /// <summary>
    /// A membership proof asked for without a tree is refused on the
    /// <c>tree</c> parameter even when the pool is missing as well. The tree is
    /// what the proof is drawn from, so it is checked first and its absence is
    /// what the caller is told about.
    /// </summary>
    [TestMethod]
    public void ProveMembershipRefusesANullTreeBeforeANullPool()
    {
        const int FirstEntryIndex = 0;
        const string TreeParameterName = "tree";

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => MerkleSetCommitment.ProveMembership(null!, FirstEntryIndex, null!).Dispose(),
            "A membership proof without a tree must be refused.");

        Assert.AreEqual(TreeParameterName, thrown.ParamName, "The tree is checked before the pool.");
    }


    /// <summary>
    /// A membership check without a root is refused on the <c>root</c>
    /// parameter. The root is the value every width in the claim is measured
    /// against, so its absence is a caller fault rather than a claim the surface
    /// could report as a non-match: there is nothing to measure against at all.
    /// </summary>
    [TestMethod]
    public void VerifyMembershipRefusesANullRoot()
    {
        const int EntryCount = 2;
        const int ProvenIndex = 0;
        const int ValueSalt = 7;
        const int EntriesLengthBytes = EntryCount * ChunksPerEntry * DigestSizeBytes;
        const string RootParameterName = "root";
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        IMemoryOwner<byte> entriesOwner = Track(pool.Rent(EntriesLengthBytes));
        Memory<byte> entries = entriesOwner.Memory[..EntriesLengthBytes];
        FillEntries(entries.Span, EntryCount, ValueSalt);

        MerkleTree tree = Track(MerkleSetCommitment.Commit(entries.Span, EntryCount, DigestSizeBytes, Hash, pool));
        MerkleAuthenticationPath path = Track(MerkleSetCommitment.ProveMembership(tree, ProvenIndex, pool));
        Memory<byte> key = entries.Slice(ProvenIndex * ChunksPerEntry * DigestSizeBytes, DigestSizeBytes);
        Memory<byte> value = entries.Slice((ProvenIndex * ChunksPerEntry * DigestSizeBytes) + DigestSizeBytes, DigestSizeBytes);

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => _ = MerkleSetCommitment.VerifyMembership(null!, ProvenIndex, key.Span, value.Span, path, Hash),
            "A membership check without a root must be refused.");

        Assert.AreEqual(RootParameterName, thrown.ParamName, "The refusal must name the root parameter.");
    }


    /// <summary>
    /// A membership check without a path is refused on the <c>path</c>
    /// parameter even when the claim is malformed in a way the surface would
    /// otherwise report as a non-match. A missing reference is a caller fault
    /// and is answered before any shape is inspected, so the negative index
    /// here — which is reported as a non-match when the path is present — does
    /// not get to answer first.
    /// </summary>
    [TestMethod]
    public void VerifyMembershipRefusesANullPathBeforeReportingANonMatch()
    {
        const int EntryCount = 2;
        const int ProvenIndex = 0;
        const int NegativeEntryIndex = -1;
        const int ValueSalt = 7;
        const int EntriesLengthBytes = EntryCount * ChunksPerEntry * DigestSizeBytes;
        const string PathParameterName = "path";
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        IMemoryOwner<byte> entriesOwner = Track(pool.Rent(EntriesLengthBytes));
        Memory<byte> entries = entriesOwner.Memory[..EntriesLengthBytes];
        FillEntries(entries.Span, EntryCount, ValueSalt);

        MerkleTree tree = Track(MerkleSetCommitment.Commit(entries.Span, EntryCount, DigestSizeBytes, Hash, pool));
        Memory<byte> key = entries.Slice(ProvenIndex * ChunksPerEntry * DigestSizeBytes, DigestSizeBytes);
        Memory<byte> value = entries.Slice((ProvenIndex * ChunksPerEntry * DigestSizeBytes) + DigestSizeBytes, DigestSizeBytes);

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => _ = MerkleSetCommitment.VerifyMembership(tree.Root, NegativeEntryIndex, key.Span, value.Span, null!, Hash),
            "A membership check without a path must be refused.");

        Assert.AreEqual(PathParameterName, thrown.ParamName, "The refusal must name the path parameter.");
    }


    /// <summary>
    /// A membership check without a compression is refused on the <c>hash</c>
    /// parameter. Every width in the claim is well formed, so the compression
    /// would first be reached where the leaf is recomputed — past the point
    /// where a missing one can be reported as a caller fault.
    /// </summary>
    [TestMethod]
    public void VerifyMembershipRefusesANullHash()
    {
        const int EntryCount = 2;
        const int ProvenIndex = 0;
        const int ValueSalt = 7;
        const int EntriesLengthBytes = EntryCount * ChunksPerEntry * DigestSizeBytes;
        const string HashParameterName = "hash";
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        IMemoryOwner<byte> entriesOwner = Track(pool.Rent(EntriesLengthBytes));
        Memory<byte> entries = entriesOwner.Memory[..EntriesLengthBytes];
        FillEntries(entries.Span, EntryCount, ValueSalt);

        MerkleTree tree = Track(MerkleSetCommitment.Commit(entries.Span, EntryCount, DigestSizeBytes, Hash, pool));
        MerkleAuthenticationPath path = Track(MerkleSetCommitment.ProveMembership(tree, ProvenIndex, pool));
        Memory<byte> key = entries.Slice(ProvenIndex * ChunksPerEntry * DigestSizeBytes, DigestSizeBytes);
        Memory<byte> value = entries.Slice((ProvenIndex * ChunksPerEntry * DigestSizeBytes) + DigestSizeBytes, DigestSizeBytes);

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => _ = MerkleSetCommitment.VerifyMembership(tree.Root, ProvenIndex, key.Span, value.Span, path, null!),
            "A membership check without a compression must be refused.");

        Assert.AreEqual(HashParameterName, thrown.ParamName, "The refusal must name the hash parameter.");
    }


    /// <summary>
    /// A value narrower than the committed root reports as a non-match even
    /// when the committed leaf really is the compression of that key and that
    /// narrow value. Key and value are each measured against the root width on
    /// their own, so a key of exactly root width does not excuse a value one
    /// byte short; the control check first shows the path authenticates
    /// precisely that leaf, so only the refused width separates the two results.
    /// </summary>
    [TestMethod]
    public void VerifyMembershipReportsAValueNarrowerThanTheRootAsANonMatch()
    {
        const int LeafCount = 2;
        const int ProvenIndex = 0;
        const int SingleEntryCount = 1;
        const int ValueSalt = 7;
        const int ShortValueLengthBytes = DigestSizeBytes - 1;
        const int EntryLengthBytes = SingleEntryCount * ChunksPerEntry * DigestSizeBytes;
        const int LeavesLengthBytes = LeafCount * DigestSizeBytes;
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        IMemoryOwner<byte> entryOwner = Track(pool.Rent(EntryLengthBytes));
        Span<byte> entry = entryOwner.Memory.Span[..EntryLengthBytes];
        FillEntries(entry, SingleEntryCount, ValueSalt);
        ReadOnlySpan<byte> key = entry[..DigestSizeBytes];
        ReadOnlySpan<byte> shortValue = entry.Slice(DigestSizeBytes, ShortValueLengthBytes);

        //The committed leaf is the compression of the key and the narrow value,
        //so nothing but the width check can separate the claim from the tree.
        IMemoryOwner<byte> leavesOwner = Track(pool.Rent(LeavesLengthBytes));
        Span<byte> leaves = leavesOwner.Memory.Span[..LeavesLengthBytes];
        leaves.Clear();
        Hash(key, shortValue, leaves[..DigestSizeBytes]);

        MerkleTree tree = Track(MerkleTree.Build(leaves, LeafCount, new MerkleCommitmentParameters(Hash, DigestSizeBytes), pool));
        MerkleAuthenticationPath path = Track(tree.BuildPath(ProvenIndex, pool));

        Assert.IsTrue(
            path.Verify(tree.Root, ProvenIndex, leaves[..DigestSizeBytes], Hash),
            "The path must authenticate exactly the leaf built from the key and the narrow value.");
        Assert.IsFalse(
            MerkleSetCommitment.VerifyMembership(tree.Root, ProvenIndex, key, shortValue, path, Hash),
            "A value narrower than the root must report as a non-match.");
    }


    /// <summary>
    /// A membership claim whose digest width is exactly the Merkle surface's
    /// cap verifies. The cap is the widest node the verification stack reserves
    /// room for, and that width is admitted rather than refused: a set the
    /// commitment surface accepts at the cap must stay openable by the very
    /// surface that committed it.
    /// </summary>
    [TestMethod]
    public void VerifyMembershipAcceptsAnAtCapDigestWidth()
    {
        const int EntryCount = 2;
        const int ProvenIndex = 0;
        const int AtCapDigestSizeBytes = WellKnownMerkleHashParameters.MaximumDigestSizeBytes;
        const int EntriesLengthBytes = EntryCount * ChunksPerEntry * AtCapDigestSizeBytes;
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        IMemoryOwner<byte> entriesOwner = Track(pool.Rent(EntriesLengthBytes));
        Span<byte> entries = entriesOwner.Memory.Span[..EntriesLengthBytes];
        FillAscendingKeys(entries, EntryCount, AtCapDigestSizeBytes);

        MerkleTree tree = Track(MerkleSetCommitment.Commit(entries, EntryCount, AtCapDigestSizeBytes, HashTwoToOneAtCap, pool));
        MerkleAuthenticationPath path = Track(MerkleSetCommitment.ProveMembership(tree, ProvenIndex, pool));
        ReadOnlySpan<byte> key = entries.Slice(ProvenIndex * ChunksPerEntry * AtCapDigestSizeBytes, AtCapDigestSizeBytes);
        ReadOnlySpan<byte> value = entries.Slice((ProvenIndex * ChunksPerEntry * AtCapDigestSizeBytes) + AtCapDigestSizeBytes, AtCapDigestSizeBytes);

        Assert.IsTrue(
            MerkleSetCommitment.VerifyMembership(tree.Root, ProvenIndex, key, value, path, HashTwoToOneAtCap),
            "A membership claim at the cap digest width must verify.");
    }


    /// <summary>
    /// A key that descends after an ascending pair is refused on the
    /// <c>entries</c> parameter, and the refusal states the ascending-order rule
    /// and names the first entry that breaks it. Each key is compared with its
    /// immediate predecessor, not with the smallest key: here key 0 is below
    /// both later keys, so the only way to see the violation is to compare
    /// entry 2 against entry 1.
    /// </summary>
    [TestMethod]
    public void CommitRefusalNamesTheFirstEntryWhoseKeyDescends()
    {
        const int EntryCount = 3;
        const int ValueSalt = 7;
        const int SecondEntryIndex = 1;
        const int ThirdEntryIndex = 2;
        const int EntriesLengthBytes = EntryCount * ChunksPerEntry * DigestSizeBytes;
        const string EntriesParameterName = "entries";
        const string AscendingRuleFragment = "strictly ascending";

        IMemoryOwner<byte> entriesOwner = Track(BaseMemoryPool.Shared.Rent(EntriesLengthBytes));
        Memory<byte> entries = entriesOwner.Memory[..EntriesLengthBytes];
        FillEntries(entries.Span, EntryCount, ValueSalt);

        //Exchange the keys of entries 1 and 2, so the keys read low, high,
        //middle and the first ascending pair is still in order.
        Span<byte> swap = stackalloc byte[DigestSizeBytes];
        Span<byte> secondKey = entries.Span.Slice(SecondEntryIndex * ChunksPerEntry * DigestSizeBytes, DigestSizeBytes);
        Span<byte> thirdKey = entries.Span.Slice(ThirdEntryIndex * ChunksPerEntry * DigestSizeBytes, DigestSizeBytes);
        secondKey.CopyTo(swap);
        thirdKey.CopyTo(secondKey);
        swap.CopyTo(thirdKey);

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => MerkleSetCommitment.Commit(entries.Span, EntryCount, DigestSizeBytes, Hash, BaseMemoryPool.Shared).Dispose(),
            "A key that descends after an ascending pair must be refused.");

        Assert.AreEqual(EntriesParameterName, thrown.ParamName, "The refusal must name the entries parameter.");
        Assert.Contains(AscendingRuleFragment, thrown.Message, StringComparison.Ordinal,
            "The refusal must state the ascending-order rule.");
        Assert.Contains($"violated at entry {ThirdEntryIndex}.", thrown.Message, StringComparison.Ordinal,
            "The refusal must name the first entry whose key descends.");
    }


    /// <summary>
    /// Entries with ascending keys derived from the index and values from a
    /// salt; deterministic so equal-set comparisons are exact.
    /// </summary>
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


    /// <summary>
    /// The wired two-to-one compression: BLAKE3 over the concatenated
    /// children at the default 32-byte pairing.
    /// </summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>
    /// Zeroed entries carrying an index-prefixed key each: strictly ascending
    /// keys at any digest width, which is all the shape checks require.
    /// </summary>
    private static void FillAscendingKeys(Span<byte> entries, int entryCount, int digestSizeBytes)
    {
        entries.Clear();
        for(int i = 0; i < entryCount; i++)
        {
            Span<byte> key = entries.Slice(i * 2 * digestSizeBytes, digestSizeBytes);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(key[..4], i + 1);
        }
    }


    /// <summary>
    /// The at-cap two-to-one compression: BLAKE3 buffered for the widest node
    /// the Merkle surface admits and sliced to the actual input widths,
    /// because the class's default compression is sized for the wired
    /// 32-byte pairing.
    /// </summary>
    private static void HashTwoToOneAtCap(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * WellKnownMerkleHashParameters.MaximumDigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    /// <summary>
    /// Registers a disposable for release in <see cref="DisposeRentals"/> and
    /// returns it, so a test body holds its rentals without using declarations.
    /// </summary>
    private T Track<T>(T disposable) where T : IDisposable
    {
        Disposables.Add(disposable);

        return disposable;
    }
}

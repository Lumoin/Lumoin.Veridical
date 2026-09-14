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
    /// <summary>The default Merkle digest width, so ordinary fixtures use the library's wired hash pairing.</summary>
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    /// <summary>An entry is a key chunk followed by a value chunk, each one digest wide.</summary>
    private const int ChunksPerEntry = 2;

    /// <summary>The byte width of a complete key-value entry, so slices preserve both digest-sized chunks.</summary>
    private const int EntrySizeBytes = ChunksPerEntry * DigestSizeBytes;

    /// <summary>One entry exercises the tree with no sibling path and isolates argument guards from key ordering.</summary>
    private const int SingleEntryCount = 1;

    /// <summary>Two entries are the smallest set with an internal tree node and a nonempty authentication path.</summary>
    private const int PairedEntryCount = 2;

    /// <summary>Three entries let ordering checks distinguish the first key pair from a later descending pair.</summary>
    private const int OrderingEntryCount = 3;

    /// <summary>Four entries fill a complete tree, exercising membership without padding.</summary>
    private const int CompleteEntryCount = 4;

    /// <summary>Five entries require padding to eight leaves and leave an interior entry available for altered claims.</summary>
    private const int PaddedEntryCount = 5;

    /// <summary>Six entries give root comparisons a multi-level tree with a padded tail.</summary>
    private const int RootComparisonEntryCount = 6;

    /// <summary>Thirteen entries require padding to sixteen leaves, exercising a deeper padded authentication path.</summary>
    private const int LargerPaddedEntryCount = 13;

    /// <summary>A zero entry count exercises the boundary below the smallest admissible set.</summary>
    private const int ZeroEntryCount = 0;

    /// <summary>The first entry index is zero because membership paths address entries from the start of the set.</summary>
    private const int FirstEntryIndex = 0;

    /// <summary>The second entry index follows the first key, so it locates the first possible ordering violation.</summary>
    private const int SecondEntryIndex = FirstEntryIndex + 1;

    /// <summary>The third entry provides an interior claim and a key after the first ascending pair.</summary>
    private const int ThirdEntryIndex = SecondEntryIndex + 1;

    /// <summary>The fourth entry is adjacent to the proven third entry, isolating the claim's index binding.</summary>
    private const int FourthEntryIndex = ThirdEntryIndex + 1;

    /// <summary>Minus one is immediately below the valid index range, isolating the negative-index guard.</summary>
    private const int NegativeEntryIndex = -1;

    /// <summary>Seven gives ordinary fixtures a deterministic nonzero value salt while leaving keys independent of values.</summary>
    private const int ValueSalt = 7;

    /// <summary>Eight differs from the ordinary salt by one, changing values while preserving their keys.</summary>
    private const int DifferentValueSalt = ValueSalt + 1;

    /// <summary>Nine gives a foreign set a third deterministic value salt under the same keys.</summary>
    private const int ForeignValueSalt = DifferentValueSalt + 1;

    /// <summary>One byte is the smallest trailing fragment that makes a whole entry's length malformed.</summary>
    private const int TrailingByteCount = 1;

    /// <summary>The malformed entry includes exactly one stray byte, isolating the entry-length check.</summary>
    private const int MalformedEntrySizeBytes = EntrySizeBytes + TrailingByteCount;

    /// <summary>The paired fixture occupies two whole entries, so its shape passes before argument and claim checks run.</summary>
    private const int PairedEntriesSizeBytes = PairedEntryCount * EntrySizeBytes;

    /// <summary>The ordering fixture occupies three whole entries, leaving key order as its only malformed feature.</summary>
    private const int OrderingEntriesSizeBytes = OrderingEntryCount * EntrySizeBytes;

    /// <summary>Zero digest bytes exercises the boundary below every supported Merkle node width.</summary>
    private const int ZeroDigestSizeBytes = 0;

    /// <summary>The maximum Merkle digest width exercises the inclusive upper width boundary.</summary>
    private const int AtCapDigestSizeBytes = WellKnownMerkleHashParameters.MaximumDigestSizeBytes;

    /// <summary>A one-byte difference selects the nearest invalid value width and the nearest over-cap digest width.</summary>
    private const int DigestWidthDifferenceBytes = 1;

    /// <summary>One byte beyond the Merkle cap isolates the upper width guard before entries are read.</summary>
    private const int PastCapDigestSizeBytes = AtCapDigestSizeBytes + DigestWidthDifferenceBytes;

    /// <summary>Two complete at-cap entries let membership exercise an internal node at the widest supported width.</summary>
    private const int AtCapEntriesSizeBytes = PairedEntryCount * ChunksPerEntry * AtCapDigestSizeBytes;

    /// <summary>Two complete over-cap entries satisfy the entry shape, leaving only their unsupported digest width.</summary>
    private const int PastCapEntriesSizeBytes = PairedEntryCount * ChunksPerEntry * PastCapDigestSizeBytes;

    /// <summary>A value one byte narrower than its root isolates the value-width check from the key width.</summary>
    private const int ShortValueLengthBytes = DigestSizeBytes - DigestWidthDifferenceBytes;

    /// <summary>Two leaves are the smallest tree that authenticates the deliberately narrow-value compression through a sibling.</summary>
    private const int NarrowValueLeafCount = 2;

    /// <summary>The narrow-value fixture reserves one full digest per leaf so only the claimed value is undersized.</summary>
    private const int NarrowValueLeavesSizeBytes = NarrowValueLeafCount * DigestSizeBytes;

    /// <summary>The first value byte is at offset zero, so a single mutation stays within every ordinary digest.</summary>
    private const int ChangedValueByteOffset = 0;

    /// <summary>A one-bit mask changes the proven value without changing its width.</summary>
    private const byte ChangedValueBitMask = 0x01;

    /// <summary>The index occupies a signed 32-bit encoding because the fixture writes indices with WriteInt32BigEndian.</summary>
    private const int IndexEncodingSizeBytes = sizeof(int);

    /// <summary>The salt occupies a signed 32-bit encoding because the fixture writes salts with WriteInt32BigEndian.</summary>
    private const int SaltEncodingSizeBytes = sizeof(int);

    /// <summary>The salt follows the complete index encoding, keeping the two deterministic hash inputs disjoint.</summary>
    private const int SaltEncodingOffsetBytes = IndexEncodingSizeBytes;

    /// <summary>Hash material holds one index and one salt encoding, including the zero salt used for keys.</summary>
    private const int EntryMaterialSizeBytes = IndexEncodingSizeBytes + SaltEncodingSizeBytes;

    /// <summary>Starting at one gives the arbitrary-width key fixture nonzero ascending prefixes.</summary>
    private const int FirstKeyPrefix = 1;

    /// <summary>Merkle compression combines exactly two child digests into their parent.</summary>
    private const int ChildrenPerParent = 2;

    /// <summary>The malformed entry shape and key ordering guards identify their entries input by this parameter name.</summary>
    private const string EntriesParameterName = "entries";

    /// <summary>The missing compression guard identifies its hash input by this parameter name.</summary>
    private const string HashParameterName = "hash";

    /// <summary>The missing memory pool guard identifies its pool input by this parameter name.</summary>
    private const string PoolParameterName = "pool";

    /// <summary>The empty-set guard identifies its count input by this parameter name.</summary>
    private const string EntryCountParameterName = "entryCount";

    /// <summary>The digest-width guards identify their width input by this parameter name.</summary>
    private const string DigestSizeParameterName = "digestSizeBytes";

    /// <summary>The missing-tree guard identifies its tree input by this parameter name.</summary>
    private const string TreeParameterName = "tree";

    /// <summary>The missing-root guard identifies its root input by this parameter name.</summary>
    private const string RootParameterName = "root";

    /// <summary>The missing-path guard identifies its path input by this parameter name.</summary>
    private const string PathParameterName = "path";

    /// <summary>The ordering refusal states this rule, distinguishing it from other malformed-entry refusals.</summary>
    private const string AscendingRuleFragment = "strictly ascending";

    /// <summary>The BLAKE3 two-to-one compression used by the ordinary-width set fixtures.</summary>
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


    /// <summary>Every canonical entry authenticates in singleton, complete and padded trees, including each populated tail entry.</summary>
    [TestMethod]
    [DataRow(SingleEntryCount)]
    [DataRow(CompleteEntryCount)]
    [DataRow(PaddedEntryCount)]
    [DataRow(LargerPaddedEntryCount)]
    public void MembershipRoundtripsForEveryEntry(int entryCount)
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> entriesOwner = pool.Rent(entryCount * EntrySizeBytes);
        Span<byte> entries = entriesOwner.Memory.Span[..(entryCount * EntrySizeBytes)];
        FillEntries(entries, entryCount, valueSalt: ValueSalt);

        using MerkleTree tree = MerkleSetCommitment.Commit(entries, entryCount, DigestSizeBytes, Hash, pool);

        for(int i = 0; i < entryCount; i++)
        {
            using MerkleAuthenticationPath path = MerkleSetCommitment.ProveMembership(tree, i, pool);
            ReadOnlySpan<byte> key = entries.Slice(i * EntrySizeBytes, DigestSizeBytes);
            ReadOnlySpan<byte> value = entries.Slice((i * EntrySizeBytes) + DigestSizeBytes, DigestSizeBytes);

            Assert.IsTrue(
                MerkleSetCommitment.VerifyMembership(tree.Root, i, key, value, path, Hash),
                $"Membership of entry {i} of {entryCount} must verify.");
        }
    }


    /// <summary>Repeated commitments to the same canonical set produce identical roots.</summary>
    [TestMethod]
    public void EqualSetsCommitIdentically()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> entriesOwner = pool.Rent(RootComparisonEntryCount * EntrySizeBytes);
        Span<byte> entries = entriesOwner.Memory.Span[..(RootComparisonEntryCount * EntrySizeBytes)];
        FillEntries(entries, RootComparisonEntryCount, valueSalt: ValueSalt);

        using MerkleTree first = MerkleSetCommitment.Commit(entries, RootComparisonEntryCount, DigestSizeBytes, Hash, pool);
        using MerkleTree second = MerkleSetCommitment.Commit(entries, RootComparisonEntryCount, DigestSizeBytes, Hash, pool);

        Assert.IsTrue(
            first.Root.AsReadOnlySpan().SequenceEqual(second.Root.AsReadOnlySpan()),
            "The same canonical set must always produce the same root.");
    }


    /// <summary>Changing values under an unchanged ordered key set changes the commitment root.</summary>
    [TestMethod]
    public void DifferentValueChangesTheRoot()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> entriesOwner = pool.Rent(RootComparisonEntryCount * EntrySizeBytes);
        Span<byte> entries = entriesOwner.Memory.Span[..(RootComparisonEntryCount * EntrySizeBytes)];

        FillEntries(entries, RootComparisonEntryCount, valueSalt: ValueSalt);
        using MerkleTree first = MerkleSetCommitment.Commit(entries, RootComparisonEntryCount, DigestSizeBytes, Hash, pool);

        FillEntries(entries, RootComparisonEntryCount, valueSalt: DifferentValueSalt);
        using MerkleTree second = MerkleSetCommitment.Commit(entries, RootComparisonEntryCount, DigestSizeBytes, Hash, pool);

        Assert.IsFalse(
            first.Root.AsReadOnlySpan().SequenceEqual(second.Root.AsReadOnlySpan()),
            "A different value under the same keys must change the root.");
    }


    /// <summary>A descending or duplicate adjacent key prevents a canonical set commitment.</summary>
    [TestMethod]
    public void UnsortedOrDuplicateKeysAreRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> entriesOwner = pool.Rent(OrderingEntriesSizeBytes);
        Memory<byte> entriesMemory = entriesOwner.Memory[..OrderingEntriesSizeBytes];
        FillEntries(entriesMemory.Span, OrderingEntryCount, valueSalt: ValueSalt);

        //Swap the first two keys: descending order at entry 1.
        Span<byte> swap = stackalloc byte[DigestSizeBytes];
        entriesMemory.Span[..DigestSizeBytes].CopyTo(swap);
        entriesMemory.Span.Slice(SecondEntryIndex * EntrySizeBytes, DigestSizeBytes).CopyTo(entriesMemory.Span[..DigestSizeBytes]);
        swap.CopyTo(entriesMemory.Span.Slice(SecondEntryIndex * EntrySizeBytes, DigestSizeBytes));

        Assert.ThrowsExactly<ArgumentException>(() =>
            MerkleSetCommitment.Commit(entriesMemory.Span, OrderingEntryCount, DigestSizeBytes, Hash, BaseMemoryPool.Shared).Dispose());

        //Duplicate keys: copy entry 0's key into entry 1.
        FillEntries(entriesMemory.Span, OrderingEntryCount, valueSalt: ValueSalt);
        entriesMemory.Span[..DigestSizeBytes].CopyTo(entriesMemory.Span.Slice(SecondEntryIndex * EntrySizeBytes, DigestSizeBytes));

        Assert.ThrowsExactly<ArgumentException>(() =>
            MerkleSetCommitment.Commit(entriesMemory.Span, OrderingEntryCount, DigestSizeBytes, Hash, BaseMemoryPool.Shared).Dispose());
    }


    /// <summary>A membership proof binds the claimed value, entry index and commitment root.</summary>
    [TestMethod]
    public void WrongValueWrongIndexAndForeignRootAreRejected()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> entriesOwner = pool.Rent(PaddedEntryCount * EntrySizeBytes);
        Span<byte> entries = entriesOwner.Memory.Span[..(PaddedEntryCount * EntrySizeBytes)];
        FillEntries(entries, PaddedEntryCount, valueSalt: ValueSalt);

        using MerkleTree tree = MerkleSetCommitment.Commit(entries, PaddedEntryCount, DigestSizeBytes, Hash, pool);

        using MerkleAuthenticationPath path = MerkleSetCommitment.ProveMembership(tree, ThirdEntryIndex, pool);
        ReadOnlySpan<byte> key = entries.Slice(ThirdEntryIndex * EntrySizeBytes, DigestSizeBytes);
        Span<byte> wrongValue = stackalloc byte[DigestSizeBytes];
        entries.Slice((ThirdEntryIndex * EntrySizeBytes) + DigestSizeBytes, DigestSizeBytes).CopyTo(wrongValue);
        wrongValue[ChangedValueByteOffset] ^= ChangedValueBitMask;

        Assert.IsFalse(
            MerkleSetCommitment.VerifyMembership(tree.Root, ThirdEntryIndex, key, wrongValue, path, Hash),
            "A different value under the proven key must be rejected.");

        ReadOnlySpan<byte> value = entries.Slice((ThirdEntryIndex * EntrySizeBytes) + DigestSizeBytes, DigestSizeBytes);
        Assert.IsFalse(
            MerkleSetCommitment.VerifyMembership(tree.Root, FourthEntryIndex, key, value, path, Hash),
            "The proof must be bound to its entry index.");

        //A different value salt produces a foreign root under the same keys.
        FillEntries(entries, PaddedEntryCount, valueSalt: ForeignValueSalt);
        using MerkleTree foreign = MerkleSetCommitment.Commit(entries, PaddedEntryCount, DigestSizeBytes, Hash, pool);
        Assert.IsFalse(
            MerkleSetCommitment.VerifyMembership(foreign.Root, ThirdEntryIndex, key, value, path, Hash),
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        using IMemoryOwner<byte> atCapOwner = pool.Rent(AtCapEntriesSizeBytes);
        Span<byte> atCapEntries = atCapOwner.Memory.Span[..AtCapEntriesSizeBytes];
        FillAscendingKeys(atCapEntries, PairedEntryCount, AtCapDigestSizeBytes);

        using(MerkleTree tree = MerkleSetCommitment.Commit(atCapEntries, PairedEntryCount, AtCapDigestSizeBytes, HashTwoToOneAtCap, pool))
        {
            Assert.AreEqual(AtCapDigestSizeBytes, tree.NodeSizeBytes, "An at-cap digest width must commit and carry that width.");
        }

        using IMemoryOwner<byte> pastCapOwner = pool.Rent(PastCapEntriesSizeBytes);
        Memory<byte> pastCapEntries = pastCapOwner.Memory[..PastCapEntriesSizeBytes];
        FillAscendingKeys(pastCapEntries.Span, PairedEntryCount, PastCapDigestSizeBytes);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => MerkleSetCommitment.Commit(pastCapEntries.Span, PairedEntryCount, PastCapDigestSizeBytes, HashTwoToOneAtCap, BaseMemoryPool.Shared).Dispose(),
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
        IMemoryOwner<byte> entriesOwner = Track(BaseMemoryPool.Shared.Rent(MalformedEntrySizeBytes));
        Memory<byte> entries = entriesOwner.Memory[..MalformedEntrySizeBytes];
        entries.Span.Clear();

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => MerkleSetCommitment.Commit(entries.Span, SingleEntryCount, DigestSizeBytes, Hash, BaseMemoryPool.Shared).Dispose(),
            "An entries span that is not a whole number of entries must be refused.");

        Assert.AreEqual(EntriesParameterName, thrown.ParamName, "The refusal must name the entries parameter.");
        Assert.Contains($"received {MalformedEntrySizeBytes}.", thrown.Message, StringComparison.Ordinal,
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        IMemoryOwner<byte> entriesOwner = Track(pool.Rent(PairedEntriesSizeBytes));
        Span<byte> entries = entriesOwner.Memory.Span[..PairedEntriesSizeBytes];
        FillEntries(entries, PairedEntryCount, ValueSalt);

        MerkleTree tree = Track(MerkleSetCommitment.Commit(entries, PairedEntryCount, DigestSizeBytes, Hash, pool));
        MerkleAuthenticationPath path = Track(MerkleSetCommitment.ProveMembership(tree, FirstEntryIndex, pool));
        ReadOnlySpan<byte> key = entries.Slice(FirstEntryIndex * EntrySizeBytes, DigestSizeBytes);
        ReadOnlySpan<byte> value = entries.Slice((FirstEntryIndex * EntrySizeBytes) + DigestSizeBytes, DigestSizeBytes);

        Assert.IsTrue(
            MerkleSetCommitment.VerifyMembership(tree.Root, FirstEntryIndex, key, value, path, Hash),
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
        IMemoryOwner<byte> entriesOwner = Track(BaseMemoryPool.Shared.Rent(EntrySizeBytes));
        Memory<byte> entries = entriesOwner.Memory[..EntrySizeBytes];
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
        IMemoryOwner<byte> entriesOwner = Track(BaseMemoryPool.Shared.Rent(EntrySizeBytes));
        Memory<byte> entries = entriesOwner.Memory[..EntrySizeBytes];
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
        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => MerkleSetCommitment.Commit(ReadOnlySpan<byte>.Empty, SingleEntryCount, ZeroDigestSizeBytes, Hash, BaseMemoryPool.Shared).Dispose(),
            "A zero digest width must be refused.");

        Assert.AreEqual(DigestSizeParameterName, thrown.ParamName, "The refusal must name the digest size parameter.");
        Assert.AreEqual(ZeroDigestSizeBytes, thrown.ActualValue, "The refusal must carry the refused digest width.");
    }


    /// <summary>
    /// A digest width one byte past the Merkle surface's cap is refused on the
    /// <c>digestSizeBytes</c> parameter, carrying the refused width.
    /// The width has to be named by the width check itself: were the entries
    /// read first, the compression would fault on its own cap-sized buffers and
    /// report a range fault naming nothing the caller passed.
    /// </summary>
    [TestMethod]
    public void CommitRefusalNamesTheDigestWidthPastTheCap()
    {
        IMemoryOwner<byte> entriesOwner = Track(BaseMemoryPool.Shared.Rent(PastCapEntriesSizeBytes));
        Memory<byte> entries = entriesOwner.Memory[..PastCapEntriesSizeBytes];
        FillAscendingKeys(entries.Span, PairedEntryCount, PastCapDigestSizeBytes);

        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => MerkleSetCommitment.Commit(entries.Span, PairedEntryCount, PastCapDigestSizeBytes, HashTwoToOneAtCap, BaseMemoryPool.Shared).Dispose(),
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        IMemoryOwner<byte> entriesOwner = Track(pool.Rent(PairedEntriesSizeBytes));
        Memory<byte> entries = entriesOwner.Memory[..PairedEntriesSizeBytes];
        FillEntries(entries.Span, PairedEntryCount, ValueSalt);

        MerkleTree tree = Track(MerkleSetCommitment.Commit(entries.Span, PairedEntryCount, DigestSizeBytes, Hash, pool));
        MerkleAuthenticationPath path = Track(MerkleSetCommitment.ProveMembership(tree, FirstEntryIndex, pool));
        Memory<byte> key = entries.Slice(FirstEntryIndex * EntrySizeBytes, DigestSizeBytes);
        Memory<byte> value = entries.Slice((FirstEntryIndex * EntrySizeBytes) + DigestSizeBytes, DigestSizeBytes);

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => _ = MerkleSetCommitment.VerifyMembership(null!, FirstEntryIndex, key.Span, value.Span, path, Hash),
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        IMemoryOwner<byte> entriesOwner = Track(pool.Rent(PairedEntriesSizeBytes));
        Memory<byte> entries = entriesOwner.Memory[..PairedEntriesSizeBytes];
        FillEntries(entries.Span, PairedEntryCount, ValueSalt);

        MerkleTree tree = Track(MerkleSetCommitment.Commit(entries.Span, PairedEntryCount, DigestSizeBytes, Hash, pool));
        Memory<byte> key = entries.Slice(FirstEntryIndex * EntrySizeBytes, DigestSizeBytes);
        Memory<byte> value = entries.Slice((FirstEntryIndex * EntrySizeBytes) + DigestSizeBytes, DigestSizeBytes);

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
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        IMemoryOwner<byte> entriesOwner = Track(pool.Rent(PairedEntriesSizeBytes));
        Memory<byte> entries = entriesOwner.Memory[..PairedEntriesSizeBytes];
        FillEntries(entries.Span, PairedEntryCount, ValueSalt);

        MerkleTree tree = Track(MerkleSetCommitment.Commit(entries.Span, PairedEntryCount, DigestSizeBytes, Hash, pool));
        MerkleAuthenticationPath path = Track(MerkleSetCommitment.ProveMembership(tree, FirstEntryIndex, pool));
        Memory<byte> key = entries.Slice(FirstEntryIndex * EntrySizeBytes, DigestSizeBytes);
        Memory<byte> value = entries.Slice((FirstEntryIndex * EntrySizeBytes) + DigestSizeBytes, DigestSizeBytes);

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(
            () => _ = MerkleSetCommitment.VerifyMembership(tree.Root, FirstEntryIndex, key.Span, value.Span, path, null!),
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        IMemoryOwner<byte> entryOwner = Track(pool.Rent(EntrySizeBytes));
        Span<byte> entry = entryOwner.Memory.Span[..EntrySizeBytes];
        FillEntries(entry, SingleEntryCount, ValueSalt);
        ReadOnlySpan<byte> key = entry[..DigestSizeBytes];
        ReadOnlySpan<byte> shortValue = entry.Slice(DigestSizeBytes, ShortValueLengthBytes);

        //The committed leaf is the compression of the key and the narrow value,
        //so nothing but the width check can separate the claim from the tree.
        IMemoryOwner<byte> leavesOwner = Track(pool.Rent(NarrowValueLeavesSizeBytes));
        Span<byte> leaves = leavesOwner.Memory.Span[..NarrowValueLeavesSizeBytes];
        leaves.Clear();
        Hash(key, shortValue, leaves[..DigestSizeBytes]);

        MerkleTree tree = Track(MerkleTree.Build(leaves, NarrowValueLeafCount, new MerkleCommitmentParameters(Hash, DigestSizeBytes), pool));
        MerkleAuthenticationPath path = Track(tree.BuildPath(FirstEntryIndex, pool));

        Assert.IsTrue(
            path.Verify(tree.Root, FirstEntryIndex, leaves[..DigestSizeBytes], Hash),
            "The path must authenticate exactly the leaf built from the key and the narrow value.");
        Assert.IsFalse(
            MerkleSetCommitment.VerifyMembership(tree.Root, FirstEntryIndex, key, shortValue, path, Hash),
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;

        IMemoryOwner<byte> entriesOwner = Track(pool.Rent(AtCapEntriesSizeBytes));
        Span<byte> entries = entriesOwner.Memory.Span[..AtCapEntriesSizeBytes];
        FillAscendingKeys(entries, PairedEntryCount, AtCapDigestSizeBytes);

        MerkleTree tree = Track(MerkleSetCommitment.Commit(entries, PairedEntryCount, AtCapDigestSizeBytes, HashTwoToOneAtCap, pool));
        MerkleAuthenticationPath path = Track(MerkleSetCommitment.ProveMembership(tree, FirstEntryIndex, pool));
        ReadOnlySpan<byte> key = entries.Slice(FirstEntryIndex * ChunksPerEntry * AtCapDigestSizeBytes, AtCapDigestSizeBytes);
        ReadOnlySpan<byte> value = entries.Slice((FirstEntryIndex * ChunksPerEntry * AtCapDigestSizeBytes) + AtCapDigestSizeBytes, AtCapDigestSizeBytes);

        Assert.IsTrue(
            MerkleSetCommitment.VerifyMembership(tree.Root, FirstEntryIndex, key, value, path, HashTwoToOneAtCap),
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
        IMemoryOwner<byte> entriesOwner = Track(BaseMemoryPool.Shared.Rent(OrderingEntriesSizeBytes));
        Memory<byte> entries = entriesOwner.Memory[..OrderingEntriesSizeBytes];
        FillEntries(entries.Span, OrderingEntryCount, ValueSalt);

        //Exchange the keys of entries 1 and 2, so the keys read low, high,
        //middle and the first ascending pair is still in order.
        Span<byte> swap = stackalloc byte[DigestSizeBytes];
        Span<byte> secondKey = entries.Span.Slice(SecondEntryIndex * EntrySizeBytes, DigestSizeBytes);
        Span<byte> thirdKey = entries.Span.Slice(ThirdEntryIndex * EntrySizeBytes, DigestSizeBytes);
        secondKey.CopyTo(swap);
        thirdKey.CopyTo(secondKey);
        swap.CopyTo(thirdKey);

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(
            () => MerkleSetCommitment.Commit(entries.Span, OrderingEntryCount, DigestSizeBytes, Hash, BaseMemoryPool.Shared).Dispose(),
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
        Span<byte> material = stackalloc byte[EntryMaterialSizeBytes];
        for(int i = 0; i < entryCount; i++)
        {
            Span<byte> key = entries.Slice(i * EntrySizeBytes, DigestSizeBytes);
            Span<byte> value = entries.Slice((i * EntrySizeBytes) + DigestSizeBytes, DigestSizeBytes);

            material.Clear();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(material[..IndexEncodingSizeBytes], i);
            Blake3.Hash(material, key);
            //Force strict ascending order with an index prefix over the digest.
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(key[..IndexEncodingSizeBytes], i);

            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(material[..IndexEncodingSizeBytes], i);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(material.Slice(SaltEncodingOffsetBytes, SaltEncodingSizeBytes), valueSalt);
            Blake3.Hash(material, value);
        }
    }


    /// <summary>
    /// The wired two-to-one compression: BLAKE3 over the concatenated
    /// children at the default 32-byte pairing.
    /// </summary>
    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[ChildrenPerParent * DigestSizeBytes];
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
            Span<byte> key = entries.Slice(i * ChunksPerEntry * digestSizeBytes, digestSizeBytes);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(key[..IndexEncodingSizeBytes], i + FirstKeyPrefix);
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
        Span<byte> combined = stackalloc byte[ChildrenPerParent * AtCapDigestSizeBytes];
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

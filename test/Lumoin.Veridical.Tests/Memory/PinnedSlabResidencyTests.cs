using System;
using System.Buffers;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Lumoin.Veridical.Tests.Memory;

/// <summary>
/// Pins the pool's pinned-object-heap residency contract: a rental of
/// <see cref="AllocationKind.Pinned"/> is backed by an array the garbage
/// collector never relocates, and a returned segment is wiped before the
/// pool marks it available again.
/// </summary>
/// <remarks>
/// <para>
/// Zeroize-on-return only erases the bytes it can still reach. If the backing
/// array were an ordinary relocatable allocation, a compacting collection
/// could copy secret material to a new address mid-lifetime and leave the
/// stale original bytes on the heap, where no clear ever reaches them —
/// silently defeating clear-on-dispose. Pinned-object-heap allocation
/// forecloses that: POH segments are never compacted, so the wiped bytes are
/// the only copy that ever existed. The pool ships as a binary package
/// dependency, so this suite asserts the residency contract behaviorally
/// rather than by source inspection.
/// </para>
/// <para>
/// The relocation assertion is one-sided by design: a pinned array holding
/// its address through a forced compacting collection is guaranteed, while
/// observing a relocatable array actually move depends on collector
/// heuristics — so the test can never flake while the contract holds, and
/// fails with high probability if it regresses. The generation assertion
/// closes the small-object gap deterministically: a pinned-object-heap array
/// reports the oldest generation from birth, whereas a fresh small-object
/// array reports generation zero.
/// </para>
/// </remarks>
[TestClass]
internal sealed class PinnedSlabResidencyTests
{
    /// <summary>A representative secret size: one field scalar.</summary>
    private const int SegmentBytes = 32;

    /// <summary>A recognizable non-zero fill so a missed wipe is unambiguous.</summary>
    private const byte PoisonByte = 0xA5;

    /// <summary>Transient allocations dropped before collecting, so the compacting collection has garbage to slide survivors over.</summary>
    private const int GarbageArrayCount = 256;

    /// <summary>Size of each transient garbage allocation.</summary>
    private const int GarbageArrayBytes = 4096;


    [TestMethod]
    public void PinnedRentalReportsTheOldestGenerationFromBirth()
    {
        using BaseMemoryPool pool = new();
        using IMemoryOwner<byte> owner = pool.Rent(SegmentBytes, AllocationKind.Pinned);

        byte[] backing = BackingArrayOf(owner);

        //Pinned-object-heap (and large-object-heap) arrays are born in the
        //oldest generation; generation zero means the slab is an ordinary
        //relocatable small-object allocation, which a compacting collection
        //may copy before any zeroize runs.
        Assert.AreEqual(GC.MaxGeneration, GC.GetGeneration(backing),
            "A Pinned rental must be backed by a pinned-object-heap array. A generation-zero backing array is relocatable, so secret bytes could be copied by the collector before zeroize-on-return reaches them.");
    }


    [TestMethod]
    public void PinnedRentalKeepsItsAddressAcrossACompactingCollection()
    {
        using BaseMemoryPool pool = new();
        using IMemoryOwner<byte> owner = pool.Rent(SegmentBytes, AllocationKind.Pinned);

        byte[] backing = BackingArrayOf(owner);
        IntPtr addressBefore = AddressOf(backing);

        ChurnAndCompact();

        IntPtr addressAfter = AddressOf(backing);
        Assert.AreEqual(addressBefore, addressAfter,
            "A Pinned rental's backing array relocated across a compacting collection. The pool must allocate Pinned slabs on the pinned-object-heap so secret bytes are never copied by the collector.");
    }


    [TestMethod]
    [DataRow(AllocationKind.Pinned)]
    [DataRow(AllocationKind.Managed)]
    public void ReturnedSegmentIsWipedBeforeThePoolReclaimsIt(AllocationKind kind)
    {
        using BaseMemoryPool pool = new();

        IMemoryOwner<byte> owner = pool.Rent(SegmentBytes, kind);
        ArraySegment<byte> segment;
        try
        {
            segment = SegmentOf(owner);
            owner.Memory.Span.Fill(PoisonByte);
        }
        finally
        {
            owner.Dispose();
        }

        //The dispose returned the segment to the pool; the wipe must already
        //have happened, because from this point another renter can receive
        //the same backing bytes.
        Assert.AreEqual(-1, segment.AsSpan().IndexOfAnyExcept((byte)0),
            "A returned segment still holds non-zero bytes. The pool must wipe a segment before marking it available, or a later renter of the same slab observes the previous renter's secret material.");
    }


    private static byte[] BackingArrayOf(IMemoryOwner<byte> owner)
    {
        ArraySegment<byte> segment = SegmentOf(owner);

        return segment.Array!;
    }


    private static ArraySegment<byte> SegmentOf(IMemoryOwner<byte> owner)
    {
        Assert.IsTrue(MemoryMarshal.TryGetArray<byte>(owner.Memory, out ArraySegment<byte> segment),
            "The pool rental is expected to be backed by a managed array so residency can be observed.");

        return segment;
    }


    //Reading the address through a pinning handle is safe regardless of
    //where the array lives; the handle is released between the two reads so
    //a relocatable array is free to move in the interim.
    private static IntPtr AddressOf(byte[] array)
    {
        GCHandle handle = GCHandle.Alloc(array, GCHandleType.Pinned);
        try
        {
            return handle.AddrOfPinnedObject();
        }
        finally
        {
            handle.Free();
        }
    }


    //NoInlining keeps the garbage allocations out of the caller's frame so
    //they are genuinely dead when the collection runs.
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ChurnAndCompact()
    {
        for(int i = 0; i < GarbageArrayCount; i++)
        {
            byte[] garbage = new byte[GarbageArrayBytes];
            garbage[0] = PoisonByte;
        }

        GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
        GC.WaitForPendingFinalizers();
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, blocking: true, compacting: true);
    }
}

using Lumoin.Veridical.Core.Memory;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Lumoin.Veridical.Tests.Memory;

/// <summary>
/// Pins the <see cref="SensitiveMemory"/> lifetime contract: an undisposed
/// wrapper ORPHANS its pool slot — the segment is never returned to the pool,
/// not even by garbage collection.
/// </summary>
/// <remarks>
/// <para>
/// This contract exists because the opposite behaviour was a real bug: the
/// base class used to carry a finalizer that cleared the buffer and returned
/// the segment. In a chained expression such as <c>a.Add(b, …).Add(c, …)</c>
/// the intermediate wrapper becomes unreachable as soon as the outer call is
/// invoked, while the callee is still reading its span — the span keeps the
/// underlying array alive, but not the wrapper or its rental. Under
/// allocation pressure the finalizer thread returned the segment mid-read, a
/// concurrent renter overwrote it, and the CI property tests on the ARM64
/// legs failed with one-shot, irreproducible wrong results (run 26980481026).
/// A finalizer that touches the buffer is a use-after-free; a leaked slot is
/// bounded and safe.
/// </para>
/// <para>
/// The test uses a private pool and <see cref="BaseMemoryPool.TrimExcess"/>
/// as the observer: TrimExcess reclaims only slabs with no active rentals, so
/// a reclaim count of zero after collection proves the leaked segment is
/// still marked rented (orphaned), and the disposed-control case proves the
/// observer actually sees returns.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SensitiveMemoryLifetimeTests
{
    //Matches the scalar size the incident exercised; any size works.
    private const int SegmentBytes = 32;


    [TestMethod]
    public void UndisposedInstanceOrphansItsPoolSlotEvenAfterGarbageCollection()
    {
        using BaseMemoryPool pool = new();

        AllocateAndLeak(pool);

        //Collect the leaked wrapper and run any finalizers it might (wrongly)
        //have. With the contract intact nothing returns the segment, so the
        //slab still has an active rental and TrimExcess must reclaim nothing.
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        Assert.AreEqual(0, pool.TrimExcess(),
            "A leaked SensitiveMemory must orphan its pool slot. A reclaimed slab means something returned the segment after collection — reintroducing the finalizer use-after-free race.");
    }


    [TestMethod]
    public void DisposedInstanceReturnsItsPoolSlot()
    {
        using BaseMemoryPool pool = new();

        using(PlainSensitiveMemory memory = new(pool.Rent(SegmentBytes), SegmentBytes))
        {
            Assert.AreEqual(SegmentBytes, memory.Length);
        }

        //The only rental was returned by Dispose, so the slab is fully
        //available and TrimExcess reclaims it — proving the observer works.
        Assert.AreEqual(1, pool.TrimExcess());
    }


    //NoInlining keeps the wrapper's reference from being treated as live in
    //the caller's frame, so the leaked instance is genuinely collectable.
    [MethodImpl(MethodImplOptions.NoInlining)]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The leak is the subject under test: the wrapper is deliberately dropped undisposed to prove its pool slot is orphaned, not returned.")]
    private static void AllocateAndLeak(BaseMemoryPool pool)
    {
        PlainSensitiveMemory leaked = new(pool.Rent(SegmentBytes), SegmentBytes);
        Assert.AreEqual(SegmentBytes, leaked.Length);
    }
}

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Threading;

namespace Lumoin.Veridical.Core.Telemetry;

/// <summary>
/// Per-process aggregator for cryptographic-operation counts plus a
/// streaming observable of individual operation events. Designed for two
/// distinct audiences: production monitoring via OpenTelemetry counters,
/// and interactive debugging via an <see cref="IObservable{T}"/> event
/// stream.
/// </summary>
/// <remarks>
/// <para>
/// Backends call <see cref="Increment"/> at the entry of each
/// delegate implementation. The hot-path cost when counting and observing
/// are both disabled is two volatile reads and a branch — small enough
/// to keep on the inner path of a prover backend. When either gate is
/// enabled, the cost rises to a tagged <see cref="Counter{T}.Add(T, System.Collections.Generic.KeyValuePair{string, object?}[])"/>
/// (OTel) plus an interlocked array bump per call (counting), and a
/// snapshot-then-iterate over subscribed observers (observing).
/// </para>
/// <para>
/// The two gates are independent so a workload can capture aggregate
/// counts without paying the event-allocation cost of the streaming
/// path, and a debugger can subscribe to events without forcing OTel
/// counters to be wired.
/// </para>
/// <para>
/// Process-wide aggregation means tests that depend on specific counts
/// need to opt out of MSTest parallelism (<see cref="DoNotParallelizeAttribute"/>
/// on the class) and surround their measurement scope with
/// <see cref="Reset"/> at start and <see cref="Snapshot"/> at finish.
/// </para>
/// <para>
/// Runtime-tuning use cases (the architectural motivation for this
/// surface) work through <see cref="Subscribe"/>: a strategy selector
/// observes the event stream and swaps which delegate instance is
/// registered for a given operation kind based on workload patterns —
/// switching to Pippenger batching when the multi-scalar-multiplication
/// rate crosses a threshold, for example.
/// </para>
/// </remarks>
public static class CryptographicOperationCounters
{
    /// <summary>The OTel meter through which aggregated counts surface to monitoring infrastructure.</summary>
    public static Meter Meter { get; } = new("Lumoin.Veridical.CryptographicOperations", "1.0.0");


    /// <summary>The single tagged counter that backs all OTel reporting. Tags <c>kind</c> and <c>curve</c> distinguish the aggregations.</summary>
    private static readonly Counter<long> OperationCounter = Meter.CreateCounter<long>(
        name: "Lumoin.Veridical.CryptographicOperations.Total",
        unit: "operations",
        description: "Total cryptographic operations by kind and curve.");


    /// <summary>
    /// Process-wide on/off switch for counter aggregation. The hot path
    /// reads this with no synchronisation; the value need not be exactly
    /// up to date on every thread for diagnostic counting to remain
    /// useful.
    /// </summary>
    public static bool IsCountingEnabled { get; set; }


    /// <summary>
    /// Process-wide on/off switch for the event-stream emit path.
    /// Independent of <see cref="IsCountingEnabled"/> because the per-event
    /// allocation and observer-snapshot cost are paid separately.
    /// </summary>
    public static bool IsObservingEnabled { get; set; }


    /// <summary>
    /// Internal counts indexed by <see cref="CryptographicOperationKind.Code"/>.
    /// Grown lazily as new kinds appear; bumps are interlocked.
    /// </summary>
    private static long[] counts = new long[InitialCountsCapacity];

    private const int InitialCountsCapacity = 64;

    private static readonly Lock CountsLock = new();

    private static readonly Lock ObserversLock = new();
    private static List<IObserver<CryptographicOperationEvent>> observers = [];


    /// <summary>
    /// Records that <paramref name="delta"/> operations of kind
    /// <paramref name="kind"/> over curve <paramref name="curve"/> have
    /// happened. Cost is near zero when both gates are off, and a tagged
    /// counter add plus interlocked bump per call when counting is on.
    /// </summary>
    /// <param name="kind">The kind of operation.</param>
    /// <param name="curve">The curve parameter set the operation ran over. Pass <see cref="CurveParameterSet.None"/> for curve-agnostic operations.</param>
    /// <param name="delta">The number of operations represented by this call. For batched ops, the batch count. Defaults to one.</param>
    public static void Increment(CryptographicOperationKind kind, CurveParameterSet curve, long delta = 1)
    {
        //Early-out before any tag construction or allocation. Two volatile-ish
        //reads and a branch; the JIT collapses this on hot paths where both
        //flags are routinely false.
        bool countingEnabled = IsCountingEnabled;
        bool observingEnabled = IsObservingEnabled;
        if(!countingEnabled && !observingEnabled)
        {
            return;
        }

        if(countingEnabled)
        {
            EnsureCapacity(kind.Code);
            Interlocked.Add(ref counts[kind.Code], delta);

            OperationCounter.Add(
                delta,
                new KeyValuePair<string, object?>("kind", CryptographicOperationKindNames.GetName(kind)),
                new KeyValuePair<string, object?>("curve", CurveParameterSetNames.GetName(curve)));
        }

        if(observingEnabled)
        {
            var evt = new CryptographicOperationEvent(kind, curve, delta, Stopwatch.GetTimestamp());
            EmitToObservers(evt);
        }
    }


    /// <summary>
    /// Returns the current aggregate count for <paramref name="kind"/>.
    /// Reads are not synchronised against concurrent
    /// <see cref="Increment"/> calls, so the value seen is a recent but
    /// not necessarily latest observation.
    /// </summary>
    public static long GetCount(CryptographicOperationKind kind)
    {
        long[] currentCounts = counts;
        if((uint)kind.Code >= (uint)currentCounts.Length)
        {
            return 0;
        }


        return Volatile.Read(ref currentCounts[kind.Code]);
    }


    /// <summary>
    /// Returns a snapshot of the non-zero counts for every kind
    /// registered with <see cref="CryptographicOperationKind"/>. Useful
    /// for tests and one-shot reporting; not synchronised against
    /// concurrent increments.
    /// </summary>
    public static IReadOnlyDictionary<CryptographicOperationKind, long> Snapshot()
    {
        var result = new Dictionary<CryptographicOperationKind, long>();
        foreach(CryptographicOperationKind kind in CryptographicOperationKind.Kinds)
        {
            long count = GetCount(kind);
            if(count != 0)
            {
                result[kind] = count;
            }
        }


        return result;
    }


    /// <summary>
    /// Resets every count to zero. Intended for test setup and benchmark
    /// scope boundaries; not synchronised against concurrent increments.
    /// </summary>
    public static void Reset()
    {
        using(CountsLock.EnterScope())
        {
            Array.Clear(counts);
        }
    }


    /// <summary>
    /// Subscribes <paramref name="observer"/> to the event stream. The
    /// returned <see cref="IDisposable"/> unsubscribes when disposed.
    /// </summary>
    /// <remarks>
    /// Subscribers receive <see cref="CryptographicOperationEvent"/>
    /// instances on whatever thread emitted the event. Observers must be
    /// thread-safe. No <see cref="IObserver{T}.OnCompleted"/> or
    /// <see cref="IObserver{T}.OnError(Exception)"/> is ever called by
    /// this surface — the stream's lifetime is the process lifetime.
    /// </remarks>
    public static IDisposable Subscribe(IObserver<CryptographicOperationEvent> observer)
    {
        ArgumentNullException.ThrowIfNull(observer);

        using(ObserversLock.EnterScope())
        {
            observers.Add(observer);
        }


        return new Unsubscriber(observer);
    }


    private static void EmitToObservers(CryptographicOperationEvent evt)
    {
        //Snapshot under lock to avoid invoking observer callbacks while
        //holding the lock, which would let a malicious or slow observer
        //starve other observers and other emitting threads.
        IObserver<CryptographicOperationEvent>[] snapshot;
        using(ObserversLock.EnterScope())
        {
            int count = observers.Count;
            if(count == 0)
            {
                return;
            }

            snapshot = new IObserver<CryptographicOperationEvent>[count];
            for(int i = 0; i < count; i++)
            {
                snapshot[i] = observers[i];
            }
        }

        foreach(IObserver<CryptographicOperationEvent> observer in snapshot)
        {
            //OnNext must not throw per the IObservable contract; observers that
            //violate it are isolated so one bad observer does not block the rest.
            try
            {
                observer.OnNext(evt);
            }
            catch
            {
                //Suppression is deliberate; the counter surface is best-effort and
                //must not propagate observer faults back to the emitting thread.
            }
        }
    }


    private static void EnsureCapacity(int code)
    {
        long[] currentCounts = counts;
        if((uint)code < (uint)currentCounts.Length)
        {
            return;
        }

        using(CountsLock.EnterScope())
        {
            currentCounts = counts;
            if((uint)code < (uint)currentCounts.Length)
            {
                return;
            }

            int newSize = Math.Max(currentCounts.Length * 2, code + 1);
            long[] resized = new long[newSize];
            currentCounts.CopyTo(resized, 0);
            counts = resized;
        }
    }


    private sealed class Unsubscriber: IDisposable
    {
        private IObserver<CryptographicOperationEvent>? observer;

        public Unsubscriber(IObserver<CryptographicOperationEvent> observer)
        {
            this.observer = observer;
        }

        public void Dispose()
        {
            IObserver<CryptographicOperationEvent>? toRemove = observer;
            if(toRemove is null)
            {
                return;
            }

            observer = null;
            using(ObserversLock.EnterScope())
            {
                observers.Remove(toRemove);
            }
        }
    }
}
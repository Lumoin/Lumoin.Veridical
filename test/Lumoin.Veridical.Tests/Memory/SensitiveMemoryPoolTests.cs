using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Tests.Memory;

/// <summary>
/// Behavioural and performance tests for <see cref="SensitiveMemoryPool{T}"/>.
/// </summary>
/// <remarks>
/// <para>
/// The pool sits underneath every algebraic leaf type in the library; an
/// upstream slowdown in <see cref="SensitiveMemoryPool{T}.Rent"/> shows up
/// as cryptographic operations taking far longer than the math itself
/// would explain. The performance tests in this class put a hard upper
/// bound on the time a single <c>Rent</c> may take and on the rate at
/// which many rents may complete, so a regression like an accidental
/// pool-internal hang turns into a clear test failure with a pointer at
/// the right code rather than a runaway test run.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SensitiveMemoryPoolTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void RentReturnsExactBufferSize()
    {
        using SensitiveMemoryPool<byte> pool = new();

        int[] testSizes = [1, 16, 32, 64, 128, 256, 512, 1024];

        foreach(int size in testSizes)
        {
            using IMemoryOwner<byte> buffer = pool.Rent(size);
            Assert.AreEqual(size, buffer.Memory.Length, $"Buffer size should be exactly {size} bytes.");
        }
    }


    [TestMethod]
    public void RentReusesSlabsForSameSize()
    {
        using SensitiveMemoryPool<byte> pool = new();
        const int bufferSize = 64;
        const int rentCount = 10;

        List<IMemoryOwner<byte>> buffers = [];

        try
        {
            for(int i = 0; i < rentCount; i++)
            {
                buffers.Add(pool.Rent(bufferSize));
            }

            foreach(IMemoryOwner<byte> buffer in buffers)
            {
                Assert.AreEqual(bufferSize, buffer.Memory.Length);
            }
        }
        finally
        {
            foreach(IMemoryOwner<byte> buffer in buffers)
            {
                buffer.Dispose();
            }
        }
    }


    [TestMethod]
    public void DisposeClearsMemoryAndPreventsAccess()
    {
        using SensitiveMemoryPool<byte> pool = new();
        IMemoryOwner<byte> buffer = pool.Rent(32);

        buffer.Memory.Span.Fill(0xFF);
        buffer.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => _ = buffer.Memory);
    }


    [TestMethod]
    public void DoubleDisposeIsIdempotent()
    {
        using SensitiveMemoryPool<byte> pool = new();
        IMemoryOwner<byte> buffer = pool.Rent(32);

        buffer.Memory.Span.Fill(0xFF);
        buffer.Dispose();

        //Second dispose should not throw.
        buffer.Dispose();
    }


    [TestMethod]
    public void ReturnedMemoryIsZeroed()
    {
        using Meter meter = new("Test", "1.0.0");
        using SensitiveMemoryPool<byte> pool = new(
            meter,
            capacityStrategy: _ => 1);

        //Rent, fill with a recognizable pattern, and return.
        IMemoryOwner<byte> first = pool.Rent(32);
        first.Memory.Span.Fill(0xDE);
        first.Dispose();

        //Rent again from the same slab and verify the memory is zeroed.
        using IMemoryOwner<byte> second = pool.Rent(32);
        foreach(byte b in second.Memory.Span)
        {
            Assert.AreEqual(0, b, "Returned memory must be zeroed for security.");
        }
    }


    [TestMethod]
    public void RentHandlesEdgeCases()
    {
        using SensitiveMemoryPool<byte> pool = new();

        using(IMemoryOwner<byte> buffer = pool.Rent(1))
        {
            Assert.AreEqual(1, buffer.Memory.Length);
        }

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => pool.Rent(0));
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => pool.Rent(-1));
    }


    [TestMethod]
    public void RentThrowsWhenPoolDisposed()
    {
        SensitiveMemoryPool<byte> pool = new();
        pool.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => pool.Rent(32));
    }


    [TestMethod]
    public void DisposingRentalAfterPoolDisposedDoesNotThrow()
    {
        SensitiveMemoryPool<byte> pool = new();
        IMemoryOwner<byte> owner = pool.Rent(32);
        owner.Memory.Span.Fill(0xCC);

        //Disposing the pool clears all slabs while a rental is still active.
        pool.Dispose();

        //The rental's Dispose calls Pool.Return on an already-disposed slab.
        //This must not throw — the error is caught internally and the lifecycle
        //activity records an error status instead.
        owner.Dispose();
    }


    [TestMethod]
    public void TrimExcessThrowsWhenPoolDisposed()
    {
        SensitiveMemoryPool<byte> pool = new();
        pool.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => pool.TrimExcess());
    }


    [TestMethod]
    public void SharedReturnsSingletonInstance()
    {
        SensitiveMemoryPool<byte> first = SensitiveMemoryPool<byte>.Shared;
        SensitiveMemoryPool<byte> second = SensitiveMemoryPool<byte>.Shared;

        Assert.AreSame(first, second, "Shared should return the same instance.");

        using IMemoryOwner<byte> buffer = first.Rent(64);
        Assert.AreEqual(64, buffer.Memory.Length);
    }


    [TestMethod]
    public void DefaultCapacityStrategyReturnsMoreSegmentsForSmallerSizes()
    {
        int smallCapacity = SensitiveMemoryPool<byte>.DefaultCapacityStrategy(32);
        int mediumCapacity = SensitiveMemoryPool<byte>.DefaultCapacityStrategy(128);
        int largeCapacity = SensitiveMemoryPool<byte>.DefaultCapacityStrategy(8192);

        //Smaller sizes should get more segments per slab than larger sizes.
        Assert.IsGreaterThan(mediumCapacity, smallCapacity,
            "Small buffers should get more segments per slab than medium buffers.");
        Assert.IsGreaterThan(largeCapacity, mediumCapacity,
            "Medium buffers should get more segments per slab than large buffers.");
    }


    [TestMethod]
    public void CustomCapacityStrategyIsUsed()
    {
        int strategyCallCount = 0;

        int customStrategy(int segmentSize)
        {
            Interlocked.Increment(ref strategyCallCount);
            return 2;
        }

        using Meter meter = new("Test", "1.0.0");
        using SensitiveMemoryPool<byte> pool = new(
            meter,
            capacityStrategy: customStrategy);

        //Rent three buffers of the same size to force slab creation and overflow.
        using IMemoryOwner<byte> b1 = pool.Rent(32);
        using IMemoryOwner<byte> b2 = pool.Rent(32);
        using IMemoryOwner<byte> b3 = pool.Rent(32);

        //The strategy should have been invoked at least twice (first slab holds 2, second slab for the third rent).
        Assert.IsGreaterThanOrEqualTo(2, strategyCallCount,
            $"Custom strategy should have been called at least twice, was called {strategyCallCount} times.");
    }


    [TestMethod]
    public void TrimExcessReclaimsUnusedSlabs()
    {
        using Meter meter = new("Test", "1.0.0");
        using SensitiveMemoryPool<byte> pool = new(
            meter,
            capacityStrategy: _ => 2);

        //Hold three buffers simultaneously to force creation of a second slab (capacity 2 per slab).
        IMemoryOwner<byte> b1 = pool.Rent(32);
        IMemoryOwner<byte> b2 = pool.Rent(32);
        IMemoryOwner<byte> b3 = pool.Rent(32);

        //Return all buffers so both slabs become fully available.
        b1.Dispose();
        b2.Dispose();
        b3.Dispose();

        int reclaimed = pool.TrimExcess();
        Assert.IsGreaterThan(0, reclaimed, "TrimExcess should reclaim at least one unused slab.");
    }


    [TestMethod]
    public void TrimExcessDoesNotReclaimSlabsWithActiveRentals()
    {
        using Meter meter = new("Test", "1.0.0");
        using SensitiveMemoryPool<byte> pool = new(
            meter,
            capacityStrategy: _ => 2);

        //Keep a rental alive so the slab cannot be reclaimed.
        using IMemoryOwner<byte> active = pool.Rent(32);

        int reclaimed = pool.TrimExcess();
        Assert.AreEqual(0, reclaimed, "TrimExcess should not reclaim slabs with active rentals.");
    }


    [TestMethod]
    public void RentWorksAfterTrimExcess()
    {
        using Meter meter = new("Test", "1.0.0");
        using SensitiveMemoryPool<byte> pool = new(
            meter,
            capacityStrategy: _ => 2);

        //Create slabs, return everything, then trim.
        IMemoryOwner<byte> b1 = pool.Rent(64);
        IMemoryOwner<byte> b2 = pool.Rent(64);
        b1.Dispose();
        b2.Dispose();
        pool.TrimExcess();

        //Pool should create fresh slabs on demand after trimming.
        using IMemoryOwner<byte> afterTrim = pool.Rent(64);
        Assert.AreEqual(64, afterTrim.Memory.Length, "Rent should work after TrimExcess reclaims slabs.");
    }


    [TestMethod]
    public void TracingCanBeDisabled()
    {
        ConcurrentBag<Activity> activities = [];
        using ActivityListener listener = new()
        {
            ShouldListenTo = source => source.Name == "SensitiveMemoryPool",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = activity => activities.Add(activity)
        };
        ActivitySource.AddActivityListener(listener);

        using Meter meter = new("Test", "1.0.0");
        using SensitiveMemoryPool<byte> pool = new(
            meter,
            tracingEnabled: false);

        using(pool.Rent(32))
        {
        }

        Assert.IsEmpty(activities,
            "No activities should be created when tracing is disabled.");
    }


    [TestMethod]
    public async Task MetricsAreReportedCorrectly()
    {
        using Meter meter = new(CryptographyMetrics.MeterName, "1.0.0");
        ConcurrentDictionary<string, long> reportedMetrics = new();

        using MeterListener listener = new();

        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if(instrument.Meter == meter)
            {
                meterListener.EnableMeasurementEvents(instrument);
            }
        };

        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            reportedMetrics.AddOrUpdate(instrument.Name, measurement, (_, _) => measurement);
        });

        listener.SetMeasurementEventCallback<int>((instrument, measurement, tags, state) =>
        {
            reportedMetrics.AddOrUpdate(instrument.Name, measurement, (_, _) => measurement);
        });

        listener.Start();

        using SensitiveMemoryPool<byte> pool = new(meter);

        using(pool.Rent(100))
        {
            using(pool.Rent(200))
            {
                listener.RecordObservableInstruments();
                await Task.Delay(TimeSpan.FromMilliseconds(10), TestContext.CancellationToken).ConfigureAwait(false);

                bool foundSlabs = reportedMetrics.TryGetValue(CryptographyMetrics.SensitiveMemoryPoolTotalSlabs, out long totalSlabs);
                Assert.IsTrue(foundSlabs, "TotalSlabs metric should be reported.");
                Assert.AreEqual(2, totalSlabs, "Should have created two slabs for different buffer sizes.");

                bool foundMemory = reportedMetrics.TryGetValue(CryptographyMetrics.SensitiveMemoryPoolTotalMemoryAllocated, out long totalMemory);
                Assert.IsTrue(foundMemory, "TotalMemoryAllocated metric should be reported.");

                //Expected memory uses the default capacity strategy.
                int expectedCapacity100 = SensitiveMemoryPool<byte>.DefaultCapacityStrategy(100);
                int expectedCapacity200 = SensitiveMemoryPool<byte>.DefaultCapacityStrategy(200);
                long expectedMemory = (100 * expectedCapacity100) + (200 * expectedCapacity200);
                Assert.AreEqual(expectedMemory, totalMemory, "Total memory should match expected allocation.");
            }
        }
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Analyzer false positive on testRoot.")]
    public void TracingRecordsSingleLifecycleActivityPerRental()
    {
        Activity.Current = null;

        using Activity testRoot = new Activity("TestRoot").Start();
        ActivityTraceId testTraceId = testRoot.TraceId;

        List<Activity> activities = [];

        using ActivityListener activityListener = new()
        {
            ShouldListenTo = source => source.Name == "SensitiveMemoryPool",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = activity =>
            {
                if(activity.TraceId == testTraceId)
                {
                    activities.Add(activity);
                }
            }
        };

        ActivitySource.AddActivityListener(activityListener);

        using SensitiveMemoryPool<byte> pool = new();

        using(pool.Rent(100))
        {
        }

        using(pool.Rent(200))
        {
        }

        testRoot.Stop();

        //Single-activity model: one "Rent" activity per rental lifecycle, no separate "Dispose" activity.
        List<Activity> rentActivities = activities.Where(a => a.OperationName == "Rent").ToList();
        Assert.HasCount(2, rentActivities, "Should have exactly two lifecycle activities.");

        Activity? firstRent = rentActivities.FirstOrDefault(a => a.GetTagItem("bufferSize")?.ToString() == "100");
        Activity? secondRent = rentActivities.FirstOrDefault(a => a.GetTagItem("bufferSize")?.ToString() == "200");

        Assert.IsNotNull(firstRent, "Should have lifecycle activity for 100-byte buffer.");
        Assert.IsNotNull(secondRent, "Should have lifecycle activity for 200-byte buffer.");

        //No separate dispose activities should exist.
        List<Activity> disposeActivities = activities.Where(a => a.OperationName == "Dispose").ToList();
        Assert.HasCount(0, disposeActivities,
            "Single-activity model should not create separate dispose activities.");
    }


    [TestMethod]
    public async Task RentOnOneThreadDisposeOnAnotherWithConfigureAwaitFalse()
    {
        using SensitiveMemoryPool<byte> pool = new();

        //Rent on the current thread.
        IMemoryOwner<byte> owner = pool.Rent(128);
        owner.Memory.Span.Fill(0xBB);

        //Force a thread switch via ConfigureAwait(false).
        await Task.Yield();
        await Task.Delay(TimeSpan.FromMilliseconds(5), TestContext.CancellationToken).ConfigureAwait(false);

        //Dispose may now execute on a thread pool thread.
        owner.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => _ = owner.Memory,
            "Buffer must be inaccessible after cross-thread dispose.");

        //Pool should still be functional after cross-thread return.
        using IMemoryOwner<byte> subsequent = pool.Rent(128);
        Assert.AreEqual(128, subsequent.Memory.Length,
            "Pool must remain usable after cross-thread disposal.");
    }


    [TestMethod]
    public async Task ConcurrentRentAndDisposeAcrossThreads()
    {
        using SensitiveMemoryPool<byte> pool = new();

        IEnumerable<Task<int>> tasks = Enumerable.Range(0, 50).Select(async i =>
        {
            IMemoryOwner<byte> owner = pool.Rent(((i % 8) + 1) * 16);
            owner.Memory.Span.Fill((byte)(i % 256));

            //Yield to force potential thread switches.
            await Task.Yield();

            int length = owner.Memory.Length;
            owner.Dispose();

            return length;
        });

        int[] results = await Task.WhenAll(tasks).ConfigureAwait(false);

        Assert.HasCount(50, results, "All concurrent rent-dispose cycles should complete.");
    }


    [TestMethod]
    [Timeout(2000, CooperativeCancellation = true)]
    public void RentCompletesInBoundedTime()
    {
        //Hard upper bound on a single Rent against a fresh pool with no
        //listeners attached. A regression like an unintended deadlock or a
        //meter callback that blocks on the pool's own lock turns into a
        //deterministic test failure here rather than a hung test run.
        using SensitiveMemoryPool<byte> pool = new();

        Stopwatch stopwatch = Stopwatch.StartNew();
        using IMemoryOwner<byte> owner = pool.Rent(48);
        stopwatch.Stop();

        Assert.IsLessThan(
            TimeSpan.FromMilliseconds(100),
            stopwatch.Elapsed,
            $"A single fresh-slab Rent should complete in well under 100 ms; took {stopwatch.Elapsed.TotalMilliseconds:F2} ms.");
    }


    [TestMethod]
    [Timeout(5000, CooperativeCancellation = true)]
    public void ManyRentsOnSharedPoolCompleteInBoundedTime()
    {
        //Stresses the path the cryptographic tests exercise: many sequential
        //rent/return cycles against the shared singleton pool. This is the
        //regression net for the symptom that surfaced through the G1
        //arithmetic tests, where each operation triggers several pool rents
        //and the cumulative cost dominated test runtime.
        SensitiveMemoryPool<byte> pool = SensitiveMemoryPool<byte>.Shared;
        const int iterations = 5000;

        Stopwatch stopwatch = Stopwatch.StartNew();
        for(int i = 0; i < iterations; i++)
        {
            using IMemoryOwner<byte> owner = pool.Rent(48);
            owner.Memory.Span[0] = (byte)(i & 0xFF);
        }

        stopwatch.Stop();

        double perOpMicroseconds = stopwatch.Elapsed.TotalMilliseconds * 1000.0 / iterations;
        TestContext.WriteLine(
            $"{iterations} rent/return cycles took {stopwatch.Elapsed.TotalMilliseconds:F2} ms ({perOpMicroseconds:F2} µs/op).".ToString(CultureInfo.InvariantCulture));

        Assert.IsLessThan(
            TimeSpan.FromMilliseconds(2000),
            stopwatch.Elapsed,
            $"{iterations} rent/return cycles should complete in well under 2 s; took {stopwatch.Elapsed.TotalMilliseconds:F2} ms.");
    }
}
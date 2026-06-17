using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Telemetry;

/// <summary>
/// Behavioural tests for <see cref="CryptographicOperationCounters"/> —
/// the on/off gates, counter aggregation, observable event stream, and
/// the wiring of the scalar backends to the counter surface.
/// </summary>
/// <remarks>
/// <para>
/// All tests in this class run sequentially (<see cref="DoNotParallelizeAttribute"/>)
/// because the counter aggregation and observer list are process-wide
/// static state. Each test resets the gates and counters in its own
/// fixture; the test class restores the gates to their default state in
/// cleanup so other test classes are unaffected.
/// </para>
/// </remarks>
[TestClass]
[DoNotParallelize]
internal sealed class CryptographicOperationCountersTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestInitialize]
    public void Initialize()
    {
        //Start each test with both gates off and counters cleared so the test
        //sees a clean slate independent of preceding test runs.
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;
        CryptographicOperationCounters.Reset();
    }


    [TestCleanup]
    public void Cleanup()
    {
        //Restore the off-default state so subsequent test classes start clean.
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;
        CryptographicOperationCounters.Reset();
    }


    [TestMethod]
    public void CountsStayAtZeroWhenCountingDisabled()
    {
        //Pre-condition: counting is disabled (set in Initialize).
        //Action: perform a scalar add through the BigInteger reference backend.
        //Post-condition: GetCount returns zero for every kind.
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarAddDelegate add = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

        ReadOnlySpan<byte> three = [0x03];
        ReadOnlySpan<byte> five = [0x05];
        using Scalar a = Scalar.FromBytesReduced(three, reduce, CurveParameterSet.Bls12Curve381, pool);
        using Scalar b = Scalar.FromBytesReduced(five, reduce, CurveParameterSet.Bls12Curve381, pool);

        using Scalar _ = a.Add(b, add, pool);

        Assert.AreEqual(0, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarAdd));
        Assert.AreEqual(0, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarReduce));
    }


    [TestMethod]
    public void CountsAccumulateWhenCountingEnabled()
    {
        //Pre-condition: counting is enabled.
        //Action: perform two scalar adds and one scalar subtract.
        //Post-condition: GetCount reports the correct count per kind.
        CryptographicOperationCounters.IsCountingEnabled = true;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarAddDelegate add = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarSubtractDelegate subtract = Bls12Curve381BigIntegerScalarReference.GetSubtract();
        ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

        ReadOnlySpan<byte> three = [0x03];
        ReadOnlySpan<byte> five = [0x05];
        using Scalar a = Scalar.FromBytesReduced(three, reduce, CurveParameterSet.Bls12Curve381, pool);
        using Scalar b = Scalar.FromBytesReduced(five, reduce, CurveParameterSet.Bls12Curve381, pool);

        using Scalar sum1 = a.Add(b, add, pool);
        using Scalar sum2 = a.Add(b, add, pool);
        using Scalar diff = a.Subtract(b, subtract, pool);

        Assert.AreEqual(2, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarAdd));
        Assert.AreEqual(1, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarSubtract));
        //Reduce ran twice during scalar construction.
        Assert.AreEqual(2, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarReduce));
    }


    [TestMethod]
    public void BatchedDelegateIncrementsByCountNotByOne()
    {
        //Pre-condition: counting is enabled.
        //Action: invoke the batched-add delegate with a batch of seven scalars.
        //Post-condition: ScalarBatchAdd counter increments by seven, ScalarAdd
        //stays at zero (the batched path must not double-count by also bumping
        //the single-element counter through any internal element-wise loop).
        CryptographicOperationCounters.IsCountingEnabled = true;

        const int batchSize = 7;
        int stride = Scalar.SizeBytes;
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarBatchAddDelegate batchAdd = Bls12Curve381BigIntegerScalarReference.GetBatchAdd();
        ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

        using IMemoryOwner<byte> aBufOwner = pool.Rent(batchSize * stride);
        using IMemoryOwner<byte> bBufOwner = pool.Rent(batchSize * stride);
        using IMemoryOwner<byte> resultOwner = pool.Rent(batchSize * stride);

        Span<byte> aBuf = aBufOwner.Memory.Span[..(batchSize * stride)];
        Span<byte> bBuf = bBufOwner.Memory.Span[..(batchSize * stride)];

        //Populate each batch slot with a tiny reduced scalar. Reduce will bump
        //the ScalarReduce counter; ScalarAdd stays at zero throughout, which
        //is exactly the invariant under test.
        for(int i = 0; i < batchSize; i++)
        {
            int offset = i * stride;
            ReadOnlySpan<byte> raw = [(byte)(i + 1)];
            reduce(raw, aBuf.Slice(offset, stride), CurveParameterSet.Bls12Curve381);
            reduce(raw, bBuf.Slice(offset, stride), CurveParameterSet.Bls12Curve381);
        }

        //Reset to isolate the batched-add count from the setup-time reduces.
        CryptographicOperationCounters.Reset();
        batchAdd(aBuf, bBuf, resultOwner.Memory.Span[..(batchSize * stride)], batchSize, CurveParameterSet.Bls12Curve381);

        Assert.AreEqual(batchSize, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarBatchAdd),
            "Batched delegate should increment ScalarBatchAdd by the batch count.");
        Assert.AreEqual(0, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarAdd),
            "Batched delegate must not double-count by also bumping ScalarAdd through any internal element-wise loop.");
    }


    [TestMethod]
    public void SnapshotReportsAllNonZeroCounts()
    {
        CryptographicOperationCounters.IsCountingEnabled = true;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarAddDelegate add = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

        ReadOnlySpan<byte> raw = [0x03];
        using Scalar a = Scalar.FromBytesReduced(raw, reduce, CurveParameterSet.Bls12Curve381, pool);
        using Scalar b = Scalar.FromBytesReduced(raw, reduce, CurveParameterSet.Bls12Curve381, pool);
        using Scalar _ = a.Add(b, add, pool);

        IReadOnlyDictionary<CryptographicOperationKind, long> snapshot = CryptographicOperationCounters.Snapshot();
        Assert.IsTrue(snapshot.ContainsKey(CryptographicOperationKind.ScalarAdd));
        Assert.IsTrue(snapshot.ContainsKey(CryptographicOperationKind.ScalarReduce));
        Assert.IsFalse(snapshot.ContainsKey(CryptographicOperationKind.ScalarMultiply),
            "Snapshot should omit kinds whose count is zero.");
    }


    [TestMethod]
    public void ObserverReceivesEventsWhenObservingEnabled()
    {
        //Pre-condition: observing is enabled; counting may be off.
        //Action: subscribe an observer, perform two scalar operations.
        //Post-condition: observer receives one event per operation, in order.
        CryptographicOperationCounters.IsObservingEnabled = true;

        ConcurrentQueue<CryptographicOperationEvent> received = new();
        IObserver<CryptographicOperationEvent> observer = new ActionObserver(evt => received.Enqueue(evt));

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarAddDelegate add = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

        ReadOnlySpan<byte> raw = [0x03];
        using Scalar a = Scalar.FromBytesReduced(raw, reduce, CurveParameterSet.Bls12Curve381, pool);
        using Scalar b = Scalar.FromBytesReduced(raw, reduce, CurveParameterSet.Bls12Curve381, pool);

        using(CryptographicOperationCounters.Subscribe(observer))
        {
            using Scalar _ = a.Add(b, add, pool);
        }

        //Inside the using block, the observer was subscribed; outside it has
        //been unsubscribed. We expect exactly one event — the single Add call
        //performed inside the subscription scope.
        Assert.HasCount(1, received);
        Assert.IsTrue(received.TryDequeue(out CryptographicOperationEvent evt));
        Assert.AreEqual(CryptographicOperationKind.ScalarAdd, evt.Kind);
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, evt.Curve);
        Assert.AreEqual(1, evt.Delta);
    }


    [TestMethod]
    public void UnsubscribedObserverStopsReceivingEvents()
    {
        CryptographicOperationCounters.IsObservingEnabled = true;

        ConcurrentQueue<CryptographicOperationEvent> received = new();
        IObserver<CryptographicOperationEvent> observer = new ActionObserver(evt => received.Enqueue(evt));

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarAddDelegate add = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

        ReadOnlySpan<byte> raw = [0x03];
        using Scalar a = Scalar.FromBytesReduced(raw, reduce, CurveParameterSet.Bls12Curve381, pool);
        using Scalar b = Scalar.FromBytesReduced(raw, reduce, CurveParameterSet.Bls12Curve381, pool);

        IDisposable subscription = CryptographicOperationCounters.Subscribe(observer);
        using(Scalar _ = a.Add(b, add, pool)) { }
        subscription.Dispose();
        using(Scalar _ = a.Add(b, add, pool)) { }

        Assert.HasCount(1, received);
    }


    [TestMethod]
    public void ObserverNotInvokedWhenObservingDisabled()
    {
        //Even with an active subscription, observing must be enabled for events
        //to be emitted. This is the architectural gate that lets applications
        //subscribe at startup but defer the cost of emission until they enable it.
        CryptographicOperationCounters.IsObservingEnabled = false;

        ConcurrentQueue<CryptographicOperationEvent> received = new();
        IObserver<CryptographicOperationEvent> observer = new ActionObserver(evt => received.Enqueue(evt));

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarAddDelegate add = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

        ReadOnlySpan<byte> raw = [0x03];
        using Scalar a = Scalar.FromBytesReduced(raw, reduce, CurveParameterSet.Bls12Curve381, pool);
        using Scalar b = Scalar.FromBytesReduced(raw, reduce, CurveParameterSet.Bls12Curve381, pool);

        using(CryptographicOperationCounters.Subscribe(observer))
        {
            using Scalar _ = a.Add(b, add, pool);
        }

        Assert.IsEmpty(received);
    }


    [TestMethod]
    public void G1ReferenceIncrementsExpectedKindsForFullWorkflow()
    {
        //Walks the canonical G1 delegate surface — Generator, FromHashToCurve,
        //Add, ScalarMultiply, IsOnCurve, IsInPrimeOrderSubgroup — and checks
        //that each lights up its own counter, with no cross-talk to scalar-
        //field counters. This is the regression net for "did we add the wrong
        //Increment call somewhere" after the G1 wiring lands.
        CryptographicOperationCounters.IsCountingEnabled = true;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        G1AddDelegate g1Add = Bls12Curve381BigIntegerG1Reference.GetAdd();
        G1ScalarMultiplyDelegate g1ScalarMul = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
        G1HashToCurveDelegate g1HashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
        G1IsOnCurveDelegate g1IsOnCurve = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();
        G1IsInPrimeOrderSubgroupDelegate g1IsInSubgroup = Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();
        ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

        ReadOnlySpan<byte> message = [0x10, 0x20, 0x30];
        ReadOnlySpan<byte> dst = "VERIDICAL-COUNTER-TEST-DST"u8;
        ReadOnlySpan<byte> rawScalar = [0x05];

        using G1Point generator = G1Point.Generator(CurveParameterSet.Bls12Curve381, pool);
        using G1Point hashed = G1Point.FromHashToCurve(message, dst, g1HashToCurve, CurveParameterSet.Bls12Curve381, pool);
        using Scalar five = Scalar.FromBytesReduced(rawScalar, reduce, CurveParameterSet.Bls12Curve381, pool);

        //Resetting after construction isolates the counts under test from the
        //setup costs above. The G1HashToCurve counter is reset alongside.
        CryptographicOperationCounters.Reset();

        using G1Point fiveTimesGen = generator.ScalarMultiply(five, g1ScalarMul, pool);
        using G1Point combined = fiveTimesGen.Add(hashed, g1Add, pool);
        bool onCurve = combined.IsOnCurve(g1IsOnCurve);
        bool inSubgroup = combined.IsInPrimeOrderSubgroup(g1IsInSubgroup);

        Assert.IsTrue(onCurve);
        Assert.IsTrue(inSubgroup);
        Assert.AreEqual(1, CryptographicOperationCounters.GetCount(CryptographicOperationKind.G1ScalarMultiply));
        Assert.AreEqual(1, CryptographicOperationCounters.GetCount(CryptographicOperationKind.G1Add));
        Assert.AreEqual(1, CryptographicOperationCounters.GetCount(CryptographicOperationKind.G1IsOnCurve));
        Assert.AreEqual(1, CryptographicOperationCounters.GetCount(CryptographicOperationKind.G1IsInPrimeOrderSubgroup));
        Assert.AreEqual(0, CryptographicOperationCounters.GetCount(CryptographicOperationKind.G1HashToCurve),
            "HashToCurve was called before Reset; its count should be zero in the post-Reset window.");
        //Scalar-field counters must not be bumped by G1-only operations.
        Assert.AreEqual(0, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarAdd));
        Assert.AreEqual(0, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarMultiply));
    }


    [TestMethod]
    public void SimdAndBigIntegerBackendsIncrementSameKind()
    {
        //Two different backends implementing the same delegate must increment
        //the same operation kind. If they ever diverged, downstream tuning logic
        //that strategies on "how many adds" would silently break across backends.
        if(!Bls12Curve381SimdScalarBackend.IsSupported)
        {
            Assert.Inconclusive("AVX2 is not available on the host CPU; the SIMD scalar backend cannot run.");
            return;
        }

        CryptographicOperationCounters.IsCountingEnabled = true;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        ScalarAddDelegate bigIntegerAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
        ScalarAddDelegate simdAdd = Bls12Curve381SimdScalarBackend.GetAdd();
        ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

        ReadOnlySpan<byte> raw = [0x03];
        using Scalar a = Scalar.FromBytesReduced(raw, reduce, CurveParameterSet.Bls12Curve381, pool);
        using Scalar b = Scalar.FromBytesReduced(raw, reduce, CurveParameterSet.Bls12Curve381, pool);

        CryptographicOperationCounters.Reset();
        using(Scalar _ = a.Add(b, bigIntegerAdd, pool)) { }
        using(Scalar _ = a.Add(b, simdAdd, pool)) { }

        Assert.AreEqual(2, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarAdd),
            "Both backends must bump ScalarAdd; one bump per backend invocation.");
    }


    private sealed class ActionObserver: IObserver<CryptographicOperationEvent>
    {
        private readonly Action<CryptographicOperationEvent> onNext;

        public ActionObserver(Action<CryptographicOperationEvent> onNext)
        {
            this.onNext = onNext;
        }

        public void OnCompleted()
        {
        }

        public void OnError(Exception error)
        {
        }

        public void OnNext(CryptographicOperationEvent value)
        {
            onNext(value);
        }
    }
}
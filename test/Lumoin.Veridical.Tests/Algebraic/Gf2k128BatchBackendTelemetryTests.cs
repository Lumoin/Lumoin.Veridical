using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The <see cref="Gf2k128BatchBackend"/> batch and fused-multiply-accumulate ops increment the
/// telemetry counters by the batch count, not by one — the CBOM/op-count discipline that the
/// per-scalar <see cref="Gf2k128Backend"/> historically lacked. Each FMA-family op rolls up into
/// <see cref="CryptographicOperationKind.ScalarBatchMultiplyAccumulate"/>; plain batch multiply/
/// add/subtract roll up into their existing kinds.
/// </summary>
/// <remarks>
/// Counter aggregation is process-wide static state, so these tests run sequentially
/// (<see cref="DoNotParallelizeAttribute"/>) and reset the gates and counts in their own fixture,
/// matching <c>CryptographicOperationCountersTests</c>.
/// </remarks>
[TestClass]
[DoNotParallelize]
internal sealed class Gf2k128BatchBackendTelemetryTests
{
    private const int ScalarSize = 32;


    [TestInitialize]
    public void Initialize()
    {
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;
        CryptographicOperationCounters.Reset();
    }


    [TestCleanup]
    public void Cleanup()
    {
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;
        CryptographicOperationCounters.Reset();
    }


    [TestMethod]
    public void BatchMultiplyIncrementsByCount()
    {
        const int count = 9;
        CryptographicOperationCounters.IsCountingEnabled = true;

        byte[] left = new byte[count * ScalarSize];
        byte[] right = new byte[count * ScalarSize];
        byte[] result = new byte[count * ScalarSize];

        Gf2k128BatchBackend.GetBatchMultiply()(left, right, result, count, CurveParameterSet.None);

        Assert.AreEqual(count, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarBatchMultiply),
            "BatchMultiply should increment ScalarBatchMultiply by the batch count.");
    }


    [TestMethod]
    public void BatchAddAndSubtractIncrementTheirOwnKindsByCount()
    {
        const int count = 5;
        CryptographicOperationCounters.IsCountingEnabled = true;

        byte[] left = new byte[count * ScalarSize];
        byte[] right = new byte[count * ScalarSize];
        byte[] result = new byte[count * ScalarSize];

        Gf2k128BatchBackend.GetBatchAdd()(left, right, result, count, CurveParameterSet.None);
        Gf2k128BatchBackend.GetBatchSubtract()(left, right, result, count, CurveParameterSet.None);

        Assert.AreEqual(count, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarBatchAdd),
            "BatchAdd should increment ScalarBatchAdd by the batch count.");
        Assert.AreEqual(count, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarBatchSubtract),
            "BatchSubtract should increment ScalarBatchSubtract by the batch count.");
    }


    [TestMethod]
    public void FusedMultiplyAccumulateFamilyIncrementsTheFmaKindByCount()
    {
        const int count = 8;
        const int stride = 6;
        CryptographicOperationCounters.IsCountingEnabled = true;

        byte[] left = new byte[count * ScalarSize];
        byte[] right = new byte[count * ScalarSize];
        byte[] accumulators = new byte[count * ScalarSize];
        byte[] scalar = new byte[ScalarSize];
        byte[] data = new byte[count * ScalarSize];
        int[] inputIndices = new int[count];
        int[] outputIndices = new int[count];

        byte[] twiddle = new byte[ScalarSize];
        byte[] low = new byte[stride * ScalarSize];
        byte[] high = new byte[stride * ScalarSize];

        Gf2k128BatchBackend.GetBatchMultiplyAccumulate()(left, right, accumulators, accumulate: true, count, CurveParameterSet.None);
        Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate()(scalar, right, accumulators, accumulate: true, count, CurveParameterSet.None);
        Gf2k128BatchBackend.GetGatherMultiplyAccumulate()(left, data, inputIndices, outputIndices, accumulators, count, CurveParameterSet.None);
        Gf2k128BatchBackend.GetButterflyBatch()(twiddle, low, high, stride, CurveParameterSet.None);

        //Three count-sized FMA ops plus one stride-sized butterfly all roll up into the one kind.
        long expected = (3L * count) + stride;
        Assert.AreEqual(expected, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarBatchMultiplyAccumulate),
            "The FMA family should increment ScalarBatchMultiplyAccumulate by the summed counts.");
    }


    [TestMethod]
    public void BindQuadReduceIncrementsTheFmaKindByThreeTimesCount()
    {
        //Three reduced multiplies per term (the chained product), rolled into the one FMA kind.
        const int count = 7;
        CryptographicOperationCounters.IsCountingEnabled = true;

        byte[] coefficientTable = new byte[count * ScalarSize];
        byte[] beta = new byte[ScalarSize];
        byte[] eqg = new byte[count * ScalarSize];
        byte[] eqh0 = new byte[count * ScalarSize];
        byte[] eqh1 = new byte[count * ScalarSize];
        int[] coefficientIndices = new int[count];
        int[] gateIndices = new int[count];
        int[] leftIndices = new int[count];
        int[] rightIndices = new int[count];
        byte[] isZeroFlags = new byte[count];
        byte[] accumulator = new byte[ScalarSize];

        Gf2k128BatchBackend.GetBindQuadReduce()(
            coefficientTable, coefficientIndices, beta, eqg, eqh0, eqh1, gateIndices, leftIndices, rightIndices, isZeroFlags, count, accumulator, CurveParameterSet.None);

        Assert.AreEqual(3L * count, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarBatchMultiplyAccumulate),
            "BindQuadReduce should increment ScalarBatchMultiplyAccumulate by three times the term count.");
    }


    [TestMethod]
    public void CountsStayAtZeroWhenCountingDisabled()
    {
        const int count = 4;
        //Counting is disabled by Initialize.
        byte[] left = new byte[count * ScalarSize];
        byte[] right = new byte[count * ScalarSize];
        byte[] accumulators = new byte[count * ScalarSize];

        Gf2k128BatchBackend.GetBatchMultiplyAccumulate()(left, right, accumulators, accumulate: true, count, CurveParameterSet.None);

        Assert.AreEqual(0, CryptographicOperationCounters.GetCount(CryptographicOperationKind.ScalarBatchMultiplyAccumulate),
            "No counts should accrue while counting is disabled.");
    }
}

using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Byte-identical agreement between the batch and fused-multiply-accumulate
/// <see cref="Gf2k128BatchBackend"/> and the per-scalar <see cref="Gf2k128Reference"/> oracle loop —
/// the established two-backend agreement pattern extended to the vector seam. Every batch op is
/// checked against the obvious per-element reference loop over random deterministic-seed spans at
/// edge sizes (0, 1, odd, large). The deferred-reduction FMA is additionally checked against a
/// naive multiply-then-add-then-reduce-each-step loop so the deferral is shown mathematically
/// invisible. The packed unpack/pack representation is pinned by a round-trip property test.
/// </summary>
/// <remarks>
/// The pairing is deliberate and recurs across this codebase: the optimised batch backend keeps a
/// slow, independently-written reference twin (the BigInteger <see cref="Gf2k128Reference"/>), and
/// the gate is BYTE-IDENTITY on shared inputs, not plausibility. The reference reduces on every
/// multiply; the batch FMA defers the <c>0x87</c> fold to once per accumulation — so this suite is
/// the proof the deferral does not drift.
/// </remarks>
[TestClass]
internal sealed class Gf2k128BatchBackendAgreementTests
{
    private const int ScalarSize = 32;
    private const int ElementOffset = 16;

    //Edge sizes: empty, single, an odd non-trivial count, and a large run that exercises the
    //per-element loop well past any tail.
    private static readonly int[] BatchSizes = [0, 1, 2, 3, 7, 64, 257];

    private static ScalarMultiplyDelegate ReferenceMultiply { get; } = Gf2k128Reference.GetMultiply();

    private static ScalarAddDelegate ReferenceAdd { get; } = Gf2k128Reference.GetAdd();

    private static ScalarBatchMultiplyDelegate BatchMultiply { get; } = Gf2k128BatchBackend.GetBatchMultiply();

    private static ScalarBatchAddDelegate BatchAdd { get; } = Gf2k128BatchBackend.GetBatchAdd();

    private static ScalarBatchSubtractDelegate BatchSubtract { get; } = Gf2k128BatchBackend.GetBatchSubtract();

    private static ScalarBatchMultiplyAccumulateDelegate BatchMultiplyAccumulate { get; } = Gf2k128BatchBackend.GetBatchMultiplyAccumulate();

    private static ScalarBroadcastMultiplyAccumulateDelegate BroadcastMultiplyAccumulate { get; } = Gf2k128BatchBackend.GetBroadcastMultiplyAccumulate();

    private static ScalarGatherMultiplyAccumulateDelegate GatherMultiplyAccumulate { get; } = Gf2k128BatchBackend.GetGatherMultiplyAccumulate();

    private static Gf2kButterflyBatchDelegate ButterflyBatch { get; } = Gf2k128BatchBackend.GetButterflyBatch();

    private static ScalarBindQuadReduceDelegate BindQuadReduce { get; } = Gf2k128BatchBackend.GetBindQuadReduce();


    [TestMethod]
    public void BatchMultiplyAgreesWithTheReferenceLoop()
    {
        foreach(int count in BatchSizes)
        {
            byte[] left = RandomElements(count, seed: 11);
            byte[] right = RandomElements(count, seed: 23);
            byte[] actual = new byte[count * ScalarSize];
            byte[] expected = new byte[count * ScalarSize];

            BatchMultiply(left, right, actual, count, CurveParameterSet.None);
            for(int i = 0; i < count; i++)
            {
                int offset = i * ScalarSize;
                ReferenceMultiply(left.AsSpan(offset, ScalarSize), right.AsSpan(offset, ScalarSize), expected.AsSpan(offset, ScalarSize), CurveParameterSet.None);
            }

            Assert.IsTrue(actual.AsSpan().SequenceEqual(expected), $"BatchMultiply must agree with the reference loop at count {count}.");
        }
    }


    [TestMethod]
    public void BatchAddAndSubtractAgreeWithTheReferenceLoop()
    {
        foreach(int count in BatchSizes)
        {
            byte[] left = RandomElements(count, seed: 31);
            byte[] right = RandomElements(count, seed: 47);
            byte[] actualAdd = new byte[count * ScalarSize];
            byte[] actualSubtract = new byte[count * ScalarSize];
            byte[] expected = new byte[count * ScalarSize];

            BatchAdd(left, right, actualAdd, count, CurveParameterSet.None);
            BatchSubtract(left, right, actualSubtract, count, CurveParameterSet.None);
            for(int i = 0; i < count; i++)
            {
                int offset = i * ScalarSize;
                ReferenceAdd(left.AsSpan(offset, ScalarSize), right.AsSpan(offset, ScalarSize), expected.AsSpan(offset, ScalarSize), CurveParameterSet.None);
            }

            Assert.IsTrue(actualAdd.AsSpan().SequenceEqual(expected), $"BatchAdd must agree with the reference loop at count {count}.");
            Assert.IsTrue(actualSubtract.AsSpan().SequenceEqual(expected), $"BatchSubtract must equal add in characteristic two at count {count}.");
        }
    }


    [TestMethod]
    public void BatchMultiplyAccumulateOverwriteEqualsBatchMultiply()
    {
        //accumulate == false gives plain batch-multiply for free; it must equal the reference loop.
        foreach(int count in BatchSizes)
        {
            byte[] left = RandomElements(count, seed: 53);
            byte[] right = RandomElements(count, seed: 67);
            byte[] actual = RandomElements(count, seed: 71);
            byte[] expected = new byte[count * ScalarSize];

            BatchMultiplyAccumulate(left, right, actual, accumulate: false, count, CurveParameterSet.None);
            for(int i = 0; i < count; i++)
            {
                int offset = i * ScalarSize;
                ReferenceMultiply(left.AsSpan(offset, ScalarSize), right.AsSpan(offset, ScalarSize), expected.AsSpan(offset, ScalarSize), CurveParameterSet.None);
            }

            Assert.IsTrue(actual.AsSpan().SequenceEqual(expected), $"FMA overwrite must equal the reference multiply at count {count}.");
        }
    }


    [TestMethod]
    public void DeferredFmaIsByteIdenticalToNaiveMultiplyThenAddThenReduce()
    {
        //The decisive gate: the deferred-reduction accumulate must equal the naive per-step loop
        //that reduces every multiply before adding. acc[i] += a[i]·b[i] starting from a non-zero
        //accumulator so the read-modify-write is exercised.
        Span<byte> product = stackalloc byte[ScalarSize];
        foreach(int count in BatchSizes)
        {
            byte[] left = RandomElements(count, seed: 83);
            byte[] right = RandomElements(count, seed: 97);
            byte[] seedAccumulator = RandomElements(count, seed: 101);

            byte[] actual = (byte[])seedAccumulator.Clone();
            BatchMultiplyAccumulate(left, right, actual, accumulate: true, count, CurveParameterSet.None);

            byte[] expected = (byte[])seedAccumulator.Clone();
            for(int i = 0; i < count; i++)
            {
                int offset = i * ScalarSize;
                ReferenceMultiply(left.AsSpan(offset, ScalarSize), right.AsSpan(offset, ScalarSize), product, CurveParameterSet.None);
                ReferenceAdd(expected.AsSpan(offset, ScalarSize), product, expected.AsSpan(offset, ScalarSize), CurveParameterSet.None);
            }

            Assert.IsTrue(actual.AsSpan().SequenceEqual(expected), $"Deferred FMA must equal naive multiply-then-add-then-reduce at count {count}.");
        }
    }


    [TestMethod]
    public void BroadcastMultiplyAccumulateAgreesWithTheReferenceLoop()
    {
        Span<byte> product = stackalloc byte[ScalarSize];
        foreach(int count in BatchSizes)
        {
            byte[] scalar = RandomElements(1, seed: 103);
            byte[] operands = RandomElements(count, seed: 107);
            byte[] seedAccumulator = RandomElements(count, seed: 109);

            byte[] actual = (byte[])seedAccumulator.Clone();
            BroadcastMultiplyAccumulate(scalar, operands, actual, accumulate: true, count, CurveParameterSet.None);

            byte[] expected = (byte[])seedAccumulator.Clone();
            for(int i = 0; i < count; i++)
            {
                int offset = i * ScalarSize;
                ReferenceMultiply(scalar, operands.AsSpan(offset, ScalarSize), product, CurveParameterSet.None);
                ReferenceAdd(expected.AsSpan(offset, ScalarSize), product, expected.AsSpan(offset, ScalarSize), CurveParameterSet.None);
            }

            Assert.IsTrue(actual.AsSpan().SequenceEqual(expected), $"Broadcast FMA must agree with the reference loop at count {count}.");
        }
    }


    [TestMethod]
    public void BroadcastMultiplyAccumulateOverwriteEqualsTheReferenceProduct()
    {
        //The overwrite (accumulate:false) branch is what filleq consumes; pin it directly against the
        //reference product, the broadcast counterpart of BatchMultiplyAccumulateOverwriteEqualsBatchMultiply.
        foreach(int count in BatchSizes)
        {
            byte[] scalar = RandomElements(1, seed: 211);
            byte[] operands = RandomElements(count, seed: 223);

            //A non-zero seed proves the overwrite ignores the prior accumulator contents.
            byte[] actual = RandomElements(count, seed: 227);
            BroadcastMultiplyAccumulate(scalar, operands, actual, accumulate: false, count, CurveParameterSet.None);

            byte[] expected = new byte[count * ScalarSize];
            for(int i = 0; i < count; i++)
            {
                int offset = i * ScalarSize;
                ReferenceMultiply(scalar, operands.AsSpan(offset, ScalarSize), expected.AsSpan(offset, ScalarSize), CurveParameterSet.None);
            }

            Assert.IsTrue(actual.AsSpan().SequenceEqual(expected), $"Broadcast FMA overwrite must equal the reference product at count {count}.");
        }
    }


    [TestMethod]
    public void GatherMultiplyAccumulateAgreesWithTheReferenceLoop()
    {
        //Indices walk the data table forward and the output slots backward so reads and writes
        //genuinely gather/scatter, and two terms hit the same output slot to exercise the fold.
        Span<byte> product = stackalloc byte[ScalarSize];
        foreach(int count in BatchSizes)
        {
            if(count == 0)
            {
                byte[] emptyAcc = [];
                GatherMultiplyAccumulate([], [], [], [], emptyAcc, 0, CurveParameterSet.None);
                continue;
            }

            int tableSize = count;
            byte[] coefficients = RandomElements(count, seed: 113);
            byte[] data = RandomElements(tableSize, seed: 127);
            byte[] seedAccumulator = RandomElements(tableSize, seed: 131);

            //Consecutive pairs share an output slot so the backend's multi-product deferred-
            //reduction run is exercised, while the input gather still jumps around the table.
            int[] inputIndices = new int[count];
            int[] outputIndices = new int[count];
            for(int k = 0; k < count; k++)
            {
                inputIndices[k] = (k * 5) % tableSize;
                outputIndices[k] = ((k / 2) * 3) % tableSize;
            }

            byte[] actual = (byte[])seedAccumulator.Clone();
            GatherMultiplyAccumulate(coefficients, data, inputIndices, outputIndices, actual, count, CurveParameterSet.None);

            byte[] expected = (byte[])seedAccumulator.Clone();
            for(int k = 0; k < count; k++)
            {
                int coeffOffset = k * ScalarSize;
                int dataOffset = inputIndices[k] * ScalarSize;
                int outOffset = outputIndices[k] * ScalarSize;
                ReferenceMultiply(coefficients.AsSpan(coeffOffset, ScalarSize), data.AsSpan(dataOffset, ScalarSize), product, CurveParameterSet.None);
                ReferenceAdd(expected.AsSpan(outOffset, ScalarSize), product, expected.AsSpan(outOffset, ScalarSize), CurveParameterSet.None);
            }

            Assert.IsTrue(actual.AsSpan().SequenceEqual(expected), $"Gather FMA must agree with the reference loop at count {count}.");
        }
    }


    [TestMethod]
    public void GatherMultiplyAccumulateWithConsecutiveDuplicateOutputSlotsAgreesWithTheReferenceLoop()
    {
        //outputIndices[k] = k/2 produces a consecutive duplicate at every pair (run length 2),
        //exercising the deferred-reduction run at the smallest non-trivial length for every size.
        Span<byte> product = stackalloc byte[ScalarSize];
        foreach(int count in BatchSizes)
        {
            if(count == 0)
            {
                byte[] emptyAcc = [];
                GatherMultiplyAccumulate([], [], [], [], emptyAcc, 0, CurveParameterSet.None);
                continue;
            }

            int tableSize = count;
            byte[] coefficients = RandomElements(count, seed: 157);
            byte[] data = RandomElements(tableSize, seed: 163);
            byte[] seedAccumulator = RandomElements(tableSize, seed: 167);

            //Every consecutive pair of terms maps to the same output slot (run length 2 throughout).
            int[] inputIndices = new int[count];
            int[] outputIndices = new int[count];
            for(int k = 0; k < count; k++)
            {
                inputIndices[k] = (k * 3) % tableSize;
                outputIndices[k] = k / 2;
            }

            byte[] actual = (byte[])seedAccumulator.Clone();
            GatherMultiplyAccumulate(coefficients, data, inputIndices, outputIndices, actual, count, CurveParameterSet.None);

            byte[] expected = (byte[])seedAccumulator.Clone();
            for(int k = 0; k < count; k++)
            {
                int coeffOffset = k * ScalarSize;
                int dataOffset = inputIndices[k] * ScalarSize;
                int outOffset = outputIndices[k] * ScalarSize;
                ReferenceMultiply(coefficients.AsSpan(coeffOffset, ScalarSize), data.AsSpan(dataOffset, ScalarSize), product, CurveParameterSet.None);
                ReferenceAdd(expected.AsSpan(outOffset, ScalarSize), product, expected.AsSpan(outOffset, ScalarSize), CurveParameterSet.None);
            }

            Assert.IsTrue(actual.AsSpan().SequenceEqual(expected), $"Gather FMA with consecutive duplicate output slots must agree with the reference loop at count {count}.");
        }
    }


    [TestMethod]
    public void GatherMultiplyAccumulateRejectsAnAccumulatorOverlappingTheInputs()
    {
        //A run's reduced sum is written into the accumulator before later runs gather their inputs,
        //so an accumulator slot aliasing a data slot would feed a corrupted value forward. The
        //contract forbids the overlap and the backend rejects it instead of computing wrong bytes —
        //the foot-gun the prover-rewiring stage would otherwise hit with in-place accumulation.
        const int count = 4;
        byte[] coefficients = RandomElements(count, seed: 173);
        byte[] table = RandomElements(count, seed: 179);
        int[] inputIndices = [0, 1, 2, 3];
        int[] outputIndices = [3, 2, 1, 0];

        Assert.ThrowsExactly<ArgumentException>(() =>
            GatherMultiplyAccumulate(coefficients, table, inputIndices, outputIndices, table, count, CurveParameterSet.None),
            "An accumulator span aliasing the data span must be rejected.");
        Assert.ThrowsExactly<ArgumentException>(() =>
            GatherMultiplyAccumulate(coefficients, table, inputIndices, outputIndices, coefficients, count, CurveParameterSet.None),
            "An accumulator span aliasing the coefficient span must be rejected.");
    }


    [TestMethod]
    public void ButterflyBatchAgreesWithThePerElementButterfly()
    {
        Span<byte> product = stackalloc byte[ScalarSize];
        foreach(int stride in BatchSizes)
        {
            byte[] twiddle = RandomElements(1, seed: 137);
            byte[] low = RandomElements(stride, seed: 139);
            byte[] high = RandomElements(stride, seed: 149);

            byte[] actualLow = (byte[])low.Clone();
            byte[] actualHigh = (byte[])high.Clone();
            ButterflyBatch(twiddle, actualLow, actualHigh, stride, CurveParameterSet.None);

            byte[] expectedLow = (byte[])low.Clone();
            byte[] expectedHigh = (byte[])high.Clone();
            for(int offset = 0; offset < stride; offset++)
            {
                int slot = offset * ScalarSize;
                //low += twiddle·high; high += low (the just-updated low).
                ReferenceMultiply(twiddle, expectedHigh.AsSpan(slot, ScalarSize), product, CurveParameterSet.None);
                ReferenceAdd(expectedLow.AsSpan(slot, ScalarSize), product, expectedLow.AsSpan(slot, ScalarSize), CurveParameterSet.None);
                ReferenceAdd(expectedHigh.AsSpan(slot, ScalarSize), expectedLow.AsSpan(slot, ScalarSize), expectedHigh.AsSpan(slot, ScalarSize), CurveParameterSet.None);
            }

            Assert.IsTrue(actualLow.AsSpan().SequenceEqual(expectedLow), $"Butterfly low half must agree at stride {stride}.");
            Assert.IsTrue(actualHigh.AsSpan().SequenceEqual(expectedHigh), $"Butterfly high half must agree at stride {stride}.");
        }
    }


    [TestMethod]
    public void PackUnpackRoundTripsTheCanonicalSlot()
    {
        //pack(unpack(slot)) == slot for canonical inputs, and unpack(pack(h,l)) == (h,l).
        byte[] elements = RandomElements(64, seed: 151);
        Span<byte> repacked = stackalloc byte[ScalarSize];
        for(int i = 0; i < 64; i++)
        {
            ReadOnlySpan<byte> slot = elements.AsSpan(i * ScalarSize, ScalarSize);
            (ulong high, ulong low) = Gf2k128BatchBackend.Unpack(slot);
            Gf2k128BatchBackend.Pack(high, low, repacked);
            Assert.IsTrue(repacked.SequenceEqual(slot), $"pack(unpack(slot)) must equal the canonical slot for element {i}.");

            (ulong reHigh, ulong reLow) = Gf2k128BatchBackend.Unpack(repacked);
            Assert.AreEqual(high, reHigh, $"unpack(pack(h,l)) high limb must round-trip for element {i}.");
            Assert.AreEqual(low, reLow, $"unpack(pack(h,l)) low limb must round-trip for element {i}.");
        }
    }


    [TestMethod]
    public void TheSoftwareMultiplyReducePathMatchesTheReference()
    {
        //The intrinsic path runs on this hardware; the portable software multiply-reduce path
        //(the same deferred-reduction lanes, but never touching PCLMULQDQ) is gated explicitly
        //against the per-scalar reference, so it cannot silently rot.
        byte[] left = RandomElements(128, seed: 211);
        byte[] right = RandomElements(128, seed: 223);
        Span<byte> expected = stackalloc byte[ScalarSize];
        Span<byte> actual = stackalloc byte[ScalarSize];
        for(int i = 0; i < 128; i++)
        {
            int offset = i * ScalarSize;
            ReadOnlySpan<byte> a = left.AsSpan(offset, ScalarSize);
            ReadOnlySpan<byte> b = right.AsSpan(offset, ScalarSize);

            (ulong leftHigh, ulong leftLow) = Gf2k128BatchBackend.Unpack(a);
            (ulong rightHigh, ulong rightLow) = Gf2k128BatchBackend.Unpack(b);
            (ulong productHigh, ulong productLow) = Gf2k128BatchBackend.SoftwareMultiplyReduce(leftHigh, leftLow, rightHigh, rightLow);
            Gf2k128BatchBackend.Pack(productHigh, productLow, actual);

            ReferenceMultiply(a, b, expected, CurveParameterSet.None);
            Assert.IsTrue(actual.SequenceEqual(expected), $"The software multiply-reduce path must match the reference for element {i}.");
        }
    }


    [TestMethod]
    public void BindQuadReduceIsByteIdenticalToTheChainedScalarReduce()
    {
        //The decisive gate: the fused bind_quad reduce must equal a literal port of the ReduceRange
        //chain — scaled-v select via the zero flag, three reference multiplies chained (each reducing
        //BEFORE the next consumes it), reference XOR-add accumulate into a caller-cleared slot. This
        //gate has teeth: if reduction were deferred across the chain (reduce(a)·b != reduce(a·b) for
        //the limb representation) the bytes would diverge here.
        foreach(int count in BatchSizes)
        {
            BindQuadReduceCase(count, BindQuadReduce, $"BindQuadReduce must equal the chained scalar reduce at count {count}.");
        }
    }


    [TestMethod]
    public void SoftwareBindQuadReduceIsByteIdenticalToTheChainedScalarReduce()
    {
        //The same gate over the forced-software CLMUL tier, so it cannot silently rot on hardware that
        //would otherwise always take the intrinsic.
        foreach(int count in BatchSizes)
        {
            BindQuadReduceCase(count, Gf2k128BatchBackend.SoftwareBindQuadReduce, $"SoftwareBindQuadReduce must equal the chained scalar reduce at count {count}.");
        }
    }


    [TestMethod]
    public void BindQuadReducePartitionedAndCombinedEqualsTheWholeRange()
    {
        //The fused BindQuad route (LongfellowZkConstraintBuilder.BindQuadFused) partitions [0, termCount)
        //into P contiguous chunks with the long-arithmetic bounds it shares with the trusted scalar parallel
        //reduction, runs the primitive per chunk into its own partials slot, and XOR-combines the partials in
        //chunk-index order. This pins that property DIRECTLY at a count above the parallel threshold (4096):
        //partition + XOR-combine must equal one whole-range call AND the independent reference. It catches a
        //partition-bounds or combine-order regression in the fast suite rather than only at the [Slow] crown
        //gate, which is the sole large-count coverage of the parallel path otherwise.
        const int Count = 8192;
        const int PartitionCount = 4;

        int tableSize = Count;
        int nv = Count;
        int nw = Count;
        byte[] coefficientTable = RandomElements(tableSize, seed: 311);
        byte[] beta = RandomElements(1, seed: 313);
        byte[] eqg = RandomElements(nv, seed: 317);
        byte[] eqh0 = RandomElements(nw, seed: 331);
        byte[] eqh1 = RandomElements(nw, seed: 337);

        int[] coefficientIndices = new int[Count];
        int[] gateIndices = new int[Count];
        int[] leftIndices = new int[Count];
        int[] rightIndices = new int[Count];
        byte[] isZeroFlags = new byte[Count];
        for(int k = 0; k < Count; k++)
        {
            coefficientIndices[k] = ((k * 7) + 3) % tableSize;
            gateIndices[k] = (k * 5) % nv;
            leftIndices[k] = (k * 11) % nw;
            rightIndices[k] = (k * 13) % nw;
            isZeroFlags[k] = (byte)(((k * 3) % 5 == 0) ? 1 : 0);
        }

        //One whole-range call.
        byte[] whole = new byte[ScalarSize];
        BindQuadReduce(coefficientTable, coefficientIndices, beta, eqg, eqh0, eqh1, gateIndices, leftIndices, rightIndices, isZeroFlags, Count, whole, CurveParameterSet.None);

        //Partition + XOR-combine, mirroring BindQuadFused's bounds and combine order. The tables and beta are
        //passed whole (the indices address the whole tables); only the per-term index spans are sub-sliced.
        byte[] combined = new byte[ScalarSize];
        for(int partition = 0; partition < PartitionCount; partition++)
        {
            int start = (int)((long)partition * Count / PartitionCount);
            int end = (int)((long)(partition + 1) * Count / PartitionCount);
            int count = end - start;

            byte[] partial = new byte[ScalarSize];
            BindQuadReduce(
                coefficientTable, coefficientIndices.AsSpan(start, count), beta, eqg, eqh0, eqh1,
                gateIndices.AsSpan(start, count), leftIndices.AsSpan(start, count), rightIndices.AsSpan(start, count),
                isZeroFlags.AsSpan(start, count), count, partial, CurveParameterSet.None);

            //GF(2^128) add is byte XOR over the canonical slot (the high sixteen bytes are zero on both).
            for(int b = 0; b < ScalarSize; b++)
            {
                combined[b] ^= partial[b];
            }
        }

        byte[] expected = ReferenceBindQuadReduce(coefficientTable, coefficientIndices, beta, eqg, eqh0, eqh1, gateIndices, leftIndices, rightIndices, isZeroFlags, Count);

        Assert.IsTrue(whole.AsSpan().SequenceEqual(combined), "Partition + XOR-combine must equal the whole-range bind_quad reduce above the parallel threshold.");
        Assert.IsTrue(whole.AsSpan().SequenceEqual(expected), "The whole-range bind_quad reduce must equal the independent reference at count 8192.");
    }


    //One byte-identity case: builds random tables and per-term in-range indices and zero flags, runs the
    //primitive into a cleared accumulator, and compares against the literal ReduceRange chain port.
    private static void BindQuadReduceCase(int count, ScalarBindQuadReduceDelegate primitive, string message)
    {
        //Distinct table sizes so the index spaces genuinely differ and the slices are exercised.
        int tableSize = Math.Max(count, 1);
        int nv = Math.Max(count, 1);
        int nw = Math.Max(count, 1);

        byte[] coefficientTable = RandomElements(tableSize, seed: 311);
        byte[] beta = RandomElements(1, seed: 313);
        byte[] eqg = RandomElements(nv, seed: 317);
        byte[] eqh0 = RandomElements(nw, seed: 331);
        byte[] eqh1 = RandomElements(nw, seed: 337);

        int[] coefficientIndices = new int[count];
        int[] gateIndices = new int[count];
        int[] leftIndices = new int[count];
        int[] rightIndices = new int[count];
        byte[] isZeroFlags = new byte[count];
        for(int k = 0; k < count; k++)
        {
            coefficientIndices[k] = ((k * 7) + 3) % tableSize;
            gateIndices[k] = (k * 5) % nv;
            leftIndices[k] = (k * 11) % nw;
            rightIndices[k] = (k * 13) % nw;

            //A spread of zero flags so both the beta and the coefficient branch are exercised.
            isZeroFlags[k] = (byte)(((k * 3) % 5 == 0) ? 1 : 0);
        }

        byte[] actual = new byte[ScalarSize];
        primitive(coefficientTable, coefficientIndices, beta, eqg, eqh0, eqh1, gateIndices, leftIndices, rightIndices, isZeroFlags, count, actual, CurveParameterSet.None);

        byte[] expected = ReferenceBindQuadReduce(coefficientTable, coefficientIndices, beta, eqg, eqh0, eqh1, gateIndices, leftIndices, rightIndices, isZeroFlags, count);

        Assert.IsTrue(actual.AsSpan().SequenceEqual(expected), message);
    }


    //A literal C# port of the ReduceRange chain: per term scaled-v = (isZero ? beta : coefficient),
    //chain = scaled-v · eqg[g] · eqh0[h0] · eqh1[h1] (three reference multiplies, each reducing before
    //the next), accumulator ^= chain (reference XOR add), into a caller-cleared accumulator.
    private static byte[] ReferenceBindQuadReduce(
        byte[] coefficientTable,
        int[] coefficientIndices,
        byte[] beta,
        byte[] eqg,
        byte[] eqh0,
        byte[] eqh1,
        int[] gateIndices,
        int[] leftIndices,
        int[] rightIndices,
        byte[] isZeroFlags,
        int count)
    {
        byte[] accumulator = new byte[ScalarSize];
        Span<byte> chain = stackalloc byte[ScalarSize];
        Span<byte> sum = stackalloc byte[ScalarSize];
        for(int k = 0; k < count; k++)
        {
            ReadOnlySpan<byte> scaledV = isZeroFlags[k] != 0 ? beta.AsSpan() : coefficientTable.AsSpan(coefficientIndices[k] * ScalarSize, ScalarSize);
            ReferenceMultiply(scaledV, eqg.AsSpan(gateIndices[k] * ScalarSize, ScalarSize), chain, CurveParameterSet.None);
            ReferenceMultiply(chain, eqh0.AsSpan(leftIndices[k] * ScalarSize, ScalarSize), chain, CurveParameterSet.None);
            ReferenceMultiply(chain, eqh1.AsSpan(rightIndices[k] * ScalarSize, ScalarSize), chain, CurveParameterSet.None);

            ReferenceAdd(accumulator, chain, sum, CurveParameterSet.None);
            sum.CopyTo(accumulator);
        }

        return accumulator;
    }


    //Deterministic pseudo-random canonical elements: each 32-byte slot has its high sixteen bytes
    //zero (the GF(2^128) value lives in the low sixteen), matching the canonical layout the seam
    //consumes and produces. The byte formula mirrors the established deterministic-seed pattern in
    //Gf2k128BackendAgreementTests — no Random, fully reproducible across runs.
    private static byte[] RandomElements(int count, int seed)
    {
        byte[] buffer = new byte[count * ScalarSize];
        for(int i = 0; i < count; i++)
        {
            int elementStart = (i * ScalarSize) + ElementOffset;
            for(int b = 0; b < ScalarSize - ElementOffset; b++)
            {
                buffer[elementStart + b] = (byte)((181 * ((i * 16) + b)) + (97 * seed) + 29);
            }
        }

        return buffer;
    }
}

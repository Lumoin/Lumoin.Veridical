using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Direct agreement tests for the AVX-512 VPCLMULQDQ GF(2^128) four-element wide kernels in
/// <see cref="Gf2k128Vpclmulqdq"/>, called past the <see cref="Gf2k128BatchBackend"/> dispatch
/// facade so the wide path itself is pinned rather than whichever backend the facade happens to
/// pick on this host. Ground truth is the per-scalar BigInteger <see cref="Gf2k128Reference"/>
/// oracle applied element-by-element over the exact canonical 32-byte slots the wide kernels
/// consume; the kernels only ever handle whole four-element groups, so every comparison is
/// restricted to the <c>count &amp; ~3</c> elements a kernel call actually returns, with the tail
/// left to the caller's scalar loop.
/// </summary>
/// <remarks>
/// Inconclusive when the host CPU lacks the AVX-512F + 512-bit carry-less multiply + AVX-512BW
/// combination the kernels require — most consumer x64 chips and all ARM hosts — so these tests
/// light up only on Sapphire Rapids / Zen 4+ silicon. Without them the wide kernels are exercised
/// only indirectly through the dispatch facade, and only on hosts where the facade picks them.
/// </remarks>
[TestClass]
internal sealed class Gf2k128VpclmulqdqAgreementTests
{
    /// <summary>The canonical big-endian scalar slot width every GF(2^128) element rides in.</summary>
    private const int ScalarSize = 32;

    /// <summary>The width of one raw element draw: exactly the 128-bit field width, so embedding it into a canonical slot needs no polynomial reduction.</summary>
    private const int ElementSizeBytes = 16;

    /// <summary>Below one four-wide group: the kernel returns zero and the whole batch is left to the caller's scalar tail loop.</summary>
    private const int BelowGroupCount = 3;

    /// <summary>Exactly one four-wide group and no tail — the smallest size the wide kernel itself does any work at.</summary>
    private const int ExactGroupCount = 4;

    /// <summary>Sixteen full groups plus a two-element tail (<c>4k + 2</c>), the smallest non-trivial multi-group remainder.</summary>
    private const int LargeCountWithTwoTail = 66;

    /// <summary>Sixty-four full groups plus a three-element tail (<c>4k + 3</c>), the largest possible remainder below the next group.</summary>
    private const int LargeCountWithThreeTail = 259;

    /// <summary>The batch sizes this class exercises: below one group, exactly one group, and two large multi-group non-multiple-of-four remainders.</summary>
    private static int[] BatchSizes { get; } = [BelowGroupCount, ExactGroupCount, LargeCountWithTwoTail, LargeCountWithThreeTail];

    /// <summary>The canonical byte length of the largest batch this class exercises; the fixed structural (non-CsCheck) tests stackalloc once at this width and slice per batch size so the allocation sits outside the loop over BatchSizes.</summary>
    private const int MaxScalarBufferByteLength = LargeCountWithThreeTail * ScalarSize;

    /// <summary>CsCheck sample count per batch size; the kernels are pure and data-independent, so a moderate draw count already exercises every code path repeatedly.</summary>
    private const long IterationCount = 30;

    /// <summary>The byte the tail-untouched tests pre-fill result and accumulator buffers with; non-zero so an accidental clear-to-zero would also be caught.</summary>
    private const byte TailSentinel = 0xCC;

    /// <summary>The per-scalar carry-less multiply oracle every wide-kernel comparison reduces to.</summary>
    private static ScalarMultiplyDelegate ReferenceMultiply { get; } = Gf2k128Reference.GetMultiply();

    /// <summary>The per-scalar XOR-add oracle used to fold products into accumulators, matching characteristic two.</summary>
    private static ScalarAddDelegate ReferenceAdd { get; } = Gf2k128Reference.GetAdd();

    /// <summary>The per-scalar reduce oracle used to embed a raw 16-byte draw into a canonical 32-byte slot.</summary>
    private static ScalarReduceDelegate ReferenceReduce { get; } = Gf2k128Reference.GetReduce();


    /// <summary>Gates the whole class Inconclusive on hosts without AVX-512F + 512-bit VPCLMULQDQ + AVX-512BW.</summary>
    [TestInitialize]
    public void RequireVpclmulqdq() => InstructionSetRequirements.RequireAvx512Vpclmulqdq();


    /// <summary>Pins that the test gate and the kernel's own capability check agree: once RequireAvx512Vpclmulqdq lets the test run, IsSupported must also report true.</summary>
    [TestMethod]
    public void IsSupportedIsTrueAfterTheGatePasses()
    {
        Assert.IsTrue(Gf2k128Vpclmulqdq.IsSupported, "IsSupported must be true whenever RequireAvx512Vpclmulqdq lets the test run.");
    }


    /// <summary>BatchMultiply agrees with the per-element reference over every wide-covered element, at every batch size, and reports the consumed count as count rounded down to a multiple of four.</summary>
    [TestMethod]
    public void BatchMultiplyAgreesWithTheReferenceLoop()
    {
        foreach(int count in BatchSizes)
        {
            int wideCount = count & ~(Gf2k128Vpclmulqdq.WideElementCount - 1);
            Gen<byte[]> rawGen = Gen.Byte.Array[count * ElementSizeBytes];
            Gen.Select(rawGen, rawGen).Sample((leftRaw, rightRaw) =>
            {
                Span<byte> left = stackalloc byte[count * ScalarSize];
                Span<byte> right = stackalloc byte[count * ScalarSize];
                Span<byte> results = stackalloc byte[count * ScalarSize];
                Span<byte> expected = stackalloc byte[wideCount * ScalarSize];
                BuildCanonicalElements(leftRaw, left, count);
                BuildCanonicalElements(rightRaw, right, count);

                int consumed = Gf2k128Vpclmulqdq.BatchMultiply(left, right, results, count);
                ReferenceMultiplyElements(left, right, expected, wideCount);

                return consumed == wideCount && results[..(wideCount * ScalarSize)].SequenceEqual(expected);
            }, iter: IterationCount);
        }
    }


    /// <summary>Every kernel call touches exactly its consumed prefix; the caller-owned tail past count rounded down to four stays byte-for-byte as it was found.</summary>
    [TestMethod]
    public void BatchMultiplyReturnsCountRoundedDownAndLeavesTheTailUntouched()
    {
        Span<byte> leftBuffer = stackalloc byte[MaxScalarBufferByteLength];
        Span<byte> rightBuffer = stackalloc byte[MaxScalarBufferByteLength];
        Span<byte> resultsBuffer = stackalloc byte[MaxScalarBufferByteLength];
        foreach(int count in BatchSizes)
        {
            int wideCount = count & ~(Gf2k128Vpclmulqdq.WideElementCount - 1);
            Span<byte> left = leftBuffer[..(count * ScalarSize)];
            Span<byte> right = rightBuffer[..(count * ScalarSize)];
            Span<byte> results = resultsBuffer[..(count * ScalarSize)];
            FillDeterministicElements(left, count, seed: 1);
            FillDeterministicElements(right, count, seed: 2);
            results.Fill(TailSentinel);

            int consumed = Gf2k128Vpclmulqdq.BatchMultiply(left, right, results, count);

            Assert.AreEqual(wideCount, consumed, $"BatchMultiply must consume count rounded down to a multiple of four at count {count}.");
            AssertTailUntouched(results, wideCount, count, $"BatchMultiply must leave the tail slots untouched at count {count}.");
        }
    }


    /// <summary>A results span that is the SAME buffer as the left operand, at identical offsets, still agrees with the reference computed from a pristine copy taken before the call.</summary>
    [TestMethod]
    public void BatchMultiplyWithResultsAliasingTheLeftOperandAgreesWithThePristineReference()
    {
        foreach(int count in BatchSizes)
        {
            int wideCount = count & ~(Gf2k128Vpclmulqdq.WideElementCount - 1);
            Gen<byte[]> rawGen = Gen.Byte.Array[count * ElementSizeBytes];
            Gen.Select(rawGen, rawGen).Sample((leftRaw, rightRaw) =>
            {
                Span<byte> left = stackalloc byte[count * ScalarSize];
                Span<byte> right = stackalloc byte[count * ScalarSize];
                Span<byte> pristineLeft = stackalloc byte[count * ScalarSize];
                BuildCanonicalElements(leftRaw, left, count);
                BuildCanonicalElements(rightRaw, right, count);
                left.CopyTo(pristineLeft);

                Span<byte> expected = stackalloc byte[wideCount * ScalarSize];
                ReferenceMultiplyElements(pristineLeft, right, expected, wideCount);

                //The results span IS the left operand span, same buffer and offsets: the kernel
                //loads a whole group before storing into it, so this whole-buffer overlap is the
                //group-granular aliasing guarantee the wide kernels make.
                int consumed = Gf2k128Vpclmulqdq.BatchMultiply(left, right, left, count);

                return consumed == wideCount && left[..(wideCount * ScalarSize)].SequenceEqual(expected);
            }, iter: IterationCount);
        }
    }


    /// <summary>BatchMultiplyAccumulate with accumulate:true XORs the reference product into the pre-seeded accumulator, over every wide-covered element at every batch size.</summary>
    [TestMethod]
    public void BatchMultiplyAccumulateAgreesWithTheReferenceLoopWhenAccumulating()
    {
        foreach(int count in BatchSizes)
        {
            int wideCount = count & ~(Gf2k128Vpclmulqdq.WideElementCount - 1);
            Gen<byte[]> rawGen = Gen.Byte.Array[count * ElementSizeBytes];
            Gen.Select(rawGen, rawGen, rawGen).Sample((leftRaw, rightRaw, seedRaw) =>
            {
                Span<byte> left = stackalloc byte[count * ScalarSize];
                Span<byte> right = stackalloc byte[count * ScalarSize];
                Span<byte> accumulators = stackalloc byte[count * ScalarSize];
                BuildCanonicalElements(leftRaw, left, count);
                BuildCanonicalElements(rightRaw, right, count);
                BuildCanonicalElements(seedRaw, accumulators, count);

                Span<byte> expected = stackalloc byte[wideCount * ScalarSize];
                ReferenceMultiplyAccumulateElements(left, right, accumulators[..(wideCount * ScalarSize)], expected, wideCount);

                int consumed = Gf2k128Vpclmulqdq.BatchMultiplyAccumulate(left, right, accumulators, accumulate: true, count);

                return consumed == wideCount && accumulators[..(wideCount * ScalarSize)].SequenceEqual(expected);
            }, iter: IterationCount);
        }
    }


    /// <summary>BatchMultiplyAccumulate with accumulate:false equals the plain reference product and ignores whatever the accumulator held before, over every batch size.</summary>
    [TestMethod]
    public void BatchMultiplyAccumulateAgreesWithTheReferenceLoopWhenOverwriting()
    {
        foreach(int count in BatchSizes)
        {
            int wideCount = count & ~(Gf2k128Vpclmulqdq.WideElementCount - 1);
            Gen<byte[]> rawGen = Gen.Byte.Array[count * ElementSizeBytes];
            Gen.Select(rawGen, rawGen, rawGen).Sample((leftRaw, rightRaw, seedRaw) =>
            {
                Span<byte> left = stackalloc byte[count * ScalarSize];
                Span<byte> right = stackalloc byte[count * ScalarSize];
                Span<byte> accumulators = stackalloc byte[count * ScalarSize];
                BuildCanonicalElements(leftRaw, left, count);
                BuildCanonicalElements(rightRaw, right, count);

                //A non-zero seed proves the overwrite ignores whatever the accumulator held before.
                BuildCanonicalElements(seedRaw, accumulators, count);

                Span<byte> expected = stackalloc byte[wideCount * ScalarSize];
                ReferenceMultiplyElements(left, right, expected, wideCount);

                int consumed = Gf2k128Vpclmulqdq.BatchMultiplyAccumulate(left, right, accumulators, accumulate: false, count);

                return consumed == wideCount && accumulators[..(wideCount * ScalarSize)].SequenceEqual(expected);
            }, iter: IterationCount);
        }
    }


    /// <summary>BatchMultiplyAccumulate leaves the accumulator tail untouched and reports count rounded down to a multiple of four.</summary>
    [TestMethod]
    public void BatchMultiplyAccumulateReturnsCountRoundedDownAndLeavesTheTailUntouched()
    {
        Span<byte> leftBuffer = stackalloc byte[MaxScalarBufferByteLength];
        Span<byte> rightBuffer = stackalloc byte[MaxScalarBufferByteLength];
        Span<byte> accumulatorsBuffer = stackalloc byte[MaxScalarBufferByteLength];
        foreach(int count in BatchSizes)
        {
            int wideCount = count & ~(Gf2k128Vpclmulqdq.WideElementCount - 1);
            Span<byte> left = leftBuffer[..(count * ScalarSize)];
            Span<byte> right = rightBuffer[..(count * ScalarSize)];
            Span<byte> accumulators = accumulatorsBuffer[..(count * ScalarSize)];
            FillDeterministicElements(left, count, seed: 3);
            FillDeterministicElements(right, count, seed: 4);
            accumulators.Fill(TailSentinel);

            int consumed = Gf2k128Vpclmulqdq.BatchMultiplyAccumulate(left, right, accumulators, accumulate: true, count);

            Assert.AreEqual(wideCount, consumed, $"BatchMultiplyAccumulate must consume count rounded down to a multiple of four at count {count}.");
            AssertTailUntouched(accumulators, wideCount, count, $"BatchMultiplyAccumulate must leave the tail slots untouched at count {count}.");
        }
    }


    /// <summary>An accumulator span that is the SAME buffer as the left operand still agrees with the reference, which reads the pristine left value as both the multiplicand and the seed accumulator.</summary>
    [TestMethod]
    public void BatchMultiplyAccumulateWithAccumulatorAliasingTheLeftOperandAgreesWithThePristineReference()
    {
        foreach(int count in BatchSizes)
        {
            int wideCount = count & ~(Gf2k128Vpclmulqdq.WideElementCount - 1);
            Gen<byte[]> rawGen = Gen.Byte.Array[count * ElementSizeBytes];
            Gen.Select(rawGen, rawGen).Sample((leftRaw, rightRaw) =>
            {
                Span<byte> left = stackalloc byte[count * ScalarSize];
                Span<byte> right = stackalloc byte[count * ScalarSize];
                Span<byte> pristineLeft = stackalloc byte[count * ScalarSize];
                BuildCanonicalElements(leftRaw, left, count);
                BuildCanonicalElements(rightRaw, right, count);
                left.CopyTo(pristineLeft);

                Span<byte> expected = stackalloc byte[wideCount * ScalarSize];
                ReferenceMultiplyAccumulateElements(pristineLeft, right, pristineLeft[..(wideCount * ScalarSize)], expected, wideCount);

                int consumed = Gf2k128Vpclmulqdq.BatchMultiplyAccumulate(left, right, left, accumulate: true, count);

                return consumed == wideCount && left[..(wideCount * ScalarSize)].SequenceEqual(expected);
            }, iter: IterationCount);
        }
    }


    /// <summary>BroadcastMultiplyAccumulate with accumulate:true XORs the reference broadcast product into the pre-seeded accumulator, over every wide-covered element at every batch size.</summary>
    [TestMethod]
    public void BroadcastMultiplyAccumulateAgreesWithTheReferenceLoopWhenAccumulating()
    {
        foreach(int count in BatchSizes)
        {
            int wideCount = count & ~(Gf2k128Vpclmulqdq.WideElementCount - 1);
            Gen<byte[]> operandRawGen = Gen.Byte.Array[count * ElementSizeBytes];
            Gen<byte[]> scalarRawGen = Gen.Byte.Array[ElementSizeBytes];
            Gen.Select(scalarRawGen, operandRawGen, operandRawGen).Sample((scalarRaw, operandRaw, seedRaw) =>
            {
                Span<byte> scalar = stackalloc byte[ScalarSize];
                Span<byte> operands = stackalloc byte[count * ScalarSize];
                Span<byte> accumulators = stackalloc byte[count * ScalarSize];
                BuildCanonicalElements(scalarRaw, scalar, elementCount: 1);
                BuildCanonicalElements(operandRaw, operands, count);
                BuildCanonicalElements(seedRaw, accumulators, count);

                Span<byte> expected = stackalloc byte[wideCount * ScalarSize];
                ReferenceBroadcastAccumulateElements(scalar, operands, accumulators[..(wideCount * ScalarSize)], expected, wideCount);

                (ulong scalarHigh, ulong scalarLow) = Gf2k128BatchBackend.Unpack(scalar);
                int consumed = Gf2k128Vpclmulqdq.BroadcastMultiplyAccumulate(scalarHigh, scalarLow, operands, accumulators, accumulate: true, count);

                return consumed == wideCount && accumulators[..(wideCount * ScalarSize)].SequenceEqual(expected);
            }, iter: IterationCount);
        }
    }


    /// <summary>BroadcastMultiplyAccumulate with accumulate:false equals the plain reference broadcast product and ignores whatever the accumulator held before, over every batch size.</summary>
    [TestMethod]
    public void BroadcastMultiplyAccumulateAgreesWithTheReferenceLoopWhenOverwriting()
    {
        foreach(int count in BatchSizes)
        {
            int wideCount = count & ~(Gf2k128Vpclmulqdq.WideElementCount - 1);
            Gen<byte[]> operandRawGen = Gen.Byte.Array[count * ElementSizeBytes];
            Gen<byte[]> scalarRawGen = Gen.Byte.Array[ElementSizeBytes];
            Gen.Select(scalarRawGen, operandRawGen, operandRawGen).Sample((scalarRaw, operandRaw, seedRaw) =>
            {
                Span<byte> scalar = stackalloc byte[ScalarSize];
                Span<byte> operands = stackalloc byte[count * ScalarSize];
                Span<byte> accumulators = stackalloc byte[count * ScalarSize];
                BuildCanonicalElements(scalarRaw, scalar, elementCount: 1);
                BuildCanonicalElements(operandRaw, operands, count);

                //A non-zero seed proves the overwrite ignores whatever the accumulator held before.
                BuildCanonicalElements(seedRaw, accumulators, count);

                Span<byte> expected = stackalloc byte[wideCount * ScalarSize];
                ReferenceBroadcastElements(scalar, operands, expected, wideCount);

                (ulong scalarHigh, ulong scalarLow) = Gf2k128BatchBackend.Unpack(scalar);
                int consumed = Gf2k128Vpclmulqdq.BroadcastMultiplyAccumulate(scalarHigh, scalarLow, operands, accumulators, accumulate: false, count);

                return consumed == wideCount && accumulators[..(wideCount * ScalarSize)].SequenceEqual(expected);
            }, iter: IterationCount);
        }
    }


    /// <summary>BroadcastMultiplyAccumulate leaves the accumulator tail untouched and reports count rounded down to a multiple of four.</summary>
    [TestMethod]
    public void BroadcastMultiplyAccumulateReturnsCountRoundedDownAndLeavesTheTailUntouched()
    {
        Span<byte> scalar = stackalloc byte[ScalarSize];
        Span<byte> operandsBuffer = stackalloc byte[MaxScalarBufferByteLength];
        Span<byte> accumulatorsBuffer = stackalloc byte[MaxScalarBufferByteLength];
        foreach(int count in BatchSizes)
        {
            int wideCount = count & ~(Gf2k128Vpclmulqdq.WideElementCount - 1);
            Span<byte> operands = operandsBuffer[..(count * ScalarSize)];
            Span<byte> accumulators = accumulatorsBuffer[..(count * ScalarSize)];
            FillDeterministicElements(scalar, count: 1, seed: 6);
            FillDeterministicElements(operands, count, seed: 7);
            accumulators.Fill(TailSentinel);

            (ulong scalarHigh, ulong scalarLow) = Gf2k128BatchBackend.Unpack(scalar);
            int consumed = Gf2k128Vpclmulqdq.BroadcastMultiplyAccumulate(scalarHigh, scalarLow, operands, accumulators, accumulate: true, count);

            Assert.AreEqual(wideCount, consumed, $"BroadcastMultiplyAccumulate must consume count rounded down to a multiple of four at count {count}.");
            AssertTailUntouched(accumulators, wideCount, count, $"BroadcastMultiplyAccumulate must leave the tail slots untouched at count {count}.");
        }
    }


    /// <summary>An accumulator span that is the SAME buffer as the operands still agrees with the reference, which reads the pristine operand value as both the multiplicand and the seed accumulator.</summary>
    [TestMethod]
    public void BroadcastMultiplyAccumulateWithAccumulatorAliasingTheOperandAgreesWithThePristineReference()
    {
        foreach(int count in BatchSizes)
        {
            int wideCount = count & ~(Gf2k128Vpclmulqdq.WideElementCount - 1);
            Gen<byte[]> operandRawGen = Gen.Byte.Array[count * ElementSizeBytes];
            Gen<byte[]> scalarRawGen = Gen.Byte.Array[ElementSizeBytes];
            Gen.Select(scalarRawGen, operandRawGen).Sample((scalarRaw, operandRaw) =>
            {
                Span<byte> scalar = stackalloc byte[ScalarSize];
                Span<byte> operands = stackalloc byte[count * ScalarSize];
                Span<byte> pristineOperands = stackalloc byte[count * ScalarSize];
                BuildCanonicalElements(scalarRaw, scalar, elementCount: 1);
                BuildCanonicalElements(operandRaw, operands, count);
                operands.CopyTo(pristineOperands);

                Span<byte> expected = stackalloc byte[wideCount * ScalarSize];
                ReferenceBroadcastAccumulateElements(scalar, pristineOperands, pristineOperands[..(wideCount * ScalarSize)], expected, wideCount);

                (ulong scalarHigh, ulong scalarLow) = Gf2k128BatchBackend.Unpack(scalar);
                int consumed = Gf2k128Vpclmulqdq.BroadcastMultiplyAccumulate(scalarHigh, scalarLow, operands, operands, accumulate: true, count);

                return consumed == wideCount && operands[..(wideCount * ScalarSize)].SequenceEqual(expected);
            }, iter: IterationCount);
        }
    }


    /// <summary>ButterflyBatch agrees with the per-element chained butterfly (low ^= twiddle·high; high ^= low) over every wide-covered element at every batch size.</summary>
    [TestMethod]
    public void ButterflyBatchAgreesWithThePerElementButterfly()
    {
        foreach(int stride in BatchSizes)
        {
            int wideCount = stride & ~(Gf2k128Vpclmulqdq.WideElementCount - 1);
            Gen<byte[]> valueRawGen = Gen.Byte.Array[stride * ElementSizeBytes];
            Gen<byte[]> twiddleRawGen = Gen.Byte.Array[ElementSizeBytes];
            Gen.Select(twiddleRawGen, valueRawGen, valueRawGen).Sample((twiddleRaw, lowRaw, highRaw) =>
            {
                Span<byte> twiddle = stackalloc byte[ScalarSize];
                Span<byte> low = stackalloc byte[stride * ScalarSize];
                Span<byte> high = stackalloc byte[stride * ScalarSize];
                BuildCanonicalElements(twiddleRaw, twiddle, elementCount: 1);
                BuildCanonicalElements(lowRaw, low, stride);
                BuildCanonicalElements(highRaw, high, stride);

                Span<byte> expectedLow = stackalloc byte[wideCount * ScalarSize];
                Span<byte> expectedHigh = stackalloc byte[wideCount * ScalarSize];
                low[..(wideCount * ScalarSize)].CopyTo(expectedLow);
                high[..(wideCount * ScalarSize)].CopyTo(expectedHigh);
                ReferenceButterflyElements(twiddle, expectedLow, expectedHigh, wideCount);

                (ulong twiddleHigh, ulong twiddleLow) = Gf2k128BatchBackend.Unpack(twiddle);
                int consumed = Gf2k128Vpclmulqdq.ButterflyBatch(twiddleHigh, twiddleLow, low, high, stride);

                return consumed == wideCount
                    && low[..(wideCount * ScalarSize)].SequenceEqual(expectedLow)
                    && high[..(wideCount * ScalarSize)].SequenceEqual(expectedHigh);
            }, iter: IterationCount);
        }
    }


    /// <summary>ButterflyBatch leaves both the low and high tails untouched and reports stride rounded down to a multiple of four.</summary>
    [TestMethod]
    public void ButterflyBatchReturnsCountRoundedDownAndLeavesTheTailUntouched()
    {
        Span<byte> twiddle = stackalloc byte[ScalarSize];
        Span<byte> lowBuffer = stackalloc byte[MaxScalarBufferByteLength];
        Span<byte> highBuffer = stackalloc byte[MaxScalarBufferByteLength];
        foreach(int stride in BatchSizes)
        {
            int wideCount = stride & ~(Gf2k128Vpclmulqdq.WideElementCount - 1);
            Span<byte> low = lowBuffer[..(stride * ScalarSize)];
            Span<byte> high = highBuffer[..(stride * ScalarSize)];
            FillDeterministicElements(twiddle, count: 1, seed: 8);
            low.Fill(TailSentinel);
            high.Fill(TailSentinel);

            (ulong twiddleHigh, ulong twiddleLow) = Gf2k128BatchBackend.Unpack(twiddle);
            int consumed = Gf2k128Vpclmulqdq.ButterflyBatch(twiddleHigh, twiddleLow, low, high, stride);

            Assert.AreEqual(wideCount, consumed, $"ButterflyBatch must consume stride rounded down to a multiple of four at stride {stride}.");
            AssertTailUntouched(low, wideCount, stride, $"ButterflyBatch must leave the low tail slots untouched at stride {stride}.");
            AssertTailUntouched(high, wideCount, stride, $"ButterflyBatch must leave the high tail slots untouched at stride {stride}.");
        }
    }


    //Computes the per-element reference product left[i]·right[i] into expected[0, elementCount);
    //the kernels never touch elements past their own consumed count, so callers only ask for that
    //many here.
    private static void ReferenceMultiplyElements(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> expected, int elementCount)
    {
        for(int i = 0; i < elementCount; i++)
        {
            int offset = i * ScalarSize;
            ReferenceMultiply(left.Slice(offset, ScalarSize), right.Slice(offset, ScalarSize), expected.Slice(offset, ScalarSize), CurveParameterSet.None);
        }
    }


    //Computes seedAccumulator[i] ^ left[i]·right[i] into expected[0, elementCount) — the
    //accumulate:true reference for BatchMultiplyAccumulate.
    private static void ReferenceMultiplyAccumulateElements(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, ReadOnlySpan<byte> seedAccumulator, Span<byte> expected, int elementCount)
    {
        Span<byte> product = stackalloc byte[ScalarSize];
        for(int i = 0; i < elementCount; i++)
        {
            int offset = i * ScalarSize;
            ReferenceMultiply(left.Slice(offset, ScalarSize), right.Slice(offset, ScalarSize), product, CurveParameterSet.None);
            ReferenceAdd(seedAccumulator.Slice(offset, ScalarSize), product, expected.Slice(offset, ScalarSize), CurveParameterSet.None);
        }
    }


    //Computes the fixed-scalar reference product scalar·operand[i] into expected[0, elementCount) —
    //the accumulate:false reference for BroadcastMultiplyAccumulate.
    private static void ReferenceBroadcastElements(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> operands, Span<byte> expected, int elementCount)
    {
        for(int i = 0; i < elementCount; i++)
        {
            int offset = i * ScalarSize;
            ReferenceMultiply(scalar, operands.Slice(offset, ScalarSize), expected.Slice(offset, ScalarSize), CurveParameterSet.None);
        }
    }


    //Computes seedAccumulator[i] ^ scalar·operand[i] into expected[0, elementCount) — the
    //accumulate:true reference for BroadcastMultiplyAccumulate.
    private static void ReferenceBroadcastAccumulateElements(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> operands, ReadOnlySpan<byte> seedAccumulator, Span<byte> expected, int elementCount)
    {
        Span<byte> product = stackalloc byte[ScalarSize];
        for(int i = 0; i < elementCount; i++)
        {
            int offset = i * ScalarSize;
            ReferenceMultiply(scalar, operands.Slice(offset, ScalarSize), product, CurveParameterSet.None);
            ReferenceAdd(seedAccumulator.Slice(offset, ScalarSize), product, expected.Slice(offset, ScalarSize), CurveParameterSet.None);
        }
    }


    //Chains the documented butterfly update in place over low[0, elementCount) and
    //high[0, elementCount): low ^= twiddle·high, then high ^= the just-updated low — a literal port
    //of the kernel's own doc comment, not a derived identity, so it independently pins the order of
    //operations.
    private static void ReferenceButterflyElements(ReadOnlySpan<byte> twiddle, Span<byte> low, Span<byte> high, int elementCount)
    {
        Span<byte> product = stackalloc byte[ScalarSize];
        for(int i = 0; i < elementCount; i++)
        {
            int offset = i * ScalarSize;
            ReferenceMultiply(twiddle, high.Slice(offset, ScalarSize), product, CurveParameterSet.None);
            ReferenceAdd(low.Slice(offset, ScalarSize), product, low.Slice(offset, ScalarSize), CurveParameterSet.None);
            ReferenceAdd(high.Slice(offset, ScalarSize), low.Slice(offset, ScalarSize), high.Slice(offset, ScalarSize), CurveParameterSet.None);
        }
    }


    //Embeds each raw ElementSizeBytes draw as a canonical 32-byte big-endian slot (high sixteen
    //bytes zero) via the reduce oracle; a 16-byte draw is already within the field width, so this
    //is a pure embed, not an actual reduction, matching the canonical layout the kernels consume.
    private static void BuildCanonicalElements(ReadOnlySpan<byte> rawElementBytes, Span<byte> canonical, int elementCount)
    {
        for(int i = 0; i < elementCount; i++)
        {
            ReferenceReduce(rawElementBytes.Slice(i * ElementSizeBytes, ElementSizeBytes), canonical.Slice(i * ScalarSize, ScalarSize), CurveParameterSet.None);
        }
    }


    //Deterministic pseudo-random canonical elements for the structural (non-property) tests, where
    //element content is irrelevant and only structural behavior — consumed count, tail preservation
    //— is under test; avoids pulling CsCheck into tests that need no random trials.
    private static void FillDeterministicElements(Span<byte> canonical, int count, int seed)
    {
        canonical.Clear();
        for(int i = 0; i < count; i++)
        {
            int elementStart = (i * ScalarSize) + (ScalarSize - ElementSizeBytes);
            for(int b = 0; b < ElementSizeBytes; b++)
            {
                canonical[elementStart + b] = (byte)((181 * ((i * ElementSizeBytes) + b)) + (97 * seed) + 29);
            }
        }
    }


    //Confirms the kernel touched exactly its consumed prefix and left the caller-owned tail
    //byte-for-byte as it found it.
    private static void AssertTailUntouched(ReadOnlySpan<byte> buffer, int consumedElementCount, int totalElementCount, string message)
    {
        ReadOnlySpan<byte> tail = buffer[(consumedElementCount * ScalarSize)..(totalElementCount * ScalarSize)];

        Assert.IsLessThan(0, tail.IndexOfAnyExcept(TailSentinel), message);
    }
}

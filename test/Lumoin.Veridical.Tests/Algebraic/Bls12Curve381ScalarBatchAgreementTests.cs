using CsCheck;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Property-based cross-implementation tests for the batched scalar-field
/// delegates introduced in this batch. Sweeps random batches through the
/// SIMD backend (real 4-wide lane-interleaved arithmetic for full
/// quartets, single-element fallback for the tail) and the BigInteger
/// reference (loop over the single-element delegate), asserting bit
/// equality of the concatenated output.
/// </summary>
/// <remarks>
/// <para>
/// The batch lengths sweep over <c>{1, 3, 4, 5, 8, 17}</c> rather than a
/// single fixed length: the SIMD backend has different code paths for the
/// full-quartet body (counts divisible by 4) and the tail (counts that
/// are not), and the agreement check has to cover both. Count 1 exercises
/// only the tail; count 4 only the body; count 5 mixes one quartet plus
/// one tail element; count 17 mixes four quartets plus one tail element.
/// </para>
/// <para>
/// Each batch-length sample exercises <see cref="IterationCount"/> random
/// scalar inputs, giving enough coverage for lane-mixup and carry-chain
/// bugs to surface as CsCheck-shrunk minimal counterexamples.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Bls12Curve381ScalarBatchAgreementTests
{
    private static readonly ScalarReduceDelegate ReduceDelegate =
        Bls12Curve381BigIntegerScalarReference.GetReduce();

    private static readonly ScalarBatchAddDelegate BigIntegerBatchAdd =
        Bls12Curve381BigIntegerScalarReference.GetBatchAdd();

    private static readonly ScalarBatchSubtractDelegate BigIntegerBatchSubtract =
        Bls12Curve381BigIntegerScalarReference.GetBatchSubtract();

    private static readonly ScalarBatchMultiplyDelegate BigIntegerBatchMultiply =
        Bls12Curve381BigIntegerScalarReference.GetBatchMultiply();

    private static readonly Gen<byte[]> RawScalarBytesGen =
        Gen.Byte.Array[Scalar.SizeBytes];

    private static readonly int[] BatchSizesToSweep = [1, 3, 4, 5, 8, 17];


    private const long IterationCount = 100;


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void SimdBatchAddAgreesWithBigIntegerBatchAddAcrossBatchSizes()
    {
        if(!Bls12Curve381SimdScalarBackend.IsSupported)
        {
            Assert.Inconclusive("AVX2 is not available on the host CPU; the SIMD scalar backend cannot run.");
            return;
        }

        ScalarBatchAddDelegate simdBatchAdd = Bls12Curve381SimdScalarBackend.GetBatchAdd();

        foreach(int batchSize in BatchSizesToSweep)
        {
            Gen.Select(RawScalarBytesGen.Array[batchSize], RawScalarBytesGen.Array[batchSize])
                .Sample((aBatch, bBatch) =>
                {
                    return AssertBatchedAgreement(aBatch, bBatch, batchSize, BigIntegerBatchAdd, simdBatchAdd);
                }, iter: IterationCount);
        }
    }


    [TestMethod]
    public void SimdBatchSubtractAgreesWithBigIntegerBatchSubtractAcrossBatchSizes()
    {
        if(!Bls12Curve381SimdScalarBackend.IsSupported)
        {
            Assert.Inconclusive("AVX2 is not available on the host CPU; the SIMD scalar backend cannot run.");
            return;
        }

        ScalarBatchSubtractDelegate simdBatchSubtract = Bls12Curve381SimdScalarBackend.GetBatchSubtract();

        foreach(int batchSize in BatchSizesToSweep)
        {
            Gen.Select(RawScalarBytesGen.Array[batchSize], RawScalarBytesGen.Array[batchSize])
                .Sample((aBatch, bBatch) =>
                {
                    return AssertBatchedAgreement(aBatch, bBatch, batchSize, BigIntegerBatchSubtract, simdBatchSubtract);
                }, iter: IterationCount);
        }
    }


    [TestMethod]
    public void SimdBatchMultiplyAgreesWithBigIntegerBatchMultiplyAcrossBatchSizes()
    {
        if(!Bls12Curve381SimdScalarBackend.IsSupported)
        {
            Assert.Inconclusive("AVX2 is not available on the host CPU; the SIMD scalar backend cannot run.");
            return;
        }

        ScalarBatchMultiplyDelegate simdBatchMultiply = Bls12Curve381SimdScalarBackend.GetBatchMultiply();

        foreach(int batchSize in BatchSizesToSweep)
        {
            Gen.Select(RawScalarBytesGen.Array[batchSize], RawScalarBytesGen.Array[batchSize])
                .Sample((aBatch, bBatch) =>
                {
                    return AssertBatchedAgreement(aBatch, bBatch, batchSize, BigIntegerBatchMultiply, simdBatchMultiply);
                }, iter: IterationCount);
        }
    }


    [TestMethod]
    public void SimdBatchAddAgreesWithSingleAddPerElement()
    {
        //Cross-check the batched path against the single-element path of the
        //same backend: pull the batched output and the row-by-row output of
        //the per-element delegate apart and compare. If the two disagree,
        //the bug is in the SIMD batched code's lane handling or tail logic,
        //independent of any disagreement with the BigInteger reference.
        if(!Bls12Curve381SimdScalarBackend.IsSupported)
        {
            Assert.Inconclusive("AVX2 is not available on the host CPU; the SIMD scalar backend cannot run.");
            return;
        }

        ScalarAddDelegate simdAdd = Bls12Curve381SimdScalarBackend.GetAdd();
        ScalarBatchAddDelegate simdBatchAdd = Bls12Curve381SimdScalarBackend.GetBatchAdd();

        foreach(int batchSize in BatchSizesToSweep)
        {
            Gen.Select(RawScalarBytesGen.Array[batchSize], RawScalarBytesGen.Array[batchSize])
                .Sample((aBatch, bBatch) =>
                {
                    int stride = Scalar.SizeBytes;
                    int total = batchSize * stride;

                    using IMemoryOwner<byte> aBufOwner = BaseMemoryPool.Shared.Rent(total);
                    using IMemoryOwner<byte> bBufOwner = BaseMemoryPool.Shared.Rent(total);
                    using IMemoryOwner<byte> batchedResultOwner = BaseMemoryPool.Shared.Rent(total);
                    using IMemoryOwner<byte> perElementResultOwner = BaseMemoryPool.Shared.Rent(total);

                    Span<byte> aBuf = aBufOwner.Memory.Span[..total];
                    Span<byte> bBuf = bBufOwner.Memory.Span[..total];
                    Span<byte> batchedResult = batchedResultOwner.Memory.Span[..total];
                    Span<byte> perElementResult = perElementResultOwner.Memory.Span[..total];

                    PackReducedScalars(aBatch, aBuf, stride);
                    PackReducedScalars(bBatch, bBuf, stride);

                    simdBatchAdd(aBuf, bBuf, batchedResult, batchSize, CurveParameterSet.Bls12Curve381);

                    for(int i = 0; i < batchSize; i++)
                    {
                        int offset = i * stride;
                        simdAdd(
                            aBuf.Slice(offset, stride),
                            bBuf.Slice(offset, stride),
                            perElementResult.Slice(offset, stride),
                            CurveParameterSet.Bls12Curve381);
                    }


                    return batchedResult.SequenceEqual(perElementResult);
                }, iter: IterationCount);
        }
    }


    private static bool AssertBatchedAgreement(
        byte[][] aBatch,
        byte[][] bBatch,
        int batchSize,
        ScalarBatchAddDelegate referenceDelegate,
        ScalarBatchAddDelegate candidateDelegate)
    {
        int stride = Scalar.SizeBytes;
        int total = batchSize * stride;

        using IMemoryOwner<byte> aBufOwner = BaseMemoryPool.Shared.Rent(total);
        using IMemoryOwner<byte> bBufOwner = BaseMemoryPool.Shared.Rent(total);
        using IMemoryOwner<byte> referenceResultOwner = BaseMemoryPool.Shared.Rent(total);
        using IMemoryOwner<byte> candidateResultOwner = BaseMemoryPool.Shared.Rent(total);

        Span<byte> aBuf = aBufOwner.Memory.Span[..total];
        Span<byte> bBuf = bBufOwner.Memory.Span[..total];
        Span<byte> referenceResult = referenceResultOwner.Memory.Span[..total];
        Span<byte> candidateResult = candidateResultOwner.Memory.Span[..total];

        PackReducedScalars(aBatch, aBuf, stride);
        PackReducedScalars(bBatch, bBuf, stride);

        referenceDelegate(aBuf, bBuf, referenceResult, batchSize, CurveParameterSet.Bls12Curve381);
        candidateDelegate(aBuf, bBuf, candidateResult, batchSize, CurveParameterSet.Bls12Curve381);

        return referenceResult.SequenceEqual(candidateResult);
    }


    private static bool AssertBatchedAgreement(
        byte[][] aBatch,
        byte[][] bBatch,
        int batchSize,
        ScalarBatchSubtractDelegate referenceDelegate,
        ScalarBatchSubtractDelegate candidateDelegate)
    {
        int stride = Scalar.SizeBytes;
        int total = batchSize * stride;

        using IMemoryOwner<byte> aBufOwner = BaseMemoryPool.Shared.Rent(total);
        using IMemoryOwner<byte> bBufOwner = BaseMemoryPool.Shared.Rent(total);
        using IMemoryOwner<byte> referenceResultOwner = BaseMemoryPool.Shared.Rent(total);
        using IMemoryOwner<byte> candidateResultOwner = BaseMemoryPool.Shared.Rent(total);

        Span<byte> aBuf = aBufOwner.Memory.Span[..total];
        Span<byte> bBuf = bBufOwner.Memory.Span[..total];
        Span<byte> referenceResult = referenceResultOwner.Memory.Span[..total];
        Span<byte> candidateResult = candidateResultOwner.Memory.Span[..total];

        PackReducedScalars(aBatch, aBuf, stride);
        PackReducedScalars(bBatch, bBuf, stride);

        referenceDelegate(aBuf, bBuf, referenceResult, batchSize, CurveParameterSet.Bls12Curve381);
        candidateDelegate(aBuf, bBuf, candidateResult, batchSize, CurveParameterSet.Bls12Curve381);

        return referenceResult.SequenceEqual(candidateResult);
    }


    private static bool AssertBatchedAgreement(
        byte[][] aBatch,
        byte[][] bBatch,
        int batchSize,
        ScalarBatchMultiplyDelegate referenceDelegate,
        ScalarBatchMultiplyDelegate candidateDelegate)
    {
        int stride = Scalar.SizeBytes;
        int total = batchSize * stride;

        using IMemoryOwner<byte> aBufOwner = BaseMemoryPool.Shared.Rent(total);
        using IMemoryOwner<byte> bBufOwner = BaseMemoryPool.Shared.Rent(total);
        using IMemoryOwner<byte> referenceResultOwner = BaseMemoryPool.Shared.Rent(total);
        using IMemoryOwner<byte> candidateResultOwner = BaseMemoryPool.Shared.Rent(total);

        Span<byte> aBuf = aBufOwner.Memory.Span[..total];
        Span<byte> bBuf = bBufOwner.Memory.Span[..total];
        Span<byte> referenceResult = referenceResultOwner.Memory.Span[..total];
        Span<byte> candidateResult = candidateResultOwner.Memory.Span[..total];

        PackReducedScalars(aBatch, aBuf, stride);
        PackReducedScalars(bBatch, bBuf, stride);

        referenceDelegate(aBuf, bBuf, referenceResult, batchSize, CurveParameterSet.Bls12Curve381);
        candidateDelegate(aBuf, bBuf, candidateResult, batchSize, CurveParameterSet.Bls12Curve381);

        return referenceResult.SequenceEqual(candidateResult);
    }


    private static void PackReducedScalars(byte[][] rawBatch, Span<byte> destination, int stride)
    {
        //Reduce each raw 32-byte sample modulo r so the batched delegate inputs
        //are always canonical-form scalars in [0, r). Uses the BigInteger
        //reference's Reduce delegate.
        for(int i = 0; i < rawBatch.Length; i++)
        {
            int offset = i * stride;
            ReduceDelegate(rawBatch[i], destination.Slice(offset, stride), CurveParameterSet.Bls12Curve381);
        }
    }
}
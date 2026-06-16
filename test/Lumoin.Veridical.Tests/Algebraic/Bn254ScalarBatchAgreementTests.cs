using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Property-based cross-implementation tests for the BN254 batched scalar-field
/// delegates, the BN254 mirror of <see cref="Bls12Curve381ScalarBatchAgreementTests"/>.
/// Sweeps random batches through the BN254 SIMD facade (lane-interleaved arithmetic
/// for full lane-groups, single-element fallback for the tail) and the BigInteger
/// reference, asserting bit equality of the concatenated output.
/// </summary>
/// <remarks>
/// The batch lengths sweep over <c>{1, 3, 4, 5, 8, 17}</c> to cover both the full
/// lane-group body and the tail across the 4-wide (AVX2) and 8-wide (AVX-512) widths
/// the facade may pick: count 1 exercises only the tail; counts 4 and 8 the bodies;
/// counts 5 and 17 mix a body with a tail element.
/// </remarks>
[TestClass]
internal sealed class Bn254ScalarBatchAgreementTests
{
    private static readonly ScalarReduceDelegate ReduceDelegate =
        Bn254BigIntegerScalarReference.GetReduce();

    private static readonly ScalarBatchAddDelegate BigIntegerBatchAdd =
        Bn254BigIntegerScalarReference.GetBatchAdd();

    private static readonly ScalarBatchSubtractDelegate BigIntegerBatchSubtract =
        Bn254BigIntegerScalarReference.GetBatchSubtract();

    private static readonly ScalarBatchMultiplyDelegate BigIntegerBatchMultiply =
        Bn254BigIntegerScalarReference.GetBatchMultiply();

    private static readonly Gen<byte[]> RawScalarBytesGen =
        Gen.Byte.Array[Scalar.SizeBytes];

    private static readonly int[] BatchSizesToSweep = [1, 3, 4, 5, 8, 17];


    private const long IterationCount = 100;


    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void SimdBatchAddAgreesWithBigIntegerBatchAddAcrossBatchSizes()
    {
        if(!Bn254SimdScalarBackend.IsSupported)
        {
            Assert.Inconclusive("No SIMD scalar backend is available on the host CPU.");
            return;
        }

        ScalarBatchAddDelegate simdBatchAdd = Bn254SimdScalarBackend.GetBatchAdd();

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
        if(!Bn254SimdScalarBackend.IsSupported)
        {
            Assert.Inconclusive("No SIMD scalar backend is available on the host CPU.");
            return;
        }

        ScalarBatchSubtractDelegate simdBatchSubtract = Bn254SimdScalarBackend.GetBatchSubtract();

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
        if(!Bn254SimdScalarBackend.IsSupported)
        {
            Assert.Inconclusive("No SIMD scalar backend is available on the host CPU.");
            return;
        }

        ScalarBatchMultiplyDelegate simdBatchMultiply = Bn254SimdScalarBackend.GetBatchMultiply();

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
        //Cross-check the batched path against the single-element path of the same
        //backend: if they disagree, the bug is in the SIMD batched code's lane
        //handling or tail logic, independent of the BigInteger reference.
        if(!Bn254SimdScalarBackend.IsSupported)
        {
            Assert.Inconclusive("No SIMD scalar backend is available on the host CPU.");
            return;
        }

        ScalarAddDelegate simdAdd = Bn254SimdScalarBackend.GetAdd();
        ScalarBatchAddDelegate simdBatchAdd = Bn254SimdScalarBackend.GetBatchAdd();

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

                    simdBatchAdd(aBuf, bBuf, batchedResult, batchSize, CurveParameterSet.Bn254);

                    for(int i = 0; i < batchSize; i++)
                    {
                        int offset = i * stride;
                        simdAdd(
                            aBuf.Slice(offset, stride),
                            bBuf.Slice(offset, stride),
                            perElementResult.Slice(offset, stride),
                            CurveParameterSet.Bn254);
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

        referenceDelegate(aBuf, bBuf, referenceResult, batchSize, CurveParameterSet.Bn254);
        candidateDelegate(aBuf, bBuf, candidateResult, batchSize, CurveParameterSet.Bn254);

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

        referenceDelegate(aBuf, bBuf, referenceResult, batchSize, CurveParameterSet.Bn254);
        candidateDelegate(aBuf, bBuf, candidateResult, batchSize, CurveParameterSet.Bn254);

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

        referenceDelegate(aBuf, bBuf, referenceResult, batchSize, CurveParameterSet.Bn254);
        candidateDelegate(aBuf, bBuf, candidateResult, batchSize, CurveParameterSet.Bn254);

        return referenceResult.SequenceEqual(candidateResult);
    }


    private static void PackReducedScalars(byte[][] rawBatch, Span<byte> destination, int stride)
    {
        //Reduce each raw 32-byte sample modulo r so the batched delegate inputs are
        //always canonical-form scalars in [0, r).
        for(int i = 0; i < rawBatch.Length; i++)
        {
            int offset = i * stride;
            ReduceDelegate(rawBatch[i], destination.Slice(offset, stride), CurveParameterSet.Bn254);
        }
    }
}

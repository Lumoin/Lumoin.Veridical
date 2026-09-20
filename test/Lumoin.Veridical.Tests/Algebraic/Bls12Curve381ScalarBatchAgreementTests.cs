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
/// delegates. Sweeps random batches through the
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
    /// <summary>The BigInteger reference's scalar reduction delegate, used to canonicalize raw sampled bytes into scalars.</summary>
    private static ScalarReduceDelegate ReduceDelegate { get; } =
        Bls12Curve381BigIntegerScalarReference.GetReduce();

    /// <summary>The BigInteger reference's batched scalar-add delegate.</summary>
    private static ScalarBatchAddDelegate BigIntegerBatchAdd { get; } =
        Bls12Curve381BigIntegerScalarReference.GetBatchAdd();

    /// <summary>The BigInteger reference's batched scalar-subtract delegate.</summary>
    private static ScalarBatchSubtractDelegate BigIntegerBatchSubtract { get; } =
        Bls12Curve381BigIntegerScalarReference.GetBatchSubtract();

    /// <summary>The BigInteger reference's batched scalar-multiply delegate.</summary>
    private static ScalarBatchMultiplyDelegate BigIntegerBatchMultiply { get; } =
        Bls12Curve381BigIntegerScalarReference.GetBatchMultiply();

    /// <summary>Generates one scalar's worth of uniformly random raw bytes, before reduction to canonical form.</summary>
    private static Gen<byte[]> RawScalarBytesGen { get; } =
        Gen.Byte.Array[Scalar.SizeBytes];

    /// <summary>The batch sizes swept by every agreement test: 1 and 5 exercise the tail alone or mixed with a quartet, 4 and 8 exercise only full quartets, 17 mixes four quartets with a tail element.</summary>
    private static int[] BatchSizesToSweep { get; } = [1, 3, 4, 5, 8, 17];


    /// <summary>The number of random samples CsCheck draws per batch-length sweep.</summary>
    private const long IterationCount = 100;


    /// <summary>The MSTest context for this test class; set by the test host.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Verifies that the SIMD batched scalar-add delegate agrees with the BigInteger reference's batched add, across every swept batch size.</summary>
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


    /// <summary>Verifies that the SIMD batched scalar-subtract delegate agrees with the BigInteger reference's batched subtract, across every swept batch size.</summary>
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


    /// <summary>Verifies that the SIMD batched scalar-multiply delegate agrees with the BigInteger reference's batched multiply, across every swept batch size.</summary>
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


    /// <summary>Verifies that the SIMD batched scalar-add delegate's output matches the same backend's single-element add applied row by row, isolating the batched path's own lane and tail handling from any reference disagreement.</summary>
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


    /// <summary>Packs both operand batches into canonical scalars, runs the reference and candidate batched-add delegates, and reports whether their outputs agree byte for byte.</summary>
    /// <param name="aBatch">The left operands, raw bytes before reduction.</param>
    /// <param name="bBatch">The right operands, raw bytes before reduction.</param>
    /// <param name="batchSize">The number of scalar pairs in the batch.</param>
    /// <param name="referenceDelegate">The BigInteger reference's batched add.</param>
    /// <param name="candidateDelegate">The batched add under test.</param>
    /// <returns><see langword="true"/> when the two outputs agree byte for byte.</returns>
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


    /// <summary>Packs both operand batches into canonical scalars, runs the reference and candidate batched-subtract delegates, and reports whether their outputs agree byte for byte.</summary>
    /// <param name="aBatch">The left operands, raw bytes before reduction.</param>
    /// <param name="bBatch">The right operands, raw bytes before reduction.</param>
    /// <param name="batchSize">The number of scalar pairs in the batch.</param>
    /// <param name="referenceDelegate">The BigInteger reference's batched subtract.</param>
    /// <param name="candidateDelegate">The batched subtract under test.</param>
    /// <returns><see langword="true"/> when the two outputs agree byte for byte.</returns>
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


    /// <summary>Packs both operand batches into canonical scalars, runs the reference and candidate batched-multiply delegates, and reports whether their outputs agree byte for byte.</summary>
    /// <param name="aBatch">The left operands, raw bytes before reduction.</param>
    /// <param name="bBatch">The right operands, raw bytes before reduction.</param>
    /// <param name="batchSize">The number of scalar pairs in the batch.</param>
    /// <param name="referenceDelegate">The BigInteger reference's batched multiply.</param>
    /// <param name="candidateDelegate">The batched multiply under test.</param>
    /// <returns><see langword="true"/> when the two outputs agree byte for byte.</returns>
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


    /// <summary>Reduces each raw sample modulo the scalar-field order via the BigInteger reference's <see cref="ReduceDelegate"/>, packing the canonical results contiguously.</summary>
    /// <param name="rawBatch">The raw, pre-reduction scalar samples.</param>
    /// <param name="destination">Receives the packed canonical scalars.</param>
    /// <param name="stride">The canonical scalar width in bytes.</param>
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
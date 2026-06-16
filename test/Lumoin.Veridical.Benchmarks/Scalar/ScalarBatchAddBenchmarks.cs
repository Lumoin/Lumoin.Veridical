using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using Lumoin.Veridical.Tests.Algebraic;
using System;

namespace Lumoin.Veridical.Benchmarks.Scalar;

/// <summary>
/// Throughput of batched <see cref="ScalarBatchAddDelegate"/> and
/// <see cref="ScalarBatchSubtractDelegate"/> across the BigInteger
/// reference (loop over single-element) and the SIMD backends
/// (lane-interleaved real batching). Parameterised by batch size so the
/// crossover between "single-element is fine" and "batching pays off"
/// is visible in one results table.
/// </summary>
/// <remarks>
/// <para>
/// On AVX2 hosts the SIMD batched path processes four scalars per
/// iteration of the inner carry chain; the per-scalar amortised cost
/// should be roughly a quarter of the single-element SIMD cost at full
/// batch sizes, less at small batches where the tail handling dominates.
/// On AArch64 NEON the parallelism is 2-wide instead of 4-wide; the
/// same shape, half the slope.
/// </para>
/// <para>
/// Buffers are sized for the maximum <see cref="BatchSize"/> once in
/// <see cref="Setup"/> so the benchmark hot path takes a slice rather
/// than allocating. <see cref="BenchmarkDotNet"/> uses the slice
/// construction inside the method; that is a single Span ctor and
/// negligible compared to even one scalar add.
/// </para>
/// </remarks>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput)]
public class ScalarBatchAddBenchmarks
{
    private const int ScalarBytes = 32;
    private const int BenchmarkSeed = 0x5EED5EED;
    private const int MaxBatchSize = 1024;
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;


    /// <summary>
    /// Batch sizes the benchmark sweeps. 16 exercises a few SIMD pairs/
    /// quartets plus tail, 64 fills a few hundred bytes of cache, 256
    /// crosses one cache line per scalar, 1024 is the rough size of a
    /// prover sub-phase batch.
    /// </summary>
    [Params(16, 64, 256, 1024)]
    public int BatchSize { get; set; }


    private byte[] aBatch = null!;
    private byte[] bBatch = null!;
    private byte[] resultBatch = null!;

    private ScalarBatchAddDelegate bigIntegerBatchAdd = null!;
    private ScalarBatchSubtractDelegate bigIntegerBatchSubtract = null!;
    private ScalarBatchAddDelegate simdBatchAdd = null!;
    private ScalarBatchSubtractDelegate simdBatchSubtract = null!;


    [GlobalSetup]
    public void Setup()
    {
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;

        bigIntegerBatchAdd = Bls12Curve381BigIntegerScalarReference.GetBatchAdd();
        bigIntegerBatchSubtract = Bls12Curve381BigIntegerScalarReference.GetBatchSubtract();

        if(Bls12Curve381SimdScalarBackend.IsSupported)
        {
            simdBatchAdd = Bls12Curve381SimdScalarBackend.GetBatchAdd();
            simdBatchSubtract = Bls12Curve381SimdScalarBackend.GetBatchSubtract();
        }
        else
        {
            simdBatchAdd = bigIntegerBatchAdd;
            simdBatchSubtract = bigIntegerBatchSubtract;
        }

        //Allocate buffers sized for the maximum batch so [Params] iterations
        //slice into them without reallocation. Each 32-byte slot gets a
        //canonical reduced scalar; reduction happens once during setup, not
        //inside the timed body.
        aBatch = new byte[MaxBatchSize * ScalarBytes];
        bBatch = new byte[MaxBatchSize * ScalarBytes];
        resultBatch = new byte[MaxBatchSize * ScalarBytes];

        ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();
        Random rng = new(BenchmarkSeed);
        Span<byte> raw = stackalloc byte[64];
        for(int i = 0; i < MaxBatchSize; i++)
        {
            int offset = i * ScalarBytes;
            rng.NextBytes(raw);
            reduce(raw, aBatch.AsSpan(offset, ScalarBytes), Curve);
            rng.NextBytes(raw);
            reduce(raw, bBatch.AsSpan(offset, ScalarBytes), Curve);
        }
    }


    [Benchmark(Baseline = true, Description = "BigInteger BatchAdd")]
    public void BigIntegerBatchAdd()
    {
        int total = BatchSize * ScalarBytes;
        bigIntegerBatchAdd(
            aBatch.AsSpan(0, total),
            bBatch.AsSpan(0, total),
            resultBatch.AsSpan(0, total),
            BatchSize,
            Curve);
    }


    [Benchmark(Description = "SIMD BatchAdd (AVX2 4-wide or NEON 2-wide via dispatch)")]
    public void SimdBatchAdd()
    {
        int total = BatchSize * ScalarBytes;
        simdBatchAdd(
            aBatch.AsSpan(0, total),
            bBatch.AsSpan(0, total),
            resultBatch.AsSpan(0, total),
            BatchSize,
            Curve);
    }


    [Benchmark(Description = "BigInteger BatchSubtract")]
    public void BigIntegerBatchSubtract()
    {
        int total = BatchSize * ScalarBytes;
        bigIntegerBatchSubtract(
            aBatch.AsSpan(0, total),
            bBatch.AsSpan(0, total),
            resultBatch.AsSpan(0, total),
            BatchSize,
            Curve);
    }


    [Benchmark(Description = "SIMD BatchSubtract")]
    public void SimdBatchSubtract()
    {
        int total = BatchSize * ScalarBytes;
        simdBatchSubtract(
            aBatch.AsSpan(0, total),
            bBatch.AsSpan(0, total),
            resultBatch.AsSpan(0, total),
            BatchSize,
            Curve);
    }
}
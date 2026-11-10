using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Lumoin.Veridical.Backends.Managed;
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
/// (lane-interleaved real batching), for both the BLS12-381 and the BN254
/// scalar fields. The BLS12-381 rows go through
/// <see cref="Bls12Curve381SimdScalarBackend"/> and the BN254 rows through
/// <see cref="Bn254SimdScalarBackend"/>, each falling back to its BigInteger
/// reference when the host has no SIMD tier. Parameterised by batch size so the
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
    private const int Bn254SeedOffset = 1;
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;
    private static CurveParameterSet Bn254Curve { get; } = CurveParameterSet.Bn254;


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

    private byte[] bnABatch = null!;
    private byte[] bnBBatch = null!;
    private byte[] bnResultBatch = null!;

    private ScalarBatchAddDelegate bnBigIntegerBatchAdd = null!;
    private ScalarBatchSubtractDelegate bnBigIntegerBatchSubtract = null!;
    private ScalarBatchAddDelegate bnSimdBatchAdd = null!;
    private ScalarBatchSubtractDelegate bnSimdBatchSubtract = null!;


    /// <summary>Resolves the BigInteger and SIMD batch add/subtract delegates for both curves and fills the operand buffers with reduced scalars.</summary>
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

        SetupBn254();
    }


    /// <summary>
    /// Resolves the BN254 BigInteger and SIMD batch add/subtract delegates and fills the BN254 operand
    /// buffers with reduced scalars from a seed distinct from the BLS12-381 one.
    /// </summary>
    private void SetupBn254()
    {
        bnBigIntegerBatchAdd = Bn254BigIntegerScalarReference.GetBatchAdd();
        bnBigIntegerBatchSubtract = Bn254BigIntegerScalarReference.GetBatchSubtract();

        if(Bn254SimdScalarBackend.IsSupported)
        {
            bnSimdBatchAdd = Bn254SimdScalarBackend.GetBatchAdd();
            bnSimdBatchSubtract = Bn254SimdScalarBackend.GetBatchSubtract();
        }
        else
        {
            bnSimdBatchAdd = bnBigIntegerBatchAdd;
            bnSimdBatchSubtract = bnBigIntegerBatchSubtract;
        }

        bnABatch = new byte[MaxBatchSize * ScalarBytes];
        bnBBatch = new byte[MaxBatchSize * ScalarBytes];
        bnResultBatch = new byte[MaxBatchSize * ScalarBytes];

        ScalarReduceDelegate reduce = Bn254BigIntegerScalarReference.GetReduce();
        Random rng = new(BenchmarkSeed + Bn254SeedOffset);
        Span<byte> raw = stackalloc byte[64];
        for(int i = 0; i < MaxBatchSize; i++)
        {
            int offset = i * ScalarBytes;
            rng.NextBytes(raw);
            reduce(raw, bnABatch.AsSpan(offset, ScalarBytes), Bn254Curve);
            rng.NextBytes(raw);
            reduce(raw, bnBBatch.AsSpan(offset, ScalarBytes), Bn254Curve);
        }
    }


    /// <summary>Benchmarks BigInteger batched addition over the BLS12-381 scalar field.</summary>
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


    /// <summary>Benchmarks SIMD lane-interleaved batched addition over the BLS12-381 scalar field.</summary>
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


    /// <summary>Benchmarks BigInteger batched subtraction over the BLS12-381 scalar field.</summary>
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


    /// <summary>Benchmarks SIMD lane-interleaved batched subtraction over the BLS12-381 scalar field.</summary>
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

    /// <summary>Benchmarks BigInteger batched addition over the BN254 scalar field.</summary>
    [Benchmark(Description = "BN254 BigInteger BatchAdd")]
    public void BN254BigIntegerBatchAdd()
    {
        int total = BatchSize * ScalarBytes;
        bnBigIntegerBatchAdd(
            bnABatch.AsSpan(0, total),
            bnBBatch.AsSpan(0, total),
            bnResultBatch.AsSpan(0, total),
            BatchSize,
            Bn254Curve);
    }

    /// <summary>Benchmarks SIMD lane-interleaved batched addition over the BN254 scalar field.</summary>
    [Benchmark(Description = "BN254 SIMD BatchAdd")]
    public void BN254SIMDBatchAdd()
    {
        int total = BatchSize * ScalarBytes;
        bnSimdBatchAdd(
            bnABatch.AsSpan(0, total),
            bnBBatch.AsSpan(0, total),
            bnResultBatch.AsSpan(0, total),
            BatchSize,
            Bn254Curve);
    }

    /// <summary>Benchmarks BigInteger batched subtraction over the BN254 scalar field.</summary>
    [Benchmark(Description = "BN254 BigInteger BatchSubtract")]
    public void BN254BigIntegerBatchSubtract()
    {
        int total = BatchSize * ScalarBytes;
        bnBigIntegerBatchSubtract(
            bnABatch.AsSpan(0, total),
            bnBBatch.AsSpan(0, total),
            bnResultBatch.AsSpan(0, total),
            BatchSize,
            Bn254Curve);
    }

    /// <summary>Benchmarks SIMD lane-interleaved batched subtraction over the BN254 scalar field.</summary>
    [Benchmark(Description = "BN254 SIMD BatchSubtract")]
    public void BN254SIMDBatchSubtract()
    {
        int total = BatchSize * ScalarBytes;
        bnSimdBatchSubtract(
            bnABatch.AsSpan(0, total),
            bnBBatch.AsSpan(0, total),
            bnResultBatch.AsSpan(0, total),
            BatchSize,
            Bn254Curve);
    }
}

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Engines;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Telemetry;
using System;

namespace Lumoin.Veridical.Benchmarks.Scalar;

/// <summary>
/// Throughput of the GF(2^128) fused multiply-accumulate (<c>acc[i] += a[i]·b[i]</c>) — the
/// dominant dot-product-shaped prover loop (the per-round weight precompute and the round-poly
/// accumulations) — against the naive per-scalar multiply-then-add loop that the prover runs today.
/// The naive loop reduces the <c>0x87</c> fold on every multiply; the batch FMA defers it to once
/// per accumulation, the reference's <c>gf2_128_mac</c> lever. Parameterised by batch size across
/// the prover's sub-phase range.
/// </summary>
/// <remarks>
/// Both paths start from a populated accumulator span so the read-modify-write is timed. Buffers
/// are sized for the maximum <see cref="BatchSize"/> once in <see cref="Setup"/>; the timed body
/// re-seeds the accumulator slice each invocation so accumulation does not drift across iterations,
/// a cost paid identically by both arms.
/// </remarks>
[Config(typeof(Config))]
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput, warmupCount: 3, iterationCount: 5)]
public class Gf2kFusedMultiplyAccumulateBenchmarks
{
    //BDN's default build timeout (2 min) is exhausted by this solution's cold build;
    //10 min covers the first-run compile without affecting subsequent cached builds.
    private sealed class Config : ManualConfig
    {
        public Config() => BuildTimeout = TimeSpan.FromMinutes(10);
    }



    private const int ScalarBytes = 32;
    private const int ElementOffset = 16;
    private const int BenchmarkSeed = 0x1AC0F2C0;
    private const int MaxBatchSize = 16384;
    private static readonly CurveParameterSet Curve = CurveParameterSet.None;


    /// <summary>Batch sizes the benchmark sweeps: 64, 1024, 16384.</summary>
    [Params(64, 1024, 16384)]
    public int BatchSize { get; set; }


    private byte[] left = null!;
    private byte[] right = null!;
    private byte[] seedAccumulator = null!;
    private byte[] accumulator = null!;
    private byte[] product = null!;

    private ScalarMultiplyDelegate scalarMultiply = null!;
    private ScalarAddDelegate scalarAdd = null!;
    private ScalarBatchMultiplyAccumulateDelegate batchMultiplyAccumulate = null!;


    /// <summary>Resolves the GF(2^128) scalar and batch-FMA delegates and fills the operand and accumulator buffers.</summary>
    [GlobalSetup]
    public void Setup()
    {
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;

        scalarMultiply = Gf2k128Backend.GetMultiply();
        scalarAdd = Gf2k128Backend.GetAdd();
        batchMultiplyAccumulate = Gf2k128BatchBackend.GetBatchMultiplyAccumulate();

        left = new byte[MaxBatchSize * ScalarBytes];
        right = new byte[MaxBatchSize * ScalarBytes];
        seedAccumulator = new byte[MaxBatchSize * ScalarBytes];
        accumulator = new byte[MaxBatchSize * ScalarBytes];
        product = new byte[ScalarBytes];

        Random rng = new(BenchmarkSeed);
        for(int i = 0; i < MaxBatchSize; i++)
        {
            int elementStart = (i * ScalarBytes) + ElementOffset;
            rng.NextBytes(left.AsSpan(elementStart, ScalarBytes - ElementOffset));
            rng.NextBytes(right.AsSpan(elementStart, ScalarBytes - ElementOffset));
            rng.NextBytes(seedAccumulator.AsSpan(elementStart, ScalarBytes - ElementOffset));
        }
    }


    /// <summary>Benchmarks GF(2^128) fused multiply-accumulate as a naive per-scalar multiply-then-add loop.</summary>
    [Benchmark(Baseline = true, Description = "Naive multiply-then-add loop (reduce per multiply)")]
    public void NaiveMultiplyAddLoop()
    {
        int total = BatchSize * ScalarBytes;
        seedAccumulator.AsSpan(0, total).CopyTo(accumulator.AsSpan(0, total));
        for(int i = 0; i < BatchSize; i++)
        {
            int offset = i * ScalarBytes;
            scalarMultiply(left.AsSpan(offset, ScalarBytes), right.AsSpan(offset, ScalarBytes), product, Curve);
            scalarAdd(accumulator.AsSpan(offset, ScalarBytes), product, accumulator.AsSpan(offset, ScalarBytes), Curve);
        }
    }


    /// <summary>Benchmarks GF(2^128) batch fused multiply-accumulate with deferred reduction.</summary>
    [Benchmark(Description = "Batch FMA (deferred reduce)")]
    public void BatchFusedMultiplyAccumulate()
    {
        int total = BatchSize * ScalarBytes;
        seedAccumulator.AsSpan(0, total).CopyTo(accumulator.AsSpan(0, total));
        batchMultiplyAccumulate(
            left.AsSpan(0, total),
            right.AsSpan(0, total),
            accumulator.AsSpan(0, total),
            accumulate: true,
            BatchSize,
            Curve);
    }
}

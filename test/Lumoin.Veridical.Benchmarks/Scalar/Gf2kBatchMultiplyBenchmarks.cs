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
/// Throughput of GF(2^128) batched multiply and fused multiply-accumulate
/// (<see cref="Gf2k128BatchBackend"/>) against the per-scalar delegate loop
/// (<see cref="Gf2k128Backend"/>) — the seam the Longfellow hash side runs on. Parameterised by
/// batch size so the win from devirtualising the per-scalar call, packing the limbs once, and
/// deferring the <c>0x87</c> reduction across the accumulation is visible across the prover's range
/// of sub-phase sizes.
/// </summary>
/// <remarks>
/// <para>
/// The scalar-loop baseline walks the same concatenated span calling the single-element multiply
/// per element — exactly what the prover does today. The batch-multiply path reduces per product
/// like the baseline but amortises the indirect call and the limb parse; the FMA path additionally
/// defers reduction, the reference's <c>gf2_128_mac</c> lever. The 16384 size sits at the scale of
/// a Ligero row encode / a layer's wire-table fold.
/// </para>
/// <para>
/// Buffers are sized for the maximum <see cref="BatchSize"/> once in <see cref="Setup"/> so the
/// timed body slices rather than allocates, matching <c>ScalarBatchAddBenchmarks</c>.
/// </para>
/// </remarks>
[Config(typeof(Config))]
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput, warmupCount: 3, iterationCount: 5)]
public class Gf2kBatchMultiplyBenchmarks
{
    /// <summary>
    /// BDN's default build timeout (2 min) is exhausted by this solution's cold build; 10 min covers the
    /// first-run compile without affecting subsequent cached builds.
    /// </summary>
    private sealed class Config : ManualConfig
    {
        /// <summary>Raises the benchmark build timeout.</summary>
        public Config() => BuildTimeout = TimeSpan.FromMinutes(10);
    }



    /// <summary>The width in bytes of one scalar slot.</summary>
    private const int ScalarBytes = 32;
    /// <summary>The offset of the 16-byte GF(2^128) element within a scalar slot; the bytes before it stay zero.</summary>
    private const int ElementOffset = 16;
    /// <summary>The seed of the generator that draws the operands, fixed so every run measures the same inputs.</summary>
    private const int BenchmarkSeed = 0x6F2C0128;
    /// <summary>The largest batch size, which the operand buffers are sized for.</summary>
    private const int MaxBatchSize = 16384;
    /// <summary>The curve tag passed to the scalar delegates; the GF(2^128) kernels do not depend on it.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.None;


    /// <summary>Batch sizes the benchmark sweeps: 64 (a small sub-phase), 1024 (a fold step), 16384 (a row encode / layer fold).</summary>
    [Params(64, 1024, 16384)]
    public int BatchSize { get; set; }


    /// <summary>The concatenated left operands.</summary>
    private byte[] left = null!;
    /// <summary>The concatenated right operands.</summary>
    private byte[] right = null!;
    /// <summary>The concatenated results.</summary>
    private byte[] result = null!;

    /// <summary>The single-element multiply the scalar-loop baseline calls per element.</summary>
    private ScalarMultiplyDelegate scalarMultiply = null!;
    /// <summary>The batched multiply.</summary>
    private ScalarBatchMultiplyDelegate batchMultiply = null!;
    /// <summary>The fused batched multiply-accumulate.</summary>
    private ScalarBatchMultiplyAccumulateDelegate batchMultiplyAccumulate = null!;


    /// <summary>Resolves the GF(2^128) scalar and batch multiply delegates and fills canonical operand buffers.</summary>
    [GlobalSetup]
    public void Setup()
    {
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;

        scalarMultiply = Gf2k128Backend.GetMultiply();
        batchMultiply = Gf2k128BatchBackend.GetBatchMultiply();
        batchMultiplyAccumulate = Gf2k128BatchBackend.GetBatchMultiplyAccumulate();

        left = new byte[MaxBatchSize * ScalarBytes];
        right = new byte[MaxBatchSize * ScalarBytes];
        result = new byte[MaxBatchSize * ScalarBytes];

        //Canonical elements: the GF(2^128) value in the low sixteen bytes, the high sixteen zero.
        Random rng = new(BenchmarkSeed);
        for(int i = 0; i < MaxBatchSize; i++)
        {
            int elementStart = (i * ScalarBytes) + ElementOffset;
            rng.NextBytes(left.AsSpan(elementStart, ScalarBytes - ElementOffset));
            rng.NextBytes(right.AsSpan(elementStart, ScalarBytes - ElementOffset));
        }
    }


    /// <summary>Benchmarks GF(2^128) multiplication as a per-scalar delegate loop.</summary>
    [Benchmark(Baseline = true, Description = "Per-scalar multiply loop")]
    public void ScalarMultiplyLoop()
    {
        for(int i = 0; i < BatchSize; i++)
        {
            int offset = i * ScalarBytes;
            scalarMultiply(
                left.AsSpan(offset, ScalarBytes),
                right.AsSpan(offset, ScalarBytes),
                result.AsSpan(offset, ScalarBytes),
                Curve);
        }
    }


    /// <summary>Benchmarks GF(2^128) batch multiplication with packed limbs and per-product reduction.</summary>
    [Benchmark(Description = "Batch multiply (packed limbs, reduce per product)")]
    public void BatchMultiply()
    {
        int total = BatchSize * ScalarBytes;
        batchMultiply(
            left.AsSpan(0, total),
            right.AsSpan(0, total),
            result.AsSpan(0, total),
            BatchSize,
            Curve);
    }


    /// <summary>Benchmarks GF(2^128) batch multiply in overwrite mode with deferred reduction.</summary>
    [Benchmark(Description = "Batch FMA overwrite (packed limbs, deferred reduce)")]
    public void BatchFusedMultiplyAccumulate()
    {
        int total = BatchSize * ScalarBytes;
        batchMultiplyAccumulate(
            left.AsSpan(0, total),
            right.AsSpan(0, total),
            result.AsSpan(0, total),
            accumulate: false,
            BatchSize,
            Curve);
    }
}

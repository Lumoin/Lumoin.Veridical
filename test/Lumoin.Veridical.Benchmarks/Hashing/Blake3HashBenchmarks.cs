using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using BenchmarkDotNet.Jobs;
using System;

namespace Lumoin.Veridical.Benchmarks.Hashing;

/// <summary>
/// Head-to-head BLAKE3 throughput comparison: the managed
/// implementation in <see cref="Lumoin.Veridical.Hashing.Blake3"/>
/// against the xoofx Rust-FFI <c>Blake3</c> NuGet package.
/// </summary>
/// <remarks>
/// <para>
/// The managed entry is the baseline (BenchmarkDotNet's
/// <see cref="BenchmarkAttribute.Baseline"/>) so the report shows
/// "xoofx vs. managed" as a ratio with managed at 1.00. A ratio below
/// 1.00 means xoofx is faster.
/// </para>
/// <para>
/// Input sizes span the BLAKE3 dispatch decision boundaries: 32 B
/// (sub-block), 64 B (exactly one block), 1 KiB (exactly one chunk —
/// the single-chunk path), 8 KiB (one AVX2 batch on x86_64 with AVX2),
/// 16 KiB (one AVX-512 batch), 64 KiB and 1 MiB (many batches, where
/// the chunk-parallel SIMD path dominates).
/// </para>
/// </remarks>
[MemoryDiagnoser]
[ShortRunJob]
public class Blake3HashBenchmarks
{
    /// <summary>Input size in bytes covering the BLAKE3 dispatch decision boundaries.</summary>
    [Params(32, 64, 1024, 8192, 16384, 65536, 1048576)]
    public int InputSize { get; set; }


    private byte[] input = null!;
    private readonly byte[] output = new byte[32];


    /// <summary>Fills the deterministic input buffer sized for the current input size.</summary>
    [GlobalSetup]
    public void Setup()
    {
        //Deterministic input so successive runs measure the same bytes.
        input = new byte[InputSize];
        new Random(0x5EED5EED).NextBytes(input);
    }


    /// <summary>Benchmarks the managed BLAKE3 implementation's auto-selected backend.</summary>
    [Benchmark(Baseline = true, Description = "Managed (auto-selected backend)")]
    public void Managed()
    {
        Lumoin.Veridical.Hashing.Blake3.Hash(input, output);
    }


    /// <summary>Benchmarks the xoofx Rust-FFI BLAKE3 implementation.</summary>
    [Benchmark(Description = "Xoofx (Rust FFI)")]
    public void Xoofx()
    {
        global::Blake3.Hasher.Hash(input, output);
    }
}
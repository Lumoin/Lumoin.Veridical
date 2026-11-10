using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using Lumoin.Veridical.Tests.Algebraic;
using System;

namespace Lumoin.Veridical.Benchmarks.Commitments.Ligero;

/// <summary>
/// Per-row timing of the Ligero systematic Reed–Solomon encoder
/// (<see cref="LigeroReedSolomonEncoder"/>) over the P-256 base field Fp256, at
/// the two codeword shapes the prover encodes: the tableau shape
/// <c>Block → BlockEncoded</c> and the dot-product response shape
/// <c>Block → DoubleBlock</c>. The current encoder is the NTT-free barycentric
/// one: per row of message length <c>m</c> extended to length <c>n</c> it is
/// O(m²) for the weights plus O(m·(n−m)) for the evaluation. Sweeping
/// <see cref="Block"/> shows how that cost scales, which (together with the
/// per-op Fp256 cost) tells us whether the encoder is worth replacing.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput)]
public class LigeroEncoderBenchmarks
{
    /// <summary>The width in bytes of one Fp256 element.</summary>
    private const int ScalarBytes = 32;
    /// <summary>The seed of the generator that draws the message, fixed so every run measures the same input.</summary>
    private const int BenchmarkSeed = 0x5EED5EED;
    /// <summary>The inverse code rate of the tableau shape: the codeword is the message extended by this factor.</summary>
    private const int InverseRate = 4;
    /// <summary>The curve tag passed to the scalar delegates; the P-256 base-field kernels do not depend on it.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.None;
    /// <summary>The pool the encoder rents its working buffers from.</summary>
    private static BaseMemoryPool Pool { get; } = BaseMemoryPool.Shared;

    /// <summary>
    /// Reed-Solomon message lengths (a Ligero row's witness block) the benchmark sweeps. The tableau codeword
    /// has <c>(2 + InverseRate) * Block - 1</c> elements and the dot-product response codeword has
    /// <c>2 * Block - 1</c>.
    /// </summary>
    [Params(16, 64, 256)]
    public int Block { get; set; }

    /// <summary>The message row, a vector of reduced field elements.</summary>
    private byte[] message = null!;
    /// <summary>The destination of the tableau-shape encoding.</summary>
    private byte[] codewordExtended = null!;
    /// <summary>The destination of the dot-product-response-shape encoding.</summary>
    private byte[] codewordDouble = null!;

    /// <summary>The field addition.</summary>
    private ScalarAddDelegate add = null!;
    /// <summary>The field subtraction.</summary>
    private ScalarSubtractDelegate subtract = null!;
    /// <summary>The field multiplication.</summary>
    private ScalarMultiplyDelegate multiply = null!;
    /// <summary>The field inversion.</summary>
    private ScalarInvertDelegate invert = null!;


    /// <summary>The codeword length of the tableau shape, <c>(2 + InverseRate) * Block - 1</c>.</summary>
    private int BlockEncoded => ((2 + InverseRate) * Block) - 1;

    /// <summary>The codeword length of the dot-product response shape, <c>2 * Block - 1</c>.</summary>
    private int DoubleBlock => (2 * Block) - 1;


    /// <summary>Resolves the Fp256 op delegates, fills a random reduced message row, and sizes the codeword buffers.</summary>
    [GlobalSetup]
    public void Setup()
    {
        CryptographicOperationCounters.IsCountingEnabled = false;
        CryptographicOperationCounters.IsObservingEnabled = false;

        add = P256BaseFieldReference.GetAdd();
        subtract = P256BaseFieldReference.GetSubtract();
        multiply = P256BaseFieldReference.GetMultiply();
        invert = P256BaseFieldReference.GetInvert();
        ScalarReduceDelegate reduce = P256BaseFieldReference.GetReduce();

        message = new byte[Block * ScalarBytes];
        var random = new Random(BenchmarkSeed);
        Span<byte> raw = stackalloc byte[64];
        for(int i = 0; i < Block; i++)
        {
            random.NextBytes(raw);
            reduce(raw, message.AsSpan(i * ScalarBytes, ScalarBytes), Curve);
        }

        codewordExtended = new byte[BlockEncoded * ScalarBytes];
        codewordDouble = new byte[DoubleBlock * ScalarBytes];
    }


    /// <summary>Benchmarks Reed-Solomon encoding a row to the extended tableau codeword length.</summary>
    [Benchmark(Baseline = true, Description = "Encode Block -> BlockEncoded (tableau row)")]
    public void EncodeToBlockEncoded() => LigeroReedSolomonEncoder.Encode(
        message, Block, codewordExtended, BlockEncoded, add, subtract, multiply, invert, Curve, Pool);


    /// <summary>Benchmarks Reed-Solomon encoding a row to the double-block response codeword length.</summary>
    [Benchmark(Description = "Encode Block -> DoubleBlock (response row)")]
    public void EncodeToDoubleBlock() => LigeroReedSolomonEncoder.Encode(
        message, Block, codewordDouble, DoubleBlock, add, subtract, multiply, invert, Curve, Pool);
}

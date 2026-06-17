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
    private const int ScalarBytes = 32;
    private const int BenchmarkSeed = 0x5EED5EED;
    private const int InverseRate = 4;
    private static readonly CurveParameterSet Curve = CurveParameterSet.None;
    private static readonly BaseMemoryPool Pool = BaseMemoryPool.Shared;

    //The RS message length (a Ligero row's witness block). BlockEncoded =
    //(2 + InverseRate)·Block − 1; DoubleBlock = 2·Block − 1.
    [Params(16, 64, 256)]
    public int Block { get; set; }

    private byte[] message = null!;
    private byte[] codewordExtended = null!;
    private byte[] codewordDouble = null!;

    private ScalarAddDelegate add = null!;
    private ScalarSubtractDelegate subtract = null!;
    private ScalarMultiplyDelegate multiply = null!;
    private ScalarInvertDelegate invert = null!;


    private int BlockEncoded => ((2 + InverseRate) * Block) - 1;

    private int DoubleBlock => (2 * Block) - 1;


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


    [Benchmark(Baseline = true, Description = "Encode Block -> BlockEncoded (tableau row)")]
    public void EncodeToBlockEncoded() => LigeroReedSolomonEncoder.Encode(
        message, Block, codewordExtended, BlockEncoded, add, subtract, multiply, invert, Curve, Pool);


    [Benchmark(Description = "Encode Block -> DoubleBlock (response row)")]
    public void EncodeToDoubleBlock() => LigeroReedSolomonEncoder.Encode(
        message, Block, codewordDouble, DoubleBlock, add, subtract, multiply, invert, Curve, Pool);
}

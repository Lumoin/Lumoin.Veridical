using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Engines;
using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Buffers.Binary;
using System.Text;

namespace Lumoin.Veridical.Benchmarks.Algebraic;

/// <summary>
/// The Pippenger payoff over the naive per-point-ladder MSM at the sizes the
/// Pedersen/Hyrax/Bulletproofs paths actually use: commitment rows and IPA
/// vectors from a few dozen to a few thousand points. Both run the same
/// BigInteger Jacobian core, so the ratio isolates the algorithm.
/// </summary>
[MemoryDiagnoser]
[SimpleJob(RunStrategy.Throughput)]
public class G1MultiScalarMultiplyBenchmarks
{
    /// <summary>The width in bytes of one compressed G1 point.</summary>
    private const int PointSize = WellKnownCurves.Bls12Curve381G1CompressedSizeBytes;
    /// <summary>The width in bytes of one scalar.</summary>
    private const int ScalarSize = 32;
    /// <summary>
    /// One salt selects both deterministic streams (the hash-to-curve messages and the scalar fill); any
    /// small value works, it only has to be fixed.
    /// </summary>
    private const int PointStreamSalt = 7;
    /// <summary>The curve whose G1 group is measured.</summary>
    private static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;
    /// <summary>The domain separation tag of the hash-to-curve that produces the benchmark points.</summary>
    private static byte[] DomainSeparationTag { get; } = Encoding.UTF8.GetBytes("VERIDICAL-PIPPENGER-BENCH-V1");

    /// <summary>The BigInteger reference multi-scalar multiplication.</summary>
    private static G1MultiScalarMultiplyDelegate ReferenceMsm { get; } = Bls12Curve381BigIntegerG1Reference.GetMultiScalarMultiply();
    /// <summary>The Pippenger multi-scalar multiplication that decodes the points on every call.</summary>
    private static G1MultiScalarMultiplyDelegate PippengerMsm { get; } = Bls12Curve381PippengerG1Backend.GetMultiScalarMultiply();
    /// <summary>The Pippenger multi-scalar multiplication that caches the decoded points between calls.</summary>
    private static G1MultiScalarMultiplyDelegate CachingMsm { get; } = Bls12Curve381PippengerG1Backend.CreateCachingMultiScalarMultiply();


    /// <summary>Vector lengths: a Hyrax row, an IPA opening, a large commitment.</summary>
    [Params(32, 256, 2048)]
    public int Count { get; set; }


    /// <summary>The concatenated compressed points.</summary>
    private byte[] points = null!;
    /// <summary>The concatenated scalars.</summary>
    private byte[] scalars = null!;
    /// <summary>The destination of the multi-scalar multiplication.</summary>
    private byte[] result = null!;


    /// <summary>Hashes the benchmark points onto G1, fills the scalars, and warms the cached-Pippenger point cache.</summary>
    [GlobalSetup]
    public void Setup()
    {
        G1HashToCurveDelegate hashToCurve = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
        ScalarReduceDelegate reduce = Bls12Curve381BigIntegerScalarReference.GetReduce();

        points = new byte[Count * PointSize];
        scalars = new byte[Count * ScalarSize];
        result = new byte[PointSize];
        Span<byte> message = stackalloc byte[8];
        for(int i = 0; i < Count; i++)
        {
            BinaryPrimitives.WriteInt32BigEndian(message[..4], PointStreamSalt);
            BinaryPrimitives.WriteInt32BigEndian(message[4..], i);
            _ = hashToCurve(message, DomainSeparationTag, points.AsSpan(i * PointSize, PointSize), Curve, Tag.Empty);
        }

        DeterministicScalarFill.FillCanonical(scalars, PointStreamSalt, reduce, Curve);

        //Warm the decoded-point cache so the CachedPippenger cell measures
        //the steady state a stable commitment key sees.
        CachingMsm(points, scalars, Count, result, Curve);
    }


    /// <summary>Benchmarks the naive per-point double-and-add multi-scalar multiplication.</summary>
    [Benchmark(Baseline = true)]
    public byte NaiveLadder()
    {
        ReferenceMsm(points, scalars, Count, result, Curve);

        return result[0];
    }


    /// <summary>Benchmarks the Pippenger multi-scalar multiplication.</summary>
    [Benchmark]
    public byte Pippenger()
    {
        PippengerMsm(points, scalars, Count, result, Curve);

        return result[0];
    }


    /// <summary>Benchmarks Pippenger multi-scalar multiplication with the decoded-point cache warmed.</summary>
    [Benchmark]
    public byte CachedPippenger()
    {
        CachingMsm(points, scalars, Count, result, Curve);

        return result[0];
    }
}

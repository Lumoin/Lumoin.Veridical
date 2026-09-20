using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Bbs;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.Circom;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Threading;

namespace Lumoin.Veridical.Tests.Fuzzing;

/// <summary>
/// Feeds a byte span, unmodified or hostile, into one of the library's hand-written binary
/// decoders. A single-statement pass or a documented rejection exception both count as
/// success; anything else is a fuzz finding.
/// </summary>
internal delegate void FuzzTargetInvoke(ReadOnlySpan<byte> input);

/// <summary>
/// One decoder under fuzz: its invocation wrapper and the exception types that count as a
/// graceful, documented rejection of malformed input. An empty <see cref="ExpectedRejections"/>
/// marks a target that is contractually total (a <c>TryRead</c>/predicate shape) and must
/// never throw at all.
/// </summary>
/// <param name="Name">The target's short identifying label, used in test names and failure messages.</param>
/// <param name="Invoke">The wrapper that feeds a byte span into the decoder's real entry point.</param>
/// <param name="ExpectedRejections">The exception types that count as a graceful, documented rejection; empty for a target that must never throw.</param>
internal sealed record FuzzTarget(string Name, FuzzTargetInvoke Invoke, Type[] ExpectedRejections);

/// <summary>
/// The registry of decoder fuzz targets, shared by <see cref="DecoderRobustnessTests"/> and any
/// future standalone fuzz harness (for example a SharpFuzz console driver). Each target wraps
/// exactly one hand-written decoder entry point with the wiring (format label, curve, pool)
/// its real call sites use; seed corpora are the caller's concern, not the registry's.
/// </summary>
internal static class DecoderFuzzTargets
{
    /// <summary>Spartan's outer sumcheck round polynomial degree; any degree at least 2 exercises the same <c>FromCompressedBytes</c> parse path, so the smallest realistic value keeps the fixed-length edge-case inputs small.</summary>
    private const int RoundPolynomialDegree = 3;

    /// <summary>The reference implementation's field id for GF(2^128), the field the small anchor circuit in <c>LongfellowCircuitReaderTests</c> is serialized over.</summary>
    private const int LongfellowFieldId = 4;
    /// <summary>The on-wire element width, in bytes, of a GF(2^128) element.</summary>
    private const int LongfellowElementBytes = 16;

    /// <summary>The BLS12-381 G1 on-curve predicate under fuzz.</summary>
    private static G1IsOnCurveDelegate BlsG1OnCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();
    /// <summary>The BLS12-381 G2 on-curve predicate under fuzz.</summary>
    private static G2IsOnCurveDelegate BlsG2OnCurve { get; } = Bls12Curve381BigIntegerG2Reference.GetIsOnCurve();
    /// <summary>The BN254 G1 on-curve predicate under fuzz.</summary>
    private static G1IsOnCurveDelegate Bn254G1OnCurve { get; } = Bn254BigIntegerG1Reference.GetIsOnCurve();
    /// <summary>The BN254 G2 on-curve predicate under fuzz.</summary>
    private static G2IsOnCurveDelegate Bn254G2OnCurve { get; } = Bn254BigIntegerG2Reference.GetIsOnCurve();


    /// <summary>The fixed set of decoder fuzz targets, one entry per hand-written binary decoder.</summary>
    public static IReadOnlyList<FuzzTarget> All { get; } =
    [
        new FuzzTarget(
            "circom-r1cs",
            InvokeCircomR1cs,
            [typeof(ArgumentException), typeof(R1csUnsupportedFieldException)]),

        new FuzzTarget(
            "circom-wtns",
            InvokeCircomWitness,
            [typeof(ArgumentException), typeof(R1csUnsupportedFieldException)]),

        new FuzzTarget(
            "zkinterface-decoder",
            InvokeZkInterfaceDecoder,
            [typeof(ArgumentException)]),

        new FuzzTarget(
            "zkinterface-r1cs",
            InvokeZkInterfaceR1cs,
            [typeof(ArgumentException), typeof(R1csUnsupportedFieldException)]),

        new FuzzTarget(
            "zkinterface-wtns",
            InvokeZkInterfaceWitness,
            [typeof(ArgumentException), typeof(R1csUnsupportedFieldException)]),

        new FuzzTarget(
            "longfellow-circuit",
            InvokeLongfellowCircuit,
            Type.EmptyTypes),

        new FuzzTarget(
            "bls-g1-oncurve",
            input => _ = BlsG1OnCurve(input, CurveParameterSet.Bls12Curve381),
            Type.EmptyTypes),

        new FuzzTarget(
            "bls-g2-oncurve",
            input => _ = BlsG2OnCurve(input, CurveParameterSet.Bls12Curve381),
            Type.EmptyTypes),

        new FuzzTarget(
            "bn254-g1-oncurve",
            input => _ = Bn254G1OnCurve(input, CurveParameterSet.Bn254),
            Type.EmptyTypes),

        new FuzzTarget(
            "bn254-g2-oncurve",
            input => _ = Bn254G2OnCurve(input, CurveParameterSet.Bn254),
            Type.EmptyTypes),

        new FuzzTarget(
            "compressed-round-poly",
            InvokeCompressedRoundPolynomial,
            [typeof(ArgumentException)]),

        new FuzzTarget(
            "raw-r1cs-witness",
            InvokeRawR1csWitness,
            [typeof(ArgumentException)]),

        new FuzzTarget(
            "bbs-commitment-with-proof",
            InvokeBbsCommitmentWithProof,
            [typeof(ArgumentException)]),

        new FuzzTarget(
            "bbs-blind-proof",
            InvokeBbsBlindProof,
            [typeof(ArgumentException)]),
    ];


    /// <summary>Exercises the Circom R1CS decoder with arbitrary fuzz input.</summary>
    private static void InvokeCircomR1cs(ReadOnlySpan<byte> input)
    {
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(input.ToArray()));
        using RawR1csInstance instance = CircomR1csReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomBinary,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);
    }


    /// <summary>Exercises the Circom witness decoder with arbitrary fuzz input.</summary>
    private static void InvokeCircomWitness(ReadOnlySpan<byte> input)
    {
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(input.ToArray()));
        using RawR1csWitness witness = CircomWitnessReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomWitness,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);
    }


    /// <summary>Exercises the built-in decoder with arbitrary fuzz input and an explicit staging pool.</summary>
    private static void InvokeZkInterfaceDecoder(ReadOnlySpan<byte> input)
    {
        ZkInterfaceCursorDecoder.Decoder(
            new ReadOnlySequence<byte>(input.ToArray()),
            new NoOpZkInterfaceMessageSink(), BaseMemoryPool.Shared,
            CancellationToken.None);
    }


    /// <summary>Exercises the ZkInterface R1CS decoder with arbitrary fuzz input.</summary>
    private static void InvokeZkInterfaceR1cs(ReadOnlySpan<byte> input)
    {
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(input.ToArray()));
        using RawR1csInstance instance = ZkInterfaceR1csReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.ZkInterface,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);
    }


    /// <summary>Exercises the ZkInterface witness decoder with arbitrary fuzz input.</summary>
    private static void InvokeZkInterfaceWitness(ReadOnlySpan<byte> input)
    {
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(input.ToArray()));
        using RawR1csWitness witness = ZkInterfaceWitnessReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.ZkInterface,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);
    }


    /// <summary>Exercises circuit parsing and releases successful output within an independent pool lifetime.</summary>
    private static void InvokeLongfellowCircuit(ReadOnlySpan<byte> input)
    {
        using var circuitScope = new LongfellowCircuitTestScope();
        circuitScope.TryRead(
            input,
            LongfellowFieldId,
            LongfellowElementBytes,
            out _,
            out _,
            out _,
            null);
    }


    /// <summary>Exercises the compressed sumcheck round-polynomial decoder with arbitrary fuzz input.</summary>
    private static void InvokeCompressedRoundPolynomial(ReadOnlySpan<byte> input)
    {
        using CompressedRoundPolynomial polynomial = CompressedRoundPolynomial.FromCompressedBytes(
            input,
            RoundPolynomialDegree,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared);
    }


    /// <summary>Exercises the raw R1CS witness decoder with arbitrary fuzz input.</summary>
    private static void InvokeRawR1csWitness(ReadOnlySpan<byte> input)
    {
        using RawR1csWitness witness = RawR1csWitness.FromCanonical(
            input,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared);
    }


    /// <summary>Exercises the BBS commitment-with-proof decoder with arbitrary fuzz input.</summary>
    private static void InvokeBbsCommitmentWithProof(ReadOnlySpan<byte> input)
    {
        using BbsCommitmentWithProof commitment = BbsCommitmentWithProof.FromCanonical(
            input,
            BbsCiphersuite.Bls12Curve381Sha256Blind,
            BaseMemoryPool.Shared);
    }


    /// <summary>Exercises the BBS blind-proof decoder with arbitrary fuzz input.</summary>
    private static void InvokeBbsBlindProof(ReadOnlySpan<byte> input)
    {
        using BbsBlindProof proof = BbsBlindProof.FromCanonical(
            input,
            BbsCiphersuite.Bls12Curve381Sha256Blind,
            BaseMemoryPool.Shared);
    }


    /// <summary>All methods default to no-ops on <see cref="IZkInterfaceMessageSink"/>, so this sink implementation is intentionally empty: it drives the decoder's framing/union-classification logic without accumulating any decoded state.</summary>
    private sealed class NoOpZkInterfaceMessageSink: IZkInterfaceMessageSink
    {
    }
}

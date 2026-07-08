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
internal sealed record FuzzTarget(string Name, FuzzTargetInvoke Invoke, Type[] ExpectedRejections);

/// <summary>
/// The registry of decoder fuzz targets, shared by <see cref="DecoderRobustnessTests"/> and any
/// future standalone fuzz harness (for example a SharpFuzz console driver). Each target wraps
/// exactly one hand-written decoder entry point with the wiring (format label, curve, pool)
/// its real call sites use; seed corpora are the caller's concern, not the registry's.
/// </summary>
internal static class DecoderFuzzTargets
{
    //Spartan's outer sumcheck round polynomial degree; any degree >= 2 exercises the same
    //FromCompressedBytes parse path, so the smallest realistic value keeps the fixed-length
    //edge-case inputs small.
    private const int RoundPolynomialDegree = 3;

    //Reference implementation's FieldID for GF(2^128), the field the small anchor circuit in
    //LongfellowCircuitReaderTests is serialized over.
    private const int LongfellowFieldId = 4;
    private const int LongfellowElementBytes = 16;

    private static readonly G1IsOnCurveDelegate BlsG1OnCurve = Bls12Curve381BigIntegerG1Reference.GetIsOnCurve();
    private static readonly G2IsOnCurveDelegate BlsG2OnCurve = Bls12Curve381BigIntegerG2Reference.GetIsOnCurve();
    private static readonly G1IsOnCurveDelegate Bn254G1OnCurve = Bn254BigIntegerG1Reference.GetIsOnCurve();
    private static readonly G2IsOnCurveDelegate Bn254G2OnCurve = Bn254BigIntegerG2Reference.GetIsOnCurve();


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


    private static void InvokeCircomR1cs(ReadOnlySpan<byte> input)
    {
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(input.ToArray()));
        using RawR1csInstance instance = CircomR1csReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomBinary,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            CancellationToken.None);
    }


    private static void InvokeCircomWitness(ReadOnlySpan<byte> input)
    {
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(input.ToArray()));
        using RawR1csWitness witness = CircomWitnessReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomWitness,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            CancellationToken.None);
    }


    private static void InvokeZkInterfaceDecoder(ReadOnlySpan<byte> input)
    {
        ZkInterfaceCursorDecoder.Decoder(
            new ReadOnlySequence<byte>(input.ToArray()),
            new NoOpZkInterfaceMessageSink(),
            CancellationToken.None);
    }


    private static void InvokeZkInterfaceR1cs(ReadOnlySpan<byte> input)
    {
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(input.ToArray()));
        using RawR1csInstance instance = ZkInterfaceR1csReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.ZkInterface,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            CancellationToken.None);
    }


    private static void InvokeZkInterfaceWitness(ReadOnlySpan<byte> input)
    {
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(input.ToArray()));
        using RawR1csWitness witness = ZkInterfaceWitnessReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.ZkInterface,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            CancellationToken.None);
    }


    private static void InvokeLongfellowCircuit(ReadOnlySpan<byte> input)
    {
        LongfellowCircuitReader.TryRead(
            input,
            LongfellowFieldId,
            LongfellowElementBytes,
            out _,
            out _,
            out _,
            null);
    }


    private static void InvokeCompressedRoundPolynomial(ReadOnlySpan<byte> input)
    {
        using CompressedRoundPolynomial polynomial = CompressedRoundPolynomial.FromCompressedBytes(
            input,
            RoundPolynomialDegree,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared);
    }


    private static void InvokeRawR1csWitness(ReadOnlySpan<byte> input)
    {
        using RawR1csWitness witness = RawR1csWitness.FromCanonical(
            input,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared);
    }


    private static void InvokeBbsCommitmentWithProof(ReadOnlySpan<byte> input)
    {
        using BbsCommitmentWithProof commitment = BbsCommitmentWithProof.FromCanonical(
            input,
            BbsCiphersuite.Bls12Curve381Sha256Blind,
            BaseMemoryPool.Shared);
    }


    private static void InvokeBbsBlindProof(ReadOnlySpan<byte> input)
    {
        using BbsBlindProof proof = BbsBlindProof.FromCanonical(
            input,
            BbsCiphersuite.Bls12Curve381Sha256Blind,
            BaseMemoryPool.Shared);
    }


    //All methods default to no-ops on IZkInterfaceMessageSink, so this sink implementation is
    //intentionally empty: it drives the decoder's framing/union-classification logic without
    //accumulating any decoded state.
    private sealed class NoOpZkInterfaceMessageSink: IZkInterfaceMessageSink
    {
    }
}

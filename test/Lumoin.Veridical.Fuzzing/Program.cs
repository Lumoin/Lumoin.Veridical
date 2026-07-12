using Lumoin.Base;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.Circom;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.IO.Pipelines;
using System.Threading;

namespace Lumoin.Veridical.Fuzzing;

internal delegate void FuzzTargetInvoke(ReadOnlySpan<byte> input);

/// <summary>
/// A SharpFuzz libFuzzer host for the library's hand-written external-input decoders. Each
/// process fuzzes exactly one target, named by the first argument (libFuzzer's own flags
/// follow it). The target set mirrors the public-surface external parsers covered by the
/// deterministic corpus-replay harness in Lumoin.Veridical.Tests (DecoderRobustnessTests /
/// DecoderFuzzTargets), which additionally covers the internal Longfellow and curve decoders
/// through InternalsVisibleTo.
/// </summary>
/// <remarks>
/// Built inert by default: without <c>-p:EnableSharpFuzz=true</c> the libFuzzer entry is not
/// compiled and <see cref="Main"/> only prints an activation notice. See FUZZING.md.
/// </remarks>
internal static class Program
{
    //Spartan's outer sumcheck round-polynomial degree; any degree >= 2 exercises the same
    //FromCompressedBytes parse path.
    private const int RoundPolynomialDegree = 3;

    private const int ExitUsage = 2;
#if ENABLE_SHARPFUZZ
    private const int ExitOk = 0;
#else
    private const int ExitInert = 1;
#endif

    private static readonly string[] TargetNames =
    [
        "circom-r1cs",
        "circom-wtns",
        "zkinterface-decoder",
        "zkinterface-r1cs",
        "zkinterface-wtns",
        "compressed-round-poly",
        "raw-r1cs-witness",
    ];


    private static int Main(string[] args)
    {
        if(args.Length < 1)
        {
            Console.Error.WriteLine("usage: Lumoin.Veridical.Fuzzing <target-name> [libFuzzer options]");
            Console.Error.WriteLine($"targets: {string.Join(", ", TargetNames)}");

            return ExitUsage;
        }

        FuzzTarget? target = ResolveTarget(args[0]);
        if(target is null)
        {
            Console.Error.WriteLine($"unknown target '{args[0]}'. targets: {string.Join(", ", TargetNames)}");

            return ExitUsage;
        }

#if ENABLE_SHARPFUZZ
        //libFuzzer drives this callback with each mutated input. A decoder's OWN documented
        //rejection of malformed input (FuzzTarget.ExpectedRejections, mirrored from the Tests
        //harness's DecoderFuzzTargets) is the contract's graceful "no" and is swallowed here; any
        //OTHER exception is the genuine finding libFuzzer records and minimizes. Without this
        //filter nearly every input a fuzzer generates is malformed and throws a documented
        //rejection, so every one would register as a false crash — starting with the empty unit.
        FuzzTarget resolved = target;
        SharpFuzz.Fuzzer.LibFuzzer.Run(bytes => Guard(resolved, bytes));

        return ExitOk;
#else
        Console.Error.WriteLine(
            "SharpFuzz is not enabled in this build. Rebuild with -p:EnableSharpFuzz=true after adding the " +
            "SharpFuzz package owner to NuGet.config <owners>; see FUZZING.md. The deterministic corpus-replay " +
            "harness in Lumoin.Veridical.Tests (DecoderRobustnessTests) exercises these same targets today.");

        return ExitInert;
#endif
    }


    //Each target pairs its decoder invocation with the exception types that count as a graceful,
    //documented rejection of malformed input (mirrors DecoderFuzzTargets.All in the Tests harness).
    private static FuzzTarget? ResolveTarget(string targetName) => targetName switch
    {
        "circom-r1cs" => new FuzzTarget(InvokeCircomR1cs, [typeof(ArgumentException), typeof(R1csUnsupportedFieldException)]),
        "circom-wtns" => new FuzzTarget(InvokeCircomWitness, [typeof(ArgumentException), typeof(R1csUnsupportedFieldException)]),
        "zkinterface-decoder" => new FuzzTarget(InvokeZkInterfaceDecoder, [typeof(ArgumentException)]),
        "zkinterface-r1cs" => new FuzzTarget(InvokeZkInterfaceR1cs, [typeof(ArgumentException), typeof(R1csUnsupportedFieldException)]),
        "zkinterface-wtns" => new FuzzTarget(InvokeZkInterfaceWitness, [typeof(ArgumentException), typeof(R1csUnsupportedFieldException)]),
        "compressed-round-poly" => new FuzzTarget(InvokeCompressedRoundPolynomial, [typeof(ArgumentException)]),
        "raw-r1cs-witness" => new FuzzTarget(InvokeRawR1csWitness, [typeof(ArgumentException)]),
        _ => null,
    };


#if ENABLE_SHARPFUZZ
    //Runs one decoder invocation under the same contract the deterministic harness asserts: a
    //documented rejection returns normally (not a finding); any other exception propagates so
    //libFuzzer records and minimizes it.
    private static void Guard(FuzzTarget target, ReadOnlySpan<byte> input)
    {
        try
        {
            target.Invoke(input);
        }
        catch(Exception exception) when(IsDocumentedRejection(exception, target.ExpectedRejections))
        {
            //Documented rejection of malformed input — the contract's graceful "no", not a crash.
        }
    }


    private static bool IsDocumentedRejection(Exception exception, Type[] expectedRejections)
    {
        foreach(Type expected in expectedRejections)
        {
            if(expected.IsInstanceOfType(exception))
            {
                return true;
            }
        }

        return false;
    }
#endif


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


    //One decoder under fuzz: its invocation wrapper and the exception types that count as a
    //graceful, documented rejection of malformed input.
    private sealed record FuzzTarget(FuzzTargetInvoke Invoke, Type[] ExpectedRejections);


    //All IZkInterfaceMessageSink members default to no-ops, so this sink drives the decoder's
    //framing and union-classification logic without accumulating any decoded state.
    private sealed class NoOpZkInterfaceMessageSink: IZkInterfaceMessageSink
    {
    }
}

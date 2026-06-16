using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers.Binary;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// Shared scaffolding for GKR tests over <c>GF(2^128)</c>: the binary-field delegates, the
/// deterministic randomness factory the committed prover requires, and the committed
/// prove/verify wiring on the binary Reed–Solomon domain — the binary-field counterpart of
/// <see cref="GkrTestSupport"/>. The engine tests run on the fast <see cref="Gf2k128Backend"/>
/// (byte-identical to the reference by the agreement gates; the field-gate tests keep the
/// BigInteger reference as the independent oracle).
/// </summary>
internal static class GkrGf2kTestSupport
{
    public const int ScalarSize = 32;

    private const int InverseRate = 4;
    private const int OpenedColumns = 4;
    private const int Block = 64;

    public static ScalarAddDelegate Add { get; } = Gf2k128Backend.GetAdd();

    public static ScalarSubtractDelegate Subtract { get; } = Gf2k128Backend.GetSubtract();

    public static ScalarMultiplyDelegate Multiply { get; } = Gf2k128Backend.GetMultiply();

    public static ScalarInvertDelegate Invert { get; } = Gf2k128Backend.GetInvert();

    public static ScalarReduceDelegate Reduce { get; } = Gf2k128Backend.GetReduce();

    public static FiatShamirHashDelegate Hash { get; } = Blake3FiatShamirBackend.GetHash();

    public static FiatShamirSqueezeDelegate Squeeze { get; } = Blake3FiatShamirBackend.GetSqueeze();

    public static byte[] One { get; } = GkrTestSupport.Scalar(1);


    public static FiatShamirTranscript NewTranscript(FiatShamirDomainLabel domain, ReadOnlySpan<byte> seed, ReadOnlySpan<byte> statement)
    {
        var transcript = FiatShamirTranscript.Initialise(domain, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        transcript.AbsorbBytes(GkrTranscriptLabels.Inputs, statement, Hash);

        return transcript;
    }


    public static GkrCommittedProof Prove(
        GkrCircuit circuit,
        ReadOnlySpan<byte> inputs,
        int copyCount,
        byte[] randomnessSeed,
        FiatShamirTranscript transcript,
        LigeroQuadraticConstraint[] statementQuadratics)
    {
        var parameters = new LigeroParameters(copyCount * circuit.InputCount, statementQuadratics.Length, InverseRate, OpenedColumns, Block, LigeroNodeDomain.BinaryField);

        return GkrCommittedProver.Prove(
            circuit, inputs, copyCount, parameters, [], [], statementQuadratics,
            () => new BinaryDeterministicRandom(randomnessSeed).AsDelegate(),
            Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            transcript, Squeeze, Hash, Hash, GkrTestSupport.Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared);
    }


    public static bool Verify(
        GkrCircuit circuit,
        ReadOnlySpan<byte> outputs,
        int copyCount,
        GkrCommittedProof proof,
        FiatShamirTranscript transcript,
        LigeroQuadraticConstraint[] statementQuadratics)
    {
        var parameters = new LigeroParameters(copyCount * circuit.InputCount, statementQuadratics.Length, InverseRate, OpenedColumns, Block, LigeroNodeDomain.BinaryField);

        return GkrCommittedVerifier.Verify(
            circuit, outputs, copyCount, proof, parameters, [], [], statementQuadratics,
            Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            transcript, Squeeze, Hash, Hash, GkrTestSupport.Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared);
    }


    public static GkrCommittedProof Prove(
        GkrCommittedInstance[] instances,
        ReadOnlySpan<byte> witness,
        byte[] randomnessSeed,
        FiatShamirTranscript transcript,
        LigeroLinearConstraint[] statementConstraints,
        byte[] statementTargets,
        LigeroQuadraticConstraint[] statementQuadratics)
    {
        var parameters = new LigeroParameters(WitnessCount(instances), statementQuadratics.Length, InverseRate, OpenedColumns, Block, LigeroNodeDomain.BinaryField);

        return GkrCommittedProver.Prove(
            instances, witness, parameters, statementConstraints, statementTargets, statementQuadratics,
            () => new BinaryDeterministicRandom(randomnessSeed).AsDelegate(),
            Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            transcript, Squeeze, Hash, Hash, GkrTestSupport.Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared);
    }


    public static bool Verify(
        GkrCommittedInstance[] instances,
        ReadOnlySpan<byte> outputs,
        GkrCommittedProof proof,
        FiatShamirTranscript transcript,
        LigeroLinearConstraint[] statementConstraints,
        byte[] statementTargets,
        LigeroQuadraticConstraint[] statementQuadratics)
    {
        var parameters = new LigeroParameters(WitnessCount(instances), statementQuadratics.Length, InverseRate, OpenedColumns, Block, LigeroNodeDomain.BinaryField);

        return GkrCommittedVerifier.Verify(
            instances, outputs, proof, parameters, statementConstraints, statementTargets, statementQuadratics,
            Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            transcript, Squeeze, Hash, Hash, GkrTestSupport.Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared);
    }


    public static void Outputs(GkrCircuit circuit, ReadOnlySpan<byte> inputs, int copyCount, Span<byte> outputs)
    {
        using GkrWireTables tables = circuit.EvaluateDataParallel(inputs, copyCount, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);
        tables.Table(0).Span.CopyTo(outputs);
    }


    private static int WitnessCount(GkrCommittedInstance[] instances)
    {
        int count = 0;
        foreach(GkrCommittedInstance instance in instances)
        {
            count += instance.CopyCount * instance.Circuit.InputCount;
        }

        return count;
    }


    //A reproducible GF(2^128) randomness source: BLAKE3 of seed‖counter, the low 128 bits as
    //the element. The factory restart is signature ceremony — the committed prover draws once.
    private sealed class BinaryDeterministicRandom
    {
        private byte[] Seed { get; }

        private int Counter { get; set; }

        public BinaryDeterministicRandom(ReadOnlySpan<byte> seed) => Seed = seed.ToArray();

        public ScalarRandomDelegate AsDelegate() => Fill;

        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[Seed.Length + sizeof(int)];
            Seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[Seed.Length..], Counter);
            Counter++;

            Span<byte> digest = stackalloc byte[32];
            Blake3.Hash(input, digest);
            destination.Clear();
            digest[..16].CopyTo(destination[16..]);

            return inboundTag;
        }
    }
}

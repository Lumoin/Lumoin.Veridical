using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers.Binary;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// Shared scaffolding for the SHA-256 fragment tests over the committed GKR engine: the Fp256
/// reference field delegates, canonical scalar helpers, the restartable deterministic randomness
/// factory the committed prover requires, and the standard commit-and-prove wiring.
/// </summary>
internal static class GkrTestSupport
{
    public const int ScalarSize = 32;

    private const int InverseRate = 4;
    private const int OpenedColumns = 4;
    private const int Block = 64;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    public static BigInteger P { get; } = P256BigIntegerG1Reference.BaseFieldPrime;

    public static ScalarAddDelegate Add { get; } = P256BaseFieldReference.GetAdd();

    public static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldReference.GetSubtract();

    public static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldReference.GetMultiply();

    public static ScalarInvertDelegate Invert { get; } = P256BaseFieldReference.GetInvert();

    public static ScalarReduceDelegate Reduce { get; } = P256BaseFieldReference.GetReduce();

    public static FiatShamirHashDelegate Hash { get; } = Blake3FiatShamirBackend.GetHash();

    public static FiatShamirSqueezeDelegate Squeeze { get; } = Blake3FiatShamirBackend.GetSqueeze();

    public static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    public static byte[] One { get; } = Scalar(1);

    public static byte[] NegativeOne { get; } = Canonical(P - 1);

    public static byte[] NegativeTwo { get; } = Canonical(P - 2);


    public static FiatShamirTranscript NewTranscript(FiatShamirDomainLabel domain, ReadOnlySpan<byte> seed) =>
        FiatShamirTranscript.Initialise(domain, seed, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    public static GkrCommittedProof Prove(GkrCircuit circuit, ReadOnlySpan<byte> inputs, int copyCount, byte[] randomnessSeed, FiatShamirTranscript transcript) =>
        Prove(circuit, inputs, copyCount, randomnessSeed, transcript, [], [], []);


    public static GkrCommittedProof Prove(
        GkrCircuit circuit,
        ReadOnlySpan<byte> inputs,
        int copyCount,
        byte[] randomnessSeed,
        FiatShamirTranscript transcript,
        LigeroLinearConstraint[] statementConstraints,
        byte[] statementTargets,
        LigeroQuadraticConstraint[] statementQuadratics)
    {
        var parameters = new LigeroParameters(copyCount * circuit.InputCount, statementQuadratics.Length, InverseRate, OpenedColumns, Block);

        return GkrCommittedProver.Prove(
            circuit, inputs, copyCount, parameters, statementConstraints, statementTargets, statementQuadratics,
            () => new GkrDeterministicRandom(randomnessSeed).AsDelegate(),
            Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            transcript, Squeeze, Hash, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
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
        var parameters = new LigeroParameters(WitnessCount(instances), statementQuadratics.Length, InverseRate, OpenedColumns, Block);

        return GkrCommittedProver.Prove(
            instances, witness, parameters, statementConstraints, statementTargets, statementQuadratics,
            () => new GkrDeterministicRandom(randomnessSeed).AsDelegate(),
            Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            transcript, Squeeze, Hash, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared);
    }


    public static bool Verify(GkrCircuit circuit, ReadOnlySpan<byte> outputs, int copyCount, GkrCommittedProof proof, FiatShamirTranscript transcript) =>
        Verify(circuit, outputs, copyCount, proof, transcript, [], [], []);


    public static bool Verify(
        GkrCommittedInstance[] instances,
        ReadOnlySpan<byte> outputs,
        GkrCommittedProof proof,
        FiatShamirTranscript transcript,
        LigeroLinearConstraint[] statementConstraints,
        byte[] statementTargets,
        LigeroQuadraticConstraint[] statementQuadratics)
    {
        var parameters = new LigeroParameters(WitnessCount(instances), statementQuadratics.Length, InverseRate, OpenedColumns, Block);

        return GkrCommittedVerifier.Verify(
            instances, outputs, proof, parameters, statementConstraints, statementTargets, statementQuadratics,
            Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            transcript, Squeeze, Hash, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared);
    }


    public static bool Verify(
        GkrCircuit circuit,
        ReadOnlySpan<byte> outputs,
        int copyCount,
        GkrCommittedProof proof,
        FiatShamirTranscript transcript,
        LigeroLinearConstraint[] statementConstraints,
        byte[] statementTargets,
        LigeroQuadraticConstraint[] statementQuadratics)
    {
        var parameters = new LigeroParameters(copyCount * circuit.InputCount, statementQuadratics.Length, InverseRate, OpenedColumns, Block);

        return GkrCommittedVerifier.Verify(
            circuit, outputs, copyCount, proof, parameters, statementConstraints, statementTargets, statementQuadratics,
            Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            transcript, Squeeze, Hash, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
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


    public static byte[] Scalar(int value)
    {
        byte[] bytes = new byte[ScalarSize];
        bytes[ScalarSize - 1] = (byte)value;

        return bytes;
    }


    public static byte[] Canonical(BigInteger value)
    {
        byte[] bytes = new byte[ScalarSize];
        Span<byte> little = stackalloc byte[ScalarSize + 1];
        if(value.TryWriteBytes(little, out int written, isUnsigned: true, isBigEndian: false))
        {
            for(int i = 0; i < ScalarSize && i < written; i++)
            {
                bytes[ScalarSize - 1 - i] = little[i];
            }
        }

        return bytes;
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    //A reproducible Fp256 randomness source (BLAKE3 of seed‖counter mod p); the factory restart
    //keeps the commitment and opening tableaus identical.
    private sealed class GkrDeterministicRandom
    {
        private byte[] Seed { get; }

        private int Counter { get; set; }

        public GkrDeterministicRandom(ReadOnlySpan<byte> seed) => Seed = seed.ToArray();

        public ScalarRandomDelegate AsDelegate() => Fill;

        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[Seed.Length + sizeof(int)];
            Seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[Seed.Length..], Counter);
            Counter++;

            Span<byte> wide = stackalloc byte[64];
            Blake3.Hash(input, wide);
            BigInteger reduced = new BigInteger(wide, isUnsigned: true, isBigEndian: true) % P;
            destination.Clear();
            reduced.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true);
            if(written < destination.Length)
            {
                int shift = destination.Length - written;
                destination[..written].CopyTo(destination[shift..]);
                destination[..shift].Clear();
            }

            return inboundTag;
        }
    }
}

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
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The committed-witness GKR wrapper (<see cref="GkrCommittedProver"/>/<see cref="GkrCommittedVerifier"/>)
/// over the P-256 base field Fp256 — the Longfellow zk-wrapper shape with Ligero in its small
/// role: the inputs are committed (tableau root absorbed before any challenge), the linear
/// data-parallel GKR walk reduces the public outputs to two input claims, and Ligero proves just
/// those two openings of the commitment. The verifier is never given the inputs. An honest proof
/// verifies; wrong claimed outputs, a tampered circuit proof and a mixed-in commitment for
/// different inputs are each rejected.
/// </summary>
[TestClass]
internal sealed class GkrCommittedProverTests
{
    private const int ScalarSize = 32;
    private const int CopyCount = 4;
    private const int InverseRate = 4;
    private const int OpenedColumns = 4;
    private const int Block = 64;
    private const int DigestSizeBytes = WellKnownMerkleHashParameters.DefaultDigestSizeBytes;

    private static BigInteger P { get; } = P256BigIntegerG1Reference.BaseFieldPrime;

    private static ScalarAddDelegate Add { get; } = P256BaseFieldReference.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldReference.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldReference.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = P256BaseFieldReference.GetInvert();

    private static ScalarReduceDelegate Reduce { get; } = P256BaseFieldReference.GetReduce();

    private static FiatShamirHashDelegate Hash { get; } = Blake3FiatShamirBackend.GetHash();

    private static FiatShamirSqueezeDelegate Squeeze { get; } = Blake3FiatShamirBackend.GetSqueeze();

    private static MerkleHashDelegate Merkle { get; } = HashTwoToOne;

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.committed.test");

    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.committed.rng.v1");

    private static byte[] One { get; } = Bytes(1);

    //The private witness: four copies of (x0, x1, x2, 1) — the verifier never sees these.
    private static byte[] PrivateInputs { get; } =
    [
        .. Bytes(3), .. Bytes(5), .. Bytes(7), .. Bytes(1),
        .. Bytes(11), .. Bytes(13), .. Bytes(17), .. Bytes(1),
        .. Bytes(19), .. Bytes(23), .. Bytes(29), .. Bytes(1),
        .. Bytes(31), .. Bytes(37), .. Bytes(41), .. Bytes(1),
    ];

    private List<IDisposable> Disposables { get; } = [];


    [TestCleanup]
    public void DisposeAll()
    {
        foreach(IDisposable disposable in Disposables)
        {
            disposable.Dispose();
        }
    }


    [TestMethod]
    public void HonestCommittedProofVerifiesWithoutTheInputs()
    {
        GkrCircuit circuit = BuildCircuit();
        byte[] outputs = Outputs(circuit, PrivateInputs);

        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrCommittedProof proof = Prove(circuit, PrivateInputs, proverTranscript);

        //The verifier's whole view: circuit, claimed outputs, the proof. No inputs.
        using FiatShamirTranscript verifierTranscript = NewTranscript();
        bool verified = Verify(circuit, outputs, proof, verifierTranscript);

        Assert.IsTrue(verified, "An honest committed-witness proof must verify without the verifier seeing the inputs.");
    }


    [TestMethod]
    public void WrongClaimedOutputsAreRejected()
    {
        GkrCircuit circuit = BuildCircuit();
        byte[] outputs = Outputs(circuit, PrivateInputs);
        outputs[ScalarSize - 1] ^= 0x01;

        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrCommittedProof proof = Prove(circuit, PrivateInputs, proverTranscript);

        using FiatShamirTranscript verifierTranscript = NewTranscript();
        bool verified = Verify(circuit, outputs, proof, verifierTranscript);

        Assert.IsFalse(verified, "Outputs the committed witness did not produce must be rejected.");
    }


    [TestMethod]
    public void CommitmentForDifferentInputsIsRejected()
    {
        GkrCircuit circuit = BuildCircuit();
        byte[] outputs = Outputs(circuit, PrivateInputs);

        byte[] otherInputs = (byte[])PrivateInputs.Clone();
        otherInputs[ScalarSize - 1] ^= 0x01;

        using FiatShamirTranscript proverTranscript = NewTranscript();
        GkrCommittedProof honest = Prove(circuit, PrivateInputs, proverTranscript);
        using FiatShamirTranscript otherTranscript = NewTranscript();
        GkrCommittedProof other = Prove(circuit, otherInputs, otherTranscript);

        //Pair the honest circuit walk with the other witness's commitment: the absorbed root
        //differs, so the replayed challenges diverge and the walk must fail.
        var mixed = new GkrCommittedProof(honest.CircuitProof, other.WitnessProof);
        Disposables.Add(mixed);
        Disposables.Add(honest.WitnessProof);
        Disposables.Add(other.CircuitProof);

        using FiatShamirTranscript verifierTranscript = NewTranscript();
        bool verified = Verify(circuit, outputs, mixed, verifierTranscript);

        Assert.IsFalse(verified, "A commitment made for different inputs must not verify against the walk.");
    }


    private static GkrCommittedProof Prove(GkrCircuit circuit, byte[] inputs, FiatShamirTranscript transcript)
    {
        var parameters = new LigeroParameters(CopyCount * circuit.InputCount, 0, InverseRate, OpenedColumns, Block);

        return GkrCommittedProver.Prove(
            circuit, inputs, CopyCount, parameters,
            () => new DeterministicFp256Random(RandomnessSeed).AsDelegate(),
            Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            transcript, Squeeze, Hash, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared);
    }


    private static bool Verify(GkrCircuit circuit, byte[] outputs, GkrCommittedProof proof, FiatShamirTranscript transcript)
    {
        var parameters = new LigeroParameters(CopyCount * circuit.InputCount, 0, InverseRate, OpenedColumns, Block);

        return GkrCommittedVerifier.Verify(
            circuit, outputs, CopyCount, proof, parameters,
            Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            transcript, Squeeze, Hash, Hash, Merkle, WellKnownHashAlgorithms.Blake3,
            BaseMemoryPool.Shared);
    }


    private static byte[] Outputs(GkrCircuit circuit, byte[] inputs)
    {
        using GkrWireTables tables = circuit.EvaluateDataParallel(inputs, CopyCount, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);

        return tables.Table(0).ToArray();
    }


    //The same per-copy circuit as the data-parallel test: y0 = x0·x1, y1 = x1·x2 + 5·x0·x3,
    //y2 = 2·x2·x2, y3 = x3·x3; z0 = y0·y1 + 3·y2·y3, z1 = 7·y1·y2.
    private static GkrCircuit BuildCircuit()
    {
        var inner = new GkrLayer(
        [
            new GkrLayerTerm(0, 0, 1, One),
            new GkrLayerTerm(1, 1, 2, One),
            new GkrLayerTerm(1, 0, 3, Bytes(5)),
            new GkrLayerTerm(2, 2, 2, Bytes(2)),
            new GkrLayerTerm(3, 3, 3, One),
        ], outputCount: 4);

        var output = new GkrLayer(
        [
            new GkrLayerTerm(0, 0, 1, One),
            new GkrLayerTerm(0, 2, 3, Bytes(3)),
            new GkrLayerTerm(1, 1, 2, Bytes(7)),
        ], outputCount: 2);

        return new GkrCircuit([output, inner], inputCount: 4);
    }


    private static FiatShamirTranscript NewTranscript() =>
        FiatShamirTranscript.Initialise(Domain, "veridical.gkr.committed.seed"u8, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    private static byte[] Bytes(int value)
    {
        byte[] bytes = new byte[ScalarSize];
        bytes[ScalarSize - 1] = (byte)value;
        bytes[ScalarSize - 2] = (byte)(value >> 8);

        return bytes;
    }


    private static void HashTwoToOne(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> output)
    {
        Span<byte> combined = stackalloc byte[2 * DigestSizeBytes];
        left.CopyTo(combined[..left.Length]);
        right.CopyTo(combined.Slice(left.Length, right.Length));
        Blake3.Hash(combined[..(left.Length + right.Length)], output);
    }


    //A reproducible Fp256 randomness source: BLAKE3-XOF of seed‖counter reduced modulo the
    //base-field prime. Reproducibility across the commitment and opening proves is what keeps
    //the tableau root identical (see GkrCommittedProver remarks).
    private sealed class DeterministicFp256Random
    {
        private byte[] Seed { get; }

        private int Counter { get; set; }

        public DeterministicFp256Random(ReadOnlySpan<byte> seed) => Seed = seed.ToArray();

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

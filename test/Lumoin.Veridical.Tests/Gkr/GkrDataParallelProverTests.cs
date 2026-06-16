using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Hashing;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The data-parallel GKR prover and verifier
/// (<see cref="GkrDataParallelProver"/>/<see cref="GkrDataParallelVerifier"/>) over the P-256
/// base field Fp256: four copies of the same two-layer per-copy circuit with distinct inputs per
/// copy, the copy variable bound once across all copies. The data-parallel evaluation is gated
/// per copy against the single-copy evaluator; an honest proof verifies end to end (the
/// copy-round phase, the hand sumchecks, and the tensor-point input checks); a tampered
/// copy-round polynomial, wrong claimed outputs and wrong claimed inputs are each rejected.
/// </summary>
[TestClass]
internal sealed class GkrDataParallelProverTests
{
    private const int ScalarSize = 32;
    private const int CopyCount = 4;

    private static ScalarAddDelegate Add { get; } = P256BaseFieldReference.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldReference.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldReference.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = P256BaseFieldReference.GetInvert();

    private static ScalarReduceDelegate Reduce { get; } = P256BaseFieldReference.GetReduce();

    private static FiatShamirHashDelegate Hash { get; } = Blake3FiatShamirBackend.GetHash();

    private static FiatShamirSqueezeDelegate Squeeze { get; } = Blake3FiatShamirBackend.GetSqueeze();

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.parallel.test");

    private static byte[] One { get; } = Bytes(1);

    //Four copies of (x0, x1, x2, 1) with distinct values per copy; the fourth wire is the
    //constant-one the per-copy linear terms route through.
    private static byte[] Inputs { get; } =
    [
        .. Bytes(3), .. Bytes(5), .. Bytes(7), .. Bytes(1),
        .. Bytes(11), .. Bytes(13), .. Bytes(17), .. Bytes(1),
        .. Bytes(19), .. Bytes(23), .. Bytes(29), .. Bytes(1),
        .. Bytes(31), .. Bytes(37), .. Bytes(41), .. Bytes(1),
    ];


    [TestMethod]
    public void DataParallelEvaluationMatchesPerCopyEvaluation()
    {
        GkrCircuit circuit = BuildCircuit();
        using GkrWireTables parallel = circuit.EvaluateDataParallel(Inputs, CopyCount, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);

        int outputCount = circuit.Layers[0].OutputCount;
        for(int c = 0; c < CopyCount; c++)
        {
            ReadOnlySpan<byte> copyInputs = Inputs.AsSpan(c * circuit.InputCount * ScalarSize, circuit.InputCount * ScalarSize);
            using GkrWireTables single = circuit.Evaluate(copyInputs, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);

            bool matches = parallel.Table(0).Span.Slice(c * outputCount * ScalarSize, outputCount * ScalarSize)
                .SequenceEqual(single.Table(0).Span);
            Assert.IsTrue(matches, $"Copy {c} of the data-parallel evaluation must match the single-copy evaluator.");
        }
    }


    [TestMethod]
    public void HonestDataParallelProofVerifies()
    {
        GkrCircuit circuit = BuildCircuit();
        using GkrWireTables tables = circuit.EvaluateDataParallel(Inputs, CopyCount, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);
        byte[] outputs = tables.Table(0).ToArray();

        using FiatShamirTranscript proverTranscript = NewTranscript(Inputs);
        using GkrDataParallelProverResult result = GkrDataParallelProver.Prove(
            circuit, Inputs, CopyCount, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            proverTranscript, Squeeze, Hash, BaseMemoryPool.Shared);
        using GkrDataParallelProof proof = result.Proof;

        using FiatShamirTranscript verifierTranscript = NewTranscript(Inputs);
        bool verified = GkrDataParallelVerifier.Verify(
            circuit, Inputs, outputs, CopyCount, proof, Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            verifierTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        Assert.IsTrue(verified, "An honest data-parallel GKR proof must verify down to the inputs.");
    }


    [TestMethod]
    public void TamperedCopyRoundIsRejected()
    {
        GkrCircuit circuit = BuildCircuit();
        using GkrWireTables tables = circuit.EvaluateDataParallel(Inputs, CopyCount, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);
        byte[] outputs = tables.Table(0).ToArray();

        using FiatShamirTranscript proverTranscript = NewTranscript(Inputs);
        using GkrDataParallelProverResult result = GkrDataParallelProver.Prove(
            circuit, Inputs, CopyCount, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            proverTranscript, Squeeze, Hash, BaseMemoryPool.Shared);
        using GkrDataParallelProof proof = result.Proof;

        //Copy both layers, flipping a byte in the output layer's first copy-round polynomial.
        byte[] tamperedRounds = proof.LayerProofs[0].CopyRoundPolynomials.ToArray();
        tamperedRounds[ScalarSize - 1] ^= 0x01;
        var copies = new GkrDataParallelLayerProof[2];
        copies[0] = GkrDataParallelLayerProof.FromParts(
            tamperedRounds, proof.LayerProofs[0].CopyRoundCount,
            CopyHandProof(proof.LayerProofs[0].HandProof), BaseMemoryPool.Shared);
        copies[1] = GkrDataParallelLayerProof.FromParts(
            proof.LayerProofs[1].CopyRoundPolynomials.Span, proof.LayerProofs[1].CopyRoundCount,
            CopyHandProof(proof.LayerProofs[1].HandProof), BaseMemoryPool.Shared);
        using var tamperedProof = new GkrDataParallelProof(copies);

        using FiatShamirTranscript verifierTranscript = NewTranscript(Inputs);
        bool verified = GkrDataParallelVerifier.Verify(
            circuit, Inputs, outputs, CopyCount, tamperedProof, Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            verifierTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "A tampered copy-round polynomial must be rejected.");
    }


    [TestMethod]
    public void WrongClaimedOutputsAreRejected()
    {
        GkrCircuit circuit = BuildCircuit();
        using GkrWireTables tables = circuit.EvaluateDataParallel(Inputs, CopyCount, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);

        using FiatShamirTranscript proverTranscript = NewTranscript(Inputs);
        using GkrDataParallelProverResult result = GkrDataParallelProver.Prove(
            circuit, Inputs, CopyCount, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            proverTranscript, Squeeze, Hash, BaseMemoryPool.Shared);
        using GkrDataParallelProof proof = result.Proof;

        byte[] wrongOutputs = tables.Table(0).ToArray();
        wrongOutputs[ScalarSize - 1] ^= 0x01;

        using FiatShamirTranscript verifierTranscript = NewTranscript(Inputs);
        bool verified = GkrDataParallelVerifier.Verify(
            circuit, Inputs, wrongOutputs, CopyCount, proof, Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            verifierTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "Outputs the copies did not produce must be rejected.");
    }


    [TestMethod]
    public void WrongClaimedInputsAreRejected()
    {
        GkrCircuit circuit = BuildCircuit();
        using GkrWireTables tables = circuit.EvaluateDataParallel(Inputs, CopyCount, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);
        byte[] outputs = tables.Table(0).ToArray();

        using FiatShamirTranscript proverTranscript = NewTranscript(Inputs);
        using GkrDataParallelProverResult result = GkrDataParallelProver.Prove(
            circuit, Inputs, CopyCount, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            proverTranscript, Squeeze, Hash, BaseMemoryPool.Shared);
        using GkrDataParallelProof proof = result.Proof;

        byte[] wrongInputs = (byte[])Inputs.Clone();
        wrongInputs[ScalarSize - 1] ^= 0x01;

        using FiatShamirTranscript verifierTranscript = NewTranscript(Inputs);
        bool verified = GkrDataParallelVerifier.Verify(
            circuit, wrongInputs, outputs, CopyCount, proof, Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            verifierTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "Inputs the proof was not produced for must be rejected.");
    }


    private static ProductSumcheckProof CopyHandProof(ProductSumcheckProof source) =>
        ProductSumcheckProof.FromParts(
            source.RoundPolynomials.Span, source.FinalValues.Span,
            source.VariableCount, source.FactorCount, BaseMemoryPool.Shared);


    //The same per-copy circuit as the single-copy layered test: y0 = x0·x1,
    //y1 = x1·x2 + 5·x0·x3, y2 = 2·x2·x2, y3 = x3·x3; z0 = y0·y1 + 3·y2·y3, z1 = 7·y1·y2.
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


    //The caller binds the statement (here the public inputs) before proving or verifying.
    private static FiatShamirTranscript NewTranscript(byte[] statement)
    {
        var transcript = FiatShamirTranscript.Initialise(Domain, "veridical.gkr.parallel.seed"u8, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);
        transcript.AbsorbBytes(GkrTranscriptLabels.Inputs, statement, Hash);

        return transcript;
    }


    private static byte[] Bytes(int value)
    {
        byte[] bytes = new byte[ScalarSize];
        bytes[ScalarSize - 1] = (byte)value;
        bytes[ScalarSize - 2] = (byte)(value >> 8);

        return bytes;
    }
}

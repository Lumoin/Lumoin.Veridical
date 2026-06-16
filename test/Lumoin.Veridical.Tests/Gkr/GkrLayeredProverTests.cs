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
/// The layered GKR prover and verifier (<see cref="GkrProver"/>/<see cref="GkrVerifier"/>) over
/// the P-256 base field Fp256, on a hand-built two-layer circuit exercising multiplication
/// gates, scaled terms and linear terms routed through a constant-one wire. The evaluation is
/// gated against a BigInteger oracle; an honest proof verifies end to end (output claim → layer
/// sumchecks → input multilinear check); a tampered layer proof, wrong claimed outputs and wrong
/// claimed inputs are each rejected.
/// </summary>
[TestClass]
internal sealed class GkrLayeredProverTests
{
    private const int ScalarSize = 32;
    private static BigInteger P { get; } = P256BigIntegerG1Reference.BaseFieldPrime;

    private static ScalarAddDelegate Add { get; } = P256BaseFieldReference.GetAdd();

    private static ScalarSubtractDelegate Subtract { get; } = P256BaseFieldReference.GetSubtract();

    private static ScalarMultiplyDelegate Multiply { get; } = P256BaseFieldReference.GetMultiply();

    private static ScalarInvertDelegate Invert { get; } = P256BaseFieldReference.GetInvert();

    private static ScalarReduceDelegate Reduce { get; } = P256BaseFieldReference.GetReduce();

    private static FiatShamirHashDelegate Hash { get; } = Blake3FiatShamirBackend.GetHash();

    private static FiatShamirSqueezeDelegate Squeeze { get; } = Blake3FiatShamirBackend.GetSqueeze();

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.layered.test");

    private static byte[] One { get; } = Bytes(1);

    //Inputs x0 = 3, x1 = 5, x2 = 7 and the constant-one wire x3 the linear terms route through.
    private static byte[] Inputs { get; } = [.. Bytes(3), .. Bytes(5), .. Bytes(7), .. Bytes(1)];


    [TestMethod]
    public void EvaluatesTheLayeredCircuitLikeTheOracle()
    {
        GkrCircuit circuit = BuildCircuit();
        using GkrWireTables tables = circuit.Evaluate(Inputs, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);

        //The same circuit in plain arithmetic: y0 = x0·x1, y1 = x1·x2 + 5·x0, y2 = 2·x2²,
        //y3 = 1; z0 = y0·y1 + 3·y2·y3, z1 = 7·y1·y2.
        BigInteger y0 = Mod(3 * 5);
        BigInteger y1 = Mod((5 * 7) + (5 * 3));
        BigInteger y2 = Mod(2 * 7 * 7);
        BigInteger y3 = BigInteger.One;
        BigInteger z0 = Mod((y0 * y1) + (3 * y2 * y3));
        BigInteger z1 = Mod(7 * y1 * y2);

        ReadOnlySpan<byte> outputs = tables.Table(0).Span;
        Assert.AreEqual(z0, ToInteger(outputs[..ScalarSize]), "Output 0 must match the oracle.");
        Assert.AreEqual(z1, ToInteger(outputs.Slice(ScalarSize, ScalarSize)), "Output 1 must match the oracle.");
    }


    [TestMethod]
    public void HonestLayeredProofVerifies()
    {
        GkrCircuit circuit = BuildCircuit();
        using GkrWireTables tables = circuit.Evaluate(Inputs, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);
        byte[] outputs = tables.Table(0).ToArray();

        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrProof proof = GkrProver.Prove(
            circuit, Inputs, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            proverTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        using FiatShamirTranscript verifierTranscript = NewTranscript();
        bool verified = GkrVerifier.Verify(
            circuit, Inputs, outputs, proof, Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            verifierTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        Assert.IsTrue(verified, "An honest layered GKR proof must verify down to the inputs.");
    }


    [TestMethod]
    public void TamperedLayerProofIsRejected()
    {
        GkrCircuit circuit = BuildCircuit();
        using GkrWireTables tables = circuit.Evaluate(Inputs, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);
        byte[] outputs = tables.Table(0).ToArray();

        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrProof proof = GkrProver.Prove(
            circuit, Inputs, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            proverTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        //Copy both layer proofs, flipping a byte in the output layer's first round polynomial.
        byte[] tamperedRounds = proof.LayerProofs[0].RoundPolynomials.ToArray();
        tamperedRounds[ScalarSize - 1] ^= 0x01;
        var copies = new ProductSumcheckProof[2];
        copies[0] = ProductSumcheckProof.FromParts(
            tamperedRounds, proof.LayerProofs[0].FinalValues.Span,
            proof.LayerProofs[0].VariableCount, 3, BaseMemoryPool.Shared);
        copies[1] = ProductSumcheckProof.FromParts(
            proof.LayerProofs[1].RoundPolynomials.Span, proof.LayerProofs[1].FinalValues.Span,
            proof.LayerProofs[1].VariableCount, 3, BaseMemoryPool.Shared);
        using var tamperedProof = new GkrProof(copies);

        using FiatShamirTranscript verifierTranscript = NewTranscript();
        bool verified = GkrVerifier.Verify(
            circuit, Inputs, outputs, tamperedProof, Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            verifierTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "A tampered layer proof must be rejected.");
    }


    [TestMethod]
    public void WrongClaimedOutputsAreRejected()
    {
        GkrCircuit circuit = BuildCircuit();
        using GkrWireTables tables = circuit.Evaluate(Inputs, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);

        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrProof proof = GkrProver.Prove(
            circuit, Inputs, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            proverTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        byte[] wrongOutputs = tables.Table(0).ToArray();
        wrongOutputs[ScalarSize - 1] ^= 0x01;

        using FiatShamirTranscript verifierTranscript = NewTranscript();
        bool verified = GkrVerifier.Verify(
            circuit, Inputs, wrongOutputs, proof, Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            verifierTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "Outputs the circuit did not produce must be rejected.");
    }


    [TestMethod]
    public void WrongClaimedInputsAreRejected()
    {
        GkrCircuit circuit = BuildCircuit();
        using GkrWireTables tables = circuit.Evaluate(Inputs, Add, Multiply, CurveParameterSet.None, BaseMemoryPool.Shared);
        byte[] outputs = tables.Table(0).ToArray();

        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrProof proof = GkrProver.Prove(
            circuit, Inputs, Add, Subtract, Multiply, Reduce, CurveParameterSet.None,
            proverTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        byte[] wrongInputs = (byte[])Inputs.Clone();
        wrongInputs[ScalarSize - 1] ^= 0x01;

        using FiatShamirTranscript verifierTranscript = NewTranscript();
        bool verified = GkrVerifier.Verify(
            circuit, wrongInputs, outputs, proof, Add, Subtract, Multiply, Invert, Reduce, CurveParameterSet.None,
            verifierTranscript, Squeeze, Hash, BaseMemoryPool.Shared);

        Assert.IsFalse(verified, "Inputs the proof was not produced for must be rejected.");
    }


    //Two layers over four inputs. Layer above the inputs: y0 = x0·x1, y1 = x1·x2 + 5·x0·x3,
    //y2 = 2·x2·x2, y3 = x3·x3 (x3 is the constant-one wire, so the 5·x0·x3 term is linear).
    //Output layer: z0 = y0·y1 + 3·y2·y3, z1 = 7·y1·y2.
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
        FiatShamirTranscript.Initialise(Domain, "veridical.gkr.layered.seed"u8, WellKnownHashAlgorithms.Blake3, Hash, BaseMemoryPool.Shared);


    private static byte[] Bytes(int value)
    {
        byte[] bytes = new byte[ScalarSize];
        bytes[ScalarSize - 1] = (byte)value;
        bytes[ScalarSize - 2] = (byte)(value >> 8);

        return bytes;
    }


    private static BigInteger ToInteger(ReadOnlySpan<byte> bytes) => new(bytes, isUnsigned: true, isBigEndian: true);


    private static BigInteger Mod(BigInteger value) => ((value % P) + P) % P;
}

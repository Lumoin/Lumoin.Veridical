using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using System;
using System.Collections.Generic;
using static Lumoin.Veridical.Tests.Algebraic.LongfellowKernelZkTestHarness;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The evaluation-mode and host-side semantic gates for the ported SHA-3 stack: the host SHAKE256
/// reproduces every reference vector (the transcription self-check), the witness-free Keccak
/// permutation agrees with the host permutation lane for lane, the SHAKE256 assertion accepts
/// every reference vector under the evaluation backend, and a corrupted witness lane is rejected.
/// </summary>
[TestClass]
internal sealed class LongfellowSha3CircuitTests
{
    /// <summary>The lane grid's side length.</summary>
    private const int GridSize = 5;

    /// <summary>One lane's bit width.</summary>
    private const int LaneBits = 64;

    /// <summary>The sextic extension's subfield width, selecting the three-way assertion split.</summary>
    private const int SexticSubfieldBits = 32;

    /// <summary>The deterministic lane fill of the reference's permutation test: <c>3x + 1000y</c>.</summary>
    private const int LaneFillRowFactor = 3;

    /// <summary>The deterministic lane fill's column factor.</summary>
    private const int LaneFillColumnFactor = 1000;

    /// <summary>The first sliced round (the earliest re-anchoring assertion the corruption gate can fire).</summary>
    private const int FirstSlicedRound = 5;


    /// <summary>Pins the host SHAKE256 against every reference vector — the transcription self-check for the vector table and the host sponge.</summary>
    [TestMethod]
    public void TheHostShakeMatchesEveryReferenceVector()
    {
        for(int i = 0; i < LongfellowSha3TestVectors.Shake256Vectors.Count; i++)
        {
            LongfellowSha3TestVectors.ShakeVector vector = LongfellowSha3TestVectors.Shake256Vectors[i];
            byte[] seed = Convert.FromHexString(vector.Input);
            byte[] expected = Convert.FromHexString(vector.Output);

            var output = new byte[expected.Length];
            LongfellowSha3Witness.Shake256Hash(seed, output);

            Assert.AreSequenceEqual(expected, output, $"The host SHAKE256 must reproduce reference vector {i}.");
        }
    }


    /// <summary>Pins the witness-free permutation against the host permutation lane for lane under the evaluation backend, over the reference's deterministic state fill.</summary>
    [TestMethod]
    public void TheWitnessFreePermutationMatchesTheHostInEvaluation()
    {
        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);
        var circuit = new LongfellowSha3Circuit(logic, SexticSubfieldBits);

        var state = new LongfellowBitWire[GridSize][][];
        var hostState = new ulong[GridSize][];
        for(int x = 0; x < GridSize; x++)
        {
            state[x] = new LongfellowBitWire[GridSize][];
            hostState[x] = new ulong[GridSize];
            for(int y = 0; y < GridSize; y++)
            {
                ulong lane = (ulong)((LaneFillRowFactor * x) + (LaneFillColumnFactor * y));
                state[x][y] = logic.BitVector(LaneBits, lane);
                hostState[x][y] = lane;
            }
        }

        circuit.KeccakF1600(state);

        var hostWitness = new LongfellowSha3BlockWitness();
        LongfellowSha3Witness.ComputeWitnessBlock(hostState, hostWitness);

        for(int x = 0; x < GridSize; x++)
        {
            for(int y = 0; y < GridSize; y++)
            {
                logic.AssertEqual(state[x][y], logic.BitVector(LaneBits, hostState[x][y]));
            }
        }

        Assert.IsFalse(backend.AssertionFailed, "The permutation must agree with the host lane for lane.");
    }


    /// <summary>Pins that the SHAKE256 assertion accepts every reference vector under the evaluation backend with the generator's witnesses.</summary>
    [TestMethod]
    public void TheShakeAssertionAcceptsEveryReferenceVectorInEvaluation()
    {
        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        for(int i = 0; i < LongfellowSha3TestVectors.Shake256Vectors.Count; i++)
        {
            LongfellowSha3TestVectors.ShakeVector vector = LongfellowSha3TestVectors.Shake256Vectors[i];
            byte[] seed = Convert.FromHexString(vector.Input);
            byte[] expected = Convert.FromHexString(vector.Output);

            var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
            var logic = new LongfellowLogic(backend, field);
            var circuit = new LongfellowSha3Circuit(logic, SexticSubfieldBits);

            LongfellowBitWire[][] output = circuit.AssertShake256(
                InternBytes(logic, seed),
                expected.Length,
                InternWitnesses(logic, LongfellowSha3Witness.ComputeWitnessShake256(seed, expected.Length)));

            Assert.HasCount(expected.Length, output, $"Vector {i}'s output length must match.");
            for(int b = 0; b < expected.Length; b++)
            {
                logic.AssertEqual(output[b], logic.BitVector(LongfellowLogic.BitWidth8, expected[b]));
            }

            Assert.IsFalse(backend.AssertionFailed, $"Vector {i} must satisfy the SHAKE assertion with its computed witnesses.");
        }
    }


    /// <summary>Pins that a corrupted witness lane fails the re-anchoring assertion under the evaluation backend.</summary>
    [TestMethod]
    public void ACorruptedWitnessLaneIsRejectedInEvaluation()
    {
        LongfellowLogicFieldOperations field = NewFp24SexticBundle();
        LongfellowSha3TestVectors.ShakeVector vector = LongfellowSha3TestVectors.Shake256Vectors[1];
        byte[] seed = Convert.FromHexString(vector.Input);
        byte[] expected = Convert.FromHexString(vector.Output);

        var backend = new LongfellowEvaluationLogicBackend(field, panicOnAssertionFailure: false);
        var logic = new LongfellowLogic(backend, field);
        var circuit = new LongfellowSha3Circuit(logic, SexticSubfieldBits);

        IReadOnlyList<LongfellowSha3BlockWitness> witnesses = LongfellowSha3Witness.ComputeWitnessShake256(seed, expected.Length);
        //Flip one bit of the first sliced round's origin lane; the round-five assertion must fire.
        witnesses[0].AIntermediate[FirstSlicedRound][0][0] ^= 1UL;

        _ = circuit.AssertShake256(InternBytes(logic, seed), expected.Length, InternWitnesses(logic, witnesses));

        Assert.IsTrue(backend.AssertionFailed, "A corrupted witness lane must fail the re-anchoring assertion.");
    }


    /// <summary>Interns bytes as constant eight-bit vectors.</summary>
    /// <param name="logic">The gadget layer producing constant bit vectors.</param>
    /// <param name="bytes">The bytes to intern.</param>
    /// <returns>The byte vectors.</returns>
    private static LongfellowBitWire[][] InternBytes(LongfellowLogic logic, ReadOnlySpan<byte> bytes)
    {
        var vectors = new LongfellowBitWire[bytes.Length][];
        for(int i = 0; i < bytes.Length; i++)
        {
            vectors[i] = logic.BitVector(LongfellowLogic.BitWidth8, bytes[i]);
        }

        return vectors;
    }


    /// <summary>Interns the generator's witnesses as constant lane vectors at the sliced rounds.</summary>
    /// <param name="logic">The gadget layer producing constant bit vectors.</param>
    /// <param name="witnesses">The host witnesses.</param>
    /// <returns>The wire bundles.</returns>
    private static LongfellowSha3BlockWitnessWires[] InternWitnesses(LongfellowLogic logic, IReadOnlyList<LongfellowSha3BlockWitness> witnesses)
    {
        var wires = new LongfellowSha3BlockWitnessWires[witnesses.Count];
        for(int w = 0; w < witnesses.Count; w++)
        {
            wires[w] = new LongfellowSha3BlockWitnessWires();
            for(int round = 0; round < LongfellowSha3Constants.RoundCount; round++)
            {
                if(!LongfellowSha3Constants.SliceAt(round))
                {
                    continue;
                }

                for(int x = 0; x < GridSize; x++)
                {
                    for(int y = 0; y < GridSize; y++)
                    {
                        wires[w].AIntermediate[round][x][y] = logic.BitVector(LaneBits, witnesses[w].AIntermediate[round][x][y]);
                    }
                }
            }
        }

        return wires;
    }
}

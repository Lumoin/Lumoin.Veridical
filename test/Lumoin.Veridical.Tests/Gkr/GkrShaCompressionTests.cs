using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The full SHA-256 compression function through the committed GKR engine: all 64 rounds of a
/// real block as data-parallel copies of one round-check circuit — the translation the fragment
/// tests built toward. Copy r witnesses its round boundary (the working variables a..h entering
/// round r), the schedule word, the round outputs new_a/new_e and the radix-4 carry digits of the
/// two modular additions; the circuit recomputes Σ1, Σ0, Ch and Maj from the witnessed bits and
/// emits one radix-4 column check per bit pair per addition. Three structural points beyond the
/// fragments:
/// <list type="bullet">
/// <item>The round constants differ per round while the circuit is shared across copies, so they
/// live in the verifier's expected output table: column j of copy r must equal
/// <c>−(K_r,2j + 2·K_r,2j+1)</c> — public outputs may vary per copy, term coefficients may not.</item>
/// <item>Cross-round consistency (round r+1 starts where round r ended) and the public ends of
/// the chain (the initial vector, the schedule words, the claimed final state) are sparse linear
/// constraints on the Ligero commitment, proven inside the same witness-opening proof: the GKR
/// walk proves each round internally, the commitment glues the rounds.</item>
/// <item>Bitness of every witnessed bit is a quadratic commitment constraint
/// <c>W[b]·W[b] = W[b]</c>. That frees the circuit of bitness outputs and of the constant-one
/// wire entirely: a committed bit may be passed or used linearly as its own square, and internal
/// wires built from constrained bits are bit-valued because the walk proves the evaluation.</item>
/// </list>
/// The schedule words are pinned to public values here; the scheduled compression test replaces
/// those pins with in-circuit schedule checks. Gated bit-exact against a uint SHA-256 oracle on
/// the "abc" block; the circuit, the oracle and the witness packing live in
/// <see cref="GkrShaRoundSupport"/>.
/// </summary>
[TestClass]
internal sealed class GkrShaCompressionTests
{
    private const int ScalarSize = GkrShaRoundSupport.ScalarSize;
    private const int CopyCount = GkrShaRoundSupport.RoundCount;
    private const int InputCount = GkrShaRoundSupport.InputCount;
    private const int OutputCount = GkrShaRoundSupport.OutputCount;
    private const int WitnessBytes = GkrShaRoundSupport.RoundWitnessBytes;
    private const int OutputBytes = GkrShaRoundSupport.RoundOutputBytes;

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.sha.compression.test");

    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.sha.compression.rng.v1");


    [TestMethod]
    public void RoundCircuitOutputsAreTheNegatedRoundConstantsAcrossAllRounds()
    {
        GkrCircuit circuit = GkrShaRoundSupport.BuildRoundCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(WitnessBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..WitnessBytes];
        GkrShaRoundSupport.PackRoundWitness(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..OutputBytes];
        GkrTestSupport.Outputs(circuit, inputs, CopyCount, outputs);
        using IMemoryOwner<byte> expectedOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> expected = expectedOwner.Memory.Span[..OutputBytes];
        GkrShaRoundSupport.ExpectedRoundOutputs(expected);

        Assert.IsTrue(outputs.SequenceEqual(expected), "Every column check of every round must close to its negated round-constant pair against the real trace.");
    }


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void CommittedCompressionProofVerifiesAndBindsItsPublicStatement()
    {
        //On the order of a couple of minutes, hardware-dependent: the committed prove and
        //verify through the real pipeline. The default-suite gates above check the same round
        //circuit bit-exactly against the uint oracle, so this gate adds the end-to-end proving,
        //not the logic coverage.
        GkrCircuit circuit = GkrShaRoundSupport.BuildRoundCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(WitnessBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..WitnessBytes];
        GkrShaRoundSupport.PackRoundWitness(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..OutputBytes];
        GkrShaRoundSupport.ExpectedRoundOutputs(outputs);
        (LigeroLinearConstraint[] statement, byte[] targets) = BuildStatement();
        LigeroQuadraticConstraint[] bitness = BuildBitnessConstraints();

        //One prove serves the honest check and both statement bindings — the prove is the
        //expensive half at this width.
        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrCommittedProof proof = GkrTestSupport.Prove(circuit, inputs, CopyCount, RandomnessSeed, proverTranscript, statement, targets, bitness);

        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Assert.IsTrue(
                GkrTestSupport.Verify(circuit, outputs, CopyCount, proof, verifierTranscript, statement, targets, bitness),
                "All 64 committed rounds must verify with the chain glue, the IV, schedule and final-state pins and the bitness constraints.");
        }

        //A claimed final state with one flipped bit: the digest pin targets sit at the end of
        //the statement.
        byte[] flippedDigest = (byte[])targets.Clone();
        int lastPin = targets.Length - ScalarSize;
        flippedDigest[(lastPin + ScalarSize) - 1] ^= 0x01;
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Assert.IsFalse(
                GkrTestSupport.Verify(circuit, outputs, CopyCount, proof, verifierTranscript, statement, flippedDigest, bitness),
                "A claimed final state that differs in one bit must be rejected by the pinned commitment.");
        }

        //A wrong round constant: flip one byte of one copy's expected column value in a copy of
        //the honest outputs.
        using IMemoryOwner<byte> wrongConstantsOwner = BaseMemoryPool.Shared.Rent(OutputBytes);
        Span<byte> wrongConstants = wrongConstantsOwner.Memory.Span[..OutputBytes];
        outputs.CopyTo(wrongConstants);
        wrongConstants[((((10 * OutputCount) + 3) * ScalarSize) + ScalarSize) - 1] ^= 0x01;
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Assert.IsFalse(
                GkrTestSupport.Verify(circuit, wrongConstants, CopyCount, proof, verifierTranscript, statement, targets, bitness),
                "A tampered round constant in the expected outputs must be rejected by the walk.");
        }
    }


    [TestMethod]
    public void ABrokenRoundChainIsUnprovable()
    {
        GkrCircuit circuit = GkrShaRoundSupport.BuildRoundCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(WitnessBytes);
        Memory<byte> inputs = inputsOwner.Memory[..WitnessBytes];
        GkrShaRoundSupport.PackRoundWitness(inputs.Span);
        (LigeroLinearConstraint[] statement, byte[] targets) = BuildStatement();
        LigeroQuadraticConstraint[] bitness = BuildBitnessConstraints();

        //Round 30 claims to start from a state that is not where round 29 ended.
        int wire = ((((30 * InputCount) + GkrShaRoundSupport.AWire + 5) * ScalarSize) + ScalarSize) - 1;
        inputs.Span[wire] ^= 0x01;

        using FiatShamirTranscript proverTranscript = NewTranscript();
        Assert.ThrowsExactly<InvalidOperationException>(
            () => GkrTestSupport.Prove(circuit, inputs.Span, CopyCount, RandomnessSeed, proverTranscript, statement, targets, bitness).Dispose(),
            "A witness whose round boundaries do not chain must violate the glue constraints.");
    }


    [TestMethod]
    public void ANonBitCarryDigitIsUnprovable()
    {
        GkrCircuit circuit = GkrShaRoundSupport.BuildRoundCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(WitnessBytes);
        Memory<byte> inputs = inputsOwner.Memory[..WitnessBytes];
        GkrShaRoundSupport.PackRoundWitness(inputs.Span);
        (LigeroLinearConstraint[] statement, byte[] targets) = BuildStatement();
        LigeroQuadraticConstraint[] bitness = BuildBitnessConstraints();

        //A carry wire holding two is exactly the digit-two encoding the bitness constraints
        //exist to kill; here it violates W[b]·W[b] = W[b] inside the commitment itself.
        int wire = ((((20 * InputCount) + GkrShaRoundSupport.CarryAWire + 7) * ScalarSize) + ScalarSize) - 1;
        inputs.Span[wire] = 2;

        using FiatShamirTranscript proverTranscript = NewTranscript();
        Assert.ThrowsExactly<InvalidOperationException>(
            () => GkrTestSupport.Prove(circuit, inputs.Span, CopyCount, RandomnessSeed, proverTranscript, statement, targets, bitness).Dispose(),
            "A non-bit carry digit must violate the quadratic bitness constraints of the commitment.");
    }


    //The public statement over the commitment: round r+1's boundary equals round r's outcome
    //(a ← new_a, e ← new_e, the rest shift), round 0 starts at the initial vector, every
    //schedule word is pinned, and round 63's outputs are pinned to the claimed final state.
    private static (LigeroLinearConstraint[] Constraints, byte[] Targets) BuildStatement()
    {
        uint[] schedule = GkrShaRoundSupport.Schedule();
        uint[][] trace = GkrShaRoundSupport.Trace(schedule);
        var statement = new GkrStatementBuilder();

        int[][] shifts =
        [
            [GkrShaRoundSupport.AWire, GkrShaRoundSupport.NewAWire],
            [GkrShaRoundSupport.BWire, GkrShaRoundSupport.AWire],
            [GkrShaRoundSupport.CWire, GkrShaRoundSupport.BWire],
            [GkrShaRoundSupport.DWire, GkrShaRoundSupport.CWire],
            [GkrShaRoundSupport.EWire, GkrShaRoundSupport.NewEWire],
            [GkrShaRoundSupport.FWire, GkrShaRoundSupport.EWire],
            [GkrShaRoundSupport.GWire, GkrShaRoundSupport.FWire],
            [GkrShaRoundSupport.HWire, GkrShaRoundSupport.GWire],
        ];
        for(int r = 0; r + 1 < CopyCount; r++)
        {
            foreach(int[] shift in shifts)
            {
                for(int i = 0; i < GkrShaRoundSupport.WordBits; i++)
                {
                    statement.Equal(Index(r + 1, shift[0] + i), Index(r, shift[1] + i));
                }
            }
        }

        for(int word = 0; word < 8; word++)
        {
            statement.PinWord(Index(0, word * GkrShaRoundSupport.WordBits), GkrShaRoundSupport.InitialState[word]);
        }

        for(int r = 0; r < CopyCount; r++)
        {
            statement.PinWord(Index(r, GkrShaRoundSupport.WWire), schedule[r]);
        }

        statement.PinWord(Index(CopyCount - 1, GkrShaRoundSupport.NewAWire), trace[CopyCount][0]);
        statement.PinWord(Index(CopyCount - 1, GkrShaRoundSupport.NewEWire), trace[CopyCount][4]);

        return statement.Build();
    }


    //Every freshly witnessed digit — the round outputs and all carry digits — is a bit by the
    //quadratic constraint W[b]·W[b] = W[b]; the boundary words inherit bitness through the glue.
    private static LigeroQuadraticConstraint[] BuildBitnessConstraints()
    {
        var quadratics = new List<LigeroQuadraticConstraint>();
        (int Base, int Count)[] groups =
        [
            (GkrShaRoundSupport.NewAWire, GkrShaRoundSupport.WordBits),
            (GkrShaRoundSupport.NewEWire, GkrShaRoundSupport.WordBits),
            (GkrShaRoundSupport.CarryAWire, GkrShaRoundSupport.CarryWireCount),
            (GkrShaRoundSupport.CarryEWire, GkrShaRoundSupport.CarryWireCount),
        ];
        for(int r = 0; r < CopyCount; r++)
        {
            foreach((int wireBase, int count) in groups)
            {
                for(int k = 0; k < count; k++)
                {
                    int index = Index(r, wireBase + k);
                    quadratics.Add(new LigeroQuadraticConstraint(index, index, index));
                }
            }
        }

        return [.. quadratics];
    }


    private static int Index(int copy, int wire) => (copy * InputCount) + wire;


    private static FiatShamirTranscript NewTranscript() =>
        GkrTestSupport.NewTranscript(Domain, "veridical.gkr.sha.compression.seed"u8);
}

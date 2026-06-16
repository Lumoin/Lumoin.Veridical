using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The complete single-block SHA-256 statement through the committed GKR engine — three circuit
/// instances proven against one shared commitment, claiming the real digest. The round instance
/// is exactly the compression test's (64 copies × 512 wires) with its schedule-word and
/// final-state pins dropped; the schedule instance (64 copies × 256 wires) checks the recurrence
/// <c>W_r = σ1(W_{r−2}) + W_{r−7} + σ0(W_{r−15}) + W_{r−16}</c> as radix-4 columns over its own
/// witnessed copy of W_r, its four predecessor words and carry digits; the digest instance
/// (8 copies × 256 wires, one layer) computes <c>H_w = IV_w + state64_w mod 2³²</c> per state
/// word — the block-chaining addition shape. The statement glues the instances together: the two
/// W copies per round, each schedule predecessor to the copy it names, and the digest operands
/// to round copy 63's final state — the uniform-copy rule binds only the circuit, so
/// per-copy-asymmetric glue is free. For rounds below 16 the recurrence does not apply: those
/// copies' predecessors and carries are pinned to zero, which degenerates every schedule column
/// to <c>−W_r</c>, and the verifier's expected outputs there are the negated message-word digits
/// — the message enters through the expected output table, not through pins. The public claim is
/// the genuine SHA-256 digest, cross-checked against <c>SHA256.HashData</c>. Splitting the
/// schedule and digest into their own small instances is what keeps every layer at or under 512
/// wires; folding them into the round circuit would push all layers to 1024 and quadruple the
/// width² sumcheck cost.
/// </summary>
[TestClass]
internal sealed class GkrShaScheduledCompressionTests
{
    private const int ScalarSize = GkrShaRoundSupport.ScalarSize;
    private const int CopyCount = GkrShaRoundSupport.RoundCount;
    private const int WordBits = GkrShaRoundSupport.WordBits;
    private const int PairCount = GkrShaRoundSupport.PairCount;
    private const int CarryWireCount = GkrShaRoundSupport.CarryWireCount;

    //Schedule-instance wire layout, shared with the preimage tests.
    private const int ScheduleInputCount = GkrShaRoundSupport.ScheduleInputCount;
    private const int SwWire = GkrShaRoundSupport.ScheduleWordWire;
    private const int P2Wire = GkrShaRoundSupport.Predecessor2Wire;
    private const int P7Wire = GkrShaRoundSupport.Predecessor7Wire;
    private const int P15Wire = GkrShaRoundSupport.Predecessor15Wire;
    private const int P16Wire = GkrShaRoundSupport.Predecessor16Wire;
    private const int ScWire = GkrShaRoundSupport.ScheduleCarryWire;
    private const int ScheduleOutputCount = GkrShaRoundSupport.ScheduleOutputCount;

    //Segment offsets in the shared commitment: the round instance, the schedule, the digest.
    private const int RoundSegment = 0;
    private const int ScheduleSegment = CopyCount * GkrShaRoundSupport.InputCount;
    private const int DigestSegment = ScheduleSegment + (CopyCount * ScheduleInputCount);

    //The pooled-buffer sizes: per instance and for the concatenated witness and output tables.
    private const int ScheduleWitnessBytes = GkrShaRoundSupport.ScheduleWitnessBytes;
    private const int ScheduleOutputBytes = GkrShaRoundSupport.ScheduleOutputBytes;
    private const int CombinedWitnessBytes = GkrShaRoundSupport.RoundWitnessBytes + ScheduleWitnessBytes + GkrShaRoundSupport.DigestWitnessBytes;
    private const int CombinedOutputBytes = GkrShaRoundSupport.RoundOutputBytes + ScheduleOutputBytes + GkrShaRoundSupport.DigestOutputBytes;

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.sha.scheduled.test");

    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.sha.scheduled.rng.v1");


    [TestMethod]
    public void ScheduleCircuitClosesEveryRecurrenceAcrossTheBlock()
    {
        GkrCircuit circuit = GkrShaRoundSupport.BuildScheduleCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(ScheduleWitnessBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..ScheduleWitnessBytes];
        PackScheduleWitness(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(ScheduleOutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..ScheduleOutputBytes];
        GkrTestSupport.Outputs(circuit, inputs, CopyCount, outputs);
        using IMemoryOwner<byte> expectedOwner = BaseMemoryPool.Shared.Rent(ScheduleOutputBytes);
        Span<byte> expected = expectedOwner.Memory.Span[..ScheduleOutputBytes];
        ExpectedScheduleOutputs(expected);

        Assert.IsTrue(outputs.SequenceEqual(expected), "Every schedule column must close to zero for the recurrence rounds and to the negated message digits below round 16.");
    }


    [TestMethod]
    public void DigestAdditionClosesToTheRealSha256Digest()
    {
        //The claimed digest words are independently cross-checked against .NET's SHA-256
        //before the circuit gate: the public statement is the genuine hash, not our own math.
        uint[] digest = GkrShaRoundSupport.DigestWords();
        byte[] reference = SHA256.HashData("abc"u8);
        for(int w = 0; w < 8; w++)
        {
            uint expected = BinaryPrimitives.ReadUInt32BigEndian(reference.AsSpan(4 * w));
            Assert.AreEqual(expected, digest[w], $"Digest word {w} must match SHA256.HashData.");
        }

        GkrCircuit circuit = GkrShaRoundSupport.BuildDigestCircuit();
        using IMemoryOwner<byte> inputsOwner = BaseMemoryPool.Shared.Rent(GkrShaRoundSupport.DigestWitnessBytes);
        Span<byte> inputs = inputsOwner.Memory.Span[..GkrShaRoundSupport.DigestWitnessBytes];
        GkrShaRoundSupport.PackDigestWitness(inputs);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(GkrShaRoundSupport.DigestOutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..GkrShaRoundSupport.DigestOutputBytes];
        GkrTestSupport.Outputs(circuit, inputs, GkrShaRoundSupport.DigestCopyCount, outputs);

        Assert.IsFalse(outputs.ContainsAnyExcept((byte)0), "Every digest-addition column must close to zero for the real digest words.");
    }


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void CommittedSha256ProofClaimsTheRealDigest()
    {
        //On the order of a few minutes, hardware-dependent: the three-instance committed prove
        //and verify. The default-suite gates above check the schedule and digest circuits
        //bit-exactly against the uint oracle, so this gate adds the end-to-end proving, not the
        //logic coverage.
        GkrCommittedInstance[] instances = Instances();
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(CombinedWitnessBytes);
        Span<byte> witness = witnessOwner.Memory.Span[..CombinedWitnessBytes];
        PackCombinedWitness(witness);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(CombinedOutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..CombinedOutputBytes];
        CombinedOutputs(outputs);
        (LigeroLinearConstraint[] statement, byte[] targets) = BuildStatement();
        LigeroQuadraticConstraint[] bitness = BuildBitnessConstraints();

        //One prove serves the honest check and both bindings — the prove is the expensive half.
        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrCommittedProof proof = GkrTestSupport.Prove(instances, witness, RandomnessSeed, proverTranscript, statement, targets, bitness);

        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Assert.IsTrue(
                GkrTestSupport.Verify(instances, outputs, proof, verifierTranscript, statement, targets, bitness),
                "The compression, the in-circuit schedule and the digest addition must verify together against the shared commitment.");
        }

        //A different message: flip an expected schedule output of round 3 in a copy of the
        //honest outputs — the message word binding lives in the expected output table, not in a pin.
        using IMemoryOwner<byte> differentMessageOwner = BaseMemoryPool.Shared.Rent(CombinedOutputBytes);
        Span<byte> differentMessage = differentMessageOwner.Memory.Span[..CombinedOutputBytes];
        outputs.CopyTo(differentMessage);
        differentMessage[(GkrShaRoundSupport.RoundOutputBytes + ((((3 * ScheduleOutputCount) + 0) * ScalarSize) + ScalarSize)) - 1] ^= 0x01;
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Assert.IsFalse(
                GkrTestSupport.Verify(instances, differentMessage, proof, verifierTranscript, statement, targets, bitness),
                "A claimed message that differs in one word must be rejected by the schedule instance's expected outputs.");
        }

        //A wrong claimed digest: the digest-word pins are the last statement targets.
        byte[] wrongDigest = (byte[])targets.Clone();
        int lastPin = targets.Length - ScalarSize;
        wrongDigest[(lastPin + ScalarSize) - 1] ^= 0x01;
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Assert.IsFalse(
                GkrTestSupport.Verify(instances, outputs, proof, verifierTranscript, statement, wrongDigest, bitness),
                "A claimed digest that differs in one bit must be rejected by the pinned commitment.");
        }
    }


    [TestMethod]
    public void ABrokenScheduleGlueIsUnprovable()
    {
        GkrCommittedInstance[] instances = Instances();
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(CombinedWitnessBytes);
        Memory<byte> witness = witnessOwner.Memory[..CombinedWitnessBytes];
        PackCombinedWitness(witness.Span);
        (LigeroLinearConstraint[] statement, byte[] targets) = BuildStatement();
        LigeroQuadraticConstraint[] bitness = BuildBitnessConstraints();

        //Round 20's schedule copy claims a predecessor that is not round 18's schedule word.
        int wire = (((ScheduleIndex(20, P2Wire) * ScalarSize) + ScalarSize)) - 1;
        witness.Span[wire] ^= 0x01;

        using FiatShamirTranscript proverTranscript = NewTranscript();
        Assert.ThrowsExactly<InvalidOperationException>(
            () => GkrTestSupport.Prove(instances, witness.Span, RandomnessSeed, proverTranscript, statement, targets, bitness).Dispose(),
            "A predecessor word that does not match the copy it names must violate the glue constraints.");
    }


    [TestMethod]
    public void ABrokenFinalStateGlueIsUnprovable()
    {
        GkrCommittedInstance[] instances = Instances();
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(CombinedWitnessBytes);
        Memory<byte> witness = witnessOwner.Memory[..CombinedWitnessBytes];
        PackCombinedWitness(witness.Span);
        (LigeroLinearConstraint[] statement, byte[] targets) = BuildStatement();
        LigeroQuadraticConstraint[] bitness = BuildBitnessConstraints();

        //The digest addition claims a final-state operand that is not round 63's outcome.
        int wire = (((DigestIndex(0, GkrShaRoundSupport.DigestRightWire) * ScalarSize) + ScalarSize)) - 1;
        witness.Span[wire] ^= 0x01;

        using FiatShamirTranscript proverTranscript = NewTranscript();
        Assert.ThrowsExactly<InvalidOperationException>(
            () => GkrTestSupport.Prove(instances, witness.Span, RandomnessSeed, proverTranscript, statement, targets, bitness).Dispose(),
            "A digest operand that does not match the final round state must violate the glue constraints.");
    }


    private static GkrCommittedInstance[] Instances() =>
    [
        new GkrCommittedInstance(GkrShaRoundSupport.BuildRoundCircuit(), CopyCount),
        new GkrCommittedInstance(GkrShaRoundSupport.BuildScheduleCircuit(), CopyCount),
        new GkrCommittedInstance(GkrShaRoundSupport.BuildDigestCircuit(), GkrShaRoundSupport.DigestCopyCount),
    ];


    //The honest schedule-instance witness: each copy's schedule word, its predecessors and the
    //recurrence carries; below round 16 the predecessors and carries are zero (and pinned so).
    private static void PackScheduleWitness(Span<byte> inputs)
    {
        uint[] schedule = GkrShaRoundSupport.Schedule();

        inputs.Clear();
        for(int r = 0; r < CopyCount; r++)
        {
            Span<byte> copy = inputs.Slice(r * ScheduleInputCount * ScalarSize, ScheduleInputCount * ScalarSize);
            GkrShaRoundSupport.WriteWord(copy, SwWire, schedule[r]);
            if(r >= 16)
            {
                GkrShaRoundSupport.WriteWord(copy, P2Wire, schedule[r - 2]);
                GkrShaRoundSupport.WriteWord(copy, P7Wire, schedule[r - 7]);
                GkrShaRoundSupport.WriteWord(copy, P15Wire, schedule[r - 15]);
                GkrShaRoundSupport.WriteWord(copy, P16Wire, schedule[r - 16]);
                GkrShaRoundSupport.WriteCarries(
                    copy, ScWire,
                    [GkrShaRoundSupport.SmallSigma1(schedule[r - 2]), schedule[r - 7], GkrShaRoundSupport.SmallSigma0(schedule[r - 15]), schedule[r - 16]],
                    0, schedule[r]);
            }
        }
    }


    //The expected schedule outputs: zero where the recurrence holds, the negated message-word
    //digits below round 16 (the degenerate column is 0 + 0 + carry 0 − W_r).
    private static void ExpectedScheduleOutputs(Span<byte> outputs)
    {
        uint[] schedule = GkrShaRoundSupport.Schedule();

        outputs.Clear();
        for(int r = 0; r < 16; r++)
        {
            for(int j = 0; j < PairCount; j++)
            {
                int pair = GkrShaRoundSupport.PairDigit(schedule[r], j);
                if(pair == 0)
                {
                    continue;
                }

                byte[] value = GkrTestSupport.Canonical(GkrTestSupport.P - pair);
                value.CopyTo(outputs.Slice(((r * ScheduleOutputCount) + j) * ScalarSize, ScalarSize));
            }
        }
    }


    private static void PackCombinedWitness(Span<byte> witness)
    {
        GkrShaRoundSupport.PackRoundWitness(witness[..GkrShaRoundSupport.RoundWitnessBytes]);
        PackScheduleWitness(witness.Slice(GkrShaRoundSupport.RoundWitnessBytes, ScheduleWitnessBytes));
        GkrShaRoundSupport.PackDigestWitness(witness.Slice(GkrShaRoundSupport.RoundWitnessBytes + ScheduleWitnessBytes, GkrShaRoundSupport.DigestWitnessBytes));
    }


    //The digest instance's expected outputs are all zero: its public values — the initial
    //vector and the claimed digest — enter as pins on its operand and sum wires.
    private static void CombinedOutputs(Span<byte> outputs)
    {
        GkrShaRoundSupport.ExpectedRoundOutputs(outputs[..GkrShaRoundSupport.RoundOutputBytes]);
        ExpectedScheduleOutputs(outputs.Slice(GkrShaRoundSupport.RoundOutputBytes, ScheduleOutputBytes));
        outputs[(GkrShaRoundSupport.RoundOutputBytes + ScheduleOutputBytes)..].Clear();
    }


    //The public statement over the shared commitment: the round-chain glue and initial-vector
    //pins, the W glue between the round and schedule instances, the predecessor glue to the
    //copies they name, the zero pins that degenerate the first sixteen schedule copies, and the
    //digest instance's glue and pins — its state operands are round copy 63's outcome, its
    //other operand is the initial vector and its sum is the claimed digest.
    private static (LigeroLinearConstraint[] Constraints, byte[] Targets) BuildStatement()
    {
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
                for(int i = 0; i < WordBits; i++)
                {
                    statement.Equal(RoundIndex(r + 1, shift[0] + i), RoundIndex(r, shift[1] + i));
                }
            }
        }

        for(int word = 0; word < 8; word++)
        {
            statement.PinWord(RoundIndex(0, word * WordBits), GkrShaRoundSupport.InitialState[word]);
        }

        //The two instances witness the same schedule word per round.
        for(int r = 0; r < CopyCount; r++)
        {
            for(int i = 0; i < WordBits; i++)
            {
                statement.Equal(ScheduleIndex(r, SwWire + i), RoundIndex(r, GkrShaRoundSupport.WWire + i));
            }
        }

        //Each predecessor is the schedule word of the copy it names; below round 16 the
        //predecessors and carries are zero and the expected outputs carry the message.
        (int Wire, int Back)[] predecessors = [(P2Wire, 2), (P7Wire, 7), (P15Wire, 15), (P16Wire, 16)];
        for(int r = 0; r < CopyCount; r++)
        {
            if(r >= 16)
            {
                foreach((int wire, int back) in predecessors)
                {
                    for(int i = 0; i < WordBits; i++)
                    {
                        statement.Equal(ScheduleIndex(r, wire + i), ScheduleIndex(r - back, SwWire + i));
                    }
                }

                continue;
            }

            foreach((int wire, _) in predecessors)
            {
                for(int i = 0; i < WordBits; i++)
                {
                    statement.Pin(ScheduleIndex(r, wire + i), 0);
                }
            }

            for(int k = 0; k < CarryWireCount; k++)
            {
                statement.Pin(ScheduleIndex(r, ScWire + k), 0);
            }
        }

        //The digest addition: per state word the right operand is round copy 63's outcome, the
        //left operand is the initial vector and the sum is the claimed digest.
        uint[] digest = GkrShaRoundSupport.DigestWords();
        int[] finalStateSources =
        [
            GkrShaRoundSupport.NewAWire, GkrShaRoundSupport.AWire, GkrShaRoundSupport.BWire, GkrShaRoundSupport.CWire,
            GkrShaRoundSupport.NewEWire, GkrShaRoundSupport.EWire, GkrShaRoundSupport.FWire, GkrShaRoundSupport.GWire,
        ];
        for(int w = 0; w < GkrShaRoundSupport.DigestCopyCount; w++)
        {
            for(int i = 0; i < WordBits; i++)
            {
                statement.Equal(DigestIndex(w, GkrShaRoundSupport.DigestRightWire + i), RoundIndex(CopyCount - 1, finalStateSources[w] + i));
            }

            statement.PinWord(DigestIndex(w, GkrShaRoundSupport.DigestLeftWire), GkrShaRoundSupport.InitialState[w]);
            statement.PinWord(DigestIndex(w, GkrShaRoundSupport.DigestSumWire), digest[w]);
        }

        return statement.Build();
    }


    //Bitness: the round instance's freshly witnessed digits as in the compression test, plus —
    //now that the schedule words are private — the round W wires, the schedule carries and the
    //digest carries. The schedule instance's words inherit bitness through the glue and the
    //zero pins; the digest operands and sum are glued or pinned.
    private static LigeroQuadraticConstraint[] BuildBitnessConstraints()
    {
        var quadratics = new List<LigeroQuadraticConstraint>();
        (int Base, int Count)[] roundGroups =
        [
            (GkrShaRoundSupport.NewAWire, WordBits),
            (GkrShaRoundSupport.NewEWire, WordBits),
            (GkrShaRoundSupport.CarryAWire, CarryWireCount),
            (GkrShaRoundSupport.CarryEWire, CarryWireCount),
            (GkrShaRoundSupport.WWire, WordBits),
        ];
        for(int r = 0; r < CopyCount; r++)
        {
            foreach((int wireBase, int count) in roundGroups)
            {
                for(int k = 0; k < count; k++)
                {
                    int index = RoundIndex(r, wireBase + k);
                    quadratics.Add(new LigeroQuadraticConstraint(index, index, index));
                }
            }

            for(int k = 0; k < CarryWireCount; k++)
            {
                int index = ScheduleIndex(r, ScWire + k);
                quadratics.Add(new LigeroQuadraticConstraint(index, index, index));
            }
        }

        for(int w = 0; w < GkrShaRoundSupport.DigestCopyCount; w++)
        {
            for(int k = 0; k < CarryWireCount; k++)
            {
                int index = DigestIndex(w, GkrShaRoundSupport.DigestCarryWire + k);
                quadratics.Add(new LigeroQuadraticConstraint(index, index, index));
            }
        }

        return [.. quadratics];
    }


    private static int RoundIndex(int copy, int wire) => RoundSegment + (copy * GkrShaRoundSupport.InputCount) + wire;

    private static int ScheduleIndex(int copy, int wire) => ScheduleSegment + (copy * ScheduleInputCount) + wire;

    private static int DigestIndex(int copy, int wire) => DigestSegment + (copy * GkrShaRoundSupport.DigestInputCount) + wire;


    private static FiatShamirTranscript NewTranscript() =>
        GkrTestSupport.NewTranscript(Domain, "veridical.gkr.sha.scheduled.seed"u8);
}

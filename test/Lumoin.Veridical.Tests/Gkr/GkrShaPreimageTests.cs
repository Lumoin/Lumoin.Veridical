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
/// The SHA-256 preimage statement through the committed GKR engine: knowledge of a PRIVATE
/// two-block message hashing to a public digest. Three instances on one shared commitment —
/// 128 round copies, 128 schedule copies and 16 addition copies — with the blocks chained
/// through the addition instance: round block b+1 starts from addition block b's sum words,
/// only block 0's left operands are pinned to the initial vector and only the last block's sums
/// are pinned to the digest. The message stays private by replacing the scheduled-compression
/// test's degenerate first-sixteen copies with VIRTUAL PREDECESSORS: each block witnesses
/// sixteen words W₋₁₆..W₋₁ (solved so the recurrence holds for every round), each homed at the
/// <c>P16</c> slot of the copy that names it with all other references glued to that home. Every
/// schedule column then expects zero, so no public value depends on the message — the virtual
/// words are pure witness freedom (any preimage admits them), and the message words bind only
/// through the digest. The digest is cross-checked against <c>SHA256.HashData</c>.
/// </summary>
[TestClass]
internal sealed class GkrShaPreimageTests
{
    private const int ScalarSize = GkrShaRoundSupport.ScalarSize;
    private const int WordBits = GkrShaRoundSupport.WordBits;
    private const int CarryWireCount = GkrShaRoundSupport.CarryWireCount;
    private const int RoundsPerBlock = GkrShaRoundSupport.RoundCount;
    private const int WordsPerState = GkrShaRoundSupport.WordsPerState;

    private const int BlockCount = 2;
    private const int RoundCopies = BlockCount * RoundsPerBlock;
    private const int AdditionCopies = BlockCount * WordsPerState;

    private const int RoundSegment = 0;
    private const int ScheduleSegment = RoundCopies * GkrShaRoundSupport.InputCount;
    private const int AdditionSegment = ScheduleSegment + (RoundCopies * GkrShaRoundSupport.ScheduleInputCount);

    //The pooled-buffer sizes: per instance (two blocks each) and for the concatenated witness
    //and output tables.
    private const int RoundInstanceBytes = BlockCount * GkrShaRoundSupport.RoundWitnessBytes;
    private const int ScheduleInstanceBytes = BlockCount * GkrShaRoundSupport.ScheduleWitnessBytes;
    private const int AdditionInstanceBytes = BlockCount * GkrShaRoundSupport.DigestWitnessBytes;
    private const int CombinedWitnessBytes = RoundInstanceBytes + ScheduleInstanceBytes + AdditionInstanceBytes;
    private const int RoundOutputBytes = BlockCount * GkrShaRoundSupport.RoundOutputBytes;
    private const int ScheduleOutputBytes = BlockCount * GkrShaRoundSupport.ScheduleOutputBytes;
    private const int AdditionOutputBytes = BlockCount * GkrShaRoundSupport.DigestOutputBytes;
    private const int CombinedOutputBytes = RoundOutputBytes + ScheduleOutputBytes + AdditionOutputBytes;

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.sha.preimage.test");

    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.sha.preimage.rng.v1");

    //A deterministic 100-byte message — two padded blocks. Private in the statement: it never
    //appears in the constraints, the expected outputs or the pins.
    private static byte[] Message { get; } = BuildMessage();


    [TestMethod]
    public void TwoBlockWitnessClosesEveryInstanceAgainstDotNetSha256()
    {
        //The chained uint oracle must agree with .NET before anything in-circuit is trusted.
        (uint[][] blocks, uint[][] chain, _, _) = Oracle();
        byte[] reference = SHA256.HashData(Message);
        for(int w = 0; w < WordsPerState; w++)
        {
            uint expected = BinaryPrimitives.ReadUInt32BigEndian(reference.AsSpan(4 * w));
            Assert.AreEqual(expected, chain[BlockCount][w], $"Digest word {w} must match SHA256.HashData across {blocks.Length} blocks.");
        }

        //Every instance's evaluation must close: the rounds to the negated round constants, the
        //schedule (with virtual predecessors) and the additions to zero.
        using IMemoryOwner<byte> roundInputsOwner = BaseMemoryPool.Shared.Rent(RoundInstanceBytes);
        Span<byte> roundInputs = roundInputsOwner.Memory.Span[..RoundInstanceBytes];
        PackRoundInstance(roundInputs);
        using IMemoryOwner<byte> roundOutputsOwner = BaseMemoryPool.Shared.Rent(RoundOutputBytes);
        Span<byte> roundOutputs = roundOutputsOwner.Memory.Span[..RoundOutputBytes];
        GkrTestSupport.Outputs(GkrShaRoundSupport.BuildRoundCircuit(), roundInputs, RoundCopies, roundOutputs);
        using IMemoryOwner<byte> expectedRoundOwner = BaseMemoryPool.Shared.Rent(RoundOutputBytes);
        Span<byte> expectedRound = expectedRoundOwner.Memory.Span[..RoundOutputBytes];
        ExpectedRoundOutputs(expectedRound);
        Assert.IsTrue(roundOutputs.SequenceEqual(expectedRound), "Every round column of both blocks must close to its negated round-constant pair.");

        using IMemoryOwner<byte> scheduleInputsOwner = BaseMemoryPool.Shared.Rent(ScheduleInstanceBytes);
        Span<byte> scheduleInputs = scheduleInputsOwner.Memory.Span[..ScheduleInstanceBytes];
        PackScheduleInstance(scheduleInputs);
        using IMemoryOwner<byte> scheduleOutputsOwner = BaseMemoryPool.Shared.Rent(ScheduleOutputBytes);
        Span<byte> scheduleOutputs = scheduleOutputsOwner.Memory.Span[..ScheduleOutputBytes];
        GkrTestSupport.Outputs(GkrShaRoundSupport.BuildScheduleCircuit(), scheduleInputs, RoundCopies, scheduleOutputs);
        Assert.IsFalse(scheduleOutputs.ContainsAnyExcept((byte)0), "Every schedule column must close to zero under the virtual predecessors.");

        using IMemoryOwner<byte> additionInputsOwner = BaseMemoryPool.Shared.Rent(AdditionInstanceBytes);
        Span<byte> additionInputs = additionInputsOwner.Memory.Span[..AdditionInstanceBytes];
        PackAdditionInstance(additionInputs);
        using IMemoryOwner<byte> additionOutputsOwner = BaseMemoryPool.Shared.Rent(AdditionOutputBytes);
        Span<byte> additionOutputs = additionOutputsOwner.Memory.Span[..AdditionOutputBytes];
        GkrTestSupport.Outputs(GkrShaRoundSupport.BuildDigestCircuit(), additionInputs, AdditionCopies, additionOutputs);
        Assert.IsFalse(additionOutputs.ContainsAnyExcept((byte)0), "Every chaining-addition column must close to zero.");
    }


    [TestMethod]
    public void ABrokenBlockChainIsUnprovable()
    {
        GkrCommittedInstance[] instances = Instances();
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(CombinedWitnessBytes);
        Memory<byte> witness = witnessOwner.Memory[..CombinedWitnessBytes];
        PackCombinedWitness(witness.Span);
        (LigeroLinearConstraint[] statement, byte[] targets) = BuildStatement();
        LigeroQuadraticConstraint[] bitness = BuildBitnessConstraints();

        //Block 1 claims to start from a state that is not block 0's feed-forward sum.
        int wire = ((((RoundIndex(RoundsPerBlock, GkrShaRoundSupport.AWire + 3)) * ScalarSize) + ScalarSize)) - 1;
        witness.Span[wire] ^= 0x01;

        using FiatShamirTranscript proverTranscript = NewTranscript();
        Assert.ThrowsExactly<InvalidOperationException>(
            () => GkrTestSupport.Prove(instances, witness.Span, RandomnessSeed, proverTranscript, statement, targets, bitness).Dispose(),
            "A block boundary that does not chain through the addition instance must violate the glue constraints.");
    }


    [TestMethod]
    public void ABrokenVirtualPredecessorGlueIsUnprovable()
    {
        GkrCommittedInstance[] instances = Instances();
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(CombinedWitnessBytes);
        Memory<byte> witness = witnessOwner.Memory[..CombinedWitnessBytes];
        PackCombinedWitness(witness.Span);
        (LigeroLinearConstraint[] statement, byte[] targets) = BuildStatement();
        LigeroQuadraticConstraint[] bitness = BuildBitnessConstraints();

        //Copy 1's P2 names the virtual word homed at copy 15's P16; claiming a different value
        //there must break the glue.
        int wire = ((((ScheduleIndex(1, GkrShaRoundSupport.Predecessor2Wire)) * ScalarSize) + ScalarSize)) - 1;
        witness.Span[wire] ^= 0x01;

        using FiatShamirTranscript proverTranscript = NewTranscript();
        Assert.ThrowsExactly<InvalidOperationException>(
            () => GkrTestSupport.Prove(instances, witness.Span, RandomnessSeed, proverTranscript, statement, targets, bitness).Dispose(),
            "A virtual-predecessor reference that does not match its home must violate the glue constraints.");
    }


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void CommittedTwoBlockPreimageProofClaimsOnlyTheDigest()
    {
        //On the order of five to ten minutes, hardware-dependent: the committed two-block
        //preimage prove and verify, ~102k witnesses. The default-suite gates above check the
        //chained oracle against .NET SHA-256 and every instance evaluation cheaply, so this
        //gate adds the end-to-end proving, not the logic coverage.
        GkrCommittedInstance[] instances = Instances();
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(CombinedWitnessBytes);
        Span<byte> witness = witnessOwner.Memory.Span[..CombinedWitnessBytes];
        PackCombinedWitness(witness);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(CombinedOutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..CombinedOutputBytes];
        CombinedOutputs(outputs);
        (LigeroLinearConstraint[] statement, byte[] targets) = BuildStatement();
        LigeroQuadraticConstraint[] bitness = BuildBitnessConstraints();

        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrCommittedProof proof = GkrTestSupport.Prove(instances, witness, RandomnessSeed, proverTranscript, statement, targets, bitness);

        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Assert.IsTrue(
                GkrTestSupport.Verify(instances, outputs, proof, verifierTranscript, statement, targets, bitness),
                "Knowledge of a private two-block preimage of the public digest must verify against the shared commitment.");
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


    private static GkrCommittedInstance[] Instances() =>
    [
        new GkrCommittedInstance(GkrShaRoundSupport.BuildRoundCircuit(), RoundCopies),
        new GkrCommittedInstance(GkrShaRoundSupport.BuildScheduleCircuit(), RoundCopies),
        new GkrCommittedInstance(GkrShaRoundSupport.BuildDigestCircuit(), AdditionCopies),
    ];


    //The chained oracle: padded blocks, the hash-state chain H_0..H_B, and per block the
    //schedule and the 65-state trace.
    private static (uint[][] Blocks, uint[][] Chain, uint[][] Schedules, uint[][][] Traces) Oracle()
    {
        uint[][] blocks = GkrShaRoundSupport.PadMessage(Message);
        var chain = new uint[blocks.Length + 1][];
        var schedules = new uint[blocks.Length][];
        var traces = new uint[blocks.Length][][];
        chain[0] = (uint[])GkrShaRoundSupport.InitialState.Clone();
        for(int b = 0; b < blocks.Length; b++)
        {
            schedules[b] = GkrShaRoundSupport.ScheduleOf(blocks[b]);
            traces[b] = GkrShaRoundSupport.TraceFrom(chain[b], schedules[b]);
            chain[b + 1] = new uint[WordsPerState];
            for(int w = 0; w < WordsPerState; w++)
            {
                chain[b + 1][w] = chain[b][w] + traces[b][RoundsPerBlock][w];
            }
        }

        return (blocks, chain, schedules, traces);
    }


    private static void PackRoundInstance(Span<byte> inputs)
    {
        (_, _, uint[][] schedules, uint[][][] traces) = Oracle();
        inputs.Clear();
        for(int b = 0; b < BlockCount; b++)
        {
            GkrShaRoundSupport.PackRoundBlock(inputs.Slice(b * GkrShaRoundSupport.RoundWitnessBytes, GkrShaRoundSupport.RoundWitnessBytes), traces[b], schedules[b]);
        }
    }


    private static void PackScheduleInstance(Span<byte> inputs)
    {
        (_, _, uint[][] schedules, _) = Oracle();
        inputs.Clear();
        for(int b = 0; b < BlockCount; b++)
        {
            GkrShaRoundSupport.PackScheduleBlock(inputs.Slice(b * GkrShaRoundSupport.ScheduleWitnessBytes, GkrShaRoundSupport.ScheduleWitnessBytes), schedules[b], GkrShaRoundSupport.VirtualPredecessors(schedules[b]));
        }
    }


    private static void PackAdditionInstance(Span<byte> inputs)
    {
        (_, uint[][] chain, _, uint[][][] traces) = Oracle();
        inputs.Clear();
        for(int b = 0; b < BlockCount; b++)
        {
            GkrShaRoundSupport.PackAdditionBlock(inputs.Slice(b * GkrShaRoundSupport.DigestWitnessBytes, GkrShaRoundSupport.DigestWitnessBytes), chain[b], traces[b][RoundsPerBlock], chain[b + 1]);
        }
    }


    private static void PackCombinedWitness(Span<byte> witness)
    {
        PackRoundInstance(witness[..RoundInstanceBytes]);
        PackScheduleInstance(witness.Slice(RoundInstanceBytes, ScheduleInstanceBytes));
        PackAdditionInstance(witness.Slice(RoundInstanceBytes + ScheduleInstanceBytes, AdditionInstanceBytes));
    }


    //The round columns expect the negated round-constant digits per block round; the schedule
    //and addition instances expect all zeros — nothing public depends on the message.
    private static void CombinedOutputs(Span<byte> outputs)
    {
        ExpectedRoundOutputs(outputs[..RoundOutputBytes]);
        outputs[RoundOutputBytes..].Clear();
    }


    private static void ExpectedRoundOutputs(Span<byte> outputs)
    {
        for(int b = 0; b < BlockCount; b++)
        {
            GkrShaRoundSupport.ExpectedRoundOutputs(outputs.Slice(b * GkrShaRoundSupport.RoundOutputBytes, GkrShaRoundSupport.RoundOutputBytes));
        }
    }


    //The public statement: per block the round-chain glue, the W glue and the predecessor glue
    //(virtual words homed at the P16 slots of the first sixteen copies); across blocks the
    //chain runs through the addition instance; the initial vector pins block 0 and the digest
    //pins the last block's sums. The message appears nowhere.
    private static (LigeroLinearConstraint[] Constraints, byte[] Targets) BuildStatement()
    {
        (_, uint[][] chain, _, _) = Oracle();
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
        int[] finalStateSources =
        [
            GkrShaRoundSupport.NewAWire, GkrShaRoundSupport.AWire, GkrShaRoundSupport.BWire, GkrShaRoundSupport.CWire,
            GkrShaRoundSupport.NewEWire, GkrShaRoundSupport.EWire, GkrShaRoundSupport.FWire, GkrShaRoundSupport.GWire,
        ];
        (int Wire, int Back)[] predecessors =
        [
            (GkrShaRoundSupport.Predecessor2Wire, 2),
            (GkrShaRoundSupport.Predecessor7Wire, 7),
            (GkrShaRoundSupport.Predecessor15Wire, 15),
            (GkrShaRoundSupport.Predecessor16Wire, 16),
        ];

        for(int b = 0; b < BlockCount; b++)
        {
            int baseCopy = b * RoundsPerBlock;

            //The round chain within the block.
            for(int r = 0; r + 1 < RoundsPerBlock; r++)
            {
                foreach(int[] shift in shifts)
                {
                    for(int i = 0; i < WordBits; i++)
                    {
                        statement.Equal(RoundIndex(baseCopy + r + 1, shift[0] + i), RoundIndex(baseCopy + r, shift[1] + i));
                    }
                }
            }

            //The block's entry state: the initial vector for block 0, the previous block's
            //feed-forward sums otherwise.
            for(int w = 0; w < WordsPerState; w++)
            {
                if(b == 0)
                {
                    statement.PinWord(RoundIndex(0, w * WordBits), GkrShaRoundSupport.InitialState[w]);

                    continue;
                }

                for(int i = 0; i < WordBits; i++)
                {
                    statement.Equal(RoundIndex(baseCopy, (w * WordBits) + i), AdditionIndex(((b - 1) * WordsPerState) + w, GkrShaRoundSupport.DigestSumWire + i));
                }
            }

            //The two instances witness the same schedule word per round, and each predecessor
            //is the schedule word of the copy it names — or, below zero, the virtual word homed
            //at the P16 slot of the copy whose own sixteen-back reference it is.
            for(int r = 0; r < RoundsPerBlock; r++)
            {
                for(int i = 0; i < WordBits; i++)
                {
                    statement.Equal(ScheduleIndex(baseCopy + r, GkrShaRoundSupport.ScheduleWordWire + i), RoundIndex(baseCopy + r, GkrShaRoundSupport.WWire + i));
                }

                foreach((int wire, int back) in predecessors)
                {
                    int named = r - back;
                    if(named >= 0)
                    {
                        for(int i = 0; i < WordBits; i++)
                        {
                            statement.Equal(ScheduleIndex(baseCopy + r, wire + i), ScheduleIndex(baseCopy + named, GkrShaRoundSupport.ScheduleWordWire + i));
                        }

                        continue;
                    }

                    int home = named + 16;
                    if(wire == GkrShaRoundSupport.Predecessor16Wire && r == home)
                    {
                        continue;
                    }

                    for(int i = 0; i < WordBits; i++)
                    {
                        statement.Equal(ScheduleIndex(baseCopy + r, wire + i), ScheduleIndex(baseCopy + home, GkrShaRoundSupport.Predecessor16Wire + i));
                    }
                }
            }

            //The chaining addition: the right operands are the block's final round state, the
            //left operands chain (pinned to the initial vector for block 0), and the last
            //block's sums are pinned to the public digest.
            for(int w = 0; w < WordsPerState; w++)
            {
                int copy = (b * WordsPerState) + w;
                for(int i = 0; i < WordBits; i++)
                {
                    statement.Equal(AdditionIndex(copy, GkrShaRoundSupport.DigestRightWire + i), RoundIndex(baseCopy + RoundsPerBlock - 1, finalStateSources[w] + i));
                }

                if(b == 0)
                {
                    statement.PinWord(AdditionIndex(copy, GkrShaRoundSupport.DigestLeftWire), GkrShaRoundSupport.InitialState[w]);
                }
                else
                {
                    for(int i = 0; i < WordBits; i++)
                    {
                        statement.Equal(AdditionIndex(copy, GkrShaRoundSupport.DigestLeftWire + i), AdditionIndex(((b - 1) * WordsPerState) + w, GkrShaRoundSupport.DigestSumWire + i));
                    }
                }

                if(b == BlockCount - 1)
                {
                    statement.PinWord(AdditionIndex(copy, GkrShaRoundSupport.DigestSumWire), chain[BlockCount][w]);
                }
            }
        }

        return statement.Build();
    }


    //Bitness: the round instance's witnessed digits and schedule words; the schedule carries
    //and the virtual-word homes (the P16 slots of each block's first sixteen copies); the
    //addition carries and the intermediate chain sums. Everything else is glued or pinned.
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
        for(int copy = 0; copy < RoundCopies; copy++)
        {
            foreach((int wireBase, int count) in roundGroups)
            {
                for(int k = 0; k < count; k++)
                {
                    AddBit(quadratics, RoundIndex(copy, wireBase + k));
                }
            }

            for(int k = 0; k < CarryWireCount; k++)
            {
                AddBit(quadratics, ScheduleIndex(copy, GkrShaRoundSupport.ScheduleCarryWire + k));
            }

            if(copy % RoundsPerBlock < 16)
            {
                for(int k = 0; k < WordBits; k++)
                {
                    AddBit(quadratics, ScheduleIndex(copy, GkrShaRoundSupport.Predecessor16Wire + k));
                }
            }
        }

        for(int copy = 0; copy < AdditionCopies; copy++)
        {
            for(int k = 0; k < CarryWireCount; k++)
            {
                AddBit(quadratics, AdditionIndex(copy, GkrShaRoundSupport.DigestCarryWire + k));
            }

            if(copy / WordsPerState < BlockCount - 1)
            {
                for(int k = 0; k < WordBits; k++)
                {
                    AddBit(quadratics, AdditionIndex(copy, GkrShaRoundSupport.DigestSumWire + k));
                }
            }
        }

        return [.. quadratics];

        static void AddBit(List<LigeroQuadraticConstraint> quadratics, int index) =>
            quadratics.Add(new LigeroQuadraticConstraint(index, index, index));
    }


    private static byte[] BuildMessage()
    {
        byte[] message = new byte[100];
        for(int i = 0; i < message.Length; i++)
        {
            message[i] = (byte)((7 * i) + 31);
        }

        return message;
    }


    private static int RoundIndex(int copy, int wire) => RoundSegment + (copy * GkrShaRoundSupport.InputCount) + wire;

    private static int ScheduleIndex(int copy, int wire) => ScheduleSegment + (copy * GkrShaRoundSupport.ScheduleInputCount) + wire;

    private static int AdditionIndex(int copy, int wire) => AdditionSegment + (copy * GkrShaRoundSupport.DigestInputCount) + wire;


    private static FiatShamirTranscript NewTranscript() =>
        GkrTestSupport.NewTranscript(Domain, "veridical.gkr.sha.preimage.seed"u8);
}

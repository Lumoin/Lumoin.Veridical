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
/// The SHA-256 preimage statement over <c>GF(2^128)</c> — the deployed Longfellow's hash field:
/// knowledge of a private two-block message hashing to a public digest, as three characteristic-
/// two circuit instances on one shared commitment (128 round copies, 128 schedule copies, 16
/// chaining-addition copies). The statement shape is the Fp256 preimage's — block chaining
/// through the addition instance, privacy via virtual predecessors homed at the P16 slots — with
/// the char-2 differences: the round constants are witnessed wires PINNED per copy (inner layers
/// cannot absorb constants and per-copy constants cannot be coefficients), the additions run
/// through in-circuit CSA compressors with only the final two-operand carries witnessed, and
/// EVERY expected output of every instance is zero. The digest is cross-checked against
/// <c>SHA256.HashData</c>.
/// </summary>
[TestClass]
internal sealed class GkrGf2kShaPreimageTests
{
    private const int ScalarSize = GkrGf2kShaSupport.ScalarSize;
    private const int WordBits = GkrGf2kShaSupport.WordBits;
    private const int RoundsPerBlock = GkrGf2kShaSupport.RoundCount;
    private const int FinalCarryCount = GkrGf2kShaSupport.FinalCarryCount;
    private const int WordsPerState = GkrShaRoundSupport.WordsPerState;

    private const int BlockCount = 2;
    private const int RoundCopies = BlockCount * RoundsPerBlock;
    private const int AdditionCopies = BlockCount * WordsPerState;

    private const int RoundSegment = 0;
    private const int ScheduleSegment = RoundCopies * GkrGf2kShaSupport.RoundInputCount;
    private const int AdditionSegment = ScheduleSegment + (RoundCopies * GkrGf2kShaSupport.ScheduleInputCount);

    private const int RoundWitnessBytes = BlockCount * GkrGf2kShaSupport.RoundWitnessBytes;
    private const int ScheduleWitnessBytes = BlockCount * GkrGf2kShaSupport.ScheduleWitnessBytes;
    private const int AdditionWitnessBytes = BlockCount * GkrGf2kShaSupport.AdditionWitnessBytesPerBlock;
    private const int CombinedWitnessBytes = RoundWitnessBytes + ScheduleWitnessBytes + AdditionWitnessBytes;

    private const int RoundOutputBytes = BlockCount * GkrGf2kShaSupport.RoundOutputBytes;
    private const int ScheduleOutputBytes = BlockCount * GkrGf2kShaSupport.ScheduleOutputBytes;
    private const int AdditionOutputBytes = BlockCount * GkrGf2kShaSupport.AdditionOutputBytesPerBlock;
    private const int CombinedOutputBytes = RoundOutputBytes + ScheduleOutputBytes + AdditionOutputBytes;

    private static FiatShamirDomainLabel Domain { get; } = new("veridical.gkr.gf2k.preimage.test");

    private static byte[] RandomnessSeed { get; } = System.Text.Encoding.UTF8.GetBytes("veridical.gkr.gf2k.preimage.rng.v1");

    //The same deterministic 100-byte two-block message as the Fp256 preimage. Private in the
    //statement: it appears in no constraint, pin or expected output.
    private static byte[] Message { get; } = BuildMessage();


    [TestMethod]
    public void EveryInstanceClosesToZeroAgainstDotNetSha256()
    {
        //The chained uint oracle must agree with .NET before anything in-circuit is trusted.
        (_, uint[][] chain, _, _) = Oracle();
        byte[] reference = SHA256.HashData(Message);
        for(int w = 0; w < WordsPerState; w++)
        {
            uint expected = BinaryPrimitives.ReadUInt32BigEndian(reference.AsSpan(4 * w));
            Assert.AreEqual(expected, chain[BlockCount][w], $"Digest word {w} must match SHA256.HashData.");
        }

        //Every characteristic-two instance evaluates to all-zero outputs on the honest witness.
        AssertInstanceClosed(GkrGf2kShaSupport.BuildRoundCircuit(), PackRoundInstance, RoundWitnessBytes, RoundOutputBytes, RoundCopies, "round");
        AssertInstanceClosed(GkrGf2kShaSupport.BuildScheduleCircuit(), PackScheduleInstance, ScheduleWitnessBytes, ScheduleOutputBytes, RoundCopies, "schedule");
        AssertInstanceClosed(GkrGf2kShaSupport.BuildAdditionCircuit(), PackAdditionInstance, AdditionWitnessBytes, AdditionOutputBytes, AdditionCopies, "addition");
    }


    [TestMethod]
    public void ABrokenBlockChainIsUnprovable()
    {
        GkrCommittedInstance[] instances = Instances();
        (LigeroLinearConstraint[] statement, byte[] targets) = BuildStatement();
        LigeroQuadraticConstraint[] bitness = BuildBitnessConstraints();
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(CombinedWitnessBytes);
        Memory<byte> witness = witnessOwner.Memory[..CombinedWitnessBytes];
        PackCombinedWitness(witness.Span);

        //Block 1 claims to start from a state that is not block 0's feed-forward sum.
        int wire = (((RoundIndex(RoundsPerBlock, GkrGf2kShaSupport.AWire + 3) * ScalarSize) + ScalarSize)) - 1;
        witness.Span[wire] ^= 0x01;

        using FiatShamirTranscript proverTranscript = NewTranscript();
        Assert.ThrowsExactly<InvalidOperationException>(
            () => GkrGf2kTestSupport.Prove(instances, witness.Span, RandomnessSeed, proverTranscript, statement, targets, bitness).Dispose(),
            "A block boundary that does not chain through the addition instance must violate the glue constraints.");
    }


    [TestMethod]
    [TestCategory(TestCategories.Slow)]
    public void CommittedTwoBlockPreimageProofClaimsOnlyTheDigest()
    {
        //On the order of a few minutes, hardware-dependent: the committed prove and verify
        //over GF(2^128) on the fast carry-less backend. The default-suite gates above check
        //the chained oracle and every instance evaluation cheaply, so this gate adds the
        //end-to-end proving, not the logic coverage.
        GkrCommittedInstance[] instances = Instances();
        (LigeroLinearConstraint[] statement, byte[] targets) = BuildStatement();
        LigeroQuadraticConstraint[] bitness = BuildBitnessConstraints();
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(CombinedWitnessBytes);
        Span<byte> witness = witnessOwner.Memory.Span[..CombinedWitnessBytes];
        PackCombinedWitness(witness);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(CombinedOutputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..CombinedOutputBytes];
        outputs.Clear();

        using FiatShamirTranscript proverTranscript = NewTranscript();
        using GkrCommittedProof proof = GkrGf2kTestSupport.Prove(instances, witness, RandomnessSeed, proverTranscript, statement, targets, bitness);

        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Assert.IsTrue(
                GkrGf2kTestSupport.Verify(instances, outputs, proof, verifierTranscript, statement, targets, bitness),
                "Knowledge of a private two-block preimage of the public digest must verify over GF(2^128).");
        }

        //A wrong claimed digest: the digest pins are the last statement targets.
        byte[] wrongDigest = (byte[])targets.Clone();
        int lastPin = targets.Length - ScalarSize;
        wrongDigest[(lastPin + ScalarSize) - 1] ^= 0x01;
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Assert.IsFalse(
                GkrGf2kTestSupport.Verify(instances, outputs, proof, verifierTranscript, statement, wrongDigest, bitness),
                "A claimed digest that differs in one bit must be rejected by the pinned commitment.");
        }

        //A wrong round constant: the K pins are public statement targets too.
        byte[] wrongConstant = (byte[])targets.Clone();
        wrongConstant[(KPinTargetIndex * ScalarSize) + ScalarSize - 1] ^= 0x01;
        using(FiatShamirTranscript verifierTranscript = NewTranscript())
        {
            Assert.IsFalse(
                GkrGf2kTestSupport.Verify(instances, outputs, proof, verifierTranscript, statement, wrongConstant, bitness),
                "A claimed round constant that differs in one bit must be rejected by the pinned commitment.");
        }
    }


    private static GkrCommittedInstance[] Instances() =>
    [
        new GkrCommittedInstance(GkrGf2kShaSupport.BuildRoundCircuit(), RoundCopies),
        new GkrCommittedInstance(GkrGf2kShaSupport.BuildScheduleCircuit(), RoundCopies),
        new GkrCommittedInstance(GkrGf2kShaSupport.BuildAdditionCircuit(), AdditionCopies),
    ];


    //The chained oracle: padded blocks, the hash-state chain H_0..H_B, per-block schedules and
    //traces — all shared with the Fp256 preimage, the uint arithmetic being field-independent.
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


    private static void PackRoundInstance(Span<byte> destination)
    {
        (_, _, uint[][] schedules, uint[][][] traces) = Oracle();
        destination.Clear();
        for(int b = 0; b < BlockCount; b++)
        {
            GkrGf2kShaSupport.PackRoundBlock(destination.Slice(b * GkrGf2kShaSupport.RoundWitnessBytes, GkrGf2kShaSupport.RoundWitnessBytes), traces[b], schedules[b]);
        }
    }


    private static void PackScheduleInstance(Span<byte> destination)
    {
        (_, _, uint[][] schedules, _) = Oracle();
        destination.Clear();
        for(int b = 0; b < BlockCount; b++)
        {
            GkrGf2kShaSupport.PackScheduleBlock(
                destination.Slice(b * GkrGf2kShaSupport.ScheduleWitnessBytes, GkrGf2kShaSupport.ScheduleWitnessBytes),
                schedules[b],
                GkrShaRoundSupport.VirtualPredecessors(schedules[b]));
        }
    }


    private static void PackAdditionInstance(Span<byte> destination)
    {
        (_, uint[][] chain, _, uint[][][] traces) = Oracle();
        destination.Clear();
        for(int b = 0; b < BlockCount; b++)
        {
            GkrGf2kShaSupport.PackAdditionBlock(
                destination.Slice(b * GkrGf2kShaSupport.AdditionWitnessBytesPerBlock, GkrGf2kShaSupport.AdditionWitnessBytesPerBlock),
                chain[b],
                traces[b][RoundsPerBlock],
                chain[b + 1]);
        }
    }


    private static void PackCombinedWitness(Span<byte> witness)
    {
        PackRoundInstance(witness[..RoundWitnessBytes]);
        PackScheduleInstance(witness.Slice(RoundWitnessBytes, ScheduleWitnessBytes));
        PackAdditionInstance(witness.Slice(RoundWitnessBytes + ScheduleWitnessBytes, AdditionWitnessBytes));
    }


    //The first K pin's position among the statement targets — recorded by BuildStatement so
    //the tamper test can flip a public round-constant bit.
    private static int KPinTargetIndex { get; set; }


    //The public statement: the round-chain and block-chain glue, the initial-vector and digest
    //pins, the per-copy round-constant pins, the W glue between the round and schedule
    //instances, and the virtual-predecessor glue. The message appears nowhere.
    private static (LigeroLinearConstraint[] Constraints, byte[] Targets) BuildStatement()
    {
        (_, uint[][] chain, _, _) = Oracle();

        //Over the binary field the equality coefficient is the element one: −1 ≡ 1.
        var statement = new GkrStatementBuilder(GkrGf2kTestSupport.One);

        int[][] shifts =
        [
            [GkrGf2kShaSupport.AWire, GkrGf2kShaSupport.NewAWire],
            [GkrGf2kShaSupport.BWire, GkrGf2kShaSupport.AWire],
            [GkrGf2kShaSupport.CWire, GkrGf2kShaSupport.BWire],
            [GkrGf2kShaSupport.DWire, GkrGf2kShaSupport.CWire],
            [GkrGf2kShaSupport.EWire, GkrGf2kShaSupport.NewEWire],
            [GkrGf2kShaSupport.FWire, GkrGf2kShaSupport.EWire],
            [GkrGf2kShaSupport.GWire, GkrGf2kShaSupport.FWire],
            [GkrGf2kShaSupport.HWire, GkrGf2kShaSupport.GWire],
        ];
        int[] finalStateSources =
        [
            GkrGf2kShaSupport.NewAWire, GkrGf2kShaSupport.AWire, GkrGf2kShaSupport.BWire, GkrGf2kShaSupport.CWire,
            GkrGf2kShaSupport.NewEWire, GkrGf2kShaSupport.EWire, GkrGf2kShaSupport.FWire, GkrGf2kShaSupport.GWire,
        ];
        (int Wire, int Back)[] predecessors =
        [
            (GkrGf2kShaSupport.Predecessor2Wire, 2),
            (GkrGf2kShaSupport.Predecessor7Wire, 7),
            (GkrGf2kShaSupport.Predecessor15Wire, 15),
            (GkrGf2kShaSupport.Predecessor16Wire, 16),
        ];

        KPinTargetIndex = -1;
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
                    statement.Equal(RoundIndex(baseCopy, (w * WordBits) + i), AdditionIndex(((b - 1) * WordsPerState) + w, GkrGf2kShaSupport.AdditionSumWire + i));
                }
            }

            //The per-copy round constants are public pins, and the two instances witness the
            //same schedule word per round.
            for(int r = 0; r < RoundsPerBlock; r++)
            {
                if(KPinTargetIndex < 0)
                {
                    KPinTargetIndex = statement.ConstraintCount;
                }

                statement.PinWord(RoundIndex(baseCopy + r, GkrGf2kShaSupport.KWire), GkrShaRoundSupport.RoundConstants[r]);
                for(int i = 0; i < WordBits; i++)
                {
                    statement.Equal(ScheduleIndex(baseCopy + r, GkrGf2kShaSupport.ScheduleWordWire + i), RoundIndex(baseCopy + r, GkrGf2kShaSupport.WWire + i));
                }

                foreach((int wire, int back) in predecessors)
                {
                    int named = r - back;
                    if(named >= 0)
                    {
                        for(int i = 0; i < WordBits; i++)
                        {
                            statement.Equal(ScheduleIndex(baseCopy + r, wire + i), ScheduleIndex(baseCopy + named, GkrGf2kShaSupport.ScheduleWordWire + i));
                        }

                        continue;
                    }

                    int home = named + 16;
                    if(wire == GkrGf2kShaSupport.Predecessor16Wire && r == home)
                    {
                        continue;
                    }

                    for(int i = 0; i < WordBits; i++)
                    {
                        statement.Equal(ScheduleIndex(baseCopy + r, wire + i), ScheduleIndex(baseCopy + home, GkrGf2kShaSupport.Predecessor16Wire + i));
                    }
                }
            }

            //The chaining addition: right operands are the block's final round state, left
            //operands chain (pinned to the initial vector for block 0), the last block's sums
            //are pinned to the public digest.
            for(int w = 0; w < WordsPerState; w++)
            {
                int copy = (b * WordsPerState) + w;
                for(int i = 0; i < WordBits; i++)
                {
                    statement.Equal(AdditionIndex(copy, GkrGf2kShaSupport.AdditionRightWire + i), RoundIndex((baseCopy + RoundsPerBlock) - 1, finalStateSources[w] + i));
                }

                if(b == 0)
                {
                    statement.PinWord(AdditionIndex(copy, GkrGf2kShaSupport.AdditionLeftWire), GkrShaRoundSupport.InitialState[w]);
                }
                else
                {
                    for(int i = 0; i < WordBits; i++)
                    {
                        statement.Equal(AdditionIndex(copy, GkrGf2kShaSupport.AdditionLeftWire + i), AdditionIndex(((b - 1) * WordsPerState) + w, GkrGf2kShaSupport.AdditionSumWire + i));
                    }
                }

                if(b == BlockCount - 1)
                {
                    statement.PinWord(AdditionIndex(copy, GkrGf2kShaSupport.AdditionSumWire), chain[BlockCount][w]);
                }
            }
        }

        return statement.Build();
    }


    //Bitness: the round instance's witnessed digits (W, the outcomes, both carry sets — K is
    //pinned, the boundary words inherit through the glue); the schedule carries and the
    //virtual-word homes; the addition carries and the intermediate chain sums.
    private static LigeroQuadraticConstraint[] BuildBitnessConstraints()
    {
        var quadratics = new List<LigeroQuadraticConstraint>();
        (int Base, int Count)[] roundGroups =
        [
            (GkrGf2kShaSupport.WWire, WordBits),
            (GkrGf2kShaSupport.NewAWire, WordBits),
            (GkrGf2kShaSupport.NewEWire, WordBits),
            (GkrGf2kShaSupport.CarryAWire, FinalCarryCount),
            (GkrGf2kShaSupport.CarryEWire, FinalCarryCount),
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

            for(int k = 0; k < FinalCarryCount; k++)
            {
                AddBit(quadratics, ScheduleIndex(copy, GkrGf2kShaSupport.ScheduleCarryWire + k));
            }

            if(copy % RoundsPerBlock < 16)
            {
                for(int k = 0; k < WordBits; k++)
                {
                    AddBit(quadratics, ScheduleIndex(copy, GkrGf2kShaSupport.Predecessor16Wire + k));
                }
            }
        }

        for(int copy = 0; copy < AdditionCopies; copy++)
        {
            for(int k = 0; k < FinalCarryCount; k++)
            {
                AddBit(quadratics, AdditionIndex(copy, GkrGf2kShaSupport.AdditionCarryWire + k));
            }

            if(copy / WordsPerState < BlockCount - 1)
            {
                for(int k = 0; k < WordBits; k++)
                {
                    AddBit(quadratics, AdditionIndex(copy, GkrGf2kShaSupport.AdditionSumWire + k));
                }
            }
        }

        return [.. quadratics];

        static void AddBit(List<LigeroQuadraticConstraint> quadratics, int index) =>
            quadratics.Add(new LigeroQuadraticConstraint(index, index, index));
    }


    private delegate void InstancePacker(Span<byte> destination);


    private static void AssertInstanceClosed(GkrCircuit circuit, InstancePacker packer, int witnessBytes, int outputBytes, int copyCount, string name)
    {
        using IMemoryOwner<byte> witnessOwner = BaseMemoryPool.Shared.Rent(witnessBytes);
        Span<byte> witness = witnessOwner.Memory.Span[..witnessBytes];
        packer(witness);
        using IMemoryOwner<byte> outputsOwner = BaseMemoryPool.Shared.Rent(outputBytes);
        Span<byte> outputs = outputsOwner.Memory.Span[..outputBytes];
        GkrGf2kTestSupport.Outputs(circuit, witness, copyCount, outputs);

        Assert.IsFalse(outputs.ContainsAnyExcept((byte)0), $"Every output of the honest {name} instance must be zero.");
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


    private static int RoundIndex(int copy, int wire) => RoundSegment + (copy * GkrGf2kShaSupport.RoundInputCount) + wire;

    private static int ScheduleIndex(int copy, int wire) => ScheduleSegment + (copy * GkrGf2kShaSupport.ScheduleInputCount) + wire;

    private static int AdditionIndex(int copy, int wire) => AdditionSegment + (copy * GkrGf2kShaSupport.AdditionInputCount) + wire;


    private static FiatShamirTranscript NewTranscript() =>
        GkrGf2kTestSupport.NewTranscript(Domain, "veridical.gkr.gf2k.preimage.seed"u8, []);
}

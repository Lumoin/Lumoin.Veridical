using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Gkr;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The GF(2^128) half of the mdoc end-to-end, shared by the digest-only binding
/// (<see cref="GkrMdocDigestTests"/>), the digest-plus-ECDSA binding
/// (<see cref="GkrMdocEcdsaTests"/>) and the full disclosure chain
/// (<see cref="GkrMdocDisclosureTests"/>): the in-circuit SHA-256 of a real ISO 18013-5
/// <c>Sig_structure</c> as characteristic-two CSA round/schedule/addition instances, the flat
/// witness layout that decomposes the block count into descending power-of-two components, the
/// glue statement, the bitness quadratics, the per-instance expected outputs, and the
/// digest-to-MAC binding. Constructed from the signed bytes and the key shares so the layout
/// (which depends on the message length) is computed once.
/// <para>
/// When an <c>IssuerSignedItem</c> is supplied the layout appends the item's own power-of-two
/// block components after the message's and before the MAC segment: the item is hashed in-circuit
/// as a SECOND SHA-256 preimage on the SAME commitment, its non-disclosed bytes stay private
/// through the schedule virtual predecessors, and the disclosure statement binds (a) the item's
/// digest to the signed Sig_structure bytes at the public <c>ItemDigestOffset</c> and (b) the
/// item's bytes at the public <c>AttributeOffset</c> to the public disclosure pattern. The
/// offsets and pattern are public by design.
/// </para>
/// </summary>
internal sealed class GkrMdocSupport
{
    private const int ScalarSize = GkrGf2kShaSupport.ScalarSize;
    private const int WordBits = GkrGf2kShaSupport.WordBits;
    private const int RoundsPerBlock = GkrGf2kShaSupport.RoundCount;
    private const int FinalCarryCount = GkrGf2kShaSupport.FinalCarryCount;
    private const int WordsPerState = GkrShaRoundSupport.WordsPerState;
    private const int DigestBytes = GkrShaRoundSupport.DigestBytes;
    private const int BitsPerByte = GkrShaRoundSupport.BitsPerByte;
    private const int BytesPerWord = GkrShaRoundSupport.BytesPerWord;
    private const int MessageWordsPerBlock = GkrShaRoundSupport.MessageWordsPerBlock;
    private const int BytesPerBlock = GkrShaRoundSupport.BytesPerBlock;
    private const int WordsPerHalf = HalfBits / WordBits;
    //Block counts decompose into descending powers of two; 2^30 bounds any int block count.
    private const int LargestComponentExponent = 30;

    public const int Halves = GkrGf2kMacSupport.CopyCount;
    public const int HalfBits = GkrGf2kMacSupport.HalfBits;

    private byte[] SignedStructure { get; }

    private byte[]? Item { get; }

    private byte[]? AttributePattern { get; }

    private byte[][] KeyShares { get; }

    private GkrWitnessLayout Layout { get; }


    public GkrMdocSupport(byte[] signedStructure, byte[][] keyShares)
    {
        ArgumentNullException.ThrowIfNull(signedStructure);
        ArgumentNullException.ThrowIfNull(keyShares);

        SignedStructure = signedStructure;
        Item = null;
        AttributePattern = null;
        KeyShares = keyShares;
        Layout = BuildLayout(signedStructure, null, null, 0);
    }


    //The item-bearing construction: the item is hashed as a second preimage on the same
    //commitment and the disclosure pattern at the public attribute offset is pinned.
    public GkrMdocSupport(byte[] signedStructure, byte[] item, byte[] attribute, int attributeOffset, byte[][] keyShares)
    {
        ArgumentNullException.ThrowIfNull(signedStructure);
        ArgumentNullException.ThrowIfNull(item);
        ArgumentNullException.ThrowIfNull(attribute);
        ArgumentNullException.ThrowIfNull(keyShares);

        SignedStructure = signedStructure;
        Item = item;
        AttributePattern = attribute;
        KeyShares = keyShares;
        Layout = BuildLayout(signedStructure, item, attribute, attributeOffset);
    }


    public int WitnessScalars => Layout.WitnessScalars;

    public int WitnessBytes => Layout.WitnessBytes;

    public int OutputBytes => Layout.OutputBytes;

    public int BlockCount => Layout.BlockCount;

    public int ItemDigestOffset => Layout.ItemDigestOffset;

    public int AttributeOffset => Layout.AttributeOffset;


    //The witness wire holding value-bit k of item-digest byte d: the addition-sum bit of the
    //item's last block, word d>>2 — the read-back side of the digest glue, exercised by the
    //wire-mapping oracle.
    public int ItemDigestWire(int d, int k) =>
        AdditionIndex(Layout.BlockCount - 1, d / BytesPerWord, GkrGf2kShaSupport.AdditionSumWire + WordBit(d % BytesPerWord, k));


    //The witness wire holding value-bit k of the item byte at the given item offset: the schedule
    //word of the round that holds it — the read-back side of the attribute pins.
    public int ItemAttributeWire(int itemOffset, int k)
    {
        (int round, int byteInWord) = ItemByteLocation(itemOffset);

        return ScheduleIndex(Layout.MessageBlockCount + (itemOffset / BytesPerBlock), round, GkrGf2kShaSupport.ScheduleWordWire + WordBit(byteInWord, k));
    }


    //The chained oracle digest of the real Sig_structure — the genuine SHA-256.
    public void ComputeDigest(Span<byte> digest)
    {
        uint[][] chain = Oracle(SignedStructure).Chain;
        WriteDigest(chain, digest);
    }


    //The chained oracle on the given message: padded blocks, the hash-state chain, the per-block
    //schedules and traces.
    private static (uint[][] Blocks, uint[][] Chain, uint[][] Schedules, uint[][][] Traces) Oracle(byte[] message)
    {
        uint[][] blocks = GkrShaRoundSupport.PadMessage(message);
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


    public static void WriteDigest(uint[][] chain, Span<byte> digest)
    {
        for(int w = 0; w < WordsPerState; w++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(digest.Slice(BytesPerWord * w, BytesPerWord), chain[^1][w]);
        }
    }


    //The flat witness: every block's round, schedule and addition slices at their layout bases,
    //then the MAC copies holding the digest bits and the key shares.
    public void PackGfWitness(Span<byte> witness, ReadOnlySpan<byte> digest) => PackGfWitness(witness, digest, null);


    //The flat witness with an optional item override packed into the item region (its block count
    //must match the real item's, so the layout still fits) — the tamper hook the disclosure tests
    //use to pack a one-byte-different item against the real digest glue.
    public void PackGfWitness(Span<byte> witness, ReadOnlySpan<byte> digest, byte[]? itemOverride)
    {
        witness.Clear();
        PackPreimage(witness, SignedStructure, 0);
        if(Item is not null)
        {
            byte[] item = itemOverride ?? Item;
            if(GkrShaRoundSupport.PadMessage(item).Length != Layout.ItemBlockCount)
            {
                throw new InvalidOperationException("The item override must occupy the same number of blocks as the real item.");
            }

            PackPreimage(witness, item, Layout.MessageBlockCount);
        }

        GkrGf2kMacSupport.PackGfWitness(
            witness.Slice(Layout.MacBase * ScalarSize, GkrGf2kMacSupport.WitnessBytes), digest, KeyShares);
    }


    private void PackPreimage(Span<byte> witness, byte[] message, int blockBase)
    {
        (_, uint[][] chain, uint[][] schedules, uint[][][] traces) = Oracle(message);
        for(int b = 0; b < schedules.Length; b++)
        {
            int block = blockBase + b;
            GkrGf2kShaSupport.PackRoundBlock(
                witness.Slice(Layout.RoundBase[block] * ScalarSize, GkrGf2kShaSupport.RoundWitnessBytes), traces[b], schedules[b]);
            GkrGf2kShaSupport.PackScheduleBlock(
                witness.Slice(Layout.ScheduleBase[block] * ScalarSize, GkrGf2kShaSupport.ScheduleWitnessBytes),
                schedules[b],
                GkrShaRoundSupport.VirtualPredecessors(schedules[b]));
            GkrGf2kShaSupport.PackAdditionBlock(
                witness.Slice(Layout.AdditionBase[block] * ScalarSize, GkrGf2kShaSupport.AdditionWitnessBytesPerBlock),
                chain[b],
                traces[b][RoundsPerBlock],
                chain[b + 1]);
        }
    }


    //One round/schedule/addition triple per power-of-two component (the message's, then the
    //item's when present), then the MAC instance — the order the witness layout and the expected
    //outputs follow.
    public GkrCommittedInstance[] Instances(ReadOnlySpan<byte> verifierKey)
    {
        var instances = new List<GkrCommittedInstance>();
        foreach(int size in Layout.ComponentSizes)
        {
            instances.Add(new GkrCommittedInstance(GkrGf2kShaSupport.BuildRoundCircuit(), size * RoundsPerBlock));
            instances.Add(new GkrCommittedInstance(GkrGf2kShaSupport.BuildScheduleCircuit(), size * RoundsPerBlock));
            instances.Add(new GkrCommittedInstance(GkrGf2kShaSupport.BuildAdditionCircuit(), size * WordsPerState));
        }

        instances.Add(new GkrCommittedInstance(GkrGf2kMacSupport.BuildMacCircuit(verifierKey), Halves));

        return [.. instances];
    }


    //The expected outputs in instance order: zeros for every SHA instance, the macs (and a zero
    //second slot) for the MAC copies.
    public void ExpectedOutputs(ReadOnlySpan<byte> macs, Span<byte> outputs)
    {
        outputs.Clear();
        for(int h = 0; h < Halves; h++)
        {
            macs.Slice(h * ScalarSize, ScalarSize).CopyTo(
                outputs.Slice((Layout.MacOutputBase + (h * GkrGf2kMacSupport.OutputCount)) * ScalarSize, ScalarSize));
        }
    }


    //Direct evaluation of every instance on its witness slice — the fast oracle gate.
    public void EvaluateInstances(ReadOnlySpan<byte> witness, ReadOnlySpan<byte> verifierKey, Span<byte> outputs)
    {
        GkrCommittedInstance[] instances = Instances(verifierKey);
        int witnessCursor = 0;
        int outputCursor = 0;
        foreach(GkrCommittedInstance instance in instances)
        {
            int witnessScalars = instance.CopyCount * instance.Circuit.InputCount;
            int outputScalars = instance.CopyCount * instance.Circuit.Layers[0].OutputCount;
            GkrGf2kTestSupport.Outputs(
                instance.Circuit,
                witness.Slice(witnessCursor * ScalarSize, witnessScalars * ScalarSize),
                instance.CopyCount,
                outputs.Slice(outputCursor * ScalarSize, outputScalars * ScalarSize));
            witnessCursor += witnessScalars;
            outputCursor += outputScalars;
        }
    }


    //The public statement, the two-block preimage's generalized to the message's B blocks plus
    //(when an item is present) the item's own preimage and the disclosure glue, and the
    //digest-to-MAC glue: the round chain, the block-entry glue (initial-vector pins for each
    //preimage's first block), the per-copy round-constant pins, the W and predecessor glue, the
    //chaining addition glue — and instead of message-digest pins, the last message block's sum
    //bits equal the MAC instance's message bits. The message AND the digest appear nowhere.
    public (LigeroLinearConstraint[] Constraints, byte[] Targets) BuildStatement() => BuildStatement(null, null);


    //The public statement against a (possibly tampered) disclosure pattern and item-digest offset
    //— the tamper hooks the disclosure tests rebuild with one flipped pattern byte or a shifted
    //offset to drive verifier-side rejections.
    public (LigeroLinearConstraint[] Constraints, byte[] Targets) BuildStatement(byte[]? attributeOverride, int? itemDigestOffsetOverride)
    {
        var statement = new GkrStatementBuilder(GkrGf2kTestSupport.One);

        AppendPreimageStatement(statement, 0, Layout.MessageBlockCount);
        if(Item is not null)
        {
            AppendPreimageStatement(statement, Layout.MessageBlockCount, Layout.ItemBlockCount);
        }

        //The digest-to-MAC glue: bit i of half h is bit (i mod 32) of message-digest word
        //4h+3−⌊i/32⌋ — the big-endian byte order of the digest against the x^i coefficient order
        //of the half.
        int lastMessageBlock = Layout.MessageBlockCount - 1;
        for(int h = 0; h < Halves; h++)
        {
            for(int i = 0; i < HalfBits; i++)
            {
                int word = ((h * WordsPerHalf) + (WordsPerHalf - 1)) - (i / WordBits);
                statement.Equal(MacIndex(h, i), AdditionIndex(lastMessageBlock, word, GkrGf2kShaSupport.AdditionSumWire + (i % WordBits)));
            }
        }

        if(Item is not null)
        {
            AppendDisclosureStatement(statement, attributeOverride ?? Attribute(), itemDigestOffsetOverride ?? Layout.ItemDigestOffset);
        }

        return statement.Build();
    }


    //One preimage's round chain, entry-state pins/glue, round-constant pins, schedule glue and
    //chaining additions over its block range. The first block of the range pins the initial
    //vector; later blocks feed-forward from the previous block's addition sums.
    private void AppendPreimageStatement(GkrStatementBuilder statement, int blockBase, int blockCount)
    {
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

        for(int local = 0; local < blockCount; local++)
        {
            int b = blockBase + local;

            //The round chain within the block.
            for(int r = 0; r + 1 < RoundsPerBlock; r++)
            {
                foreach(int[] shift in shifts)
                {
                    for(int i = 0; i < WordBits; i++)
                    {
                        statement.Equal(RoundIndex(b, r + 1, shift[0] + i), RoundIndex(b, r, shift[1] + i));
                    }
                }
            }

            //The block's entry state: the initial vector for the preimage's first block, the
            //previous block's feed-forward sums otherwise — across component boundaries when they
            //fall there.
            for(int w = 0; w < WordsPerState; w++)
            {
                if(local == 0)
                {
                    statement.PinWord(RoundIndex(b, 0, w * WordBits), GkrShaRoundSupport.InitialState[w]);

                    continue;
                }

                for(int i = 0; i < WordBits; i++)
                {
                    statement.Equal(RoundIndex(b, 0, (w * WordBits) + i), AdditionIndex(b - 1, w, GkrGf2kShaSupport.AdditionSumWire + i));
                }
            }

            //The per-copy round constants are public pins, and the round and schedule instances
            //witness the same schedule word per round.
            for(int r = 0; r < RoundsPerBlock; r++)
            {
                statement.PinWord(RoundIndex(b, r, GkrGf2kShaSupport.KWire), GkrShaRoundSupport.RoundConstants[r]);
                for(int i = 0; i < WordBits; i++)
                {
                    statement.Equal(ScheduleIndex(b, r, GkrGf2kShaSupport.ScheduleWordWire + i), RoundIndex(b, r, GkrGf2kShaSupport.WWire + i));
                }

                foreach((int wire, int back) in predecessors)
                {
                    int named = r - back;
                    if(named >= 0)
                    {
                        for(int i = 0; i < WordBits; i++)
                        {
                            statement.Equal(ScheduleIndex(b, r, wire + i), ScheduleIndex(b, named, GkrGf2kShaSupport.ScheduleWordWire + i));
                        }

                        continue;
                    }

                    int home = named + MessageWordsPerBlock;
                    if(wire == GkrGf2kShaSupport.Predecessor16Wire && r == home)
                    {
                        continue;
                    }

                    for(int i = 0; i < WordBits; i++)
                    {
                        statement.Equal(ScheduleIndex(b, r, wire + i), ScheduleIndex(b, home, GkrGf2kShaSupport.Predecessor16Wire + i));
                    }
                }
            }

            //The chaining addition: right operands are the block's final round state, left
            //operands chain (pinned to the initial vector for the preimage's first block). The
            //message's last block sums are NOT pinned — they are the private digest that glues to
            //the MAC; the item's last block sums glue to the Sig_structure at ItemDigestOffset.
            for(int w = 0; w < WordsPerState; w++)
            {
                for(int i = 0; i < WordBits; i++)
                {
                    statement.Equal(AdditionIndex(b, w, GkrGf2kShaSupport.AdditionRightWire + i), RoundIndex(b, RoundsPerBlock - 1, finalStateSources[w] + i));
                }

                if(local == 0)
                {
                    statement.PinWord(AdditionIndex(b, w, GkrGf2kShaSupport.AdditionLeftWire), GkrShaRoundSupport.InitialState[w]);
                }
                else
                {
                    for(int i = 0; i < WordBits; i++)
                    {
                        statement.Equal(AdditionIndex(b, w, GkrGf2kShaSupport.AdditionLeftWire + i), AdditionIndex(b - 1, w, GkrGf2kShaSupport.AdditionSumWire + i));
                    }
                }
            }
        }
    }


    //The disclosure glue: (a) the item's digest equals the signed Sig_structure bytes at the
    //public ItemDigestOffset, and (b) the item's bytes at the public AttributeOffset equal the
    //public disclosure pattern. Both bind through the schedule words of the rounds that hold the
    //named message/item bytes (rounds r < 16 witness the raw message words).
    private void AppendDisclosureStatement(GkrStatementBuilder statement, byte[] attribute, int itemDigestOffset)
    {
        int itemLastBlock = Layout.BlockCount - 1;

        //(a) The 32 item-digest bytes equal the 32 Sig_structure bytes at ItemDigestOffset. Item
        //digest byte d is state word d>>2's bytes; the Sig_structure byte at ItemDigestOffset+d
        //lives in the message schedule (round = the message word index for that offset).
        for(int d = 0; d < DigestBytes; d++)
        {
            int word = d / BytesPerWord;
            for(int k = 0; k < BitsPerByte; k++)
            {
                int wordBit = WordBit(d % BytesPerWord, k);
                int sumWire = AdditionIndex(itemLastBlock, word, GkrGf2kShaSupport.AdditionSumWire + wordBit);
                statement.Equal(sumWire, MessageByteWire(itemDigestOffset + d, k));
            }
        }

        //(b) The item's bytes at AttributeOffset equal the public pattern: per pattern byte, pin
        //the eight schedule-word bits of the item byte to the public byte's bits.
        for(int idx = 0; idx < attribute.Length; idx++)
        {
            int offset = Layout.AttributeOffset + idx;
            byte value = attribute[idx];
            for(int k = 0; k < BitsPerByte; k++)
            {
                statement.Pin(ItemAttributeWire(offset, k), (value >> k) & 1);
            }
        }
    }


    //The public disclosure pattern of the item.
    private byte[] Attribute() =>
        AttributePattern ?? throw new InvalidOperationException("The disclosure layout carries no attribute pattern.");


    //Bitness: the round instances' witnessed digits, the schedule carries and virtual-word homes,
    //the addition carries and ALL chain sums — the message's last block sums are private digest
    //bits the MAC instance squares; the item's last block sums are its private digest — plus the
    //MAC message wires themselves.
    public LigeroQuadraticConstraint[] BuildBitnessConstraints()
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
        for(int b = 0; b < Layout.BlockCount; b++)
        {
            for(int r = 0; r < RoundsPerBlock; r++)
            {
                foreach((int wireBase, int count) in roundGroups)
                {
                    for(int k = 0; k < count; k++)
                    {
                        AddBit(quadratics, RoundIndex(b, r, wireBase + k));
                    }
                }

                for(int k = 0; k < FinalCarryCount; k++)
                {
                    AddBit(quadratics, ScheduleIndex(b, r, GkrGf2kShaSupport.ScheduleCarryWire + k));
                }

                if(r < MessageWordsPerBlock)
                {
                    for(int k = 0; k < WordBits; k++)
                    {
                        AddBit(quadratics, ScheduleIndex(b, r, GkrGf2kShaSupport.Predecessor16Wire + k));
                    }
                }
            }

            for(int w = 0; w < WordsPerState; w++)
            {
                for(int k = 0; k < FinalCarryCount; k++)
                {
                    AddBit(quadratics, AdditionIndex(b, w, GkrGf2kShaSupport.AdditionCarryWire + k));
                }

                for(int k = 0; k < WordBits; k++)
                {
                    AddBit(quadratics, AdditionIndex(b, w, GkrGf2kShaSupport.AdditionSumWire + k));
                }
            }
        }

        for(int h = 0; h < Halves; h++)
        {
            for(int i = 0; i < HalfBits; i++)
            {
                AddBit(quadratics, MacIndex(h, i));
            }
        }

        return [.. quadratics];

        static void AddBit(List<LigeroQuadraticConstraint> quadratics, int index) =>
            quadratics.Add(new LigeroQuadraticConstraint(index, index, index));
    }


    private int RoundIndex(int block, int round, int wire) =>
        Layout.RoundBase[block] + (round * GkrGf2kShaSupport.RoundInputCount) + wire;

    private int ScheduleIndex(int block, int round, int wire) =>
        Layout.ScheduleBase[block] + (round * GkrGf2kShaSupport.ScheduleInputCount) + wire;

    private int AdditionIndex(int block, int word, int wire) =>
        Layout.AdditionBase[block] + (word * GkrGf2kShaSupport.AdditionInputCount) + wire;

    private int MacIndex(int half, int wire) =>
        Layout.MacBase + (half * GkrGf2kMacSupport.InputCount) + wire;


    //The witness wire holding value-bit k (k = 0 the least-significant) of the Sig_structure byte
    //at the given global message offset. Message rounds r < 16 witness the raw message words, so
    //the byte lives in the schedule of round (word index within the block).
    private int MessageByteWire(int offset, int k)
    {
        int block = offset / BytesPerBlock;

        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(block, Layout.MessageBlockCount, nameof(offset));

        int round = (offset % BytesPerBlock) / BytesPerWord;
        int byteInWord = offset % BytesPerWord;

        return ScheduleIndex(block, round, GkrGf2kShaSupport.ScheduleWordWire + WordBit(byteInWord, k));
    }


    //The (round, byte-within-word) of the item byte at the given item offset.
    private static (int Round, int ByteInWord) ItemByteLocation(int offset) =>
        ((offset % BytesPerBlock) / BytesPerWord, offset % BytesPerWord);


    //The schedule-word bit index of value-bit k of the byte at big-endian position byteInWord
    //(0 the most-significant byte of the word). Word bytes are big-endian; WriteWord stores bit i
    //at wire base + i, so the byte's value-bit k is word bit 8·(3−byteInWord) + k.
    private static int WordBit(int byteInWord, int k) => (BitsPerByte * (BytesPerWord - 1 - byteInWord)) + k;


    //The witness geometry: the message's block count and (when present) the item's, each
    //decomposed into descending power-of-two components, each component's three instance segments
    //laid out in instance order, the MAC segment last, with per-block scalar bases for the glue
    //indexing.
    private static GkrWitnessLayout BuildLayout(byte[] signedStructure, byte[]? item, byte[]? attribute, int attributeOffset)
    {
        int messageBlockCount = GkrShaRoundSupport.PadMessage(signedStructure).Length;
        int itemBlockCount = item is null ? 0 : GkrShaRoundSupport.PadMessage(item).Length;
        int blockCount = messageBlockCount + itemBlockCount;

        var componentSizes = new List<int>();
        Decompose(componentSizes, messageBlockCount);
        Decompose(componentSizes, itemBlockCount);

        int[] roundBase = new int[blockCount];
        int[] scheduleBase = new int[blockCount];
        int[] additionBase = new int[blockCount];
        int offset = 0;
        int outputOffset = 0;
        int block = 0;
        foreach(int size in componentSizes)
        {
            for(int l = 0; l < size; l++)
            {
                roundBase[block + l] = offset + (l * RoundsPerBlock * GkrGf2kShaSupport.RoundInputCount);
            }

            offset += size * RoundsPerBlock * GkrGf2kShaSupport.RoundInputCount;
            for(int l = 0; l < size; l++)
            {
                scheduleBase[block + l] = offset + (l * RoundsPerBlock * GkrGf2kShaSupport.ScheduleInputCount);
            }

            offset += size * RoundsPerBlock * GkrGf2kShaSupport.ScheduleInputCount;
            for(int l = 0; l < size; l++)
            {
                additionBase[block + l] = offset + (l * WordsPerState * GkrGf2kShaSupport.AdditionInputCount);
            }

            offset += size * WordsPerState * GkrGf2kShaSupport.AdditionInputCount;
            outputOffset += size * ((RoundsPerBlock * GkrGf2kShaSupport.RoundOutputCount)
                + (RoundsPerBlock * GkrGf2kShaSupport.ScheduleOutputCount)
                + (WordsPerState * GkrGf2kShaSupport.AdditionOutputCount));
            block += size;
        }

        int itemDigestOffset = ValidateDisclosure(signedStructure, item, attribute, attributeOffset);

        return new GkrWitnessLayout(
            blockCount,
            messageBlockCount,
            itemBlockCount,
            [.. componentSizes],
            roundBase,
            scheduleBase,
            additionBase,
            itemDigestOffset,
            attributeOffset,
            MacBase: offset,
            WitnessScalars: offset + (Halves * GkrGf2kMacSupport.InputCount),
            MacOutputBase: outputOffset,
            OutputScalars: outputOffset + (Halves * GkrGf2kMacSupport.OutputCount));
    }


    //Validates the disclosure geometry so a bad offset fails here, not in a proof: the item's
    //digest window must land inside the real Sig_structure bytes and the attribute window inside
    //the real item bytes (never the SHA padding). Returns the located item-digest offset.
    private static int ValidateDisclosure(byte[] signedStructure, byte[]? item, byte[]? attribute, int attributeOffset)
    {
        if(item is null)
        {
            return 0;
        }

        byte[] itemDigest = System.Security.Cryptography.SHA256.HashData(item);
        int itemDigestOffset = signedStructure.AsSpan().IndexOf(itemDigest);
        if(itemDigestOffset < 0)
        {
            throw new InvalidOperationException("The item's SHA-256 digest is not present in the signed structure.");
        }

        if(itemDigestOffset + itemDigest.Length > signedStructure.Length)
        {
            throw new InvalidOperationException("The item-digest window runs past the real Sig_structure bytes.");
        }

        ArgumentNullException.ThrowIfNull(attribute);
        if(attributeOffset < 0 || attributeOffset + attribute.Length > item.Length)
        {
            throw new InvalidOperationException("The attribute window runs past the real item bytes.");
        }

        return itemDigestOffset;
    }


    private static void Decompose(List<int> sizes, int blockCount)
    {
        for(int bit = LargestComponentExponent; bit >= 0; bit--)
        {
            if((blockCount & (1 << bit)) != 0)
            {
                sizes.Add(1 << bit);
            }
        }
    }


    private sealed record GkrWitnessLayout(
        int BlockCount,
        int MessageBlockCount,
        int ItemBlockCount,
        int[] ComponentSizes,
        int[] RoundBase,
        int[] ScheduleBase,
        int[] AdditionBase,
        int ItemDigestOffset,
        int AttributeOffset,
        int MacBase,
        int WitnessScalars,
        int MacOutputBase,
        int OutputScalars)
    {
        public int WitnessBytes => WitnessScalars * ScalarSize;

        public int OutputBytes => OutputScalars * ScalarSize;
    }
}

using Lumoin.Veridical.Core.Gkr;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The shared SHA-256 round-check material: the FIPS 180-4 constants, the "abc" test block, the
/// uint oracle (message schedule and round-boundary trace), the three-layer round circuit and
/// its honest witness packing. Used by the compression test (schedule words pinned public) and
/// the scheduled compression test (schedule checked in-circuit by a second instance against the
/// same commitment). The circuit conventions: rotations are index rewiring, XOR is
/// <c>x² + y² − 2xy</c>, and every pass or linear use of a bit is its own square — sound because
/// the input bits carry quadratic bitness constraints on the commitment and internal wires are
/// proven evaluations of them.
/// </summary>
internal static class GkrShaRoundSupport
{
    public const int ScalarSize = GkrTestSupport.ScalarSize;
    public const int WordBits = 32;
    public const int RoundCount = 64;
    public const int PairCount = WordBits / 2;
    public const int CarryWireCount = 3 * PairCount;

    //SHA-256 byte geometry, shared by every consumer that addresses message bytes or digest
    //words: 4-byte big-endian words, 64-byte blocks whose first 16 words are the raw message,
    //an 8-word hash state, a 32-byte digest.
    public const int BitsPerByte = 8;
    public const int BytesPerWord = WordBits / BitsPerByte;
    public const int MessageWordsPerBlock = 16;
    public const int BytesPerBlock = MessageWordsPerBlock * BytesPerWord;
    public const int WordsPerState = 8;
    public const int DigestBytes = WordsPerState * BytesPerWord;

    //Input wires per round copy: the round-boundary state a..h, the schedule word, the round
    //outputs and the radix-4 carry bits of the two additions, zero-padded to 512.
    public const int InputCount = 512;
    public const int AWire = 0;
    public const int BWire = 32;
    public const int CWire = 64;
    public const int DWire = 96;
    public const int EWire = 128;
    public const int FWire = 160;
    public const int GWire = 192;
    public const int HWire = 224;
    public const int WWire = 256;
    public const int NewAWire = 288;
    public const int NewEWire = 320;
    public const int CarryAWire = 352;
    public const int CarryEWire = 400;
    public const int RoundWitnessBytes = RoundCount * InputCount * ScalarSize;

    //The inner layer next to the inputs: the first XOR pairs of Σ1 and Σ0, the Maj product and
    //XOR, the full Ch, and squared passes of everything the upper layers still need.
    private const int XorE = 0;
    private const int XorA = 32;
    private const int ProductAb = 64;
    private const int XorAb = 96;
    private const int Choose = 128;
    private const int PassE = 160;
    private const int PassA = 192;
    private const int PassC = 224;
    private const int PassD = 256;
    private const int PassH = 288;
    private const int PassW = 320;
    private const int PassNewA = 352;
    private const int PassNewE = 384;
    private const int PassCarryA = 416;
    private const int PassCarryE = 464;
    private const int InnerWidth = 512;

    //The middle layer: the finished word functions and the column operands.
    private const int Sigma1Wire = 0;
    private const int Sigma0Wire = 32;
    private const int MajorityWire = 64;
    private const int ChooseWire = 96;
    private const int MidD = 128;
    private const int MidH = 160;
    private const int MidW = 192;
    private const int MidNewA = 224;
    private const int MidNewE = 256;
    private const int MidCarryA = 288;
    private const int MidCarryE = 336;
    private const int MiddleWidth = 512;

    //Outputs: 16 radix-4 columns for the new_a addition, 16 for the new_e addition.
    public const int OutputCount = 32;
    public const int RoundOutputBytes = RoundCount * OutputCount * ScalarSize;

    //The digest-addition instance: one copy per state word computes one
    //H_w = IV_w + state64_w mod 2³² with witnessed carries — the block-chaining addition shape.
    public const int DigestCopyCount = 8;
    public const int DigestInputCount = 256;
    public const int DigestLeftWire = 0;
    public const int DigestRightWire = 32;
    public const int DigestSumWire = 64;
    public const int DigestCarryWire = 96;
    public const int DigestOutputCount = PairCount;
    public const int DigestWitnessBytes = DigestCopyCount * DigestInputCount * ScalarSize;
    public const int DigestOutputBytes = DigestCopyCount * DigestOutputCount * ScalarSize;

    //The schedule instance: per copy the schedule word, its four predecessors and the radix-4
    //carry digits of the recurrence addition, zero-padded to 256.
    public const int ScheduleInputCount = 256;
    public const int ScheduleWordWire = 0;
    public const int Predecessor2Wire = 32;
    public const int Predecessor7Wire = 64;
    public const int Predecessor15Wire = 96;
    public const int Predecessor16Wire = 128;
    public const int ScheduleCarryWire = 160;
    public const int ScheduleOutputCount = PairCount;
    public const int ScheduleWitnessBytes = RoundCount * ScheduleInputCount * ScalarSize;
    public const int ScheduleOutputBytes = RoundCount * ScheduleOutputCount * ScalarSize;

    //The schedule circuit's inner layer (the first XOR pairs of σ1 and σ0 plus squared passes)
    //and middle layer (the finished σ words and the column operands).
    private const int ScheduleU1 = 0;
    private const int ScheduleU0 = 32;
    private const int ScheduleInnerP2 = 64;
    private const int ScheduleInnerP15 = 96;
    private const int ScheduleInnerP7 = 128;
    private const int ScheduleInnerP16 = 160;
    private const int ScheduleInnerCarry = 192;
    private const int ScheduleInnerWord = 240;
    private const int ScheduleInnerWidth = 512;
    private const int ScheduleSigma1 = 0;
    private const int ScheduleSigma0 = 32;
    private const int ScheduleMidP7 = 64;
    private const int ScheduleMidP16 = 96;
    private const int ScheduleMidCarry = 128;
    private const int ScheduleMidWord = 176;
    private const int ScheduleMiddleWidth = 256;

    private static byte[] One { get; } = GkrTestSupport.One;

    private static byte[] Two { get; } = GkrTestSupport.Scalar(2);

    private static byte[] Four { get; } = GkrTestSupport.Scalar(4);

    private static byte[] NegativeOne { get; } = GkrTestSupport.NegativeOne;

    private static byte[] NegativeTwo { get; } = GkrTestSupport.NegativeTwo;

    private static byte[] NegativeFour { get; } = GkrTestSupport.Canonical(GkrTestSupport.P - 4);

    private static byte[] NegativeEight { get; } = GkrTestSupport.Canonical(GkrTestSupport.P - 8);

    private static byte[] NegativeSixteen { get; } = GkrTestSupport.Canonical(GkrTestSupport.P - 16);

    public static uint[] RoundConstants { get; } =
    [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    public static uint[] InitialState { get; } =
    [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    //The single padded block of "abc".
    public static uint[] MessageBlock { get; } =
    [
        0x61626380, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000018,
    ];


    //One round as a three-layer circuit; copy r is round r.
    public static GkrCircuit BuildRoundCircuit()
    {
        var inner = new List<GkrLayerTerm>();
        for(int i = 0; i < WordBits; i++)
        {
            AddXor(inner, XorE + i, EWire + ((i + 6) & 31), EWire + ((i + 11) & 31));
            AddXor(inner, XorA + i, AWire + ((i + 2) & 31), AWire + ((i + 13) & 31));
            inner.Add(new GkrLayerTerm(ProductAb + i, AWire + i, BWire + i, One));
            AddXor(inner, XorAb + i, AWire + i, BWire + i);
            inner.Add(new GkrLayerTerm(Choose + i, EWire + i, FWire + i, One));
            inner.Add(new GkrLayerTerm(Choose + i, GWire + i, GWire + i, One));
            inner.Add(new GkrLayerTerm(Choose + i, EWire + i, GWire + i, NegativeOne));
        }

        AddSquarePass(inner, PassE, EWire, WordBits);
        AddSquarePass(inner, PassA, AWire, WordBits);
        AddSquarePass(inner, PassC, CWire, WordBits);
        AddSquarePass(inner, PassD, DWire, WordBits);
        AddSquarePass(inner, PassH, HWire, WordBits);
        AddSquarePass(inner, PassW, WWire, WordBits);
        AddSquarePass(inner, PassNewA, NewAWire, WordBits);
        AddSquarePass(inner, PassNewE, NewEWire, WordBits);
        AddSquarePass(inner, PassCarryA, CarryAWire, CarryWireCount);
        AddSquarePass(inner, PassCarryE, CarryEWire, CarryWireCount);

        var middle = new List<GkrLayerTerm>();
        for(int i = 0; i < WordBits; i++)
        {
            AddXor(middle, Sigma1Wire + i, XorE + i, PassE + ((i + 25) & 31));
            AddXor(middle, Sigma0Wire + i, XorA + i, PassA + ((i + 22) & 31));
            middle.Add(new GkrLayerTerm(MajorityWire + i, ProductAb + i, ProductAb + i, One));
            middle.Add(new GkrLayerTerm(MajorityWire + i, PassC + i, XorAb + i, One));
        }

        AddSquarePass(middle, ChooseWire, Choose, WordBits);
        AddSquarePass(middle, MidD, PassD, WordBits);
        AddSquarePass(middle, MidH, PassH, WordBits);
        AddSquarePass(middle, MidW, PassW, WordBits);
        AddSquarePass(middle, MidNewA, PassNewA, WordBits);
        AddSquarePass(middle, MidNewE, PassNewE, WordBits);
        AddSquarePass(middle, MidCarryA, PassCarryA, CarryWireCount);
        AddSquarePass(middle, MidCarryE, PassCarryE, CarryWireCount);

        var output = new List<GkrLayerTerm>();
        for(int j = 0; j < PairCount; j++)
        {
            AddColumn(output, j, [MidH, Sigma1Wire, ChooseWire, MidW, Sigma0Wire, MajorityWire], MidCarryA, MidNewA);
            AddColumn(output, PairCount + j, [MidD, MidH, Sigma1Wire, ChooseWire, MidW], MidCarryE, MidNewE);
        }

        return new GkrCircuit(
            [new GkrLayer([.. output], OutputCount), new GkrLayer([.. middle], MiddleWidth), new GkrLayer([.. inner], InnerWidth)],
            InputCount);
    }


    //The honest round-instance witness of the single test block; the destination may be pooled,
    //so the zero padding the block packer relies on is written explicitly.
    public static void PackRoundWitness(Span<byte> destination)
    {
        uint[] schedule = Schedule();
        destination.Clear();
        PackRoundBlock(destination, Trace(schedule), schedule);
    }


    //One block's 64 round copies: every round boundary, schedule word, round output and carry
    //digit of the block's trace, bits least-significant first.
    public static void PackRoundBlock(Span<byte> destination, uint[][] trace, uint[] schedule)
    {
        for(int r = 0; r < RoundCount; r++)
        {
            Span<byte> copy = destination.Slice(r * InputCount * ScalarSize, InputCount * ScalarSize);
            uint a = trace[r][0], b = trace[r][1], c = trace[r][2], d = trace[r][3];
            uint e = trace[r][4], f = trace[r][5], g = trace[r][6], h = trace[r][7];

            WriteWord(copy, AWire, a);
            WriteWord(copy, BWire, b);
            WriteWord(copy, CWire, c);
            WriteWord(copy, DWire, d);
            WriteWord(copy, EWire, e);
            WriteWord(copy, FWire, f);
            WriteWord(copy, GWire, g);
            WriteWord(copy, HWire, h);
            WriteWord(copy, WWire, schedule[r]);
            WriteWord(copy, NewAWire, trace[r + 1][0]);
            WriteWord(copy, NewEWire, trace[r + 1][4]);

            WriteCarries(copy, CarryAWire, [h, Sigma1(e), Ch(e, f, g), schedule[r], Sigma0(a), Maj(a, b, c)], RoundConstants[r], trace[r + 1][0]);
            WriteCarries(copy, CarryEWire, [d, h, Sigma1(e), Ch(e, f, g), schedule[r]], RoundConstants[r], trace[r + 1][4]);
        }
    }


    //One block's 64 schedule copies with the recurrence holding for EVERY round: the first
    //sixteen copies take witnessed virtual predecessors, so all columns close to zero and no
    //expected output depends on the message — the private-message binding.
    public static void PackScheduleBlock(Span<byte> destination, uint[] schedule, uint[] virtualWords)
    {
        for(int r = 0; r < RoundCount; r++)
        {
            Span<byte> copy = destination.Slice(r * ScheduleInputCount * ScalarSize, ScheduleInputCount * ScalarSize);
            uint p2 = ScheduleAt(schedule, virtualWords, r - 2);
            uint p7 = ScheduleAt(schedule, virtualWords, r - 7);
            uint p15 = ScheduleAt(schedule, virtualWords, r - 15);
            uint p16 = ScheduleAt(schedule, virtualWords, r - 16);

            WriteWord(copy, ScheduleWordWire, schedule[r]);
            WriteWord(copy, Predecessor2Wire, p2);
            WriteWord(copy, Predecessor7Wire, p7);
            WriteWord(copy, Predecessor15Wire, p15);
            WriteWord(copy, Predecessor16Wire, p16);
            WriteCarries(copy, ScheduleCarryWire, [SmallSigma1(p2), p7, SmallSigma0(p15), p16], 0, schedule[r]);
        }
    }


    //One block's 8 addition copies: left + right = sum per state word, witnessed carries.
    public static void PackAdditionBlock(Span<byte> destination, uint[] left, uint[] right, uint[] sum)
    {
        for(int w = 0; w < DigestCopyCount; w++)
        {
            Span<byte> copy = destination.Slice(w * DigestInputCount * ScalarSize, DigestInputCount * ScalarSize);
            WriteWord(copy, DigestLeftWire, left[w]);
            WriteWord(copy, DigestRightWire, right[w]);
            WriteWord(copy, DigestSumWire, sum[w]);
            WriteCarries(copy, DigestCarryWire, [left[w], right[w]], 0, sum[w]);
        }
    }


    //The expected round-instance outputs: column j of copy r closes to the negated
    //round-constant digit −(K_r,2j + 2·K_r,2j+1), the same for both additions.
    public static void ExpectedRoundOutputs(Span<byte> destination)
    {
        destination.Clear();
        for(int r = 0; r < RoundCount; r++)
        {
            for(int j = 0; j < PairCount; j++)
            {
                int pair = PairDigit(RoundConstants[r], j);
                if(pair == 0)
                {
                    continue;
                }

                byte[] value = GkrTestSupport.Canonical(GkrTestSupport.P - pair);
                value.CopyTo(destination.Slice(((r * OutputCount) + j) * ScalarSize, ScalarSize));
                value.CopyTo(destination.Slice(((r * OutputCount) + PairCount + j) * ScalarSize, ScalarSize));
            }
        }
    }


    //The schedule recurrence as a three-layer circuit; copy r is round r. σ1 = ROTR17 ⊕ ROTR19 ⊕
    //SHR10 and σ0 = ROTR7 ⊕ ROTR18 ⊕ SHR3 split their XOR across the two inner layers; shift
    //positions past the word edge drop the tap and pass the pair through.
    public static GkrCircuit BuildScheduleCircuit()
    {
        var inner = new List<GkrLayerTerm>();
        for(int i = 0; i < WordBits; i++)
        {
            AddXor(inner, ScheduleU1 + i, Predecessor2Wire + ((i + 17) & 31), Predecessor2Wire + ((i + 19) & 31));
            AddXor(inner, ScheduleU0 + i, Predecessor15Wire + ((i + 7) & 31), Predecessor15Wire + ((i + 18) & 31));
        }

        AddSquarePass(inner, ScheduleInnerP2, Predecessor2Wire, WordBits);
        AddSquarePass(inner, ScheduleInnerP15, Predecessor15Wire, WordBits);
        AddSquarePass(inner, ScheduleInnerP7, Predecessor7Wire, WordBits);
        AddSquarePass(inner, ScheduleInnerP16, Predecessor16Wire, WordBits);
        AddSquarePass(inner, ScheduleInnerCarry, ScheduleCarryWire, CarryWireCount);
        AddSquarePass(inner, ScheduleInnerWord, ScheduleWordWire, WordBits);

        var middle = new List<GkrLayerTerm>();
        for(int i = 0; i < WordBits; i++)
        {
            if(i + 10 < WordBits)
            {
                AddXor(middle, ScheduleSigma1 + i, ScheduleU1 + i, ScheduleInnerP2 + i + 10);
            }
            else
            {
                AddSquarePass(middle, ScheduleSigma1 + i, ScheduleU1 + i, 1);
            }

            if(i + 3 < WordBits)
            {
                AddXor(middle, ScheduleSigma0 + i, ScheduleU0 + i, ScheduleInnerP15 + i + 3);
            }
            else
            {
                AddSquarePass(middle, ScheduleSigma0 + i, ScheduleU0 + i, 1);
            }
        }

        AddSquarePass(middle, ScheduleMidP7, ScheduleInnerP7, WordBits);
        AddSquarePass(middle, ScheduleMidP16, ScheduleInnerP16, WordBits);
        AddSquarePass(middle, ScheduleMidCarry, ScheduleInnerCarry, CarryWireCount);
        AddSquarePass(middle, ScheduleMidWord, ScheduleInnerWord, WordBits);

        var output = new List<GkrLayerTerm>();
        for(int j = 0; j < PairCount; j++)
        {
            AddColumn(output, j, [ScheduleSigma1, ScheduleMidP7, ScheduleSigma0, ScheduleMidP16], ScheduleMidCarry, ScheduleMidWord);
        }

        return new GkrCircuit(
            [new GkrLayer([.. output], ScheduleOutputCount), new GkrLayer([.. middle], ScheduleMiddleWidth), new GkrLayer([.. inner], ScheduleInnerWidth)],
            ScheduleInputCount);
    }


    //One layer per copy: the 16 radix-4 columns of one witnessed-carry two-operand addition,
    //left + right = sum mod 2³² with the final carry discarded. Copy w is state word w.
    public static GkrCircuit BuildDigestCircuit()
    {
        var output = new List<GkrLayerTerm>();
        for(int j = 0; j < PairCount; j++)
        {
            AddColumn(output, j, [DigestLeftWire, DigestRightWire], DigestCarryWire, DigestSumWire);
        }

        return new GkrCircuit([new GkrLayer([.. output], DigestOutputCount)], DigestInputCount);
    }


    //The honest digest-instance witness: per word the initial-vector operand, the final round
    //state, the digest word and the addition carries.
    public static void PackDigestWitness(Span<byte> destination)
    {
        uint[][] trace = Trace(Schedule());
        uint[] digest = DigestWords();

        destination.Clear();
        for(int w = 0; w < DigestCopyCount; w++)
        {
            Span<byte> copy = destination.Slice(w * DigestInputCount * ScalarSize, DigestInputCount * ScalarSize);
            WriteWord(copy, DigestLeftWire, InitialState[w]);
            WriteWord(copy, DigestRightWire, trace[RoundCount][w]);
            WriteWord(copy, DigestSumWire, digest[w]);
            WriteCarries(copy, DigestCarryWire, [InitialState[w], trace[RoundCount][w]], 0, digest[w]);
        }
    }


    //The SHA-256 digest of the block: the initial vector plus the final round state, per word.
    public static uint[] DigestWords()
    {
        uint[][] trace = Trace(Schedule());

        uint[] digest = new uint[8];
        for(int w = 0; w < 8; w++)
        {
            digest[w] = InitialState[w] + trace[RoundCount][w];
        }

        return digest;
    }


    //The message schedule of the single test block.
    public static uint[] Schedule() => ScheduleOf(MessageBlock);


    //The message schedule expanded from one padded block.
    public static uint[] ScheduleOf(uint[] block)
    {
        uint[] w = new uint[64];
        block.CopyTo(w, 0);
        for(int t = 16; t < 64; t++)
        {
            w[t] = SmallSigma1(w[t - 2]) + w[t - 7] + SmallSigma0(w[t - 15]) + w[t - 16];
        }

        return w;
    }


    //The 65 round-boundary states of the single test block.
    public static uint[][] Trace(uint[] schedule) => TraceFrom(InitialState, schedule);


    //The 65 round-boundary states from a given hash state: trace[r] enters round r, trace[64]
    //is the final state before the feed-forward addition.
    public static uint[][] TraceFrom(uint[] start, uint[] schedule)
    {
        var trace = new uint[RoundCount + 1][];
        trace[0] = (uint[])start.Clone();
        for(int r = 0; r < RoundCount; r++)
        {
            uint[] s = trace[r];
            uint t1 = s[7] + Sigma1(s[4]) + Ch(s[4], s[5], s[6]) + RoundConstants[r] + schedule[r];
            uint t2 = Sigma0(s[0]) + Maj(s[0], s[1], s[2]);
            trace[r + 1] = [t1 + t2, s[0], s[1], s[2], s[3] + t1, s[4], s[5], s[6]];
        }

        return trace;
    }


    //The standard SHA-256 padding: the message, one 0x80 byte, zeros, and the bit length, cut
    //into 16-word big-endian blocks.
    public static uint[][] PadMessage(ReadOnlySpan<byte> message)
    {
        int blockCount = (message.Length + 9 + 63) / 64;
        byte[] padded = new byte[blockCount * 64];
        message.CopyTo(padded);
        padded[message.Length] = 0x80;
        BinaryPrimitives.WriteUInt64BigEndian(padded.AsSpan(padded.Length - 8), (ulong)message.Length * 8);

        var blocks = new uint[blockCount][];
        for(int b = 0; b < blockCount; b++)
        {
            blocks[b] = new uint[16];
            for(int t = 0; t < 16; t++)
            {
                blocks[b][t] = BinaryPrimitives.ReadUInt32BigEndian(padded.AsSpan((b * 64) + (4 * t)));
            }
        }

        return blocks;
    }


    //The sixteen virtual predecessor words W₋₁₆..W₋₁ that make the recurrence hold for every
    //round of the block: solved downward from r = 15, where each step's other taps are already
    //known. They are pure witness freedom — any W₀..₁₅ admits them — so binding through them
    //reveals nothing and constrains nothing about the message.
    public static uint[] VirtualPredecessors(uint[] schedule)
    {
        uint[] virtualWords = new uint[16];
        for(int r = 15; r >= 0; r--)
        {
            uint p2 = ScheduleAt(schedule, virtualWords, r - 2);
            uint p7 = ScheduleAt(schedule, virtualWords, r - 7);
            uint p15 = ScheduleAt(schedule, virtualWords, r - 15);
            virtualWords[r] = schedule[r] - SmallSigma1(p2) - p7 - SmallSigma0(p15);
        }

        return virtualWords;
    }


    //The schedule word at the given index, reaching into the virtual words below zero
    //(virtual[j + 16] holds W_j).
    public static uint ScheduleAt(uint[] schedule, uint[] virtualWords, int index) =>
        index >= 0 ? schedule[index] : virtualWords[index + 16];


    //The radix-4 column for bit pair j of a multi-operand addition: the operand digits plus the
    //carry in, minus the result digits, minus four times the carry out; any constant digit is
    //the verifier's expected value. The pair index is recovered from the output wire.
    public static void AddColumn(List<GkrLayerTerm> terms, int outputWire, int[] operands, int carryBase, int sumBase)
    {
        int j = outputWire & (PairCount - 1);
        foreach(int operand in operands)
        {
            terms.Add(new GkrLayerTerm(outputWire, operand + (2 * j), operand + (2 * j), One));
            terms.Add(new GkrLayerTerm(outputWire, operand + (2 * j) + 1, operand + (2 * j) + 1, Two));
        }

        if(j > 0)
        {
            int carryIn = carryBase + (3 * (j - 1));
            terms.Add(new GkrLayerTerm(outputWire, carryIn, carryIn, One));
            terms.Add(new GkrLayerTerm(outputWire, carryIn + 1, carryIn + 1, Two));
            terms.Add(new GkrLayerTerm(outputWire, carryIn + 2, carryIn + 2, Four));
        }

        terms.Add(new GkrLayerTerm(outputWire, sumBase + (2 * j), sumBase + (2 * j), NegativeOne));
        terms.Add(new GkrLayerTerm(outputWire, sumBase + (2 * j) + 1, sumBase + (2 * j) + 1, NegativeTwo));

        int carryOut = carryBase + (3 * j);
        terms.Add(new GkrLayerTerm(outputWire, carryOut, carryOut, NegativeFour));
        terms.Add(new GkrLayerTerm(outputWire, carryOut + 1, carryOut + 1, NegativeEight));
        terms.Add(new GkrLayerTerm(outputWire, carryOut + 2, carryOut + 2, NegativeSixteen));
    }


    public static void AddXor(List<GkrLayerTerm> terms, int outputWire, int x, int y)
    {
        terms.Add(new GkrLayerTerm(outputWire, x, x, One));
        terms.Add(new GkrLayerTerm(outputWire, y, y, One));
        terms.Add(new GkrLayerTerm(outputWire, x, y, NegativeTwo));
    }


    public static void AddSquarePass(List<GkrLayerTerm> terms, int outputBase, int inputBase, int count)
    {
        for(int k = 0; k < count; k++)
        {
            terms.Add(new GkrLayerTerm(outputBase + k, inputBase + k, inputBase + k, One));
        }
    }


    //The radix-4 schoolbook carries of one multi-operand addition: per pair, the operand and
    //constant digits plus the carry in equal the result digit plus four times the carry out.
    public static void WriteCarries(Span<byte> copy, int wireBase, uint[] operands, uint constant, uint sum)
    {
        int carry = 0;
        for(int j = 0; j < PairCount; j++)
        {
            int total = carry + PairDigit(constant, j);
            foreach(uint operand in operands)
            {
                total += PairDigit(operand, j);
            }

            int carryOut = (total - PairDigit(sum, j)) / 4;
            if((total - PairDigit(sum, j)) % 4 != 0 || carryOut < 0 || carryOut > 7)
            {
                throw new InvalidOperationException($"Pair {j}: carry {carryOut} is outside the three witnessed bits.");
            }

            for(int t = 0; t < 3; t++)
            {
                copy[((wireBase + (3 * j) + t) * ScalarSize) + ScalarSize - 1] = (byte)((carryOut >> t) & 1);
            }

            carry = carryOut;
        }
    }


    public static void WriteWord(Span<byte> copy, int wireBase, uint word)
    {
        for(int i = 0; i < WordBits; i++)
        {
            copy[((wireBase + i) * ScalarSize) + ScalarSize - 1] = (byte)((word >> i) & 1);
        }
    }


    public static int PairDigit(uint word, int pair) => (int)((word >> (2 * pair)) & 3);

    public static uint Sigma1(uint e) => uint.RotateRight(e, 6) ^ uint.RotateRight(e, 11) ^ uint.RotateRight(e, 25);

    public static uint Sigma0(uint a) => uint.RotateRight(a, 2) ^ uint.RotateRight(a, 13) ^ uint.RotateRight(a, 22);

    public static uint SmallSigma0(uint x) => uint.RotateRight(x, 7) ^ uint.RotateRight(x, 18) ^ (x >> 3);

    public static uint SmallSigma1(uint x) => uint.RotateRight(x, 17) ^ uint.RotateRight(x, 19) ^ (x >> 10);

    public static uint Ch(uint e, uint f, uint g) => (e & f) ^ (~e & g);

    public static uint Maj(uint a, uint b, uint c) => (a & b) ^ (a & c) ^ (b & c);
}

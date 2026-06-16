using Lumoin.Veridical.Core.Gkr;
using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The characteristic-two SHA-256 circuits for the committed GKR engine over <c>GF(2^128)</c>:
/// the round-check, schedule and chaining-addition instances of the preimage statement, built
/// from the 7c.1 primitives. The shapes that differ from the Fp256 circuits:
/// <list type="bullet">
/// <item>Multi-operand additions run through in-circuit CSA 3→2 compressors — the sum vector is
/// XOR3 (linear, three square terms per bit), the carry vector is the per-bit majority shifted
/// left one (carry wire zero has NO terms and is exactly zero; the majority of bit 31 is
/// dropped, which is the mod-2³² truncation) — and only the final two-operand add carries
/// witnessed bits, checked by the full-adder relations.</item>
/// <item>The round constant K_r is WITNESSED AND PINNED per copy: an inner layer cannot absorb
/// a constant (there is no constant-one wire, and per-copy constants cannot be coefficients
/// because the wiring is shared across copies). With K as pinned wires every circuit is fully
/// uniform and every expected output is zero.</item>
/// <item>Σ1/Σ0/Ch/Maj are all single-layer (XOR is addition; Maj's <c>−2abc</c> term vanishes
/// modulo two), so the round circuit is six layers, none wider than 512.</item>
/// </list>
/// The uint oracle (schedule, trace, padding, virtual predecessors) is field-independent and
/// reused from <see cref="GkrShaRoundSupport"/>.
/// </summary>
internal static class GkrGf2kShaSupport
{
    public const int ScalarSize = GkrGf2kTestSupport.ScalarSize;
    public const int WordBits = 32;
    public const int RoundCount = 64;
    public const int FinalCarryCount = WordBits - 1;

    //Round-instance input wires per copy: the boundary state a..h, the schedule word, the
    //pinned round constant, the round outputs and the two final-add carry sets, padded to 512.
    public const int RoundInputCount = 512;
    public const int AWire = 0;
    public const int BWire = 32;
    public const int CWire = 64;
    public const int DWire = 96;
    public const int EWire = 128;
    public const int FWire = 160;
    public const int GWire = 192;
    public const int HWire = 224;
    public const int WWire = 256;
    public const int KWire = 288;
    public const int NewAWire = 320;
    public const int NewEWire = 352;
    public const int CarryAWire = 384;
    public const int CarryEWire = 416;
    public const int RoundOutputCount = 128;
    public const int RoundWitnessBytes = RoundCount * RoundInputCount * ScalarSize;
    public const int RoundOutputBytes = RoundCount * RoundOutputCount * ScalarSize;

    //Layer 1: the four word functions and squared passes of everything still needed.
    private const int L1Sigma1 = 0;
    private const int L1Sigma0 = 32;
    private const int L1Choose = 64;
    private const int L1Majority = 96;
    private const int L1H = 128;
    private const int L1D = 160;
    private const int L1W = 192;
    private const int L1K = 224;
    private const int L1NewA = 256;
    private const int L1NewE = 288;
    private const int L1CarryA = 320;
    private const int L1CarryE = 352;
    private const int Layer1Width = 512;

    //Layer 2: the first compressor stage of both trees.
    private const int L2SumA1 = 0;
    private const int L2CarryA1 = 32;
    private const int L2SumA2 = 64;
    private const int L2CarryA2 = 96;
    private const int L2SumE1 = 128;
    private const int L2CarryE1 = 160;
    private const int L2SumE2 = 192;
    private const int L2CarryE2 = 224;
    private const int L2Majority = 256;
    private const int L2NewA = 288;
    private const int L2NewE = 320;
    private const int L2CarryA = 352;
    private const int L2CarryE = 384;
    private const int Layer2Width = 512;

    //Layer 3: the second compressor stage.
    private const int L3SumA3 = 0;
    private const int L3CarryA3 = 32;
    private const int L3SumE3 = 64;
    private const int L3CarryE3 = 96;
    private const int L3CarryA2 = 128;
    private const int L3CarryE2 = 160;
    private const int L3Majority = 192;
    private const int L3NewA = 224;
    private const int L3NewE = 256;
    private const int L3CarryA = 288;
    private const int L3CarryE = 320;
    private const int Layer3Width = 512;

    //Layer 4: the third compressor stage; the new_e tree finishes here.
    private const int L4SumA4 = 0;
    private const int L4CarryA4 = 32;
    private const int L4SumE4 = 64;
    private const int L4CarryE4 = 96;
    private const int L4Majority = 128;
    private const int L4NewA = 160;
    private const int L4NewE = 192;
    private const int L4CarryA = 224;
    private const int L4CarryE = 256;
    private const int Layer4Width = 512;

    //Layer 5: the last compressor of the new_a tree.
    private const int L5SumA5 = 0;
    private const int L5CarryA5 = 32;
    private const int L5SumE4 = 64;
    private const int L5CarryE4 = 96;
    private const int L5NewA = 128;
    private const int L5NewE = 160;
    private const int L5CarryA = 192;
    private const int L5CarryE = 224;
    private const int Layer5Width = 256;

    //Round outputs: the two final-add check groups.
    private const int OutSumA = 0;
    private const int OutCarryA = 32;
    private const int OutSumE = 64;
    private const int OutCarryE = 96;

    //Schedule-instance input wires per copy, padded to 256.
    public const int ScheduleInputCount = 256;
    public const int ScheduleWordWire = 0;
    public const int Predecessor2Wire = 32;
    public const int Predecessor7Wire = 64;
    public const int Predecessor15Wire = 96;
    public const int Predecessor16Wire = 128;
    public const int ScheduleCarryWire = 160;
    public const int ScheduleOutputCount = 64;
    public const int ScheduleWitnessBytes = RoundCount * ScheduleInputCount * ScalarSize;
    public const int ScheduleOutputBytes = RoundCount * ScheduleOutputCount * ScalarSize;

    private const int S1SmallSigma1 = 0;
    private const int S1SmallSigma0 = 32;
    private const int S1P7 = 64;
    private const int S1P16 = 96;
    private const int S1Word = 128;
    private const int S1Carry = 160;
    private const int ScheduleLayer1Width = 256;

    private const int S2Sum = 0;
    private const int S2Carry = 32;
    private const int S2P16 = 64;
    private const int S2Word = 96;
    private const int S2CarryPass = 128;
    private const int ScheduleLayer2Width = 256;

    private const int S3Sum = 0;
    private const int S3Carry = 32;
    private const int S3Word = 64;
    private const int S3CarryPass = 96;
    private const int ScheduleLayer3Width = 128;

    //The chaining addition: one copy per state word, left + right = sum with witnessed carries.
    public const int AdditionCopiesPerBlock = 8;
    public const int AdditionInputCount = 128;
    public const int AdditionLeftWire = 0;
    public const int AdditionRightWire = 32;
    public const int AdditionSumWire = 64;
    public const int AdditionCarryWire = 96;
    public const int AdditionOutputCount = 64;
    public const int AdditionWitnessBytesPerBlock = AdditionCopiesPerBlock * AdditionInputCount * ScalarSize;
    public const int AdditionOutputBytesPerBlock = AdditionCopiesPerBlock * AdditionOutputCount * ScalarSize;

    private static byte[] One { get; } = GkrGf2kTestSupport.One;


    //The round check: six layers, every expected output zero.
    public static GkrCircuit BuildRoundCircuit()
    {
        var layer1 = new List<GkrLayerTerm>();
        for(int i = 0; i < WordBits; i++)
        {
            AddParity(layer1, L1Sigma1 + i, EWire + ((i + 6) & 31), EWire + ((i + 11) & 31), EWire + ((i + 25) & 31));
            AddParity(layer1, L1Sigma0 + i, AWire + ((i + 2) & 31), AWire + ((i + 13) & 31), AWire + ((i + 22) & 31));
            layer1.Add(new GkrLayerTerm(L1Choose + i, EWire + i, FWire + i, One));
            layer1.Add(new GkrLayerTerm(L1Choose + i, GWire + i, GWire + i, One));
            layer1.Add(new GkrLayerTerm(L1Choose + i, EWire + i, GWire + i, One));
            AddMajority(layer1, L1Majority + i, AWire + i, BWire + i, CWire + i);
        }

        GkrShaRoundSupport.AddSquarePass(layer1, L1H, HWire, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer1, L1D, DWire, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer1, L1W, WWire, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer1, L1K, KWire, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer1, L1NewA, NewAWire, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer1, L1NewE, NewEWire, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer1, L1CarryA, CarryAWire, FinalCarryCount);
        GkrShaRoundSupport.AddSquarePass(layer1, L1CarryE, CarryEWire, FinalCarryCount);

        var layer2 = new List<GkrLayerTerm>();
        AddCompressor(layer2, L2SumA1, L2CarryA1, L1H, L1Sigma1, L1Choose);
        AddCompressor(layer2, L2SumA2, L2CarryA2, L1W, L1K, L1Sigma0);
        AddCompressor(layer2, L2SumE1, L2CarryE1, L1D, L1H, L1Sigma1);
        AddCompressor(layer2, L2SumE2, L2CarryE2, L1Choose, L1W, L1K);
        GkrShaRoundSupport.AddSquarePass(layer2, L2Majority, L1Majority, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer2, L2NewA, L1NewA, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer2, L2NewE, L1NewE, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer2, L2CarryA, L1CarryA, FinalCarryCount);
        GkrShaRoundSupport.AddSquarePass(layer2, L2CarryE, L1CarryE, FinalCarryCount);

        var layer3 = new List<GkrLayerTerm>();
        AddCompressor(layer3, L3SumA3, L3CarryA3, L2SumA1, L2CarryA1, L2SumA2);
        AddCompressor(layer3, L3SumE3, L3CarryE3, L2SumE1, L2CarryE1, L2SumE2);
        GkrShaRoundSupport.AddSquarePass(layer3, L3CarryA2, L2CarryA2, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer3, L3CarryE2, L2CarryE2, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer3, L3Majority, L2Majority, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer3, L3NewA, L2NewA, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer3, L3NewE, L2NewE, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer3, L3CarryA, L2CarryA, FinalCarryCount);
        GkrShaRoundSupport.AddSquarePass(layer3, L3CarryE, L2CarryE, FinalCarryCount);

        var layer4 = new List<GkrLayerTerm>();
        AddCompressor(layer4, L4SumA4, L4CarryA4, L3SumA3, L3CarryA3, L3CarryA2);
        AddCompressor(layer4, L4SumE4, L4CarryE4, L3SumE3, L3CarryE3, L3CarryE2);
        GkrShaRoundSupport.AddSquarePass(layer4, L4Majority, L3Majority, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer4, L4NewA, L3NewA, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer4, L4NewE, L3NewE, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer4, L4CarryA, L3CarryA, FinalCarryCount);
        GkrShaRoundSupport.AddSquarePass(layer4, L4CarryE, L3CarryE, FinalCarryCount);

        var layer5 = new List<GkrLayerTerm>();
        AddCompressor(layer5, L5SumA5, L5CarryA5, L4SumA4, L4CarryA4, L4Majority);
        GkrShaRoundSupport.AddSquarePass(layer5, L5SumE4, L4SumE4, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer5, L5CarryE4, L4CarryE4, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer5, L5NewA, L4NewA, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer5, L5NewE, L4NewE, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer5, L5CarryA, L4CarryA, FinalCarryCount);
        GkrShaRoundSupport.AddSquarePass(layer5, L5CarryE, L4CarryE, FinalCarryCount);

        var output = new List<GkrLayerTerm>();
        AddFinalAdderChecks(output, OutSumA, OutCarryA, L5SumA5, L5CarryA5, L5NewA, L5CarryA);
        AddFinalAdderChecks(output, OutSumE, OutCarryE, L5SumE4, L5CarryE4, L5NewE, L5CarryE);

        return new GkrCircuit(
            [
                new GkrLayer([.. output], RoundOutputCount),
                new GkrLayer([.. layer5], Layer5Width),
                new GkrLayer([.. layer4], Layer4Width),
                new GkrLayer([.. layer3], Layer3Width),
                new GkrLayer([.. layer2], Layer2Width),
                new GkrLayer([.. layer1], Layer1Width),
            ],
            RoundInputCount);
    }


    //The schedule recurrence check: four layers, every expected output zero.
    public static GkrCircuit BuildScheduleCircuit()
    {
        var layer1 = new List<GkrLayerTerm>();
        for(int i = 0; i < WordBits; i++)
        {
            if(i + 10 < WordBits)
            {
                AddParity(layer1, S1SmallSigma1 + i, Predecessor2Wire + ((i + 17) & 31), Predecessor2Wire + ((i + 19) & 31), Predecessor2Wire + i + 10);
            }
            else
            {
                AddParity(layer1, S1SmallSigma1 + i, Predecessor2Wire + ((i + 17) & 31), Predecessor2Wire + ((i + 19) & 31));
            }

            if(i + 3 < WordBits)
            {
                AddParity(layer1, S1SmallSigma0 + i, Predecessor15Wire + ((i + 7) & 31), Predecessor15Wire + ((i + 18) & 31), Predecessor15Wire + i + 3);
            }
            else
            {
                AddParity(layer1, S1SmallSigma0 + i, Predecessor15Wire + ((i + 7) & 31), Predecessor15Wire + ((i + 18) & 31));
            }
        }

        GkrShaRoundSupport.AddSquarePass(layer1, S1P7, Predecessor7Wire, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer1, S1P16, Predecessor16Wire, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer1, S1Word, ScheduleWordWire, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer1, S1Carry, ScheduleCarryWire, FinalCarryCount);

        var layer2 = new List<GkrLayerTerm>();
        AddCompressor(layer2, S2Sum, S2Carry, S1SmallSigma1, S1P7, S1SmallSigma0);
        GkrShaRoundSupport.AddSquarePass(layer2, S2P16, S1P16, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer2, S2Word, S1Word, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer2, S2CarryPass, S1Carry, FinalCarryCount);

        var layer3 = new List<GkrLayerTerm>();
        AddCompressor(layer3, S3Sum, S3Carry, S2Sum, S2Carry, S2P16);
        GkrShaRoundSupport.AddSquarePass(layer3, S3Word, S2Word, WordBits);
        GkrShaRoundSupport.AddSquarePass(layer3, S3CarryPass, S2CarryPass, FinalCarryCount);

        var output = new List<GkrLayerTerm>();
        AddFinalAdderChecks(output, 0, WordBits, S3Sum, S3Carry, S3Word, S3CarryPass);

        return new GkrCircuit(
            [
                new GkrLayer([.. output], ScheduleOutputCount),
                new GkrLayer([.. layer3], ScheduleLayer3Width),
                new GkrLayer([.. layer2], ScheduleLayer2Width),
                new GkrLayer([.. layer1], ScheduleLayer1Width),
            ],
            ScheduleInputCount);
    }


    //The chaining addition: one layer of full-adder checks, left + right = sum.
    public static GkrCircuit BuildAdditionCircuit()
    {
        var terms = new List<GkrLayerTerm>();
        AddFinalAdderChecks(terms, 0, WordBits, AdditionLeftWire, AdditionRightWire, AdditionSumWire, AdditionCarryWire);

        return new GkrCircuit([new GkrLayer([.. terms], AdditionOutputCount)], AdditionInputCount);
    }


    //One round copy: the boundary state, the schedule word, the pinned round constant, the
    //round outcomes and the final-add carries of both compressor trees.
    public static void PackRoundBlock(Span<byte> destination, uint[][] trace, uint[] schedule)
    {
        for(int r = 0; r < RoundCount; r++)
        {
            Span<byte> copy = destination.Slice(r * RoundInputCount * ScalarSize, RoundInputCount * ScalarSize);
            uint a = trace[r][0], b = trace[r][1], c = trace[r][2], d = trace[r][3];
            uint e = trace[r][4], f = trace[r][5], g = trace[r][6], h = trace[r][7];
            uint k = GkrShaRoundSupport.RoundConstants[r];
            uint w = schedule[r];
            uint sigma1 = GkrShaRoundSupport.Sigma1(e);
            uint sigma0 = GkrShaRoundSupport.Sigma0(a);
            uint choose = GkrShaRoundSupport.Ch(e, f, g);
            uint majority = GkrShaRoundSupport.Maj(a, b, c);

            GkrShaRoundSupport.WriteWord(copy, AWire, a);
            GkrShaRoundSupport.WriteWord(copy, BWire, b);
            GkrShaRoundSupport.WriteWord(copy, CWire, c);
            GkrShaRoundSupport.WriteWord(copy, DWire, d);
            GkrShaRoundSupport.WriteWord(copy, EWire, e);
            GkrShaRoundSupport.WriteWord(copy, FWire, f);
            GkrShaRoundSupport.WriteWord(copy, GWire, g);
            GkrShaRoundSupport.WriteWord(copy, HWire, h);
            GkrShaRoundSupport.WriteWord(copy, WWire, w);
            GkrShaRoundSupport.WriteWord(copy, KWire, k);
            GkrShaRoundSupport.WriteWord(copy, NewAWire, trace[r + 1][0]);
            GkrShaRoundSupport.WriteWord(copy, NewEWire, trace[r + 1][4]);

            //The compressor trees in the exact circuit order.
            (uint s1, uint c1) = Csa(h, sigma1, choose);
            (uint s2, uint c2) = Csa(w, k, sigma0);
            (uint s3, uint c3) = Csa(s1, c1, s2);
            (uint s4, uint c4) = Csa(s3, c3, c2);
            (uint s5, uint c5) = Csa(s4, c4, majority);
            WriteFinalCarries(copy, CarryAWire, s5, c5, trace[r + 1][0]);

            (uint t1, uint u1) = Csa(d, h, sigma1);
            (uint t2, uint u2) = Csa(choose, w, k);
            (uint t3, uint u3) = Csa(t1, u1, t2);
            (uint t4, uint u4) = Csa(t3, u3, u2);
            WriteFinalCarries(copy, CarryEWire, t4, u4, trace[r + 1][4]);
        }
    }


    //One schedule copy block: the recurrence with virtual predecessors, every column zero.
    public static void PackScheduleBlock(Span<byte> destination, uint[] schedule, uint[] virtualWords)
    {
        for(int r = 0; r < RoundCount; r++)
        {
            Span<byte> copy = destination.Slice(r * ScheduleInputCount * ScalarSize, ScheduleInputCount * ScalarSize);
            uint p2 = GkrShaRoundSupport.ScheduleAt(schedule, virtualWords, r - 2);
            uint p7 = GkrShaRoundSupport.ScheduleAt(schedule, virtualWords, r - 7);
            uint p15 = GkrShaRoundSupport.ScheduleAt(schedule, virtualWords, r - 15);
            uint p16 = GkrShaRoundSupport.ScheduleAt(schedule, virtualWords, r - 16);

            GkrShaRoundSupport.WriteWord(copy, ScheduleWordWire, schedule[r]);
            GkrShaRoundSupport.WriteWord(copy, Predecessor2Wire, p2);
            GkrShaRoundSupport.WriteWord(copy, Predecessor7Wire, p7);
            GkrShaRoundSupport.WriteWord(copy, Predecessor15Wire, p15);
            GkrShaRoundSupport.WriteWord(copy, Predecessor16Wire, p16);

            (uint s1, uint c1) = Csa(GkrShaRoundSupport.SmallSigma1(p2), p7, GkrShaRoundSupport.SmallSigma0(p15));
            (uint s2, uint c2) = Csa(s1, c1, p16);
            WriteFinalCarries(copy, ScheduleCarryWire, s2, c2, schedule[r]);
        }
    }


    //One block of chaining-addition copies: left + right = sum per state word.
    public static void PackAdditionBlock(Span<byte> destination, uint[] left, uint[] right, uint[] sum)
    {
        for(int w = 0; w < AdditionCopiesPerBlock; w++)
        {
            Span<byte> copy = destination.Slice(w * AdditionInputCount * ScalarSize, AdditionInputCount * ScalarSize);
            GkrShaRoundSupport.WriteWord(copy, AdditionLeftWire, left[w]);
            GkrShaRoundSupport.WriteWord(copy, AdditionRightWire, right[w]);
            GkrShaRoundSupport.WriteWord(copy, AdditionSumWire, sum[w]);
            WriteFinalCarries(copy, AdditionCarryWire, left[w], right[w], sum[w]);
        }
    }


    //The 3→2 compressor: x + y + z = s + c with s = x ⊕ y ⊕ z and c the majority shifted left
    //one — the uint mirror of the in-circuit compressor, truncation included.
    public static (uint Sum, uint Carry) Csa(uint x, uint y, uint z) =>
        (x ^ y ^ z, ((x & y) | (x & z) | (y & z)) << 1);


    //The ripple carries of the final two-operand add p + q = sum: carry k+1 is the majority of
    //bit k. The packer asserts the addition actually closes — a packing bug fails here, not in
    //a proof.
    private static void WriteFinalCarries(Span<byte> copy, int wireBase, uint p, uint q, uint sum)
    {
        uint carry = 0;
        for(int k = 0; k < FinalCarryCount; k++)
        {
            uint pBit = (p >> k) & 1;
            uint qBit = (q >> k) & 1;
            carry = (pBit & qBit) | (pBit & carry) | (qBit & carry);
            copy[(((wireBase + k) * ScalarSize) + ScalarSize) - 1] = (byte)carry;
        }

        if(p + q != sum)
        {
            throw new InvalidOperationException("The compressor outputs do not add to the claimed word.");
        }
    }


    //out = x ⊕ y (⊕ z): one square term per tap.
    private static void AddParity(List<GkrLayerTerm> terms, int output, params int[] taps)
    {
        foreach(int tap in taps)
        {
            terms.Add(new GkrLayerTerm(output, tap, tap, One));
        }
    }


    //out = Maj(x, y, z) = xy + xz + yz.
    private static void AddMajority(List<GkrLayerTerm> terms, int output, int x, int y, int z)
    {
        terms.Add(new GkrLayerTerm(output, x, y, One));
        terms.Add(new GkrLayerTerm(output, x, z, One));
        terms.Add(new GkrLayerTerm(output, y, z, One));
    }


    //One compressor stage over three 32-bit words: the sum word is the per-bit parity, the
    //carry word is the per-bit majority shifted left one (carry wire zero has no terms; the
    //majority of bit 31 is dropped — the mod-2³² truncation).
    private static void AddCompressor(List<GkrLayerTerm> terms, int sumBase, int carryBase, int xBase, int yBase, int zBase)
    {
        for(int i = 0; i < WordBits; i++)
        {
            AddParity(terms, sumBase + i, xBase + i, yBase + i, zBase + i);
        }

        for(int i = 0; i + 1 < WordBits; i++)
        {
            AddMajority(terms, carryBase + i + 1, xBase + i, yBase + i, zBase + i);
        }
    }


    //The full-adder checks of the final two-operand add p + q = target with witnessed carries:
    //sum check i is target_i + p_i + q_i + carry_i (the carry absent at bit zero), carry check
    //k is carry_{k+1} + Maj(p_k, q_k, carry_k) (the carry products absent at k = 0) — all
    //public-must-be-zero, addition and subtraction being the same map.
    private static void AddFinalAdderChecks(List<GkrLayerTerm> terms, int sumCheckBase, int carryCheckBase, int pBase, int qBase, int targetBase, int carryBase)
    {
        for(int i = 0; i < WordBits; i++)
        {
            AddParity(terms, sumCheckBase + i, targetBase + i, pBase + i, qBase + i);
            if(i > 0)
            {
                AddParity(terms, sumCheckBase + i, carryBase + i - 1);
            }
        }

        for(int k = 0; k < FinalCarryCount; k++)
        {
            int output = carryCheckBase + k;
            AddParity(terms, output, carryBase + k);
            terms.Add(new GkrLayerTerm(output, pBase + k, qBase + k, One));
            if(k > 0)
            {
                terms.Add(new GkrLayerTerm(output, pBase + k, carryBase + k - 1, One));
                terms.Add(new GkrLayerTerm(output, qBase + k, carryBase + k - 1, One));
            }
        }
    }
}

using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Hashing;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Gkr;

/// <summary>
/// The Fp256 half of the cross-field MAC as pure Ligero statement work, shared by the MAC
/// protocol test and the mdoc digest end-to-end: the committed carry-less products and parity
/// masks, the 0x87 fold map, the per-mac-bit parity constraints with post-challenge public
/// coefficients, and the masked-quotient publication. Also the deterministic randomness sources
/// for both fields' tableau masking.
/// </summary>
internal static class GkrCrossFieldMacSupport
{
    public const int ScalarSize = 32;
    public const int HalfBits = GkrGf2kMacSupport.HalfBits;
    public const int Halves = GkrGf2kMacSupport.CopyCount;
    public const int MaskBits = 32;
    public const int PositionCount = (2 * HalfBits) - 1;

    //The Fp-side witness layout: message bits, key-share bits, the carry-less products, the
    //parity masks.
    public const int MessageBase = 0;
    public const int KeyShareBase = Halves * HalfBits;
    public const int ProductBase = KeyShareBase + (Halves * HalfBits);
    public const int MaskBase = ProductBase + (Halves * HalfBits * HalfBits);
    public const int FpWitnessCount = MaskBase + (Halves * HalfBits * MaskBits);
    public const int FpWitnessBytes = FpWitnessCount * ScalarSize;

    //foldMap[s] = the final bit positions (with multiplicity) that x^s lands on modulo
    //x^128 + x^7 + x^2 + x + 1. Multiplicity-2 entries cancel over GF(2) but contribute an even
    //amount to the integer T, leaving the parity untouched either way.
    public static int[][] FoldMap { get; } = BuildFoldMap();


    //One parity constraint per mac bit: Σ key-message terms + Σ 2^{l+1}·mask_l = mac_j + 2·V_j,
    //where key_k·m_i is q (a_v,k = 0) or m − q (a_v,k = 1) and the coefficients carry the fold
    //multiplicities. All quantities are bitness-bounded far below p — an integer equation.
    public static (LigeroLinearConstraint[] Constraints, byte[] Targets) BuildParityStatement(ReadOnlySpan<byte> verifierKey, ReadOnlySpan<byte> macs, ulong[] maskedQuotients)
    {
        var coefficientCache = new Dictionary<long, byte[]>();
        var terms = new List<LigeroLinearConstraint>();
        var targets = new List<byte>();

        for(int h = 0; h < Halves; h++)
        {
            //coefficients[j] maps witness index → signed multiplicity for mac bit j.
            var coefficients = new Dictionary<int, int>[HalfBits];
            for(int j = 0; j < HalfBits; j++)
            {
                coefficients[j] = [];
            }

            for(int k = 0; k < HalfBits; k++)
            {
                bool keyFlips = ElementBit(verifierKey, k) == 1;
                for(int i = 0; i < HalfBits; i++)
                {
                    int product = ProductIndex(h, k, i);
                    int message = MessageIndex(h, i);
                    foreach(int position in FoldMap[i + k])
                    {
                        Dictionary<int, int> row = coefficients[position];
                        if(keyFlips)
                        {
                            row[message] = row.GetValueOrDefault(message) + 1;
                            row[product] = row.GetValueOrDefault(product) - 1;
                        }
                        else
                        {
                            row[product] = row.GetValueOrDefault(product) + 1;
                        }
                    }
                }
            }

            for(int j = 0; j < HalfBits; j++)
            {
                int constraint = (h * HalfBits) + j;
                foreach((int wire, int coefficient) in coefficients[j])
                {
                    if(coefficient != 0)
                    {
                        terms.Add(new LigeroLinearConstraint(constraint, wire, Coefficient(coefficientCache, coefficient)));
                    }
                }

                for(int l = 0; l < MaskBits; l++)
                {
                    terms.Add(new LigeroLinearConstraint(constraint, MaskIndex(h, j, l), Coefficient(coefficientCache, 2L << l)));
                }

                int macBit = ElementBit(macs.Slice(h * ScalarSize, ScalarSize), j);
                BigInteger target = macBit + (2 * new BigInteger(maskedQuotients[constraint]));
                targets.AddRange(GkrTestSupport.Canonical(target));
            }
        }

        return ([.. terms], [.. targets]);
    }


    //V_j = (T_j − mac_j)/2 + R_j with R_j the committed mask value. An odd difference means the
    //committed message cannot meet the mac — the truncated quotient then leaves the constraint
    //unsatisfied, which is the point.
    public static void ComputeMaskedQuotients(ReadOnlySpan<byte> fpWitness, ReadOnlySpan<byte> verifierKey, ReadOnlySpan<byte> macs, ulong[] maskedQuotients)
    {
        for(int h = 0; h < Halves; h++)
        {
            long[] integers = IntegerColumnSumsFromWitness(fpWitness, h, verifierKey);
            for(int j = 0; j < HalfBits; j++)
            {
                int macBit = ElementBit(macs.Slice(h * ScalarSize, ScalarSize), j);
                long quotient = (integers[j] - macBit) >> 1;

                ulong mask = 0;
                for(int l = 0; l < MaskBits; l++)
                {
                    if(fpWitness[(MaskIndex(h, j, l) * ScalarSize) + ScalarSize - 1] != 0)
                    {
                        mask |= 1UL << l;
                    }
                }

                maskedQuotients[(h * HalfBits) + j] = (ulong)quotient + mask;
            }
        }
    }


    //The integer column sums read from the packed Fp witness — what the constraints see.
    public static long[] IntegerColumnSumsFromWitness(ReadOnlySpan<byte> fpWitness, int half, ReadOnlySpan<byte> verifierKey)
    {
        long[] sums = new long[HalfBits];
        for(int k = 0; k < HalfBits; k++)
        {
            bool keyFlips = ElementBit(verifierKey, k) == 1;
            for(int i = 0; i < HalfBits; i++)
            {
                int product = fpWitness[(ProductIndex(half, k, i) * ScalarSize) + ScalarSize - 1];
                int message = fpWitness[(MessageIndex(half, i) * ScalarSize) + ScalarSize - 1];
                int value = keyFlips ? message - product : product;
                if(value == 0)
                {
                    continue;
                }

                foreach(int position in FoldMap[i + k])
                {
                    sums[position] += value;
                }
            }
        }

        return sums;
    }


    //Message bits, key-share bits, their products, and pseudo-random parity masks.
    public static void PackFpWitness(Span<byte> witness, ReadOnlySpan<byte> value, byte[][] keyShares, ReadOnlySpan<byte> maskSeed)
    {
        witness.Clear();
        Span<byte> digest = stackalloc byte[32];
        Span<byte> seedInput = stackalloc byte[maskSeed.Length + (2 * sizeof(int))];
        for(int h = 0; h < Halves; h++)
        {
            for(int i = 0; i < HalfBits; i++)
            {
                witness[(MessageIndex(h, i) * ScalarSize) + ScalarSize - 1] = (byte)GkrGf2kMacSupport.HalfBit(value, h, i);
            }

            for(int k = 0; k < HalfBits; k++)
            {
                witness[(KeyShareIndex(h, k) * ScalarSize) + ScalarSize - 1] = (byte)ElementBit(keyShares[h], k);
            }

            for(int k = 0; k < HalfBits; k++)
            {
                int keyBit = ElementBit(keyShares[h], k);
                for(int i = 0; i < HalfBits; i++)
                {
                    int bit = keyBit & GkrGf2kMacSupport.HalfBit(value, h, i);
                    witness[(ProductIndex(h, k, i) * ScalarSize) + ScalarSize - 1] = (byte)bit;
                }
            }

            for(int j = 0; j < HalfBits; j++)
            {
                maskSeed.CopyTo(seedInput);
                BinaryPrimitives.WriteInt32BigEndian(seedInput[maskSeed.Length..], h);
                BinaryPrimitives.WriteInt32BigEndian(seedInput[(maskSeed.Length + sizeof(int))..], j);
                Blake3.Hash(seedInput, digest);
                for(int l = 0; l < MaskBits; l++)
                {
                    witness[(MaskIndex(h, j, l) * ScalarSize) + ScalarSize - 1] = (byte)((digest[l >> 3] >> (l & 7)) & 1);
                }
            }
        }
    }


    //The products as quadratic triples, plus bitness for the messages, key shares and masks.
    public static LigeroQuadraticConstraint[] BuildFpQuadratics()
    {
        var quadratics = new List<LigeroQuadraticConstraint>();
        for(int h = 0; h < Halves; h++)
        {
            for(int k = 0; k < HalfBits; k++)
            {
                for(int i = 0; i < HalfBits; i++)
                {
                    quadratics.Add(new LigeroQuadraticConstraint(KeyShareIndex(h, k), MessageIndex(h, i), ProductIndex(h, k, i)));
                }
            }

            for(int i = 0; i < HalfBits; i++)
            {
                int message = MessageIndex(h, i);
                quadratics.Add(new LigeroQuadraticConstraint(message, message, message));
                int keyShare = KeyShareIndex(h, i);
                quadratics.Add(new LigeroQuadraticConstraint(keyShare, keyShare, keyShare));
            }

            for(int j = 0; j < HalfBits; j++)
            {
                for(int l = 0; l < MaskBits; l++)
                {
                    int mask = MaskIndex(h, j, l);
                    quadratics.Add(new LigeroQuadraticConstraint(mask, mask, mask));
                }
            }
        }

        return [.. quadratics];
    }


    //Bit k of a canonical 32-byte element's low 128 bits.
    public static int ElementBit(ReadOnlySpan<byte> element, int bit) =>
        (element[(ScalarSize - 1) - (bit >> 3)] >> (bit & 7)) & 1;


    public static int MessageIndex(int half, int bit) => MessageBase + (half * HalfBits) + bit;

    public static int KeyShareIndex(int half, int bit) => KeyShareBase + (half * HalfBits) + bit;

    public static int ProductIndex(int half, int keyBit, int messageBit) => ProductBase + (half * HalfBits * HalfBits) + (keyBit * HalfBits) + messageBit;

    public static int MaskIndex(int half, int macBit, int maskBit) => MaskBase + (half * HalfBits * MaskBits) + (macBit * MaskBits) + maskBit;


    public static byte[] Element(ulong high, ulong low)
    {
        byte[] bytes = new byte[ScalarSize];
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(16, 8), high);
        BinaryPrimitives.WriteUInt64BigEndian(bytes.AsSpan(24, 8), low);

        return bytes;
    }


    private static int[][] BuildFoldMap()
    {
        var map = new int[PositionCount][];
        for(int s = 0; s < PositionCount; s++)
        {
            var positions = new List<int>();
            Expand(s, positions);
            map[s] = [.. positions];
        }

        return map;

        static void Expand(int s, List<int> positions)
        {
            if(s < HalfBits)
            {
                positions.Add(s);

                return;
            }

            int reduced = s - HalfBits;
            Expand(reduced, positions);
            Expand(reduced + 1, positions);
            Expand(reduced + 2, positions);
            Expand(reduced + 7, positions);
        }
    }


    private static byte[] Coefficient(Dictionary<long, byte[]> cache, long value)
    {
        if(!cache.TryGetValue(value, out byte[]? bytes))
        {
            bytes = value >= 0 ? GkrTestSupport.Canonical(value) : GkrTestSupport.Canonical(GkrTestSupport.P + value);
            cache[value] = bytes;
        }

        return bytes;
    }


    //A reproducible Fp256 randomness source (BLAKE3 of seed‖counter mod p).
    internal sealed class FpDeterministicRandom
    {
        private byte[] Seed { get; }

        private int Counter { get; set; }

        public FpDeterministicRandom(ReadOnlySpan<byte> seed) => Seed = seed.ToArray();

        public ScalarRandomDelegate AsDelegate() => Fill;

        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[Seed.Length + sizeof(int)];
            Seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[Seed.Length..], Counter);
            Counter++;

            Span<byte> wide = stackalloc byte[64];
            Blake3.Hash(input, wide);
            BigInteger reduced = new BigInteger(wide, isUnsigned: true, isBigEndian: true) % GkrTestSupport.P;
            destination.Clear();
            Span<byte> little = stackalloc byte[ScalarSize + 1];
            if(reduced.TryWriteBytes(little, out int written, isUnsigned: true, isBigEndian: false))
            {
                for(int i = 0; i < written && i < ScalarSize; i++)
                {
                    destination[ScalarSize - 1 - i] = little[i];
                }
            }

            return inboundTag;
        }
    }


    //A reproducible GF(2^128) randomness source (BLAKE3 of seed‖counter, low 128 bits).
    internal sealed class GfDeterministicRandom
    {
        private byte[] Seed { get; }

        private int Counter { get; set; }

        public GfDeterministicRandom(ReadOnlySpan<byte> seed) => Seed = seed.ToArray();

        public ScalarRandomDelegate AsDelegate() => Fill;

        private Tag Fill(Span<byte> destination, CurveParameterSet curve, Tag inboundTag)
        {
            Span<byte> input = stackalloc byte[Seed.Length + sizeof(int)];
            Seed.CopyTo(input);
            BinaryPrimitives.WriteInt32BigEndian(input[Seed.Length..], Counter);
            Counter++;

            Span<byte> digest = stackalloc byte[32];
            Blake3.Hash(input, digest);
            destination.Clear();
            digest[..16].CopyTo(destination[16..]);

            return inboundTag;
        }
    }
}

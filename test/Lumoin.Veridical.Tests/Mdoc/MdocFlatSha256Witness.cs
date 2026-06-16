using System;

namespace Lumoin.Veridical.Tests.Mdoc;

/// <summary>
/// The SHA-256 block-witness producer, a faithful port of google/longfellow-zk's
/// <c>FlatSHA256Witness</c> (<c>lib/circuits/sha/flatsha256_witness.cc</c>). For each padded 64-byte block
/// it records the 48 message-schedule words <c>outw</c>, the 64 working-variable words <c>oute</c> and
/// <c>outa</c>, and the eight chaining words <c>h1</c> — exactly the per-block intermediate values the
/// GF(2^128) hash circuit's witness column carries (plucked four bits at a time).
/// </summary>
internal static class MdocFlatSha256Witness
{
    private const int BlockBytes = 64;
    private const uint Mask = 0xffffffff;

    private static readonly uint[] RoundConstants =
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

    private static readonly uint[] InitialHash =
    [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];


    /// <summary>One block's witness: the message schedule, the per-round working variables and the chaining words.</summary>
    internal sealed class BlockWitness
    {
        public uint[] OutW { get; } = new uint[48];

        public uint[] OutE { get; } = new uint[64];

        public uint[] OutA { get; } = new uint[64];

        public uint[] H1 { get; } = new uint[8];
    }


    /// <summary>
    /// Pads <paramref name="message"/> to <paramref name="maxBlocks"/> blocks, computes every block witness,
    /// and returns the padded input bytes plus the number of blocks that hold the genuine hash.
    /// </summary>
    public static (byte[] PaddedInput, byte NumBlocks, BlockWitness[] Blocks) TransformAndWitnessMessage(ReadOnlySpan<byte> message, int maxBlocks)
    {
        int n = message.Length;
        byte numBlocks = (byte)((n + 9 + BlockBytes - 1) / BlockBytes);

        byte[] input = new byte[BlockBytes * maxBlocks];
        int ii = 0;
        for(int i = 0; i < n; i++, ii++)
        {
            input[ii] = message[i];
        }

        input[ii++] = 0x80;
        if((ii % BlockBytes) == 0 || (ii % BlockBytes) > 56)
        {
            while(ii % BlockBytes != 0)
            {
                input[ii++] = 0;
            }
        }

        while((ii % BlockBytes) < 56)
        {
            input[ii++] = 0;
        }

        ulong bitLength = (ulong)n * 8;
        for(int i = 0; i < 8; i++)
        {
            input[ii + 7 - i] = (byte)((bitLength >> (8 * i)) & 0xff);
        }

        var blocks = new BlockWitness[maxBlocks];
        uint[] hash = (uint[])InitialHash.Clone();
        for(int bl = 0; bl < maxBlocks; bl++)
        {
            uint[] data = new uint[16];
            for(int i = 0; i < 16; i++)
            {
                int offset = bl * BlockBytes + i * 4;
                data[i] = ((uint)input[offset] << 24) | ((uint)input[offset + 1] << 16) | ((uint)input[offset + 2] << 8) | input[offset + 3];
            }

            var block = new BlockWitness();
            TransformAndWitnessBlock(data, hash, block);
            blocks[bl] = block;
            hash = block.H1;
        }

        return (input, numBlocks, blocks);
    }


    private static void TransformAndWitnessBlock(uint[] data, uint[] h0, BlockWitness block)
    {
        uint[] w = new uint[64];
        for(int i = 0; i < 16; i++)
        {
            w[i] = data[i];
        }

        for(int i = 16; i < 64; i++)
        {
            w[i] = (Sigma0Small(w[i - 15]) + w[i - 7] + Sigma1Small(w[i - 2]) + w[i - 16]) & Mask;
            block.OutW[i - 16] = w[i];
        }

        uint a = h0[0];
        uint b = h0[1];
        uint c = h0[2];
        uint d = h0[3];
        uint e = h0[4];
        uint f = h0[5];
        uint g = h0[6];
        uint h = h0[7];

        for(int t = 0; t < 64; t++)
        {
            uint t1 = (h + Sigma1Big(e) + Ch(e, f, g) + RoundConstants[t] + w[t]) & Mask;
            uint t2 = (Sigma0Big(a) + Maj(a, b, c)) & Mask;
            h = g;
            g = f;
            f = e;
            e = (d + t1) & Mask;
            block.OutE[t] = e;
            d = c;
            c = b;
            b = a;
            a = (t1 + t2) & Mask;
            block.OutA[t] = a;
        }

        block.H1[0] = (h0[0] + a) & Mask;
        block.H1[1] = (h0[1] + b) & Mask;
        block.H1[2] = (h0[2] + c) & Mask;
        block.H1[3] = (h0[3] + d) & Mask;
        block.H1[4] = (h0[4] + e) & Mask;
        block.H1[5] = (h0[5] + f) & Mask;
        block.H1[6] = (h0[6] + g) & Mask;
        block.H1[7] = (h0[7] + h) & Mask;
    }


    private static uint RotateRight(uint x, int bits) => (x >> bits) | (x << (32 - bits));

    private static uint Ch(uint x, uint y, uint z) => (x & y) ^ (~x & z);

    private static uint Maj(uint x, uint y, uint z) => (x & y) ^ (x & z) ^ (y & z);

    private static uint Sigma0Big(uint x) => RotateRight(x, 2) ^ RotateRight(x, 13) ^ RotateRight(x, 22);

    private static uint Sigma1Big(uint x) => RotateRight(x, 6) ^ RotateRight(x, 11) ^ RotateRight(x, 25);

    private static uint Sigma0Small(uint x) => RotateRight(x, 7) ^ RotateRight(x, 18) ^ (x >> 3);

    private static uint Sigma1Small(uint x) => RotateRight(x, 17) ^ RotateRight(x, 19) ^ (x >> 10);
}

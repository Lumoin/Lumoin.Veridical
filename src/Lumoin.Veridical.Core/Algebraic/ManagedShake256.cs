using System;
using System.Buffers.Binary;
using System.Numerics;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// A self-contained, managed SHAKE-256 extendable-output function
/// (FIPS 202) built on the Keccak-<c>f</c>[1600] permutation.
/// </summary>
/// <remarks>
/// <para>
/// The .NET <see cref="System.Security.Cryptography.Shake256"/> wrapper is
/// only available where the host platform's native cryptography provider
/// exposes SHA-3 — that is true on Linux (OpenSSL ≥ 1.1.1) and recent
/// Windows, but <b>not on macOS</b>, where
/// <see cref="System.Security.Cryptography.Shake256.IsSupported"/> is
/// <see langword="false"/> and the constructor throws
/// <see cref="PlatformNotSupportedException"/>. The
/// <c>BLS12-381-SHAKE-256</c> BBS ciphersuite needs SHAKE-256 on every
/// target, so the library carries its own implementation — the same posture
/// it already takes for BLAKE3.
/// </para>
/// <para>
/// This is a scalar reference implementation: correctness-first, no SIMD.
/// It is selected only as the fallback when the OS XOF is unavailable (see
/// <see cref="Rfc9380ExpandMessage.ExpandMessageXofShake256"/>); a future
/// batch can add accelerated backends behind the same call site, exactly as
/// the BLAKE3 backends are selected. Byte-identity with the OS XOF is gated
/// by an agreement test on hosts where both exist, and by the published
/// IETF BBS SHAKE-256 vectors on hosts where only this path runs.
/// </para>
/// </remarks>
public static class ManagedShake256
{
    //SHAKE-256 sponge rate r = 1600 - c, with capacity c = 512 bits.
    //(1600 - 512) / 8 = 136 absorbed/squeezed bytes per permutation.
    private const int RateBytes = 136;

    //The Keccak state is 1600 bits = 25 lanes of 64 bits.
    private const int LaneCount = 25;

    //Lanes touched by one rate block (RateBytes / 8).
    private const int RateLanes = RateBytes / 8;

    //Number of Keccak-f permutation rounds for width 1600.
    private const int RoundCount = 24;

    //SHAKE domain-separation suffix (bits 1111) merged with the first
    //pad10*1 bit, packed little-endian into a single byte: 0x1F.
    private const byte DomainSuffix = 0x1F;

    //Final pad10*1 bit set in the last byte of the rate block.
    private const byte FinalPadBit = 0x80;

    private static readonly ulong[] RoundConstants =
    [
        0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
        0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
        0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
        0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
    ];

    //Rho rotation offsets indexed by lane i = x + 5*y (FIPS 202 Table 2).
    private static ReadOnlySpan<byte> RhoOffsets =>
    [
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14
    ];


    /// <summary>
    /// Computes SHAKE-256 over <paramref name="input"/>, writing exactly
    /// <paramref name="output"/>.Length squeezed bytes into
    /// <paramref name="output"/>.
    /// </summary>
    /// <param name="input">The message to absorb.</param>
    /// <param name="output">The destination for the squeezed XOF stream; its length sets the output length.</param>
    public static void HashData(ReadOnlySpan<byte> input, Span<byte> output)
    {
        Span<ulong> state = stackalloc ulong[LaneCount];
        state.Clear();

        //Absorb every full rate block, permuting after each.
        int offset = 0;
        while(input.Length - offset >= RateBytes)
        {
            AbsorbBlock(state, input.Slice(offset, RateBytes));
            KeccakF(state);
            offset += RateBytes;
        }

        //Final (short) block: copy the tail, then apply pad10*1 with the
        //SHAKE domain suffix. XOR (not assignment) handles the corner case
        //where the suffix and the final pad bit land in the same byte.
        Span<byte> finalBlock = stackalloc byte[RateBytes];
        finalBlock.Clear();
        int remaining = input.Length - offset;
        input[offset..].CopyTo(finalBlock);
        finalBlock[remaining] ^= DomainSuffix;
        finalBlock[RateBytes - 1] ^= FinalPadBit;
        AbsorbBlock(state, finalBlock);
        KeccakF(state);

        //Squeeze, permuting between rate blocks.
        Span<byte> rateBytes = stackalloc byte[RateBytes];
        int produced = 0;
        while(produced < output.Length)
        {
            ExtractRate(state, rateBytes);
            int take = Math.Min(RateBytes, output.Length - produced);
            rateBytes[..take].CopyTo(output[produced..]);
            produced += take;
            if(produced < output.Length)
            {
                KeccakF(state);
            }
        }
    }


    //XORs one rate block (little-endian lanes) into the sponge state.
    private static void AbsorbBlock(Span<ulong> state, ReadOnlySpan<byte> block)
    {
        for(int lane = 0; lane < RateLanes; lane++)
        {
            state[lane] ^= BinaryPrimitives.ReadUInt64LittleEndian(block[(lane * sizeof(ulong))..]);
        }
    }


    //Serialises the rate portion of the state to little-endian bytes.
    private static void ExtractRate(ReadOnlySpan<ulong> state, Span<byte> rateBytes)
    {
        for(int lane = 0; lane < RateLanes; lane++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(rateBytes[(lane * sizeof(ulong))..], state[lane]);
        }
    }


    //One Keccak-f[1600] permutation: theta, rho+pi, chi, iota per round.
    private static void KeccakF(Span<ulong> a)
    {
        ReadOnlySpan<byte> rho = RhoOffsets;
        Span<ulong> c = stackalloc ulong[5];
        Span<ulong> d = stackalloc ulong[5];
        Span<ulong> b = stackalloc ulong[LaneCount];

        for(int round = 0; round < RoundCount; round++)
        {
            //Theta.
            for(int x = 0; x < 5; x++)
            {
                c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }

            for(int x = 0; x < 5; x++)
            {
                d[x] = c[(x + 4) % 5] ^ BitOperations.RotateLeft(c[(x + 1) % 5], 1);
            }

            for(int x = 0; x < 5; x++)
            {
                for(int y = 0; y < 5; y++)
                {
                    a[x + (5 * y)] ^= d[x];
                }
            }

            //Rho (per-lane rotation) composed with Pi (lane permutation).
            for(int x = 0; x < 5; x++)
            {
                for(int y = 0; y < 5; y++)
                {
                    int source = x + (5 * y);
                    int destination = y + (5 * (((2 * x) + (3 * y)) % 5));
                    b[destination] = BitOperations.RotateLeft(a[source], rho[source]);
                }
            }

            //Chi.
            for(int y = 0; y < 5; y++)
            {
                for(int x = 0; x < 5; x++)
                {
                    a[x + (5 * y)] = b[x + (5 * y)] ^ (~b[((x + 1) % 5) + (5 * y)] & b[((x + 2) % 5) + (5 * y)]);
                }
            }

            //Iota.
            a[0] ^= RoundConstants[round];
        }
    }
}

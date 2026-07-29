using System;
using System.Collections.Generic;
using System.Numerics;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// One permutation's host-side witness, a faithful port of the reference's
/// <c>Sha3Witness::BlockWitness</c>: the state after every round — the circuit and the filler
/// consume only the sliced rounds, but recording all of them keeps the generator independent of
/// the slicing parameters.
/// </summary>
internal sealed class LongfellowSha3BlockWitness
{
    /// <summary>The lane grid's side length.</summary>
    private const int GridSize = 5;

    /// <summary>The recorded states: <c>[round][x][y]</c>.</summary>
    public ulong[][][] AIntermediate { get; }


    /// <summary>Constructs the witness with zeroed states.</summary>
    public LongfellowSha3BlockWitness()
    {
        AIntermediate = new ulong[LongfellowSha3Constants.RoundCount][][];
        for(int round = 0; round < LongfellowSha3Constants.RoundCount; round++)
        {
            AIntermediate[round] = new ulong[GridSize][];
            for(int x = 0; x < GridSize; x++)
            {
                AIntermediate[round][x] = new ulong[GridSize];
            }
        }
    }
}


/// <summary>
/// The out-of-circuit SHA-3 witness generator, a faithful port of the reference's
/// <c>Sha3Witness</c> and the <c>Sha3Reference</c> permutation it drives
/// (<c>circuits/tests/sha3/sha3_witness.cc</c>, <c>sha3_reference.cc</c>): the plain Keccak-f[1600]
/// permutation, the per-round witness recording, the SHAKE256 sponge walk producing one witness per
/// permutation, and the column filler emitting the sliced rounds' lanes bit by bit.
/// </summary>
internal static class LongfellowSha3Witness
{
    /// <summary>The lane grid's side length.</summary>
    private const int GridSize = 5;

    /// <summary>The SHAKE256 sponge rate in bytes.</summary>
    private const int Rate = 136;

    /// <summary>The SHAKE128 sponge rate in bytes (the reference's <c>shake128Hash</c>), shared with the consumers that extract by whole blocks.</summary>
    public const int Shake128Rate = 168;

    /// <summary>The Keccak state's byte width.</summary>
    private const int StateBytes = 200;

    /// <summary>The SHAKE suffix-and-first-padding byte.</summary>
    private const byte ShakePadFirst = 0x1F;

    /// <summary>The final padding byte.</summary>
    private const byte PadLast = 0x80;

    /// <summary>One lane's bit width.</summary>
    private const int LaneBits = 64;


    /// <summary>
    /// The reference's <c>compute_witness_block</c>: one permutation over <paramref name="state"/>
    /// in place, recording the state after every round.
    /// </summary>
    /// <param name="state">The 5×5 lane state, transformed in place.</param>
    /// <param name="blockWitness">Receives the per-round states.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static void ComputeWitnessBlock(ulong[][] state, LongfellowSha3BlockWitness blockWitness)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(blockWitness);

        for(int round = 0; round < LongfellowSha3Constants.RoundCount; round++)
        {
            Theta(state);
            Rho(state);
            ulong[][] permuted = Pi(state);
            Chi(permuted, state);
            state[0][0] ^= LongfellowSha3Constants.RoundConstants[round];

            for(int x = 0; x < GridSize; x++)
            {
                for(int y = 0; y < GridSize; y++)
                {
                    blockWitness.AIntermediate[round][x][y] = state[x][y];
                }
            }
        }
    }


    /// <summary>
    /// The reference's <c>compute_witness_shake256</c>: walks the SHAKE256 sponge over
    /// <paramref name="seed"/>, producing one witness per padded absorb permutation and one per
    /// squeezed block after the first.
    /// </summary>
    /// <param name="seed">The input bytes.</param>
    /// <param name="outputLength">The squeezed output length in bytes.</param>
    /// <returns>The witnesses in permutation order.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="outputLength"/> is negative.</exception>
    public static IReadOnlyList<LongfellowSha3BlockWitness> ComputeWitnessShake256(ReadOnlySpan<byte> seed, int outputLength)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(outputLength);

        var witnesses = new List<LongfellowSha3BlockWitness>();
        ulong[][] state = NewState();
        Span<byte> block = stackalloc byte[StateBytes];
        int pointer = 0;

        for(int i = 0; i < seed.Length; i++)
        {
            block[pointer++] = seed[i];
            if(pointer != Rate)
            {
                continue;
            }

            XorIn(state, block);
            var absorbed = new LongfellowSha3BlockWitness();
            ComputeWitnessBlock(state, absorbed);
            witnesses.Add(absorbed);
            pointer = 0;
            block[..Rate].Clear();
        }

        block[pointer] ^= ShakePadFirst;
        block[Rate - 1] ^= PadLast;
        XorIn(state, block);
        var final = new LongfellowSha3BlockWitness();
        ComputeWitnessBlock(state, final);
        witnesses.Add(final);

        int outputCursor = 0;
        while(outputCursor < outputLength)
        {
            int take = Math.Min(Rate, outputLength - outputCursor);
            outputCursor += take;
            if(outputCursor >= outputLength)
            {
                continue;
            }

            var squeezed = new LongfellowSha3BlockWitness();
            ComputeWitnessBlock(state, squeezed);
            witnesses.Add(squeezed);
        }

        return witnesses;
    }


    /// <summary>
    /// The host-side SHAKE256 (the reference's <c>shake256Hash</c>): the same sponge the witness
    /// walk drives, squeezing <paramref name="output"/> from <paramref name="seed"/>.
    /// </summary>
    /// <param name="seed">The input bytes.</param>
    /// <param name="output">Receives the squeezed bytes.</param>
    public static void Shake256Hash(ReadOnlySpan<byte> seed, Span<byte> output)
    {
        ulong[][] state = NewState();
        Span<byte> block = stackalloc byte[StateBytes];
        int pointer = 0;

        for(int i = 0; i < seed.Length; i++)
        {
            block[pointer++] = seed[i];
            if(pointer != Rate)
            {
                continue;
            }

            XorIn(state, block);
            Permute(state);
            pointer = 0;
            block[..Rate].Clear();
        }

        block[pointer] ^= ShakePadFirst;
        block[Rate - 1] ^= PadLast;
        XorIn(state, block);
        Permute(state);

        int outputCursor = 0;
        while(outputCursor < output.Length)
        {
            int take = Math.Min(Rate, output.Length - outputCursor);
            int x = 0;
            int y = 0;
            for(int i = 0; i < take; i += 8)
            {
                ulong lane = state[x][y];
                int laneBytes = Math.Min(8, take - i);
                for(int b = 0; b < laneBytes; b++)
                {
                    output[outputCursor + i + b] = (byte)(lane >> (8 * b));
                }

                x++;
                if(x == GridSize)
                {
                    y++;
                    x = 0;
                }
            }

            outputCursor += take;
            if(outputCursor < output.Length)
            {
                Permute(state);
            }
        }
    }


    /// <summary>
    /// The host-side SHAKE128 (the reference's <c>shake128Hash</c>): the same sponge as
    /// <see cref="Shake256Hash"/> at the SHAKE128 rate, squeezing <paramref name="output"/> from
    /// <paramref name="seed"/>.
    /// </summary>
    /// <param name="seed">The input bytes.</param>
    /// <param name="output">Receives the squeezed bytes.</param>
    public static void Shake128Hash(ReadOnlySpan<byte> seed, Span<byte> output)
    {
        ulong[][] state = NewState();
        Span<byte> block = stackalloc byte[StateBytes];
        int pointer = 0;

        for(int i = 0; i < seed.Length; i++)
        {
            block[pointer++] = seed[i];
            if(pointer != Shake128Rate)
            {
                continue;
            }

            XorIn(state, block, Shake128Rate);
            Permute(state);
            pointer = 0;
            block[..Shake128Rate].Clear();
        }

        block[pointer] ^= ShakePadFirst;
        block[Shake128Rate - 1] ^= PadLast;
        XorIn(state, block, Shake128Rate);
        Permute(state);

        int outputCursor = 0;
        while(outputCursor < output.Length)
        {
            int take = Math.Min(Shake128Rate, output.Length - outputCursor);
            int x = 0;
            int y = 0;
            for(int i = 0; i < take; i += 8)
            {
                ulong lane = state[x][y];
                int laneBytes = Math.Min(8, take - i);
                for(int b = 0; b < laneBytes; b++)
                {
                    output[outputCursor + i + b] = (byte)(lane >> (8 * b));
                }

                x++;
                if(x == GridSize)
                {
                    y++;
                    x = 0;
                }
            }

            outputCursor += take;
            if(outputCursor < output.Length)
            {
                Permute(state);
            }
        }
    }


    /// <summary>
    /// The reference filler's witness region: for every witness, every sliced round's lanes in
    /// x-major then y-major order, each lane as 64 bit-elements least significant first.
    /// </summary>
    /// <param name="field">The field bundle supplying the bit elements.</param>
    /// <param name="witnesses">The witnesses in permutation order.</param>
    /// <param name="destination">The column being filled.</param>
    /// <param name="cursor">The element cursor, advanced past the region.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public static void FillWitness(LongfellowLogicFieldOperations field, IReadOnlyList<LongfellowSha3BlockWitness> witnesses, Span<byte> destination, ref int cursor)
    {
        ArgumentNullException.ThrowIfNull(field);
        ArgumentNullException.ThrowIfNull(witnesses);

        for(int w = 0; w < witnesses.Count; w++)
        {
            for(int round = 0; round < LongfellowSha3Constants.RoundCount; round++)
            {
                if(!LongfellowSha3Constants.SliceAt(round))
                {
                    continue;
                }

                for(int x = 0; x < GridSize; x++)
                {
                    for(int y = 0; y < GridSize; y++)
                    {
                        ulong lane = witnesses[w].AIntermediate[round][x][y];
                        for(int bit = 0; bit < LaneBits; bit++)
                        {
                            ReadOnlyMemory<byte> element = ((lane >> bit) & 1UL) != 0UL ? field.Compiler.One : field.Compiler.Zero;
                            element.Span.CopyTo(destination.Slice(cursor * Scalar.SizeBytes, Scalar.SizeBytes));
                            cursor++;
                        }
                    }
                }
            }
        }
    }


    /// <summary>The witness-wire count one permutation contributes: the sliced rounds' 25 lanes of 64 bits.</summary>
    public static int ElementsPerBlockWitness
    {
        get
        {
            int slicedRounds = 0;
            for(int round = 0; round < LongfellowSha3Constants.RoundCount; round++)
            {
                if(LongfellowSha3Constants.SliceAt(round))
                {
                    slicedRounds++;
                }
            }

            return slicedRounds * GridSize * GridSize * LaneBits;
        }
    }


    /// <summary>Runs one unrecorded permutation.</summary>
    /// <param name="state">The 5×5 lane state, transformed in place.</param>
    private static void Permute(ulong[][] state)
    {
        for(int round = 0; round < LongfellowSha3Constants.RoundCount; round++)
        {
            Theta(state);
            Rho(state);
            ulong[][] permuted = Pi(state);
            Chi(permuted, state);
            state[0][0] ^= LongfellowSha3Constants.RoundConstants[round];
        }
    }


    /// <summary>Allocates the zeroed 5×5 lane state.</summary>
    /// <returns>The state.</returns>
    private static ulong[][] NewState()
    {
        var state = new ulong[GridSize][];
        for(int x = 0; x < GridSize; x++)
        {
            state[x] = new ulong[GridSize];
        }

        return state;
    }


    /// <summary>The reference's <c>xorin</c>: XORs the rate-sized block into the state, one little-endian lane per eight bytes, x-major.</summary>
    /// <param name="state">The 5×5 lane state.</param>
    /// <param name="block">The zero-padded block.</param>
    /// <param name="rate">The sponge rate in bytes.</param>
    private static void XorIn(ulong[][] state, ReadOnlySpan<byte> block, int rate = Rate)
    {
        int x = 0;
        int y = 0;
        for(int i = 0; i < rate; i += 8)
        {
            ulong lane = 0;
            for(int b = 0; b < 8; b++)
            {
                lane |= (ulong)block[i + b] << (8 * b);
            }

            state[x][y] ^= lane;
            x++;
            if(x == GridSize)
            {
                y++;
                x = 0;
            }
        }
    }


    /// <summary>The host theta: the plain five-way column parity (the circuit-side split is a depth optimization only).</summary>
    /// <param name="state">The 5×5 lane state.</param>
    private static void Theta(ulong[][] state)
    {
        Span<ulong> parity = stackalloc ulong[GridSize];
        for(int x = 0; x < GridSize; x++)
        {
            parity[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
        }

        for(int x = 0; x < GridSize; x++)
        {
            ulong mix = parity[(x + 4) % GridSize] ^ BitOperations.RotateLeft(parity[(x + 1) % GridSize], 1);
            for(int y = 0; y < GridSize; y++)
            {
                state[x][y] ^= mix;
            }
        }
    }


    /// <summary>The host rho: the fixed lane-rotation walk.</summary>
    /// <param name="state">The 5×5 lane state.</param>
    private static void Rho(ulong[][] state)
    {
        int x = 1;
        int y = 0;
        for(int t = 0; t < LongfellowSha3Constants.RoundCount; t++)
        {
            state[x][y] = BitOperations.RotateLeft(state[x][y], LongfellowSha3Constants.RotationCounts[t]);
            int nextX = y;
            int nextY = ((2 * x) + (3 * y)) % GridSize;
            x = nextX;
            y = nextY;
        }
    }


    /// <summary>The host pi: the lane permutation.</summary>
    /// <param name="state">The 5×5 lane state.</param>
    /// <returns>The permuted state.</returns>
    private static ulong[][] Pi(ulong[][] state)
    {
        ulong[][] permuted = NewState();
        for(int x = 0; x < GridSize; x++)
        {
            for(int y = 0; y < GridSize; y++)
            {
                permuted[x][y] = state[((x + (3 * y)) % GridSize)][x];
            }
        }

        return permuted;
    }


    /// <summary>The host chi.</summary>
    /// <param name="permuted">The pi-permuted state.</param>
    /// <param name="state">Receives the transformed lanes.</param>
    private static void Chi(ulong[][] permuted, ulong[][] state)
    {
        for(int x = 0; x < GridSize; x++)
        {
            for(int y = 0; y < GridSize; y++)
            {
                state[x][y] = permuted[x][y] ^ (permuted[(x + 2) % GridSize][y] & ~permuted[(x + 1) % GridSize][y]);
            }
        }
    }
}

using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The per-permutation witness wires of the SHA-3 circuit, a faithful port of the reference's
/// <c>Sha3Circuit::BlockWitness</c>: one 25-lane state per sliced round (rounds 5, 11, 17 and 23),
/// which the circuit asserts against its computed state and then re-anchors on, capping the
/// arithmetic depth of the unwitnessed round runs.
/// </summary>
internal sealed class LongfellowSha3BlockWitnessWires
{
    /// <summary>The lane grid's side length.</summary>
    private const int GridSize = 5;

    /// <summary>The witnessed states: <c>[round][x][y]</c> holds a 64-bit lane at sliced rounds and an empty array elsewhere.</summary>
    public LongfellowBitWire[][][][] AIntermediate { get; }


    /// <summary>Constructs the bundle with empty lanes; <see cref="Input"/> declares the sliced rounds' wires.</summary>
    public LongfellowSha3BlockWitnessWires()
    {
        AIntermediate = new LongfellowBitWire[LongfellowSha3Constants.RoundCount][][][];
        for(int round = 0; round < LongfellowSha3Constants.RoundCount; round++)
        {
            AIntermediate[round] = new LongfellowBitWire[GridSize][][];
            for(int x = 0; x < GridSize; x++)
            {
                AIntermediate[round][x] = new LongfellowBitWire[GridSize][];
                for(int y = 0; y < GridSize; y++)
                {
                    AIntermediate[round][x][y] = [];
                }
            }
        }
    }


    /// <summary>
    /// The reference's <c>BlockWitness::input</c>: declares one 64-bit lane input per grid position
    /// at every sliced round, in round-major then x-major then y-major order.
    /// </summary>
    /// <param name="logic">The gadget layer to declare inputs on.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="logic"/> is <see langword="null"/>.</exception>
    public void Input(LongfellowLogic logic)
    {
        ArgumentNullException.ThrowIfNull(logic);

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
                    AIntermediate[round][x][y] = logic.InputVector(LongfellowLogic.BitWidth64);
                }
            }
        }
    }
}


/// <summary>
/// The Keccak-f[1600] permutation and SHAKE256 assertion circuit, a faithful port of
/// google/longfellow-zk's <c>Sha3Circuit</c> (<c>circuits/tests/sha3/sha3_circuit.h</c>, FIPS 202):
/// theta with the reference's depth-motivated split accumulation, rho, pi, chi, iota, the
/// witness-sliced permutation, and <c>assert_shake256</c> — the sponge whose squeezed output is
/// read eagerly from the witnessed final-round states while the absorb and squeeze permutations
/// are asserted in parallel.
/// </summary>
/// <remarks>
/// <para>
/// Every lane operation runs vector-at-a-time in the reference's emission order — the split theta
/// accumulation XORs the late-available half first — because the wire creation order shapes the
/// compiled circuit's scheduling and elimination counters. The state re-anchoring assertion
/// compares lanes as packed scalars over subfield-sized slices: four 16-bit slices over a 16-bit
/// subfield, otherwise the reference's three-way 22-bit split.
/// </para>
/// <para>
/// The reference marks its SHA-3 circuit as an experimental research implementation, not vetted
/// for production; this port carries the same status until the surrounding statements it serves
/// are themselves production-gated.
/// </para>
/// </remarks>
internal sealed class LongfellowSha3Circuit
{
    /// <summary>The lane grid's side length.</summary>
    private const int GridSize = 5;

    /// <summary>One lane's bit width.</summary>
    private const int LaneBits = 64;

    /// <summary>The SHAKE256 sponge rate in bytes.</summary>
    private const int Rate = 136;

    /// <summary>The Keccak state's byte width.</summary>
    private const int StateBytes = 200;

    /// <summary>The SHAKE suffix-and-first-padding byte (FIPS 202: the <c>1111</c> domain suffix with the pad-start bit).</summary>
    private const byte ShakePadFirst = 0x1F;

    /// <summary>The final padding byte.</summary>
    private const byte PadLast = 0x80;

    /// <summary>The subfield width selecting the four-way 16-bit assertion split.</summary>
    private const int SixteenBitSubfield = 16;

    /// <summary>The minimum subfield width the three-way assertion split packs into (the reference's ≥22-bit assumption).</summary>
    private const int ThreeWaySliceBits = 22;

    /// <summary>The three-way split's second boundary.</summary>
    private const int ThreeWaySecondBoundary = 43;

    private readonly LongfellowLogic logic;
    private readonly int subfieldBitCount;


    /// <summary>
    /// Constructs the circuit over a gadget layer and the field's subfield width, which selects
    /// the re-anchoring assertion's slice split (the reference reads <c>kSubFieldBits</c> from the
    /// field type).
    /// </summary>
    /// <param name="logic">The gadget layer to build on.</param>
    /// <param name="subfieldBitCount">The field's subfield bit width: 16 for GF(2^128), 32 for the sextic extension of the FIPS 204 prime.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="logic"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When the width is neither 16 nor at least the three-way split's slice size.</exception>
    public LongfellowSha3Circuit(LongfellowLogic logic, int subfieldBitCount)
    {
        ArgumentNullException.ThrowIfNull(logic);

        if(subfieldBitCount != SixteenBitSubfield)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(subfieldBitCount, ThreeWaySliceBits);
        }

        this.logic = logic;
        this.subfieldBitCount = subfieldBitCount;
    }


    /// <summary>
    /// The reference's witness-free <c>keccak_f_1600</c>: all 24 rounds computed arithmetically,
    /// the baseline for depth and cost measurement.
    /// </summary>
    /// <param name="state">The 5×5 lane state, transformed in place.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="state"/> is <see langword="null"/>.</exception>
    public void KeccakF1600(LongfellowBitWire[][][] state)
    {
        ArgumentNullException.ThrowIfNull(state);

        for(int round = 0; round < LongfellowSha3Constants.RoundCount; round++)
        {
            Theta(state);
            Rho(state);
            LongfellowBitWire[][][] permuted = Pi(state);
            Chi(permuted, state);
            Iota(state, round);
        }
    }


    /// <summary>
    /// The reference's witnessed <c>keccak_f_1600</c>: at every sliced round the computed state is
    /// asserted equal to the witness lanes and then replaced by them, re-anchoring the depth.
    /// </summary>
    /// <param name="state">The 5×5 lane state, transformed in place.</param>
    /// <param name="blockWitness">The sliced-round witness wires.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public void KeccakF1600(LongfellowBitWire[][][] state, LongfellowSha3BlockWitnessWires blockWitness)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(blockWitness);

        for(int round = 0; round < LongfellowSha3Constants.RoundCount; round++)
        {
            Theta(state);
            Rho(state);
            LongfellowBitWire[][][] permuted = Pi(state);
            Chi(permuted, state);
            Iota(state, round);

            if(!LongfellowSha3Constants.SliceAt(round))
            {
                continue;
            }

            for(int x = 0; x < GridSize; x++)
            {
                for(int y = 0; y < GridSize; y++)
                {
                    AssertLanesEqual(state[x][y], blockWitness.AIntermediate[round][x][y]);
                    state[x][y] = blockWitness.AIntermediate[round][x][y];
                }
            }
        }
    }


    /// <summary>
    /// The reference's <c>assert_shake256</c>: asserts that <paramref name="seed"/> squeezes to the
    /// returned output through the SHAKE256 sponge, consuming one witnessed permutation per padded
    /// absorb block and one per squeezed block after the first. The output bytes are read eagerly
    /// from the witnessed final-round states, so every permutation is asserted independently.
    /// </summary>
    /// <param name="seed">The input bytes as eight-bit vectors.</param>
    /// <param name="outputLength">The squeezed output length in bytes.</param>
    /// <param name="blockWitnesses">One witness bundle per permutation.</param>
    /// <returns>The squeezed output bytes as eight-bit vectors.</returns>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="outputLength"/> is negative.</exception>
    /// <exception cref="ArgumentException">When the witness count does not match the block accounting.</exception>
    public LongfellowBitWire[][] AssertShake256(LongfellowBitWire[][] seed, int outputLength, LongfellowSha3BlockWitnessWires[] blockWitnesses)
    {
        ArgumentNullException.ThrowIfNull(seed);
        ArgumentNullException.ThrowIfNull(blockWitnesses);
        ArgumentOutOfRangeException.ThrowIfNegative(outputLength);

        int absorbBlockCount = (seed.Length + Rate) / Rate;
        int squeezeBlockCount = outputLength == 0 ? 0 : (outputLength - 1) / Rate;
        if(blockWitnesses.Length != absorbBlockCount + squeezeBlockCount)
        {
            throw new ArgumentException("The witness count must equal the padded absorb blocks plus the squeezed blocks after the first.", nameof(blockWitnesses));
        }

        //Populate the output eagerly from the witnessed final-round states; these are pure wire
        //references, so the absorb assertions below can run block-parallel.
        var output = new LongfellowBitWire[outputLength][];
        int outputCursor = 0;
        int squeezeRequest = 0;
        while(outputCursor < outputLength)
        {
            var squeezeBlock = new LongfellowBitWire[StateBytes][];
            int sourceX = 0;
            int sourceY = 0;
            for(int i = 0; i < Rate; i += 8)
            {
                LongfellowBitWire[] lane = blockWitnesses[absorbBlockCount - 1 + squeezeRequest].AIntermediate[LongfellowSha3Constants.RoundCount - 1][sourceX][sourceY];
                for(int b = 0; b < 8; b++)
                {
                    var laneByte = new LongfellowBitWire[LongfellowLogic.BitWidth8];
                    for(int j = 0; j < LongfellowLogic.BitWidth8; j++)
                    {
                        laneByte[j] = lane[(b * 8) + j];
                    }

                    squeezeBlock[i + b] = laneByte;
                }

                sourceX++;
                if(sourceX == GridSize)
                {
                    sourceY++;
                    sourceX = 0;
                }
            }

            int take = Math.Min(Rate, outputLength - outputCursor);
            for(int i = 0; i < take; i++)
            {
                output[outputCursor++] = squeezeBlock[i];
            }

            squeezeRequest++;
        }

        //Absorb phase; the block buffer keeps the zero-padded invariant.
        var block = new LongfellowBitWire[StateBytes][];
        for(int i = 0; i < StateBytes; i++)
        {
            block[i] = logic.BitVector(LongfellowLogic.BitWidth8, 0);
        }

        int witnessIndex = 0;
        int pointer = 0;
        for(int i = 0; i < seed.Length; i++)
        {
            block[pointer++] = seed[i];
            if(pointer != Rate)
            {
                continue;
            }

            LongfellowBitWire[][][] absorbState = ChainState(blockWitnesses, witnessIndex, absorbBlockCount);
            XorInBlock(absorbState, block);
            KeccakF1600(absorbState, blockWitnesses[witnessIndex++]);
            pointer = 0;
            for(int j = 0; j < StateBytes; j++)
            {
                block[j] = logic.BitVector(LongfellowLogic.BitWidth8, 0);
            }
        }

        //Pad and process the last block.
        block[pointer] = logic.BitVector(LongfellowLogic.BitWidth8, ShakePadFirst);
        block[Rate - 1] = logic.Xor(block[Rate - 1], logic.BitVector(LongfellowLogic.BitWidth8, PadLast));

        LongfellowBitWire[][][] finalState = ChainState(blockWitnesses, witnessIndex, absorbBlockCount);
        XorInBlock(finalState, block);
        KeccakF1600(finalState, blockWitnesses[witnessIndex++]);

        //Squeeze-phase permutations start from the witnessed final-round states.
        for(int i = 0; i < squeezeBlockCount; i++)
        {
            var squeezeState = new LongfellowBitWire[GridSize][][];
            for(int x = 0; x < GridSize; x++)
            {
                squeezeState[x] = new LongfellowBitWire[GridSize][];
                for(int y = 0; y < GridSize; y++)
                {
                    squeezeState[x][y] = blockWitnesses[absorbBlockCount - 1 + i].AIntermediate[LongfellowSha3Constants.RoundCount - 1][x][y];
                }
            }

            KeccakF1600(squeezeState, blockWitnesses[witnessIndex++]);
        }

        if(witnessIndex != blockWitnesses.Length)
        {
            throw new ArgumentException("Every witness bundle must be consumed by the block accounting.", nameof(blockWitnesses));
        }

        return output;
    }


    /// <summary>Builds the absorb chain's incoming state: all-zero lanes before the first permutation, the previous witness's final-round lanes afterwards.</summary>
    /// <param name="blockWitnesses">The witness bundles.</param>
    /// <param name="witnessIndex">The index of the permutation about to run.</param>
    /// <param name="absorbBlockCount">The padded absorb block count (unused by the chain itself; the caller's accounting guards it).</param>
    /// <returns>The 5×5 lane state.</returns>
    private LongfellowBitWire[][][] ChainState(LongfellowSha3BlockWitnessWires[] blockWitnesses, int witnessIndex, int absorbBlockCount)
    {
        var state = new LongfellowBitWire[GridSize][][];
        for(int x = 0; x < GridSize; x++)
        {
            state[x] = new LongfellowBitWire[GridSize][];
            for(int y = 0; y < GridSize; y++)
            {
                state[x][y] = witnessIndex == 0
                    ? logic.BitVector(LaneBits, 0)
                    : blockWitnesses[witnessIndex - 1].AIntermediate[LongfellowSha3Constants.RoundCount - 1][x][y];
            }
        }

        return state;
    }


    /// <summary>
    /// The reference's <c>xorin_block</c> (FIPS 202 Algorithm 8 step 6): XORs the rate-sized block
    /// into the state lane by lane, assembling each lane from eight byte vectors.
    /// </summary>
    /// <param name="state">The 5×5 lane state.</param>
    /// <param name="block">The zero-padded block's byte vectors.</param>
    private void XorInBlock(LongfellowBitWire[][][] state, LongfellowBitWire[][] block)
    {
        int x = 0;
        int y = 0;
        for(int i = 0; i < Rate; i += 8)
        {
            var lane = new LongfellowBitWire[LaneBits];
            for(int b = 0; b < 8; b++)
            {
                for(int j = 0; j < LongfellowLogic.BitWidth8; j++)
                {
                    lane[(b * 8) + j] = block[i + b][j];
                }
            }

            state[x][y] = logic.Xor(state[x][y], lane);
            x++;
            if(x == GridSize)
            {
                y++;
                x = 0;
            }
        }
    }


    /// <summary>
    /// The reference's theta (FIPS 202 3.2.1) with its depth-motivated split: the column parity is
    /// accumulated as a two-level half plus the free fifth row, and the fifth row's contribution —
    /// available two levels earlier — is XORed into the state first.
    /// </summary>
    /// <param name="state">The 5×5 lane state.</param>
    private void Theta(LongfellowBitWire[][][] state)
    {
        var parityLow = new LongfellowBitWire[GridSize][];
        var parityHigh = new LongfellowBitWire[GridSize][];
        for(int x = 0; x < GridSize; x++)
        {
            LongfellowBitWire[] first = logic.Xor(state[x][0], state[x][1]);
            LongfellowBitWire[] second = logic.Xor(state[x][2], state[x][3]);
            parityLow[x] = logic.Xor(second, first);
            parityHigh[x] = state[x][4];
        }

        for(int x = 0; x < GridSize; x++)
        {
            LongfellowBitWire[] mixLow = logic.Xor(parityLow[(x + 4) % GridSize], LongfellowLogic.RotateLeft(parityLow[(x + 1) % GridSize], 1));
            LongfellowBitWire[] mixHigh = logic.Xor(parityHigh[(x + 4) % GridSize], LongfellowLogic.RotateLeft(parityHigh[(x + 1) % GridSize], 1));
            for(int y = 0; y < GridSize; y++)
            {
                state[x][y] = logic.Xor(state[x][y], mixHigh);
                state[x][y] = logic.Xor(state[x][y], mixLow);
            }
        }
    }


    /// <summary>The reference's rho (FIPS 202 3.2.2): the fixed lane-rotation walk (a pure index remap, no wires).</summary>
    /// <param name="state">The 5×5 lane state.</param>
    private static void Rho(LongfellowBitWire[][][] state)
    {
        int x = 1;
        int y = 0;
        for(int t = 0; t < LongfellowSha3Constants.RoundCount; t++)
        {
            state[x][y] = LongfellowLogic.RotateLeft(state[x][y], LongfellowSha3Constants.RotationCounts[t]);
            int nextX = y;
            int nextY = ((2 * x) + (3 * y)) % GridSize;
            x = nextX;
            y = nextY;
        }
    }


    /// <summary>The reference's pi (FIPS 202 3.2.3): the lane permutation (pure references, no wires).</summary>
    /// <param name="state">The 5×5 lane state.</param>
    /// <returns>The permuted state.</returns>
    private static LongfellowBitWire[][][] Pi(LongfellowBitWire[][][] state)
    {
        var permuted = new LongfellowBitWire[GridSize][][];
        for(int x = 0; x < GridSize; x++)
        {
            permuted[x] = new LongfellowBitWire[GridSize][];
        }

        for(int x = 0; x < GridSize; x++)
        {
            for(int y = 0; y < GridSize; y++)
            {
                permuted[x][y] = state[((x + (3 * y)) % GridSize)][x];
            }
        }

        return permuted;
    }


    /// <summary>The reference's chi (FIPS 202 3.2.4): each lane XORed with the AND of its second neighbor and its negated first neighbor, vector at a time.</summary>
    /// <param name="permuted">The pi-permuted state.</param>
    /// <param name="state">Receives the transformed lanes.</param>
    private void Chi(LongfellowBitWire[][][] permuted, LongfellowBitWire[][][] state)
    {
        for(int x = 0; x < GridSize; x++)
        {
            for(int y = 0; y < GridSize; y++)
            {
                state[x][y] = logic.Xor(permuted[x][y], logic.And(permuted[(x + 2) % GridSize][y], logic.Not(permuted[(x + 1) % GridSize][y])));
            }
        }
    }


    /// <summary>The reference's iota (FIPS 202 3.2.5): the round constant XORed into the origin lane.</summary>
    /// <param name="state">The 5×5 lane state.</param>
    /// <param name="round">The round index.</param>
    private void Iota(LongfellowBitWire[][][] state, int round)
    {
        state[0][0] = logic.Xor(state[0][0], logic.BitVector(LaneBits, LongfellowSha3Constants.RoundConstants[round]));
    }


    /// <summary>
    /// The reference's <c>sha3_vassert_eq</c>: asserts two lanes equal by comparing packed scalars
    /// over subfield-sized slices — four 16-bit slices over a 16-bit subfield, otherwise the
    /// three-way 22-bit split (whose packing the constructor's width guard keeps sound).
    /// </summary>
    /// <param name="computed">The computed lane.</param>
    /// <param name="witnessed">The witnessed lane.</param>
    private void AssertLanesEqual(LongfellowBitWire[] computed, LongfellowBitWire[] witnessed)
    {
        if(subfieldBitCount == SixteenBitSubfield)
        {
            AssertSliceEqual(computed, witnessed, 0, SixteenBitSubfield);
            AssertSliceEqual(computed, witnessed, SixteenBitSubfield, 2 * SixteenBitSubfield);
            AssertSliceEqual(computed, witnessed, 2 * SixteenBitSubfield, 3 * SixteenBitSubfield);
            AssertSliceEqual(computed, witnessed, 3 * SixteenBitSubfield, LaneBits);

            return;
        }

        AssertSliceEqual(computed, witnessed, 0, ThreeWaySliceBits);
        AssertSliceEqual(computed, witnessed, ThreeWaySliceBits, ThreeWaySecondBoundary);
        AssertSliceEqual(computed, witnessed, ThreeWaySecondBoundary, LaneBits);
    }


    /// <summary>Asserts one slice of two lanes equal as packed scalars.</summary>
    /// <param name="computed">The computed lane.</param>
    /// <param name="witnessed">The witnessed lane.</param>
    /// <param name="start">The slice's inclusive start bit.</param>
    /// <param name="end">The slice's exclusive end bit.</param>
    private void AssertSliceEqual(LongfellowBitWire[] computed, LongfellowBitWire[] witnessed, int start, int end)
    {
        int left = logic.AsScalar(LongfellowLogic.Slice(computed, start, end));
        int right = logic.AsScalar(LongfellowLogic.Slice(witnessed, start, end));
        _ = logic.AssertEqual(left, right);
    }
}

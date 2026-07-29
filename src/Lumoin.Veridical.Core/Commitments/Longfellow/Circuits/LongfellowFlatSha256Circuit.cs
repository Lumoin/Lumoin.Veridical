using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The flattened SHA-256 hash gadget, a faithful port of google/longfellow-zk's
/// <c>FlatSHA256Circuit&lt;Logic, BitPlucker&gt;</c> (<c>flatsha256_circuit.h</c>): the SHA-256 round
/// function is repeated in parallel rather than sequentially, so the prover supplies the intermediate
/// round values as witnesses and the circuit asserts the compression recurrence between consecutive
/// witnessed values instead of computing it. This type has no external dependency on any SHA-256
/// library, matching the reference.
/// </summary>
/// <remarks>
/// <para>
/// The reference's <c>BitPlucker bp_</c> member is constructed inline from the enclosing class's
/// <c>Logic</c> template parameter and its own <c>LOGN</c> template parameter; since this port's
/// <see cref="LongfellowBitPlucker"/> takes its point count as a runtime constructor argument rather
/// than a compile-time template parameter, the plucker is instead a constructor collaborator here,
/// supplied by the caller. <see cref="SchedulePluckerLogPointCount"/> names the reference's
/// <c>kShaPluckerSize</c> (<c>flatsha256_io.h</c>), the pack size the SHA statement conventionally
/// uses, but every member of this class works for a plucker built with any point count.
/// </para>
/// <para>
/// The reference nests <c>FlatSHA256Circuit::BlockWitness</c> (packed wires) and
/// <c>FlatSHA256Witness::BlockWitness</c> (plain <see cref="uint"/> values) as same-named inner types
/// of two different enclosing classes. This port has no nested types, so the two are distinct
/// top-level names: this file's <see cref="LongfellowFlatSha256PackedBlockWitness"/> is the in-circuit
/// (packed-wire) counterpart to <see cref="LongfellowFlatSha256BlockWitness"/>, the witness-side
/// (plain <see cref="uint"/>) type defined alongside <see cref="LongfellowFlatSha256Witness"/>.
/// </para>
/// </remarks>
internal sealed class LongfellowFlatSha256Circuit
{
    /// <summary>The reference's <c>kShaPluckerSize</c> (<c>flatsha256_io.h</c>): the point-count exponent the SHA statement conventionally plucks witness words at. Not enforced by this class, which works for any plucker.</summary>
    public const int SchedulePluckerLogPointCount = 2;

    /// <summary>The number of 32-bit words in one SHA-256 message block (the reference's <c>in[16]</c>).</summary>
    private const int InputWordCount = 16;

    /// <summary>The number of schedule-extension words (the reference's <c>outw[48]</c>).</summary>
    private const int ScheduleWordCount = 48;

    /// <summary>The number of compression rounds, and the length of the schedule array <c>w</c> (the reference's <c>w[64]</c>).</summary>
    private const int RoundCount = 64;

    /// <summary>The number of hash-state words (the reference's <c>H0</c>/<c>H1</c>).</summary>
    private const int StateWordCount = 8;

    /// <summary>The byte width of one SHA-256 block.</summary>
    private const int BytesPerBlock = 64;

    /// <summary>The byte width of one 32-bit word.</summary>
    private const int BytesPerWord = 4;

    /// <summary>The bit width of the assembled hash target (the reference's <c>v256</c>).</summary>
    private const int HashBitWidth = 256;

    /// <summary>The candidate-carry slack <see cref="LongfellowBitAdder.AssertEqualModulo"/> checks the schedule extension against (the reference's <c>assert_eqmod(w[i], ..., 4)</c>).</summary>
    private const int ScheduleCarrySlack = 4;

    /// <summary>The candidate-carry slack for register <c>e</c>'s witnessed value (the reference's <c>assert_eqmod(e, ..., 6)</c>).</summary>
    private const int RegisterECarrySlack = 6;

    /// <summary>The candidate-carry slack for register <c>a</c>'s witnessed value (the reference's <c>assert_eqmod(a, ..., 7)</c>).</summary>
    private const int RegisterACarrySlack = 7;

    /// <summary>The candidate-carry slack for the final hash-state words (the reference's <c>assert_eqmod(H1[i], ..., 2)</c>).</summary>
    private const int FinalStateCarrySlack = 2;

    private readonly LongfellowLogic logic;
    private readonly LongfellowLogicBackend backend;
    private readonly LongfellowBitPlucker plucker;

    /// <summary>The plucker this gadget unpacks witness words through (the reference's public <c>bp_</c>, exposed so a caller can size a matching <see cref="LongfellowBitPluckerEncoder"/>).</summary>
    public LongfellowBitPlucker Plucker => plucker;


    /// <summary>
    /// Constructs the gadget over the Logic/BitW gadget layer and a plucker collaborator.
    /// </summary>
    /// <param name="logic">The gadget layer every assertion lowers to.</param>
    /// <param name="plucker">The plucker witness words are unpacked through.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="logic"/> or <paramref name="plucker"/> is <see langword="null"/>.</exception>
    public LongfellowFlatSha256Circuit(LongfellowLogic logic, LongfellowBitPlucker plucker)
    {
        ArgumentNullException.ThrowIfNull(logic);
        ArgumentNullException.ThrowIfNull(plucker);

        this.logic = logic;
        backend = logic.Backend;
        this.plucker = plucker;
    }


    /// <summary>
    /// The reference's <c>packed_input</c>: declares a fresh packed 32-bit witness input (the point
    /// count the enclosing <see cref="Plucker"/> was built with, each element a raw witness wire with
    /// no bitness assertion of its own — bitness follows later from <see cref="LongfellowBitPlucker.Pluck"/>).
    /// </summary>
    /// <returns>The declared packed wires.</returns>
    public int[] PackedInputV32() => plucker.PackedInput(plucker.PackedV32ElementCount);


    /// <summary>
    /// The reference's unpacked <c>assert_transform_block</c>: asserts that the witnessed schedule
    /// extension, per-round registers and final state are consistent with <paramref name="blockWords"/>
    /// and <paramref name="initialState"/> under the SHA-256 compression recurrence, at the declared
    /// carry slacks rather than by building full-width adders.
    /// </summary>
    /// <param name="blockWords">The block's 16 message words (the reference's <c>in</c>).</param>
    /// <param name="initialState">The compression's initial state, 8 words (the reference's <c>H0</c>).</param>
    /// <param name="scheduleExtension">The witnessed 48 schedule words <c>w[16..63]</c> (the reference's <c>outw</c>).</param>
    /// <param name="registerEWitness">The witnessed 64 per-round values of register <c>e</c> (the reference's <c>oute</c>).</param>
    /// <param name="registerAWitness">The witnessed 64 per-round values of register <c>a</c> (the reference's <c>outa</c>).</param>
    /// <param name="finalState">The witnessed final state, 8 words (the reference's <c>H1</c>).</param>
    public void AssertTransformBlock(
        LongfellowBitWire[][] blockWords,
        LongfellowBitWire[][] initialState,
        LongfellowBitWire[][] scheduleExtension,
        LongfellowBitWire[][] registerEWitness,
        LongfellowBitWire[][] registerAWitness,
        LongfellowBitWire[][] finalState)
    {
        ArgumentNullException.ThrowIfNull(blockWords);
        ArgumentNullException.ThrowIfNull(initialState);
        ArgumentNullException.ThrowIfNull(scheduleExtension);
        ArgumentNullException.ThrowIfNull(registerEWitness);
        ArgumentNullException.ThrowIfNull(registerAWitness);
        ArgumentNullException.ThrowIfNull(finalState);

        var adder = new LongfellowBitAdder(logic, LongfellowLogic.BitWidth32);

        var w = new LongfellowBitWire[RoundCount][];
        for(int i = 0; i < InputWordCount; i++)
        {
            w[i] = blockWords[i];
        }

        for(int i = InputWordCount; i < RoundCount; i++)
        {
            w[i] = scheduleExtension[i - InputWordCount];
            int computedSchedule = adder.Add([SmallSigma1(w[i - 2]), w[i - 7], SmallSigma0(w[i - 15]), w[i - 16]]);
            adder.AssertEqualModulo(w[i], computedSchedule, ScheduleCarrySlack);
        }

        LongfellowBitWire[] a = initialState[0];
        LongfellowBitWire[] b = initialState[1];
        LongfellowBitWire[] c = initialState[2];
        LongfellowBitWire[] d = initialState[3];
        LongfellowBitWire[] e = initialState[4];
        LongfellowBitWire[] f = initialState[5];
        LongfellowBitWire[] g = initialState[6];
        LongfellowBitWire[] h = initialState[7];

        for(int t = 0; t < RoundCount; t++)
        {
            LongfellowBitWire[] roundConstant = logic.BitVector(LongfellowLogic.BitWidth32, LongfellowSha256Constants.RoundConstants[t]);
            int t1 = adder.Add([h, BigSigma1(e), logic.Choose(e, f, g), roundConstant, w[t]]);
            int scaledSigma0 = adder.AsFieldElement(BigSigma0(a));
            int scaledMajority = adder.AsFieldElement(logic.Majority(a, b, c));
            int t2 = adder.Add(scaledSigma0, scaledMajority);

            h = g;
            g = f;
            f = e;
            e = registerEWitness[t];
            int encodedD = adder.AsFieldElement(d);
            adder.AssertEqualModulo(e, adder.Add(t1, encodedD), RegisterECarrySlack);
            d = c;
            c = b;
            b = a;
            a = registerAWitness[t];
            adder.AssertEqualModulo(a, adder.Add(t1, t2), RegisterACarrySlack);
        }

        adder.AssertEqualModulo(finalState[0], adder.Add(initialState[0], a), FinalStateCarrySlack);
        adder.AssertEqualModulo(finalState[1], adder.Add(initialState[1], b), FinalStateCarrySlack);
        adder.AssertEqualModulo(finalState[2], adder.Add(initialState[2], c), FinalStateCarrySlack);
        adder.AssertEqualModulo(finalState[3], adder.Add(initialState[3], d), FinalStateCarrySlack);
        adder.AssertEqualModulo(finalState[4], adder.Add(initialState[4], e), FinalStateCarrySlack);
        adder.AssertEqualModulo(finalState[5], adder.Add(initialState[5], f), FinalStateCarrySlack);
        adder.AssertEqualModulo(finalState[6], adder.Add(initialState[6], g), FinalStateCarrySlack);
        adder.AssertEqualModulo(finalState[7], adder.Add(initialState[7], h), FinalStateCarrySlack);
    }


    /// <summary>
    /// The packed-witness <c>assert_transform_block</c> overload: unpacks the schedule extension, the
    /// per-round registers and the final state (in that order, matching the reference's unpack
    /// sequence) and delegates to the unpacked core. <paramref name="initialState"/> stays unpacked,
    /// matching the reference's "H0 not packed, all others packed" overload.
    /// </summary>
    /// <param name="blockWords">The block's 16 message words (the reference's <c>in</c>).</param>
    /// <param name="initialState">The compression's initial state, 8 words, unpacked (the reference's <c>H0</c>).</param>
    /// <param name="packedScheduleExtension">The witnessed schedule extension, packed (the reference's <c>poutw</c>).</param>
    /// <param name="packedRegisterEWitness">The witnessed register-<c>e</c> values, packed (the reference's <c>poute</c>).</param>
    /// <param name="packedRegisterAWitness">The witnessed register-<c>a</c> values, packed (the reference's <c>pouta</c>).</param>
    /// <param name="packedFinalState">The witnessed final state, packed (the reference's <c>pH1</c>).</param>
    public void AssertTransformBlock(
        LongfellowBitWire[][] blockWords,
        LongfellowBitWire[][] initialState,
        int[][] packedScheduleExtension,
        int[][] packedRegisterEWitness,
        int[][] packedRegisterAWitness,
        int[][] packedFinalState)
    {
        ArgumentNullException.ThrowIfNull(packedScheduleExtension);
        ArgumentNullException.ThrowIfNull(packedRegisterEWitness);
        ArgumentNullException.ThrowIfNull(packedRegisterAWitness);
        ArgumentNullException.ThrowIfNull(packedFinalState);

        var finalState = new LongfellowBitWire[StateWordCount][];
        for(int i = 0; i < StateWordCount; i++)
        {
            finalState[i] = plucker.UnpackV32(packedFinalState[i]);
        }

        var scheduleExtension = new LongfellowBitWire[ScheduleWordCount][];
        for(int i = 0; i < ScheduleWordCount; i++)
        {
            scheduleExtension[i] = plucker.UnpackV32(packedScheduleExtension[i]);
        }

        var registerEWitness = new LongfellowBitWire[RoundCount][];
        var registerAWitness = new LongfellowBitWire[RoundCount][];
        for(int i = 0; i < RoundCount; i++)
        {
            registerEWitness[i] = plucker.UnpackV32(packedRegisterEWitness[i]);
            registerAWitness[i] = plucker.UnpackV32(packedRegisterAWitness[i]);
        }

        AssertTransformBlock(blockWords, initialState, scheduleExtension, registerEWitness, registerAWitness, finalState);
    }


    /// <summary>
    /// The all-packed <c>assert_transform_block</c> overload: unpacks <paramref name="packedInitialState"/>
    /// then delegates to the packed-witness overload, which unpacks the remaining witness arrays and
    /// delegates to the unpacked core — three real methods, matching the reference's own chain rather
    /// than collapsing it.
    /// </summary>
    /// <param name="blockWords">The block's 16 message words (the reference's <c>in</c>).</param>
    /// <param name="packedInitialState">The compression's initial state, packed (the reference's <c>pH0</c>).</param>
    /// <param name="packedScheduleExtension">The witnessed schedule extension, packed (the reference's <c>poutw</c>).</param>
    /// <param name="packedRegisterEWitness">The witnessed register-<c>e</c> values, packed (the reference's <c>poute</c>).</param>
    /// <param name="packedRegisterAWitness">The witnessed register-<c>a</c> values, packed (the reference's <c>pouta</c>).</param>
    /// <param name="packedFinalState">The witnessed final state, packed (the reference's <c>pH1</c>).</param>
    public void AssertTransformBlock(
        LongfellowBitWire[][] blockWords,
        int[][] packedInitialState,
        int[][] packedScheduleExtension,
        int[][] packedRegisterEWitness,
        int[][] packedRegisterAWitness,
        int[][] packedFinalState)
    {
        ArgumentNullException.ThrowIfNull(packedInitialState);

        var initialState = new LongfellowBitWire[StateWordCount][];
        for(int i = 0; i < StateWordCount; i++)
        {
            initialState[i] = plucker.UnpackV32(packedInitialState[i]);
        }

        AssertTransformBlock(blockWords, initialState, packedScheduleExtension, packedRegisterEWitness, packedRegisterAWitness, packedFinalState);
    }


    /// <summary>
    /// The reference's <c>assert_message</c>: assembles each block's 16 message words from its raw
    /// bytes in big-endian order, asserts the compression recurrence over every block (the first block
    /// against the initial context, later blocks against the previous block's packed final state), and
    /// asserts that every block beyond the occupied count is zero.
    /// </summary>
    /// <param name="maxBlocks">The block capacity <paramref name="messageBytes"/> and <paramref name="blockWitnesses"/> are sized for (the reference's <c>max</c>).</param>
    /// <param name="blockCount">The witnessed occupied-block count, 8 bits (the reference's <c>nb</c>).</param>
    /// <param name="messageBytes">The padded message, one byte-vector per byte, <c>64 * maxBlocks</c> entries (the reference's <c>in</c>).</param>
    /// <param name="blockWitnesses">The per-block witnesses, exactly <paramref name="maxBlocks"/> entries (the reference's <c>bw</c>).</param>
    public void AssertMessage(int maxBlocks, LongfellowBitWire[] blockCount, LongfellowBitWire[][] messageBytes, LongfellowFlatSha256PackedBlockWitness[] blockWitnesses)
    {
        ArgumentNullException.ThrowIfNull(blockCount);
        ArgumentNullException.ThrowIfNull(messageBytes);
        ArgumentNullException.ThrowIfNull(blockWitnesses);

        int[][]? previousState = null;

        for(int block = 0; block < maxBlocks; block++)
        {
            var blockWords = new LongfellowBitWire[InputWordCount][];
            for(int i = 0; i < InputWordCount; i++)
            {
                int wordBase = (block * BytesPerBlock) + (BytesPerWord * i);
                LongfellowBitWire[] mostSignificantByte = messageBytes[wordBase];
                LongfellowBitWire[] secondByte = messageBytes[wordBase + 1];
                LongfellowBitWire[] thirdByte = messageBytes[wordBase + 2];
                LongfellowBitWire[] leastSignificantByte = messageBytes[wordBase + 3];

                blockWords[i] = LongfellowLogic.Append(
                    LongfellowLogic.Append(leastSignificantByte, thirdByte),
                    LongfellowLogic.Append(secondByte, mostSignificantByte));
            }

            if(block == 0)
            {
                AssertTransformBlock(blockWords, InitialContext(), blockWitnesses[block].ScheduleExtension, blockWitnesses[block].RegisterEWitness, blockWitnesses[block].RegisterAWitness, blockWitnesses[block].FinalState);
            }
            else
            {
                AssertTransformBlock(blockWords, previousState!, blockWitnesses[block].ScheduleExtension, blockWitnesses[block].RegisterEWitness, blockWitnesses[block].RegisterAWitness, blockWitnesses[block].FinalState);
            }

            previousState = blockWitnesses[block].FinalState;
        }

        AssertZeroPadding(maxBlocks, blockCount, messageBytes);
    }


    /// <summary>
    /// The reference's <c>assert_message_hash</c>: asserts the block chain via <see cref="AssertMessage"/>
    /// and the resulting hash via <see cref="AssertHash"/>.
    /// </summary>
    /// <param name="maxBlocks">The block capacity (the reference's <c>max</c>).</param>
    /// <param name="blockCount">The witnessed occupied-block count, 8 bits (the reference's <c>nb</c>).</param>
    /// <param name="messageBytes">The padded message, one byte-vector per byte (the reference's <c>in</c>).</param>
    /// <param name="target">The claimed hash, 256 bits (the reference's <c>target</c>).</param>
    /// <param name="blockWitnesses">The per-block witnesses (the reference's <c>bw</c>).</param>
    public void AssertMessageHash(int maxBlocks, LongfellowBitWire[] blockCount, LongfellowBitWire[][] messageBytes, LongfellowBitWire[] target, LongfellowFlatSha256PackedBlockWitness[] blockWitnesses)
    {
        AssertMessage(maxBlocks, blockCount, messageBytes, blockWitnesses);
        AssertHash(maxBlocks, target, blockCount, blockWitnesses);
    }


    /// <summary>
    /// The reference's <c>assert_hash</c>: selects the occupied-block-count-th block's final state via
    /// a one-hot accumulation over <paramref name="blockCount"/>, then unpacks it into a 256-bit value
    /// in REVERSE word order (word 0 lands in the top 32 bits of the target comparison) and asserts it
    /// equals <paramref name="target"/>.
    /// </summary>
    /// <param name="maxBlocks">The block capacity (the reference's <c>max</c>).</param>
    /// <param name="target">The claimed hash, 256 bits (the reference's <c>e</c>).</param>
    /// <param name="blockCount">The witnessed occupied-block count, 8 bits (the reference's <c>nb</c>).</param>
    /// <param name="blockWitnesses">The per-block witnesses (the reference's <c>bw</c>).</param>
    public void AssertHash(int maxBlocks, LongfellowBitWire[] target, LongfellowBitWire[] blockCount, LongfellowFlatSha256PackedBlockWitness[] blockWitnesses)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(blockCount);
        ArgumentNullException.ThrowIfNull(blockWitnesses);

        var accumulated = new int[StateWordCount][];
        for(int i = 0; i < StateWordCount; i++)
        {
            accumulated[i] = new int[plucker.PackedV32ElementCount];
        }

        for(int block = 0; block < maxBlocks; block++)
        {
            LongfellowBitWire isLastOccupiedBlock = logic.Equal(blockCount, (ulong)(block + 1));
            int selector = logic.Eval(isLastOccupiedBlock);
            for(int i = 0; i < StateWordCount; i++)
            {
                for(int k = 0; k < plucker.PackedV32ElementCount; k++)
                {
                    int maybeSha = backend.Mul(selector, blockWitnesses[block].FinalState[i][k]);
                    accumulated[i][k] = block == 0 ? maybeSha : backend.Add(accumulated[i][k], maybeSha);
                }
            }
        }

        var reconstructedHash = new LongfellowBitWire[HashBitWidth];
        for(int j = 0; j < StateWordCount; j++)
        {
            LongfellowBitWire[] word = plucker.UnpackV32(accumulated[j]);
            for(int k = 0; k < LongfellowLogic.BitWidth32; k++)
            {
                reconstructedHash[((StateWordCount - 1 - j) * LongfellowLogic.BitWidth32) + k] = word[k];
            }
        }

        logic.AssertEqual(reconstructedHash, target);
    }


    /// <summary>
    /// The reference's <c>assert_zero_padding</c>: asserts that every block at or beyond
    /// <paramref name="blockCount"/> is entirely zero bytes.
    /// </summary>
    /// <param name="maxBlocks">The block capacity (the reference's <c>max</c>).</param>
    /// <param name="blockCount">The witnessed occupied-block count, 8 bits (the reference's <c>nb</c>).</param>
    /// <param name="messageBytes">The padded message, one byte-vector per byte (the reference's <c>in</c>).</param>
    public void AssertZeroPadding(int maxBlocks, LongfellowBitWire[] blockCount, LongfellowBitWire[][] messageBytes)
    {
        ArgumentNullException.ThrowIfNull(blockCount);
        ArgumentNullException.ThrowIfNull(messageBytes);

        for(int block = 0; block < maxBlocks; block++)
        {
            LongfellowBitWire wantZero = logic.LessThanOrEqual(blockCount, (ulong)block);
            for(int j = 0; j < BytesPerBlock; j++)
            {
                int index = (block * BytesPerBlock) + j;
                LongfellowBitWire isZero = logic.Equal(messageBytes[index], 0UL);
                logic.AssertImplies(wantZero, isZero);
            }
        }
    }


    /// <summary>
    /// The reference's <c>find_len_bits</c>: recovers the 64-bit big-endian bit-length field from the last 8
    /// bytes of the occupied-block-count-th block (a one-hot selection over <paramref name="blockCount"/>,
    /// exactly as <see cref="AssertHash"/> selects the final state), then asserts every recovered bit is
    /// genuinely a bit.
    /// </summary>
    /// <param name="maxBlocks">The block capacity (the reference's <c>max</c>).</param>
    /// <param name="messageBytes">The padded message, one byte-vector per byte (the reference's <c>in</c>).</param>
    /// <param name="blockCount">The witnessed occupied-block count, 8 bits (the reference's <c>nb</c>).</param>
    /// <returns>The recovered 64-bit bit length, least significant bit first.</returns>
    public LongfellowBitWire[] FindLength(int maxBlocks, LongfellowBitWire[][] messageBytes, LongfellowBitWire[] blockCount)
    {
        ArgumentNullException.ThrowIfNull(messageBytes);
        ArgumentNullException.ThrowIfNull(blockCount);

        LongfellowBitWire[] length = logic.BitVector(LongfellowLogic.BitWidth64, 0UL);
        for(int block = 0; block < maxBlocks; block++)
        {
            LongfellowBitWire isBlock = logic.Equal(blockCount, (ulong)(block + 1));
            int lastByteIndex = (block * BytesPerBlock) + (BytesPerBlock - 1);
            for(int j = 0; j < LongfellowLogic.BitWidth64; j++)
            {
                LongfellowBitWire byteBit = messageBytes[lastByteIndex - (j / LongfellowLogic.BitWidth8)][j % LongfellowLogic.BitWidth8];
                length[j] = logic.OrExclusive(length[j], logic.And(isBlock, byteBit));
            }
        }

        logic.AssertIsBit(length);

        return length;
    }


    /// <summary>The reference's <c>initial_context</c>: the 8 initial hash-state words as bit vectors.</summary>
    /// <returns>The initial context, 8 32-bit words.</returns>
    private LongfellowBitWire[][] InitialContext()
    {
        var context = new LongfellowBitWire[StateWordCount][];
        for(int i = 0; i < StateWordCount; i++)
        {
            context[i] = logic.BitVector(LongfellowLogic.BitWidth32, LongfellowSha256Constants.InitialHash[i]);
        }

        return context;
    }


    /// <summary>The reference's <c>Sigma0</c> (FIPS 180-4 section 4.1.2's uppercase Σ0).</summary>
    /// <param name="x">The operand, 32 bits.</param>
    /// <returns>The rotated exclusive-or.</returns>
    private LongfellowBitWire[] BigSigma0(LongfellowBitWire[] x) =>
        logic.Xor(LongfellowLogic.RotateRight(x, 2), LongfellowLogic.RotateRight(x, 13), LongfellowLogic.RotateRight(x, 22));


    /// <summary>The reference's <c>Sigma1</c> (FIPS 180-4 section 4.1.2's uppercase Σ1).</summary>
    /// <param name="x">The operand, 32 bits.</param>
    /// <returns>The rotated exclusive-or.</returns>
    private LongfellowBitWire[] BigSigma1(LongfellowBitWire[] x) =>
        logic.Xor(LongfellowLogic.RotateRight(x, 6), LongfellowLogic.RotateRight(x, 11), LongfellowLogic.RotateRight(x, 25));


    /// <summary>The reference's <c>sigma0</c> (FIPS 180-4 section 4.1.2's lowercase σ0).</summary>
    /// <param name="x">The operand, 32 bits.</param>
    /// <returns>The rotated and shifted exclusive-or.</returns>
    private LongfellowBitWire[] SmallSigma0(LongfellowBitWire[] x) =>
        logic.Xor(LongfellowLogic.RotateRight(x, 7), LongfellowLogic.RotateRight(x, 18), logic.ShiftRight(x, 3));


    /// <summary>The reference's <c>sigma1</c> (FIPS 180-4 section 4.1.2's lowercase σ1).</summary>
    /// <param name="x">The operand, 32 bits.</param>
    /// <returns>The rotated and shifted exclusive-or.</returns>
    private LongfellowBitWire[] SmallSigma1(LongfellowBitWire[] x) =>
        logic.Xor(LongfellowLogic.RotateRight(x, 17), LongfellowLogic.RotateRight(x, 19), logic.ShiftRight(x, 10));
}

/// <summary>
/// The packed in-circuit record of one SHA-256 block's witness, a faithful port of
/// google/longfellow-zk's <c>FlatSHA256Circuit::BlockWitness</c> (<c>flatsha256_circuit.h</c>): every
/// round value is a packed wire group (<see cref="LongfellowBitPlucker.PackedV32ElementCount"/> wires
/// per 32-bit word) rather than the plain <see cref="uint"/> the witness-side
/// <see cref="LongfellowFlatSha256BlockWitness"/> holds.
/// </summary>
internal sealed class LongfellowFlatSha256PackedBlockWitness
{
    /// <summary>The number of schedule words this witness declares (the reference's <c>outw[48]</c>).</summary>
    private const int ScheduleWordCount = 48;

    /// <summary>The number of compression rounds this witness declares (the reference's <c>oute[64]</c>/<c>outa[64]</c>).</summary>
    private const int RoundCount = 64;

    /// <summary>The number of hash-state words this witness declares (the reference's <c>h1[8]</c>).</summary>
    private const int StateWordCount = 8;

    /// <summary>The 48 packed schedule words <c>w[16..63]</c> (the reference's <c>outw</c>).</summary>
    public int[][] ScheduleExtension { get; }

    /// <summary>The 64 packed per-round values of register <c>e</c> (the reference's <c>oute</c>).</summary>
    public int[][] RegisterEWitness { get; }

    /// <summary>The 64 packed per-round values of register <c>a</c> (the reference's <c>outa</c>).</summary>
    public int[][] RegisterAWitness { get; }

    /// <summary>The block's packed final hash state, 8 words (the reference's <c>h1</c>).</summary>
    public int[][] FinalState { get; }


    /// <summary>
    /// Constructs the witness, allocating its four fixed-size wire-array tables; <see cref="Input"/>
    /// fills them with freshly declared packed witness wires.
    /// </summary>
    public LongfellowFlatSha256PackedBlockWitness()
    {
        ScheduleExtension = new int[ScheduleWordCount][];
        RegisterEWitness = new int[RoundCount][];
        RegisterAWitness = new int[RoundCount][];
        FinalState = new int[StateWordCount][];
    }


    /// <summary>
    /// The reference's <c>BlockWitness::input</c>: declares this block's packed witness wires in the
    /// reference's exact order — the schedule extension, then the per-round registers interleaved
    /// (<c>e</c> then <c>a</c> at each round), then the final state.
    /// </summary>
    /// <param name="circuit">The gadget whose <see cref="LongfellowFlatSha256Circuit.PackedInputV32"/> declares each packed word.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="circuit"/> is <see langword="null"/>.</exception>
    public void Input(LongfellowFlatSha256Circuit circuit)
    {
        ArgumentNullException.ThrowIfNull(circuit);

        for(int k = 0; k < ScheduleWordCount; k++)
        {
            ScheduleExtension[k] = circuit.PackedInputV32();
        }

        for(int k = 0; k < RoundCount; k++)
        {
            RegisterEWitness[k] = circuit.PackedInputV32();
            RegisterAWitness[k] = circuit.PackedInputV32();
        }

        for(int k = 0; k < StateWordCount; k++)
        {
            FinalState[k] = circuit.PackedInputV32();
        }
    }
}

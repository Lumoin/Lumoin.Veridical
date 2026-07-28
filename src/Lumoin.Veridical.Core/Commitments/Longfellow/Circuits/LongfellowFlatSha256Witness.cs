using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// The out-of-circuit witness generator for <see cref="LongfellowFlatSha256Circuit"/>, a faithful
/// port of google/longfellow-zk's <c>FlatSHA256Witness</c> (<c>flatsha256_witness.{h,cc}</c>): plain
/// <see cref="uint"/> arithmetic that both computes the SHA-256 hash and records the intermediate
/// round values (<see cref="LongfellowFlatSha256BlockWitness"/>) the flattened in-circuit gadget
/// later asserts against. This type carries no dependency on <see cref="LongfellowLogic"/> or any
/// field-operation bundle, matching the reference's own header, which includes neither.
/// </summary>
internal static class LongfellowFlatSha256Witness
{
    /// <summary>The number of 32-bit words in one SHA-256 message block (the reference's <c>in[16]</c>).</summary>
    private const int InputWordCount = 16;

    /// <summary>The number of compression rounds, and the length of the schedule array <c>w</c> (the reference's <c>w[64]</c>).</summary>
    private const int RoundCount = 64;

    /// <summary>The byte width of one SHA-256 block.</summary>
    private const int BytesPerBlock = 64;

    /// <summary>The byte width of one 32-bit word.</summary>
    private const int BytesPerWord = 4;

    /// <summary>The number of bits in one byte, the scale factor between a byte count and a bit count in the length field.</summary>
    private const int BitsPerByte = 8;

    /// <summary>The padding overhead in bytes the reference's <c>ceildiv(n + 9, 64)</c> accounts for: one <c>0x80</c> marker byte plus the 8-byte big-endian bit-length field.</summary>
    private const int PaddingOverheadBytes = 9;

    /// <summary>The SHA-256 padding marker byte appended immediately after the message (FIPS 180-4 section 5.1.1).</summary>
    private const byte PaddingMarkerByte = 0x80;

    /// <summary>The byte offset, within a 64-byte block, where the 8-byte big-endian bit-length field begins (FIPS 180-4 section 5.1.1).</summary>
    private const int LengthFieldOffset = 56;

    /// <summary>
    /// The reference's <c>SHA256_ru32be</c>: reads four bytes as a big-endian 32-bit word, one byte
    /// shifted in at a time exactly as the reference's loop does, rather than through a bulk
    /// big-endian read primitive.
    /// </summary>
    /// <param name="source">The bytes to read; at least <see cref="BytesPerWord"/> long.</param>
    /// <returns>The big-endian word.</returns>
    public static uint ReadUInt32BigEndian(ReadOnlySpan<byte> source)
    {
        uint value = 0;
        for(int i = 0; i < BytesPerWord; i++)
        {
            value = (value << BitsPerByte) + source[i];
        }

        return value;
    }

    /// <summary>
    /// The reference's <c>transform_and_witness_block</c>: runs the SHA-256 compression function over
    /// one message block in plain <see cref="uint"/> arithmetic (wrapping modulo 2^32, matching the
    /// reference's <c>uint32_t</c> overflow), recording the schedule extension and the per-round
    /// register witnesses the in-circuit gadget later asserts against.
    /// </summary>
    /// <param name="blockWords">The block's 16 message words (the reference's <c>in</c>).</param>
    /// <param name="initialState">The compression's initial state, 8 words (the reference's <c>H0</c>).</param>
    /// <param name="scheduleExtension">Receives the 48 schedule words <c>w[16..63]</c> (the reference's <c>outw</c>).</param>
    /// <param name="registerEWitness">Receives the 64 per-round values of register <c>e</c> (the reference's <c>oute</c>).</param>
    /// <param name="registerAWitness">Receives the 64 per-round values of register <c>a</c> (the reference's <c>outa</c>).</param>
    /// <param name="finalState">Receives the compression's final state, 8 words (the reference's <c>H1</c>).</param>
    public static void TransformAndWitnessBlock(
        ReadOnlySpan<uint> blockWords,
        ReadOnlySpan<uint> initialState,
        Span<uint> scheduleExtension,
        Span<uint> registerEWitness,
        Span<uint> registerAWitness,
        Span<uint> finalState)
    {
        Span<uint> w = stackalloc uint[RoundCount];
        for(int i = 0; i < InputWordCount; i++)
        {
            w[i] = blockWords[i];
        }

        for(int i = InputWordCount; i < RoundCount; i++)
        {
            w[i] = SmallSigma1(w[i - 2]) + w[i - 7] + SmallSigma0(w[i - 15]) + w[i - 16];
            scheduleExtension[i - InputWordCount] = w[i];
        }

        uint a = initialState[0];
        uint b = initialState[1];
        uint c = initialState[2];
        uint d = initialState[3];
        uint e = initialState[4];
        uint f = initialState[5];
        uint g = initialState[6];
        uint h = initialState[7];

        for(int t = 0; t < RoundCount; t++)
        {
            uint t1 = h + BigSigma1(e) + Choose(e, f, g) + LongfellowSha256Constants.RoundConstants[t] + w[t];
            uint t2 = BigSigma0(a) + Majority(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + t1;
            registerEWitness[t] = e;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
            registerAWitness[t] = a;
        }

        finalState[0] = initialState[0] + a;
        finalState[1] = initialState[1] + b;
        finalState[2] = initialState[2] + c;
        finalState[3] = initialState[3] + d;
        finalState[4] = initialState[4] + e;
        finalState[5] = initialState[5] + f;
        finalState[6] = initialState[6] + g;
        finalState[7] = initialState[7] + h;
    }

    /// <summary>
    /// The reference's <c>transform_and_witness_message</c>: pads <paramref name="message"/> per FIPS
    /// 180-4 section 5.1.1 (a <c>0x80</c> marker, zeros, then the 64-bit big-endian bit length in the
    /// last 8 bytes of its block), then runs <see cref="TransformAndWitnessBlock"/> over every block,
    /// chaining each block's final state into the next block's initial state.
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="maxBlocks">The block capacity of <paramref name="paddedMessage"/> and <paramref name="blockWitnesses"/>; the message plus padding must fit within it.</param>
    /// <param name="occupiedBlockCount">Receives the number of blocks the padded message actually occupies (the reference's <c>numb</c>).</param>
    /// <param name="paddedMessage">Receives the padded message, exactly <c>64 * maxBlocks</c> bytes; any bytes beyond the occupied blocks are zero.</param>
    /// <param name="blockWitnesses">Receives one witness per block, exactly <paramref name="maxBlocks"/> entries.</param>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="maxBlocks"/> is negative.</exception>
    /// <exception cref="ArgumentException">When <paramref name="paddedMessage"/> or <paramref name="blockWitnesses"/> is not exactly the expected length, or when the occupied block count would not fit a <see cref="byte"/>.</exception>
    /// <exception cref="InvalidOperationException">When the padding computation does not land on a block boundary, indicating a broken invariant rather than a caller error.</exception>
    public static void TransformAndWitnessMessage(
        ReadOnlySpan<byte> message,
        int maxBlocks,
        out byte occupiedBlockCount,
        Span<byte> paddedMessage,
        Span<LongfellowFlatSha256BlockWitness> blockWitnesses)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxBlocks);

        if(paddedMessage.Length != BytesPerBlock * maxBlocks)
        {
            throw new ArgumentException($"The padded destination needs exactly {BytesPerBlock * maxBlocks} bytes.", nameof(paddedMessage));
        }

        if(blockWitnesses.Length != maxBlocks)
        {
            throw new ArgumentException($"The block witnesses destination needs exactly {maxBlocks} entries.", nameof(blockWitnesses));
        }

        int n = message.Length;
        int requiredBlocks = CeilingDivide((long)n + PaddingOverheadBytes, BytesPerBlock);
        if(requiredBlocks > byte.MaxValue)
        {
            throw new ArgumentException("The message needs more occupied blocks than the occupied-block count can represent.", nameof(message));
        }

        if(requiredBlocks > maxBlocks)
        {
            throw new ArgumentException($"The message and its padding need {requiredBlocks} blocks but the destination is sized for {maxBlocks}.", nameof(message));
        }

        occupiedBlockCount = (byte)requiredBlocks;

        int index = 0;
        for(int i = 0; i < n; i++, index++)
        {
            paddedMessage[index] = message[i];
        }

        paddedMessage[index++] = PaddingMarkerByte;
        if(index % BytesPerBlock == 0 || index % BytesPerBlock > LengthFieldOffset)
        {
            while(index % BytesPerBlock != 0)
            {
                paddedMessage[index++] = 0;
            }
        }

        while(index % BytesPerBlock < LengthFieldOffset)
        {
            paddedMessage[index++] = 0;
        }

        WriteUInt64BigEndian(paddedMessage.Slice(index, sizeof(ulong)), (ulong)n * BitsPerByte);
        index += sizeof(ulong);

        if(index % BytesPerBlock != 0)
        {
            throw new InvalidOperationException("The SHA-256 padding computation did not land on a block boundary.");
        }

        while(index < BytesPerBlock * maxBlocks)
        {
            paddedMessage[index++] = 0;
        }

        Span<uint> blockWords = stackalloc uint[InputWordCount];
        ReadOnlySpan<uint> state = LongfellowSha256Constants.InitialHash;
        for(int block = 0; block < maxBlocks; block++)
        {
            for(int i = 0; i < InputWordCount; i++)
            {
                blockWords[i] = ReadUInt32BigEndian(paddedMessage.Slice((block * BytesPerBlock) + (i * BytesPerWord), BytesPerWord));
            }

            blockWitnesses[block] = new LongfellowFlatSha256BlockWitness();
            TransformAndWitnessBlock(blockWords, state, blockWitnesses[block].ScheduleExtension, blockWitnesses[block].RegisterEWitness, blockWitnesses[block].RegisterAWitness, blockWitnesses[block].FinalState);
            state = blockWitnesses[block].FinalState;
        }
    }

    /// <summary>The reference's <c>rotr</c>: a 32-bit rotation right.</summary>
    /// <param name="value">The value to rotate.</param>
    /// <param name="amount">The rotation amount.</param>
    /// <returns>The rotated value.</returns>
    private static uint RotateRight(uint value, int amount)
    {
        const int WordBitWidth = 32;

        return (value >> amount) | (value << (WordBitWidth - amount));
    }

    /// <summary>The reference's <c>shr</c>: a logical shift right.</summary>
    /// <param name="value">The value to shift.</param>
    /// <param name="amount">The shift amount.</param>
    /// <returns>The shifted value.</returns>
    private static uint ShiftRight(uint value, int amount) => value >> amount;

    /// <summary>The reference's <c>Ch</c>: <c>(x &amp; y) ^ (~x &amp; z)</c>.</summary>
    /// <param name="x">The selector.</param>
    /// <param name="y">The value chosen when <paramref name="x"/>'s bit is set.</param>
    /// <param name="z">The value chosen when <paramref name="x"/>'s bit is clear.</param>
    /// <returns>The choice.</returns>
    private static uint Choose(uint x, uint y, uint z) => (x & y) ^ (~x & z);

    /// <summary>The reference's <c>Maj</c>: <c>(x &amp; y) ^ (x &amp; z) ^ (y &amp; z)</c>.</summary>
    /// <param name="x">The first operand.</param>
    /// <param name="y">The second operand.</param>
    /// <param name="z">The third operand.</param>
    /// <returns>The majority.</returns>
    private static uint Majority(uint x, uint y, uint z) => (x & y) ^ (x & z) ^ (y & z);

    /// <summary>The reference's <c>Sigma0</c> (FIPS 180-4 section 4.1.2's uppercase Σ0).</summary>
    /// <param name="x">The operand.</param>
    /// <returns>The rotated exclusive-or.</returns>
    private static uint BigSigma0(uint x) => RotateRight(x, 2) ^ RotateRight(x, 13) ^ RotateRight(x, 22);

    /// <summary>The reference's <c>Sigma1</c> (FIPS 180-4 section 4.1.2's uppercase Σ1).</summary>
    /// <param name="x">The operand.</param>
    /// <returns>The rotated exclusive-or.</returns>
    private static uint BigSigma1(uint x) => RotateRight(x, 6) ^ RotateRight(x, 11) ^ RotateRight(x, 25);

    /// <summary>The reference's <c>sigma0</c> (FIPS 180-4 section 4.1.2's lowercase σ0).</summary>
    /// <param name="x">The operand.</param>
    /// <returns>The rotated and shifted exclusive-or.</returns>
    private static uint SmallSigma0(uint x) => RotateRight(x, 7) ^ RotateRight(x, 18) ^ ShiftRight(x, 3);

    /// <summary>The reference's <c>sigma1</c> (FIPS 180-4 section 4.1.2's lowercase σ1).</summary>
    /// <param name="x">The operand.</param>
    /// <returns>The rotated and shifted exclusive-or.</returns>
    private static uint SmallSigma1(uint x) => RotateRight(x, 17) ^ RotateRight(x, 19) ^ ShiftRight(x, 10);

    /// <summary>The reference's <c>SHA256_wu64be</c>: writes a 64-bit value as 8 big-endian bytes.</summary>
    /// <param name="destination">Receives the 8 bytes.</param>
    /// <param name="value">The value to write.</param>
    private static void WriteUInt64BigEndian(Span<byte> destination, ulong value)
    {
        const int ByteMask = 0xff;

        for(int i = 0; i < sizeof(ulong); i++)
        {
            destination[7 - i] = (byte)((value >> (BitsPerByte * i)) & ByteMask);
        }
    }

    /// <summary>The reference's <c>ceildiv</c>: the ceiling of <paramref name="numerator"/> divided by <paramref name="denominator"/>.</summary>
    /// <param name="numerator">The numerator; widened so the addition of the padding overhead to a maximum-length span cannot overflow.</param>
    /// <param name="denominator">The denominator.</param>
    /// <returns>The ceiling quotient.</returns>
    private static int CeilingDivide(long numerator, int denominator) => (int)((numerator / denominator) + (numerator % denominator == 0 ? 0 : 1));
}

/// <summary>
/// The plain-<see cref="uint"/> record of one SHA-256 block's compression, a faithful port of
/// google/longfellow-zk's <c>FlatSHA256Witness::BlockWitness</c> (<c>flatsha256_witness.h</c>): the
/// witness-side counterpart to <see cref="LongfellowFlatSha256PackedBlockWitness"/>, which holds the
/// same shape of values as in-circuit wires instead of raw integers.
/// </summary>
internal readonly struct LongfellowFlatSha256BlockWitness
{
    /// <summary>The number of schedule words this witness records (the reference's <c>outw[48]</c>).</summary>
    private const int ScheduleWordCount = 48;

    /// <summary>The number of compression rounds this witness records (the reference's <c>oute[64]</c>/<c>outa[64]</c>).</summary>
    private const int RoundCount = 64;

    /// <summary>The number of hash-state words this witness records (the reference's <c>h1[8]</c>).</summary>
    private const int StateWordCount = 8;

    /// <summary>The 48 schedule words <c>w[16..63]</c> (the reference's <c>outw</c>).</summary>
    public uint[] ScheduleExtension { get; }

    /// <summary>The 64 per-round values of register <c>e</c> (the reference's <c>oute</c>).</summary>
    public uint[] RegisterEWitness { get; }

    /// <summary>The 64 per-round values of register <c>a</c> (the reference's <c>outa</c>).</summary>
    public uint[] RegisterAWitness { get; }

    /// <summary>The block's final hash state, 8 words (the reference's <c>h1</c>).</summary>
    public uint[] FinalState { get; }


    /// <summary>
    /// Constructs the witness, allocating its four fixed-size arrays. Array-of-struct allocation in
    /// .NET bypasses a value type's parameterless constructor, so callers filling a
    /// <see cref="Span{T}"/> of these witnesses must assign a freshly constructed instance to each
    /// element before writing into its arrays, exactly as <see cref="LongfellowFlatSha256Witness.TransformAndWitnessMessage"/>
    /// does.
    /// </summary>
    public LongfellowFlatSha256BlockWitness()
    {
        ScheduleExtension = new uint[ScheduleWordCount];
        RegisterEWitness = new uint[RoundCount];
        RegisterAWitness = new uint[RoundCount];
        FinalState = new uint[StateWordCount];
    }
}

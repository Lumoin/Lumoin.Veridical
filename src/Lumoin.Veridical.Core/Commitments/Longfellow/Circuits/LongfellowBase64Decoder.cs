using System;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;

/// <summary>
/// Asserts a base64url decoding in-circuit, a faithful port of google/longfellow-zk's
/// <c>Base64Decoder&lt;Logic&gt;</c> (<c>circuits/tests/base64/decode.h</c>): each input byte maps
/// through espresso-minimized sum-of-products covers to its six-bit symbol value plus an invalid
/// flag, and four-symbol groups repack into three output bytes. The alphabet is the URL-safe,
/// unpadded one (<c>A–Z a–z 0–9 - _</c>, values 0–63); the padding character <c>=</c> counts as
/// invalid, matching the SD-JWT convention the statement circuits rely on.
/// </summary>
/// <remarks>
/// The covers are transcribed from the reference's <c>decode</c> tables (themselves generated from
/// <c>base64.espresso</c>) as bit-mask pairs: a clause is the conjunction of <c>in[b]</c> for every
/// bit set in the positive mask and <c>NOT in[b]</c> for every bit set in the negative mask, with
/// literals emitted from bit seven downward — the order every reference clause lists them in — so
/// the emitted gate structure matches the reference clause for clause.
/// </remarks>
internal sealed class LongfellowBase64Decoder
{
    private const int InputBitWidth = 8;
    private const int SymbolBitWidth = 6;

    //The reference's overflow guard on n·6 index arithmetic.
    private const int MaxInputCount = 1 << 28;

    //Four six-bit symbols repack into three bytes per group.
    private const int SymbolsPerGroup = 4;
    private const int BytesPerGroup = 3;
    private const int BitsPerGroup = SymbolsPerGroup * SymbolBitWidth;

    private readonly LongfellowLogic logic;

    /// <summary>
    /// One espresso product term: the conjunction of the input bits set in
    /// <see cref="PositiveMask"/> and the negated input bits set in <see cref="NegativeMask"/>.
    /// </summary>
    /// <param name="PositiveMask">The plain-literal bit mask.</param>
    /// <param name="NegativeMask">The negated-literal bit mask.</param>
    private readonly record struct ProductTerm(byte PositiveMask, byte NegativeMask);

    /// <summary>
    /// The reference's seven covers in declaration order: index zero is the invalid flag, indices
    /// one through six are output bits five down to zero. Each clause's masks transcribe the
    /// reference's literal list verbatim.
    /// </summary>
    private static ProductTerm[][] Covers { get; } =
    [
        //exp[0], the invalid flag.
        [
            new ProductTerm(0x00, 0x1F), //['!v4','!v3','!v2','!v1','!v0']
            new ProductTerm(0x1B, 0x04), //['v4','v3','!v2','v1','v0']
            new ProductTerm(0x3B, 0x00), //['v5','v4','v3','v1','v0']
            new ProductTerm(0x0C, 0x41), //['!v6','v3','v2','!v0']
            new ProductTerm(0x1C, 0x02), //['v4','v3','v2','!v1']
            new ProductTerm(0x1C, 0x01), //['v4','v3','v2','!v0']
            new ProductTerm(0x00, 0x58), //['!v6','!v4','!v3']
            new ProductTerm(0x00, 0x54), //['!v6','!v4','!v2']
            new ProductTerm(0x0A, 0x40), //['!v6','v3','v1']
            new ProductTerm(0x00, 0x60), //['!v6','!v5']
            new ProductTerm(0x80, 0x00), //['v7']
        ],
        //exp[1], output bit five.
        [
            new ProductTerm(0x70, 0x0C), //['v6','v5','v4','!v3','!v2']
            new ProductTerm(0x70, 0x09), //['v6','v5','v4','!v3','!v0']
            new ProductTerm(0x74, 0x02), //['v6','v5','v4','v2','!v1']
            new ProductTerm(0x27, 0x00), //['v5','v2','v1','v0']
            new ProductTerm(0x1B, 0x00), //['v4','v3','v1','v0']
            new ProductTerm(0x28, 0x00), //['v5','v3']
            new ProductTerm(0x00, 0x44), //['!v6','!v2']
            new ProductTerm(0x04, 0x40), //['!v6','v2']
        ],
        //exp[2], output bit four.
        [
            new ProductTerm(0x20, 0x1A), //['v5','!v4','!v3','!v1']
            new ProductTerm(0x20, 0x1C), //['v5','!v4','!v3','!v2']
            new ProductTerm(0x12, 0x20), //['!v5','v4','v1']
            new ProductTerm(0x20, 0x19), //['v5','!v4','!v3','!v0']
            new ProductTerm(0x17, 0x00), //['v4','v2','v1','v0']
            new ProductTerm(0x11, 0x20), //['!v5','v4','v0']
            new ProductTerm(0x14, 0x20), //['!v5','v4','v2']
            new ProductTerm(0x18, 0x00), //['v4','v3']
            new ProductTerm(0x00, 0x44), //['!v6','!v2']
            new ProductTerm(0x04, 0x40), //['!v6','v2']
        ],
        //exp[3], output bit three.
        [
            new ProductTerm(0x40, 0x0F), //['v6','!v3','!v2','!v1','!v0']
            new ProductTerm(0x70, 0x0C), //['v6','v5','v4','!v3','!v2']
            new ProductTerm(0x70, 0x09), //['v6','v5','v4','!v3','!v0']
            new ProductTerm(0x74, 0x02), //['v6','v5','v4','v2','!v1']
            new ProductTerm(0x20, 0x1A), //['v5','!v4','!v3','!v1']
            new ProductTerm(0x20, 0x1C), //['v5','!v4','!v3','!v2']
            new ProductTerm(0x20, 0x19), //['v5','!v4','!v3','!v0']
            new ProductTerm(0x0A, 0x20), //['!v5','v3','v1']
            new ProductTerm(0x0F, 0x00), //['v3','v2','v1','v0']
            new ProductTerm(0x09, 0x20), //['!v5','v3','v0']
            new ProductTerm(0x0C, 0x20), //['!v5','v3','v2']
            new ProductTerm(0x08, 0x40), //['!v6','v3']
            new ProductTerm(0x04, 0x40), //['!v6','v2']
        ],
        //exp[4], output bit two.
        [
            new ProductTerm(0x25, 0x12), //['v5','!v4','v2','!v1','v0']
            new ProductTerm(0x74, 0x02), //['v6','v5','v4','v2','!v1']
            new ProductTerm(0x00, 0x27), //['!v5','!v2','!v1','!v0']
            new ProductTerm(0x64, 0x01), //['v6','v5','v2','!v0']
            new ProductTerm(0x23, 0x04), //['v5','!v2','v1','v0']
            new ProductTerm(0x05, 0x20), //['!v5','v2','v0']
            new ProductTerm(0x06, 0x20), //['!v5','v2','v1']
            new ProductTerm(0x00, 0x44), //['!v6','!v2']
        ],
        //exp[5], output bit one.
        [
            new ProductTerm(0x25, 0x12), //['v5','!v4','v2','!v1','v0']
            new ProductTerm(0x61, 0x02), //['v6','v5','!v1','v0']
            new ProductTerm(0x00, 0x23), //['!v5','!v1','!v0']
            new ProductTerm(0x03, 0x20), //['!v5','v1','v0']
            new ProductTerm(0x22, 0x01), //['v5','v1','!v0']
            new ProductTerm(0x02, 0x40), //['!v6','v1']
        ],
        //exp[6], output bit zero.
        [
            new ProductTerm(0x1B, 0x00), //['v4','v3','v1','v0']
            new ProductTerm(0x11, 0x40), //['!v6','v4','v0']
            new ProductTerm(0x40, 0x01), //['v6','!v0']
        ],
    ];


    /// <summary>
    /// Constructs the gadget over a gadget layer.
    /// </summary>
    /// <param name="logic">The gadget layer every cover builds on.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="logic"/> is <see langword="null"/>.</exception>
    public LongfellowBase64Decoder(LongfellowLogic logic)
    {
        ArgumentNullException.ThrowIfNull(logic);

        this.logic = logic;
    }


    /// <summary>
    /// The reference's asserting <c>decode</c>: maps one input byte to its six-bit symbol and
    /// asserts the byte is a valid alphabet character.
    /// </summary>
    /// <param name="input">The input byte's bits, least significant first.</param>
    /// <param name="output">Receives the symbol's bits, least significant first.</param>
    public void Decode(LongfellowBitWire[] input, LongfellowBitWire[] output)
    {
        Decode(input, output, out LongfellowBitWire invalid);
        _ = logic.AssertZero(invalid);
    }


    /// <summary>
    /// The reference's flag-reporting <c>decode</c>: maps one input byte to its six-bit symbol and
    /// reports validity through <paramref name="invalid"/> instead of asserting it, so a caller can
    /// gate the assertion on a length predicate.
    /// </summary>
    /// <param name="input">The input byte's bits, least significant first.</param>
    /// <param name="output">Receives the symbol's bits, least significant first.</param>
    /// <param name="invalid">Receives the bit that is one exactly when the byte is not in the alphabet.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="input"/> or <paramref name="output"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When either bit vector has the wrong width.</exception>
    public void Decode(LongfellowBitWire[] input, LongfellowBitWire[] output, out LongfellowBitWire invalid)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);

        if(input.Length != InputBitWidth || output.Length != SymbolBitWidth)
        {
            throw new ArgumentException($"The decoder maps {InputBitWidth} input bits to {SymbolBitWidth} symbol bits.");
        }

        var negated = new LongfellowBitWire[InputBitWidth];
        for(int i = 0; i < InputBitWidth; i++)
        {
            negated[i] = logic.Not(input[i]);
        }

        invalid = logic.OrOfAnd(BuildClauses(Covers[0], input, negated));
        for(int i = 0; i < SymbolBitWidth; i++)
        {
            output[SymbolBitWidth - 1 - i] = logic.OrOfAnd(BuildClauses(Covers[i + 1], input, negated));
        }
    }


    /// <summary>
    /// The reference's <c>base64_rawurl_decode</c>: decodes <paramref name="count"/> input bytes in
    /// four-symbol groups, asserting every byte valid, and repacks the symbols into the output's
    /// leading <c>ceil(count·6/8)</c> bytes. Output bytes beyond that prefix are left untouched.
    /// </summary>
    /// <param name="inputs">The input bytes as eight-bit vectors, least significant bit first.</param>
    /// <param name="output">The output bytes as caller-owned eight-bit vectors, most significant bit at index seven.</param>
    /// <param name="count">The input byte count to decode; the inputs array may be longer.</param>
    public void RawUrlDecode(LongfellowBitWire[][] inputs, LongfellowBitWire[][] output, int count)
    {
        GuardShape(inputs, output, count);

        LongfellowBitWire[] zero = logic.BitVector(SymbolBitWidth, 0);
        int decodedByteCount = CeilingDivide(count * SymbolBitWidth, InputBitWidth);

        int outputCursor = 0;
        for(int i = 0; i < count; i += SymbolsPerGroup, outputCursor += BytesPerGroup)
        {
            var group = NewGroup(zero);
            for(int j = 0; j < SymbolsPerGroup && i + j < count; j++)
            {
                Decode(inputs[i + j], group[j]);
            }

            Repack(group, output, outputCursor, decodedByteCount);
        }
    }


    /// <summary>
    /// The reference's <c>base64_rawurl_decode_len</c>: decodes like
    /// <see cref="RawUrlDecode"/> but with a wire-valued length — validity is asserted only for
    /// input positions below <paramref name="length"/>, so the region past the genuine payload may
    /// hold arbitrary bytes without making the circuit unsatisfiable.
    /// </summary>
    /// <param name="inputs">The input bytes as eight-bit vectors, least significant bit first.</param>
    /// <param name="output">The output bytes as caller-owned eight-bit vectors, most significant bit at index seven.</param>
    /// <param name="count">The input byte count to decode; the inputs array may be longer.</param>
    /// <param name="length">The wire-valued genuine input length's bits, least significant first.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="length"/> is <see langword="null"/>.</exception>
    public void RawUrlDecodeWithLength(LongfellowBitWire[][] inputs, LongfellowBitWire[][] output, int count, LongfellowBitWire[] length)
    {
        GuardShape(inputs, output, count);
        ArgumentNullException.ThrowIfNull(length);

        LongfellowBitWire[] zero = logic.BitVector(SymbolBitWidth, 0);
        int decodedByteCount = CeilingDivide(count * SymbolBitWidth, InputBitWidth);

        int outputCursor = 0;
        for(int i = 0; i < count; i += SymbolsPerGroup, outputCursor += BytesPerGroup)
        {
            var group = NewGroup(zero);
            for(int j = 0; j < SymbolsPerGroup && i + j < count; j++)
            {
                Decode(inputs[i + j], group[j], out LongfellowBitWire invalid);
                LongfellowBitWire inRange = logic.LessThan((ulong)(i + j), length);
                _ = logic.AssertImplies(inRange, logic.Not(invalid));
            }

            Repack(group, output, outputCursor, decodedByteCount);
        }
    }


    /// <summary>Builds one cover's clause arrays: per clause, the plain and negated literals from bit seven downward, the order the reference tables list them in.</summary>
    /// <param name="cover">The cover's product terms.</param>
    /// <param name="input">The input byte's bits.</param>
    /// <param name="negated">The input byte's negated bits.</param>
    /// <returns>The clause arrays for <see cref="LongfellowLogic.OrOfAnd"/>.</returns>
    private static LongfellowBitWire[][] BuildClauses(ProductTerm[] cover, LongfellowBitWire[] input, LongfellowBitWire[] negated)
    {
        var clauses = new LongfellowBitWire[cover.Length][];
        for(int c = 0; c < cover.Length; c++)
        {
            ProductTerm term = cover[c];
            var literals = new LongfellowBitWire[BitOperations.PopCount(term.PositiveMask) + BitOperations.PopCount(term.NegativeMask)];

            int cursor = 0;
            for(int bit = InputBitWidth - 1; bit >= 0; bit--)
            {
                if((term.PositiveMask & (1 << bit)) != 0)
                {
                    literals[cursor] = input[bit];
                    cursor++;
                }

                if((term.NegativeMask & (1 << bit)) != 0)
                {
                    literals[cursor] = negated[bit];
                    cursor++;
                }
            }

            clauses[c] = literals;
        }

        return clauses;
    }


    /// <summary>The reference's repack loop: scatters a group's four six-bit symbols into up to three output bytes, most significant bit first on both sides, stopping at the decoded prefix's end.</summary>
    /// <param name="group">The group's symbol vectors.</param>
    /// <param name="output">The output bytes.</param>
    /// <param name="outputCursor">The group's first output byte index.</param>
    /// <param name="decodedByteCount">The decoded prefix length bounding the writes.</param>
    private static void Repack(LongfellowBitWire[][] group, LongfellowBitWire[][] output, int outputCursor, int decodedByteCount)
    {
        for(int j = 0; j < BitsPerGroup && outputCursor + (j / InputBitWidth) < decodedByteCount; j++)
        {
            output[outputCursor + (j / InputBitWidth)][InputBitWidth - 1 - (j % InputBitWidth)] = group[j / SymbolBitWidth][SymbolBitWidth - 1 - (j % SymbolBitWidth)];
        }
    }


    /// <summary>Allocates a group of four symbol vectors, each starting as a copy of the constant-zero symbol (the reference's <c>v6 quad[4]{zero, ...}</c>).</summary>
    /// <param name="zero">The constant-zero symbol vector.</param>
    /// <returns>The group.</returns>
    private static LongfellowBitWire[][] NewGroup(LongfellowBitWire[] zero)
    {
        var group = new LongfellowBitWire[SymbolsPerGroup][];
        for(int j = 0; j < SymbolsPerGroup; j++)
        {
            group[j] = (LongfellowBitWire[])zero.Clone();
        }

        return group;
    }


    /// <summary>Validates the shared decode shape bounds.</summary>
    /// <param name="inputs">The input byte vectors.</param>
    /// <param name="output">The output byte vectors.</param>
    /// <param name="count">The input byte count to decode.</param>
    /// <exception cref="ArgumentNullException">When an array is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="count"/> is negative, exceeds the overflow guard, or overruns either array.</exception>
    private static void GuardShape(LongfellowBitWire[][] inputs, LongfellowBitWire[][] output, int count)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(count, MaxInputCount);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, inputs.Length);
        ArgumentOutOfRangeException.ThrowIfLessThan(output.Length, CeilingDivide(count * SymbolBitWidth, InputBitWidth));
    }


    /// <summary>The ceiling of <paramref name="numerator"/> divided by <paramref name="denominator"/> (the reference's <c>ceildiv</c>).</summary>
    /// <param name="numerator">The numerator.</param>
    /// <param name="denominator">The denominator.</param>
    /// <returns>The ceiling quotient.</returns>
    private static int CeilingDivide(int numerator, int denominator)
    {
        return (numerator + denominator - 1) / denominator;
    }
}

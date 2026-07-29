using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Gates for the base64url decoder gadget (<see cref="LongfellowBase64Decoder"/>), the
/// evaluation-half port of google/longfellow-zk's <c>decode_test.cc</c>: the reference's
/// <c>test_each_symbol</c> exhaustive byte sweep (every one of the 256 possible input bytes decodes
/// to its alphabet index with a clear invalid flag, or else latches the flag), plus two gates the
/// reference's <c>test_strings</c> table does not cover on its own — the asserting overload's latch
/// on a single invalid byte, and the wire-valued-length overload's trailing-garbage tolerance versus
/// its full-length latch.
/// </summary>
/// <remarks>
/// The reference sweeps both gates over <c>Fp256Base</c> (this port's <see cref="Fp256Field"/>); the
/// GF(2^128) arm has no counterpart in <c>decode_test.cc</c>, so this port does not add one either.
/// <c>test_strings</c>'s table of whole base64 strings is replaced here by
/// <see cref="TheLengthGatedDecodeIgnoresTrailingGarbage"/>, which exercises the same
/// <c>base64_rawurl_decode</c>/<c>base64_rawurl_decode_len</c> repacking path on a single deterministic
/// string ("QUJD" decodes to "ABC") while additionally covering the wire-valued length the reference's
/// fixed-length table never exercises.
/// </remarks>
[TestClass]
internal sealed class LongfellowBase64DecoderTests
{
    /// <summary>The decoder's fixed six-bit symbol width.</summary>
    private const int SymbolBitWidth = 6;

    /// <summary>The input byte range the reference's <c>test_each_symbol</c> sweeps exhaustively.</summary>
    private const int ByteValueCount = 256;

    /// <summary>The reference's URL-safe, unpadded base64 alphabet, index order defining each symbol's six-bit value.</summary>
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// <summary>The padding character, deliberately outside <see cref="Alphabet"/>, that the asserting-overload latch gate decodes.</summary>
    private const char PaddingCharacter = '=';

    /// <summary>A genuine alphabet character the asserting-overload latch gate decodes on a fresh backend, to pin that the latch stays clear on valid input.</summary>
    private const char ValidCharacter = 'A';

    /// <summary>"QUJD####"'s total byte count fed to the length-gated decode.</summary>
    private const int LengthGatedInputByteCount = 8;

    /// <summary><c>ceil(8 * 6 / 8)</c>: the decoded byte count the length-gated decode's output prefix covers.</summary>
    private const int LengthGatedDecodedByteCount = 6;

    /// <summary>The genuine payload length ("QUJD" is four symbols) the trailing-garbage-tolerant gate claims.</summary>
    private const int LengthGatedGenuineLength = 4;

    /// <summary>The bit width of the wire-valued length: four bits comfortably covers both <see cref="LengthGatedGenuineLength"/> and <see cref="LengthGatedInputByteCount"/>.</summary>
    private const int LengthWireBitWidth = 4;

    /// <summary>"ABC", the three-byte prefix the length-gated decode's output must spell when only the genuine length is claimed.</summary>
    private static byte[] ExpectedDecodedPrefix { get; } = [0x41, 0x42, 0x43];

    /// <summary>"QUJD", the base64url encoding of "ABC", padded with four trailing '#' bytes outside the genuine payload.</summary>
    private static byte[] LengthGatedInputBytes { get; } = "QUJD####"u8.ToArray();

    /// <summary>The P-256 base field's modulus-minus-one, canonical big-endian, used to construct <see cref="Fp256Field"/>.</summary>
    private static ReadOnlyMemory<byte> Fp256MinusOne { get; } = BuildFp256MinusOne();

    /// <summary>The P-256 base field bundle gated over by every test in this class.</summary>
    private static LongfellowLogicFieldOperations Fp256Field { get; } = LongfellowLogicFieldOperations.CreateFp256(
        P256BaseFieldReference.GetAdd(),
        P256BaseFieldReference.GetSubtract(),
        P256BaseFieldReference.GetMultiply(),
        P256BaseFieldReference.GetInvert(),
        Fp256MinusOne);


    /// <summary>Pins that every one of the 256 possible input bytes decodes to its alphabet index with a clear invalid flag, or else latches the invalid flag.</summary>
    [TestMethod]
    public void EveryByteDecodesToItsAlphabetValue()
    {
        var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        for(int b = 0; b < ByteValueCount; b++)
        {
            LongfellowBitWire[] input = logic.BitVector(LongfellowLogic.BitWidth8, (ulong)b);
            var output = new LongfellowBitWire[SymbolBitWidth];

            decoder.Decode(input, output, out LongfellowBitWire invalid);

            int alphabetIndex = Alphabet.IndexOf((char)b, StringComparison.Ordinal);
            if(alphabetIndex >= 0)
            {
                Assert.IsTrue(LongfellowCompilerFieldOperations.ElementIsZero(EvaluatedBytes(logic, logic.Eval(invalid))), $"Byte {b} is in the alphabet, so the invalid flag must evaluate to zero.");

                for(int bit = 0; bit < SymbolBitWidth; bit++)
                {
                    int expectedBit = (alphabetIndex >> bit) & 1;
                    byte[] expected = (expectedBit == 0 ? Fp256Field.Compiler.Zero : Fp256Field.Compiler.One).ToArray();

                    Assert.IsTrue(EvaluatedBytes(logic, logic.Eval(output[bit])).AsSpan().SequenceEqual(expected), $"Byte {b}'s decoded bit {bit} must equal alphabet index {alphabetIndex}'s bit {bit}.");
                }
            }
            else
            {
                Assert.IsFalse(LongfellowCompilerFieldOperations.ElementIsZero(EvaluatedBytes(logic, logic.Eval(invalid))), $"Byte {b} is not in the alphabet, so the invalid flag must evaluate to one.");
            }
        }
    }


    /// <summary>Pins that the asserting overload latches a failure on the padding character, and that a fresh backend's latch stays clear on a genuine alphabet character.</summary>
    [TestMethod]
    public void TheAssertingDecodeLatchesOnAnInvalidByte()
    {
        var invalidBackend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        var invalidLogic = new LongfellowLogic(invalidBackend, Fp256Field);
        var invalidDecoder = new LongfellowBase64Decoder(invalidLogic);

        LongfellowBitWire[] paddingInput = invalidLogic.BitVector(LongfellowLogic.BitWidth8, PaddingCharacter);
        var paddingOutput = new LongfellowBitWire[SymbolBitWidth];
        invalidDecoder.Decode(paddingInput, paddingOutput);

        Assert.IsTrue(invalidBackend.AssertionFailed, "Decoding the padding character must latch an invalid-alphabet assertion failure.");

        var validBackend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        var validLogic = new LongfellowLogic(validBackend, Fp256Field);
        var validDecoder = new LongfellowBase64Decoder(validLogic);

        LongfellowBitWire[] validInput = validLogic.BitVector(LongfellowLogic.BitWidth8, ValidCharacter);
        var validOutput = new LongfellowBitWire[SymbolBitWidth];
        validDecoder.Decode(validInput, validOutput);

        Assert.IsFalse(validBackend.AssertionFailed, "Decoding a genuine alphabet character must never latch a failure.");
    }


    /// <summary>Pins that the wire-valued-length overload tolerates trailing garbage beyond the claimed length while still decoding the genuine prefix, and latches once the trailing garbage is claimed genuine too.</summary>
    [TestMethod]
    public void TheLengthGatedDecodeIgnoresTrailingGarbage()
    {
        byte[] paddedInput = LengthGatedInputBytes;

        var shortLengthBackend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        var shortLengthLogic = new LongfellowLogic(shortLengthBackend, Fp256Field);
        var shortLengthDecoder = new LongfellowBase64Decoder(shortLengthLogic);

        LongfellowBitWire[][] shortLengthInputs = BuildInputByteVectors(shortLengthLogic, paddedInput);
        LongfellowBitWire[][] shortLengthOutput = AllocateOutputByteVectors(LengthGatedDecodedByteCount);
        LongfellowBitWire[] shortLength = shortLengthLogic.BitVector(LengthWireBitWidth, LengthGatedGenuineLength);

        shortLengthDecoder.RawUrlDecodeWithLength(shortLengthInputs, shortLengthOutput, LengthGatedInputByteCount, shortLength);

        Assert.IsFalse(shortLengthBackend.AssertionFailed, "A genuine length of four must not latch a failure over the trailing '#' garbage.");

        for(int i = 0; i < ExpectedDecodedPrefix.Length; i++)
        {
            byte actual = ReadByteFromBits(shortLengthLogic, shortLengthOutput[i]);

            Assert.AreEqual(ExpectedDecodedPrefix[i], actual, $"Decoded output byte {i} must equal 'ABC' byte {i}.");
        }

        var fullLengthBackend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        var fullLengthLogic = new LongfellowLogic(fullLengthBackend, Fp256Field);
        var fullLengthDecoder = new LongfellowBase64Decoder(fullLengthLogic);

        LongfellowBitWire[][] fullLengthInputs = BuildInputByteVectors(fullLengthLogic, paddedInput);
        LongfellowBitWire[][] fullLengthOutput = AllocateOutputByteVectors(LengthGatedDecodedByteCount);
        LongfellowBitWire[] fullLength = fullLengthLogic.BitVector(LengthWireBitWidth, LengthGatedInputByteCount);

        fullLengthDecoder.RawUrlDecodeWithLength(fullLengthInputs, fullLengthOutput, LengthGatedInputByteCount, fullLength);

        Assert.IsTrue(fullLengthBackend.AssertionFailed, "Claiming all eight bytes genuine must latch a failure once the trailing '#' bytes are checked.");
    }


    /// <summary>Builds one unpacked eight-bit vector wire per input byte, least significant bit first (the reference's <c>vbit&lt;8&gt;</c> over an array).</summary>
    /// <param name="logic">The gadget layer to build wires over.</param>
    /// <param name="bytes">The input bytes.</param>
    /// <returns>One bit vector per byte.</returns>
    private static LongfellowBitWire[][] BuildInputByteVectors(LongfellowLogic logic, ReadOnlySpan<byte> bytes)
    {
        var result = new LongfellowBitWire[bytes.Length][];
        for(int i = 0; i < bytes.Length; i++)
        {
            result[i] = logic.BitVector(LongfellowLogic.BitWidth8, bytes[i]);
        }

        return result;
    }


    /// <summary>Allocates the caller-owned eight-bit output byte vectors <see cref="LongfellowBase64Decoder.RawUrlDecodeWithLength"/> writes into.</summary>
    /// <param name="byteCount">The output byte count to allocate.</param>
    /// <returns>The allocated, as-yet-unset output byte vectors.</returns>
    private static LongfellowBitWire[][] AllocateOutputByteVectors(int byteCount)
    {
        var result = new LongfellowBitWire[byteCount][];
        for(int i = 0; i < byteCount; i++)
        {
            result[i] = new LongfellowBitWire[LongfellowLogic.BitWidth8];
        }

        return result;
    }


    /// <summary>Reconstructs a byte from its decoded bit vector, most significant bit at index seven, matching the decoder's own output convention.</summary>
    /// <param name="logic">The gadget layer the bits were built over.</param>
    /// <param name="bits">The eight decoded output bits.</param>
    /// <returns>The reconstructed byte.</returns>
    private static byte ReadByteFromBits(LongfellowLogic logic, LongfellowBitWire[] bits)
    {
        byte value = 0;
        for(int bit = 0; bit < LongfellowLogic.BitWidth8; bit++)
        {
            if(!LongfellowCompilerFieldOperations.ElementIsZero(EvaluatedBytes(logic, logic.Eval(bits[bit]))))
            {
                value |= (byte)(1 << bit);
            }
        }

        return value;
    }


    /// <summary>Reads a wire's canonical bytes off its evaluating backend.</summary>
    /// <param name="logic">The gadget layer the wire was built over.</param>
    /// <param name="wire">The wire to read.</param>
    /// <returns>The wire's canonical bytes.</returns>
    private static byte[] EvaluatedBytes(LongfellowLogic logic, int wire) => ((LongfellowEvaluationLogicBackend)logic.Backend).ElementAt(wire).ToArray();


    /// <summary>Builds the P-256 base field's modulus-minus-one, canonical big-endian, for <see cref="LongfellowLogicFieldOperations.CreateFp256"/>.</summary>
    /// <returns>The canonical <c>p - 1</c>.</returns>
    private static byte[] BuildFp256MinusOne()
    {
        byte[] canonical = new byte[Scalar.SizeBytes];
        byte[] bigEndian = (P256BaseFieldReference.FieldOrder - 1).ToByteArray(isUnsigned: true, isBigEndian: true);
        bigEndian.CopyTo(canonical.AsSpan(Scalar.SizeBytes - bigEndian.Length));

        return canonical;
    }
}

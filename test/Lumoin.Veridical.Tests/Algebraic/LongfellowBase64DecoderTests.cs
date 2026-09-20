using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Longfellow.Circuits;
using Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;
using System;
using System.Buffers;
using System.Globalization;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Pins the base64url decoder gadget's alphabet mapping, invalid-input latch, decoded-byte
/// repacking, length gating and argument guards over the P-256 base field. Every possible input
/// byte decodes to its alphabet index with a clear invalid flag or latches the flag; the asserting
/// overload latches on an invalid byte; and the wire-valued-length overload tolerates garbage only
/// beyond its claimed length.
/// </summary>
/// <remarks>
/// The exhaustive byte sweep follows google/longfellow-zk's <c>decode_test.cc</c> over
/// <c>Fp256Base</c>. Deterministic strings cover full and partial four-symbol groups and the
/// wire-valued length's boundary between genuine payload and trailing garbage.
/// </remarks>
[TestClass]
internal sealed class LongfellowBase64DecoderTests: IDisposable
{
    /// <summary>Owns this test's field, curve and scalar storage through cleanup.</summary>
    private LongfellowCircuitTestScope CircuitScope { get; } = new();

    /// <summary>Releases all pooled owners after this test, including failed assertions.</summary>
    [TestCleanup]
    public void Cleanup()
    {
        Dispose();
    }

    /// <summary>Releases this test's owners and their pool. Repeated disposal has no effect.</summary>
    public void Dispose()
    {
        CircuitScope.Dispose();
    }

    /// <summary>The canonical byte width of one scalar, which the P-256 modulus-minus-one buffer must occupy.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

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

    /// <summary>One bit wider than the decoder's eight-bit input, so the width guard is the only check that rejects the vector: the decoder's bit loops are bounded by eight and would read it without leaving bounds.</summary>
    private const int OversizedInputBitWidth = 9;

    /// <summary>The exact message the flag-reporting decode's width guard reports, naming the eight input bits and six symbol bits the decoder maps between.</summary>
    private const string WidthGuardMessage = "The decoder maps 8 input bits to 6 symbol bits.";

    /// <summary>A negative input byte count, rejected by the fixed-length decode's non-negative count guard and by none of its upper-bound guards.</summary>
    private const int NegativeCount = -1;

    /// <summary>The parameter name the fixed-length decode's count guards report.</summary>
    private const string CountParameterName = "count";

    /// <summary>"QUJDREU"'s byte count: one full four-symbol group followed by a trailing three-symbol group, with the input array exactly this long.</summary>
    private const int GroupedInputByteCount = 7;

    /// <summary><c>ceil(7 * 6 / 8)</c>: the decoded byte count the fixed-length decode writes for <see cref="GroupedInputByteCount"/> symbols.</summary>
    private const int GroupedDecodedByteCount = 6;

    /// <summary>"QUJDRA"'s byte count, the counted prefix of <see cref="CountedInputBytes"/>: one full four-symbol group followed by a trailing two-symbol group.</summary>
    private const int CountedInputByteCount = 6;

    /// <summary><c>ceil(6 * 6 / 8)</c>: the decoded byte count the fixed-length decode writes for <see cref="CountedInputByteCount"/> symbols.</summary>
    private const int CountedDecodedByteCount = 5;

    /// <summary>The parameter name the constructor's gadget-layer null check reports.</summary>
    private const string LogicParameterName = "logic";

    /// <summary>The parameter name the flag-reporting decode's input null check reports.</summary>
    private const string InputParameterName = "input";

    /// <summary>The parameter name reported by both output null checks, the flag-reporting decode's and the shared shape guard's, since both name an <c>output</c> parameter.</summary>
    private const string OutputParameterName = "output";

    /// <summary>The parameter name the shared shape guard's input-array null check reports.</summary>
    private const string InputsParameterName = "inputs";

    /// <summary>The parameter name the length-gated decode's length null check reports.</summary>
    private const string LengthParameterName = "length";

    /// <summary>The caller-argument expression the shared shape guard's output-length check reports, the one parameter name no other guard in the decoder produces.</summary>
    private const string OutputLengthParameterName = "output.Length";

    /// <summary>A zero input byte count: it clears every shape bound over empty arrays, so a null-argument check is the only guard left that can answer.</summary>
    private const int EmptyCount = 0;

    /// <summary>The decoder's overflow bound on its <c>count * 6</c> index arithmetic: a count at or above this is refused.</summary>
    private const int OverflowBoundCount = 1 << 28;

    /// <summary>One past <see cref="OverflowBoundCount"/>, so the refused count and the bound print as different numbers and the bound in the rejection message cannot be mistaken for the count.</summary>
    private const int CountPastOverflowBound = OverflowBoundCount + 1;

    /// <summary>A single input byte to decode, the smallest count whose decoded prefix is a whole byte.</summary>
    private const int SingleSymbolCount = 1;

    /// <summary><c>ceil(1 * 6 / 8)</c>: the decoded byte count <see cref="SingleSymbolCount"/> input byte needs.</summary>
    private const int SingleSymbolDecodedByteCount = 1;

    /// <summary>An output array holding no byte vectors at all, the length the output-length guard reports when it refuses one.</summary>
    private const int EmptyOutputByteCount = 0;

    /// <summary>"ABC", the three-byte prefix the length-gated decode's output must spell when only the genuine length is claimed.</summary>
    private static ReadOnlySpan<byte> ExpectedDecodedPrefix => [0x41, 0x42, 0x43];

    /// <summary>"QUJD", the base64url encoding of "ABC", padded with four trailing '#' bytes outside the genuine payload.</summary>
    private static ReadOnlySpan<byte> LengthGatedInputBytes => "QUJD####"u8;

    /// <summary>"QUJDREU", the unpadded base64url encoding of "ABCDE": the full group "QUJD" followed by the trailing three-symbol group "REU".</summary>
    private static ReadOnlySpan<byte> GroupedInputBytes => "QUJDREU"u8;

    /// <summary>"ABCDE" followed by a zero byte: Q, U, J, D (16, 20, 9, 3) pack to 0x41 0x42 0x43, and R, E, U (17, 4, 20) with the trailing group's constant-zero fourth symbol pack to 0x44 0x45 0x00.</summary>
    private static ReadOnlySpan<byte> ExpectedGroupedOutput => [0x41, 0x42, 0x43, 0x44, 0x45, 0x00];

    /// <summary>"QUJDRA", the unpadded base64url encoding of "ABCD", followed by two '#' bytes outside the alphabet that lie past the counted prefix.</summary>
    private static ReadOnlySpan<byte> CountedInputBytes => "QUJDRA##"u8;

    /// <summary>"ABCD" followed by a zero partial byte: R and A (17, 0) pack to 0x44, and the low four bits of A with the top four bits of the constant-zero third symbol give 0x00.</summary>
    private static ReadOnlySpan<byte> ExpectedCountedOutput => [0x41, 0x42, 0x43, 0x44, 0x00];

    /// <summary><see cref="OverflowBoundCount"/> in decimal, the message fragment only the overflow guard produces: the input-array guard measures the count against the input array's length and reports that instead.</summary>
    private static string OverflowBoundText { get; } = OverflowBoundCount.ToString(CultureInfo.InvariantCulture);

    /// <summary>Owns the P-256 modulus-minus-one bytes retained by the shared field bundle until class cleanup.</summary>
    private static IMemoryOwner<byte> Fp256MinusOneOwner { get; } = BuildFp256MinusOne();

    /// <summary>The P-256 base field's modulus-minus-one, canonical big-endian, used to construct <see cref="Fp256Field"/>.</summary>
    private static ReadOnlyMemory<byte> Fp256MinusOne => Fp256MinusOneOwner.Memory[..ScalarSize];

    /// <summary>The cached Fp256Field owner for this test instance.</summary>
    private LongfellowLogicFieldOperations? fp256Field;

    /// <summary>The P-256 base field bundle gated over by every test in this class.</summary>
    private LongfellowLogicFieldOperations Fp256Field => fp256Field ??= CircuitScope.Track(LongfellowLogicFieldOperations.CreateFp256(
        P256BaseFieldReference.GetAdd(),
        P256BaseFieldReference.GetSubtract(),
        P256BaseFieldReference.GetMultiply(),
        P256BaseFieldReference.GetInvert(),
        Fp256MinusOne, CircuitScope.Pool));


    /// <summary>Returns the modulus rental after every test using the shared field bundle has completed.</summary>
    [ClassCleanup]
    public static void DisposeModulusRental()
    {
        Fp256MinusOneOwner.Dispose();
    }


    /// <summary>Pins that every one of the 256 possible input bytes decodes to its alphabet index with a clear invalid flag, or else latches the invalid flag.</summary>
    [TestMethod]
    public void EveryByteDecodesToItsAlphabetValue()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        using var logic = new LongfellowLogic(backend, Fp256Field);
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
                    ReadOnlySpan<byte> expected = (expectedBit == 0 ? Fp256Field.Compiler.Zero : Fp256Field.Compiler.One).Span;

                    Assert.IsTrue(EvaluatedBytes(logic, logic.Eval(output[bit])).SequenceEqual(expected), $"Byte {b}'s decoded bit {bit} must equal alphabet index {alphabetIndex}'s bit {bit}.");
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
        using var invalidBackend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        using var invalidLogic = new LongfellowLogic(invalidBackend, Fp256Field);
        var invalidDecoder = new LongfellowBase64Decoder(invalidLogic);

        LongfellowBitWire[] paddingInput = invalidLogic.BitVector(LongfellowLogic.BitWidth8, PaddingCharacter);
        var paddingOutput = new LongfellowBitWire[SymbolBitWidth];
        invalidDecoder.Decode(paddingInput, paddingOutput);

        Assert.IsTrue(invalidBackend.AssertionFailed, "Decoding the padding character must latch an invalid-alphabet assertion failure.");

        using var validBackend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        using var validLogic = new LongfellowLogic(validBackend, Fp256Field);
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
        ReadOnlySpan<byte> paddedInput = LengthGatedInputBytes;

        using var shortLengthBackend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        using var shortLengthLogic = new LongfellowLogic(shortLengthBackend, Fp256Field);
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

        using var fullLengthBackend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        using var fullLengthLogic = new LongfellowLogic(fullLengthBackend, Fp256Field);
        var fullLengthDecoder = new LongfellowBase64Decoder(fullLengthLogic);

        LongfellowBitWire[][] fullLengthInputs = BuildInputByteVectors(fullLengthLogic, paddedInput);
        LongfellowBitWire[][] fullLengthOutput = AllocateOutputByteVectors(LengthGatedDecodedByteCount);
        LongfellowBitWire[] fullLength = fullLengthLogic.BitVector(LengthWireBitWidth, LengthGatedInputByteCount);

        fullLengthDecoder.RawUrlDecodeWithLength(fullLengthInputs, fullLengthOutput, LengthGatedInputByteCount, fullLength);

        Assert.IsTrue(fullLengthBackend.AssertionFailed, "Claiming all eight bytes genuine must latch a failure once the trailing '#' bytes are checked.");
    }


    /// <summary>
    /// Pins that the flag-reporting overload rejects an input vector wider than eight bits with an
    /// <see cref="ArgumentException"/> carrying the width message and no parameter name. Both vectors
    /// are non-null, so neither null check answers first; the output vector has the six-bit symbol
    /// width and the input's low eight bits spell a genuine alphabet character, so the input width is
    /// the only defect. The flag-reporting overload makes no assertion, so the panicking backend cannot
    /// throw on its own.
    /// </summary>
    [TestMethod]
    public void TheFlagReportingDecodeRejectsAnOversizedInputVector()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        using var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        LongfellowBitWire[] input = logic.BitVector(OversizedInputBitWidth, ValidCharacter);
        var output = new LongfellowBitWire[SymbolBitWidth];

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(() => decoder.Decode(input, output, out _), "A nine-bit input vector must be rejected.");

        Assert.AreEqual(WidthGuardMessage, exception.Message, "The rejection must name the eight input bits and six symbol bits the decoder maps between.");
        Assert.IsNull(exception.ParamName, "The width guard reports no parameter name.");
    }


    /// <summary>
    /// Pins that the fixed-length overload rejects a negative input byte count with an
    /// <see cref="ArgumentOutOfRangeException"/> naming <c>count</c> and carrying the refused value.
    /// Both arrays are non-null and empty, so the null checks pass; a count of minus one is below the
    /// overflow bound, does not exceed the empty input array and needs no output bytes, so only the
    /// non-negative guard answers, and only that guard reports a negative actual value.
    /// </summary>
    [TestMethod]
    public void TheFixedLengthDecodeRejectsANegativeCount()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        using var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        LongfellowBitWire[][] inputs = [];
        LongfellowBitWire[][] output = [];

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => decoder.RawUrlDecode(inputs, output, NegativeCount), "A negative input byte count must be rejected.");

        Assert.AreEqual(CountParameterName, exception.ParamName, "The rejection must name the count parameter.");
        Assert.AreEqual(NegativeCount, exception.ActualValue, "The rejection must carry the negative count it refused.");
    }


    /// <summary>
    /// Pins that the fixed-length overload decodes an input array exactly <c>count</c> bytes long across
    /// a full four-symbol group and a trailing three-symbol group, writing every bit of the
    /// <c>ceil(count * 6 / 8)</c> decoded bytes: "QUJDREU" repacks to "ABCDE" followed by the zero byte
    /// the trailing group's constant-zero fourth symbol completes, and no byte latches the validity
    /// assertion.
    /// </summary>
    [TestMethod]
    public void TheFixedLengthDecodeRepacksFullAndPartialGroups()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        using var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        LongfellowBitWire[][] inputs = BuildInputByteVectors(logic, GroupedInputBytes);
        LongfellowBitWire[][] output = AllocateOutputByteVectors(GroupedDecodedByteCount);

        decoder.RawUrlDecode(inputs, output, GroupedInputByteCount);

        Assert.IsFalse(backend.AssertionFailed, "Every byte of 'QUJDREU' is in the alphabet, so no validity assertion may latch.");

        for(int i = 0; i < ExpectedGroupedOutput.Length; i++)
        {
            for(int bit = 0; bit < LongfellowLogic.BitWidth8; bit++)
            {
                Assert.HasCount(Scalar.SizeBytes, output[i][bit].LinearCoefficient.Span, $"Decoded output byte {i}'s bit {bit} must be written.");
            }

            Assert.AreEqual(ExpectedGroupedOutput[i], ReadByteFromBits(logic, output[i]), $"Decoded output byte {i} must equal byte {i} of 'ABCDE' followed by a zero byte.");
        }
    }


    /// <summary>
    /// Pins that the fixed-length overload reads only the first <c>count</c> input bytes when the input
    /// array is longer: with a count of six over "QUJDRA##", the two '#' bytes past the count are neither
    /// decoded nor checked, so no validity assertion latches, and the trailing two-symbol group repacks
    /// "QUJDRA" to "ABCD" followed by a zero partial byte.
    /// </summary>
    [TestMethod]
    public void TheFixedLengthDecodeLeavesBytesPastCountUnread()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        using var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        LongfellowBitWire[][] inputs = BuildInputByteVectors(logic, CountedInputBytes);
        LongfellowBitWire[][] output = AllocateOutputByteVectors(CountedDecodedByteCount);

        decoder.RawUrlDecode(inputs, output, CountedInputByteCount);

        Assert.IsFalse(backend.AssertionFailed, "The '#' bytes past the count must not be decoded or checked.");

        for(int i = 0; i < ExpectedCountedOutput.Length; i++)
        {
            Assert.AreEqual(ExpectedCountedOutput[i], ReadByteFromBits(logic, output[i]), $"Decoded output byte {i} must equal byte {i} of 'ABCD' followed by a zero partial byte.");
        }
    }


    /// <summary>
    /// Pins that the constructor rejects a null gadget layer with an <see cref="ArgumentNullException"/>
    /// naming <c>logic</c>. The constructor takes no other argument, so that null check is the only guard
    /// that can answer.
    /// </summary>
    [TestMethod]
    public void TheConstructorRejectsANullLogic()
    {
        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(() => new LongfellowBase64Decoder(null!), "A null gadget layer must be rejected.");

        Assert.AreEqual(LogicParameterName, exception.ParamName, "The rejection must name the gadget-layer parameter.");
    }


    /// <summary>
    /// Pins that the flag-reporting overload rejects a null input vector with an
    /// <see cref="ArgumentNullException"/> naming <c>input</c>. The output vector is non-null and carries
    /// the six-bit symbol width, so neither the output null check nor the width guard can answer instead,
    /// and only the input null check reports that parameter name.
    /// </summary>
    [TestMethod]
    public void TheFlagReportingDecodeRejectsANullInputVector()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        using var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        var output = new LongfellowBitWire[SymbolBitWidth];

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(() => decoder.Decode(null!, output, out _), "A null input vector must be rejected.");

        Assert.AreEqual(InputParameterName, exception.ParamName, "The rejection must name the input parameter.");
    }


    /// <summary>
    /// Pins that the flag-reporting overload rejects a null output vector with an
    /// <see cref="ArgumentNullException"/> naming <c>output</c>. The input vector is non-null, exactly eight
    /// bits wide and spells a genuine alphabet character, so neither the input null check nor the width
    /// guard can answer instead, and only the output null check reports that parameter name.
    /// </summary>
    [TestMethod]
    public void TheFlagReportingDecodeRejectsANullOutputVector()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        using var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        LongfellowBitWire[] input = logic.BitVector(LongfellowLogic.BitWidth8, ValidCharacter);

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(() => decoder.Decode(input, null!, out _), "A null output vector must be rejected.");

        Assert.AreEqual(OutputParameterName, exception.ParamName, "The rejection must name the output parameter.");
    }


    /// <summary>
    /// Pins that the fixed-length overload rejects a null input array with an
    /// <see cref="ArgumentNullException"/> naming <c>inputs</c>. The output array is non-null and a zero
    /// count clears every bound the shape guard measures, so the input-array null check is the only guard
    /// that can answer, and only it reports that parameter name.
    /// </summary>
    [TestMethod]
    public void TheFixedLengthDecodeRejectsNullInputs()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        using var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        LongfellowBitWire[][] output = [];

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(() => decoder.RawUrlDecode(null!, output, EmptyCount), "A null input array must be rejected.");

        Assert.AreEqual(InputsParameterName, exception.ParamName, "The rejection must name the input-array parameter.");
    }


    /// <summary>
    /// Pins that the fixed-length overload rejects a null output array with an
    /// <see cref="ArgumentNullException"/> naming <c>output</c>. The input array is non-null and a zero
    /// count clears every bound the shape guard measures, so the output null check is the only guard that
    /// can answer, and only it reports that parameter name.
    /// </summary>
    [TestMethod]
    public void TheFixedLengthDecodeRejectsANullOutput()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        using var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        LongfellowBitWire[][] inputs = [];

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(() => decoder.RawUrlDecode(inputs, null!, EmptyCount), "A null output array must be rejected.");

        Assert.AreEqual(OutputParameterName, exception.ParamName, "The rejection must name the output parameter.");
    }


    /// <summary>
    /// Pins that the fixed-length overload rejects a count at or above the decoder's <c>count * 6</c>
    /// index-arithmetic bound, reporting the bound it measured against. Both arrays are non-null and the
    /// count is positive, so no null check and no non-negative check answers; the refused count is one past
    /// the bound, so the bound's own digits appear in the message only because the overflow guard put them
    /// there, and no other count guard measures against that number.
    /// </summary>
    [TestMethod]
    public void TheFixedLengthDecodeRejectsACountPastTheOverflowBound()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        using var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        LongfellowBitWire[][] inputs = [];
        LongfellowBitWire[][] output = [];

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => decoder.RawUrlDecode(inputs, output, CountPastOverflowBound), "A count past the index-arithmetic bound must be rejected.");

        Assert.AreEqual(CountParameterName, exception.ParamName, "The rejection must name the count parameter.");
        Assert.Contains(OverflowBoundText, exception.Message, StringComparison.Ordinal, "The rejection must quote the index-arithmetic bound it measured against.");
    }


    /// <summary>
    /// Pins that the fixed-length overload rejects a count reaching past the input array with an
    /// <see cref="ArgumentOutOfRangeException"/> naming <c>count</c> and carrying the refused value. Both
    /// arrays are non-null, one is a non-negative count well below the overflow bound, and the output array
    /// already holds the one byte that count decodes to, so the input-length bound is the only one the
    /// shape guard can fail.
    /// </summary>
    [TestMethod]
    public void TheFixedLengthDecodeRejectsACountPastTheInputArray()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        using var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        LongfellowBitWire[][] inputs = [];
        LongfellowBitWire[][] output = AllocateOutputByteVectors(SingleSymbolDecodedByteCount);

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => decoder.RawUrlDecode(inputs, output, SingleSymbolCount), "A count reaching past the input array must be rejected.");

        Assert.AreEqual(CountParameterName, exception.ParamName, "The rejection must name the count parameter.");
        Assert.AreEqual(SingleSymbolCount, exception.ActualValue, "The rejection must carry the count it refused.");
    }


    /// <summary>
    /// Pins that the fixed-length overload rejects an output array shorter than the
    /// <c>ceil(count * 6 / 8)</c> decoded prefix, reporting the measured output length. Both arrays are
    /// non-null, and a count of one is non-negative, below the overflow bound and within the one-byte input
    /// array, so the output-length bound is the only one the shape guard can fail, and it is the only guard
    /// in the decoder that reports the output length as its parameter name.
    /// </summary>
    [TestMethod]
    public void TheFixedLengthDecodeRejectsAnOutputShorterThanTheDecodedPrefix()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        using var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        LongfellowBitWire[][] inputs = [logic.BitVector(LongfellowLogic.BitWidth8, ValidCharacter)];
        LongfellowBitWire[][] output = [];

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => decoder.RawUrlDecode(inputs, output, SingleSymbolCount), "An output array shorter than the decoded prefix must be rejected.");

        Assert.AreEqual(OutputLengthParameterName, exception.ParamName, "The rejection must name the output length it measured.");
        Assert.AreEqual(EmptyOutputByteCount, exception.ActualValue, "The rejection must carry the output length it refused.");
    }


    /// <summary>
    /// Pins that the wire-valued-length overload runs the same shape guard as the fixed-length one, rejecting
    /// a negative input byte count with an <see cref="ArgumentOutOfRangeException"/> naming <c>count</c> and
    /// carrying the refused value. Both arrays are non-null and empty and the length vector is non-null, so
    /// no null check answers; a count of minus one is below the overflow bound, does not exceed the empty
    /// input array and needs no output bytes, so only the non-negative bound rejects it, and only that
    /// bound reports a negative actual value.
    /// </summary>
    [TestMethod]
    public void TheLengthGatedDecodeRejectsANegativeCount()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        using var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        LongfellowBitWire[][] inputs = [];
        LongfellowBitWire[][] output = [];
        LongfellowBitWire[] length = logic.BitVector(LengthWireBitWidth, LengthGatedGenuineLength);

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => decoder.RawUrlDecodeWithLength(inputs, output, NegativeCount, length), "A negative input byte count must be rejected.");

        Assert.AreEqual(CountParameterName, exception.ParamName, "The rejection must name the count parameter.");
        Assert.AreEqual(NegativeCount, exception.ActualValue, "The rejection must carry the negative count it refused.");
    }


    /// <summary>
    /// Pins that the wire-valued-length overload rejects a null length vector with an
    /// <see cref="ArgumentNullException"/> naming <c>length</c>. Both arrays are non-null and a zero count
    /// clears every bound the shape guard measures, so the length null check is the only guard that can
    /// answer, and only it reports that parameter name.
    /// </summary>
    [TestMethod]
    public void TheLengthGatedDecodeRejectsANullLength()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field);
        using var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        LongfellowBitWire[][] inputs = [];
        LongfellowBitWire[][] output = [];

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(() => decoder.RawUrlDecodeWithLength(inputs, output, EmptyCount, null!), "A null length vector must be rejected.");

        Assert.AreEqual(LengthParameterName, exception.ParamName, "The rejection must name the length parameter.");
    }


    /// <summary>
    /// Pins that the wire-valued-length overload reads exactly the counted input bytes across a full
    /// four-symbol group and a trailing three-symbol group, writing every bit of the
    /// <c>ceil(count * 6 / 8)</c> decoded bytes: "QUJDREU", whose array is exactly as long as the count,
    /// repacks to "ABCDE" followed by the zero byte the trailing group's constant-zero fourth symbol
    /// completes. The claimed length covers all seven bytes and every one of them is in the alphabet, so
    /// no validity assertion latches.
    /// </summary>
    [TestMethod]
    public void TheLengthGatedDecodeRepacksFullAndPartialGroups()
    {
        using var backend = new LongfellowEvaluationLogicBackend(Fp256Field, panicOnAssertionFailure: false);
        using var logic = new LongfellowLogic(backend, Fp256Field);
        var decoder = new LongfellowBase64Decoder(logic);

        LongfellowBitWire[][] inputs = BuildInputByteVectors(logic, GroupedInputBytes);
        LongfellowBitWire[][] output = AllocateOutputByteVectors(GroupedDecodedByteCount);
        LongfellowBitWire[] length = logic.BitVector(LengthWireBitWidth, GroupedInputByteCount);

        decoder.RawUrlDecodeWithLength(inputs, output, GroupedInputByteCount, length);

        Assert.IsFalse(backend.AssertionFailed, "Every byte of 'QUJDREU' is in the alphabet and inside the claimed length, so no validity assertion may latch.");

        for(int i = 0; i < ExpectedGroupedOutput.Length; i++)
        {
            for(int bit = 0; bit < LongfellowLogic.BitWidth8; bit++)
            {
                Assert.HasCount(Scalar.SizeBytes, output[i][bit].LinearCoefficient.Span, $"Decoded output byte {i}'s bit {bit} must be written.");
            }

            Assert.AreEqual(ExpectedGroupedOutput[i], ReadByteFromBits(logic, output[i]), $"Decoded output byte {i} must equal byte {i} of 'ABCDE' followed by a zero byte.");
        }
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
    private static ReadOnlySpan<byte> EvaluatedBytes(LongfellowLogic logic, int wire) => ((LongfellowEvaluationLogicBackend)logic.Backend).ElementAt(wire).Span;


    /// <summary>Rents and writes the P-256 base field's modulus-minus-one, canonical big-endian, for <see cref="LongfellowLogicFieldOperations.CreateFp256"/>.</summary>
    /// <returns>The owner of the canonical <c>p - 1</c> buffer, released by class cleanup.</returns>
    private static IMemoryOwner<byte> BuildFp256MinusOne()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(ScalarSize);
        Span<byte> canonical = owner.Memory.Span[..ScalarSize];
        //The P-256 modulus-minus-one occupies every canonical byte, so the write fills the rental.
        _ = (P256BaseFieldReference.FieldOrder - 1).TryWriteBytes(canonical, out _, isUnsigned: true, isBigEndian: true);

        return owner;
    }
}

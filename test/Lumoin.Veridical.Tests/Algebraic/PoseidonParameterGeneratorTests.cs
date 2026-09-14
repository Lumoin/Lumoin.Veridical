using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// The argument surface and the draw sequence of <see cref="PoseidonParameterGenerator.Generate"/>. A null
/// delegate, a state width below two, a non-positive or odd round count, a field size outside one scalar, a modulus
/// that is not one scalar wide and a modulus whose bit length is not the field size are each rejected with the
/// documented exception and parameter name before the Grain stream is seeded and before the caller-supplied add and
/// invert backends run; a field size of exactly
/// one scalar is accepted; and over fields narrow enough to follow draw by draw, the round constants the stream
/// yields, the rejection sampling that keeps them below the modulus, and the one-step reduction of the raw Cauchy
/// points are pinned to values derived from the Grain procedure rather than from this implementation.
/// </summary>
[TestClass]
internal sealed class PoseidonParameterGeneratorTests
{
    /// <summary>The canonical byte width of one scalar, which is also the width the modulus must have.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The number of bits in one byte, used to express the widest field size one scalar carries.</summary>
    private const int BitsPerByte = 8;

    /// <summary>The BN254 scalar-field order, canonical big-endian, one scalar wide.</summary>
    private const string Bn254ScalarOrderHex = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

    /// <summary>The bit length of the BN254 scalar-field order.</summary>
    private const int Bn254FieldSizeBits = 254;

    /// <summary>The smallest state width the generator accepts.</summary>
    private const int ValidStateWidth = 2;

    /// <summary>A positive, even full-round count that passes every full-round check.</summary>
    private const int EvenFullRounds = 2;

    /// <summary>A positive full-round count that fails only the parity check.</summary>
    private const int OddFullRounds = 3;

    /// <summary>A positive partial-round count that passes the partial-round check.</summary>
    private const int ValidPartialRounds = 1;

    /// <summary>A field size of zero bits, below the accepted range.</summary>
    private const int ZeroFieldSizeBits = 0;

    /// <summary>A field size one bit wider than a single scalar carries, above the accepted range.</summary>
    private const int FieldSizeBitsBeyondOneScalar = (BitsPerByte * ScalarSize) + 1;

    /// <summary>A field size one bit shorter than the bit length of the BN254 order.</summary>
    private const int FieldSizeBitsBelowTheBn254Order = Bn254FieldSizeBits - 1;

    /// <summary>A field size one bit longer than the bit length of the BN254 order.</summary>
    private const int FieldSizeBitsAboveTheBn254Order = Bn254FieldSizeBits + 1;

    /// <summary>A modulus of zero, one scalar wide, whose bit length of zero matches no accepted field size.</summary>
    private const string ZeroModulusHex = "0000000000000000000000000000000000000000000000000000000000000000";

    /// <summary>The bit length of the zero modulus.</summary>
    private const int ZeroModulusBitLength = 0;

    /// <summary>A modulus length one byte short of one scalar.</summary>
    private const int NarrowModulusLength = ScalarSize - 1;

    /// <summary>A modulus length one byte beyond one scalar.</summary>
    private const int WideModulusLength = ScalarSize + 1;

    /// <summary>The backend call count of a generation that is rejected at argument validation.</summary>
    private const int NoBackendCalls = 0;

    /// <summary>The parameter name the full-round parity guard reports.</summary>
    private const string FullRoundsParameterName = "fullRounds";

    /// <summary>The parameter name the field-size range guard reports.</summary>
    private const string FieldSizeBitsParameterName = "fieldSizeBits";

    /// <summary>The parameter name the modulus width guard reports.</summary>
    private const string ModulusParameterName = "modulus";

    /// <summary>The parity guard's message; the framework range checks on the round counts do not produce this text.</summary>
    private const string OddFullRoundsMessage = "The full rounds split evenly around the partial rounds; the count must be even.";

    /// <summary>The parameter name the addition-backend null guard reports.</summary>
    private const string AddParameterName = "add";

    /// <summary>The parameter name the inversion-backend null guard reports.</summary>
    private const string InvertParameterName = "invert";

    /// <summary>The parameter name the state-width guard reports.</summary>
    private const string StateWidthParameterName = "stateWidth";

    /// <summary>The parameter name the partial-round guard reports.</summary>
    private const string PartialRoundsParameterName = "partialRounds";

    /// <summary>
    /// The widest state width below the accepted minimum that still drives the generator all the way to the
    /// backends: one lane draws round constants and two Cauchy points, where a zero-lane state draws none.
    /// </summary>
    private const int SingleLaneStateWidth = 1;

    /// <summary>A full-round count of zero, which is even and so reaches the range check rather than the parity check.</summary>
    private const int ZeroFullRounds = 0;

    /// <summary>A partial-round count of zero, below the accepted range.</summary>
    private const int ZeroPartialRounds = 0;

    /// <summary>The widest field size one scalar carries, which is the largest the generator accepts.</summary>
    private const int FieldSizeBitsOfOneScalar = BitsPerByte * ScalarSize;

    /// <summary>
    /// The number of entries a two-lane MDS matrix has, which is also the number of additions and the number of
    /// inversions a generation that runs to completion at that width asks for.
    /// </summary>
    private const int MdsEntryCount = ValidStateWidth * ValidStateWidth;

    /// <summary>The number of bytes the entries of a two-lane MDS matrix occupy.</summary>
    private const int MdsByteCount = MdsEntryCount * ScalarSize;

    /// <summary>The number of rounds the two-lane, two-full-round, one-partial-round shape has.</summary>
    private const int SmallShapeRoundCount = EvenFullRounds + ValidPartialRounds;

    /// <summary>The number of round constants that same shape draws, one per lane per round.</summary>
    private const int SmallShapeConstantCount = SmallShapeRoundCount * ValidStateWidth;

    /// <summary>
    /// A modulus of <c>2^256 - 1</c>: one scalar wide with a bit length of exactly 256, so it is the widest modulus
    /// whose raw Cauchy draws still stay below twice the modulus and the one-step reduction stays correct.
    /// </summary>
    private const string WidestModulusHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    /// <summary>An eight-bit field size, matching the bit length of the eight-bit modulus.</summary>
    private const int EightBitFieldSize = 8;

    /// <summary>
    /// A modulus of <c>0xFB</c>, exactly eight bits wide like the field it samples, and above each of the six round
    /// constants the stream yields for the two-lane shape, so none of those draws is rejected.
    /// </summary>
    private const string EightBitModulusHex = "00000000000000000000000000000000000000000000000000000000000000FB";

    /// <summary>
    /// The six round constants the Grain stream yields for the two-lane shape over an eight-bit field, one byte
    /// each, in round-major lane order. The procedure seeds an 80-bit register with the parameter descriptor,
    /// discards 160 raw bits, and takes output bits pairwise, and these are the values that stream produces.
    /// </summary>
    private const string ExpectedEightBitRoundConstantsHex = "2FDB8CF3C585";

    /// <summary>A sixteen-bit field size, matching the bit length of the narrow modulus so a raw Cauchy draw can land above it.</summary>
    private const int SixteenBitFieldSize = 16;

    /// <summary>
    /// A modulus of <c>0x80FF</c>, exactly sixteen bits wide, so roughly half of the sixteen-bit raw Cauchy draws
    /// land above it and take the one-step reduction, and the reduced values stay small enough to follow by hand.
    /// </summary>
    private const string NarrowModulusHex = "00000000000000000000000000000000000000000000000000000000000080FF";

    /// <summary>
    /// The four entries of the Cauchy MDS matrix the two-lane shape builds over the narrow modulus, row-major.
    /// Each entry inverts the sum of one reduced Cauchy point pair; the sums and inverses are taken in the BN254
    /// scalar field, because the modulus argument governs only the Grain sampling while the backends stay BN254.
    /// Two of the four points come from raw draws above the narrow modulus, so these entries also pin the borrow
    /// chain of the one-step reduction.
    /// </summary>
    private const string ExpectedNarrowMdsHex =
        "14E424C2129D743C79CA66D7753B2726DFDC4986E81D5987FE4606F897FD1247"
        + "2E086DB9BE3EA019C2782589A5A802383BA5EED252B27F1501AE81832914E61D"
        + "178B572D72144C53DCBB1C4B769A552C2ABC8862C2BA83A1ABBE565D197B0981"
        + "0EB0ED9C97F19E7CF698185E4213E0F4DDA778B048336AA04155A0DC98FB79B8";

    /// <summary>A modulus of one, below which zero is the only field element.</summary>
    private const string UnitModulusHex = "0000000000000000000000000000000000000000000000000000000000000001";

    /// <summary>A field size of one bit, matching the bit length of the unit modulus, so every draw is a single filtered bit.</summary>
    private const int UnitFieldSizeBits = 1;

    /// <summary>A sixteen-lane state, whose thirty-two raw Cauchy draws give the single filtered bit many chances to land on the modulus.</summary>
    private const int WideStateWidth = 16;

    /// <summary>A partial-round count that, with the even full rounds, gives the sixteen-lane state four rounds of constants.</summary>
    private const int WidePartialRounds = 2;

    /// <summary>The number of rounds the sixteen-lane shape has.</summary>
    private const int WideShapeRoundCount = EvenFullRounds + WidePartialRounds;

    /// <summary>
    /// The number of entries a sixteen-lane MDS matrix has, which is also the number of additions and the number
    /// of inversions that generation asks for.
    /// </summary>
    private const int WideMdsEntryCount = WideStateWidth * WideStateWidth;

    /// <summary>The low byte of the scalar one, which the unit-sum backend offsets every reported sum by.</summary>
    private const byte UnitScalarLowByte = 1;

    /// <summary>The BN254 reference scalar-addition backend the counting backend forwards to.</summary>
    private static ScalarAddDelegate Bn254Add { get; } = Bn254BigIntegerScalarReference.GetAdd();

    /// <summary>The BN254 reference scalar-inversion backend the counting backend forwards to.</summary>
    private static ScalarInvertDelegate Bn254Invert { get; } = Bn254BigIntegerScalarReference.GetInvert();


    /// <summary>The modulus rentals opened during a test, released together in cleanup.</summary>
    private List<IDisposable> Disposables { get; } = [];


    /// <summary>Disposes every rental the test opened, most recent first.</summary>
    [TestCleanup]
    public void DisposeRentals()
    {
        for(int i = Disposables.Count - 1; i >= 0; i--)
        {
            Disposables[i].Dispose();
        }

        Disposables.Clear();
    }


    /// <summary>
    /// Pins that <see cref="PoseidonParameterGenerator.Generate"/> rejects an odd full-round count with an
    /// <see cref="ArgumentOutOfRangeException"/> that names <c>fullRounds</c> and explains that the full rounds
    /// split evenly around the partial rounds, and that it does so before any backend delegate is called. The
    /// <see cref="PoseidonParameters"/> constructor repeats the parity check with the same exception, parameter
    /// name and message, so the zero add and invert counts are what show the generator refuses the count itself
    /// instead of leaving it to the constructor after a full Grain generation. Both delegates are non-null, the
    /// state width is at least two, both round counts are positive, the field size fits one scalar and the
    /// modulus is one scalar wide, so no sibling guard answers first.
    /// </summary>
    [TestMethod]
    public void GenerateRejectsOddFullRoundsBeforeAnyBackendCall()
    {
        Memory<byte> modulus = RentBn254Modulus(ScalarSize);
        var backend = new CountingBn254ScalarBackend();

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => PoseidonParameterGenerator.Generate(ValidStateWidth, OddFullRounds, ValidPartialRounds, Bn254FieldSizeBits, modulus.Span, CurveParameterSet.Bn254, backend.Add, backend.Invert),
            "An odd full-round count must be rejected.");

        Assert.AreEqual(FullRoundsParameterName, exception.ParamName, "The rejection must name the fullRounds parameter.");
        Assert.Contains(OddFullRoundsMessage, exception.Message, StringComparison.Ordinal);
        Assert.AreEqual(NoBackendCalls, backend.AddCalls, "An odd full-round count must be rejected before any scalar addition.");
        Assert.AreEqual(NoBackendCalls, backend.InvertCalls, "An odd full-round count must be rejected before any scalar inversion.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonParameterGenerator.Generate"/> rejects a field size outside <c>(0, 256]</c>
    /// bits with an <see cref="ArgumentOutOfRangeException"/> that names <c>fieldSizeBits</c>, before any backend
    /// delegate is called. The field size is not passed on to <see cref="PoseidonParameters"/>, so this guard is
    /// the only check that keeps an unusable bit length out of the Grain descriptor and the field-element
    /// sampling. Both delegates are non-null, the state width and round counts are valid and the modulus is one
    /// scalar wide, so no sibling guard answers first, and no other guard reports this parameter name.
    /// </summary>
    /// <param name="fieldSizeBits">A field size below or above the accepted range.</param>
    [TestMethod]
    [DataRow(ZeroFieldSizeBits)]
    [DataRow(FieldSizeBitsBeyondOneScalar)]
    public void GenerateRejectsAFieldSizeOutsideOneScalar(int fieldSizeBits)
    {
        Memory<byte> modulus = RentBn254Modulus(ScalarSize);
        var backend = new CountingBn254ScalarBackend();

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => PoseidonParameterGenerator.Generate(ValidStateWidth, EvenFullRounds, ValidPartialRounds, fieldSizeBits, modulus.Span, CurveParameterSet.Bn254, backend.Add, backend.Invert),
            "A field size outside one scalar must be rejected.");

        Assert.AreEqual(FieldSizeBitsParameterName, exception.ParamName, "The rejection must name the fieldSizeBits parameter.");
        Assert.AreEqual(NoBackendCalls, backend.AddCalls, "A field size outside one scalar must be rejected before any scalar addition.");
        Assert.AreEqual(NoBackendCalls, backend.InvertCalls, "A field size outside one scalar must be rejected before any scalar inversion.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonParameterGenerator.Generate"/> rejects a modulus one byte narrower or one byte
    /// wider than one scalar with an <see cref="ArgumentException"/> that names <c>modulus</c> and states both the
    /// required width and the received length, before any backend delegate is called. The modulus is not passed on
    /// to <see cref="PoseidonParameters"/>, so this guard is the only width check ahead of the rejection sampling
    /// and the one-step reduction, both of which read the modulus as one canonical scalar. Every numeric argument
    /// is valid and both delegates are non-null, so no sibling guard answers first, and the exact exception type
    /// excludes the <see cref="ArgumentOutOfRangeException"/> the numeric range checks raise.
    /// </summary>
    /// <param name="modulusLength">The byte length of the rejected modulus, whose leading bytes are the BN254 order.</param>
    [TestMethod]
    [DataRow(NarrowModulusLength)]
    [DataRow(WideModulusLength)]
    public void GenerateRejectsAModulusThatIsNotOneScalarWide(int modulusLength)
    {
        Memory<byte> modulus = RentBn254Modulus(modulusLength);
        var backend = new CountingBn254ScalarBackend();
        string expectedMessage = $"The modulus must be exactly {ScalarSize} canonical bytes; received {modulusLength}.";

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => PoseidonParameterGenerator.Generate(ValidStateWidth, EvenFullRounds, ValidPartialRounds, Bn254FieldSizeBits, modulus.Span, CurveParameterSet.Bn254, backend.Add, backend.Invert),
            "A modulus that is not one scalar wide must be rejected.");

        Assert.AreEqual(ModulusParameterName, exception.ParamName, "The rejection must name the modulus parameter.");
        Assert.Contains(expectedMessage, exception.Message, StringComparison.Ordinal);
        Assert.AreEqual(NoBackendCalls, backend.AddCalls, "A modulus that is not one scalar wide must be rejected before any scalar addition.");
        Assert.AreEqual(NoBackendCalls, backend.InvertCalls, "A modulus that is not one scalar wide must be rejected before any scalar inversion.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonParameterGenerator.Generate"/> rejects a modulus whose bit length is not
    /// <c>fieldSizeBits</c> with an <see cref="ArgumentException"/> that names <c>modulus</c> and states both bit
    /// lengths, before any backend delegate is called. The field size is the bit length the Grain descriptor
    /// encodes, the width of every draw, and the bound the one-step Cauchy reduction relies on: with a shorter
    /// modulus a raw draw can exceed twice the modulus and leave the reduction non-canonical, and with a longer one
    /// the constants belong to a different parameter set. The BN254 order is 254 bits, so a field size one bit either
    /// side of it is the smallest mismatch. Every other argument is valid and the modulus is one scalar wide, so no
    /// sibling guard answers first, and the exact exception type excludes the
    /// <see cref="ArgumentOutOfRangeException"/> the range checks raise.
    /// </summary>
    /// <param name="fieldSizeBits">A field size one bit shorter or longer than the BN254 order.</param>
    [TestMethod]
    [DataRow(FieldSizeBitsBelowTheBn254Order)]
    [DataRow(FieldSizeBitsAboveTheBn254Order)]
    public void GenerateRejectsAModulusWhoseBitLengthIsNotTheFieldSize(int fieldSizeBits)
    {
        Memory<byte> modulus = RentBn254Modulus(ScalarSize);
        var backend = new CountingBn254ScalarBackend();
        string expectedMessage = $"The modulus bit length must equal fieldSizeBits ({fieldSizeBits}); received a modulus of {Bn254FieldSizeBits} bits.";

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => PoseidonParameterGenerator.Generate(ValidStateWidth, EvenFullRounds, ValidPartialRounds, fieldSizeBits, modulus.Span, CurveParameterSet.Bn254, backend.Add, backend.Invert),
            "A modulus whose bit length is not the field size must be rejected.");

        Assert.AreEqual(ModulusParameterName, exception.ParamName, "The rejection must name the modulus parameter.");
        Assert.Contains(expectedMessage, exception.Message, StringComparison.Ordinal);
        Assert.AreEqual(NoBackendCalls, backend.AddCalls, "A modulus of the wrong bit length must be rejected before any scalar addition.");
        Assert.AreEqual(NoBackendCalls, backend.InvertCalls, "A modulus of the wrong bit length must be rejected before any scalar inversion.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonParameterGenerator.Generate"/> rejects a modulus of zero with an
    /// <see cref="ArgumentException"/> that names <c>modulus</c>, instead of entering rejection sampling, where no
    /// draw can ever fall below zero. Every accepted field size is at least one bit, so the zero modulus's bit length
    /// of zero never matches; every other argument is valid, so no sibling guard answers first.
    /// </summary>
    [TestMethod]
    public void GenerateRejectsAZeroModulus()
    {
        Memory<byte> modulus = RentModulus(ZeroModulusHex);
        var backend = new CountingBn254ScalarBackend();
        string expectedMessage = $"The modulus bit length must equal fieldSizeBits ({Bn254FieldSizeBits}); received a modulus of {ZeroModulusBitLength} bits.";

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => PoseidonParameterGenerator.Generate(ValidStateWidth, EvenFullRounds, ValidPartialRounds, Bn254FieldSizeBits, modulus.Span, CurveParameterSet.Bn254, backend.Add, backend.Invert),
            "A zero modulus must be rejected.");

        Assert.AreEqual(ModulusParameterName, exception.ParamName, "The rejection must name the modulus parameter.");
        Assert.Contains(expectedMessage, exception.Message, StringComparison.Ordinal);
        Assert.AreEqual(NoBackendCalls, backend.AddCalls, "A zero modulus must be rejected before any scalar addition.");
        Assert.AreEqual(NoBackendCalls, backend.InvertCalls, "A zero modulus must be rejected before any scalar inversion.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonParameterGenerator.Generate"/> rejects a null addition backend with an
    /// <see cref="ArgumentNullException"/> that names <c>add</c>, rather than seeding the Grain stream, drawing
    /// every round constant and every Cauchy point, and only then faulting with a
    /// <see cref="NullReferenceException"/> at the first Cauchy sum. Nothing downstream repeats the check: the
    /// generator holds the delegate until the MDS matrix is built, and <see cref="PoseidonParameters"/> never sees
    /// it. The inversion backend is non-null and every numeric and span argument is valid, so no sibling guard
    /// answers first, and the inversion guard reports <c>invert</c> rather than this name.
    /// </summary>
    [TestMethod]
    public void GenerateRejectsANullAddBackendBeforeAnyInversion()
    {
        Memory<byte> modulus = RentBn254Modulus(ScalarSize);
        var backend = new CountingBn254ScalarBackend();

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => PoseidonParameterGenerator.Generate(ValidStateWidth, EvenFullRounds, ValidPartialRounds, Bn254FieldSizeBits, modulus.Span, CurveParameterSet.Bn254, null!, backend.Invert),
            "A null addition backend must be rejected.");

        Assert.AreEqual(AddParameterName, exception.ParamName, "The rejection must name the add parameter.");
        Assert.AreEqual(NoBackendCalls, backend.InvertCalls, "A null addition backend must be rejected before any scalar inversion.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonParameterGenerator.Generate"/> rejects a null inversion backend with an
    /// <see cref="ArgumentNullException"/> that names <c>invert</c>, rather than drawing the whole stream, adding
    /// the first Cauchy pair through the live addition backend, and only then faulting with a
    /// <see cref="NullReferenceException"/>. The zero addition count is what shows the refusal comes from the
    /// guard rather than from the delegate invocation that follows the first sum. The addition backend is non-null
    /// and every numeric and span argument is valid, so no sibling guard answers first.
    /// </summary>
    [TestMethod]
    public void GenerateRejectsANullInvertBackendBeforeAnyAddition()
    {
        Memory<byte> modulus = RentBn254Modulus(ScalarSize);
        var backend = new CountingBn254ScalarBackend();

        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => PoseidonParameterGenerator.Generate(ValidStateWidth, EvenFullRounds, ValidPartialRounds, Bn254FieldSizeBits, modulus.Span, CurveParameterSet.Bn254, backend.Add, null!),
            "A null inversion backend must be rejected.");

        Assert.AreEqual(InvertParameterName, exception.ParamName, "The rejection must name the invert parameter.");
        Assert.AreEqual(NoBackendCalls, backend.AddCalls, "A null inversion backend must be rejected before any scalar addition.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonParameterGenerator.Generate"/> rejects a state width below two with an
    /// <see cref="ArgumentOutOfRangeException"/> that names <c>stateWidth</c>, and that it does so before any
    /// backend delegate is called. The <see cref="PoseidonParameters"/> constructor repeats the same width check
    /// with the same exception, parameter name and message, so the zero add and invert counts are the only thing
    /// that distinguishes a generator which refuses the width outright from one that draws a single lane's
    /// constants and Cauchy points first and leaves the refusal to the constructor. Both delegates are non-null,
    /// both round counts are positive with an even full-round count, the field size fits one scalar and the
    /// modulus is one scalar wide, so no sibling guard answers first and no other guard reports this name.
    /// </summary>
    [TestMethod]
    public void GenerateRejectsAStateWidthBelowTwoBeforeAnyBackendCall()
    {
        Memory<byte> modulus = RentBn254Modulus(ScalarSize);
        var backend = new CountingBn254ScalarBackend();

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => PoseidonParameterGenerator.Generate(SingleLaneStateWidth, EvenFullRounds, ValidPartialRounds, Bn254FieldSizeBits, modulus.Span, CurveParameterSet.Bn254, backend.Add, backend.Invert),
            "A state width below two must be rejected.");

        Assert.AreEqual(StateWidthParameterName, exception.ParamName, "The rejection must name the stateWidth parameter.");
        Assert.AreEqual(NoBackendCalls, backend.AddCalls, "A state width below two must be rejected before any scalar addition.");
        Assert.AreEqual(NoBackendCalls, backend.InvertCalls, "A state width below two must be rejected before any scalar inversion.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonParameterGenerator.Generate"/> rejects a full-round count of zero with an
    /// <see cref="ArgumentOutOfRangeException"/> that names <c>fullRounds</c>, and that it does so before any
    /// backend delegate is called. Zero is even, so the parity guard cannot answer and only the range check can
    /// fire; both guards report this same parameter name, so the absence of the parity guard's message is what
    /// says which of the two refused. The <see cref="PoseidonParameters"/> constructor repeats that range check
    /// identically, so the zero add and invert counts are what pin the refusal to the generator rather than to the
    /// constructor after a completed Grain generation. Every other argument is valid, so no sibling guard answers
    /// first.
    /// </summary>
    [TestMethod]
    public void GenerateRejectsZeroFullRoundsBeforeAnyBackendCall()
    {
        Memory<byte> modulus = RentBn254Modulus(ScalarSize);
        var backend = new CountingBn254ScalarBackend();

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => PoseidonParameterGenerator.Generate(ValidStateWidth, ZeroFullRounds, ValidPartialRounds, Bn254FieldSizeBits, modulus.Span, CurveParameterSet.Bn254, backend.Add, backend.Invert),
            "A full-round count of zero must be rejected.");

        Assert.AreEqual(FullRoundsParameterName, exception.ParamName, "The rejection must name the fullRounds parameter.");
        Assert.DoesNotContain(OddFullRoundsMessage, exception.Message, StringComparison.Ordinal, "A full-round count of zero must be refused by the range check, not by the parity check.");
        Assert.AreEqual(NoBackendCalls, backend.AddCalls, "A full-round count of zero must be rejected before any scalar addition.");
        Assert.AreEqual(NoBackendCalls, backend.InvertCalls, "A full-round count of zero must be rejected before any scalar inversion.");
    }


    /// <summary>
    /// Pins that <see cref="PoseidonParameterGenerator.Generate"/> rejects a partial-round count of zero with an
    /// <see cref="ArgumentOutOfRangeException"/> that names <c>partialRounds</c>, and that it does so before any
    /// backend delegate is called. The <see cref="PoseidonParameters"/> constructor repeats that range check
    /// identically, so the zero add and invert counts are what pin the refusal to the generator rather than to the
    /// constructor after a completed Grain generation. No other guard reports this parameter name, and every other
    /// argument is valid, so no sibling guard answers first.
    /// </summary>
    [TestMethod]
    public void GenerateRejectsZeroPartialRoundsBeforeAnyBackendCall()
    {
        Memory<byte> modulus = RentBn254Modulus(ScalarSize);
        var backend = new CountingBn254ScalarBackend();

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => PoseidonParameterGenerator.Generate(ValidStateWidth, EvenFullRounds, ZeroPartialRounds, Bn254FieldSizeBits, modulus.Span, CurveParameterSet.Bn254, backend.Add, backend.Invert),
            "A partial-round count of zero must be rejected.");

        Assert.AreEqual(PartialRoundsParameterName, exception.ParamName, "The rejection must name the partialRounds parameter.");
        Assert.AreEqual(NoBackendCalls, backend.AddCalls, "A partial-round count of zero must be rejected before any scalar addition.");
        Assert.AreEqual(NoBackendCalls, backend.InvertCalls, "A partial-round count of zero must be rejected before any scalar inversion.");
    }


    /// <summary>
    /// Pins that a field size of exactly one scalar is inside the accepted range: 256 bits is the widest modulus
    /// bit length a canonical scalar carries, every value bit of such a draw lands inside the destination, and a
    /// modulus of that bit length keeps the one-step Cauchy reduction correct. The generation therefore runs to
    /// completion and asks the backends for one addition and one inversion per MDS entry, which is what separates
    /// the accepted boundary from the first rejected width one bit above it.
    /// </summary>
    [TestMethod]
    public void GenerateAcceptsAFieldSizeOfExactlyOneScalar()
    {
        Memory<byte> modulus = RentModulus(WidestModulusHex);
        var backend = new CountingBn254ScalarBackend();

        PoseidonParameters parameters = PoseidonParameterGenerator.Generate(
            ValidStateWidth, EvenFullRounds, ValidPartialRounds, FieldSizeBitsOfOneScalar, modulus.Span, CurveParameterSet.Bn254, backend.Add, backend.Invert);

        Assert.AreEqual(ValidStateWidth, parameters.StateWidth, "The accepted generation must carry the requested state width.");
        Assert.AreEqual(EvenFullRounds, parameters.FullRounds, "The accepted generation must carry the requested full-round count.");
        Assert.AreEqual(ValidPartialRounds, parameters.PartialRounds, "The accepted generation must carry the requested partial-round count.");
        Assert.AreEqual(MdsEntryCount, backend.AddCalls, "A completed generation must ask for one addition per MDS entry.");
        Assert.AreEqual(MdsEntryCount, backend.InvertCalls, "A completed generation must ask for one inversion per MDS entry.");
    }


    /// <summary>
    /// Pins the round constants the Grain stream yields for a two-lane state over an eight-bit field against the
    /// values the procedure defines: seed the 80-bit register with the parameter descriptor, step it by the
    /// feedback recurrence, discard the first 160 raw bits, and take the remaining bits pairwise. The modulus
    /// <c>0xFB</c> has the field's eight-bit length and lies above all six draws, so no draw is rejected and each
    /// constant is exactly the eight filtered bits that follow the previous one. That makes the whole register — its
    /// seeding, its stepping and the discarded prefix — observable in six bytes.
    /// </summary>
    [TestMethod]
    public void GenerateDrawsTheGrainRoundConstantsOverAnEightBitField()
    {
        Memory<byte> modulus = RentModulus(EightBitModulusHex);
        var backend = new CountingBn254ScalarBackend();

        PoseidonParameters parameters = PoseidonParameterGenerator.Generate(
            ValidStateWidth, EvenFullRounds, ValidPartialRounds, EightBitFieldSize, modulus.Span, CurveParameterSet.Bn254, backend.Add, backend.Invert);

        Span<byte> expectedLowBytes = stackalloc byte[SmallShapeConstantCount];
        _ = Convert.FromHexString(ExpectedEightBitRoundConstantsHex, expectedLowBytes, out _, out _);
        Span<byte> expected = stackalloc byte[ScalarSize];

        for(int round = 0; round < SmallShapeRoundCount; round++)
        {
            for(int lane = 0; lane < ValidStateWidth; lane++)
            {
                expected.Clear();
                expected[ScalarSize - 1] = expectedLowBytes[(round * ValidStateWidth) + lane];
                ReadOnlySpan<byte> generated = parameters.GetRoundConstant(round, lane);
                Assert.IsTrue(
                    generated.SequenceEqual(expected),
                    $"The round constant for round {round} lane {lane} must be the Grain draw {Convert.ToHexString(expected)}; generated {Convert.ToHexString(generated)}.");
            }
        }
    }


    /// <summary>
    /// Pins the Cauchy MDS matrix a two-lane state builds over a sixteen-bit modulus. The Cauchy points continue
    /// the same Grain stream as raw sixteen-bit draws, taken without rejection and reduced once modulo the
    /// modulus, and a modulus of sixteen bits puts roughly half of those draws above it, so the pinned entries
    /// cover both a point taken as drawn and a point carried through the borrow chain of the reduction. The
    /// modulus governs only the sampling: the sums and their inverses are taken by the BN254 reference backends,
    /// so each entry is the inverse in the BN254 scalar field of one reduced point pair's sum.
    /// </summary>
    [TestMethod]
    public void GenerateReducesARawCauchyDrawOnceBelowANarrowModulus()
    {
        Memory<byte> modulus = RentModulus(NarrowModulusHex);
        var backend = new CountingBn254ScalarBackend();

        PoseidonParameters parameters = PoseidonParameterGenerator.Generate(
            ValidStateWidth, EvenFullRounds, ValidPartialRounds, SixteenBitFieldSize, modulus.Span, CurveParameterSet.Bn254, backend.Add, backend.Invert);

        Span<byte> expected = stackalloc byte[MdsByteCount];
        _ = Convert.FromHexString(ExpectedNarrowMdsHex, expected, out _, out _);

        for(int row = 0; row < ValidStateWidth; row++)
        {
            for(int column = 0; column < ValidStateWidth; column++)
            {
                ReadOnlySpan<byte> expectedEntry = expected.Slice(((row * ValidStateWidth) + column) * ScalarSize, ScalarSize);
                ReadOnlySpan<byte> generated = parameters.GetMdsEntry(row, column);
                Assert.IsTrue(
                    generated.SequenceEqual(expectedEntry),
                    $"The MDS entry at row {row} column {column} must invert the sum of the reduced Cauchy points; expected {Convert.ToHexString(expectedEntry)}, generated {Convert.ToHexString(generated)}.");
            }
        }

        Assert.AreEqual(MdsEntryCount, backend.AddCalls, "A completed generation must ask for one addition per MDS entry.");
        Assert.AreEqual(MdsEntryCount, backend.InvertCalls, "A completed generation must ask for one inversion per MDS entry.");
    }


    /// <summary>
    /// Pins that every round constant the generator keeps is strictly below the modulus. A modulus of one makes
    /// that boundary testable: zero is the only field element below it, so a draw equal to the modulus must be
    /// rejected and redrawn, and the expected value follows from the modulus alone rather than from the stream. A
    /// one-bit field size matches the modulus bit length, so each attempt is a single filtered bit and the
    /// rejection loop ends at the first zero bit it draws.
    /// </summary>
    [TestMethod]
    public void GenerateDrawsEveryRoundConstantBelowTheModulus()
    {
        Memory<byte> modulus = RentModulus(UnitModulusHex);
        var backend = new UnitSumRecordingBackend(RentScalarBuffer());

        PoseidonParameters parameters = PoseidonParameterGenerator.Generate(
            WideStateWidth, EvenFullRounds, WidePartialRounds, UnitFieldSizeBits, modulus.Span, CurveParameterSet.Bn254, backend.Add, backend.Invert);

        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();

        for(int round = 0; round < WideShapeRoundCount; round++)
        {
            for(int lane = 0; lane < WideStateWidth; lane++)
            {
                ReadOnlySpan<byte> generated = parameters.GetRoundConstant(round, lane);
                Assert.IsTrue(
                    generated.SequenceEqual(zero),
                    $"The round constant for round {round} lane {lane} must be the only field element below a modulus of one; generated {Convert.ToHexString(generated)}.");
            }
        }
    }


    /// <summary>
    /// Pins that every Cauchy point the generator hands to the addition backend has been reduced below the
    /// modulus. The raw Cauchy draws are taken without rejection, so the one-step reduction is the only thing that
    /// brings a draw that reached or passed the modulus back into the field, and the reduced points are visible
    /// only as the operands of the caller-supplied addition. A modulus of one makes every such draw either already
    /// zero or exactly the modulus, so the union of every operand byte is zero precisely when each draw that
    /// needed reducing was reduced.
    /// </summary>
    [TestMethod]
    public void GenerateReducesEveryCauchyPointBelowTheModulus()
    {
        Memory<byte> modulus = RentModulus(UnitModulusHex);
        Memory<byte> operandUnion = RentScalarBuffer();
        var backend = new UnitSumRecordingBackend(operandUnion);

        _ = PoseidonParameterGenerator.Generate(
            WideStateWidth, EvenFullRounds, WidePartialRounds, UnitFieldSizeBits, modulus.Span, CurveParameterSet.Bn254, backend.Add, backend.Invert);

        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();

        Assert.IsTrue(
            operandUnion.Span.SequenceEqual(zero),
            $"Every Cauchy point handed to the addition backend must be reduced below the modulus; the union of the operands was {Convert.ToHexString(operandUnion.Span)}.");
        Assert.AreEqual(WideMdsEntryCount, backend.AddCalls, "A completed generation must ask for one addition per MDS entry.");
        Assert.AreEqual(WideMdsEntryCount, backend.InvertCalls, "A completed generation must ask for one inversion per MDS entry.");
    }


    /// <summary>
    /// Rents a modulus buffer of <paramref name="length"/> bytes whose leading bytes are the BN254 scalar-field
    /// order and whose remaining bytes are zero. The rental is tracked for cleanup, and the buffer is returned as
    /// <see cref="Memory{T}"/> because the assertion lambdas can capture it where they cannot capture a stack span.
    /// </summary>
    /// <param name="length">The modulus length in bytes.</param>
    /// <returns>The modulus buffer, exactly <paramref name="length"/> bytes long.</returns>
    private Memory<byte> RentBn254Modulus(int length)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(length);
        Disposables.Add(owner);

        Span<byte> order = stackalloc byte[ScalarSize];
        _ = Convert.FromHexString(Bn254ScalarOrderHex, order, out _, out _);

        Memory<byte> modulus = owner.Memory[..length];
        modulus.Span.Clear();
        order[..Math.Min(length, ScalarSize)].CopyTo(modulus.Span);

        return modulus;
    }


    /// <summary>
    /// Rents a cleared buffer exactly one scalar wide and tracks the rental for cleanup. The buffer is returned as
    /// <see cref="Memory{T}"/> so that a backend the generator calls back into can hold it across invocations,
    /// which a stack span cannot be.
    /// </summary>
    /// <returns>The cleared buffer, exactly one scalar wide.</returns>
    private Memory<byte> RentScalarBuffer()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(ScalarSize);
        Disposables.Add(owner);

        Memory<byte> buffer = owner.Memory[..ScalarSize];
        buffer.Span.Clear();

        return buffer;
    }


    /// <summary>
    /// Rents a modulus buffer exactly one scalar wide holding <paramref name="modulusHex"/> as canonical
    /// big-endian bytes, and tracks the rental for cleanup.
    /// </summary>
    /// <param name="modulusHex">The modulus, exactly one scalar wide, as hexadecimal.</param>
    /// <returns>The modulus buffer, exactly one scalar wide.</returns>
    private Memory<byte> RentModulus(string modulusHex)
    {
        Memory<byte> modulus = RentScalarBuffer();
        _ = Convert.FromHexString(modulusHex, modulus.Span, out _, out _);

        return modulus;
    }


    /// <summary>
    /// A BN254 scalar backend that counts the additions and inversions it is asked for and forwards each one to the
    /// BigInteger reference, so a test observes whether generation reached the backend at all.
    /// </summary>
    private sealed class CountingBn254ScalarBackend
    {
        /// <summary>The number of scalar additions requested so far.</summary>
        public int AddCalls { get; private set; }

        /// <summary>The number of scalar inversions requested so far.</summary>
        public int InvertCalls { get; private set; }


        /// <summary>Counts one scalar addition and forwards it to the BN254 reference.</summary>
        /// <param name="a">The left operand, canonical big-endian.</param>
        /// <param name="b">The right operand, canonical big-endian.</param>
        /// <param name="result">The destination of the canonical sum.</param>
        /// <param name="curve">The curve identifying the scalar field.</param>
        public void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
        {
            AddCalls++;
            Bn254Add(a, b, result, curve);
        }


        /// <summary>Counts one scalar inversion and forwards it to the BN254 reference.</summary>
        /// <param name="a">The operand, canonical big-endian.</param>
        /// <param name="result">The destination of the canonical inverse.</param>
        /// <param name="curve">The curve identifying the scalar field.</param>
        public void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
        {
            InvertCalls++;
            Bn254Invert(a, result, curve);
        }
    }


    /// <summary>
    /// A BN254 scalar backend for a generation over a modulus of one, where every Cauchy point is zero and the
    /// reference inversion of the resulting zero sum would throw. It reports each sum offset by the scalar one,
    /// which keeps every inversion defined without touching the operands, and it accumulates the bitwise union of
    /// every addition operand, so a test reads whether any Cauchy point reached the backend above the modulus.
    /// </summary>
    private sealed class UnitSumRecordingBackend
    {
        /// <summary>The buffer the bitwise union of every addition operand accumulates in, one scalar wide.</summary>
        private Memory<byte> OperandUnion { get; }

        /// <summary>The number of scalar additions requested so far.</summary>
        public int AddCalls { get; private set; }

        /// <summary>The number of scalar inversions requested so far.</summary>
        public int InvertCalls { get; private set; }


        /// <summary>Constructs the backend over a cleared union buffer.</summary>
        /// <param name="operandUnion">The cleared buffer the operand union accumulates in, one scalar wide.</param>
        public UnitSumRecordingBackend(Memory<byte> operandUnion)
        {
            OperandUnion = operandUnion;
        }


        /// <summary>
        /// Folds both operands into the running union, counts the addition, and reports the BN254 reference sum
        /// offset by one so that no inversion downstream is asked for the inverse of zero.
        /// </summary>
        /// <param name="a">The left operand, canonical big-endian.</param>
        /// <param name="b">The right operand, canonical big-endian.</param>
        /// <param name="result">The destination of the reported sum.</param>
        /// <param name="curve">The curve identifying the scalar field.</param>
        public void Add(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> result, CurveParameterSet curve)
        {
            Accumulate(a);
            Accumulate(b);
            AddCalls++;

            Span<byte> one = stackalloc byte[ScalarSize];
            one.Clear();
            one[ScalarSize - 1] = UnitScalarLowByte;
            Span<byte> sum = stackalloc byte[ScalarSize];
            Bn254Add(a, b, sum, curve);
            Bn254Add(sum, one, result, curve);
        }


        /// <summary>Counts one scalar inversion and forwards it to the BN254 reference.</summary>
        /// <param name="a">The operand, canonical big-endian.</param>
        /// <param name="result">The destination of the canonical inverse.</param>
        /// <param name="curve">The curve identifying the scalar field.</param>
        public void Invert(ReadOnlySpan<byte> a, Span<byte> result, CurveParameterSet curve)
        {
            InvertCalls++;
            Bn254Invert(a, result, curve);
        }


        /// <summary>Folds one addition operand into the running bitwise union.</summary>
        /// <param name="operand">The operand, canonical big-endian.</param>
        private void Accumulate(ReadOnlySpan<byte> operand)
        {
            Span<byte> union = OperandUnion.Span;
            for(int i = 0; i < union.Length; i++)
            {
                union[i] |= operand[i];
            }
        }
    }
}

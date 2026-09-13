using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Buffers;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>
/// Argument validation for <see cref="PoseidonParameterGenerator.Generate"/>: an odd full-round count, a field
/// size that is zero or wider than one scalar, and a modulus that is not one scalar wide are each rejected with
/// the documented exception and parameter name before the Grain stream is seeded and before the caller-supplied
/// add and invert backends run.
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
}

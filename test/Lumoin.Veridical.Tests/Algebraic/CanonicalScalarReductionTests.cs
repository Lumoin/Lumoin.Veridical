using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.Algebraic;

/// <summary>Byte-exact reduction, borrow propagation, aliasing and width guards for canonical scalar bytes.</summary>
[TestClass]
internal sealed class CanonicalScalarReductionTests
{
    /// <summary>The byte width used by the witness and nonce callers.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The smallest nonempty width, which exercises reduction without leading padding.</summary>
    private const int SingleByteSize = 1;

    /// <summary>An operand width one byte shorter than the canonical scalar.</summary>
    private const int NarrowLength = ScalarSize - 1;

    /// <summary>An operand width one byte longer than the canonical scalar.</summary>
    private const int WideLength = ScalarSize + 1;

    /// <summary>A zero scalar's low byte.</summary>
    private const byte ZeroByte = 0;

    /// <summary>A unit scalar's low byte and the leading byte that terminates a borrow chain.</summary>
    private const byte UnitByte = 1;

    /// <summary>The low byte of a modulus above half the single-byte range.</summary>
    private const byte ModulusLowByte = 0xA7;

    /// <summary>A nonzero low byte strictly below the modulus.</summary>
    private const byte BelowModulusLowByte = 0x53;

    /// <summary>A low byte strictly above the modulus and below twice the modulus.</summary>
    private const byte AboveModulusLowByte = 0xFE;

    /// <summary>The low byte of the above-modulus input after exactly one subtraction.</summary>
    private const byte ReducedLowByte = 0x57;

    /// <summary>The final borrow when subtraction does not underflow.</summary>
    private const int NoBorrow = 0;

    /// <summary>The final borrow when subtraction underflows the entire byte width.</summary>
    private const int FullBorrow = 1;


    /// <summary>Zero and a nonzero value below the modulus survive both reduction entry points unchanged.</summary>
    /// <param name="lowByte">The low byte of the input below the modulus.</param>
    [TestMethod]
    [DataRow(ZeroByte)]
    [DataRow(BelowModulusLowByte)]
    public void ReduceOnceBelowModulusKeepsValue(byte lowByte)
    {
        Span<byte> value = stackalloc byte[ScalarSize];
        Span<byte> modulus = stackalloc byte[ScalarSize];
        WriteLowByte(lowByte, value);
        WriteLowByte(ModulusLowByte, modulus);

        AssertReduction(value, modulus, value);
    }


    /// <summary>An input equal to the modulus reduces to zero at both supported test widths.</summary>
    /// <param name="length">The common byte width of the operands and destination.</param>
    [TestMethod]
    [DataRow(SingleByteSize)]
    [DataRow(ScalarSize)]
    public void ReduceOnceEqualToModulusReturnsZero(int length)
    {
        Span<byte> value = stackalloc byte[length];
        Span<byte> modulus = stackalloc byte[length];
        Span<byte> expected = stackalloc byte[length];
        WriteLowByte(ModulusLowByte, value);
        WriteLowByte(ModulusLowByte, modulus);
        expected.Clear();

        AssertReduction(value, modulus, expected);
    }


    /// <summary>An input between the modulus and twice the modulus is reduced by exactly one subtraction.</summary>
    /// <param name="length">The common byte width of the operands and destination.</param>
    [TestMethod]
    [DataRow(SingleByteSize)]
    [DataRow(ScalarSize)]
    public void ReduceOnceAboveModulusSubtractsOnce(int length)
    {
        Span<byte> value = stackalloc byte[length];
        Span<byte> modulus = stackalloc byte[length];
        Span<byte> expected = stackalloc byte[length];
        WriteLowByte(AboveModulusLowByte, value);
        WriteLowByte(ModulusLowByte, modulus);
        WriteLowByte(ReducedLowByte, expected);

        AssertReduction(value, modulus, expected);
    }


    /// <summary>The subtraction 0x0100...00 minus 0x00FF...FF propagates a borrow to the leading byte.</summary>
    [TestMethod]
    public void ReduceOncePropagatesBorrowAcrossEveryByte()
    {
        Span<byte> value = stackalloc byte[ScalarSize];
        Span<byte> modulus = stackalloc byte[ScalarSize];
        Span<byte> expected = stackalloc byte[ScalarSize];
        value.Clear();
        value[0] = UnitByte;
        modulus.Fill(byte.MaxValue);
        modulus[0] = ZeroByte;
        WriteLowByte(UnitByte, expected);

        //Every lower byte borrows, and the leading unit settles the final borrow.
        AssertReduction(value, modulus, expected);
    }


    /// <summary>The final borrow is zero for both equal operands and a strictly larger minuend.</summary>
    /// <param name="minuendLowByte">The low byte of the original minuend.</param>
    /// <param name="expectedLowByte">The low byte of the expected difference.</param>
    [TestMethod]
    [DataRow(ModulusLowByte, ZeroByte)]
    [DataRow(AboveModulusLowByte, ReducedLowByte)]
    public void SubtractInPlaceReturnsZeroWhenMinuendIsAtLeastSubtrahend(byte minuendLowByte, byte expectedLowByte)
    {
        Span<byte> minuend = stackalloc byte[ScalarSize];
        Span<byte> subtrahend = stackalloc byte[ScalarSize];
        Span<byte> expected = stackalloc byte[ScalarSize];
        WriteLowByte(minuendLowByte, minuend);
        WriteLowByte(ModulusLowByte, subtrahend);
        WriteLowByte(expectedLowByte, expected);

        int borrow = CanonicalScalarReduction.SubtractInPlace(minuend, subtrahend);

        Assert.AreEqual(NoBorrow, borrow, "A nonnegative difference must not borrow beyond the scalar.");
        Assert.IsTrue(minuend.SequenceEqual(expected), "Subtraction must write the exact big-endian difference.");
    }


    /// <summary>Zero minus one wraps to all set bits and reports a borrow beyond the leading byte.</summary>
    [TestMethod]
    public void SubtractInPlaceReturnsOneForFullBorrow()
    {
        Span<byte> minuend = stackalloc byte[ScalarSize];
        Span<byte> subtrahend = stackalloc byte[ScalarSize];
        Span<byte> expected = stackalloc byte[ScalarSize];
        minuend.Clear();
        WriteLowByte(UnitByte, subtrahend);
        expected.Fill(byte.MaxValue);

        int borrow = CanonicalScalarReduction.SubtractInPlace(minuend, subtrahend);

        Assert.AreEqual(FullBorrow, borrow, "Zero minus one must borrow across the entire scalar.");
        Assert.IsTrue(minuend.SequenceEqual(expected), "Underflow must wrap at the scalar's byte width.");
    }


    /// <summary>A modulus whose width differs from the input is rejected before reduction.</summary>
    /// <param name="modulusLength">The rejected modulus width.</param>
    [TestMethod]
    [DataRow(NarrowLength)]
    [DataRow(WideLength)]
    public void ReduceOnceRejectsMismatchedModulusLength(int modulusLength)
    {
        Assert.ThrowsExactly<ArgumentException>(() => InvokeReduceOnce(modulusLength, ScalarSize));
    }


    /// <summary>A destination whose width differs from the input is rejected before reduction.</summary>
    /// <param name="destinationLength">The rejected destination width.</param>
    [TestMethod]
    [DataRow(NarrowLength)]
    [DataRow(WideLength)]
    public void ReduceOnceRejectsMismatchedDestinationLength(int destinationLength)
    {
        Assert.ThrowsExactly<ArgumentException>(() => InvokeReduceOnce(ScalarSize, destinationLength));
    }


    /// <summary>In-place reduction enforces the same equal-width contract as separate-output reduction.</summary>
    /// <param name="modulusLength">The rejected modulus width.</param>
    [TestMethod]
    [DataRow(NarrowLength)]
    [DataRow(WideLength)]
    public void ReduceOnceInPlaceRejectsMismatchedLength(int modulusLength)
    {
        Assert.ThrowsExactly<ArgumentException>(() => InvokeReduceOnceInPlace(modulusLength));
    }


    /// <summary>In-place subtraction rejects a subtrahend of a different width.</summary>
    /// <param name="subtrahendLength">The rejected subtrahend width.</param>
    [TestMethod]
    [DataRow(NarrowLength)]
    [DataRow(WideLength)]
    public void SubtractInPlaceRejectsMismatchedLength(int subtrahendLength)
    {
        Assert.ThrowsExactly<ArgumentException>(() => InvokeSubtractInPlace(subtrahendLength));
    }


    /// <summary>Invokes separate-output reduction with stack buffers of the requested widths.</summary>
    /// <param name="modulusLength">The modulus buffer width.</param>
    /// <param name="destinationLength">The destination buffer width.</param>
    private static void InvokeReduceOnce(int modulusLength, int destinationLength)
    {
        Span<byte> value = stackalloc byte[ScalarSize];
        Span<byte> modulus = stackalloc byte[modulusLength];
        Span<byte> destination = stackalloc byte[destinationLength];
        value.Clear();
        WriteLowByte(ModulusLowByte, modulus);

        CanonicalScalarReduction.ReduceOnce(value, modulus, destination);
    }


    /// <summary>Invokes in-place reduction with a stack modulus buffer of the requested width.</summary>
    /// <param name="modulusLength">The modulus buffer width.</param>
    private static void InvokeReduceOnceInPlace(int modulusLength)
    {
        Span<byte> value = stackalloc byte[ScalarSize];
        Span<byte> modulus = stackalloc byte[modulusLength];
        value.Clear();
        WriteLowByte(ModulusLowByte, modulus);

        CanonicalScalarReduction.ReduceOnceInPlace(value, modulus);
    }


    /// <summary>Invokes in-place subtraction with a stack subtrahend buffer of the requested width.</summary>
    /// <param name="subtrahendLength">The subtrahend buffer width.</param>
    private static void InvokeSubtractInPlace(int subtrahendLength)
    {
        Span<byte> minuend = stackalloc byte[ScalarSize];
        Span<byte> subtrahend = stackalloc byte[subtrahendLength];
        minuend.Clear();
        WriteLowByte(UnitByte, subtrahend);

        CanonicalScalarReduction.SubtractInPlace(minuend, subtrahend);
    }


    /// <summary>Checks separate-output reduction, explicit in-place reduction and an exactly aliased destination.</summary>
    /// <param name="value">The original value below twice the modulus.</param>
    /// <param name="modulus">The nonzero modulus.</param>
    /// <param name="expected">The pinned canonical result.</param>
    private static void AssertReduction(ReadOnlySpan<byte> value, ReadOnlySpan<byte> modulus, ReadOnlySpan<byte> expected)
    {
        Span<byte> destination = stackalloc byte[value.Length];
        destination.Fill(byte.MaxValue);
        CanonicalScalarReduction.ReduceOnce(value, modulus, destination);
        Assert.IsTrue(destination.SequenceEqual(expected), "Reduction must write the exact canonical result.");

        //An aliased destination must retain the original input when the subtraction underflows.
        value.CopyTo(destination);
        CanonicalScalarReduction.ReduceOnceInPlace(destination, modulus);
        Assert.IsTrue(destination.SequenceEqual(expected), "In-place reduction must agree with separate-output reduction.");

        value.CopyTo(destination);
        CanonicalScalarReduction.ReduceOnce(destination, modulus, destination);
        Assert.IsTrue(destination.SequenceEqual(expected), "An exactly aliased destination must preserve the same reduction.");
    }


    /// <summary>Writes a zero-padded canonical scalar with the supplied least significant byte.</summary>
    /// <param name="lowByte">The scalar's least significant byte.</param>
    /// <param name="destination">The nonempty scalar buffer to fill.</param>
    private static void WriteLowByte(byte lowByte, Span<byte> destination)
    {
        destination.Clear();
        destination[^1] = lowByte;
    }
}

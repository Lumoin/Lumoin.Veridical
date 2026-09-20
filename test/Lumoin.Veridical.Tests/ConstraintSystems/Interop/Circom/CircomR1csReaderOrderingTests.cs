using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.Circom;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Numerics;
using System.Threading;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.Circom;

/// <summary>
/// The reader accepts wire ids in any order within a constraint and sorts the encoded terms before constructing
/// the matrices, keeping each coefficient paired with its wire.
/// </summary>
/// <remarks>
/// A minimal in-test encoder supplies the same constraint system in different term orders so the sorting contract
/// is independent of the term order in the committed circuit fixtures.
/// </remarks>
[TestClass]
internal sealed class CircomR1csReaderOrderingTests
{
    /// <summary>The 32-byte scalar width of the BLS12-381 field used by these encoded circuits.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The four ASCII bytes in the R1CS file signature.</summary>
    private const int MagicBytes = 4;

    /// <summary>The file header holds the magic, a 32-bit version and a 32-bit section count.</summary>
    private const int FileHeaderBytes = MagicBytes + sizeof(uint) + sizeof(uint);

    /// <summary>Each section starts with a 32-bit type and a 64-bit payload length.</summary>
    private const int SectionPrefixBytes = sizeof(uint) + sizeof(ulong);

    /// <summary>Version 1 identifies the supported R1CS binary layout.</summary>
    private const uint FileVersion = 1u;

    /// <summary>The test encoding includes the header and constraint sections only.</summary>
    private const uint SectionCount = 2u;

    /// <summary>Section type 1 identifies the field and circuit header.</summary>
    private const uint HeaderSectionType = 1u;

    /// <summary>Section type 2 identifies the encoded linear combinations.</summary>
    private const uint ConstraintSectionType = 2u;

    /// <summary>The header carries four 32-bit wire counts: total, public outputs, public inputs and private inputs.</summary>
    private const int HeaderWireCountFieldCount = 4;

    /// <summary>The header payload contains the field width, prime, four wire counts, label count and constraint count.</summary>
    private const int HeaderPayloadBytes = sizeof(uint) + ScalarSize + (HeaderWireCountFieldCount * sizeof(uint)) + sizeof(ulong) + sizeof(uint);

    /// <summary>Each constraint encodes one linear combination for each of A, B and C.</summary>
    private const int LinearCombinationsPerConstraint = 3;

    /// <summary>Each term occupies one 32-bit wire index followed by one scalar coefficient.</summary>
    private const int EncodedTermBytes = sizeof(uint) + ScalarSize;

    /// <summary>The leading constant wire is excluded from the private input and witness counts.</summary>
    private const int ConstantWireCount = 1;

    /// <summary>The encoded circuit declares its single result wire as a public output.</summary>
    private const uint PublicOutputWireCount = 1u;

    /// <summary>The encoded circuits declare no public input wires.</summary>
    private const uint PublicInputWireCount = 0u;

    /// <summary>The constant and the one public output account for the two nonprivate wires.</summary>
    private const int NonPrivateWireCount = ConstantWireCount + (int)PublicOutputWireCount;

    /// <summary>The witness supplies the three nonconstant wires of the four-wire circuit.</summary>
    private const int WitnessVariableCount = TwoTermWireCount - ConstantWireCount;

    /// <summary>The lower input wire is the first returned witness scalar after the constant is omitted.</summary>
    private const int FirstInputOffset = 0;

    /// <summary>The higher input wire follows the lower input by one scalar.</summary>
    private const int SecondInputOffset = FirstInputOffset + ScalarSize;

    /// <summary>The result follows both input scalars in witness order.</summary>
    private const int ResultOffset = SecondInputOffset + ScalarSize;

    /// <summary>The lower wire value is 2 in the satisfying addition witness.</summary>
    private const int FirstInputValue = 2;

    /// <summary>The higher wire value is 3 in the satisfying addition witness.</summary>
    private const int SecondInputValue = 3;

    /// <summary>The result is 5 so the addition constraint is satisfied.</summary>
    private const int ResultValue = FirstInputValue + SecondInputValue;

    /// <summary>The wire count of the one-constraint circuit whose C linear combination has no terms: the constant wire and three others.</summary>
    private const int EmptyMatrixWireCount = 4;

    /// <summary>The constant wire <c>z[0] = 1</c>, which the B linear combination names.</summary>
    private const int ConstantWire = 0;

    /// <summary>A non-constant wire, which the A linear combination names.</summary>
    private const int OutputWire = 1;

    /// <summary>The number of entries the reader stores for a matrix that received no terms: the single synthesised entry.</summary>
    private const int SynthesisedNonzeroCount = 1;

    /// <summary>The row of the entry the reader synthesises for a matrix that received no terms.</summary>
    private const int SynthesisedRow = 0;

    /// <summary>The column of the entry the reader synthesises for a matrix that received no terms.</summary>
    private const int SynthesisedColumn = 0;

    /// <summary>The index of the first stored triple of a matrix.</summary>
    private const int FirstTripleIndex = 0;

    /// <summary>The value of every byte of a zero coefficient.</summary>
    private const byte ZeroByte = 0;

    /// <summary>The wire count of the one-constraint circuit whose A linear combination holds two terms: the constant wire and three others.</summary>
    private const int TwoTermWireCount = 4;

    /// <summary>The lower-numbered wire of the two A terms, emitted second.</summary>
    private const int LowerTermWire = 1;

    /// <summary>The higher-numbered wire of the two A terms, emitted first.</summary>
    private const int HigherTermWire = 2;

    /// <summary>The wire the C linear combination names.</summary>
    private const int ResultWire = 3;

    /// <summary>The coefficient of the lower-numbered A term, distinct from the other so a value paired with the wrong wire shows.</summary>
    private const int LowerTermCoefficient = 7;

    /// <summary>The coefficient of the higher-numbered A term.</summary>
    private const int HigherTermCoefficient = 9;

    /// <summary>The number of entries the reader stores for the two-term A linear combination.</summary>
    private const int TwoTermNonzeroCount = 2;

    /// <summary>The row of the only constraint.</summary>
    private const int OnlyConstraintRow = 0;

    /// <summary>The index of the second stored triple of a matrix.</summary>
    private const int SecondTripleIndex = 1;


    /// <summary>The ASCII signature written at the start of each encoded R1CS file.</summary>
    private static ReadOnlySpan<byte> FileMagic => "r1cs"u8;

    /// <summary>The pooled encoded files released together after each test.</summary>
    private List<IDisposable> Disposables { get; } = [];


    /// <summary>Releases all encoded file rentals opened during the test.</summary>
    [TestCleanup]
    public void DisposeRentals()
    {
        for(int i = Disposables.Count - 1; i >= 0; i--)
        {
            Disposables[i].Dispose();
        }

        Disposables.Clear();
    }


    /// <summary>The BLS12-381 scalar field order encoded into the test file header.</summary>
    private static BigInteger Bls12Curve381Prime { get; } = Bls12Curve381BigIntegerScalarReference.FieldOrder;

    /// <summary>The BLS12-381 reference scalar addition backend for checking satisfaction.</summary>
    private static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();

    /// <summary>The BLS12-381 reference scalar multiplication backend for checking satisfaction.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();


    /// <summary>Descending wire ids within a constraint parse into ascending matrix entries and retain satisfaction of the encoded addition.</summary>
    [TestMethod]
    public void ReaderAcceptsNonAscendingWireOrderWithinConstraint()
    {
        //The two A terms of (z[1] + z[2]) * z[0] = z[3] arrive in descending wire order.
        //The witness z = (1, 2, 3, 5) satisfies the constraint.
        Memory<byte> bytes = EncodeR1cs(
            Bls12Curve381Prime,
            wireCount: TwoTermWireCount,
            constraints:
            [
                new ConstraintTriple(
                    A: [(HigherTermWire, BigInteger.One), (LowerTermWire, BigInteger.One)],
                    B: [(ConstantWire, BigInteger.One)],
                    C: [(ResultWire, BigInteger.One)]),
            ]);

        using RawR1csInstance instance = ParseR1cs(bytes);

        //The reader sorts, so the parsed A triples are in ascending (row, column)
        //order regardless of the emitted order.
        Assert.AreEqual(TwoTermNonzeroCount, instance.A.NonzeroCount);
        Assert.AreEqual((OnlyConstraintRow, LowerTermWire), instance.A.GetTriplePosition(FirstTripleIndex), "A[0] should sort to (constraint 0, wire 1)");
        Assert.AreEqual((OnlyConstraintRow, HigherTermWire), instance.A.GetTriplePosition(SecondTripleIndex), "A[1] should sort to (constraint 0, wire 2)");

        using RawR1csWitness witness = BuildWitness(FirstInputValue, SecondInputValue, ResultValue);
        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, Add, Multiply, BaseMemoryPool.Shared);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction);
    }


    /// <summary>Reversing the order of distinct wire terms produces byte-identical matrices.</summary>
    [TestMethod]
    public void ReaderIsInvariantToWireOrderWithinConstraint()
    {
        //The same constraint system encoded twice — A's terms ascending in one,
        //descending in the other. The reader must produce byte-identical matrices.
        Memory<byte> ascending = EncodeR1cs(
            Bls12Curve381Prime,
            wireCount: TwoTermWireCount,
            constraints:
            [
                new ConstraintTriple(
                    A: [(LowerTermWire, new BigInteger(LowerTermCoefficient)), (HigherTermWire, new BigInteger(HigherTermCoefficient))],
                    B: [(ConstantWire, BigInteger.One)],
                    C: [(ResultWire, BigInteger.One)]),
            ]);

        Memory<byte> descending = EncodeR1cs(
            Bls12Curve381Prime,
            wireCount: TwoTermWireCount,
            constraints:
            [
                new ConstraintTriple(
                    A: [(HigherTermWire, new BigInteger(HigherTermCoefficient)), (LowerTermWire, new BigInteger(LowerTermCoefficient))],
                    B: [(ConstantWire, BigInteger.One)],
                    C: [(ResultWire, BigInteger.One)]),
            ]);

        using RawR1csInstance fromAscending = ParseR1cs(ascending);
        using RawR1csInstance fromDescending = ParseR1cs(descending);

        AssertMatricesEqual(fromAscending.A, fromDescending.A, "A");
        AssertMatricesEqual(fromAscending.B, fromDescending.B, "B");
        AssertMatricesEqual(fromAscending.C, fromDescending.C, "C");
    }


    /// <summary>
    /// A constraint system in which the C linear combination of every constraint has no terms parses into a C matrix
    /// holding one synthesised zero-valued entry at <c>(0, 0)</c>. The entry meets the at-least-one-entry requirement of
    /// the matrix encoding without changing which witnesses satisfy the system.
    /// </summary>
    [TestMethod]
    public void ReaderSynthesisesZeroEntryForMatrixWithNoTerms()
    {
        Memory<byte> bytes = EncodeR1cs(
            Bls12Curve381Prime,
            wireCount: EmptyMatrixWireCount,
            constraints:
            [
                new ConstraintTriple(
                    A: [(OutputWire, BigInteger.One)],
                    B: [(ConstantWire, BigInteger.One)],
                    C: []),
            ]);

        using RawR1csInstance instance = ParseR1cs(bytes);

        Assert.AreEqual(SynthesisedNonzeroCount, instance.C.NonzeroCount, "C must carry exactly the synthesised entry.");
        Assert.AreEqual((SynthesisedRow, SynthesisedColumn), instance.C.GetTriplePosition(FirstTripleIndex), "The synthesised entry must sit at (0, 0).");
        Assert.IsFalse(instance.C.GetValueBytes(FirstTripleIndex).ContainsAnyExcept(ZeroByte), "The synthesised coefficient must be zero.");
    }


    /// <summary>
    /// A linear combination whose terms arrive in descending wire order is sorted into ascending column order with each
    /// coefficient carried along with its own wire, so the value stored at each sorted position is the coefficient the
    /// file gave that wire, in canonical big-endian form.
    /// </summary>
    [TestMethod]
    public void ReaderCarriesEachCoefficientWithItsWireWhenSorting()
    {
        Memory<byte> bytes = EncodeR1cs(
            Bls12Curve381Prime,
            wireCount: TwoTermWireCount,
            constraints:
            [
                new ConstraintTriple(
                    A: [(HigherTermWire, new BigInteger(HigherTermCoefficient)), (LowerTermWire, new BigInteger(LowerTermCoefficient))],
                    B: [(ConstantWire, BigInteger.One)],
                    C: [(ResultWire, BigInteger.One)]),
            ]);

        using RawR1csInstance instance = ParseR1cs(bytes);

        Span<byte> lowerTermValue = stackalloc byte[ScalarSize];
        WriteCanonical(new BigInteger(LowerTermCoefficient), lowerTermValue);
        Span<byte> higherTermValue = stackalloc byte[ScalarSize];
        WriteCanonical(new BigInteger(HigherTermCoefficient), higherTermValue);

        Assert.AreEqual(TwoTermNonzeroCount, instance.A.NonzeroCount);
        Assert.AreEqual((OnlyConstraintRow, LowerTermWire), instance.A.GetTriplePosition(FirstTripleIndex));
        Assert.IsTrue(lowerTermValue.SequenceEqual(instance.A.GetValueBytes(FirstTripleIndex)), "The first sorted entry must carry the coefficient of the lower wire.");
        Assert.AreEqual((OnlyConstraintRow, HigherTermWire), instance.A.GetTriplePosition(SecondTripleIndex));
        Assert.IsTrue(higherTermValue.SequenceEqual(instance.A.GetValueBytes(SecondTripleIndex)), "The second sorted entry must carry the coefficient of the higher wire.");
    }


    /// <summary>Checks that two matrices store identical term counts, row indices, column indices and coefficient bytes.</summary>
    private static void AssertMatricesEqual(R1csMatrix expected, R1csMatrix actual, string name)
    {
        Assert.AreEqual(expected.NonzeroCount, actual.NonzeroCount, $"{name}.NonzeroCount");
        Assert.IsTrue(expected.GetRowIndicesBytes().SequenceEqual(actual.GetRowIndicesBytes()), $"{name} row indices differ");
        Assert.IsTrue(expected.GetColumnIndicesBytes().SequenceEqual(actual.GetColumnIndicesBytes()), $"{name} column indices differ");
        Assert.IsTrue(expected.GetValuesBytes().SequenceEqual(actual.GetValuesBytes()), $"{name} values differ");
    }


    /// <summary>Parses the complete pooled file as a BLS12-381 Circom R1CS instance.</summary>
    private static RawR1csInstance ParseR1cs(ReadOnlyMemory<byte> bytes)
    {
        PipeReader pipe = PipeReader.Create(new ReadOnlySequence<byte>(bytes));

        return CircomR1csReader.Reader(
            pipe,
            WellKnownR1csFormatLabel.CircomBinary,
            CurveParameterSet.Bls12Curve381,
            BaseMemoryPool.Shared,
            WellKnownR1csIntakeLimits.Unbounded,
            CancellationToken.None);
    }


    /// <summary>Writes the three nonconstant witness values in canonical scalar order.</summary>
    private static RawR1csWitness BuildWitness(int z1, int z2, int z3)
    {
        Span<byte> witness = stackalloc byte[WitnessVariableCount * ScalarSize];
        WriteCanonical(new BigInteger(z1), witness.Slice(FirstInputOffset, ScalarSize));
        WriteCanonical(new BigInteger(z2), witness.Slice(SecondInputOffset, ScalarSize));
        WriteCanonical(new BigInteger(z3), witness.Slice(ResultOffset, ScalarSize));

        return RawR1csWitness.FromCanonical(witness, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }


    /// <summary>Writes a nonnegative value as a zero-padded canonical big-endian scalar.</summary>
    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Value did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }


    /// <summary>The three linear combinations of one constraint, each retaining its supplied wire order.</summary>
    /// <param name="A">The left multiplicand terms.</param>
    /// <param name="B">The right multiplicand terms.</param>
    /// <param name="C">The product terms.</param>
    private readonly record struct ConstraintTriple(
        IReadOnlyList<(int Wire, BigInteger Coefficient)> A,
        IReadOnlyList<(int Wire, BigInteger Coefficient)> B,
        IReadOnlyList<(int Wire, BigInteger Coefficient)> C);


    /// <summary>
    /// Encodes the header and constraints into a pooled file, preserving the supplied term order and using the
    /// BLS12-381 scalar width. The rental remains live until test cleanup.
    /// </summary>
    private Memory<byte> EncodeR1cs(BigInteger prime, int wireCount, IReadOnlyList<ConstraintTriple> constraints)
    {
        int constraintPayloadBytes = GetConstraintPayloadBytes(constraints);
        int fileBytes = FileHeaderBytes + ((int)SectionCount * SectionPrefixBytes) + HeaderPayloadBytes + constraintPayloadBytes;
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(fileBytes);
        Disposables.Add(owner);
        Memory<byte> file = owner.Memory[..fileBytes];
        Span<byte> destination = file.Span;

        FileMagic.CopyTo(destination);
        destination = destination[MagicBytes..];
        AddUInt32(ref destination, FileVersion);
        AddUInt32(ref destination, SectionCount);

        AddUInt32(ref destination, HeaderSectionType);
        AddUInt64(ref destination, HeaderPayloadBytes);
        AddUInt32(ref destination, ScalarSize);
        AddFieldLittleEndian(ref destination, prime);
        AddUInt32(ref destination, (uint)wireCount);
        AddUInt32(ref destination, PublicOutputWireCount);
        AddUInt32(ref destination, PublicInputWireCount);
        AddUInt32(ref destination, (uint)(wireCount - NonPrivateWireCount));
        AddUInt64(ref destination, (ulong)wireCount);
        AddUInt32(ref destination, (uint)constraints.Count);

        AddUInt32(ref destination, ConstraintSectionType);
        AddUInt64(ref destination, (ulong)constraintPayloadBytes);
        foreach(ConstraintTriple constraint in constraints)
        {
            AppendLinearCombination(ref destination, constraint.A);
            AppendLinearCombination(ref destination, constraint.B);
            AppendLinearCombination(ref destination, constraint.C);
        }

        return file;
    }


    /// <summary>Counts the three term-count prefixes per constraint and one wire-and-scalar encoding per term.</summary>
    private static int GetConstraintPayloadBytes(IReadOnlyList<ConstraintTriple> constraints)
    {
        int length = constraints.Count * LinearCombinationsPerConstraint * sizeof(uint);
        foreach(ConstraintTriple constraint in constraints)
        {
            length += (constraint.A.Count + constraint.B.Count + constraint.C.Count) * EncodedTermBytes;
        }

        return length;
    }


    /// <summary>Writes a term count and each wire-and-coefficient pair in the supplied order, advancing the destination.</summary>
    private static void AppendLinearCombination(ref Span<byte> destination, IReadOnlyList<(int Wire, BigInteger Coefficient)> terms)
    {
        AddUInt32(ref destination, (uint)terms.Count);
        foreach((int wire, BigInteger coefficient) in terms)
        {
            AddUInt32(ref destination, (uint)wire);
            AddFieldLittleEndian(ref destination, coefficient);
        }
    }


    /// <summary>Writes one little-endian 32-bit field and advances past its four bytes.</summary>
    private static void AddUInt32(ref Span<byte> destination, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(destination, value);
        destination = destination[sizeof(uint)..];
    }


    /// <summary>Writes one little-endian 64-bit field and advances past its eight bytes.</summary>
    private static void AddUInt64(ref Span<byte> destination, ulong value)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(destination, value);
        destination = destination[sizeof(ulong)..];
    }


    /// <summary>Writes a zero-padded unsigned little-endian field element and advances by one scalar.</summary>
    private static void AddFieldLittleEndian(ref Span<byte> destination, BigInteger value)
    {
        Span<byte> field = destination[..ScalarSize];
        field.Clear();
        if(!value.TryWriteBytes(field, out _, isUnsigned: true, isBigEndian: false))
        {
            throw new InvalidOperationException($"Coefficient does not fit in {ScalarSize} little-endian bytes.");
        }

        destination = destination[ScalarSize..];
    }
}

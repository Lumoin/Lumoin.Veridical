using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Tests the matrix-assembly sink directly by driving its push API — the
/// architecture's payoff: the assembler is exercised over a real curve
/// without needing a hand-encoded FlatBuffers fixture; the full pipe path
/// over real BLS/BN254 <c>.zkif</c> files is covered by
/// <see cref="ZkInterfaceFixtureTests"/>. The circuit
/// is the padded multiplier2 (<c>a·b = c</c> plus a <c>1·1 = 1</c> row so
/// the shape is a power of two): variables <c>z = (1, c, a, b)</c>,
/// satisfied by <c>(1, 33, 3, 11)</c>. The satisfaction check is the
/// load-bearing assertion — it runs every coefficient against the witness,
/// so an LE/BE, column, or zero-pad mistake surfaces as a non-satisfaction.
/// </summary>
/// <remarks>
/// Satisfaction cannot reveal coefficients that collapsed to zero, because all-zero matrices satisfy
/// every witness, so the ordering test reads each stored position and canonical coefficient back.
/// Several intake and build guards share an exception type, so each rejection test drives exactly one
/// guard and asserts what only that guard produces.
/// </remarks>
[TestClass]
internal sealed class ZkInterfaceR1csInstanceBuilderTests
{
    /// <summary>
    /// The four-column variable space <c>z = (1, c, a, b)</c> of multiplier2, declared as <c>free_variable_id</c>.
    /// </summary>
    private const int VariableCount = 4;

    /// <summary>The multiplier2 constraint plus the padding row.</summary>
    private const int ConstraintCount = 2;

    /// <summary>The constructor parameter a null-pool rejection names.</summary>
    private const string PoolParameterName = "pool";

    /// <summary>The parameter an unknown-selector rejection names.</summary>
    private const string MatrixParameterName = "matrix";

    /// <summary>The <c>free_variable_id</c> a header reports when it declares no variables.</summary>
    private const ulong NoDeclaredVariables = 0;

    /// <summary>The column of the constant-one variable; variable ID 0 is always column 0.</summary>
    private const int ConstantColumn = 0;

    /// <summary>The highest variable ID multiplier2 references (<c>b</c>), above the constant column.</summary>
    private const int HighestReferencedColumn = 3;

    /// <summary>Converts the highest zero-based referenced column to the column count that holds it.</summary>
    private const int ZeroBasedIdToCountOffset = 1;

    /// <summary>The coefficient one, written as the single little-endian byte a truncating producer emits.</summary>
    private const byte UnitCoefficient = 1;

    /// <summary>The first selector value past <see cref="ZkInterfaceConstraintMatrix.C"/>, which names no matrix.</summary>
    private const ZkInterfaceConstraintMatrix UnknownMatrixSelector = ZkInterfaceConstraintMatrix.C + 1;

    /// <summary>The number of A terms the ordering test pushes, one per stored triple.</summary>
    private const int OrderedTermCount = 3;

    /// <summary>The first constraint row.</summary>
    private const int FirstRow = 0;

    /// <summary>The second constraint row.</summary>
    private const int SecondRow = 1;

    /// <summary>The lower of the two first-row A columns, pushed after the higher one.</summary>
    private const int FirstRowLowColumn = 1;

    /// <summary>The higher of the two first-row A columns, pushed first.</summary>
    private const int FirstRowHighColumn = 3;

    /// <summary>The single second-row A column, which lies below the first row's higher column.</summary>
    private const int SecondRowColumn = 2;

    /// <summary>The stored index of the first row's lower column once the triples are sorted.</summary>
    private const int FirstRowLowTripleIndex = 0;

    /// <summary>The stored index of the first row's higher column once the triples are sorted.</summary>
    private const int FirstRowHighTripleIndex = 1;

    /// <summary>The stored index of the second row's column once the triples are sorted.</summary>
    private const int SecondRowTripleIndex = 2;

    /// <summary>Selects a reproducible stream of distinct, non-zero, full-width canonical coefficients.</summary>
    private const int CoefficientFillSalt = 41;

    /// <summary>The text only the repeated-declaration guard on <c>field_maximum</c> produces.</summary>
    private const string RepeatedFieldMaximumMessage = "more than one CircuitHeader field_maximum";

    /// <summary>The text only the open-constraint guard on term intake produces.</summary>
    private const string TermOutsideConstraintMessage = "outside a BeginConstraint/EndConstraint pair";

    /// <summary>The text only the empty-variable-space guard produces.</summary>
    private const string NoVariablesMessage = "declares no variables";

    /// <summary>The text only the matrix-selector dispatch produces.</summary>
    private const string UnknownMatrixSelectorMessage = "Unknown R1CS matrix selector.";


    /// <summary>
    /// Builds the padded multiplier2 over BLS12-381 and checks its shape and its satisfaction by
    /// <c>(1, 33, 3, 11)</c>.
    /// </summary>
    [TestMethod]
    public void Bls12Curve381Multiplier2BuildsAndSatisfies()
    {
        ExerciseMultiplier2(
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381BigIntegerScalarReference.GetAdd(),
            Bls12Curve381BigIntegerScalarReference.GetMultiply());
    }


    /// <summary>
    /// Builds the padded multiplier2 over BN254 and checks its shape and its satisfaction by
    /// <c>(1, 33, 3, 11)</c>.
    /// </summary>
    [TestMethod]
    public void Bn254Multiplier2BuildsAndSatisfies()
    {
        ExerciseMultiplier2(
            CurveParameterSet.Bn254,
            Bn254BigIntegerScalarReference.GetAdd(),
            Bn254BigIntegerScalarReference.GetMultiply());
    }


    /// <summary>
    /// Pins that a BLS12-381 builder rejects a declared BN254 field at the declaration itself with
    /// <see cref="R1csUnsupportedFieldException"/>.
    /// </summary>
    [TestMethod]
    public void BuilderRejectsFieldThatDoesNotMatchTheCurve()
    {
        var builder = new ZkInterfaceR1csInstanceBuilder(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        //Declaring BN254's field while asking for a BLS12-381 instance.
        byte[] bn254FieldMaximum = ZkInterfaceTestFields.FieldMaximumLittleEndian(CurveParameterSet.Bn254);
        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() => builder.OnFieldMaximum(bn254FieldMaximum));
    }


    /// <summary>
    /// Pins that a complete circuit that never declares <c>field_maximum</c> is rejected at
    /// <see cref="ZkInterfaceR1csInstanceBuilder.Build"/>, because an undeclared field cannot be
    /// validated against the curve.
    /// </summary>
    [TestMethod]
    public void BuilderRejectsAbsentField()
    {
        //A full circuit but with no field_maximum ever declared: the field
        //cannot be validated against the curve, so Build rejects it.
        var builder = new ZkInterfaceR1csInstanceBuilder(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(VariableCount);
        PushUnitConstraint(sink, ConstantColumn);

        Assert.ThrowsExactly<R1csUnsupportedFieldException>(() => builder.Build());
    }


    /// <summary>
    /// Pins that the constructor rejects a null pool with an <see cref="ArgumentNullException"/> naming
    /// <c>pool</c>. The curve is wired, so the scalar-width lookup after the null check does not throw, and
    /// nothing else in the constructor reads the pool, so only the null check can answer at construction;
    /// without it the failure would surface later, at <see cref="ZkInterfaceR1csInstanceBuilder.Build"/>.
    /// </summary>
    [TestMethod]
    public void BuilderRejectsNullPool()
    {
        ArgumentNullException exception = Assert.ThrowsExactly<ArgumentNullException>(
            () => new ZkInterfaceR1csInstanceBuilder(CurveParameterSet.Bls12Curve381, null!),
            "A null pool must be rejected.");

        Assert.AreEqual(PoolParameterName, exception.ParamName, "The rejection must name the pool parameter.");
    }


    /// <summary>
    /// Pins that a second <c>field_maximum</c> declaration is rejected even when both declarations match the
    /// curve. The repeated value is the curve's own, so the field reconciliation after the repetition check
    /// cannot throw, and the repeated-declaration guard is the only one that can answer; its message is
    /// asserted because the exception type alone does not identify it.
    /// </summary>
    [TestMethod]
    public void BuilderRejectsSecondFieldMaximum()
    {
        ZkInterfaceR1csInstanceBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        IZkInterfaceMessageSink sink = builder;
        DeclareFieldMaximum(sink, CurveParameterSet.Bls12Curve381);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => DeclareFieldMaximum(sink, CurveParameterSet.Bls12Curve381),
            "A repeated field_maximum must be rejected.");

        Assert.Contains(RepeatedFieldMaximumMessage, exception.Message, StringComparison.Ordinal, "The repeated-declaration guard must be what rejects the stream.");
    }


    /// <summary>
    /// Pins that a constraint term arriving before any <see cref="IZkInterfaceMessageSink.BeginConstraint"/>
    /// is rejected with an <see cref="InvalidOperationException"/>. The open-constraint check is the first
    /// statement of term intake, and the constant column under selector A passes every later check, so only
    /// that guard can answer; without it the term would be filed under row minus one and the call would
    /// return.
    /// </summary>
    [TestMethod]
    public void BuilderRejectsTermBeforeAnyConstraint()
    {
        ZkInterfaceR1csInstanceBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        IZkInterfaceMessageSink sink = builder;

        InvalidOperationException exception = Assert.ThrowsExactly<InvalidOperationException>(
            () => sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.A, ConstantColumn, default),
            "A term outside an open constraint must be rejected.");

        Assert.Contains(TermOutsideConstraintMessage, exception.Message, StringComparison.Ordinal, "The open-constraint guard must be what rejects the term.");
    }


    /// <summary>
    /// Pins that a term whose selector names none of A, B and C is rejected with an
    /// <see cref="ArgumentOutOfRangeException"/> naming <c>matrix</c>. A constraint is open and the constant
    /// column is in range, so only the selector dispatch can answer; its message is asserted because the
    /// exception type and parameter name stay the same whatever the text says.
    /// </summary>
    [TestMethod]
    public void BuilderRejectsUnknownMatrixSelector()
    {
        ZkInterfaceR1csInstanceBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        IZkInterfaceMessageSink sink = builder;
        sink.BeginConstraint();

        ArgumentOutOfRangeException exception = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => sink.OnConstraintTerm(UnknownMatrixSelector, ConstantColumn, default),
            "A term under an unknown matrix selector must be rejected.");

        Assert.AreEqual(MatrixParameterName, exception.ParamName, "The rejection must name the matrix parameter.");
        Assert.Contains(UnknownMatrixSelectorMessage, exception.Message, StringComparison.Ordinal, "The selector dispatch must be what rejects the term.");
    }


    /// <summary>
    /// Pins that a constraint system which declares no variables and references none is rejected at
    /// <see cref="ZkInterfaceR1csInstanceBuilder.Build"/> with an <see cref="ArgumentException"/>. Its only
    /// constraint has empty linear combinations, the zero row a decoder reports for them. The field is
    /// declared and matches, a constraint exists and the empty declaration is in range, so only the
    /// empty-variable-space guard can answer; without it the zero column count reaches matrix construction,
    /// which throws the derived <see cref="ArgumentOutOfRangeException"/> instead.
    /// </summary>
    [TestMethod]
    public void BuilderRejectsConstraintSystemWithoutVariables()
    {
        ZkInterfaceR1csInstanceBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(NoDeclaredVariables);
        DeclareFieldMaximum(sink, CurveParameterSet.Bls12Curve381);
        sink.BeginConstraint();
        sink.EndConstraint();

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => builder.Build().Dispose(),
            "A constraint system without variables must be rejected.");

        Assert.Contains(NoVariablesMessage, exception.Message, StringComparison.Ordinal, "The empty-variable-space guard must be what rejects the stream.");
    }


    /// <summary>
    /// Pins that a referenced constant column alone yields a one-column instance when the header declares
    /// no variables. With an empty declaration only the referenced IDs can size the instance, and ID 0 must
    /// count as a column, so a resolution that ignores the referenced IDs, treats ID 0 as no reference,
    /// counts short of the highest ID, or keeps the narrower of the declared and referenced widths leaves no
    /// column, and the build is rejected.
    /// </summary>
    [TestMethod]
    public void BuilderCountsTheReferencedConstantColumnWhenNoVariablesAreDeclared()
    {
        int columnCount = BuildColumnCountWithoutDeclaredVariables(ConstantColumn);

        Assert.AreEqual(ConstantColumn + ZeroBasedIdToCountOffset, columnCount, "The referenced constant column must give one column.");
    }


    /// <summary>
    /// Pins that a referenced ID above an empty declared variable space widens the column count to that ID
    /// plus one. With an empty declaration only the referenced IDs can size the instance, so a resolution
    /// that ignores the referenced IDs, drops those above zero, keeps the narrower of the declared and
    /// referenced widths, or counts short of the highest ID cannot hold the A term in column three.
    /// </summary>
    [TestMethod]
    public void BuilderWidensColumnsToHighestReferencedIdWhenNoVariablesAreDeclared()
    {
        int columnCount = BuildColumnCountWithoutDeclaredVariables(HighestReferencedColumn);

        Assert.AreEqual(HighestReferencedColumn + ZeroBasedIdToCountOffset, columnCount, "The highest referenced ID must widen the column space.");
    }


    /// <summary>
    /// Pins that terms of one matrix arriving out of column order within a row are stored in ascending
    /// <c>(row, column)</c> order, and that each keeps its own coefficient, converted from little-endian to
    /// canonical big-endian. The coefficients are distinct, non-zero, full-width scalars, so a zeroed,
    /// misplaced or wrongly sourced value, or a byte-order slip, changes a stored byte; satisfaction alone
    /// cannot show this, because all-zero matrices satisfy every witness. The matrix construction rejects
    /// triples that are not strictly ascending, so an unsorted row fails the build.
    /// </summary>
    [TestMethod]
    public void BuilderSortsTermsWithinARowAndKeepsEachCoefficient()
    {
        Span<byte> coefficients = stackalloc byte[OrderedTermCount * ZkInterfaceTestFields.FieldElementSizeBytes];
        DeterministicScalarFill.FillCanonical(
            coefficients,
            CoefficientFillSalt,
            Bls12Curve381BigIntegerScalarReference.GetReduce(),
            CurveParameterSet.Bls12Curve381);
        ReadOnlySpan<byte> firstRowLowCoefficient = CoefficientSlot(coefficients, FirstRowLowTripleIndex);
        ReadOnlySpan<byte> firstRowHighCoefficient = CoefficientSlot(coefficients, FirstRowHighTripleIndex);
        ReadOnlySpan<byte> secondRowCoefficient = CoefficientSlot(coefficients, SecondRowTripleIndex);

        ZkInterfaceR1csInstanceBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(VariableCount);
        DeclareFieldMaximum(sink, CurveParameterSet.Bls12Curve381);

        Span<byte> one = stackalloc byte[] { UnitCoefficient };

        //The first row reports its A terms in descending column order, so only the sort can store them ascending.
        sink.BeginConstraint();
        PushLittleEndianTerm(sink, ZkInterfaceConstraintMatrix.A, FirstRowHighColumn, firstRowHighCoefficient);
        PushLittleEndianTerm(sink, ZkInterfaceConstraintMatrix.A, FirstRowLowColumn, firstRowLowCoefficient);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.B, ConstantColumn, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.C, ConstantColumn, one);
        sink.EndConstraint();

        //The second row's column lies below the first row's higher column, so the row decides the order.
        sink.BeginConstraint();
        PushLittleEndianTerm(sink, ZkInterfaceConstraintMatrix.A, SecondRowColumn, secondRowCoefficient);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.B, ConstantColumn, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.C, ConstantColumn, one);
        sink.EndConstraint();

        using RawR1csInstance instance = builder.Build();

        Assert.AreEqual(OrderedTermCount, instance.A.NonzeroCount, "Every A term must be stored.");
        AssertStoredTriple(instance.A, FirstRowLowTripleIndex, FirstRow, FirstRowLowColumn, firstRowLowCoefficient);
        AssertStoredTriple(instance.A, FirstRowHighTripleIndex, FirstRow, FirstRowHighColumn, firstRowHighCoefficient);
        AssertStoredTriple(instance.A, SecondRowTripleIndex, SecondRow, SecondRowColumn, secondRowCoefficient);
    }


    /// <summary>
    /// Builds multiplier2 over <paramref name="curve"/> and asserts its shape and its satisfaction by the
    /// multiplier2 witness.
    /// </summary>
    /// <param name="curve">The curve the instance and the witness are built over.</param>
    /// <param name="add">The reference scalar addition for <paramref name="curve"/>.</param>
    /// <param name="multiply">The reference scalar multiplication for <paramref name="curve"/>.</param>
    private static void ExerciseMultiplier2(CurveParameterSet curve, ScalarAddDelegate add, ScalarMultiplyDelegate multiply)
    {
        using RawR1csInstance instance = BuildMultiplier2(curve);

        Assert.AreEqual(ConstraintCount, instance.A.RowCount, "A.RowCount");
        Assert.AreEqual(VariableCount, instance.A.ColumnCount, "A.ColumnCount");
        Assert.AreEqual(0, instance.PublicInputCount, "PublicInputCount");
        Assert.AreEqual(2, instance.A.NonzeroCount, "A.NonzeroCount");
        Assert.AreEqual(2, instance.B.NonzeroCount, "B.NonzeroCount");
        Assert.AreEqual(2, instance.C.NonzeroCount, "C.NonzeroCount");
        Assert.AreEqual(curve.Code, instance.Curve.Code, "parsed instance curve");

        using RawR1csWitness witness = BuildMultiplier2Witness(curve);
        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, add, multiply, BaseMemoryPool.Shared);

        if(satisfaction is R1csSatisfaction.Violated violated)
        {
            Assert.Fail($"multiplier2 satisfaction failed at constraint {violated.ConstraintIndex.Value}.");
        }

        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction);
    }


    /// <summary>Pushes the padded multiplier2 circuit through the sink interface and builds the instance.</summary>
    /// <param name="curve">The curve whose field the circuit declares.</param>
    /// <returns>The built instance, owned by the caller.</returns>
    private static RawR1csInstance BuildMultiplier2(CurveParameterSet curve)
    {
        var builder = new ZkInterfaceR1csInstanceBuilder(curve, BaseMemoryPool.Shared);
        //Drive the push API through the sink interface, exactly as a decoder would.
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(VariableCount);

        Span<byte> fieldMaximum = stackalloc byte[ZkInterfaceTestFields.FieldElementSizeBytes];
        ZkInterfaceTestFields.WriteFieldMaximumLittleEndian(curve, fieldMaximum);
        sink.OnFieldMaximum(fieldMaximum);

        Span<byte> one = stackalloc byte[] { 1 };

        //C0: a · b = c with z = (one, c, a, b) → A{2:1}, B{3:1}, C{1:1}.
        sink.BeginConstraint();
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.A, 2, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.B, 3, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.C, 1, one);
        sink.EndConstraint();

        //C1: 1 · 1 = 1 padding → A{0:1}, B{0:1}, C{0:1}.
        PushUnitConstraint(sink, ConstantColumn);

        return builder.Build();
    }


    /// <summary>
    /// Pushes one constraint whose A term references <paramref name="aVariableId"/> and whose B and C terms
    /// reference the constant column, each with coefficient one.
    /// </summary>
    /// <param name="sink">The sink receiving the constraint.</param>
    /// <param name="aVariableId">The variable the A term references.</param>
    private static void PushUnitConstraint(IZkInterfaceMessageSink sink, ulong aVariableId)
    {
        Span<byte> one = stackalloc byte[] { UnitCoefficient };
        sink.BeginConstraint();
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.A, aVariableId, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.B, ConstantColumn, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.C, ConstantColumn, one);
        sink.EndConstraint();
    }


    /// <summary>Declares the field maximum of <paramref name="curve"/>, which every accepted stream carries.</summary>
    /// <param name="sink">The sink receiving the declaration.</param>
    /// <param name="curve">The curve whose scalar field is declared.</param>
    private static void DeclareFieldMaximum(IZkInterfaceMessageSink sink, CurveParameterSet curve)
    {
        Span<byte> fieldMaximum = stackalloc byte[ZkInterfaceTestFields.FieldElementSizeBytes];
        ZkInterfaceTestFields.WriteFieldMaximumLittleEndian(curve, fieldMaximum);
        sink.OnFieldMaximum(fieldMaximum);
    }


    /// <summary>
    /// Builds a one-constraint BLS12-381 instance whose header declares no variables and whose A term
    /// references <paramref name="aVariableId"/>, and returns its column count.
    /// </summary>
    /// <param name="aVariableId">The variable the A term references; the B and C terms reference the constant column.</param>
    /// <returns>The column count of the built instance.</returns>
    private static int BuildColumnCountWithoutDeclaredVariables(ulong aVariableId)
    {
        ZkInterfaceR1csInstanceBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(NoDeclaredVariables);
        DeclareFieldMaximum(sink, CurveParameterSet.Bls12Curve381);
        PushUnitConstraint(sink, aVariableId);

        using RawR1csInstance instance = builder.Build();

        return instance.A.ColumnCount;
    }


    /// <summary>
    /// Reports one term whose coefficient is <paramref name="canonicalBigEndian"/> re-encoded little-endian,
    /// the byte order ZkInterface stores field elements in.
    /// </summary>
    /// <param name="sink">The sink receiving the term.</param>
    /// <param name="matrix">The matrix the term belongs to.</param>
    /// <param name="variableId">The variable the term references.</param>
    /// <param name="canonicalBigEndian">The full-width coefficient in canonical big-endian order.</param>
    private static void PushLittleEndianTerm(IZkInterfaceMessageSink sink, ZkInterfaceConstraintMatrix matrix, ulong variableId, ReadOnlySpan<byte> canonicalBigEndian)
    {
        Span<byte> littleEndian = stackalloc byte[ZkInterfaceTestFields.FieldElementSizeBytes];
        canonicalBigEndian.CopyTo(littleEndian);
        littleEndian.Reverse();
        sink.OnConstraintTerm(matrix, variableId, littleEndian);
    }


    /// <summary>Returns the canonical big-endian coefficient for one stored triple from a run of whole scalars.</summary>
    /// <param name="coefficients">Whole scalars laid end to end in stored triple order.</param>
    /// <param name="tripleIndex">The stored index of the triple whose coefficient is returned.</param>
    /// <returns>The scalar-width slice holding that coefficient.</returns>
    private static ReadOnlySpan<byte> CoefficientSlot(ReadOnlySpan<byte> coefficients, int tripleIndex)
    {
        return coefficients.Slice(tripleIndex * ZkInterfaceTestFields.FieldElementSizeBytes, ZkInterfaceTestFields.FieldElementSizeBytes);
    }


    /// <summary>Asserts the stored row, column and canonical coefficient of one triple.</summary>
    /// <param name="matrix">The matrix holding the triple.</param>
    /// <param name="tripleIndex">The triple's index in stored order.</param>
    /// <param name="expectedRow">The row the triple must sit on.</param>
    /// <param name="expectedColumn">The column the triple must sit in.</param>
    /// <param name="expectedCoefficient">The canonical big-endian coefficient the triple must hold.</param>
    private static void AssertStoredTriple(R1csMatrix matrix, int tripleIndex, int expectedRow, int expectedColumn, ReadOnlySpan<byte> expectedCoefficient)
    {
        (int row, int column) = matrix.GetTriplePosition(tripleIndex);

        Assert.AreEqual(expectedRow, row, $"Triple {tripleIndex} must sit on row {expectedRow}.");
        Assert.AreEqual(expectedColumn, column, $"Triple {tripleIndex} must sit in column {expectedColumn}.");
        Assert.IsTrue(matrix.GetValueBytes(tripleIndex).SequenceEqual(expectedCoefficient), $"Triple {tripleIndex} must keep its own coefficient in canonical big-endian order.");
    }


    /// <summary>Builds the multiplier2 witness <c>z[1..] = (33, 3, 11)</c>.</summary>
    /// <param name="curve">The curve whose scalar width the witness uses.</param>
    /// <returns>The witness, owned by the caller.</returns>
    private static RawR1csWitness BuildMultiplier2Witness(CurveParameterSet curve)
    {
        //z[1..] = (c, a, b) = (33, 3, 11); satisfies a · b = c with a = 3, b = 11.
        int scalarSize = R1csMatrix.GetValueByteSize(curve);
        Span<byte> witnessBytes = stackalloc byte[3 * ZkInterfaceTestFields.FieldElementSizeBytes];
        witnessBytes = witnessBytes[..(3 * scalarSize)];
        WriteCanonicalBigEndian(new BigInteger(33), witnessBytes.Slice(0 * scalarSize, scalarSize));
        WriteCanonicalBigEndian(new BigInteger(3), witnessBytes.Slice(1 * scalarSize, scalarSize));
        WriteCanonicalBigEndian(new BigInteger(11), witnessBytes.Slice(2 * scalarSize, scalarSize));

        return RawR1csWitness.FromCanonical(witnessBytes, curve, BaseMemoryPool.Shared);
    }


    /// <summary>
    /// Writes <paramref name="value"/> into <paramref name="destination"/> as a right-aligned canonical
    /// big-endian scalar.
    /// </summary>
    /// <param name="value">The non-negative value to write.</param>
    /// <param name="destination">The scalar-width destination.</param>
    private static void WriteCanonicalBigEndian(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        if(!value.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Witness value did not fit the canonical span.");
        }

        //TryWriteBytes packs the value at the start; right-align it so the
        //scalar is canonical big-endian (high-order zero padding on the left).
        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}

using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using Lumoin.Veridical.Core.Memory;
using System;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Boundary tests for the ZkInterface builders' variable-id intake and the witness builder's
/// source-relative column ceiling. A variable id at <see cref="int.MaxValue"/> resolves to
/// <c>int.MaxValue + 1</c> columns, which overflows the checked <c>(int)</c> cast in the
/// builders' column-count resolution; the builders must reject such an id at intake with a
/// documented <see cref="ArgumentException"/> rather than surface an <see cref="OverflowException"/>
/// at build time. Separately, the witness builder sizes a dense <c>z[1..]</c> buffer from the
/// declared <c>free_variable_id</c> and the referenced ids alone, so a hostile stream can declare
/// a huge column space from a few bytes; the builder must reject a column count the source cannot
/// justify rather than rent an unbounded buffer, the failure mode a fuzzed witness stream can
/// trigger from a few malformed bytes. A column count the source can justify is still rejected,
/// before anything is rented, when its dense buffer would exceed one addressable span.
/// </summary>
[TestClass]
internal sealed class ZkInterfaceBuilderBoundaryTests
{
    /// <summary>A variable id equal to <see cref="int.MaxValue"/> is the smallest id whose +1 column count overflows Int32.</summary>
    private const ulong Int32BoundaryVariableId = int.MaxValue;

    /// <summary>
    /// The widest column ceiling, which no Int32 column count exceeds, so the source-ceiling guard never answers
    /// and the tests that pass it reach the builders' other guards.
    /// </summary>
    private const int UnboundedColumnCeiling = int.MaxValue;

    /// <summary>The byte length of a short source, passed as the column ceiling; a stream this short cannot describe many columns.</summary>
    private const int SmallSourceByteLength = 32;

    /// <summary>The widest column count an Int32 holds, which a declared variable space may reach.</summary>
    private const int Int32BoundaryColumnCount = int.MaxValue;

    /// <summary>
    /// The <c>free_variable_id</c> that declares <see cref="Int32BoundaryColumnCount"/> columns, holding the
    /// ids <c>0</c> to <c>int.MaxValue - 1</c>: exactly the ids variable intake accepts.
    /// </summary>
    private const ulong Int32BoundaryFreeVariableId = Int32BoundaryColumnCount;

    /// <summary>The narrowest <c>free_variable_id</c> whose column count no Int32 can hold.</summary>
    private const ulong FirstFreeVariableIdBeyondInt32 = Int32BoundaryFreeVariableId + 1;

    /// <summary>
    /// The constant-one variable: the only id the declared-width tests reference, and the only one the
    /// empty-source test assigns.
    /// </summary>
    private const ulong ConstantVariableId = 0;

    /// <summary>The coefficient one, written as the single little-endian byte a truncating producer emits.</summary>
    private const byte UnitCoefficient = 1;

    /// <summary>The row count of an instance built from a single constraint.</summary>
    private const int SingleConstraintRowCount = 1;

    /// <summary>
    /// The field element one, written as the single little-endian byte a truncating producer emits; the witness
    /// rejection tests assign it where no value is ever read back.
    /// </summary>
    private const byte UnitValue = 1;

    /// <summary>The byte length of an empty source, which can describe no column at all.</summary>
    private const int EmptySourceByteLength = 0;

    /// <summary>The column count of a stream whose only referenced id is the constant variable.</summary>
    private const ulong ConstantOnlyColumnCount = ConstantVariableId + 1;

    /// <summary>
    /// A declared million-column variable space: far more columns than <see cref="SmallSourceByteLength"/> bytes can
    /// describe, and far below the dense-buffer limit.
    /// </summary>
    private const ulong SourceExceedingFreeVariableId = 1_000_000;

    /// <summary>
    /// A variable id half a million columns out: its column count is far more than <see cref="SmallSourceByteLength"/>
    /// bytes can describe, and far below the dense-buffer limit.
    /// </summary>
    private const ulong SourceExceedingAssignedId = 500_000;

    /// <summary>The column count <see cref="SourceExceedingAssignedId"/> resolves to: ids are zero-based, so one more than the id.</summary>
    private const ulong SourceExceedingAssignedIdColumnCount = SourceExceedingAssignedId + 1;


    /// <summary>
    /// Pins that a variable id equal to <see cref="int.MaxValue"/> is rejected at intake with an
    /// <see cref="ArgumentException"/> naming the id, because holding it would need <c>int.MaxValue + 1</c>
    /// columns. The id is the only input the call validates, so the range guard is the only one that can
    /// answer; its message is asserted because the exception type alone does not identify it.
    /// </summary>
    [TestMethod]
    public void R1csInstanceBuilderRejectsVariableIdAtInt32Boundary()
    {
        ZkInterfaceR1csInstanceBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => builder.OnInstanceVariable(Int32BoundaryVariableId, default),
            "A variable id at the Int32 boundary must be rejected.");

        Assert.Contains($"variable id {Int32BoundaryVariableId} exceeds the addressable column range", exception.Message, StringComparison.Ordinal, "The variable-id range guard must be what rejects the id.");
    }


    /// <summary>
    /// Pins that a <c>free_variable_id</c> equal to <see cref="int.MaxValue"/> is accepted and becomes the
    /// column count, although the only constraint references just the constant column. That declaration
    /// covers exactly the ids variable intake accepts, so rejecting it would refuse a stream whose every id is
    /// addressable, and only the recorded declaration can raise the count above the single referenced
    /// column. The build sizes its buffers by entry count, never by column count, and each matrix stores
    /// one entry, so the test stays small. Satisfaction checking and proving each rent one scalar per
    /// column, which is why the test stops at the built shape.
    /// </summary>
    [TestMethod]
    public void R1csInstanceBuilderAcceptsFreeVariableIdAtInt32Boundary()
    {
        ZkInterfaceR1csInstanceBuilder builder = CreateR1csBuilderDeclaringFreeVariableId(Int32BoundaryFreeVariableId);

        using RawR1csInstance instance = builder.Build();

        Assert.AreEqual(Int32BoundaryColumnCount, instance.A.ColumnCount, "The declared free_variable_id must set the column count.");
        Assert.AreEqual(SingleConstraintRowCount, instance.A.RowCount, "One constraint must give one row.");
    }


    /// <summary>
    /// Pins that a <c>free_variable_id</c> one past <see cref="int.MaxValue"/> is rejected at build time with
    /// an <see cref="ArgumentException"/> naming the declaration, because no Int32 column count can hold it.
    /// The field matches, a constraint exists and the only referenced id is the constant column, so the
    /// declared-width guard is the only one that can answer; the asserted text names
    /// <c>free_variable_id</c>, which the variable-id guard's message does not.
    /// </summary>
    [TestMethod]
    public void R1csInstanceBuilderRejectsFreeVariableIdBeyondInt32Range()
    {
        ZkInterfaceR1csInstanceBuilder builder = CreateR1csBuilderDeclaringFreeVariableId(FirstFreeVariableIdBeyondInt32);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => builder.Build().Dispose(),
            "A free_variable_id beyond the Int32 range must be rejected.");

        Assert.Contains($"free_variable_id {FirstFreeVariableIdBeyondInt32} exceeds the addressable column range", exception.Message, StringComparison.Ordinal, "The declared-width guard must be what rejects the stream.");
    }


    /// <summary>
    /// Pins that the witness builder rejects a variable id equal to <see cref="int.MaxValue"/> at intake with an
    /// <see cref="ArgumentException"/> naming the id, because holding it would need <c>int.MaxValue + 1</c>
    /// columns. The range check is the first statement of intake, so it is the only guard that can answer; its
    /// message is asserted because the exception type alone does not identify it.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsVariableIdAtInt32Boundary()
    {
        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, UnboundedColumnCeiling);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => builder.OnWitnessVariable(Int32BoundaryVariableId, default),
            "A variable id at the Int32 boundary must be rejected.");

        Assert.Contains($"variable id {Int32BoundaryVariableId} exceeds the addressable column range", exception.Message, StringComparison.Ordinal, "The variable-id range guard must be what rejects the id.");
    }


    /// <summary>
    /// Pins that the witness builder rejects a <c>free_variable_id</c> equal to <see cref="int.MaxValue"/> before
    /// renting anything, with an <see cref="ArgumentException"/> naming the column count: a dense <c>z[1..]</c> of
    /// <c>int.MaxValue - 1</c> scalars would need just under 64 GiB, far more than one span can address. The
    /// declared-width check accepts the declaration, since its column count fits Int32, and the widest ceiling
    /// admits it, so only the dense-buffer guard can answer. The exact type and the message are both asserted:
    /// without that guard the Int32 byte-size product wraps negative and the pool refuses the rent with the
    /// derived <see cref="ArgumentOutOfRangeException"/>, and a declared-width check that also refused
    /// <see cref="int.MaxValue"/> would name <c>free_variable_id</c> instead.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsFreeVariableIdAtInt32BoundaryAsUnaddressable()
    {
        ZkInterfaceWitnessBuilder builder = CreateWitnessBuilderDeclaringField(UnboundedColumnCeiling);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(Int32BoundaryFreeVariableId);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => builder.Build().Dispose(),
            "A column space whose dense witness no single span can address must be rejected.");

        Assert.Contains($"variable space of {Int32BoundaryColumnCount} columns exceeds the addressable dense-buffer size", exception.Message, StringComparison.Ordinal, "The dense-buffer guard must be what rejects the stream.");
    }


    /// <summary>
    /// Pins that the witness builder rejects a <c>free_variable_id</c> one past <see cref="int.MaxValue"/> at build
    /// time with an <see cref="ArgumentException"/> naming the declaration, because no Int32 column count can hold
    /// it. The field matches, nothing is assigned, and the declared-width check is the first step of column
    /// resolution, so it is the only guard that can answer; the asserted text names <c>free_variable_id</c>, which
    /// the empty-witness guard that a wrapped column count would reach does not.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsFreeVariableIdBeyondInt32Range()
    {
        ZkInterfaceWitnessBuilder builder = CreateWitnessBuilderDeclaringField(UnboundedColumnCeiling);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(FirstFreeVariableIdBeyondInt32);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => builder.Build().Dispose(),
            "A free_variable_id beyond the Int32 range must be rejected.");

        Assert.Contains($"free_variable_id {FirstFreeVariableIdBeyondInt32} exceeds the addressable column range", exception.Message, StringComparison.Ordinal, "The declared-width guard must be what rejects the stream.");
    }


    /// <summary>
    /// Pins that a short source declaring a million-column variable space through <c>free_variable_id</c> is
    /// rejected against the source ceiling instead of being sized into a dense witness of about 32 MB. The column
    /// count is far below the dense-buffer limit and nothing is assigned, so only the source-ceiling guard can
    /// answer. Its message, which names the declared column count and the source length, is asserted because a
    /// resolution that loses the declaration reaches the empty-witness guard, which throws the same type.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsFreeVariableIdExceedingSource()
    {
        ZkInterfaceWitnessBuilder builder = CreateWitnessBuilderDeclaringField(SmallSourceByteLength);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(SourceExceedingFreeVariableId);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => builder.Build().Dispose(),
            "A declared column space the source cannot describe must be rejected.");

        Assert.Contains(SourceCeilingMessage(SourceExceedingFreeVariableId, SmallSourceByteLength), exception.Message, StringComparison.Ordinal, "The source-ceiling guard must be what rejects the stream.");
    }


    /// <summary>
    /// Pins that one assignment to a far column is rejected against the source ceiling, because a referenced id
    /// widens the dense witness exactly as a declared <c>free_variable_id</c> does. The stream declares only the
    /// field, so the assigned id alone sizes the column space, and that count is far below the dense-buffer limit,
    /// so only the source-ceiling guard can answer. Its message names the column count the id resolves to, which a
    /// resolution that drops or shortens the assigned-id width cannot produce.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsAssignedIdExceedingSource()
    {
        ZkInterfaceWitnessBuilder builder = CreateWitnessBuilderDeclaringField(SmallSourceByteLength);
        IZkInterfaceMessageSink sink = builder;

        Span<byte> value = stackalloc byte[] { UnitValue };
        sink.OnWitnessVariable(SourceExceedingAssignedId, value);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => builder.Build().Dispose(),
            "A referenced column space the source cannot describe must be rejected.");

        Assert.Contains(SourceCeilingMessage(SourceExceedingAssignedIdColumnCount, SmallSourceByteLength), exception.Message, StringComparison.Ordinal, "The source-ceiling guard must be what rejects the stream.");
    }


    /// <summary>
    /// Pins that an empty source is rejected by the source ceiling even when its only assignment is to the
    /// constant variable: that assignment resolves to one column, and zero bytes can describe none. A resolution
    /// that ignored a lone column 0 would pass the ceiling and reach the empty-witness guard, which rejects the
    /// same stream with the same exception type, so the asserted text, which names the one column and the empty
    /// source, is what identifies the source-ceiling guard.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsConstantColumnAgainstEmptySource()
    {
        ZkInterfaceWitnessBuilder builder = CreateWitnessBuilderDeclaringField(EmptySourceByteLength);
        IZkInterfaceMessageSink sink = builder;

        Span<byte> one = stackalloc byte[] { UnitValue };
        sink.OnInstanceVariable(ConstantVariableId, one);

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => builder.Build().Dispose(),
            "A column space an empty source cannot describe must be rejected.");

        Assert.Contains(SourceCeilingMessage(ConstantOnlyColumnCount, EmptySourceByteLength), exception.Message, StringComparison.Ordinal, "The source-ceiling guard must be what rejects the stream.");
    }


    /// <summary>
    /// Pins that the source ceiling is inclusive: a column count exactly equal to the ceiling is accepted, so a
    /// witness whose variable space just fills its source still builds.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderAcceptsColumnCountEqualToCeiling()
    {
        const int columnCount = 4;

        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, columnCount);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFieldMaximum(ZkInterfaceTestFields.FieldMaximumLittleEndian(CurveParameterSet.Bls12Curve381));
        sink.OnFreeVariableId(columnCount);

        Span<byte> value = stackalloc byte[] { 1 };
        sink.OnWitnessVariable(1, value);
        sink.OnWitnessVariable(2, value);
        sink.OnWitnessVariable(3, value);

        using RawR1csWitness witness = builder.Build();

        Assert.AreEqual(columnCount - 1, witness.WitnessVariableCount, "WitnessVariableCount = columnCount - 1");
    }


    /// <summary>
    /// Creates a BLS12-381 instance builder that has received <paramref name="freeVariableId"/>, the curve's
    /// own field maximum and one constraint whose A, B and C terms reference only the constant column with
    /// coefficient one. Every check before column resolution passes and the referenced ids need a single
    /// column, so the declaration alone decides whether and how far the column count exceeds one.
    /// </summary>
    /// <param name="freeVariableId">The declared variable space.</param>
    /// <returns>The builder, ready to build.</returns>
    private static ZkInterfaceR1csInstanceBuilder CreateR1csBuilderDeclaringFreeVariableId(ulong freeVariableId)
    {
        ZkInterfaceR1csInstanceBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFreeVariableId(freeVariableId);

        Span<byte> fieldMaximum = stackalloc byte[ZkInterfaceTestFields.FieldElementSizeBytes];
        ZkInterfaceTestFields.WriteFieldMaximumLittleEndian(CurveParameterSet.Bls12Curve381, fieldMaximum);
        sink.OnFieldMaximum(fieldMaximum);

        Span<byte> one = stackalloc byte[] { UnitCoefficient };
        sink.BeginConstraint();
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.A, ConstantVariableId, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.B, ConstantVariableId, one);
        sink.OnConstraintTerm(ZkInterfaceConstraintMatrix.C, ConstantVariableId, one);
        sink.EndConstraint();

        return builder;
    }


    /// <summary>
    /// Creates a BLS12-381 witness builder with the column ceiling <paramref name="maxColumnCount"/> that has
    /// received the curve's own field maximum, so the field checks pass and each test's declarations and
    /// assignments decide which build guard answers.
    /// </summary>
    /// <param name="maxColumnCount">The column ceiling, standing in for the source byte length.</param>
    /// <returns>The builder, ready for declarations and assignments.</returns>
    private static ZkInterfaceWitnessBuilder CreateWitnessBuilderDeclaringField(int maxColumnCount)
    {
        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, maxColumnCount);
        IZkInterfaceMessageSink sink = builder;

        Span<byte> fieldMaximum = stackalloc byte[ZkInterfaceTestFields.FieldElementSizeBytes];
        ZkInterfaceTestFields.WriteFieldMaximumLittleEndian(CurveParameterSet.Bls12Curve381, fieldMaximum);
        sink.OnFieldMaximum(fieldMaximum);

        return builder;
    }


    /// <summary>
    /// Returns the text the witness builder's source-ceiling guard produces for a variable space of
    /// <paramref name="columnCount"/> columns and a source of <paramref name="sourceByteLength"/> bytes; no other
    /// guard names a byte length.
    /// </summary>
    /// <param name="columnCount">The column count the stream resolves to.</param>
    /// <param name="sourceByteLength">The column ceiling the builder was created with.</param>
    /// <returns>The fragment the rejection message must contain.</returns>
    private static string SourceCeilingMessage(ulong columnCount, int sourceByteLength)
    {
        return $"declares a {columnCount}-column variable space that the {sourceByteLength}-byte source cannot describe";
    }
}

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
/// trigger from a few malformed bytes.
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

    /// <summary>
    /// The field element one, written as the single little-endian byte a truncating producer emits; the witness
    /// rejection tests assign it where no value is ever read back.
    /// </summary>
    private const byte UnitValue = 1;

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


    /// <summary>
    /// Pins that a variable id equal to <see cref="int.MaxValue"/> is rejected at intake with an
    /// <see cref="ArgumentException"/>, because holding it would need <c>int.MaxValue + 1</c>
    /// columns. The id is the only input the call validates, so the range guard is the only one that can
    /// answer.
    /// </summary>
    [TestMethod]
    public void R1csInstanceBuilderRejectsVariableIdAtInt32Boundary()
    {
        ZkInterfaceR1csInstanceBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        Assert.ThrowsExactly<ArgumentException>(() => builder.OnInstanceVariable(Int32BoundaryVariableId, default));
    }


    /// <summary>
    /// Pins that the witness builder rejects a variable id equal to <see cref="int.MaxValue"/> at intake with an
    /// <see cref="ArgumentException"/>, because holding it would need <c>int.MaxValue + 1</c>
    /// columns. The range check is the first statement of intake, so it is the only guard that can answer.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsVariableIdAtInt32Boundary()
    {
        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, UnboundedColumnCeiling);

        Assert.ThrowsExactly<ArgumentException>(() => builder.OnWitnessVariable(Int32BoundaryVariableId, default));
    }


    /// <summary>
    /// Pins that a short source declaring a million-column variable space through <c>free_variable_id</c> is
    /// rejected against the source ceiling instead of being sized into a dense witness of about 32 MB. The column
    /// count is far below the dense-buffer limit and nothing is assigned, so only the source-ceiling guard can
    /// answer.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsFreeVariableIdExceedingSource()
    {
        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, SmallSourceByteLength);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFieldMaximum(ZkInterfaceTestFields.FieldMaximumLittleEndian(CurveParameterSet.Bls12Curve381));
        sink.OnFreeVariableId(SourceExceedingFreeVariableId);

        Assert.ThrowsExactly<ArgumentException>(() => builder.Build().Dispose());
    }


    /// <summary>
    /// Pins that one assignment to a far column is rejected against the source ceiling, because a referenced id
    /// widens the dense witness exactly as a declared <c>free_variable_id</c> does. The stream declares only the
    /// field, so the assigned id alone sizes the column space, and that count is far below the dense-buffer limit,
    /// so only the source-ceiling guard can answer.
    /// </summary>
    [TestMethod]
    public void WitnessBuilderRejectsAssignedIdExceedingSource()
    {
        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, SmallSourceByteLength);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFieldMaximum(ZkInterfaceTestFields.FieldMaximumLittleEndian(CurveParameterSet.Bls12Curve381));

        Span<byte> value = stackalloc byte[] { UnitValue };
        sink.OnWitnessVariable(SourceExceedingAssignedId, value);

        Assert.ThrowsExactly<ArgumentException>(() => builder.Build().Dispose());
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
}

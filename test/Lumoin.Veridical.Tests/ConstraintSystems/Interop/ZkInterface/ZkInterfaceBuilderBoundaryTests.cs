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
/// justify rather than rent an unbounded buffer (the zkinterface-wtns fuzz OOM, W1-c).
/// </summary>
[TestClass]
internal sealed class ZkInterfaceBuilderBoundaryTests
{
    //A variable id equal to int.MaxValue is the smallest id whose +1 column count overflows Int32.
    private const ulong Int32BoundaryVariableId = int.MaxValue;

    //An id above int.MaxValue is rejected before column resolution, so the ceiling below it is
    //irrelevant to the boundary tests; they pass the widest ceiling.
    private const int UnboundedColumnCeiling = int.MaxValue;

    //A tiny source cannot describe many columns; the ceiling below stands in for a short stream.
    private const int SmallSourceByteLength = 32;


    [TestMethod]
    public void R1csInstanceBuilderRejectsVariableIdAtInt32Boundary()
    {
        ZkInterfaceR1csInstanceBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        Assert.ThrowsExactly<ArgumentException>(() => builder.OnInstanceVariable(Int32BoundaryVariableId, default));
    }


    [TestMethod]
    public void WitnessBuilderRejectsVariableIdAtInt32Boundary()
    {
        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, UnboundedColumnCeiling);

        Assert.ThrowsExactly<ArgumentException>(() => builder.OnWitnessVariable(Int32BoundaryVariableId, default));
    }


    [TestMethod]
    public void WitnessBuilderRejectsFreeVariableIdExceedingSource()
    {
        //A short source declares a million-column variable space via free_variable_id; sizing the
        //dense witness from it would rent gigabytes, so Build rejects it as malformed.
        const ulong declaredColumns = 1_000_000;

        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, SmallSourceByteLength);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFieldMaximum(ZkInterfaceTestFields.FieldMaximumLittleEndian(CurveParameterSet.Bls12Curve381));
        sink.OnFreeVariableId(declaredColumns);

        Assert.ThrowsExactly<ArgumentException>(() => builder.Build());
    }


    [TestMethod]
    public void WitnessBuilderRejectsAssignedIdExceedingSource()
    {
        //The amplification also travels the assigned-id path: one reference to a far column widens
        //the dense witness the same way, so it must be rejected against the source ceiling too.
        const ulong farColumn = 500_000;

        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared, SmallSourceByteLength);
        IZkInterfaceMessageSink sink = builder;
        sink.OnFieldMaximum(ZkInterfaceTestFields.FieldMaximumLittleEndian(CurveParameterSet.Bls12Curve381));

        Span<byte> value = stackalloc byte[] { 1 };
        sink.OnWitnessVariable(farColumn, value);

        Assert.ThrowsExactly<ArgumentException>(() => builder.Build());
    }


    [TestMethod]
    public void WitnessBuilderAcceptsColumnCountEqualToCeiling()
    {
        //The ceiling is inclusive: a column count exactly equal to the source ceiling is accepted
        //(the guard is '>', not '>='). Locks that boundary so a future '>=' typo cannot silently
        //start rejecting a valid witness whose variable space just fills its source.
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

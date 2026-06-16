using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using System;
using System.Buffers.Binary;
using System.Collections.Generic;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Structural conformance tests for the hand-written FlatBuffers cursor
/// (<see cref="FlatBufferTable"/> / <see cref="FlatBufferVector"/>) against
/// the vendored upstream <c>example.zkif</c>. The sample's contents are
/// fixed and independently described by the upstream <c>example.json</c>
/// (see <c>Fixtures/FIXTURES.md</c>), so these assertions pin the cursor's
/// vtable walk, offset following, and scalar/vector/sub-table reads to a
/// reference producer's bytes. A single LE/offset/vtable mistake surfaces
/// here as a wrong value rather than as a downstream satisfaction failure.
/// </summary>
[TestClass]
internal sealed class FlatBufferCursorTests
{
    //Schema-declaration slot order (zkinterface.fbs). A FlatBuffers field's
    //vtable slot is its zero-based position in its table's field list.
    private const int RootMessageValueSlot = 1;            //Root.message (union value table)

    private const int HeaderInstanceVariablesSlot = 0;     //CircuitHeader.instance_variables
    private const int HeaderFreeVariableIdSlot = 1;        //CircuitHeader.free_variable_id
    private const int HeaderFieldMaximumSlot = 2;          //CircuitHeader.field_maximum

    private const int VariablesIdsSlot = 0;                //Variables.variable_ids
    private const int VariablesValuesSlot = 1;             //Variables.values

    private const int ConstraintSystemConstraintsSlot = 0; //ConstraintSystem.constraints
    private const int ConstraintLcASlot = 0;               //BilinearConstraint.linear_combination_a
    private const int ConstraintLcBSlot = 1;               //BilinearConstraint.linear_combination_b
    private const int ConstraintLcCSlot = 2;               //BilinearConstraint.linear_combination_c

    private const int WitnessAssignedVariablesSlot = 0;    //Witness.assigned_variables

    private const int ToyElementSizeBytes = 4;             //example.zkif uses 4-byte little-endian field elements


    [TestMethod]
    public void CircuitHeaderInstanceVariablesDecode()
    {
        byte[] file = ZkInterfaceExampleFixture.ExampleBytes();
        ZkInterfaceMessageSpan headerSpan = SingleMessageOfType(file, ZkInterfaceMessageType.CircuitHeader);

        FlatBufferTable header = UnionValueTable(file, headerSpan);

        Assert.AreEqual(6UL, header.ReadUInt64Field(HeaderFreeVariableIdSlot), "free_variable_id");
        Assert.IsFalse(header.HasField(HeaderFieldMaximumSlot), "field_maximum is absent in the toy sample");

        Assert.IsTrue(header.TryGetSubTable(HeaderInstanceVariablesSlot, out FlatBufferTable instanceVariables), "instance_variables present");

        CollectionAssert.AreEqual(
            new ulong[] { 1, 2, 3 },
            VariableIds(instanceVariables),
            "instance_variables.variable_ids");

        CollectionAssert.AreEqual(
            new uint[] { 3, 4, 25 },
            ElementValues(instanceVariables, expectedCount: 3),
            "instance_variables.values (3 four-byte little-endian elements)");
    }


    [TestMethod]
    public void ConstraintSystemConstraintsDecode()
    {
        byte[] file = ZkInterfaceExampleFixture.ExampleBytes();
        ZkInterfaceMessageSpan systemSpan = SingleMessageOfType(file, ZkInterfaceMessageType.ConstraintSystem);

        FlatBufferTable system = UnionValueTable(file, systemSpan);
        Assert.IsTrue(system.TryGetVector(ConstraintSystemConstraintsSlot, out FlatBufferVector constraints), "constraints present");
        Assert.AreEqual(3, constraints.Length, "constraint count");

        //C0: v1 * v1 = v4
        AssertConstraint(constraints.ElementTable(0), expectedA: 1, expectedB: 1, expectedC: 4);
        //C1: v2 * v2 = v5
        AssertConstraint(constraints.ElementTable(1), expectedA: 2, expectedB: 2, expectedC: 5);

        //C2: 1 * (v4 + v5) = v3 — the B combination spans two variables.
        FlatBufferTable thirdConstraint = constraints.ElementTable(2);
        AssertLinearCombination(thirdConstraint, ConstraintLcASlot, [0]);
        AssertLinearCombination(thirdConstraint, ConstraintLcBSlot, [4, 5]);
        AssertLinearCombination(thirdConstraint, ConstraintLcCSlot, [3]);
    }


    [TestMethod]
    public void WitnessAssignedVariablesDecode()
    {
        byte[] file = ZkInterfaceExampleFixture.ExampleBytes();
        ZkInterfaceMessageSpan witnessSpan = SingleMessageOfType(file, ZkInterfaceMessageType.Witness);

        FlatBufferTable witness = UnionValueTable(file, witnessSpan);
        Assert.IsTrue(witness.TryGetSubTable(WitnessAssignedVariablesSlot, out FlatBufferTable assigned), "assigned_variables present");

        CollectionAssert.AreEqual(new ulong[] { 4, 5 }, VariableIds(assigned), "assigned_variables.variable_ids");
        CollectionAssert.AreEqual(new uint[] { 9, 16 }, ElementValues(assigned, expectedCount: 2), "assigned_variables.values");
    }


    private static void AssertConstraint(FlatBufferTable constraint, ulong expectedA, ulong expectedB, ulong expectedC)
    {
        AssertLinearCombination(constraint, ConstraintLcASlot, [expectedA]);
        AssertLinearCombination(constraint, ConstraintLcBSlot, [expectedB]);
        AssertLinearCombination(constraint, ConstraintLcCSlot, [expectedC]);
    }


    private static void AssertLinearCombination(FlatBufferTable constraint, int slot, ulong[] expectedIds)
    {
        Assert.IsTrue(constraint.TryGetSubTable(slot, out FlatBufferTable combination), $"linear combination in slot {slot} present");
        CollectionAssert.AreEqual(expectedIds, VariableIds(combination), $"variable_ids in slot {slot}");

        //Every coefficient in the toy example is the field element 1, stored
        //in a single byte (element size = values.length / variable_ids.length).
        uint[] coefficients = ElementValues(combination, expectedIds.Length);
        foreach(uint coefficient in coefficients)
        {
            Assert.AreEqual(1U, coefficient, $"coefficient in slot {slot}");
        }
    }


    private static ulong[] VariableIds(FlatBufferTable variables)
    {
        Assert.IsTrue(variables.TryGetVector(VariablesIdsSlot, out FlatBufferVector ids), "variable_ids present");
        var result = new ulong[ids.Length];
        for(int i = 0; i < ids.Length; i++)
        {
            result[i] = ids.ElementUInt64(i);
        }

        return result;
    }


    private static uint[] ElementValues(FlatBufferTable variables, int expectedCount)
    {
        Assert.IsTrue(variables.TryGetVector(VariablesValuesSlot, out FlatBufferVector values), "values present");
        ReadOnlySpan<byte> raw = values.ByteSpan;

        //element size = values.length / variable_ids.length; the sample's
        //elements are small enough to fit a 4-byte (or 1-byte) little-endian
        //read, so widen each element into a uint for comparison.
        int elementSize = raw.Length / expectedCount;
        Assert.IsTrue(elementSize is 1 or ToyElementSizeBytes, $"unexpected element size {elementSize}");

        var result = new uint[expectedCount];
        for(int i = 0; i < expectedCount; i++)
        {
            ReadOnlySpan<byte> element = raw.Slice(i * elementSize, elementSize);
            uint value = 0;
            for(int b = 0; b < element.Length; b++)
            {
                value |= (uint)element[b] << (8 * b);
            }

            result[i] = value;
        }

        return result;
    }


    private static FlatBufferTable UnionValueTable(byte[] file, ZkInterfaceMessageSpan span)
    {
        ReadOnlySpan<byte> messageBuffer = file.AsSpan(span.BufferStart, span.BufferLength);
        FlatBufferTable root = FlatBufferTable.Root(messageBuffer);
        Assert.IsTrue(root.TryGetSubTable(RootMessageValueSlot, out FlatBufferTable value), "Root.message union value present");
        return value;
    }


    private static ZkInterfaceMessageSpan SingleMessageOfType(byte[] file, ZkInterfaceMessageType type)
    {
        IReadOnlyList<ZkInterfaceMessageSpan> messages = ZkInterfaceCursorDecoder.LocateMessages(file);
        ZkInterfaceMessageSpan? found = null;
        foreach(ZkInterfaceMessageSpan message in messages)
        {
            if(message.Type == type)
            {
                Assert.IsNull(found, $"expected exactly one {type} message");
                found = message;
            }
        }

        Assert.IsNotNull(found, $"no {type} message in the sample");
        return found.Value;
    }
}

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
/// vtable walk, offset following, and scalar/vector/sub-table reads to
/// bytes this repository did not itself encode. A single LE/offset/vtable
/// mistake surfaces here as a wrong value rather than as a downstream
/// satisfaction failure.
/// </summary>
/// <remarks>
/// The slot constants below name each field's zero-based position in its
/// declaring table's field list, per the <c>zkinterface.fbs</c> schema; a
/// FlatBuffers vtable indexes a field by this slot, never by name.
/// </remarks>
[TestClass]
internal sealed class FlatBufferCursorTests
{
    /// <summary>The vtable slot of <c>Root.message</c>, the union value table.</summary>
    private const int RootMessageValueSlot = 1;

    /// <summary>The vtable slot of <c>CircuitHeader.instance_variables</c>.</summary>
    private const int HeaderInstanceVariablesSlot = 0;

    /// <summary>The vtable slot of <c>CircuitHeader.free_variable_id</c>.</summary>
    private const int HeaderFreeVariableIdSlot = 1;

    /// <summary>The vtable slot of <c>CircuitHeader.field_maximum</c>.</summary>
    private const int HeaderFieldMaximumSlot = 2;

    /// <summary>The vtable slot of <c>Variables.variable_ids</c>.</summary>
    private const int VariablesIdsSlot = 0;

    /// <summary>The vtable slot of <c>Variables.values</c>.</summary>
    private const int VariablesValuesSlot = 1;

    /// <summary>The vtable slot of <c>ConstraintSystem.constraints</c>.</summary>
    private const int ConstraintSystemConstraintsSlot = 0;

    /// <summary>The vtable slot of <c>BilinearConstraint.linear_combination_a</c>.</summary>
    private const int ConstraintLcASlot = 0;

    /// <summary>The vtable slot of <c>BilinearConstraint.linear_combination_b</c>.</summary>
    private const int ConstraintLcBSlot = 1;

    /// <summary>The vtable slot of <c>BilinearConstraint.linear_combination_c</c>.</summary>
    private const int ConstraintLcCSlot = 2;

    /// <summary>The vtable slot of <c>Witness.assigned_variables</c>.</summary>
    private const int WitnessAssignedVariablesSlot = 0;

    /// <summary>The width, in bytes, of each little-endian field element <c>example.zkif</c> stores.</summary>
    private const int ToyElementSizeBytes = 4;


    /// <summary>Decodes and asserts the <c>CircuitHeader.instance_variables</c> sub-table against the vendored sample's known contents.</summary>
    [TestMethod]
    public void CircuitHeaderInstanceVariablesDecode()
    {
        byte[] file = ZkInterfaceExampleFixture.ExampleBytes();
        ZkInterfaceMessageSpan headerSpan = SingleMessageOfType(file, ZkInterfaceMessageType.CircuitHeader);

        FlatBufferTable header = UnionValueTable(file, headerSpan);

        Assert.AreEqual(6UL, header.ReadUInt64Field(HeaderFreeVariableIdSlot), "free_variable_id");
        Assert.IsFalse(header.HasField(HeaderFieldMaximumSlot), "field_maximum is absent in the toy sample");

        Assert.IsTrue(header.TryGetSubTable(HeaderInstanceVariablesSlot, out FlatBufferTable instanceVariables), "instance_variables present");

        Assert.AreSequenceEqual(
            new ulong[] { 1, 2, 3 },
            VariableIds(instanceVariables),
            "instance_variables.variable_ids");

        Assert.AreSequenceEqual(
            new uint[] { 3, 4, 25 },
            ElementValues(instanceVariables, expectedCount: 3),
            "instance_variables.values (3 four-byte little-endian elements)");
    }


    /// <summary>Decodes and asserts the <c>ConstraintSystem.constraints</c> vector, including a third constraint whose B combination spans two variables.</summary>
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


    /// <summary>Decodes and asserts the <c>Witness.assigned_variables</c> sub-table against the vendored sample's known contents.</summary>
    [TestMethod]
    public void WitnessAssignedVariablesDecode()
    {
        byte[] file = ZkInterfaceExampleFixture.ExampleBytes();
        ZkInterfaceMessageSpan witnessSpan = SingleMessageOfType(file, ZkInterfaceMessageType.Witness);

        FlatBufferTable witness = UnionValueTable(file, witnessSpan);
        Assert.IsTrue(witness.TryGetSubTable(WitnessAssignedVariablesSlot, out FlatBufferTable assigned), "assigned_variables present");

        Assert.AreSequenceEqual(new ulong[] { 4, 5 }, VariableIds(assigned), "assigned_variables.variable_ids");
        Assert.AreSequenceEqual(new uint[] { 9, 16 }, ElementValues(assigned, expectedCount: 2), "assigned_variables.values");
    }


    /// <summary>Asserts that a constraint's three linear combinations each hold exactly the one expected variable id.</summary>
    private static void AssertConstraint(FlatBufferTable constraint, ulong expectedA, ulong expectedB, ulong expectedC)
    {
        AssertLinearCombination(constraint, ConstraintLcASlot, [expectedA]);
        AssertLinearCombination(constraint, ConstraintLcBSlot, [expectedB]);
        AssertLinearCombination(constraint, ConstraintLcCSlot, [expectedC]);
    }


    /// <summary>Asserts that the linear combination in the given slot holds the expected variable ids, each with the field element 1 as its coefficient.</summary>
    private static void AssertLinearCombination(FlatBufferTable constraint, int slot, ulong[] expectedIds)
    {
        Assert.IsTrue(constraint.TryGetSubTable(slot, out FlatBufferTable combination), $"linear combination in slot {slot} present");
        Assert.AreSequenceEqual(expectedIds, VariableIds(combination), $"variable_ids in slot {slot}");

        //Every coefficient in the toy example is the field element 1, stored
        //in a single byte (element size = values.length / variable_ids.length).
        uint[] coefficients = ElementValues(combination, expectedIds.Length);
        foreach(uint coefficient in coefficients)
        {
            Assert.AreEqual(1U, coefficient, $"coefficient in slot {slot}");
        }
    }


    /// <summary>Reads every element of a <c>Variables</c>-shaped table's <c>variable_ids</c> vector.</summary>
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


    /// <summary>Reads a <c>Variables</c>-shaped table's <c>values</c> byte vector, widening each little-endian element to a <see cref="uint"/>.</summary>
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


    /// <summary>Resolves a message span's root table and returns the sub-table held by its <c>Root.message</c> union value.</summary>
    private static FlatBufferTable UnionValueTable(byte[] file, ZkInterfaceMessageSpan span)
    {
        ReadOnlySpan<byte> messageBuffer = file.AsSpan(span.BufferStart, span.BufferLength);
        FlatBufferTable root = FlatBufferTable.Root(messageBuffer);
        Assert.IsTrue(root.TryGetSubTable(RootMessageValueSlot, out FlatBufferTable value), "Root.message union value present");
        return value;
    }


    /// <summary>Locates the single message of the given type in the file, failing if none or more than one is present.</summary>
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

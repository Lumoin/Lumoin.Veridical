using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using Lumoin.Veridical.Core.Memory;
using System;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Boundary tests for the ZkInterface builders' variable-id intake. A variable id at
/// <see cref="int.MaxValue"/> resolves to <c>int.MaxValue + 1</c> columns, which overflows the
/// checked <c>(int)</c> cast in the builders' column-count resolution. The builders must reject
/// such an id at intake with a documented <see cref="ArgumentException"/> rather than surface an
/// <see cref="OverflowException"/> at build time (a fuzz-adjacent hardening finding, W1-c).
/// </summary>
[TestClass]
internal sealed class ZkInterfaceBuilderBoundaryTests
{
    //A variable id equal to int.MaxValue is the smallest id whose +1 column count overflows Int32.
    private const ulong Int32BoundaryVariableId = int.MaxValue;


    [TestMethod]
    public void R1csInstanceBuilderRejectsVariableIdAtInt32Boundary()
    {
        ZkInterfaceR1csInstanceBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        Assert.ThrowsExactly<ArgumentException>(() => builder.OnInstanceVariable(Int32BoundaryVariableId, default));
    }


    [TestMethod]
    public void WitnessBuilderRejectsVariableIdAtInt32Boundary()
    {
        ZkInterfaceWitnessBuilder builder = new(CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        Assert.ThrowsExactly<ArgumentException>(() => builder.OnWitnessVariable(Int32BoundaryVariableId, default));
    }
}

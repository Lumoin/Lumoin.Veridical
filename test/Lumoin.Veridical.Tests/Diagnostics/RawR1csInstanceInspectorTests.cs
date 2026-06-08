using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Diagnostics;
using Lumoin.Veridical.Tests.ConstraintSystems;
using System;

namespace Lumoin.Veridical.Tests.Diagnostics;

[TestClass]
internal sealed class RawR1csInstanceInspectorTests
{
    [TestMethod]
    public void InspectMultiplyCircuitReportsKnownDimensions()
    {
        using RawR1csInstance instance = R1csTestCircuits.BuildMultiplyCircuit();
        RawR1csInstanceReport report = RawR1csInstanceInspector.Inspect(instance);

        Assert.AreEqual(1, report.Dimensions.ConstraintCount);
        Assert.AreEqual(4, report.Dimensions.VariableCount);
        Assert.AreEqual(0, report.Dimensions.PublicInputCount);
        Assert.AreEqual(1, report.NonzeroCounts.A);
        Assert.AreEqual(1, report.NonzeroCounts.B);
        Assert.AreEqual(1, report.NonzeroCounts.C);
        Assert.AreEqual(CurveParameterSet.Bls12Curve381, report.Curve);
        Assert.Contains("RawR1csInstance", report.TagSummary);
    }


    [TestMethod]
    public void InspectThrowsOnNull()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => RawR1csInstanceInspector.Inspect(null!));
    }
}
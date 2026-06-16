using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Diagnostics;
using Lumoin.Veridical.Tests.ConstraintSystems;

namespace Lumoin.Veridical.Tests.Diagnostics;

[TestClass]
internal sealed class RawR1csInstanceFormatterTests
{
    [TestMethod]
    public void FormatProducesLinePerConstraint()
    {
        using RawR1csInstance instance = R1csTestCircuits.BuildMultiplyCircuit();

        string formatted = RawR1csInstanceFormatter.Format(instance);

        Assert.Contains("Curve: Bls12Curve381", formatted);
        Assert.Contains("c_0:", formatted);
        Assert.Contains("x_1", formatted);
        Assert.Contains("x_2", formatted);
        Assert.Contains("x_3", formatted);
    }


    [TestMethod]
    public void FormatUsesRegisteredVariableNames()
    {
        using RawR1csInstance instance = R1csTestCircuits.BuildMultiplyCircuit();
        var names = new R1csVariableNames
        {
            [new R1csVariableIndex(1)] = "x",
            [new R1csVariableIndex(2)] = "y",
            [new R1csVariableIndex(3)] = "z",
        };

        string formatted = RawR1csInstanceFormatter.Format(instance, names);

        Assert.Contains("·x", formatted);
        Assert.Contains("·y", formatted);
        Assert.Contains("·z", formatted);
    }
}
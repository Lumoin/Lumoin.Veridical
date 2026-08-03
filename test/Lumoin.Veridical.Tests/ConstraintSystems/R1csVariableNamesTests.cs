using Lumoin.Veridical.Core.ConstraintSystems;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

[TestClass]
internal sealed class R1csVariableNamesTests
{
    [TestMethod]
    public void PlaceholderWhenNameNotRegistered()
    {
        var names = new R1csVariableNames();
        Assert.AreEqual("x_7", names.GetOrPlaceholder(new R1csVariableIndex(7)));
    }


    [TestMethod]
    public void RegisteredNameReturned()
    {
        var names = new R1csVariableNames
        {
            [new R1csVariableIndex(1)] = "x",
            [new R1csVariableIndex(2)] = "y",
            [new R1csVariableIndex(3)] = "z",
        };

        Assert.AreEqual("x", names.GetOrPlaceholder(new R1csVariableIndex(1)));
        Assert.AreEqual("y", names.GetOrPlaceholder(new R1csVariableIndex(2)));
        Assert.AreEqual("z", names.GetOrPlaceholder(new R1csVariableIndex(3)));
        //Index 0 is unregistered in this mapping; fall back to placeholder.
        Assert.AreEqual("x_0", names.GetOrPlaceholder(new R1csVariableIndex(0)));
    }


    [TestMethod]
    public void EmptyIsShared()
    {
        //Two separate reads must observe one shared instance — the property
        //is a singleton, not a per-read allocation.
        R1csVariableNames first = R1csVariableNames.Empty;
        R1csVariableNames second = R1csVariableNames.Empty;

        Assert.AreSame(first, second);
        Assert.IsEmpty(first);
    }
}
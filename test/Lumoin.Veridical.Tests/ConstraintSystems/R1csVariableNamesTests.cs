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
        Assert.AreSame(R1csVariableNames.Empty, R1csVariableNames.Empty);
        Assert.IsEmpty(R1csVariableNames.Empty);
    }
}
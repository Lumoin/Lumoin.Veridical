using Lumoin.Veridical.Core.Common;

namespace Lumoin.Veridical.Tests.Common;

/// <summary>
/// Tests the generic <see cref="R1csBuilder{TResult, TState, TBuilder}"/> fold
/// in isolation from the constraint-system types: a synthetic
/// <c>int</c>-building builder confirms transformations apply in addition
/// order, so order is observable in the result.
/// </summary>
[TestClass]
internal sealed class R1csBuilderTests
{
    private readonly record struct FooState: IBuilderState;


    private sealed class FooBuilder: R1csBuilder<int, FooState, FooBuilder>
    {
        public override int Build()
        {
            return Build(seed: 0);
        }
    }


    [TestMethod]
    public void TransformationsApplyInAdditionOrder()
    {
        var builder = new FooBuilder();

        int result = builder
            .With((x, _, _) => x + 1)
            .With((x, _, _) => x * 2)
            .Build();

        Assert.AreEqual(2, result, "(0 + 1) * 2 = 2");
    }


    [TestMethod]
    public void ReversingTransformationOrderChangesTheResult()
    {
        var builder = new FooBuilder();

        int result = builder
            .With((x, _, _) => x * 2)
            .With((x, _, _) => x + 1)
            .Build();

        Assert.AreEqual(1, result, "(0 * 2) + 1 = 1");
    }
}

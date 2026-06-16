using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.ConstraintSystems;
using System.Collections.Immutable;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Structural-equality tests for <see cref="R1csCircuit"/>: two circuits
/// assembled from equal operation and variable sequences must compare
/// equal (and hash equally), and a single differing op must break
/// equality. The builder lands in X.2; here the circuits are assembled
/// directly to pin the equality contract the builder relies on.
/// </summary>
[TestClass]
internal sealed class R1csCircuitEqualityTests
{
    [TestMethod]
    public void IdenticallyAssembledCircuitsAreEqual()
    {
        R1csCircuit first = BuildMultiplyCircuit();
        R1csCircuit second = BuildMultiplyCircuit();

        Assert.AreEqual(first, second, "circuits assembled from equal parts are structurally equal");
        Assert.AreEqual(first.GetHashCode(), second.GetHashCode(), "equal circuits hash equally");
    }


    [TestMethod]
    public void ADifferingConstraintBreaksEquality()
    {
        R1csCircuit baseline = BuildMultiplyCircuit();

        //Same shape, but the constraint's right-hand side references a
        //different variable, so the circuits must not be equal.
        ImmutableArray<IR1csOp> mutatedOps = baseline.Operations.SetItem(
            baseline.Operations.Length - 1,
            new AddConstraintOp(
                R1csLinearCombination.From(new R1csVariableIndex(1)),
                R1csLinearCombination.From(new R1csVariableIndex(2)),
                R1csLinearCombination.From(new R1csVariableIndex(1))));

        var mutated = new R1csCircuit(
            baseline.Curve, mutatedOps, baseline.Variables, baseline.PublicInputCount, baseline.WitnessVariableCount);

        Assert.AreNotEqual(baseline, mutated, "a differing constraint op breaks structural equality");
    }


    private static R1csCircuit BuildMultiplyCircuit()
    {
        //z = (1, x, y, z): x · y = z, no public inputs. Mirrors the
        //hand-built R1csTestCircuits.BuildMultiplyCircuit shape.
        var variables = ImmutableArray.Create(
            new R1csVariableMetadata(new R1csVariableIndex(0), "one", R1csVariableKind.ConstantOne),
            new R1csVariableMetadata(new R1csVariableIndex(1), "x", R1csVariableKind.WitnessVariable),
            new R1csVariableMetadata(new R1csVariableIndex(2), "y", R1csVariableKind.WitnessVariable),
            new R1csVariableMetadata(new R1csVariableIndex(3), "z", R1csVariableKind.WitnessVariable));

        var operations = ImmutableArray.Create<IR1csOp>(
            new DeclareConstantOneOp(),
            new DeclareWitnessVariableOp(new R1csVariableIndex(1), "x"),
            new DeclareWitnessVariableOp(new R1csVariableIndex(2), "y"),
            new DeclareWitnessVariableOp(new R1csVariableIndex(3), "z"),
            new AddConstraintOp(
                R1csLinearCombination.From(new R1csVariableIndex(1)),
                R1csLinearCombination.From(new R1csVariableIndex(2)),
                R1csLinearCombination.From(new R1csVariableIndex(3))));

        return new R1csCircuit(CurveParameterSet.Bls12Curve381, operations, variables, publicInputCount: 0, witnessVariableCount: 3);
    }
}

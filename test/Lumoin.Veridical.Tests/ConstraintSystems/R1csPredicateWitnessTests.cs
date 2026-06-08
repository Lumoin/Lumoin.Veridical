using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Tests that <see cref="R1csPredicateWitness"/> produces auxiliary bindings
/// matching the predicate generators' naming and arithmetic conventions: a
/// predicate fed the helper's bindings compiles and is satisfied. This is the
/// contract that lets callers avoid hand-rolling bit decompositions, inverses,
/// and partial products.
/// </summary>
[TestClass]
internal sealed class R1csPredicateWitnessTests
{
    private static SensitiveMemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;
    private static CurveParameterSet Curve => CurveParameterSet.Bls12Curve381;


    [TestMethod]
    public void RangeCheckBitsSatisfyTheRangePredicate()
    {
        var bindings = new Dictionary<string, BigInteger> { ["v"] = 200 };
        R1csPredicateWitness.AddRangeCheckBits(bindings, "v", 200, bits: 8, Curve);

        AssertSatisfied(b => b.AssertRangeCheck(b.DeclareWitnessVariable("v"), 8, "v"), bindings);
    }


    [TestMethod]
    public void NotEqualInverseSatisfiesTheNotEqualPredicate()
    {
        var bindings = new Dictionary<string, BigInteger> { ["x"] = 7, ["y"] = 3 };
        R1csPredicateWitness.AddNotEqualInverse(bindings, "xy", 7, 3, Curve);

        AssertSatisfied(
            b =>
            {
                R1csVariableIndex x = b.DeclareWitnessVariable("x");
                R1csVariableIndex y = b.DeclareWitnessVariable("y");
                b.AssertNotEqual(x, y, "xy");
            },
            bindings);
    }


    [TestMethod]
    public void NotEqualInverseThrowsWhenValuesAreEqual()
    {
        var bindings = new Dictionary<string, BigInteger>();
        Assert.ThrowsExactly<InvalidOperationException>(
            () => R1csPredicateWitness.AddNotEqualInverse(bindings, "xy", 5, 5, Curve));
    }


    [TestMethod]
    public void SetMembershipProductsSatisfyTheInSetPredicate()
    {
        BigInteger[] set = [5, 17, 42];
        var bindings = new Dictionary<string, BigInteger> { ["x"] = 42 };
        R1csPredicateWitness.AddSetMembershipProducts(bindings, "x", 42, set, Curve);

        AssertSatisfied(b => b.AssertInSet(b.DeclareWitnessVariable("x"), set, "x"), bindings);
    }


    private static void AssertSatisfied(Action<R1csCircuitBuilder> configure, Dictionary<string, BigInteger> bindings)
    {
        var builder = new R1csCircuitBuilder(Curve);
        configure(builder);
        R1csCircuit circuit = builder.Build();

        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(new R1csCircuitInputs(bindings), Pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(
            witness,
            Bls12Curve381BigIntegerScalarReference.GetAdd(),
            Bls12Curve381BigIntegerScalarReference.GetMultiply(),
            Pool);

        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction);
    }
}

using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Tests that the <see cref="R1csSatisfaction.Violated"/> diagnostic
/// payload correctly identifies the failing constraint, the computed
/// values, and the involved variables.
/// </summary>
[TestClass]
internal sealed class R1csInstanceFailureTests
{
    private static readonly ScalarAddDelegate ScalarAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static readonly ScalarMultiplyDelegate ScalarMul = Bls12Curve381BigIntegerScalarReference.GetMultiply();


    [TestMethod]
    public void ViolatedReportsConstraintIndexZero()
    {
        using RawR1csInstance instance = R1csTestCircuits.BuildMultiplyCircuit();
        using RawR1csWitness witness = R1csTestCircuits.BuildBrokenMultiplyWitness(x: 3, y: 4);

        using R1csSatisfaction result = instance.CheckSatisfiedBy(witness, ScalarAdd, ScalarMul, BaseMemoryPool.Shared);

        var violated = (R1csSatisfaction.Violated)result;
        Assert.AreEqual(new R1csConstraintIndex(0), violated.ConstraintIndex);
    }


    [TestMethod]
    public void ViolatedReportsCorrectLhsAndRhs()
    {
        //x=3, y=4 → LHS = 3·4 = 12. Broken witness reports z = 13.
        using RawR1csInstance instance = R1csTestCircuits.BuildMultiplyCircuit();
        using RawR1csWitness witness = R1csTestCircuits.BuildBrokenMultiplyWitness(x: 3, y: 4);

        using R1csSatisfaction result = instance.CheckSatisfiedBy(witness, ScalarAdd, ScalarMul, BaseMemoryPool.Shared);

        var violated = (R1csSatisfaction.Violated)result;
        BigInteger lhs = new(violated.LeftHandSide.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);
        BigInteger rhs = new(violated.RightHandSide.AsReadOnlySpan(), isUnsigned: true, isBigEndian: true);

        Assert.AreEqual(new BigInteger(12), lhs);
        Assert.AreEqual(new BigInteger(13), rhs);
    }


    [TestMethod]
    public void ViolatedReportsInvolvedVariables()
    {
        //x·y=z circuit uses variables x (column 1), y (column 2), z (column 3).
        //Involved variables = {1, 2, 3}.
        using RawR1csInstance instance = R1csTestCircuits.BuildMultiplyCircuit();
        using RawR1csWitness witness = R1csTestCircuits.BuildBrokenMultiplyWitness(x: 3, y: 4);

        using R1csSatisfaction result = instance.CheckSatisfiedBy(witness, ScalarAdd, ScalarMul, BaseMemoryPool.Shared);

        var violated = (R1csSatisfaction.Violated)result;
        Assert.HasCount(3, violated.InvolvedVariables);
        Assert.AreEqual(new R1csVariableIndex(1), violated.InvolvedVariables[0]);
        Assert.AreEqual(new R1csVariableIndex(2), violated.InvolvedVariables[1]);
        Assert.AreEqual(new R1csVariableIndex(3), violated.InvolvedVariables[2]);
    }
}
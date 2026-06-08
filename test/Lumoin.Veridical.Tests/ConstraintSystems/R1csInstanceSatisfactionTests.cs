using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Round-trip tests for <c>RawR1csInstance.CheckSatisfiedBy</c>.
/// </summary>
[TestClass]
internal sealed class R1csInstanceSatisfactionTests
{
    private static readonly ScalarAddDelegate ScalarAdd = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static readonly ScalarMultiplyDelegate ScalarMul = Bls12Curve381BigIntegerScalarReference.GetMultiply();


    [TestMethod]
    public void SatisfiedInstanceReturnsSatisfied()
    {
        using RawR1csInstance instance = R1csTestCircuits.BuildMultiplyCircuit();
        using RawR1csWitness witness = R1csTestCircuits.BuildMultiplyWitness(x: 3, y: 4);

        using R1csSatisfaction result = instance.CheckSatisfiedBy(witness, ScalarAdd, ScalarMul, SensitiveMemoryPool<byte>.Shared);

        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(result);
    }


    [TestMethod]
    public void UnsatisfiedInstanceReturnsViolated()
    {
        using RawR1csInstance instance = R1csTestCircuits.BuildMultiplyCircuit();
        using RawR1csWitness witness = R1csTestCircuits.BuildBrokenMultiplyWitness(x: 3, y: 4);

        using R1csSatisfaction result = instance.CheckSatisfiedBy(witness, ScalarAdd, ScalarMul, SensitiveMemoryPool<byte>.Shared);

        Assert.IsInstanceOfType<R1csSatisfaction.Violated>(result);
    }
}
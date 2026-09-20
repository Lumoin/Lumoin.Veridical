using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.ConstraintSystems;
using System;
using System.Globalization;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Tests for <see cref="R1csCircuitBuilder"/>: the operation sequence the
/// fold produces, the public-input contiguity rule, idempotent
/// <see cref="R1csCircuitBuilder.Build"/>, and the declaration/constraint
/// validation guards.
/// </summary>
[TestClass]
internal sealed class R1csCircuitBuilderTests
{
    /// <summary>The number of property-test samples <see cref="VariableCountMatchesDeclarationsPlusConstant"/> draws.</summary>
    private const int IterationCount = 500;
    /// <summary>The maximum number of public inputs or witness variables the property test declares in one sample.</summary>
    private const int MaxDeclarations = 5;


    /// <summary>Verifies that building a two-input multiplier circuit produces the exact expected operation sequence: the implicit constant-one declaration, each variable declaration in order, then the multiplication constraint, with the resulting variable and input counts matching.</summary>
    [TestMethod]
    public void BuildProducesTheMultiplier2OperationSequence()
    {
        var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
        R1csVariableIndex product = builder.DeclarePublicInput("product");
        R1csVariableIndex a = builder.DeclareWitnessVariable("a");
        R1csVariableIndex b = builder.DeclareWitnessVariable("b");
        builder.AddConstraint(a, b, product);

        R1csCircuit circuit = builder.Build();

        Assert.HasCount(5, circuit.Operations, "constant-one + 3 declarations + 1 constraint");
        Assert.IsInstanceOfType<DeclareConstantOneOp>(circuit.Operations[0]);
        Assert.AreEqual(new DeclarePublicInputOp(new R1csVariableIndex(1), "product"), circuit.Operations[1]);
        Assert.AreEqual(new DeclareWitnessVariableOp(new R1csVariableIndex(2), "a"), circuit.Operations[2]);
        Assert.AreEqual(new DeclareWitnessVariableOp(new R1csVariableIndex(3), "b"), circuit.Operations[3]);
        Assert.AreEqual(
            new AddConstraintOp(
                R1csLinearCombination.From(new R1csVariableIndex(2)),
                R1csLinearCombination.From(new R1csVariableIndex(3)),
                R1csLinearCombination.From(new R1csVariableIndex(1))),
            circuit.Operations[4]);

        Assert.AreEqual(4, circuit.VariableCount, "constant + product + a + b");
        Assert.AreEqual(1, circuit.PublicInputCount, "product");
        Assert.AreEqual(2, circuit.WitnessVariableCount, "a and b");
    }


    /// <summary>Verifies that declaring a public input after a witness variable throws, since public inputs must be contiguous at the front of the variable space.</summary>
    [TestMethod]
    public void DeclaringPublicInputAfterWitnessVariableThrows()
    {
        var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
        builder.DeclareWitnessVariable("a");

        InvalidOperationException error = Assert.ThrowsExactly<InvalidOperationException>(() => builder.DeclarePublicInput("late"));
        Assert.Contains("contiguous", error.Message, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>Verifies that declaring a public input after a constraint has been added throws, since public inputs must be contiguous at the front of the variable space.</summary>
    [TestMethod]
    public void DeclaringPublicInputAfterConstraintThrows()
    {
        var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
        R1csVariableIndex a = builder.DeclareWitnessVariable("a");
        builder.AddConstraint(a, a, a);

        Assert.ThrowsExactly<InvalidOperationException>(() => builder.DeclarePublicInput("late"));
    }


    /// <summary>Verifies that calling <see cref="R1csCircuitBuilder.Build"/> twice on the same builder returns equal circuits, since <c>Build</c> reads accumulated state without mutating it.</summary>
    [TestMethod]
    public void BuildIsIdempotent()
    {
        var builder = new R1csCircuitBuilder(CurveParameterSet.Bn254);
        R1csVariableIndex x = builder.DeclareWitnessVariable("x");
        builder.AddConstraint(x, x, x);

        Assert.AreEqual(builder.Build(), builder.Build(), "Build reads accumulated state and does not mutate it");
    }


    /// <summary>Verifies that declaring a second variable under a name already in use throws.</summary>
    [TestMethod]
    public void DuplicateVariableNameThrows()
    {
        var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
        builder.DeclareWitnessVariable("dup");

        Assert.ThrowsExactly<ArgumentException>(() => builder.DeclareWitnessVariable("dup"));
    }


    /// <summary>Verifies that adding a constraint whose linear combination references an undeclared variable index throws.</summary>
    [TestMethod]
    public void ConstraintReferencingUndeclaredVariableThrows()
    {
        var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
        R1csVariableIndex a = builder.DeclareWitnessVariable("a");

        //Index 7 was never declared.
        R1csLinearCombination undeclared = R1csLinearCombination.From(new R1csVariableIndex(7));
        Assert.ThrowsExactly<ArgumentException>(() => builder.AddConstraint(a, a, undeclared));
    }


    /// <summary>Verifies that declaring a variable with an empty name throws.</summary>
    [TestMethod]
    public void EmptyVariableNameThrows()
    {
        var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
        Assert.ThrowsExactly<ArgumentException>(() => builder.DeclareWitnessVariable(""));
    }


    /// <summary>Verifies, across randomly sampled public-input and witness-variable counts, that the built circuit's variable, public-input and witness counts always equal the declared counts (plus the implicit constant-one wire for the total).</summary>
    [TestMethod]
    public void VariableCountMatchesDeclarationsPlusConstant()
    {
        Gen.Select(Gen.Int[0, MaxDeclarations], Gen.Int[0, MaxDeclarations])
            .Sample(counts =>
            {
                (int publicCount, int witnessCount) = counts;
                var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
                for(int i = 0; i < publicCount; i++)
                {
                    builder.DeclarePublicInput("p" + i.ToString(CultureInfo.InvariantCulture));
                }

                for(int j = 0; j < witnessCount; j++)
                {
                    builder.DeclareWitnessVariable("w" + j.ToString(CultureInfo.InvariantCulture));
                }

                R1csCircuit circuit = builder.Build();
                return circuit.VariableCount == publicCount + witnessCount + 1
                    && circuit.PublicInputCount == publicCount
                    && circuit.WitnessVariableCount == witnessCount;
            }, iter: IterationCount);
    }
}

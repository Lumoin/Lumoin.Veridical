using CsCheck;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Tests.Algebraic;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Tests for <see cref="R1csCircuitTransformations.PowerOfTwoPadding"/>: it
/// rounds both axes up to a power of two (floored at 2 for Spartan's sumcheck),
/// preserves the public-input layout, appends only zero-weight rows and dummy
/// witness columns, is idempotent, and yields a circuit that still compiles to
/// a satisfied instance/witness pair.
/// </summary>
[TestClass]
internal sealed class R1csCircuitTransformationsTests
{
    private const int IterationCount = 300;
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;
    private static CurveParameterSet Curve => CurveParameterSet.Bls12Curve381;
    private static R1csLinearCombination One => R1csLinearCombination.FromConstant(BigInteger.One);


    [TestMethod]
    public void PaddingRoundsBothAxesToPowerOfTwoAndPreservesPublicInputs()
    {
        R1csCircuit padded = BuildPaddedThreeByFiveCircuit();

        //3 constraints -> 4 rows; 5 variables -> 8 columns.
        Assert.AreEqual(4, padded.Operations.Count(op => op is AddConstraintOp), "rows padded to 4");
        Assert.AreEqual(8, padded.VariableCount, "columns padded to 8");
        Assert.AreEqual(1, padded.PublicInputCount, "public-input count preserved");
        Assert.AreEqual(R1csVariableKind.PublicInput, padded.Variables[1].Kind, "public input stays at index 1");
        Assert.AreEqual(6, padded.WitnessVariableCount, "3 real witness + 3 padding witness");

        //The trailing constraint row is all-zero.
        AddConstraintOp last = padded.Operations.OfType<AddConstraintOp>().Last();
        Assert.AreEqual(R1csLinearCombination.Zero, last.Left, "padding row A is zero");
        Assert.AreEqual(R1csLinearCombination.Zero, last.Middle, "padding row B is zero");
        Assert.AreEqual(R1csLinearCombination.Zero, last.Right, "padding row C is zero");

        //The padding columns are intermediate variables under the reserved prefix.
        Assert.IsTrue(
            padded.Variables.Skip(5).All(v => v.Kind == R1csVariableKind.Intermediate && v.Name.StartsWith(R1csCircuitTransformations.PaddingWitnessNamePrefix, System.StringComparison.Ordinal)),
            "padding columns are reserved-prefix intermediates");
    }


    [TestMethod]
    public void PaddedCircuitCompilesToASatisfiedPair()
    {
        R1csCircuit padded = BuildPaddedThreeByFiveCircuit();

        var bindings = new Dictionary<string, BigInteger>(System.StringComparer.Ordinal)
        {
            ["p"] = 6,
            ["a"] = 2,
            ["b"] = 3,
            ["c"] = 6,
        };
        R1csPredicateWitness.AddPowerOfTwoPaddingBindings(bindings, padded);

        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = padded.Compile(new R1csCircuitInputs(bindings), Pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        Assert.AreEqual(4, instance.A.RowCount, "compiled row count");
        Assert.AreEqual(8, instance.A.ColumnCount, "compiled column count");

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(
            witness,
            Bls12Curve381BigIntegerScalarReference.GetAdd(),
            Bls12Curve381BigIntegerScalarReference.GetMultiply(),
            Pool);

        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction, "padded circuit is satisfied by its witness");
    }


    [TestMethod]
    public void PaddingIsIdempotent()
    {
        Gen.Select(Gen.Int[0, 6], Gen.Int[0, 6])
            .Sample(counts =>
            {
                (int witnessCount, int constraintCount) = counts;

                var builder = new R1csCircuitBuilder(Curve);
                for(int i = 0; i < witnessCount; i++)
                {
                    builder.DeclareWitnessVariable("w" + i.ToString(CultureInfo.InvariantCulture));
                }

                for(int j = 0; j < constraintCount; j++)
                {
                    builder.AddConstraint(R1csLinearCombination.Zero, R1csLinearCombination.Zero, R1csLinearCombination.Zero);
                }

                R1csCircuit once = R1csCircuitTransformations.PowerOfTwoPadding(builder.Build(), builder, builder.State);
                R1csCircuit twice = R1csCircuitTransformations.PowerOfTwoPadding(once, builder, builder.State);

                return once.Equals(twice);
            }, iter: IterationCount);
    }


    private static R1csCircuit BuildPaddedThreeByFiveCircuit()
    {
        //5 variables (constant + p + a + b + c), 3 constraints. Neither is a
        //power of two, so padding rounds to 8 columns and 4 rows.
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex p = builder.DeclarePublicInput("p");
        R1csVariableIndex a = builder.DeclareWitnessVariable("a");
        R1csVariableIndex b = builder.DeclareWitnessVariable("b");
        R1csVariableIndex c = builder.DeclareWitnessVariable("c");

        builder.AddConstraint(a, b, c);   //a · b = c
        builder.AddConstraint(a, b, p);   //a · b = p
        builder.AddConstraint(c, One, p); //c · 1 = p

        return builder.With(R1csCircuitTransformations.PowerOfTwoPadding).Build();
    }
}

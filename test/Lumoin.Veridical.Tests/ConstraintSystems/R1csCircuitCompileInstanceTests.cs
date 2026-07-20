using Lumoin.Base;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using System;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Gate for <see cref="R1csCircuitCompilation.CompileInstance"/> — the witness-free
/// path a verifier uses to reconstruct the public instance without the private
/// assignment. The load-bearing property is that the instance it builds from the
/// circuit structure plus the public inputs is byte-identical to the one
/// <see cref="R1csCircuitCompilation.Compile"/> builds from the full witness: only
/// then does a proof made against the prover's instance verify against the
/// verifier's reconstructed one.
/// </summary>
[TestClass]
internal sealed class R1csCircuitCompileInstanceTests
{
    private const string Recycled = "recycled_content";
    private const string Carbon = "carbon_footprint";
    private const string RecycledMinimum = "recycled_minimum";
    private static readonly CurveParameterSet Curve = CurveParameterSet.Bls12Curve381;
    private static readonly FixedPointDomain RecycledDomain = FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(1), 100.0m);
    private static readonly FixedPointDomain CarbonDomain = FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(2), 100.00m);


    [TestMethod]
    public void CompileInstanceReproducesCompiledMatricesForConstantBounds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (R1csCircuit circuit, SupplyChainClaim[] claims) = BuildConstantCircuit();

        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(BuildConstantInputs(circuit, claims, recycled: 32.5m, carbon: 11.20m), pool);
        using RawR1csInstance full = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using RawR1csInstance lean = circuit.CompileInstance(full.GetPublicInputsBytes(), pool);

        AssertInstancesMatch(full, lean);
        Assert.AreEqual(0, lean.PublicInputCount, "A constant-bound bundle reveals no public inputs.");
    }


    [TestMethod]
    public void CompileInstanceReproducesCompiledMatricesForPublicBound()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (R1csCircuit circuit, SupplyChainClaim[] claims, string boundVariable) = BuildPublicBoundCircuit();

        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(BuildPublicBoundInputs(circuit, claims, boundVariable, recycled: 32.5m), pool);
        using RawR1csInstance full = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using RawR1csInstance lean = circuit.CompileInstance(full.GetPublicInputsBytes(), pool);

        AssertInstancesMatch(full, lean);
        Assert.AreEqual(1, lean.PublicInputCount, "A public-input bound reveals exactly one public input.");
    }


    [TestMethod]
    public void CompileInstanceRejectsWrongPublicInputLength()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        (R1csCircuit circuit, SupplyChainClaim[] _) = BuildConstantCircuit();

        //The constant-bound circuit has no public inputs, so it expects zero public-input
        //bytes; one scalar's worth is the wrong length.
        byte[] oneScalar = new byte[Scalar.SizeBytes];

        Assert.ThrowsExactly<ArgumentException>(() =>
        {
            using RawR1csInstance _ = circuit.CompileInstance(oneScalar, pool);
        });
    }


    private static void AssertInstancesMatch(RawR1csInstance expected, RawR1csInstance actual)
    {
        Assert.AreEqual(expected.PublicInputCount, actual.PublicInputCount);
        Assert.IsTrue(expected.GetPublicInputsBytes().SequenceEqual(actual.GetPublicInputsBytes()), "Public inputs differ.");
        AssertMatrixMatch(expected.A, actual.A, "A");
        AssertMatrixMatch(expected.B, actual.B, "B");
        AssertMatrixMatch(expected.C, actual.C, "C");
    }


    private static void AssertMatrixMatch(R1csMatrix expected, R1csMatrix actual, string label)
    {
        Assert.AreEqual(expected.RowCount, actual.RowCount, $"{label} row count differs.");
        Assert.AreEqual(expected.ColumnCount, actual.ColumnCount, $"{label} column count differs.");
        Assert.IsTrue(expected.GetRowIndicesBytes().SequenceEqual(actual.GetRowIndicesBytes()), $"{label} row indices differ.");
        Assert.IsTrue(expected.GetColumnIndicesBytes().SequenceEqual(actual.GetColumnIndicesBytes()), $"{label} column indices differ.");
        Assert.IsTrue(expected.GetValuesBytes().SequenceEqual(actual.GetValuesBytes()), $"{label} values differ.");
    }


    private static (R1csCircuit Circuit, SupplyChainClaim[] Claims) BuildConstantCircuit()
    {
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex recycled = builder.DeclareWitnessVariable(Recycled);
        R1csVariableIndex carbon = builder.DeclareWitnessVariable(Carbon);
        SupplyChainClaim[] claims =
        [
            SupplyChainClaim.AtLeast(Recycled, recycled, FixedPointBound.Constant(RecycledDomain, 30.0m)),
            SupplyChainClaim.AtMost(Carbon, carbon, FixedPointBound.Constant(CarbonDomain, 12.50m)),
        ];
        builder.AssertBatteryPassport(claims);

        return (builder.With(R1csCircuitTransformations.PowerOfTwoPadding).Build(), claims);
    }


    private static R1csCircuitInputs BuildConstantInputs(R1csCircuit circuit, SupplyChainClaim[] claims, decimal recycled, decimal carbon)
    {
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        R1csSupplyChainWitness.AddBatteryPassportBindings(bindings, claims, name => Measure(name, recycled, carbon), Curve);
        R1csPredicateWitness.AddPowerOfTwoPaddingBindings(bindings, circuit);

        return new R1csCircuitInputs(bindings);
    }


    private static (R1csCircuit Circuit, SupplyChainClaim[] Claims, string BoundVariable) BuildPublicBoundCircuit()
    {
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex recycledMinimum = builder.DeclarePublicInput(RecycledMinimum);
        R1csVariableIndex recycled = builder.DeclareWitnessVariable(Recycled);
        SupplyChainClaim[] claims =
        [
            SupplyChainClaim.AtLeast(Recycled, recycled, FixedPointBound.PublicInput(RecycledDomain, 30.0m, recycledMinimum)),
        ];
        builder.AssertBatteryPassport(claims);

        return (builder.With(R1csCircuitTransformations.PowerOfTwoPadding).Build(), claims, RecycledMinimum);
    }


    private static R1csCircuitInputs BuildPublicBoundInputs(R1csCircuit circuit, SupplyChainClaim[] claims, string boundVariable, decimal recycled)
    {
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal)
        {
            [boundVariable] = RecycledDomain.Encode(30.0m),
        };
        R1csSupplyChainWitness.AddBatteryPassportBindings(bindings, claims, name => recycled, Curve);
        R1csPredicateWitness.AddPowerOfTwoPaddingBindings(bindings, circuit);

        return new R1csCircuitInputs(bindings);
    }


    private static decimal Measure(string name, decimal recycled, decimal carbon)
    {
        return name switch
        {
            Recycled => recycled,
            Carbon => carbon,
            _ => throw new KeyNotFoundException($"No measurement for claim '{name}'."),
        };
    }
}

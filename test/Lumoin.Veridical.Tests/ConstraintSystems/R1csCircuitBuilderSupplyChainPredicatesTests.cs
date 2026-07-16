using Lumoin.Veridical.Backends.Managed;
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
/// Compile-level tests for the named supply-chain predicates. Each has a
/// satisfying case (the circuit compiles and <c>CheckSatisfiedBy</c> agrees), a
/// non-satisfying case (rejected at compile time), and the boundary, over both a
/// constant bound and a public-input bound. Dedicated tests isolate the two
/// load-bearing range checks: a measured value bound near the field modulus is
/// rejected (but slips past a bare ordering check), and a public-input bound bound
/// out of its domain is rejected. Compilation's own satisfaction check is the
/// rejection mechanism, so "rejected" means <see cref="R1csCircuitCompilationException"/>.
/// </summary>
[TestClass]
internal sealed class R1csCircuitBuilderSupplyChainPredicatesTests
{
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;
    private static CurveParameterSet Curve => CurveParameterSet.Bls12Curve381;
    private static BigInteger Order => WellKnownCurves.GetScalarFieldOrder(Curve);
    private static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();

    private const string Recycled = "recycled";
    private const string Carbon = "carbon";
    private const string Threshold = "threshold";
    private const decimal RecycledThreshold = 30.0m;
    private const decimal CarbonCap = 12.50m;

    private static readonly FixedPointDomain RecycledDomain = FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(1), 100.0m);
    private static readonly FixedPointDomain CarbonDomain = FixedPointDomain.Create(FixedPointScale.OfFractionalDigits(2), 100.00m);
    private static readonly FixedPointBound RecycledFloor = FixedPointBound.Constant(RecycledDomain, RecycledThreshold);
    private static readonly FixedPointBound CarbonCeiling = FixedPointBound.Constant(CarbonDomain, CarbonCap);


    [TestMethod]
    public void AtLeastAcceptsAQuantityAboveTheThreshold()
    {
        AssertSatisfied(
            b => b.AssertQuantityAtLeast(b.DeclareWitnessVariable(Recycled), RecycledFloor, Recycled),
            bindings => R1csSupplyChainWitness.AddQuantityAtLeastBindings(bindings, Recycled, Recycled, RecycledFloor, 32.5m, Curve));
    }


    [TestMethod]
    public void AtLeastAcceptsTheThresholdItself()
    {
        AssertSatisfied(
            b => b.AssertQuantityAtLeast(b.DeclareWitnessVariable(Recycled), RecycledFloor, Recycled),
            bindings => R1csSupplyChainWitness.AddQuantityAtLeastBindings(bindings, Recycled, Recycled, RecycledFloor, 30.0m, Curve));
    }


    [TestMethod]
    public void AtLeastAcceptsTheDomainMaximum()
    {
        AssertSatisfied(
            b => b.AssertQuantityAtLeast(b.DeclareWitnessVariable(Recycled), RecycledFloor, Recycled),
            bindings => R1csSupplyChainWitness.AddQuantityAtLeastBindings(bindings, Recycled, Recycled, RecycledFloor, 100.0m, Curve));
    }


    [TestMethod]
    public void AtLeastRejectsAQuantityBelowTheThreshold()
    {
        AssertRejected(
            b => b.AssertQuantityAtLeast(b.DeclareWitnessVariable(Recycled), RecycledFloor, Recycled),
            bindings => R1csSupplyChainWitness.AddQuantityAtLeastBindings(bindings, Recycled, Recycled, RecycledFloor, 28.0m, Curve));
    }


    [TestMethod]
    public void AtMostAcceptsAQuantityBelowTheCap()
    {
        AssertSatisfied(
            b => b.AssertQuantityAtMost(b.DeclareWitnessVariable(Carbon), CarbonCeiling, Carbon),
            bindings => R1csSupplyChainWitness.AddQuantityAtMostBindings(bindings, Carbon, Carbon, CarbonCeiling, 11.20m, Curve));
    }


    [TestMethod]
    public void AtMostAcceptsTheCapItself()
    {
        AssertSatisfied(
            b => b.AssertQuantityAtMost(b.DeclareWitnessVariable(Carbon), CarbonCeiling, Carbon),
            bindings => R1csSupplyChainWitness.AddQuantityAtMostBindings(bindings, Carbon, Carbon, CarbonCeiling, 12.50m, Curve));
    }


    [TestMethod]
    public void AtMostRejectsAQuantityAboveTheCap()
    {
        AssertRejected(
            b => b.AssertQuantityAtMost(b.DeclareWitnessVariable(Carbon), CarbonCeiling, Carbon),
            bindings => R1csSupplyChainWitness.AddQuantityAtMostBindings(bindings, Carbon, Carbon, CarbonCeiling, 13.75m, Curve));
    }


    [TestMethod]
    public void AtLeastWithPublicInputThresholdAcceptsAboveThreshold()
    {
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex threshold = builder.DeclarePublicInput(Threshold);
        R1csVariableIndex measured = builder.DeclareWitnessVariable(Recycled);
        FixedPointBound bound = FixedPointBound.PublicInput(RecycledDomain, RecycledThreshold, threshold);
        builder.AssertQuantityAtLeast(measured, bound, Recycled);

        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal) { [Threshold] = bound.Encode() };
        R1csSupplyChainWitness.AddQuantityAtLeastBindings(bindings, Recycled, Recycled, bound, 32.5m, Curve);

        CheckSatisfied(builder.Build(), bindings);
    }


    [TestMethod]
    public void AtLeastWithPublicInputThresholdRejectsBelowThreshold()
    {
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex threshold = builder.DeclarePublicInput(Threshold);
        R1csVariableIndex measured = builder.DeclareWitnessVariable(Recycled);
        FixedPointBound bound = FixedPointBound.PublicInput(RecycledDomain, RecycledThreshold, threshold);
        builder.AssertQuantityAtLeast(measured, bound, Recycled);

        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal) { [Threshold] = bound.Encode() };
        R1csSupplyChainWitness.AddQuantityAtLeastBindings(bindings, Recycled, Recycled, bound, 28.0m, Curve);

        CheckRejected(builder.Build(), bindings);
    }


    [TestMethod]
    public void AtMostRejectsAMeasuredValueBoundNearTheModulus()
    {
        //A malicious prover binds the measured value to r - 1 (the field element
        //that reads as -1). The at-most ordering check alone would be fooled — see
        //BareLessThanOrEqualIsFooledByANearModulusValue — but the domain range
        //check the predicate adds cannot decompose r - 1 into the domain's bits,
        //so compilation rejects it.
        AssertRejected(
            b => b.AssertQuantityAtMost(b.DeclareWitnessVariable(Carbon), CarbonCeiling, Carbon),
            bindings =>
            {
                BigInteger nearModulus = Order - 1;
                BigInteger encodedCap = CarbonCeiling.Encode();
                bindings[Carbon] = nearModulus;
                R1csPredicateWitness.AddRangeCheckBits(bindings, $"{Carbon}_domain", nearModulus, CarbonDomain.Bits, Curve);
                R1csPredicateWitness.AddLessThanOrEqualBits(bindings, Carbon, nearModulus, encodedCap, CarbonDomain.Bits, Curve);
            });
    }


    [TestMethod]
    public void AtLeastRejectsAPublicInputBoundOutsideItsDomain()
    {
        //A public-input bound set near the field modulus would let a small measured
        //value clear the check (measured - bound reads as a small positive). The
        //predicate's range check on the public bound cannot decompose r - 1 into
        //the domain's bits, so compilation rejects it.
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex threshold = builder.DeclarePublicInput(Threshold);
        R1csVariableIndex measured = builder.DeclareWitnessVariable(Recycled);
        FixedPointBound bound = FixedPointBound.PublicInput(RecycledDomain, RecycledThreshold, threshold);
        builder.AssertQuantityAtLeast(measured, bound, Recycled);

        BigInteger nearModulus = Order - 1;
        BigInteger encodedMeasured = RecycledDomain.Encode(32.5m);
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal)
        {
            [Threshold] = nearModulus,
            [Recycled] = encodedMeasured,
        };
        R1csPredicateWitness.AddRangeCheckBits(bindings, $"{Recycled}_domain", encodedMeasured, RecycledDomain.Bits, Curve);
        R1csPredicateWitness.AddRangeCheckBits(bindings, $"{Recycled}_bound", nearModulus, RecycledDomain.Bits, Curve);
        R1csPredicateWitness.AddGreaterThanOrEqualBits(bindings, Recycled, encodedMeasured, nearModulus, RecycledDomain.Bits, Curve);

        CheckRejected(builder.Build(), bindings);
    }


    [TestMethod]
    public void BareLessThanOrEqualIsFooledByANearModulusValue()
    {
        //The primitive ordering check assumes small operands: cap - (r - 1) reduces
        //to cap + 1, a small positive that the range check accepts. This is the
        //soundness gap the supply-chain at-most predicate closes with its domain
        //range check (see AtMostRejectsAMeasuredValueBoundNearTheModulus).
        BigInteger encodedCap = CarbonCeiling.Encode();
        AssertSatisfied(
            b => b.AssertLessThanOrEqual(b.DeclareWitnessVariable(Carbon), encodedCap, CarbonDomain.Bits, Carbon),
            bindings =>
            {
                BigInteger nearModulus = Order - 1;
                bindings[Carbon] = nearModulus;
                R1csPredicateWitness.AddLessThanOrEqualBits(bindings, Carbon, nearModulus, encodedCap, CarbonDomain.Bits, Curve);
            });
    }


    [TestMethod]
    public void BatteryPassportAcceptsWhenEveryClaimHolds()
    {
        AssertSatisfied(BuildBundle, bindings => BindBundle(bindings, recycled: 32.5m, carbon: 11.20m));
    }


    [TestMethod]
    public void BatteryPassportRejectsWhenOneClaimFails()
    {
        //Recycled content passes but carbon exceeds the cap; the conjunction fails.
        AssertRejected(BuildBundle, bindings => BindBundle(bindings, recycled: 32.5m, carbon: 13.00m));
    }


    [TestMethod]
    public void AssertBatteryPassportRejectsAnEmptyBundle()
    {
        var builder = new R1csCircuitBuilder(Curve);

        Assert.ThrowsExactly<ArgumentException>(() => builder.AssertBatteryPassport(ReadOnlySpan<SupplyChainClaim>.Empty));
    }


    [TestMethod]
    public void AssertBatteryPassportRejectsDuplicateClaimNames()
    {
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex first = builder.DeclareWitnessVariable("a");
        R1csVariableIndex second = builder.DeclareWitnessVariable("b");
        SupplyChainClaim[] claims =
        [
            SupplyChainClaim.AtLeast(Recycled, first, RecycledFloor),
            SupplyChainClaim.AtMost(Recycled, second, CarbonCeiling),
        ];

        Assert.ThrowsExactly<ArgumentException>(() => builder.AssertBatteryPassport(claims));
    }


    [TestMethod]
    public void FixedPointBoundConstantRejectsAThresholdOutsideTheDomain()
    {
        //150% cannot be encoded in a [0, 100%] domain, so the bound cannot be built.
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => FixedPointBound.Constant(RecycledDomain, 150.0m));
    }


    [TestMethod]
    public void AtMostWithPublicInputCapRejectsAQuantityAboveTheCap()
    {
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex cap = builder.DeclarePublicInput("cap");
        R1csVariableIndex measured = builder.DeclareWitnessVariable(Carbon);
        FixedPointBound bound = FixedPointBound.PublicInput(CarbonDomain, CarbonCap, cap);
        builder.AssertQuantityAtMost(measured, bound, Carbon);

        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal) { ["cap"] = bound.Encode() };
        R1csSupplyChainWitness.AddQuantityAtMostBindings(bindings, Carbon, Carbon, bound, 13.75m, Curve);

        CheckRejected(builder.Build(), bindings);
    }


    [TestMethod]
    public void PublicInputBoundBoundToAValueOtherThanExpectedIsRejected()
    {
        //The witness's {name}_bound bits decompose the expected bound (30.0%), but
        //the caller binds the public input to a different in-domain value (40.0%).
        //The bound range check ties the bits to the variable, so the mismatch — even
        //though the measured value clears both thresholds — fails closed.
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex threshold = builder.DeclarePublicInput(Threshold);
        R1csVariableIndex measured = builder.DeclareWitnessVariable(Recycled);
        FixedPointBound bound = FixedPointBound.PublicInput(RecycledDomain, RecycledThreshold, threshold);
        builder.AssertQuantityAtLeast(measured, bound, Recycled);

        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal) { [Threshold] = RecycledDomain.Encode(40.0m) };
        R1csSupplyChainWitness.AddQuantityAtLeastBindings(bindings, Recycled, Recycled, bound, 50.0m, Curve);

        CheckRejected(builder.Build(), bindings);
    }


    [TestMethod]
    public void AssertBatteryPassportRejectsAReservedSuffixNameCollision()
    {
        //Distinct names, but one extends the other with a reserved auxiliary suffix
        //("carbon" and "carbon_domain" both reach "carbon_domain_bit_0"), so the
        //bundle rejects the pair up front rather than failing later on a clash.
        var builder = new R1csCircuitBuilder(Curve);
        R1csVariableIndex first = builder.DeclareWitnessVariable("a");
        R1csVariableIndex second = builder.DeclareWitnessVariable("b");
        SupplyChainClaim[] claims =
        [
            SupplyChainClaim.AtMost(Carbon, first, CarbonCeiling),
            SupplyChainClaim.AtLeast($"{Carbon}_domain", second, RecycledFloor),
        ];

        Assert.ThrowsExactly<ArgumentException>(() => builder.AssertBatteryPassport(claims));
    }


    private static void BuildBundle(R1csCircuitBuilder builder)
    {
        R1csVariableIndex recycled = builder.DeclareWitnessVariable(Recycled);
        R1csVariableIndex carbon = builder.DeclareWitnessVariable(Carbon);
        SupplyChainClaim[] claims =
        [
            SupplyChainClaim.AtLeast(Recycled, recycled, RecycledFloor),
            SupplyChainClaim.AtMost(Carbon, carbon, CarbonCeiling),
        ];
        builder.AssertBatteryPassport(claims);
    }


    private static void BindBundle(IDictionary<string, BigInteger> bindings, decimal recycled, decimal carbon)
    {
        R1csSupplyChainWitness.AddQuantityAtLeastBindings(bindings, Recycled, Recycled, RecycledFloor, recycled, Curve);
        R1csSupplyChainWitness.AddQuantityAtMostBindings(bindings, Carbon, Carbon, CarbonCeiling, carbon, Curve);
    }


    private static void AssertSatisfied(Action<R1csCircuitBuilder> configure, Action<Dictionary<string, BigInteger>> bind)
    {
        var builder = new R1csCircuitBuilder(Curve);
        configure(builder);
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        bind(bindings);

        CheckSatisfied(builder.Build(), bindings);
    }


    private static void AssertRejected(Action<R1csCircuitBuilder> configure, Action<Dictionary<string, BigInteger>> bind)
    {
        var builder = new R1csCircuitBuilder(Curve);
        configure(builder);
        var bindings = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        bind(bindings);

        CheckRejected(builder.Build(), bindings);
    }


    private static void CheckSatisfied(R1csCircuit circuit, Dictionary<string, BigInteger> bindings)
    {
        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(new R1csCircuitInputs(bindings), Pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, Add, Multiply, Pool);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction, "the compiled supply-chain circuit is satisfied by its witness");
    }


    private static void CheckRejected(R1csCircuit circuit, Dictionary<string, BigInteger> bindings)
    {
        Assert.ThrowsExactly<R1csCircuitCompilationException>(() => circuit.Compile(new R1csCircuitInputs(bindings), Pool));
    }
}

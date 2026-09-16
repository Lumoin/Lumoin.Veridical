using Lumoin.Veridical.Backends.Managed;
using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Diagnostics.Metrics;
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Tests for <c>R1csCircuit.Compile</c>: build a circuit with
/// <see cref="R1csCircuitBuilder"/>, compile it against input bindings, and
/// confirm the produced instance and witness satisfy the constraints and
/// prove-and-verify under Spartan, on both wired curves. Also covers the
/// compile-time guards (null arguments, an unwired curve, a missing input, a
/// circuit without constraints or without witness variables, a non-satisfying
/// assignment), the return of every pooled rental when a compilation fails
/// after its matrices exist, the summing of two contributions that meet on the
/// constant-one column, and the byte-for-byte agreement with the hand-crafted
/// reference circuit.
/// </summary>
[TestClass]
internal sealed class R1csCircuitCompilationTests
{
    /// <summary>The left factor of the multiply assignment most compilations in this class bind; the hand-crafted reference witness uses the same value.</summary>
    private const int LeftFactor = 3;

    /// <summary>The right factor of the multiply assignment most compilations in this class bind; the hand-crafted reference witness uses the same value.</summary>
    private const int RightFactor = 11;

    /// <summary>The product that satisfies the multiply constraint for <see cref="LeftFactor"/> and <see cref="RightFactor"/>.</summary>
    private const int Product = LeftFactor * RightFactor;

    /// <summary>One more than <see cref="Product"/>, so the multiply constraint does not hold.</summary>
    private const int WrongProduct = Product + 1;

    /// <summary>The left factor of the BN254 single-constraint assignment.</summary>
    private const int Bn254LeftFactor = 4;

    /// <summary>The right factor of the BN254 single-constraint assignment.</summary>
    private const int Bn254RightFactor = 5;

    /// <summary>The product that satisfies the multiply constraint for <see cref="Bn254LeftFactor"/> and <see cref="Bn254RightFactor"/>.</summary>
    private const int Bn254Product = Bn254LeftFactor * Bn254RightFactor;

    /// <summary>The left factor of the second assignment the reused circuit compiles against.</summary>
    private const int SecondLeftFactor = 6;

    /// <summary>The right factor of the second assignment the reused circuit compiles against.</summary>
    private const int SecondRightFactor = 7;

    /// <summary>The product that satisfies the multiply constraint for the second assignment.</summary>
    private const int SecondProduct = SecondLeftFactor * SecondRightFactor;

    /// <summary>The padded multiplier's row count: its multiply constraint and the one padding constraint that reaches the two-row floor.</summary>
    private const int PaddedMultiplierRowCount = 2;

    /// <summary>The padded multiplier's column count: the constant one, the public product and the two private factors.</summary>
    private const int PaddedMultiplierColumnCount = 4;

    /// <summary>The padded multiplier's public-input count: the product.</summary>
    private const int PaddedMultiplierPublicInputCount = 1;

    /// <summary>The padded multiplier's witness count: the two factors.</summary>
    private const int PaddedMultiplierWitnessCount = 2;

    /// <summary>The value both variables of the reduced identity constraint <c>x · 1 = y</c> take.</summary>
    private const int ReducedIdentityValue = 9;

    /// <summary>A zero right factor, with which an unbound product read as zero would satisfy the multiply constraint.</summary>
    private const int ZeroRightFactor = 0;

    /// <summary>The value bound to the witness <c>w</c> of the constraint-free circuit and of the identity circuit.</summary>
    private const int WitnessValue = 5;

    /// <summary>The value bound to the public input <c>p</c> of the witness-free circuit.</summary>
    private const int PublicInputValue = 7;

    /// <summary>The coefficient of the explicit term on the constant-one variable in the merged-coefficient constraint.</summary>
    private const int ExplicitConstantOneCoefficient = 4;

    /// <summary>The constant term of the merged-coefficient constraint, which compiles onto the constant-one column.</summary>
    private const int ConstantTerm = 3;

    /// <summary>The single constant-one coefficient that the explicit term and the constant term sum to.</summary>
    private const int MergedCoefficient = ExplicitConstantOneCoefficient + ConstantTerm;

    /// <summary>The value bound to <c>x</c> in the merged-coefficient constraint.</summary>
    private const int MergedFactor = 2;

    /// <summary>The value of <c>y</c> that satisfies the merged-coefficient constraint only when its coefficient is <see cref="MergedCoefficient"/>.</summary>
    private const int MergedProduct = MergedCoefficient * MergedFactor;

    /// <summary>The stored entry count of a matrix whose one row has one non-zero column.</summary>
    private const int SingleEntryCount = 1;

    /// <summary>The position of a matrix's first stored entry.</summary>
    private const int FirstEntryIndex = 0;

    /// <summary>A declared public-input or witness count that the identity circuit's one non-constant variable backs.</summary>
    private const int BackedDeclaredCount = 1;

    /// <summary>
    /// A declared public-input or witness count beyond what the identity circuit's variable list backs, so
    /// encoding that block of the assignment reads past its end.
    /// </summary>
    private const int OverstatedDeclaredCount = 2;

    /// <summary>
    /// Zero pool operations: the starting value of the rent and return counts, and the bound the rent count of a
    /// compilation that fails after building its matrices must exceed.
    /// </summary>
    private const long NoPoolOperations = 0;

    /// <summary>The name of the private meter whose pool operation counters the rental-return tests read.</summary>
    private const string PoolMeterName = nameof(R1csCircuitCompilationTests);

    /// <summary>The parameter name the null-circuit guard reports.</summary>
    private const string CircuitParameterName = "circuit";

    /// <summary>The parameter name the null-inputs guard reports.</summary>
    private const string InputsParameterName = "inputs";

    /// <summary>The parameter name the null-pool guard reports.</summary>
    private const string PoolParameterName = "pool";

    /// <summary>The parameter name the unwired-curve guard reports; the matrix scalar-size lookup reports the same name.</summary>
    private const string CurveParameterName = "curve";

    /// <summary>The wording only the unwired-curve guard uses; the matrix scalar-size lookup refuses the same curve in other words.</summary>
    private const string UnwiredCurveMessage = "is not wired";

    /// <summary>The wording of the constraint-count guard.</summary>
    private const string NoConstraintsMessage = "no constraints";

    /// <summary>The wording of the witness-count guard.</summary>
    private const string NoWitnessVariablesMessage = "no witness variables";

    /// <summary>The missing-input guard's wording for the multiply circuit's unbound product <c>z</c>.</summary>
    private const string UnboundProductMessage = "No input value bound for variable 'z'";


    /// <summary>The shared pool the compilations in this class rent from, except where a test builds a private pool to observe its rentals.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>Compiles the padded multiplier over BLS12-381 for a prover and a verifier and checks that a Spartan proof over it verifies.</summary>
    [TestMethod]
    public void Bls12Curve381PaddedMultiplier2ProvesAndVerifies()
    {
        R1csCircuit circuit = BuildPaddedMultiplier2(CurveParameterSet.Bls12Curve381);
        R1csCircuitInputs inputs = Inputs(("product", Product), ("a", LeftFactor), ("b", RightFactor));
        ProveAndVerify(circuit, inputs, PaddedMultiplierColumnCount, Bls12Curve381Backend);
    }


    /// <summary>Compiles the padded multiplier over BN254 for a prover and a verifier and checks that a Spartan proof over it verifies.</summary>
    [TestMethod]
    public void Bn254PaddedMultiplier2ProvesAndVerifies()
    {
        R1csCircuit circuit = BuildPaddedMultiplier2(CurveParameterSet.Bn254);
        R1csCircuitInputs inputs = Inputs(("product", Product), ("a", LeftFactor), ("b", RightFactor));
        ProveAndVerify(circuit, inputs, PaddedMultiplierColumnCount, Bn254Backend);
    }


    /// <summary>Compiles the multiply constraint over BLS12-381 and checks that the compiled witness satisfies the compiled instance.</summary>
    [TestMethod]
    public void Bls12Curve381SingleConstraintCompilesAndSatisfies()
    {
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bls12Curve381);
        CompileAndAssertSatisfied(circuit, Inputs(("x", LeftFactor), ("y", RightFactor), ("z", Product)), Bls12Curve381Backend);
    }


    /// <summary>Compiles the multiply constraint over BN254 and checks that the compiled witness satisfies the compiled instance.</summary>
    [TestMethod]
    public void Bn254SingleConstraintCompilesAndSatisfies()
    {
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bn254);
        CompileAndAssertSatisfied(circuit, Inputs(("x", Bn254LeftFactor), ("y", Bn254RightFactor), ("z", Bn254Product)), Bn254Backend);
    }


    /// <summary>Checks that the builder's multiply circuit compiles to the exact matrix and witness bytes of the hand-crafted reference circuit.</summary>
    [TestMethod]
    public void CompiledInstanceMatchesHandCraftedMultiplyCircuit()
    {
        //The builder circuit z = (1, x, y, z) with x·y = z must compile to the
        //exact bytes of the hand-crafted R1csTestCircuits.BuildMultiplyCircuit.
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bls12Curve381);
        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(Inputs(("x", LeftFactor), ("y", RightFactor), ("z", Product)), Pool);

        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;
        using RawR1csInstance reference = R1csTestCircuits.BuildMultiplyCircuit();
        using RawR1csWitness referenceWitness = R1csTestCircuits.BuildMultiplyWitness(LeftFactor, RightFactor);

        Assert.AreEqual(reference.PublicInputCount, instance.PublicInputCount, "public-input count");
        AssertMatricesEqual(reference.A, instance.A, "A");
        AssertMatricesEqual(reference.B, instance.B, "B");
        AssertMatricesEqual(reference.C, instance.C, "C");
        Assert.IsTrue(referenceWitness.GetWitnessBytes().SequenceEqual(witness.GetWitnessBytes()), "witness bytes match");
    }


    /// <summary>Rejects an assignment that leaves the product unbound, and the rejection names the unbound variable.</summary>
    [TestMethod]
    public void MissingInputThrows()
    {
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bls12Curve381);
        //'z' is not bound.
        R1csCircuitCompilationException error = Assert.ThrowsExactly<R1csCircuitCompilationException>(
            () => DisposeCompiled(circuit.Compile(Inputs(("x", LeftFactor), ("y", RightFactor)), Pool)));
        Assert.Contains(UnboundProductMessage, error.Message, StringComparison.Ordinal);
    }


    /// <summary>Rejects an assignment that does not satisfy the multiply constraint, and the rejection names the failing constraint.</summary>
    [TestMethod]
    public void NonSatisfyingAssignmentThrows()
    {
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bls12Curve381);
        //The bound product is one more than the factors multiply to.
        R1csCircuitCompilationException error = Assert.ThrowsExactly<R1csCircuitCompilationException>(
            () => DisposeCompiled(circuit.Compile(Inputs(("x", LeftFactor), ("y", RightFactor), ("z", WrongProduct)), Pool)));
        Assert.Contains("constraint", error.Message, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>Compiles one circuit against two different assignments, since a circuit is a statement reusable across assignments.</summary>
    [TestMethod]
    public void TheSameCircuitCompilesAgainstDifferentInputs()
    {
        //A circuit is reusable: the same statement proves many assignments.
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bls12Curve381);
        CompileAndAssertSatisfied(circuit, Inputs(("x", LeftFactor), ("y", RightFactor), ("z", Product)), Bls12Curve381Backend);
        CompileAndAssertSatisfied(circuit, Inputs(("x", SecondLeftFactor), ("y", SecondRightFactor), ("z", SecondProduct)), Bls12Curve381Backend);
    }


    /// <summary>Checks the padded multiplier's compiled row, column, public-input and witness counts.</summary>
    [TestMethod]
    public void CompiledWitnessAndInstanceHaveExpectedShape()
    {
        R1csCircuit circuit = BuildPaddedMultiplier2(CurveParameterSet.Bls12Curve381);
        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(Inputs(("product", Product), ("a", LeftFactor), ("b", RightFactor)), Pool);

        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        Assert.AreEqual(PaddedMultiplierRowCount, instance.A.RowCount, "two constraints");
        Assert.AreEqual(PaddedMultiplierColumnCount, instance.A.ColumnCount, "constant + product + a + b");
        Assert.AreEqual(PaddedMultiplierPublicInputCount, instance.PublicInputCount, "product is public");
        Assert.AreEqual(PaddedMultiplierWitnessCount, witness.WitnessVariableCount, "a and b are private");
    }


    /// <summary>Checks that a coefficient one above the field order reduces to one, so the compiled constraint is the identity <c>x · 1 = y</c>.</summary>
    [TestMethod]
    public void EmptyConstantCoefficientsReduceModuloField()
    {
        //A coefficient larger than the field order must reduce; -1 must become
        //r - 1. Build x · 1 = y with the constraint coefficient on x set to a
        //value that reduces to 1, and confirm satisfaction.
        var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
        R1csVariableIndex x = builder.DeclareWitnessVariable("x");
        R1csVariableIndex y = builder.DeclareWitnessVariable("y");
        BigInteger order = WellKnownCurves.GetScalarFieldOrder(CurveParameterSet.Bls12Curve381);

        //(order + 1)·x · 1 = y  reduces to x · 1 = y.
        R1csLinearCombination left = (order + BigInteger.One) * R1csLinearCombination.From(x);
        builder.AddConstraint(left, R1csLinearCombination.FromConstant(BigInteger.One), y);
        R1csCircuit circuit = builder.Build();

        CompileAndAssertSatisfied(circuit, Inputs(("x", ReducedIdentityValue), ("y", ReducedIdentityValue)), Bls12Curve381Backend);
    }


    /// <summary>
    /// Compile refuses a missing circuit, naming <c>circuit</c>. The inputs satisfy the multiply constraint and the
    /// pool is real, so no other guard can answer; without the circuit guard the first read of the circuit's curve
    /// would fail as a null dereference rather than as a caller fault.
    /// </summary>
    [TestMethod]
    public void CompileRejectsANullCircuit()
    {
        R1csCircuit absent = null!;
        R1csCircuitInputs inputs = Inputs(("x", LeftFactor), ("y", RightFactor), ("z", Product));

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(() => DisposeCompiled(absent.Compile(inputs, Pool)));

        Assert.AreEqual(CircuitParameterName, thrown.ParamName);
    }


    /// <summary>
    /// Compile refuses missing inputs, naming <c>inputs</c>. The circuit and the pool are real, so no other guard
    /// can answer; without the inputs guard the binding of the first non-constant variable would fail as a null
    /// dereference rather than as a caller fault.
    /// </summary>
    [TestMethod]
    public void CompileRejectsNullInputs()
    {
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bls12Curve381);

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(() => DisposeCompiled(circuit.Compile(null!, Pool)));

        Assert.AreEqual(InputsParameterName, thrown.ParamName);
    }


    /// <summary>
    /// Compile refuses a missing pool, naming <c>pool</c>. The inputs satisfy the multiply constraint, so neither
    /// the binding nor the satisfaction check can answer first, and the constraint's left side has a non-zero
    /// entry, so without the pool guard the first coefficient staging rental would fail as a null dereference
    /// before any callee's own pool check could name the parameter.
    /// </summary>
    [TestMethod]
    public void CompileRejectsANullPool()
    {
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bls12Curve381);
        R1csCircuitInputs inputs = Inputs(("x", LeftFactor), ("y", RightFactor), ("z", Product));

        ArgumentNullException thrown = Assert.ThrowsExactly<ArgumentNullException>(() => DisposeCompiled(circuit.Compile(inputs, null!)));

        Assert.AreEqual(PoolParameterName, thrown.ParamName);
    }


    /// <summary>
    /// Compile refuses a circuit over a curve without wired backends, which the public circuit constructor
    /// accepts. P-256 has a known scalar order, so without the wired-curve guard the order lookup would pass and
    /// the matrix scalar-size lookup would refuse the curve with the same exception type and parameter name; only
    /// the guard's wording tells the two refusals apart.
    /// </summary>
    [TestMethod]
    public void CompileRejectsACircuitOverAnUnwiredCurve()
    {
        R1csCircuit wired = BuildSingleMultiply(CurveParameterSet.Bls12Curve381);
        var unwired = new R1csCircuit(CurveParameterSet.P256, wired.Operations, wired.Variables, wired.PublicInputCount, wired.WitnessVariableCount);
        R1csCircuitInputs inputs = Inputs(("x", LeftFactor), ("y", RightFactor), ("z", Product));

        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(() => DisposeCompiled(unwired.Compile(inputs, Pool)));

        Assert.AreEqual(CurveParameterName, thrown.ParamName);
        Assert.Contains(UnwiredCurveMessage, thrown.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Compile refuses a circuit that declares a witness variable but no constraint, since an instance needs at
    /// least one row. The witness is declared and bound, so neither the binding nor the witness-count guard can
    /// answer; without the constraint-count guard the matrix build would refuse the zero row count with a
    /// different exception type.
    /// </summary>
    [TestMethod]
    public void CompileRejectsACircuitWithoutConstraints()
    {
        var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
        _ = builder.DeclareWitnessVariable("w");
        R1csCircuit circuit = builder.Build();
        R1csCircuitInputs inputs = Inputs(("w", WitnessValue));

        R1csCircuitCompilationException thrown = Assert.ThrowsExactly<R1csCircuitCompilationException>(() => DisposeCompiled(circuit.Compile(inputs, Pool)));

        Assert.Contains(NoConstraintsMessage, thrown.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Compile refuses a circuit whose only non-constant variable is a public input, since a provable instance
    /// needs at least one private variable. The input is bound, the circuit has a constraint, and
    /// <c>p · 1 = p</c> holds for every <c>p</c>, so neither the binding, the constraint-count guard nor the
    /// satisfaction check can answer; without the witness-count guard compilation would reach the zero-length
    /// witness staging rental, which the pool refuses with a different exception type.
    /// </summary>
    [TestMethod]
    public void CompileRejectsACircuitWithoutWitnessVariables()
    {
        var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
        R1csVariableIndex p = builder.DeclarePublicInput("p");
        builder.AddConstraint(p, R1csLinearCombination.FromConstant(BigInteger.One), p);
        R1csCircuit circuit = builder.Build();
        R1csCircuitInputs inputs = Inputs(("p", PublicInputValue));

        R1csCircuitCompilationException thrown = Assert.ThrowsExactly<R1csCircuitCompilationException>(() => DisposeCompiled(circuit.Compile(inputs, Pool)));

        Assert.Contains(NoWitnessVariablesMessage, thrown.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Compile names an unbound variable even when reading it as zero would satisfy the constraint. The right
    /// factor is zero, so a product read as zero passes the satisfaction check; only the missing-input guard can
    /// then refuse the assignment, and without it the compilation would succeed.
    /// </summary>
    [TestMethod]
    public void AMissingInputIsRejectedEvenWhenZeroWouldSatisfy()
    {
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bls12Curve381);
        R1csCircuitInputs inputs = Inputs(("x", LeftFactor), ("y", ZeroRightFactor));

        R1csCircuitCompilationException thrown = Assert.ThrowsExactly<R1csCircuitCompilationException>(() => DisposeCompiled(circuit.Compile(inputs, Pool)));

        Assert.Contains(UnboundProductMessage, thrown.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// A compilation that fails after building its three matrices, but before an instance owns them, returns
    /// every pooled rental. The circuit declares more public inputs than its variable list holds, so encoding the
    /// public inputs reads past the end of the assignment while the compilation itself still holds the matrices;
    /// the failure path must dispose each of them.
    /// </summary>
    [TestMethod]
    public void AFailureBeforeTheInstanceOwnsTheMatricesReturnsEveryRental()
    {
        AssertFailedCompilationReturnsEveryRental(OverstatedDeclaredCount, BackedDeclaredCount);
    }


    /// <summary>
    /// A compilation that fails after the instance has taken ownership of the matrices returns every pooled
    /// rental. The circuit declares more witness variables than its variable list holds, so the instance builds
    /// and encoding the witness then reads past the end of the assignment; the failure path must dispose the
    /// instance, which returns its public-input storage and the matrices it owns.
    /// </summary>
    [TestMethod]
    public void AFailureAfterTheInstanceOwnsTheMatricesReturnsEveryRental()
    {
        AssertFailedCompilationReturnsEveryRental(BackedDeclaredCount, OverstatedDeclaredCount);
    }


    /// <summary>
    /// An explicit term on the constant-one variable and a constant term land on the same column of one matrix
    /// row, and compilation sums them into the single coefficient <see cref="MergedCoefficient"/>. A linear
    /// combination already merges repeated variable terms, so this is the one way two contributions meet on a
    /// column. Storing anything but the sum, such as the difference of the two contributions, breaks the
    /// constraint for the assignment the sum admits, so both the stored value and the satisfaction check pin the
    /// sum.
    /// </summary>
    [TestMethod]
    public void AConstantTermMeetingAnExplicitConstantOneTermSumsIntoOneCoefficient()
    {
        var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
        R1csVariableIndex x = builder.DeclareWitnessVariable("x");
        R1csVariableIndex y = builder.DeclareWitnessVariable("y");
        R1csVariableIndex one = builder.VariableByName(R1csBuildState.ConstantOneName);
        R1csLinearCombination left = (ExplicitConstantOneCoefficient * R1csLinearCombination.From(one)) + R1csLinearCombination.FromConstant(ConstantTerm);
        builder.AddConstraint(left, x, y);
        R1csCircuit circuit = builder.Build();

        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(Inputs(("x", MergedFactor), ("y", MergedProduct)), Pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        Assert.AreEqual(SingleEntryCount, instance.A.NonzeroCount, "Both contributions must share one stored entry.");
        Assert.AreEqual(one.Value, instance.A.GetTriplePosition(FirstEntryIndex).Column, "The shared entry must sit on the constant-one column.");
        Assert.AreEqual(new BigInteger(MergedCoefficient), new BigInteger(instance.A.GetValueBytes(FirstEntryIndex), isUnsigned: true, isBigEndian: true), "The shared entry must hold the sum of the two contributions.");

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, Bls12Curve381Backend.Add, Bls12Curve381Backend.Multiply, Pool);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction, "The assignment the summed coefficient admits must satisfy the compiled instance.");
    }


    /// <summary>Builds the multiply circuit <c>x · y = z</c> with three witness variables and no public inputs.</summary>
    /// <param name="curve">The wired curve to build over.</param>
    /// <returns>The built circuit.</returns>
    private static R1csCircuit BuildSingleMultiply(CurveParameterSet curve)
    {
        //z = (1, x, y, z): x · y = z, no public inputs. Matches
        //R1csTestCircuits.BuildMultiplyCircuit's variable ordering.
        var builder = new R1csCircuitBuilder(curve);
        R1csVariableIndex x = builder.DeclareWitnessVariable("x");
        R1csVariableIndex y = builder.DeclareWitnessVariable("y");
        R1csVariableIndex z = builder.DeclareWitnessVariable("z");
        builder.AddConstraint(x, y, z);

        return builder.Build();
    }


    /// <summary>Builds the multiplier with a public product and two private factors, padded to power-of-two dimensions.</summary>
    /// <param name="curve">The wired curve to build over.</param>
    /// <returns>The padded circuit.</returns>
    private static R1csCircuit BuildPaddedMultiplier2(CurveParameterSet curve)
    {
        //product public, a·b = product, padded to power-of-two dimensions via
        //the transformation rather than a hand-added padding constraint.
        var builder = new R1csCircuitBuilder(curve);
        R1csVariableIndex product = builder.DeclarePublicInput("product");
        R1csVariableIndex a = builder.DeclareWitnessVariable("a");
        R1csVariableIndex b = builder.DeclareWitnessVariable("b");
        builder.AddConstraint(a, b, product);

        return builder.With(R1csCircuitTransformations.PowerOfTwoPadding).Build();
    }


    /// <summary>
    /// Builds the one-constraint identity circuit <c>w · 1 = w</c> over BLS12-381. Its variable list holds the
    /// constant one and the witness <c>w</c>, so its assignment has room for one non-constant variable.
    /// </summary>
    /// <returns>The built circuit.</returns>
    private static R1csCircuit BuildIdentityCircuit()
    {
        var builder = new R1csCircuitBuilder(CurveParameterSet.Bls12Curve381);
        R1csVariableIndex w = builder.DeclareWitnessVariable("w");
        builder.AddConstraint(w, R1csLinearCombination.FromConstant(BigInteger.One), w);

        return builder.Build();
    }


    /// <summary>Compiles a circuit and checks that the compiled witness satisfies the compiled instance.</summary>
    /// <param name="circuit">The circuit to compile.</param>
    /// <param name="inputs">The satisfying input bindings.</param>
    /// <param name="backend">The backends of the circuit's curve.</param>
    private static void CompileAndAssertSatisfied(R1csCircuit circuit, R1csCircuitInputs inputs, SpartanBackend backend)
    {
        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(inputs, Pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, backend.Add, backend.Multiply, Pool);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction, "compiled instance is satisfied by its witness");
    }


    /// <summary>
    /// Compiles <see cref="BuildIdentityCircuit"/> re-declared with the supplied public-input and witness counts
    /// against a private pool, expects the out-of-range assignment read that an overstated count causes, and
    /// checks that the pool recorded one return for every rent. The counts come from the pool's own rent and
    /// return operation counters, read through a listener bound to the pool's private meter, so the check holds
    /// however the pool groups its segments into slabs. The pool creates its counters on the meter it is given,
    /// the listener enables only instruments of the meter this call creates, and only this call's compilation
    /// rents from that pool, so pools of tests running in parallel never reach the counts.
    /// </summary>
    /// <param name="publicInputCount">The public-input count the re-declared circuit states.</param>
    /// <param name="witnessVariableCount">The witness count the re-declared circuit states.</param>
    private static void AssertFailedCompilationReturnsEveryRental(int publicInputCount, int witnessVariableCount)
    {
        using var meter = new Meter(PoolMeterName);
        using var listener = new MeterListener();
        long rents = NoPoolOperations;
        long returns = NoPoolOperations;
        listener.InstrumentPublished = (instrument, observer) =>
        {
            if(ReferenceEquals(instrument.Meter, meter))
            {
                observer.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, measurement, tags, state) =>
        {
            if(instrument.Name == BaseMemoryPoolMetrics.BaseMemoryPoolRentOperationsTotal)
            {
                rents += measurement;
            }
            else if(instrument.Name == BaseMemoryPoolMetrics.BaseMemoryPoolReturnOperationsTotal)
            {
                returns += measurement;
            }
        });
        listener.Start();
        using BaseMemoryPool pool = new(meter);

        R1csCircuit consistent = BuildIdentityCircuit();
        var inconsistent = new R1csCircuit(consistent.Curve, consistent.Operations, consistent.Variables, publicInputCount, witnessVariableCount);
        R1csCircuitInputs inputs = Inputs(("w", WitnessValue));

        _ = Assert.ThrowsExactly<IndexOutOfRangeException>(() => DisposeCompiled(inconsistent.Compile(inputs, pool)));

        Assert.IsGreaterThan(NoPoolOperations, rents, "The failing compilation must have rented pooled storage before it failed.");
        Assert.AreEqual(rents, returns, "A compilation that fails after building its matrices must return every rental to its pool.");
    }


    /// <summary>
    /// Disposes both halves of a compilation result. The rejection tests pass their compilation through this, so
    /// a compilation that returns instead of throwing still gives its pooled storage back.
    /// </summary>
    /// <param name="compiled">The instance and witness the compilation returned.</param>
    private static void DisposeCompiled((RawR1csInstance Instance, RawR1csWitness Witness) compiled)
    {
        compiled.Instance.Dispose();
        compiled.Witness.Dispose();
    }


    /// <summary>Compiles the circuit for a prover and a verifier, proves the prover's instance under Spartan and checks that the verifier accepts the proof.</summary>
    /// <param name="circuit">The circuit to compile.</param>
    /// <param name="inputs">The satisfying input bindings.</param>
    /// <param name="columnCount">The circuit's power-of-two column count, which sizes the commitment key.</param>
    /// <param name="backend">The backends of the circuit's curve.</param>
    [SuppressMessage("Reliability", "CA2000", Justification = "Instances, witnesses, prover, verifier, and transcripts are disposed via using declarations before the assertion completes.")]
    private static void ProveAndVerify(R1csCircuit circuit, R1csCircuitInputs inputs, int columnCount, SpartanBackend backend)
    {
        int hyraxVectorLength = HyraxCommitmentDimensions
            .ForVariableCount(System.Numerics.BitOperations.Log2((uint)columnCount))
            .ColumnCount;

        using SpartanProver prover = BuildProver(hyraxVectorLength, backend);
        using SpartanVerifier verifier = BuildVerifier(hyraxVectorLength, backend);

        (RawR1csInstance Instance, RawR1csWitness Witness) proverCompiled = circuit.Compile(inputs, Pool);
        using RawR1csInstance proverInstance = proverCompiled.Instance;
        using RawR1csWitness witness = proverCompiled.Witness;

        (RawR1csInstance Instance, RawR1csWitness Witness) verifierCompiled = circuit.Compile(inputs, Pool);
        using RawR1csInstance verifierInstance = verifierCompiled.Instance;
        using RawR1csWitness spareWitness = verifierCompiled.Witness;

        using FiatShamirTranscript proverTranscript = FreshTranscript(backend);
        using SpartanProof proof = prover.Prove(
            proverInstance, witness, proverTranscript,
            backend.Hash, backend.Squeeze, backend.Reduce, backend.Add, backend.Subtract, backend.Multiply, backend.Invert, backend.Random,
            backend.G1Add, backend.G1ScalarMul, backend.G1Msm, backend.MleEvaluate, backend.MleFold, Pool);

        using FiatShamirTranscript verifierTranscript = FreshTranscript(backend);
        bool verified = verifier.Verify(
            proof, verifierInstance, verifierTranscript,
            backend.Add, backend.Multiply, backend.Subtract, backend.Invert, backend.Reduce,
            backend.G1Add, backend.G1ScalarMul, backend.G1Msm, backend.Hash, backend.Squeeze, Pool);

        Assert.IsTrue(verified, $"Spartan verification failed for a compiled circuit over {circuit.Curve}.");
    }


    /// <summary>Builds a Spartan prover over a Hyrax commitment key of the supplied vector length.</summary>
    /// <param name="hyraxVectorLength">The vector length of the commitment key.</param>
    /// <param name="backend">The backends of the prover's curve.</param>
    /// <returns>The prover, which owns the key.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver via its constructor chain.")]
    private static SpartanProver BuildProver(int hyraxVectorLength, SpartanBackend backend)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            hyraxVectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1, backend.Curve, backend.HashToCurve, Pool);

        return new SpartanProver(new SpartanProvingKey(BuildProvider(commitmentKey, backend)));
    }


    /// <summary>Builds a Spartan verifier over a Hyrax commitment key of the supplied vector length.</summary>
    /// <param name="hyraxVectorLength">The vector length of the commitment key.</param>
    /// <param name="backend">The backends of the verifier's curve.</param>
    /// <returns>The verifier, which owns the key.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanVerifier via its constructor chain.")]
    private static SpartanVerifier BuildVerifier(int hyraxVectorLength, SpartanBackend backend)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            hyraxVectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1, backend.Curve, backend.HashToCurve, Pool);

        return new SpartanVerifier(new SpartanVerifyingKey(BuildProvider(commitmentKey, backend)));
    }


    /// <summary>Creates the Hyrax commitment provider and transfers ownership of the supplied key to it.</summary>
    /// <param name="commitmentKey">The key the provider takes ownership of.</param>
    /// <param name="backend">The backends of the key's curve.</param>
    /// <returns>The provider.</returns>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey, SpartanBackend backend)
    {
        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            backend.Curve,
            backend.Hash, backend.Squeeze, backend.Reduce, backend.Add, backend.Subtract, backend.Multiply, backend.Invert, backend.Random,
            backend.G1Add, backend.G1ScalarMul, backend.G1Msm, backend.G1IsOnCurve, backend.G1IsInPrimeOrderSubgroup,
            ownsKey: true);
    }


    /// <summary>Creates a fresh BLAKE3 transcript under the Spartan protocol domain.</summary>
    /// <param name="backend">The backends whose transcript hash the transcript uses.</param>
    /// <returns>The transcript, which the caller disposes.</returns>
    private static FiatShamirTranscript FreshTranscript(SpartanBackend backend)
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, backend.Hash, Pool);
    }


    /// <summary>Checks that two matrices have the same shape and the same row, column and value bytes.</summary>
    /// <param name="expected">The reference matrix.</param>
    /// <param name="actual">The compiled matrix.</param>
    /// <param name="label">The matrix name the assertion messages carry.</param>
    private static void AssertMatricesEqual(R1csMatrix expected, R1csMatrix actual, string label)
    {
        Assert.AreEqual(expected.RowCount, actual.RowCount, $"{label}.RowCount");
        Assert.AreEqual(expected.ColumnCount, actual.ColumnCount, $"{label}.ColumnCount");
        Assert.AreEqual(expected.NonzeroCount, actual.NonzeroCount, $"{label}.NonzeroCount");
        Assert.IsTrue(expected.GetRowIndicesBytes().SequenceEqual(actual.GetRowIndicesBytes()), $"{label} row indices");
        Assert.IsTrue(expected.GetColumnIndicesBytes().SequenceEqual(actual.GetColumnIndicesBytes()), $"{label} column indices");
        Assert.IsTrue(expected.GetValuesBytes().SequenceEqual(actual.GetValuesBytes()), $"{label} values");
    }


    /// <summary>Wraps variable names and their values as circuit input bindings.</summary>
    /// <param name="pairs">The variable names and the values bound to them.</param>
    /// <returns>The input bindings.</returns>
    private static R1csCircuitInputs Inputs(params (string Name, int Value)[] pairs)
    {
        var dictionary = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        foreach((string Name, int Value) pair in pairs)
        {
            dictionary[pair.Name] = new BigInteger(pair.Value);
        }

        return new R1csCircuitInputs(dictionary);
    }


    /// <summary>The BLS12-381 backends: BLAKE3 transcripts, the BigInteger scalar, G1 and multilinear references, and the test multiscalar multiplication.</summary>
    private static SpartanBackend Bls12Curve381Backend { get; } = new(
        CurveParameterSet.Bls12Curve381,
        FiatShamirBlake3Reference.GetHash(),
        FiatShamirBlake3Reference.GetSqueeze(),
        Bls12Curve381BigIntegerScalarReference.GetReduce(),
        Bls12Curve381BigIntegerScalarReference.GetAdd(),
        Bls12Curve381BigIntegerScalarReference.GetSubtract(),
        Bls12Curve381BigIntegerScalarReference.GetMultiply(),
        Bls12Curve381BigIntegerScalarReference.GetInvert(),
        Bls12Curve381BigIntegerScalarReference.GetRandom(),
        Bls12Curve381BigIntegerG1Reference.GetAdd(),
        Bls12Curve381BigIntegerG1Reference.GetScalarMultiply(),
        TestG1Backends.Bls12Curve381Msm,
        Bls12Curve381BigIntegerG1Reference.GetIsOnCurve(),
        Bls12Curve381BigIntegerG1Reference.GetIsInPrimeOrderSubgroup(),
        Bls12Curve381BigIntegerG1Reference.GetHashToCurve(),
        MultilinearExtensionBigIntegerReference.GetEvaluate(),
        MultilinearExtensionBigIntegerReference.GetFold());


    /// <summary>The BN254 backends: BLAKE3 transcripts, the BigInteger scalar, G1 and multilinear references, and the test multiscalar multiplication.</summary>
    private static SpartanBackend Bn254Backend { get; } = new(
        CurveParameterSet.Bn254,
        FiatShamirBlake3Reference.GetHash(),
        FiatShamirBlake3Reference.GetSqueeze(),
        Bn254BigIntegerScalarReference.GetReduce(),
        Bn254BigIntegerScalarReference.GetAdd(),
        Bn254BigIntegerScalarReference.GetSubtract(),
        Bn254BigIntegerScalarReference.GetMultiply(),
        Bn254BigIntegerScalarReference.GetInvert(),
        Bn254BigIntegerScalarReference.GetRandom(),
        Bn254BigIntegerG1Reference.GetAdd(),
        Bn254BigIntegerG1Reference.GetScalarMultiply(),
        TestG1Backends.Bn254Msm,
        Bn254BigIntegerG1Reference.GetIsOnCurve(),
        Bn254BigIntegerG1Reference.GetIsInPrimeOrderSubgroup(),
        Bn254BigIntegerG1Reference.GetHashToCurve(),
        MultilinearExtensionBigIntegerReference.GetEvaluate(),
        MultilinearExtensionBigIntegerReference.GetFold());


    /// <summary>The curve and the backend delegates that one compile, prove and verify run over that curve uses.</summary>
    /// <param name="Curve">The curve the backends operate over.</param>
    /// <param name="Hash">The transcript hash.</param>
    /// <param name="Squeeze">The transcript squeeze.</param>
    /// <param name="Reduce">Scalar reduction.</param>
    /// <param name="Add">Scalar addition.</param>
    /// <param name="Subtract">Scalar subtraction.</param>
    /// <param name="Multiply">Scalar multiplication.</param>
    /// <param name="Invert">Scalar inversion.</param>
    /// <param name="Random">Random scalar generation.</param>
    /// <param name="G1Add">G1 addition.</param>
    /// <param name="G1ScalarMul">G1 scalar multiplication.</param>
    /// <param name="G1Msm">G1 multiscalar multiplication.</param>
    /// <param name="G1IsOnCurve">G1 curve membership.</param>
    /// <param name="G1IsInPrimeOrderSubgroup">G1 prime-order subgroup membership.</param>
    /// <param name="HashToCurve">Hashing to G1, which derives the commitment generators.</param>
    /// <param name="MleEvaluate">Multilinear extension evaluation.</param>
    /// <param name="MleFold">Multilinear extension folding.</param>
    private sealed record SpartanBackend(
        CurveParameterSet Curve,
        FiatShamirHashDelegate Hash,
        FiatShamirSqueezeDelegate Squeeze,
        ScalarReduceDelegate Reduce,
        ScalarAddDelegate Add,
        ScalarSubtractDelegate Subtract,
        ScalarMultiplyDelegate Multiply,
        ScalarInvertDelegate Invert,
        ScalarRandomDelegate Random,
        G1AddDelegate G1Add,
        G1ScalarMultiplyDelegate G1ScalarMul,
        G1MultiScalarMultiplyDelegate G1Msm,
        G1IsOnCurveDelegate G1IsOnCurve,
        G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup,
        G1HashToCurveDelegate HashToCurve,
        MleEvaluateDelegate MleEvaluate,
        MleFoldDelegate MleFold);
}

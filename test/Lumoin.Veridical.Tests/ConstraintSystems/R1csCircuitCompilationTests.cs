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
using System.Numerics;

namespace Lumoin.Veridical.Tests.ConstraintSystems;

/// <summary>
/// Tests for <c>R1csCircuit.Compile</c>: build a circuit with
/// <see cref="R1csCircuitBuilder"/>, compile it against input bindings, and
/// confirm the produced instance and witness satisfy the constraints and
/// prove-and-verify under Spartan, on both wired curves. Also covers the
/// compile-time guards (missing input, non-satisfying assignment) and the
/// byte-for-byte agreement with the hand-crafted reference circuit.
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

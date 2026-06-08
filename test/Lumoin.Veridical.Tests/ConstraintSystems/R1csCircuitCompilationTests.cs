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
    private static SensitiveMemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;


    [TestMethod]
    public void Bls12Curve381PaddedMultiplier2ProvesAndVerifies()
    {
        R1csCircuit circuit = BuildPaddedMultiplier2(CurveParameterSet.Bls12Curve381);
        R1csCircuitInputs inputs = Inputs(("product", 33), ("a", 3), ("b", 11));
        ProveAndVerify(circuit, inputs, columnCount: 4, Bls12Curve381Backend);
    }


    [TestMethod]
    public void Bn254PaddedMultiplier2ProvesAndVerifies()
    {
        R1csCircuit circuit = BuildPaddedMultiplier2(CurveParameterSet.Bn254);
        R1csCircuitInputs inputs = Inputs(("product", 33), ("a", 3), ("b", 11));
        ProveAndVerify(circuit, inputs, columnCount: 4, Bn254Backend);
    }


    [TestMethod]
    public void Bls12Curve381SingleConstraintCompilesAndSatisfies()
    {
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bls12Curve381);
        CompileAndAssertSatisfied(circuit, Inputs(("x", 3), ("y", 11), ("z", 33)), Bls12Curve381Backend);
    }


    [TestMethod]
    public void Bn254SingleConstraintCompilesAndSatisfies()
    {
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bn254);
        CompileAndAssertSatisfied(circuit, Inputs(("x", 4), ("y", 5), ("z", 20)), Bn254Backend);
    }


    [TestMethod]
    public void CompiledInstanceMatchesHandCraftedMultiplyCircuit()
    {
        //The builder circuit z = (1, x, y, z) with x·y = z must compile to the
        //exact bytes of the hand-crafted R1csTestCircuits.BuildMultiplyCircuit.
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bls12Curve381);
        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(Inputs(("x", 3), ("y", 11), ("z", 33)), Pool);

        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;
        using RawR1csInstance reference = R1csTestCircuits.BuildMultiplyCircuit();
        using RawR1csWitness referenceWitness = R1csTestCircuits.BuildMultiplyWitness(3, 11);

        Assert.AreEqual(reference.PublicInputCount, instance.PublicInputCount, "public-input count");
        AssertMatricesEqual(reference.A, instance.A, "A");
        AssertMatricesEqual(reference.B, instance.B, "B");
        AssertMatricesEqual(reference.C, instance.C, "C");
        Assert.IsTrue(referenceWitness.GetWitnessBytes().SequenceEqual(witness.GetWitnessBytes()), "witness bytes match");
    }


    [TestMethod]
    public void MissingInputThrows()
    {
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bls12Curve381);
        //'z' is not bound.
        R1csCircuitCompilationException error = Assert.ThrowsExactly<R1csCircuitCompilationException>(
            () => circuit.Compile(Inputs(("x", 3), ("y", 11)), Pool));
        Assert.Contains("z", error.Message, StringComparison.Ordinal);
    }


    [TestMethod]
    public void NonSatisfyingAssignmentThrows()
    {
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bls12Curve381);
        //3 · 11 = 33, not 34.
        R1csCircuitCompilationException error = Assert.ThrowsExactly<R1csCircuitCompilationException>(
            () => circuit.Compile(Inputs(("x", 3), ("y", 11), ("z", 34)), Pool));
        Assert.Contains("constraint", error.Message, StringComparison.OrdinalIgnoreCase);
    }


    [TestMethod]
    public void TheSameCircuitCompilesAgainstDifferentInputs()
    {
        //A circuit is reusable: the same statement proves many assignments.
        R1csCircuit circuit = BuildSingleMultiply(CurveParameterSet.Bls12Curve381);
        CompileAndAssertSatisfied(circuit, Inputs(("x", 3), ("y", 11), ("z", 33)), Bls12Curve381Backend);
        CompileAndAssertSatisfied(circuit, Inputs(("x", 6), ("y", 7), ("z", 42)), Bls12Curve381Backend);
    }


    [TestMethod]
    public void CompiledWitnessAndInstanceHaveExpectedShape()
    {
        R1csCircuit circuit = BuildPaddedMultiplier2(CurveParameterSet.Bls12Curve381);
        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(Inputs(("product", 33), ("a", 3), ("b", 11)), Pool);

        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        Assert.AreEqual(2, instance.A.RowCount, "two constraints");
        Assert.AreEqual(4, instance.A.ColumnCount, "constant + product + a + b");
        Assert.AreEqual(1, instance.PublicInputCount, "product is public");
        Assert.AreEqual(2, witness.WitnessVariableCount, "a and b are private");
    }


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

        CompileAndAssertSatisfied(circuit, Inputs(("x", 9), ("y", 9)), Bls12Curve381Backend);
    }


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


    private static void CompileAndAssertSatisfied(R1csCircuit circuit, R1csCircuitInputs inputs, SpartanBackend backend)
    {
        (RawR1csInstance Instance, RawR1csWitness Witness) compiled = circuit.Compile(inputs, Pool);
        using RawR1csInstance instance = compiled.Instance;
        using RawR1csWitness witness = compiled.Witness;

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, backend.Add, backend.Multiply, Pool);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction, "compiled instance is satisfied by its witness");
    }


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


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver via its constructor chain.")]
    private static SpartanProver BuildProver(int hyraxVectorLength, SpartanBackend backend)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            hyraxVectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1, backend.Curve, backend.HashToCurve, Pool);
        return new SpartanProver(new SpartanProvingKey(BuildProvider(commitmentKey, backend)));
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanVerifier via its constructor chain.")]
    private static SpartanVerifier BuildVerifier(int hyraxVectorLength, SpartanBackend backend)
    {
        HyraxCommitmentKey commitmentKey = HyraxCommitmentKey.Derive(
            hyraxVectorLength, WellKnownHyraxDomainLabels.CanonicalSeedV1, backend.Curve, backend.HashToCurve, Pool);
        return new SpartanVerifier(new SpartanVerifyingKey(BuildProvider(commitmentKey, backend)));
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey, SpartanBackend backend)
    {
        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            backend.Curve,
            backend.Hash, backend.Squeeze, backend.Reduce, backend.Add, backend.Subtract, backend.Multiply, backend.Invert, backend.Random,
            backend.G1Add, backend.G1ScalarMul, backend.G1Msm,
            ownsKey: true);
    }


    private static FiatShamirTranscript FreshTranscript(SpartanBackend backend)
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, backend.Hash, Pool);
    }


    private static void AssertMatricesEqual(R1csMatrix expected, R1csMatrix actual, string label)
    {
        Assert.AreEqual(expected.RowCount, actual.RowCount, $"{label}.RowCount");
        Assert.AreEqual(expected.ColumnCount, actual.ColumnCount, $"{label}.ColumnCount");
        Assert.AreEqual(expected.NonzeroCount, actual.NonzeroCount, $"{label}.NonzeroCount");
        Assert.IsTrue(expected.GetRowIndicesBytes().SequenceEqual(actual.GetRowIndicesBytes()), $"{label} row indices");
        Assert.IsTrue(expected.GetColumnIndicesBytes().SequenceEqual(actual.GetColumnIndicesBytes()), $"{label} column indices");
        Assert.IsTrue(expected.GetValuesBytes().SequenceEqual(actual.GetValuesBytes()), $"{label} values");
    }


    private static R1csCircuitInputs Inputs(params (string Name, int Value)[] pairs)
    {
        var dictionary = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
        foreach((string Name, int Value) pair in pairs)
        {
            dictionary[pair.Name] = new BigInteger(pair.Value);
        }

        return new R1csCircuitInputs(dictionary);
    }


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
        Bls12Curve381BigIntegerG1Reference.GetHashToCurve(),
        MultilinearExtensionBigIntegerReference.GetEvaluate(),
        MultilinearExtensionBigIntegerReference.GetFold());


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
        Bn254BigIntegerG1Reference.GetHashToCurve(),
        MultilinearExtensionBigIntegerReference.GetEvaluate(),
        MultilinearExtensionBigIntegerReference.GetFold());


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
        G1HashToCurveDelegate HashToCurve,
        MleEvaluateDelegate MleEvaluate,
        MleFoldDelegate MleFold);
}

using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.ConstraintSystems.Interop;
using Lumoin.Veridical.Core.ConstraintSystems.Interop.ZkInterface;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Pipelines;
using System.Numerics;
using System.Threading;

namespace Lumoin.Veridical.Tests.ConstraintSystems.Interop.ZkInterface;

/// <summary>
/// Real-fixture gate: owned <c>.zkif</c> files produced by the canonical
/// <c>zkinterface</c> Rust crate (see <c>Fixtures/REGENERATE.md</c>) parse
/// through the Veridical instance and witness readers and satisfy
/// <c>A·z ∘ B·z = C·z</c> in the curve's scalar arithmetic. Because the
/// bytes come from the reference producer, this is a genuine interop check
/// of the hand-written FlatBuffers reader, not a self-test against our own
/// serializer.
/// </summary>
/// <remarks>
/// The fixture is the padded multiplier2 (<c>a·b = c</c> plus a <c>1·1 = 1</c>
/// row): public output <c>c</c> in <c>instance_variables</c>, private
/// <c>a, b</c> in the witness, satisfied by <c>a = 3, b = 11, c = 33</c>.
/// The shape (2 constraints, 4 variables) is a power of two, so the parsed
/// instance also feeds the Spartan prover.
/// </remarks>
[TestClass]
internal sealed class ZkInterfaceFixtureTests
{
    private const string FixtureDirectoryRelative = "ConstraintSystems/Interop/ZkInterface/Fixtures";
    private const int ExpectedRowCount = 2;
    private const int ExpectedColumnCount = 4;
    private const int ExpectedWitnessVariableCount = 3;


    [TestMethod]
    public void Bls12Curve381Multiplier2FixtureParsesAndSatisfies()
    {
        ExerciseFixture(
            "bls12_381",
            CurveParameterSet.Bls12Curve381,
            Bls12Curve381BigIntegerScalarReference.GetAdd(),
            Bls12Curve381BigIntegerScalarReference.GetMultiply());
    }


    [TestMethod]
    public void Bn254Multiplier2FixtureParsesAndSatisfies()
    {
        ExerciseFixture(
            "bn254",
            CurveParameterSet.Bn254,
            Bn254BigIntegerScalarReference.GetAdd(),
            Bn254BigIntegerScalarReference.GetMultiply());
    }


    private static void ExerciseFixture(string curveDirectory, CurveParameterSet curve, ScalarAddDelegate add, ScalarMultiplyDelegate multiply)
    {
        byte[] fixtureBytes = LoadFixtureBytes(curveDirectory);

        using RawR1csInstance instance = ParseInstance(fixtureBytes, curve);
        using RawR1csWitness witness = ParseWitness(fixtureBytes, curve);

        Assert.AreEqual(ExpectedRowCount, instance.A.RowCount, "A.RowCount");
        Assert.AreEqual(ExpectedColumnCount, instance.A.ColumnCount, "A.ColumnCount");
        Assert.AreEqual(0, instance.PublicInputCount, "PublicInputCount");
        Assert.AreEqual(ExpectedWitnessVariableCount, witness.WitnessVariableCount, "WitnessVariableCount");
        Assert.AreEqual(curve.Code, instance.Curve.Code, "parsed instance curve");

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, add, multiply, SensitiveMemoryPool<byte>.Shared);

        if(satisfaction is R1csSatisfaction.Violated violated)
        {
            Assert.Fail($"ZkInterface fixture ({curveDirectory}) satisfaction failed at constraint {violated.ConstraintIndex.Value}.");
        }

        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction);
    }


    private static byte[] LoadFixtureBytes(string curveDirectory)
    {
        string directory = Path.Combine(AppContext.BaseDirectory, FixtureDirectoryRelative, curveDirectory);
        if(!Directory.Exists(directory))
        {
            directory = Path.Combine(FixtureDirectoryRelative, curveDirectory);
        }

        string path = Path.Combine(directory, "multiplier2.zkif");
        if(!File.Exists(path))
        {
            Assert.Inconclusive($"Fixture file not found: {path}. Regenerate per Fixtures/REGENERATE.md.");
        }

        return File.ReadAllBytes(path);
    }


    [TestMethod]
    public void Bls12Curve381Multiplier2FixtureProvesAndVerifiesWithSpartan()
    {
        //The parsed-from-real-bytes instance must also be prover-ready: prove with
        //the base Spartan prover and verify, end-to-end over the BLS12-381 fixture.
        byte[] fixtureBytes = LoadFixtureBytes("bls12_381");

        using RawR1csWitness witness = ParseWitness(fixtureBytes, CurveParameterSet.Bls12Curve381);
        using SpartanProver prover = BuildBaseProver(ExpectedColumnCount);
        using SpartanVerifier verifier = BuildBaseVerifier(ExpectedColumnCount);

        using RawR1csInstance proverInstance = ParseInstance(fixtureBytes, CurveParameterSet.Bls12Curve381);
        using RawR1csInstance verifierInstance = ParseInstance(fixtureBytes, CurveParameterSet.Bls12Curve381);

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using SpartanProof proof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            SensitiveMemoryPool<byte>.Shared);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            proof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze,
            SensitiveMemoryPool<byte>.Shared);

        Assert.IsTrue(verified, "Spartan failed to verify a ZkInterface-parsed multiplier2 instance.");
    }


    private static RawR1csInstance ParseInstance(byte[] bytes, CurveParameterSet curve)
    {
        var stream = new MemoryStream(bytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);
        return ZkInterfaceR1csReader.Reader(pipe, WellKnownR1csFormatLabel.ZkInterface, curve, SensitiveMemoryPool<byte>.Shared, CancellationToken.None);
    }


    private static RawR1csWitness ParseWitness(byte[] bytes, CurveParameterSet curve)
    {
        var stream = new MemoryStream(bytes, writable: false);
        PipeReader pipe = PipeReader.Create(stream);
        return ZkInterfaceWitnessReader.Reader(pipe, WellKnownR1csFormatLabel.ZkInterface, curve, SensitiveMemoryPool<byte>.Shared, CancellationToken.None);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver via its constructor chain.")]
    private static SpartanProver BuildBaseProver(int columnCount)
    {
        var provingKey = new SpartanProvingKey(BuildProvider(BuildCommitmentKey(columnCount)));
        return new SpartanProver(provingKey);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanVerifier via its constructor chain.")]
    private static SpartanVerifier BuildBaseVerifier(int columnCount)
    {
        var verifyingKey = new SpartanVerifyingKey(BuildProvider(BuildCommitmentKey(columnCount)));
        return new SpartanVerifier(verifyingKey);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey)
    {
        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            CurveParameterSet.Bls12Curve381,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm,
            ownsKey: true);
    }


    private static HyraxCommitmentKey BuildCommitmentKey(int columnCount)
    {
        int columnVariableCount = BitOperations.Log2((uint)columnCount);
        HyraxCommitmentDimensions commitmentDims = HyraxCommitmentDimensions.ForVariableCount(columnVariableCount);
        return HyraxCommitmentKey.Derive(
            commitmentDims.ColumnCount,
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            CurveParameterSet.Bls12Curve381,
            HashToCurve,
            SensitiveMemoryPool<byte>.Shared);
    }


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty,
            WellKnownHashAlgorithms.Blake3,
            Hash,
            SensitiveMemoryPool<byte>.Shared);
    }


    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bls12Curve381BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = Bls12Curve381BigIntegerScalarReference.GetAdd();
    private static ScalarSubtractDelegate Subtract { get; } = Bls12Curve381BigIntegerScalarReference.GetSubtract();
    private static ScalarMultiplyDelegate Multiply { get; } = Bls12Curve381BigIntegerScalarReference.GetMultiply();
    private static ScalarInvertDelegate Invert { get; } = Bls12Curve381BigIntegerScalarReference.GetInvert();
    private static ScalarRandomDelegate ScalarRandom { get; } = Bls12Curve381BigIntegerScalarReference.GetRandom();
    private static G1AddDelegate G1Add { get; } = Bls12Curve381BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bls12Curve381BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bls12Curve381Msm;
    private static G1HashToCurveDelegate HashToCurve { get; } = Bls12Curve381BigIntegerG1Reference.GetHashToCurve();
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();
}

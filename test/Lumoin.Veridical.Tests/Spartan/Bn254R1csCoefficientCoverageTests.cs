using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using Lumoin.Veridical.Tests.Algebraic;
using Lumoin.Veridical.Tests.TestInfrastructure;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// BN254 coverage for R1CS instances with non-unit matrix coefficients —
/// the property a BN254 Poseidon fixture would have exercised but which the
/// all-ones multiplier2 fixture and the all-ones programmatic Spartan tests do
/// not. A BN254 Poseidon <c>.r1cs</c> is blocked on tooling (no local circom /
/// snarkjs, and Poseidon's round constants are field-specific so the
/// multiplier2 prime-swap cannot produce one), not on the reader, which parses
/// coefficients as field-agnostic 32-byte values. These programmatic tests
/// close the substantive half of that gap: arbitrary BN254 field-element
/// coefficients flowing through <see cref="R1csInstanceExtensions.CheckSatisfiedBy"/>
/// (Poseidon's load-bearing assertion) and through the Spartan prover/verifier.
/// </summary>
[TestClass]
internal sealed class Bn254R1csCoefficientCoverageTests
{
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bn254.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bn254.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bn254.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bn254.Invert;
    private static ScalarRandomDelegate Random { get; } = Bn254BigIntegerScalarReference.GetRandom();
    private static G1AddDelegate G1Add { get; } = Bn254BigIntegerG1Reference.GetAdd();
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bn254BigIntegerG1Reference.GetScalarMultiply();
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bn254Msm;
    private static G1HashToCurveDelegate HashToCurve { get; } = Bn254BigIntegerG1Reference.GetHashToCurve();
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    private static readonly BigInteger Order = Bn254BigIntegerScalarReference.FieldOrder;
    private static CurveParameterSet Curve => CurveParameterSet.Bn254;
    private static SensitiveMemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;


    [TestMethod]
    public void NonUnitCoefficientInstanceSatisfiesInBn254Arithmetic()
    {
        //Constraint 0: (2·z[1]) · (3·z[2]) = z[3], i.e. 6·z[1]·z[2] = z[3].
        //With z[1]=2, z[2]=5, z[3]=60: 6·2·5 = 60. Padding: z[0]·z[0] = z[0].
        using RawR1csInstance instance = BuildNonUnitInstance();
        using RawR1csWitness witness = BuildSatisfyingWitness();

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, Add, Multiply, Pool);

        if(satisfaction is R1csSatisfaction.Violated violated)
        {
            Assert.Fail($"Non-unit-coefficient BN254 instance reported unsatisfied at constraint {violated.ConstraintIndex.Value}.");
        }

        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(satisfaction);
    }


    [TestMethod]
    public void NonUnitCoefficientWrongWitnessReportedViolated()
    {
        //z[3] = 61 instead of 60 violates 6·z[1]·z[2] = z[3].
        using RawR1csInstance instance = BuildNonUnitInstance();
        using RawR1csWitness witness = BuildWitness(z1: 2, z2: 5, z3: 61);

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, Add, Multiply, Pool);

        Assert.IsInstanceOfType<R1csSatisfaction.Violated>(satisfaction);
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through using declarations; disposal happens before the assertion completes.")]
    public void NonUnitCoefficientInstanceProvesAndVerifiesThroughSpartan()
    {
        using SpartanProver prover = BuildProver();
        using SpartanVerifier verifier = BuildVerifier();

        using RawR1csInstance proverInstance = BuildNonUnitInstance();
        using RawR1csInstance verifierInstance = BuildNonUnitInstance();
        using RawR1csWitness witness = BuildSatisfyingWitness();

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using SpartanProof proof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            proof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze, Pool);

        Assert.IsTrue(verified, "A BN254 instance with non-unit matrix coefficients must prove and verify through Spartan.");
    }


    //A: row0 col1 = 2, row1 col0 = 1.  B: row0 col2 = 3, row1 col0 = 1.
    //C: row0 col3 = 1, row1 col0 = 1.  (m=2, n=4). Coefficients 2 and 3 are the
    //non-unit entries the all-ones fixtures never exercise.
    private static RawR1csInstance BuildNonUnitInstance()
    {
        int scalarSize = Scalar.SizeBytes;
        ReadOnlySpan<int> rows = [0, 1];
        ReadOnlySpan<int> aCols = [1, 0];
        ReadOnlySpan<int> bCols = [2, 0];
        ReadOnlySpan<int> cCols = [3, 0];

        Span<byte> aVals = stackalloc byte[2 * scalarSize];
        WriteCanonical(new BigInteger(2), aVals[..scalarSize]);
        WriteCanonical(BigInteger.One, aVals.Slice(scalarSize, scalarSize));

        Span<byte> bVals = stackalloc byte[2 * scalarSize];
        WriteCanonical(new BigInteger(3), bVals[..scalarSize]);
        WriteCanonical(BigInteger.One, bVals.Slice(scalarSize, scalarSize));

        Span<byte> cVals = stackalloc byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, cVals[..scalarSize]);
        WriteCanonical(BigInteger.One, cVals.Slice(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(rows, aCols, aVals, 2, 4, Curve, Pool);
        R1csMatrix b = R1csMatrix.FromSortedTriples(rows, bCols, bVals, 2, 4, Curve, Pool);
        R1csMatrix c = R1csMatrix.FromSortedTriples(rows, cCols, cVals, 2, 4, Curve, Pool);
        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, Pool);
    }


    private static RawR1csWitness BuildSatisfyingWitness() => BuildWitness(z1: 2, z2: 5, z3: 60);


    private static RawR1csWitness BuildWitness(int z1, int z2, int z3)
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(z1), witness[..scalarSize]);
        WriteCanonical(new BigInteger(z2), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(z3), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver.")]
    private static SpartanProver BuildProver() =>
        new(new SpartanProvingKey(BuildProvider()));


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanVerifier.")]
    private static SpartanVerifier BuildVerifier() =>
        new(new SpartanVerifyingKey(BuildProvider()));


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the derived key transfers to the caller.")]
    private static HyraxCommitmentKey BuildCommitmentKey() =>
        HyraxCommitmentKey.Derive(2, WellKnownHyraxDomainLabels.CanonicalSeedV1, Curve, HashToCurve, Pool);


    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildProvider() =>
        HyraxPolynomialCommitmentScheme.Create(
            BuildCommitmentKey(),
            Curve,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm,
            ownsKey: true);


    private static FiatShamirTranscript FreshTranscript() =>
        FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, Pool);


    private static void WriteCanonical(BigInteger value, Span<byte> destination)
    {
        destination.Clear();
        BigInteger nonNegative = ((value % Order) + Order) % Order;
        if(!nonNegative.TryWriteBytes(destination, out int written, isUnsigned: true, isBigEndian: true))
        {
            throw new InvalidOperationException("Reduced scalar did not fit in the canonical span.");
        }

        if(written < destination.Length)
        {
            int shift = destination.Length - written;
            destination[..written].CopyTo(destination[shift..]);
            destination[..shift].Clear();
        }
    }
}

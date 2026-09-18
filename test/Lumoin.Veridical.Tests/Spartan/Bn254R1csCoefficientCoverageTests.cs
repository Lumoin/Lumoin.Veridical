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
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// BN254 coverage for R1CS instances with non-unit matrix coefficients —
/// the property a BN254 Poseidon fixture would have exercised but which the
/// all-ones multiplier2 fixture and the all-ones programmatic Spartan tests do
/// not. No BN254 Poseidon <c>.r1cs</c> fixture is committed: Poseidon's round
/// constants are field-specific, so the multiplier2 prime-swap that derives a
/// BN254 fixture from the BLS12-381 bytes cannot produce one. The reader is
/// not the obstacle — it parses coefficients as field-agnostic 32-byte values
/// regardless of curve — so these programmatic tests close the substantive
/// half of that gap directly: arbitrary BN254 field-element
/// coefficients flowing through <c>CheckSatisfiedBy</c>
/// (Poseidon's load-bearing assertion) and through the Spartan prover/verifier.
/// </summary>
[TestClass]
internal sealed class Bn254R1csCoefficientCoverageTests
{
    /// <summary>The Fiat–Shamir hash delegate, wired to the Blake3 reference implementation.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The Fiat–Shamir squeeze delegate, wired to the Blake3 reference implementation.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The scalar-reduction delegate, wired to the BN254 BigInteger reference implementation.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();

    /// <summary>The scalar-addition delegate, wired to the BN254 test backend.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bn254.Add;

    /// <summary>The scalar-subtraction delegate, wired to the BN254 test backend.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bn254.Subtract;

    /// <summary>The scalar-multiplication delegate, wired to the BN254 test backend.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bn254.Multiply;

    /// <summary>The scalar-inversion delegate, wired to the BN254 test backend.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bn254.Invert;

    /// <summary>The scalar-sampling delegate, wired to the BN254 BigInteger reference implementation.</summary>
    private static ScalarRandomDelegate Random { get; } = Bn254BigIntegerScalarReference.GetRandom();

    /// <summary>The G1 point-addition delegate, wired to the BN254 BigInteger reference implementation.</summary>
    private static G1AddDelegate G1Add { get; } = Bn254BigIntegerG1Reference.GetAdd();

    /// <summary>The G1 scalar-multiplication delegate, wired to the BN254 BigInteger reference implementation.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bn254BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>The G1 multi-scalar-multiplication delegate, wired to the BN254 test backend.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bn254Msm;

    /// <summary>The G1 curve-membership delegate, wired to the BN254 BigInteger reference implementation.</summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bn254BigIntegerG1Reference.GetIsOnCurve();

    /// <summary>The G1 prime-order-subgroup delegate, wired to the BN254 BigInteger reference implementation.</summary>
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bn254BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();

    /// <summary>The G1 hash-to-curve delegate, wired to the BN254 BigInteger reference implementation.</summary>
    private static G1HashToCurveDelegate HashToCurve { get; } = Bn254BigIntegerG1Reference.GetHashToCurve();

    /// <summary>The multilinear-extension evaluation delegate, wired to the BigInteger reference implementation.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The multilinear-extension folding delegate, wired to the BigInteger reference implementation.</summary>
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    /// <summary>The BN254 scalar field order, used to reduce constructed test values into canonical range.</summary>
    private static BigInteger Order { get; } = Bn254BigIntegerScalarReference.FieldOrder;

    /// <summary>The BN254 curve parameter set these tests exercise.</summary>
    private static CurveParameterSet Curve => CurveParameterSet.Bn254;

    /// <summary>The shared memory pool these tests rent instance, witness, and proof storage from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>Verifies that a BN254 instance with non-unit matrix coefficients is satisfied by a witness that solves it.</summary>
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


    /// <summary>Verifies that the same non-unit-coefficient instance reports the violated constraint when the witness does not solve it.</summary>
    [TestMethod]
    public void NonUnitCoefficientWrongWitnessReportedViolated()
    {
        //z[3] = 61 instead of 60 violates 6·z[1]·z[2] = z[3].
        using RawR1csInstance instance = BuildNonUnitInstance();
        using RawR1csWitness witness = BuildWitness(z1: 2, z2: 5, z3: 61);

        using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, Add, Multiply, Pool);

        Assert.IsInstanceOfType<R1csSatisfaction.Violated>(satisfaction);
    }


    /// <summary>Verifies that a BN254 instance with non-unit matrix coefficients proves and verifies through the Spartan prover and verifier.</summary>
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


    /// <summary>The row count of <see cref="BuildNonUnitInstance"/>'s matrices: two constraints.</summary>
    private const int RowCount = 2;

    /// <summary>The column count of <see cref="BuildNonUnitInstance"/>'s matrices: the constant <c>z[0]</c> plus three witness elements.</summary>
    private const int ColumnCount = 4;


    /// <summary>
    /// Builds the two-constraint, four-column BN254 instance whose non-unit
    /// coefficients — 2 and 3, which the all-ones fixtures never exercise —
    /// appear in row 0: <c>(2·z[1])·(3·z[2]) = z[3]</c>. Row 1 pads the
    /// instance with the all-ones constraint <c>z[0]·z[0] = z[0]</c>.
    /// </summary>
    private static RawR1csInstance BuildNonUnitInstance()
    {
        int scalarSize = Scalar.SizeBytes;
        ReadOnlySpan<int> rows = [0, 1];
        ReadOnlySpan<int> aCols = [1, 0];
        ReadOnlySpan<int> bCols = [2, 0];
        ReadOnlySpan<int> cCols = [3, 0];

        Span<byte> aVals = stackalloc byte[RowCount * scalarSize];
        WriteCanonical(new BigInteger(2), aVals[..scalarSize]);
        WriteCanonical(BigInteger.One, aVals.Slice(scalarSize, scalarSize));

        Span<byte> bVals = stackalloc byte[RowCount * scalarSize];
        WriteCanonical(new BigInteger(3), bVals[..scalarSize]);
        WriteCanonical(BigInteger.One, bVals.Slice(scalarSize, scalarSize));

        Span<byte> cVals = stackalloc byte[RowCount * scalarSize];
        WriteCanonical(BigInteger.One, cVals[..scalarSize]);
        WriteCanonical(BigInteger.One, cVals.Slice(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(rows, aCols, aVals, RowCount, ColumnCount, Curve, Pool);
        R1csMatrix b = R1csMatrix.FromSortedTriples(rows, bCols, bVals, RowCount, ColumnCount, Curve, Pool);
        R1csMatrix c = R1csMatrix.FromSortedTriples(rows, cCols, cVals, RowCount, ColumnCount, Curve, Pool);
        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, Pool);
    }


    /// <summary>Builds the witness that satisfies <see cref="BuildNonUnitInstance"/>: <c>z[1]=2, z[2]=5, z[3]=60</c>.</summary>
    private static RawR1csWitness BuildSatisfyingWitness() => BuildWitness(z1: 2, z2: 5, z3: 60);


    /// <summary>Builds a three-element BN254 witness from the given <c>z[1], z[2], z[3]</c> values.</summary>
    private static RawR1csWitness BuildWitness(int z1, int z2, int z3)
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(z1), witness[..scalarSize]);
        WriteCanonical(new BigInteger(z2), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(z3), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    /// <summary>Builds a Spartan prover over a freshly derived BN254 Hyrax commitment provider.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanProver.")]
    private static SpartanProver BuildProver() =>
        new(new SpartanProvingKey(BuildProvider()));


    /// <summary>Builds a Spartan verifier over a freshly derived BN254 Hyrax commitment provider.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned SpartanVerifier.")]
    private static SpartanVerifier BuildVerifier() =>
        new(new SpartanVerifyingKey(BuildProvider()));


    /// <summary>Derives a Hyrax commitment key with enough Pedersen generators for this fixture's small polynomial commitment.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the derived key transfers to the caller.")]
    private static HyraxCommitmentKey BuildCommitmentKey() =>
        HyraxCommitmentKey.Derive(2, WellKnownHyraxDomainLabels.CanonicalSeedV1, Curve, HashToCurve, Pool);


    /// <summary>Builds the Hyrax polynomial commitment provider that backs the prover and verifier.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to the Spartan key that consumes it.")]
    private static PolynomialCommitmentProvider BuildProvider() =>
        HyraxPolynomialCommitmentScheme.Create(
            BuildCommitmentKey(),
            Curve,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, Random,
            G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup,
            ownsKey: true);


    /// <summary>Initialises a fresh Fiat–Shamir transcript under the Spartan domain label.</summary>
    private static FiatShamirTranscript FreshTranscript() =>
        FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, Pool);


    /// <summary>Reduces a value modulo the BN254 scalar field order and writes it as a fixed-width canonical big-endian scalar.</summary>
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

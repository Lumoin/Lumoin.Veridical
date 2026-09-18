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
/// End-to-end BN254 coverage of the masked Spartan prover/verifier and the
/// Category-B <see cref="FoldChain"/>. Mirrors the BLS12-381
/// <see cref="MaskedSpartanRoundtripTests"/> and <see cref="FoldChainRoundtripTests"/>
/// with the BN254 reference backends. These exercise <c>MaskedSpartanProof</c>
/// and the fold path (<c>RelaxedR1csFold</c> /
/// <c>RawR1csInstanceExtensions.Prepare</c>, including the curve-correct G1
/// identity encoding) with a real second curve, confirming both constructions
/// are curve-generic rather than tied to BLS12-381.
/// </summary>
[TestClass]
internal sealed class Bn254MaskedSpartanAndFoldTests
{
    /// <summary>The Blake3 Fiat-Shamir hash delegate driving both the prover and verifier transcripts.</summary>
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();

    /// <summary>The Blake3 Fiat-Shamir squeeze delegate drawing challenges from the transcript.</summary>
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();

    /// <summary>The BN254 scalar-field reduction delegate from the BigInteger-backed reference implementation.</summary>
    private static ScalarReduceDelegate Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();

    /// <summary>The BN254 scalar-field addition delegate under test.</summary>
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bn254.Add;

    /// <summary>The BN254 scalar-field subtraction delegate under test.</summary>
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bn254.Subtract;

    /// <summary>The BN254 scalar-field multiplication delegate under test.</summary>
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bn254.Multiply;

    /// <summary>The BN254 scalar-field inversion delegate under test.</summary>
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bn254.Invert;

    /// <summary>The BN254 scalar-field random-sampling delegate from the BigInteger-backed reference implementation.</summary>
    private static ScalarRandomDelegate ScalarRandom { get; } = Bn254BigIntegerScalarReference.GetRandom();

    /// <summary>The BN254 G1 addition delegate from the BigInteger-backed reference implementation.</summary>
    private static G1AddDelegate G1Add { get; } = Bn254BigIntegerG1Reference.GetAdd();

    /// <summary>The BN254 G1 scalar-multiplication delegate from the BigInteger-backed reference implementation.</summary>
    private static G1ScalarMultiplyDelegate G1ScalarMul { get; } = Bn254BigIntegerG1Reference.GetScalarMultiply();

    /// <summary>The BN254 G1 multi-scalar-multiplication delegate under test.</summary>
    private static G1MultiScalarMultiplyDelegate G1Msm { get; } = TestG1Backends.Bn254Msm;

    /// <summary>The BN254 G1 on-curve check delegate from the BigInteger-backed reference implementation.</summary>
    private static G1IsOnCurveDelegate G1IsOnCurve { get; } = Bn254BigIntegerG1Reference.GetIsOnCurve();

    /// <summary>The BN254 G1 prime-order-subgroup membership delegate from the BigInteger-backed reference implementation.</summary>
    private static G1IsInPrimeOrderSubgroupDelegate G1IsInPrimeOrderSubgroup { get; } = Bn254BigIntegerG1Reference.GetIsInPrimeOrderSubgroup();

    /// <summary>The BN254 G1 hash-to-curve delegate from the BigInteger-backed reference implementation, used to derive the Hyrax commitment key's generators.</summary>
    private static G1HashToCurveDelegate HashToCurve { get; } = Bn254BigIntegerG1Reference.GetHashToCurve();

    /// <summary>The multilinear-extension evaluation delegate from the BigInteger-backed reference implementation.</summary>
    private static MleEvaluateDelegate MleEvaluate { get; } = MultilinearExtensionBigIntegerReference.GetEvaluate();

    /// <summary>The multilinear-extension fold delegate from the BigInteger-backed reference implementation.</summary>
    private static MleFoldDelegate MleFold { get; } = MultilinearExtensionBigIntegerReference.GetFold();

    /// <summary>The BN254 scalar-field order, used to reduce canonical witness values into range.</summary>
    private static BigInteger Order { get; } = Bn254BigIntegerScalarReference.FieldOrder;

    /// <summary>The curve parameter set selecting the BN254 instantiation throughout this class.</summary>
    private static CurveParameterSet Curve => CurveParameterSet.Bn254;

    /// <summary>The shared memory pool this class's helpers rent scratch buffers from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>Verifies that the masked Spartan prover and verifier round-trip over BN254 for the trivial one-multiply instance.</summary>
    [TestMethod]
    public void MaskedTrivialInstanceRoundtrip()
    {
        ExerciseMaskedRoundtrip(BuildOneMultiplyInstance, BuildOneMultiplyWitness, hyraxVectorLength: 2);
    }


    /// <summary>Verifies that the masked Spartan prover and verifier round-trip over BN254 for the larger two-multiply instance.</summary>
    [TestMethod]
    public void MaskedLargerInstanceRoundtrip()
    {
        ExerciseMaskedRoundtrip(BuildTwoMultiplyInstance, BuildTwoMultiplyWitness, hyraxVectorLength: 4);
    }


    /// <summary>Verifies that folding two witnesses for the one-multiply instance compresses to a proof that verifies against the final folded accumulator, over BN254.</summary>
    [TestMethod]
    public void FoldChainOfTwoOneMultiplyVerifies()
    {
        ExerciseFoldRoundtrip(
            BuildOneMultiplyInstance,
            [BuildOneMultiplyWitness, BuildAlternativeOneMultiplyWitness],
            hyraxVectorLength: 2);
    }


    /// <summary>Verifies that folding two witnesses for the two-multiply instance compresses to a proof that verifies against the final folded accumulator, over BN254.</summary>
    [TestMethod]
    public void FoldChainOfTwoTwoMultiplyVerifies()
    {
        ExerciseFoldRoundtrip(
            BuildTwoMultiplyInstance,
            [BuildTwoMultiplyWitness, BuildTwoMultiplyWitness],
            hyraxVectorLength: 4);
    }


    /// <summary>Verifies that folding a witness which violates the first constraint completes without a satisfaction check, but that finalizing the chain then throws because the accumulated statement is unsatisfied.</summary>
    [TestMethod]
    public void FoldingUnsatisfiedStatementFailsToCompress()
    {
        //z = (1, 3, 5, 99) violates c0. The fold step folds it algebraically
        //without checking; the satisfaction check at compression time throws.
        AssertUnsatisfiedFoldFailsToCompress(BuildUnsatisfyingWitness());
    }


    /// <summary>Verifies that folding a witness one unit off from satisfying completes without a satisfaction check, but that finalizing the chain then throws because the accumulated statement is unsatisfied.</summary>
    [TestMethod]
    public void FoldingOffByOneStatementFailsToCompress()
    {
        //Almost satisfying: z = (1, 3, 5, 16) instead of (1, 3, 5, 15).
        AssertUnsatisfiedFoldFailsToCompress(BuildOffByOneWitness());
    }


    /// <summary>Asserts that folding the given unsatisfying witness into a fresh chain leaves the accumulator unsatisfied, so finalizing the chain throws <see cref="R1csNotSatisfiedException"/>.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through using declarations; the unsatisfying witness is consumed by the fold step.")]
    private static void AssertUnsatisfiedFoldFailsToCompress(RawR1csWitness unsatisfyingWitness)
    {
        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey(vectorLength: 2));
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength: 2);

        using RawR1csInstance template = BuildOneMultiplyInstance();
        using FiatShamirTranscript foldTranscript = FreshTranscript();
        using FoldChain chain = FoldChain.Start(
            template, provider, foldTranscript,
            Add, Subtract, Multiply, ScalarRandom, G1Msm, Pool);

        //The fold step performs no satisfaction check — it completes, leaving
        //the accumulator unsatisfied by the r²-weighted incoming residual.
        StepRaw(chain, BuildOneMultiplyInstance(), unsatisfyingWitness);

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        Assert.ThrowsExactly<R1csNotSatisfiedException>(() =>
        {
            using MaskedSpartanProof _ = chain.Finalize(
                prover, proverTranscript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
                G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);
        });
    }


    /// <summary>Builds the witness z = (1, 3, 5, 99), which violates constraint c0 (3·5 != 99).</summary>
    private static RawR1csWitness BuildUnsatisfyingWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(99), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    /// <summary>Builds the witness z = (1, 3, 5, 16), off by one from satisfying in the product slot.</summary>
    private static RawR1csWitness BuildOffByOneWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(16), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    /// <summary>Produces a fresh raw R1CS instance for a test's fold or round-trip exercise.</summary>
    private delegate RawR1csInstance RawInstanceFactory();

    /// <summary>Produces a fresh raw R1CS witness for a test's fold or round-trip exercise.</summary>
    private delegate RawR1csWitness RawWitnessFactory();


    /// <summary>Proves and verifies a masked Spartan instance built from the given factories, asserting that the round-trip verifies.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through using declarations; disposal happens before the assertion completes.")]
    private static void ExerciseMaskedRoundtrip(
        RawInstanceFactory instanceFactory,
        RawWitnessFactory witnessFactory,
        int hyraxVectorLength)
    {
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength);
        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(hyraxVectorLength);

        using RawR1csInstance proverInstance = instanceFactory();
        using RawR1csInstance verifierInstance = instanceFactory();
        using RawR1csWitness witness = witnessFactory();

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof proof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            proof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze, Pool);

        Assert.IsTrue(verified, "BN254 masked round-trip verification failed.");
    }


    /// <summary>Folds one or more witnesses for the given instance factory into a chain, finalizes it, and asserts that the resulting proof verifies against the final folded instance.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership transfers through using declarations; disposal happens before the assertion completes.")]
    private static void ExerciseFoldRoundtrip(
        RawInstanceFactory instanceFactory,
        RawWitnessFactory[] witnessFactories,
        int hyraxVectorLength)
    {
        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey(hyraxVectorLength));
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength);
        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(hyraxVectorLength);

        using RawR1csInstance template = instanceFactory();
        using FiatShamirTranscript foldTranscript = FreshTranscript();

        using FoldChain chain = FoldChain.Start(
            template, provider, foldTranscript,
            Add, Subtract, Multiply, ScalarRandom, G1Msm, Pool);

        foreach(RawWitnessFactory witnessFactory in witnessFactories)
        {
            StepRaw(chain, instanceFactory(), witnessFactory());
        }

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof proof = chain.Finalize(
            prover, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            proof, chain.Accumulator.Instance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze, Pool);

        Assert.IsTrue(
            verified,
            $"A BN254 fold chain of {witnessFactories.Length} statement(s) must compress to a proof that verifies against the final folded instance.");
    }


    /// <summary>Prepares a raw instance and witness into a relaxed accumulator with a zero error-opening blind sized to the matrix row count, and steps the fold chain with it.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The raw instance and witness are disposed within this method; the prepared relaxed objects transfer to the accumulator the chain step consumes.")]
    private static void StepRaw(FoldChain chain, RawR1csInstance rawInstance, RawR1csWitness rawWitness)
    {
        using(rawInstance)
        using(rawWitness)
        {
            RelaxedR1csInstance instance = rawInstance.Prepare(Pool);
            RelaxedR1csWitness witness = rawWitness.Prepare(rawInstance.A.RowCount, Pool);

            //The error commitment has one Hyrax row per matrix-shape row; the blind
            //is one scalar per row, so its byte length is rowCount × scalar size.
            int rowVariableCount = BitOperations.Log2((uint)rawInstance.A.RowCount);
            int errorCommitmentRowCount = HyraxCommitmentDimensions.ForVariableCount(rowVariableCount).RowCount;
            PolynomialCommitmentBlind errorOpeningWitness = PolynomialCommitmentBlind.CreateZero(
                errorCommitmentRowCount * Scalar.SizeBytes, Curve, CommitmentScheme.Hyrax, Pool);

            using var statement = new RelaxedR1csAccumulator(instance, witness, errorOpeningWitness);
            chain.Step(
                statement.Instance, statement.Witness, statement.ErrorOpeningWitness,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, ScalarRandom,
                G1Add, G1ScalarMul, G1Msm, Pool);
        }
    }


    /// <summary>Builds a masked Spartan prover over a fresh Hyrax provider sized for the given vector length.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned MaskedSpartanProver.")]
    private static MaskedSpartanProver BuildMaskedProver(int hyraxVectorLength)
    {
        return new MaskedSpartanProver(new SpartanProvingKey(BuildProvider(BuildCommitmentKey(hyraxVectorLength))));
    }


    /// <summary>Builds a masked Spartan verifier over a fresh Hyrax provider sized for the given vector length.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned MaskedSpartanVerifier.")]
    private static MaskedSpartanVerifier BuildMaskedVerifier(int hyraxVectorLength)
    {
        return new MaskedSpartanVerifier(new SpartanVerifyingKey(BuildProvider(BuildCommitmentKey(hyraxVectorLength))));
    }


    /// <summary>Builds a Hyrax polynomial commitment provider over BN254 that takes ownership of the given commitment key.</summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to whatever owns the provider.")]
    private static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey)
    {
        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            Curve,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, G1IsOnCurve, G1IsInPrimeOrderSubgroup,
            ownsKey: true);
    }


    /// <summary>
    /// Derives a Hyrax commitment key sized for at least <paramref name="vectorLength"/>. The statistical
    /// masks' single-row vector commitments need more generators than the small witness matrices; a longer
    /// key derives the same per-index generators, so flooring the length is byte-neutral for the rest.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the derived key transfers to the caller's using declaration.")]
    private static HyraxCommitmentKey BuildCommitmentKey(int vectorLength)
    {
        return HyraxCommitmentKey.Derive(
            Math.Max(vectorLength, MaskedSpartanTestFixtures.MaskedVectorLengthFloor),
            WellKnownHyraxDomainLabels.CanonicalSeedV1, Curve, HashToCurve, Pool);
    }


    /// <summary>Initializes a fresh Fiat-Shamir transcript under the Spartan domain label, for either a prover's or a verifier's independent run.</summary>
    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, Pool);
    }


    /// <summary>Builds a one-multiplication-plus-padding R1CS instance: c0 z[1]·z[2]=z[3], c1 z[0]·z[0]=z[0] (m=2, n=4).</summary>
    private static RawR1csInstance BuildOneMultiplyInstance()
    {
        int scalarSize = Scalar.SizeBytes;
        ReadOnlySpan<int> rows = [0, 1];
        ReadOnlySpan<int> aCols = [1, 0];
        ReadOnlySpan<int> bCols = [2, 0];
        ReadOnlySpan<int> cCols = [3, 0];

        Span<byte> ones = stackalloc byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, ones[..scalarSize]);
        WriteCanonical(BigInteger.One, ones.Slice(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(rows, aCols, ones, 2, 4, Curve, Pool);
        R1csMatrix b = R1csMatrix.FromSortedTriples(rows, bCols, ones, 2, 4, Curve, Pool);
        R1csMatrix c = R1csMatrix.FromSortedTriples(rows, cCols, ones, 2, 4, Curve, Pool);
        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, Pool);
    }


    /// <summary>Builds the satisfying witness z = (1, 3, 5, 15) for the one-multiply instance: c0 3·5=15, c1 1·1=1.</summary>
    private static RawR1csWitness BuildOneMultiplyWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(15), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    /// <summary>Builds an alternative satisfying witness for the one-multiply instance: z = (1, 2, 7, 14).</summary>
    private static RawR1csWitness BuildAlternativeOneMultiplyWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(2), witness[..scalarSize]);
        WriteCanonical(new BigInteger(7), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(14), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    /// <summary>Builds a two-multiplication R1CS instance: c0 z[1]·z[2]=z[3], c1 z[4]·z[5]=z[6] (m=2, n=8).</summary>
    private static RawR1csInstance BuildTwoMultiplyInstance()
    {
        int scalarSize = Scalar.SizeBytes;
        ReadOnlySpan<int> rows = [0, 1];
        ReadOnlySpan<int> aCols = [1, 4];
        ReadOnlySpan<int> bCols = [2, 5];
        ReadOnlySpan<int> cCols = [3, 6];

        Span<byte> ones = stackalloc byte[2 * scalarSize];
        WriteCanonical(BigInteger.One, ones[..scalarSize]);
        WriteCanonical(BigInteger.One, ones.Slice(scalarSize, scalarSize));

        R1csMatrix a = R1csMatrix.FromSortedTriples(rows, aCols, ones, 2, 8, Curve, Pool);
        R1csMatrix b = R1csMatrix.FromSortedTriples(rows, bCols, ones, 2, 8, Curve, Pool);
        R1csMatrix c = R1csMatrix.FromSortedTriples(rows, cCols, ones, 2, 8, Curve, Pool);
        return RawR1csInstance.Create(a, b, c, ReadOnlySpan<byte>.Empty, Pool);
    }


    /// <summary>Builds the satisfying witness z = (1, 3, 5, 15, 2, 7, 14, 0) for the two-multiply instance: c0 3·5=15, c1 2·7=14.</summary>
    private static RawR1csWitness BuildTwoMultiplyWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[7 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(15), witness.Slice(2 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(2), witness.Slice(3 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(7), witness.Slice(4 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(14), witness.Slice(5 * scalarSize, scalarSize));
        WriteCanonical(BigInteger.Zero, witness.Slice(6 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    /// <summary>Reduces a value modulo the BN254 scalar order into [0, Order) and writes it into <paramref name="destination"/> as a canonical big-endian scalar, throwing if it does not fit.</summary>
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

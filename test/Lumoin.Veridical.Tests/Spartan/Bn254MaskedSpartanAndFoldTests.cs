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
/// with the BN254 reference backends. These exercise the U.10 curve-broadening
/// of <c>MaskedSpartanProof</c> and the fold path (<c>RelaxedR1csFold</c> /
/// <c>RawR1csInstanceExtensions.Prepare</c>, including the curve-correct G1
/// identity encoding) with a real second curve.
/// </summary>
[TestClass]
internal sealed class Bn254MaskedSpartanAndFoldTests
{
    private static FiatShamirHashDelegate Hash { get; } = FiatShamirBlake3Reference.GetHash();
    private static FiatShamirSqueezeDelegate Squeeze { get; } = FiatShamirBlake3Reference.GetSqueeze();
    private static ScalarReduceDelegate Reduce { get; } = Bn254BigIntegerScalarReference.GetReduce();
    private static ScalarAddDelegate Add { get; } = TestScalarBackends.Bn254.Add;
    private static ScalarSubtractDelegate Subtract { get; } = TestScalarBackends.Bn254.Subtract;
    private static ScalarMultiplyDelegate Multiply { get; } = TestScalarBackends.Bn254.Multiply;
    private static ScalarInvertDelegate Invert { get; } = TestScalarBackends.Bn254.Invert;
    private static ScalarRandomDelegate ScalarRandom { get; } = Bn254BigIntegerScalarReference.GetRandom();
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
    public void MaskedTrivialInstanceRoundtrip()
    {
        ExerciseMaskedRoundtrip(BuildOneMultiplyInstance, BuildOneMultiplyWitness, hyraxVectorLength: 2);
    }


    [TestMethod]
    public void MaskedLargerInstanceRoundtrip()
    {
        ExerciseMaskedRoundtrip(BuildTwoMultiplyInstance, BuildTwoMultiplyWitness, hyraxVectorLength: 4);
    }


    [TestMethod]
    public void FoldChainOfTwoOneMultiplyVerifies()
    {
        ExerciseFoldRoundtrip(
            BuildOneMultiplyInstance,
            [BuildOneMultiplyWitness, BuildAlternativeOneMultiplyWitness],
            hyraxVectorLength: 2);
    }


    [TestMethod]
    public void FoldChainOfTwoTwoMultiplyVerifies()
    {
        ExerciseFoldRoundtrip(
            BuildTwoMultiplyInstance,
            [BuildTwoMultiplyWitness, BuildTwoMultiplyWitness],
            hyraxVectorLength: 4);
    }


    [TestMethod]
    public void FoldingUnsatisfiedStatementFailsToCompress()
    {
        //z = (1, 3, 5, 99) violates c0. The fold step folds it algebraically
        //without checking; the satisfaction check at compression time throws.
        AssertUnsatisfiedFoldFailsToCompress(BuildUnsatisfyingWitness());
    }


    [TestMethod]
    public void FoldingOffByOneStatementFailsToCompress()
    {
        //Almost satisfying: z = (1, 3, 5, 16) instead of (1, 3, 5, 15).
        AssertUnsatisfiedFoldFailsToCompress(BuildOffByOneWitness());
    }


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


    //z = (1, 3, 5, 99): violates c0 (3·5 != 99).
    private static RawR1csWitness BuildUnsatisfyingWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(99), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    //z = (1, 3, 5, 16): off-by-one in the product slot.
    private static RawR1csWitness BuildOffByOneWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(16), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    private delegate RawR1csInstance RawInstanceFactory();
    private delegate RawR1csWitness RawWitnessFactory();


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


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned MaskedSpartanProver.")]
    private static MaskedSpartanProver BuildMaskedProver(int hyraxVectorLength)
    {
        return new MaskedSpartanProver(new SpartanProvingKey(BuildProvider(BuildCommitmentKey(hyraxVectorLength))));
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers to the returned MaskedSpartanVerifier.")]
    private static MaskedSpartanVerifier BuildMaskedVerifier(int hyraxVectorLength)
    {
        return new MaskedSpartanVerifier(new SpartanVerifyingKey(BuildProvider(BuildCommitmentKey(hyraxVectorLength))));
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The provider takes ownership of the key (ownsKey: true) and transfers to whatever owns the provider.")]
    private static PolynomialCommitmentProvider BuildProvider(HyraxCommitmentKey commitmentKey)
    {
        return HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            Curve,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm,
            ownsKey: true);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the derived key transfers to the caller's using declaration.")]
    private static HyraxCommitmentKey BuildCommitmentKey(int vectorLength)
    {
        //The statistical masks' single-row vector commitments need more
        //generators than the small witness matrices; a longer key derives the
        //same per-index generators, so flooring is byte-neutral for the rest.
        return HyraxCommitmentKey.Derive(
            Math.Max(vectorLength, MaskedSpartanTestFixtures.MaskedVectorLengthFloor),
            WellKnownHyraxDomainLabels.CanonicalSeedV1, Curve, HashToCurve, Pool);
    }


    private static FiatShamirTranscript FreshTranscript()
    {
        return FiatShamirTranscript.Initialise(
            new FiatShamirDomainLabel(WellKnownSpartanDomainLabels.SpartanV1),
            ReadOnlySpan<byte>.Empty, WellKnownHashAlgorithms.Blake3, Hash, Pool);
    }


    //One multiplication plus padding: c0 z[1]·z[2]=z[3], c1 z[0]·z[0]=z[0]. (m=2, n=4).
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


    //z = (1, 3, 5, 15): c0 3·5=15, c1 1·1=1.
    private static RawR1csWitness BuildOneMultiplyWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witness[..scalarSize]);
        WriteCanonical(new BigInteger(5), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(15), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    //Alternative valid witness for the one-multiply instance: z = (1, 2, 7, 14).
    private static RawR1csWitness BuildAlternativeOneMultiplyWitness()
    {
        int scalarSize = Scalar.SizeBytes;
        Span<byte> witness = stackalloc byte[3 * scalarSize];
        WriteCanonical(new BigInteger(2), witness[..scalarSize]);
        WriteCanonical(new BigInteger(7), witness.Slice(scalarSize, scalarSize));
        WriteCanonical(new BigInteger(14), witness.Slice(2 * scalarSize, scalarSize));
        return RawR1csWitness.FromCanonical(witness, Curve, Pool);
    }


    //Two multiplications: c0 z[1]·z[2]=z[3], c1 z[4]·z[5]=z[6]. (m=2, n=8).
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


    //z = (1, 3, 5, 15, 2, 7, 14, 0): c0 3·5=15, c1 2·7=14.
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

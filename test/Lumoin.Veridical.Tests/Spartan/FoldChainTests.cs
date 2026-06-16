using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Spartan;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

using static Lumoin.Veridical.Tests.Spartan.FoldChainTestFixtures;
using static Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Core completeness checks for <see cref="FoldChain"/>, the Category B
/// fold-with-randomness driver: the blinding instance produced by
/// <see cref="FoldChain.Start"/> is a satisfied relaxed instance whose
/// error commitment opens to its error vector; folding real statements
/// in keeps the accumulator satisfied across a multi-step chain; and the
/// final folded instance compresses to a masked Spartan proof that
/// verifies. The remaining gate legs live in
/// <c>FoldChainRoundtripTests</c> (shapes/lengths),
/// <c>FoldChainFailureTests</c>, <c>FoldChainSoundnessTests</c>,
/// <c>FoldChainFixtureTests</c>, and
/// <c>FoldChainIndistinguishabilityTests</c>.
/// </summary>
[TestClass]
internal sealed class FoldChainTests
{
    //One-multiply (m = 2, n = 4): witness MLE over 2 column variables
    //dominates, so a Hyrax vector length of 2 covers the chain's
    //cross-term/error commitments and the compression's witness/mask
    //commitments alike — matching the masked round-trip gate.
    private const int HyraxVectorLength = 2;


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Test composes ownership through using declarations; everything is disposed before the assertion completes.")]
    public void StartProducesASatisfiedBlindingAccumulator()
    {
        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey(HyraxVectorLength), ScalarRandom);
        using RawR1csInstance template = BuildOneMultiplyInstance();
        using FiatShamirTranscript foldTranscript = FreshTranscript();

        using FoldChain chain = StartChain(template, provider, foldTranscript, ScalarRandom);

        using R1csSatisfaction satisfaction = chain.Accumulator.Instance.CheckSatisfiedBy(
            chain.Accumulator.Witness, Add, Multiply, Pool);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(
            satisfaction,
            "The blinding instance must satisfy the relaxed identity by construction (E = Az∘Bz − u·Cz).");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Test composes ownership through using declarations; everything is disposed before the assertion completes.")]
    public void BlindingAccumulatorErrorCommitmentOpensToItsErrorVector()
    {
        using HyraxCommitmentKey commitmentKey = BuildCommitmentKey(HyraxVectorLength);
        using PolynomialCommitmentProvider provider = HyraxPolynomialCommitmentScheme.Create(
            commitmentKey,
            Curve,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm,
            ownsKey: false);
        using RawR1csInstance template = BuildOneMultiplyInstance();
        using FiatShamirTranscript foldTranscript = FreshTranscript();

        using FoldChain chain = StartChain(template, provider, foldTranscript, ScalarRandom);

        RelaxedR1csAccumulator accumulator = chain.Accumulator;
        int rowVariableCount = BitOperations.Log2((uint)accumulator.Instance.A.RowCount);

        using MultilinearExtension errorMle = MultilinearExtension.FromEvaluations(
            accumulator.Witness.GetErrorBytes(), rowVariableCount, Curve, Pool);

        //The generic error commitment / blind carry the same canonical bytes a
        //Hyrax commitment / opening witness expose; rebuild the Hyrax views (the
        //matrix shape derives from the error MLE's variable count) to drive the
        //Hyrax open/verify extension methods directly.
        HyraxCommitmentDimensions dimensions = HyraxCommitmentDimensions.ForVariableCount(rowVariableCount);
        using HyraxCommitment errorCommitment = HyraxCommitment.FromBytes(
            accumulator.Instance.ErrorCommitment.AsReadOnlySpan(),
            dimensions.RowCount, dimensions.ColumnCount, rowVariableCount, Curve, Pool);
        using HyraxOpeningWitness errorOpeningWitness = HyraxOpeningWitness.FromCanonical(
            accumulator.ErrorOpeningWitness.AsReadOnlySpan(), Curve, Pool);

        Scalar[] point = BuildPoint(rowVariableCount);
        try
        {
            using FiatShamirTranscript openTranscript = FreshTranscript();
            (HyraxOpeningProof proof, Scalar claimedValue) = errorCommitment.Open(
                errorOpeningWitness, errorMle, point, commitmentKey, openTranscript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
                G1Add, G1ScalarMul, G1Msm, Pool);

            using(proof)
            using(claimedValue)
            {
                using FiatShamirTranscript verifyTranscript = FreshTranscript();
                bool verified = errorCommitment.VerifyOpening(
                    point, claimedValue, proof, commitmentKey, verifyTranscript,
                    Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert,
                    G1Add, G1ScalarMul, G1Msm, Pool);

                Assert.IsTrue(
                    verified,
                    "The blinding instance's error commitment must open to its random error vector under the sampled blinding.");
            }
        }
        finally
        {
            foreach(Scalar scalar in point)
            {
                scalar.Dispose();
            }
        }
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Test composes ownership through using declarations; everything is disposed before the assertion completes.")]
    public void StepFoldsARealStatementAndStaysSatisfied()
    {
        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey(HyraxVectorLength), ScalarRandom);
        using RawR1csInstance template = BuildOneMultiplyInstance();
        using FiatShamirTranscript foldTranscript = FreshTranscript();

        using FoldChain chain = StartChain(template, provider, foldTranscript, ScalarRandom);

        StepRaw(chain, BuildOneMultiplyInstance(), BuildOneMultiplyWitness(), ScalarRandom);

        using R1csSatisfaction satisfaction = chain.Accumulator.Instance.CheckSatisfiedBy(
            chain.Accumulator.Witness, Add, Multiply, Pool);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(
            satisfaction,
            "Folding a satisfied real statement into the blinding accumulator must keep the relaxed identity satisfied.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Test composes ownership through using declarations; everything is disposed before the assertion completes.")]
    public void MultiStepChainStaysSatisfied()
    {
        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey(HyraxVectorLength), ScalarRandom);
        using RawR1csInstance template = BuildOneMultiplyInstance();
        using FiatShamirTranscript foldTranscript = FreshTranscript();

        using FoldChain chain = StartChain(template, provider, foldTranscript, ScalarRandom);

        //Three real statements, two distinct witnesses, folded in sequence
        //on the single chained fold transcript.
        StepRaw(chain, BuildOneMultiplyInstance(), BuildOneMultiplyWitness(), ScalarRandom);
        StepRaw(chain, BuildOneMultiplyInstance(), BuildAlternativeOneMultiplyWitness(), ScalarRandom);
        StepRaw(chain, BuildOneMultiplyInstance(), BuildOneMultiplyWitness(), ScalarRandom);

        using R1csSatisfaction satisfaction = chain.Accumulator.Instance.CheckSatisfiedBy(
            chain.Accumulator.Witness, Add, Multiply, Pool);
        Assert.IsInstanceOfType<R1csSatisfaction.Satisfied>(
            satisfaction,
            "A multi-step fold chain must keep the relaxed identity satisfied after every fold.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000", Justification = "Test composes ownership through using declarations; everything is disposed before the assertion completes.")]
    public void FoldedChainCompressesAndVerifies()
    {
        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey(HyraxVectorLength), ScalarRandom);
        using MaskedSpartanProver prover = BuildMaskedProver(HyraxVectorLength, ScalarRandom);
        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(HyraxVectorLength, ScalarRandom);

        using RawR1csInstance template = BuildOneMultiplyInstance();
        using FiatShamirTranscript foldTranscript = FreshTranscript();

        using FoldChain chain = StartChain(template, provider, foldTranscript, ScalarRandom);

        StepRaw(chain, BuildOneMultiplyInstance(), BuildOneMultiplyWitness(), ScalarRandom);
        StepRaw(chain, BuildOneMultiplyInstance(), BuildAlternativeOneMultiplyWitness(), ScalarRandom);

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof proof = Compress(chain, prover, proverTranscript, ScalarRandom);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = VerifyCompressed(verifier, proof, chain.Accumulator.Instance, verifierTranscript);

        Assert.IsTrue(
            verified,
            "The compressed proof of the final folded instance must verify against that instance.");
    }


    private static Scalar[] BuildPoint(int variableCount)
    {
        int scalarSize = Scalar.SizeBytes;
        Scalar[] point = new Scalar[variableCount];
        Span<byte> buffer = stackalloc byte[scalarSize];
        for(int i = 0; i < variableCount; i++)
        {
            buffer.Clear();
            //Arbitrary distinct small evaluation coordinates.
            WriteCanonical(new BigInteger(7 + i), buffer);
            point[i] = Scalar.FromCanonical(buffer, CurveParameterSet.Bls12Curve381, Pool);
        }

        return point;
    }
}
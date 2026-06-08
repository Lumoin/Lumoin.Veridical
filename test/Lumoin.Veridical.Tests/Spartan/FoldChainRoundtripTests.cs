using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Spartan;

using static Lumoin.Veridical.Tests.Spartan.FoldChainTestFixtures;
using static Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Completeness leg of the <see cref="FoldChain"/> gate across chain
/// lengths and circuit sizes: a chain of <c>k</c> satisfied statements
/// folded into the blinding accumulator and compressed always verifies
/// against the final folded instance. Exercises one- and two-multiply
/// circuits and chains of one, two, and three statements.
/// </summary>
[TestClass]
internal sealed class FoldChainRoundtripTests
{
    private delegate RawR1csInstance RawInstanceFactory();
    private delegate RawR1csWitness RawWitnessFactory();


    [TestMethod]
    public void OneMultiplyChainOfOneVerifies()
    {
        ExerciseFoldRoundtrip(
            BuildOneMultiplyInstance,
            [BuildOneMultiplyWitness],
            hyraxVectorLength: 2);
    }


    [TestMethod]
    public void OneMultiplyChainOfTwoVerifies()
    {
        ExerciseFoldRoundtrip(
            BuildOneMultiplyInstance,
            [BuildOneMultiplyWitness, BuildAlternativeOneMultiplyWitness],
            hyraxVectorLength: 2);
    }


    [TestMethod]
    public void OneMultiplyChainOfThreeVerifies()
    {
        ExerciseFoldRoundtrip(
            BuildOneMultiplyInstance,
            [BuildOneMultiplyWitness, BuildAlternativeOneMultiplyWitness, BuildOneMultiplyWitness],
            hyraxVectorLength: 2);
    }


    [TestMethod]
    public void TwoMultiplyChainOfTwoVerifies()
    {
        ExerciseFoldRoundtrip(
            BuildTwoMultiplyInstance,
            [BuildTwoMultiplyWitness, BuildTwoMultiplyWitness],
            hyraxVectorLength: 4);
    }


    private static void ExerciseFoldRoundtrip(
        RawInstanceFactory instanceFactory,
        RawWitnessFactory[] witnessFactories,
        int hyraxVectorLength)
    {
        using PolynomialCommitmentProvider provider = BuildProvider(BuildCommitmentKey(hyraxVectorLength), ScalarRandom);
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength, ScalarRandom);
        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(hyraxVectorLength, ScalarRandom);

        using RawR1csInstance template = instanceFactory();
        using FiatShamirTranscript foldTranscript = FreshTranscript();

        using FoldChain chain = StartChain(template, provider, foldTranscript, ScalarRandom);

        foreach(RawWitnessFactory witnessFactory in witnessFactories)
        {
            StepRaw(chain, instanceFactory(), witnessFactory(), ScalarRandom);
        }

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof proof = Compress(chain, prover, proverTranscript, ScalarRandom);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = VerifyCompressed(verifier, proof, chain.Accumulator.Instance, verifierTranscript);

        Assert.IsTrue(
            verified,
            $"A fold chain of {witnessFactories.Length} statement(s) must compress to a proof that verifies against the final folded instance.");
    }
}
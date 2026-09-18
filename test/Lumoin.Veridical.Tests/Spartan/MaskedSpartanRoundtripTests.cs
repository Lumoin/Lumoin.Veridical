using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using System.Numerics;

using static Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Completeness leg of the masked Spartan2 correctness gate:
/// for each instance shape, the masked prover constructs a proof
/// from a satisfying witness and the masked verifier accepts it.
/// </summary>
[TestClass]
internal sealed class MaskedSpartanRoundtripTests
{
    /// <summary>Pins that the masked prover and verifier round-trip successfully for a single-multiplication instance with a two-element Hyrax vector length.</summary>
    [TestMethod]
    public void TrivialInstanceRoundtrip()
    {
        ExerciseRoundtrip(BuildOneMultiplyInstance, BuildOneMultiplyWitness, hyraxVectorLength: 2);
    }


    /// <summary>Pins that the masked prover and verifier round-trip successfully for a two-multiplication instance with a four-element Hyrax vector length.</summary>
    [TestMethod]
    public void LargerInstanceRoundtrip()
    {
        ExerciseRoundtrip(BuildTwoMultiplyInstance, BuildTwoMultiplyWitness, hyraxVectorLength: 4);
    }


    /// <summary>Pins that the round trip also succeeds for a second, different satisfying witness of the same instance, so the prover's masking-polynomial sampling and the verifier's terminating-identity derivation are not over-fitted to one specific witness's algebra.</summary>
    [TestMethod]
    public void TrivialInstanceWithAlternativeWitnessRoundtrip()
    {
        //Different valid witness for the same instance — confirms the
        //prover's masking-polynomial sampling and the verifier's
        //terminating-identity derivation are not over-fitted to a
        //specific witness's algebra.
        ExerciseRoundtrip(BuildOneMultiplyInstance, BuildAlternativeOneMultiplyWitness, hyraxVectorLength: 2);
    }


    /// <summary>Pins that two independent prove-verify cycles for the same witness both succeed, so no hidden state in the prover or verifier — a static cache, an unreset transcript, a missing fresh-random draw — leaks from the first call into the second.</summary>
    [TestMethod]
    public void TwoSequentialProofsForSameWitnessBothVerify()
    {
        //Two independent prove-verify cycles back to back. Catches
        //hidden state in the prover or verifier that would break a
        //second invocation (a static cache, a non-reset transcript,
        //a missing fresh-random sample on the second call).
        ExerciseRoundtrip(BuildOneMultiplyInstance, BuildOneMultiplyWitness, hyraxVectorLength: 2);
        ExerciseRoundtrip(BuildOneMultiplyInstance, BuildOneMultiplyWitness, hyraxVectorLength: 2);
    }


    /// <summary>Produces a fresh <see cref="RawR1csInstance"/> for one round-trip exercise.</summary>
    /// <returns>The instance to prove and verify.</returns>
    private delegate RawR1csInstance RawInstanceFactory();

    /// <summary>Produces a fresh <see cref="RawR1csWitness"/> satisfying the matching <see cref="RawInstanceFactory"/> instance.</summary>
    /// <returns>The satisfying witness.</returns>
    private delegate RawR1csWitness RawWitnessFactory();


    /// <summary>Builds a masked prover and verifier sized to <paramref name="hyraxVectorLength"/>, proves the instance from <paramref name="instanceFactory"/> against the witness from <paramref name="witnessFactory"/> with a fresh transcript on each side, and asserts the verifier accepts the resulting proof.</summary>
    /// <param name="instanceFactory">Produces the R1CS instance to prove.</param>
    /// <param name="witnessFactory">Produces the satisfying witness.</param>
    /// <param name="hyraxVectorLength">The Hyrax commitment vector length the prover and verifier are built for.</param>
    private static void ExerciseRoundtrip(
        RawInstanceFactory instanceFactory,
        RawWitnessFactory witnessFactory,
        int hyraxVectorLength)
    {
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength);
        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(hyraxVectorLength);

        //The instance is a Prove/Verify parameter, not part of the key;
        //the prover and verifier each take their own copy built from
        //identical inputs.
        using RawR1csInstance proverInstance = instanceFactory();
        using RawR1csInstance verifierInstance = instanceFactory();
        using RawR1csWitness witness = witnessFactory();

        using FiatShamirTranscript proverTranscript = FreshTranscript();
        using MaskedSpartanProof proof = prover.Prove(
            proverInstance, witness, proverTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
            BaseMemoryPool.Shared);

        using FiatShamirTranscript verifierTranscript = FreshTranscript();
        bool verified = verifier.Verify(
            proof, verifierInstance, verifierTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze,
            BaseMemoryPool.Shared);

        Assert.IsTrue(verified, "Masked round-trip verification failed.");
    }
}
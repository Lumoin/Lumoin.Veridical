using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using System;
using System.Numerics;

using static Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Soundness leg of the masked Spartan2 correctness gate: a
/// cheating prover with a witness that does not satisfy the
/// constraints cannot produce an accepting proof. Distinct from
/// the failure-tests in <see cref="MaskedSpartanFailureTests"/>,
/// which tamper a valid proof's bytes; these tests start with an
/// invalid prover input and check the masked variant inherits the
/// base prover's soundness contract.
/// </summary>
[TestClass]
internal sealed class MaskedSpartanSoundnessTests
{
    [TestMethod]
    public void UnsatisfyingWitnessThrowsAtProveTime()
    {
        //Witness explicitly chosen to violate constraint 0: z[1]·z[2] = 3·5 = 15,
        //but z[3] = 99 in the witness. The R1CS-satisfaction check at the start
        //of Prove catches this and throws R1csNotSatisfiedException, matching
        //the base prover's behaviour.
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength: 2);
        using RawR1csInstance instance = BuildOneMultiplyInstance();
        using RawR1csWitness witness = BuildUnsatisfyingWitness();
        using FiatShamirTranscript transcript = FreshTranscript();

        Assert.ThrowsExactly<R1csNotSatisfiedException>(() =>
        {
            using MaskedSpartanProof _ = prover.Prove(
                instance, witness, transcript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
                G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
                BaseMemoryPool.Shared);
        });
    }


    [TestMethod]
    public void RandomFakeWitnessNeverProducesAcceptingProof()
    {
        //Fifty trials of fresh-random fake witnesses for the one-multiply
        //instance. Each fake witness has uniformly random scalar bytes;
        //the probability that random bytes satisfy z[1]·z[2] = z[3] AND
        //z[0]·z[0] = z[0] is negligible, so every trial should either
        //throw R1csNotSatisfiedException at prove time or, if some
        //pathological combination happens to satisfy the constraints,
        //produce a proof that verifies (which is the consistent case).
        //Zero accepting proofs from non-satisfying witnesses is the
        //test's actual gate; the satisfying-by-chance escape hatch is
        //documented for completeness only.
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength: 2);
        using MaskedSpartanVerifier verifier = BuildMaskedVerifier(hyraxVectorLength: 2);
        using RawR1csInstance proverInstance = BuildOneMultiplyInstance();
        using RawR1csInstance verifierInstance = BuildOneMultiplyInstance();

        int acceptingProofs = 0;
        int caughtAtProveTime = 0;

        for(int trial = 0; trial < 50; trial++)
        {
            using RawR1csWitness fakeWitness = SampleRandomWitness(trial);
            using FiatShamirTranscript proverTranscript = FreshTranscript();

            try
            {
                using MaskedSpartanProof proof = prover.Prove(
                    proverInstance, fakeWitness, proverTranscript,
                    Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
                    G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
                    BaseMemoryPool.Shared);

                //Prover did not throw — exceedingly unlikely for random
                //bytes — so it produced a proof. Run the verifier. Either
                //it accepts (meaning the fake witness happened to satisfy,
                //legitimate) or it rejects (meaning the prover would have
                //had to cheat and the cheat was caught downstream). For
                //random bytes the former has negligible probability.
                using FiatShamirTranscript verifierTranscript = FreshTranscript();
                if(verifier.Verify(
                    proof, verifierInstance, verifierTranscript,
                    Add, Multiply, Subtract, Invert, Reduce,
                    G1Add, G1ScalarMul, G1Msm, Hash, Squeeze,
                    BaseMemoryPool.Shared))
                {
                    acceptingProofs++;
                }
            }
            catch(R1csNotSatisfiedException)
            {
                caughtAtProveTime++;
            }
        }

        //Soundness is a computational property; a polynomial-time
        //cheating prover has negligible advantage. Across 50 trials of
        //random fake witnesses, zero accepting proofs is the expected
        //outcome — any accepting proof from a witness that does not
        //satisfy the constraints would be a soundness break worth
        //investigating. The test asserts the negative case directly.
        Assert.AreEqual(0, acceptingProofs,
            $"Soundness break: {acceptingProofs}/50 random fake witnesses produced an accepting proof. caught at prove time: {caughtAtProveTime}.");
    }


    [TestMethod]
    public void WitnessOffByOneInZeroSlotStillCaught()
    {
        //Edge case: a witness that's almost satisfying but off-by-one
        //in the multiplication's result slot. z = (1, 3, 5, 16) instead
        //of (1, 3, 5, 15). The R1CS check at prove time catches this.
        using MaskedSpartanProver prover = BuildMaskedProver(hyraxVectorLength: 2);
        using RawR1csInstance instance = BuildOneMultiplyInstance();

        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[3 * scalarSize];
        WriteCanonical(new BigInteger(3), witnessBytes.AsSpan(0 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(5), witnessBytes.AsSpan(1 * scalarSize, scalarSize));
        WriteCanonical(new BigInteger(16), witnessBytes.AsSpan(2 * scalarSize, scalarSize));
        using RawR1csWitness witness = RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);

        using FiatShamirTranscript transcript = FreshTranscript();

        Assert.ThrowsExactly<R1csNotSatisfiedException>(() =>
        {
            using MaskedSpartanProof _ = prover.Prove(
                instance, witness, transcript,
                Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, ScalarRandom,
                G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold,
                BaseMemoryPool.Shared);
        });
    }


    private static RawR1csWitness SampleRandomWitness(int trialIndex)
    {
        int scalarSize = Scalar.SizeBytes;
        byte[] witnessBytes = new byte[3 * scalarSize];
        //Deterministic per-trial: each trial's bytes are a hash of the
        //trial index. We don't use cryptographic randomness here; the
        //point is to exercise distinct unsatisfying witnesses, not to
        //statistically sample.
        for(int i = 0; i < 3 * scalarSize; i++)
        {
            witnessBytes[i] = (byte)((trialIndex * 251 + i * 17 + 37) % 256);
        }
        return RawR1csWitness.FromCanonical(witnessBytes, CurveParameterSet.Bls12Curve381, BaseMemoryPool.Shared);
    }
}
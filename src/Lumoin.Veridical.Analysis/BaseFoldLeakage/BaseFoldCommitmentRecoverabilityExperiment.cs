using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Analysis.BaseFoldLeakage;

/// <summary>
/// Experiment three: the structural leak. The proof carries a witness commitment
/// that is a deterministic Merkle root over the codeword <c>Enc(coeffs)</c>,
/// which is itself deterministic in the polynomial. So the commitment is a
/// deterministic fingerprint of the witness: given a candidate set, the witness
/// behind a proof is recovered by recomputing each candidate's commitment and
/// matching. This succeeds with certainty for a non-hiding (BaseFold) commitment
/// and needs no statistical detection — it is the definitive sense in which the
/// scheme is binding but not hiding.
/// </summary>
/// <remarks>
/// <para>
/// This realises the handoff's "Merkle-path-correlation" experiment through the
/// commitment root rather than the per-query authentication-path bytes. The root
/// is the binding commitment the whole codeword (hence every queried path) is
/// derived from, so it is the cleanest deterministic fingerprint; and the
/// per-query revealed entries are not extractable at the analysis layer without
/// depending on the commitment scheme's internal serialization, whereas the root
/// is a first-class public artifact. The structural conclusion is the same and
/// strictly stronger: the verifier learns enough to confirm any guessed witness.
/// </para>
/// <para>
/// A hiding commitment (Hyrax, with per-row blinding) would randomise the
/// commitment, so recomputation would not match and this experiment would report
/// <see cref="BaseFoldLeakageSignal.NotDetected"/> — which is the contrast the
/// demonstration is making.
/// </para>
/// </remarks>
public static class BaseFoldCommitmentRecoverabilityExperiment
{
    private const string Name = "commitment-recoverability";


    /// <summary>Runs the commitment-recoverability experiment at the given scale.</summary>
    /// <exception cref="ArgumentNullException">When <paramref name="harness"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    public static BaseFoldLeakageExperimentResult Run(BaseFoldLeakageHarness harness, int variableCount, int sampleCount)
    {
        ArgumentNullException.ThrowIfNull(harness);
        ArgumentOutOfRangeException.ThrowIfLessThan(variableCount, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(sampleCount, 2);

        var candidates = new MultilinearExtension[sampleCount];
        try
        {
            for(int i = 0; i < sampleCount; i++)
            {
                candidates[i] = harness.SamplePolynomial(variableCount);
            }

            //Determinism: the same witness must commit to the same bytes, or the
            //commitment is not a fingerprint at all.
            byte[] firstAgain = harness.CommitRoot(candidates[0]);
            byte[] firstOnce = harness.CommitRoot(candidates[0]);
            bool deterministic = firstOnce.AsSpan().SequenceEqual(firstAgain);

            //Pick a secret witness; its commitment is what an adversary sees.
            int secretIndex = sampleCount / 2;
            byte[] secretCommitment = harness.CommitRoot(candidates[secretIndex]);

            //Recover by recomputation: which candidates' commitments match?
            int matchCount = 0;
            int recoveredIndex = -1;
            for(int i = 0; i < sampleCount; i++)
            {
                byte[] candidateCommitment = harness.CommitRoot(candidates[i]);
                if(candidateCommitment.AsSpan().SequenceEqual(secretCommitment))
                {
                    matchCount++;
                    recoveredIndex = i;
                }
            }

            bool recovered = deterministic && matchCount == 1 && recoveredIndex == secretIndex;

            BaseFoldLeakageSignal signal = recovered ? BaseFoldLeakageSignal.StructurallyCertain : BaseFoldLeakageSignal.NotDetected;
            string summary = recovered
                ? $"Recovered the secret witness (index {secretIndex} of {sampleCount}) from its commitment alone by recomputation; the commitment is a deterministic, openable-by-guessing fingerprint of the witness."
                : deterministic
                    ? $"The commitment did not uniquely identify the secret among {sampleCount} candidates ({matchCount} matches)."
                    : "The commitment was not deterministic in the witness, so it is not a fingerprint (the provider appears to be hiding).";

            return new BaseFoldLeakageExperimentResult(Name, variableCount, sampleCount, signal, statisticalTest: null, observedMetric: null, baselineMetric: null, summary);
        }
        finally
        {
            foreach(MultilinearExtension candidate in candidates)
            {
                candidate?.Dispose();
            }
        }
    }
}

using Lumoin.Veridical.Core;
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Spartan;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

using static Lumoin.Veridical.Tests.Spartan.MaskedSpartanTestFixtures;

namespace Lumoin.Veridical.Tests.Spartan;

/// <summary>
/// Shared helpers for the <see cref="FoldChain"/> test gate. Wraps the
/// verbose Start/Step/Finalize delegate sets with the reference
/// backends from <see cref="MaskedSpartanTestFixtures"/>, leaving each
/// test to thread only the inputs that vary (the constraint system, the
/// statements, and the scalar-random source — production randomness for
/// the correctness legs, a deterministic seed for the byte-stability and
/// indistinguishability legs).
/// </summary>
internal static class FoldChainTestFixtures
{
    public static CurveParameterSet Curve { get; } = CurveParameterSet.Bls12Curve381;

    public static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// Derives a Hyrax commitment key with the canonical seed. The chain
    /// and the masked prover/verifier all derive byte-identical keys from
    /// the same <paramref name="vectorLength"/>, so the folded error
    /// commitment opens under the basis the compression uses.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of the derived key transfers to the caller's using declaration.")]
    public static HyraxCommitmentKey BuildCommitmentKey(int vectorLength)
    {
        return HyraxCommitmentKey.Derive(
            vectorLength,
            WellKnownHyraxDomainLabels.CanonicalSeedV1,
            Curve,
            HashToCurve,
            Pool);
    }


    /// <summary>Starts a fold chain (builds the blinding accumulator) with the reference backends. The provider is held non-owningly for the chain's lifetime.</summary>
    public static FoldChain StartChain(
        RawR1csInstance template,
        PolynomialCommitmentProvider provider,
        FiatShamirTranscript foldTranscript,
        ScalarRandomDelegate random)
    {
        return FoldChain.Start(
            template, provider, foldTranscript,
            Add, Subtract, Multiply, random, G1Msm, Pool);
    }


    /// <summary>Folds an already-prepared relaxed statement into the chain with the reference backends.</summary>
    public static void Step(FoldChain chain, RelaxedR1csAccumulator statement, ScalarRandomDelegate random)
    {
        chain.Step(
            statement.Instance, statement.Witness, statement.ErrorOpeningWitness,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, random,
            G1Add, G1ScalarMul, G1Msm, Pool);
    }


    /// <summary>Prepares a raw instance + witness into a relaxed statement and folds it into the chain.</summary>
    public static void StepRaw(FoldChain chain, RawR1csInstance rawInstance, RawR1csWitness rawWitness, ScalarRandomDelegate random)
    {
        using RelaxedR1csAccumulator statement = PrepareStatement(rawInstance, rawWitness);
        Step(chain, statement, random);
    }


    /// <summary>Compresses the chain's final accumulator to a masked Spartan proof with the reference backends.</summary>
    public static MaskedSpartanProof Compress(
        FoldChain chain,
        MaskedSpartanProver prover,
        FiatShamirTranscript compressionTranscript,
        ScalarRandomDelegate random)
    {
        return chain.Finalize(
            prover, compressionTranscript,
            Hash, Squeeze, Reduce, Add, Subtract, Multiply, Invert, random,
            G1Add, G1ScalarMul, G1Msm, MleEvaluate, MleFold, Pool);
    }


    /// <summary>Verifies a compressed proof against the chain's final folded instance with the reference backends.</summary>
    public static bool VerifyCompressed(
        MaskedSpartanVerifier verifier,
        MaskedSpartanProof proof,
        RelaxedR1csInstance finalInstance,
        FiatShamirTranscript verifyTranscript)
    {
        return verifier.Verify(
            proof, finalInstance, verifyTranscript,
            Add, Multiply, Subtract, Invert, Reduce,
            G1Add, G1ScalarMul, G1Msm, Hash, Squeeze, Pool);
    }


    /// <summary>
    /// Prepares a raw instance + witness into a relaxed statement
    /// (<c>u = 1</c>, zero error, identity error commitment, zero error
    /// opening witness) bundled as a <see cref="RelaxedR1csAccumulator"/>
    /// — the incoming-statement shape <see cref="FoldChain.Step"/>
    /// consumes. Owns and disposes the prepared trio; the raw inputs are
    /// disposed here.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000", Justification = "The raw instance and witness are disposed within this factory; the prepared relaxed objects transfer to the returned accumulator, which owns their disposal.")]
    public static RelaxedR1csAccumulator PrepareStatement(RawR1csInstance rawInstance, RawR1csWitness rawWitness)
    {
        using(rawInstance)
        using(rawWitness)
        {
            RelaxedR1csInstance instance = rawInstance.Prepare(Pool);
            RelaxedR1csWitness witness = rawWitness.Prepare(rawInstance.A.RowCount, Pool);

            //The error commitment has one Hyrax row per matrix-shape row; the blind
            //is one scalar per row, so its byte length is rowCount × scalar size.
            int rowVariableCount = System.Numerics.BitOperations.Log2((uint)rawInstance.A.RowCount);
            int errorCommitmentRowCount = HyraxCommitmentDimensions.ForVariableCount(rowVariableCount).RowCount;
            PolynomialCommitmentBlind errorOpeningWitness = PolynomialCommitmentBlind.CreateZero(
                errorCommitmentRowCount * Scalar.SizeBytes, Curve, CommitmentScheme.Hyrax, Pool);

            return new RelaxedR1csAccumulator(instance, witness, errorOpeningWitness);
        }
    }


    /// <summary>
    /// Reconstructs a <see cref="MaskedSpartanProof"/> over
    /// <paramref name="proofBytes"/> using <paramref name="template"/>'s
    /// dimension metadata. Used by the tamper and byte-stability legs to
    /// re-wrap mutated or captured proof bytes. A compressed fold proof
    /// shares the masked proof's layout, so the same metadata applies.
    /// </summary>
    public static MaskedSpartanProof RehydrateProof(byte[] proofBytes, MaskedSpartanProof template)
    {
        ArgumentNullException.ThrowIfNull(proofBytes);
        ArgumentNullException.ThrowIfNull(template);

        return MaskedSpartanProof.FromBytes(
            proofBytes,
            template.WitnessCommitmentRowCount,
            template.OuterMaskCommitmentRowCount,
            template.InnerMaskCommitmentRowCount,
            template.OuterRoundCount,
            template.InnerRoundCount,
            template.WitnessIpaRoundCount,
            template.OuterMaskIpaRoundCount,
            template.InnerMaskIpaRoundCount,
            template.ErrorIpaRoundCount,
            template.Curve,
            Pool);
    }
}
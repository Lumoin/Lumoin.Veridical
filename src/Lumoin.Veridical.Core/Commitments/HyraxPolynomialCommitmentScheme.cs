using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Adapts the Hyrax polynomial commitment to the scheme-agnostic
/// <see cref="PolynomialCommitmentProvider"/> surface. The factory
/// captures the commitment key and the algebraic / transcript backends
/// once; the three returned operations close over them, so Spartan
/// supplies only the per-call arguments (polynomial, point, transcript)
/// and never names a Hyrax type.
/// </summary>
/// <remarks>
/// <para>
/// The broad leaf types carry each artifact's canonical wire bytes — the
/// same bytes a <c>HyraxCommitment</c> / <c>HyraxOpeningProof</c> /
/// <c>HyraxOpeningWitness</c> exposes — so routing through this surface is
/// byte-identical to calling the Hyrax extension methods directly. The
/// matrix dimensions a Hyrax reconstruction needs are not carried on the
/// generic leaf type; they are derived at the boundary from the
/// polynomial's variable count (commit / open) or the evaluation point's
/// length (verify), exactly as the verifier already recovers shape today.
/// </para>
/// <para>
/// Mirrors how Microsoft Research's Spartan2 builds a concrete
/// <c>PCSEngineTrait</c> implementation behind the generic engine;
/// structural inspiration only, no code dependency. See microsoft/Spartan2.
/// </para>
/// </remarks>
public static class HyraxPolynomialCommitmentScheme
{
    /// <summary>
    /// Builds a Hyrax-backed provider over <paramref name="key"/>. The
    /// returned provider's <see cref="CommitmentScheme"/> is
    /// <see cref="CommitmentScheme.Hyrax"/> and its curve is
    /// <paramref name="curve"/>.
    /// </summary>
    /// <param name="key">The Hyrax commitment key the operations commit and open against.</param>
    /// <param name="curve">The curve every produced artifact is tagged with; must match <paramref name="key"/>.</param>
    /// <param name="hash">Fiat-Shamir absorb backend.</param>
    /// <param name="squeeze">Fiat-Shamir squeeze backend.</param>
    /// <param name="scalarReduce">Scalar reduction backend.</param>
    /// <param name="scalarAdd">Scalar addition backend.</param>
    /// <param name="scalarSubtract">Scalar subtraction backend.</param>
    /// <param name="scalarMul">Scalar multiplication backend.</param>
    /// <param name="scalarInvert">Scalar inversion backend.</param>
    /// <param name="scalarRandom">Scalar sampling backend (blinding factors).</param>
    /// <param name="g1Add">G1 addition backend.</param>
    /// <param name="g1ScalarMul">G1 scalar-multiplication backend.</param>
    /// <param name="g1Msm">G1 multi-scalar-multiplication backend.</param>
    /// <param name="ownsKey">
    /// When <see langword="true"/>, the returned provider takes ownership of
    /// <paramref name="key"/> and disposes it when the provider is disposed
    /// (the usual choice when a proving/verifying key holds the provider). When
    /// <see langword="false"/> (the default), the caller retains ownership of
    /// <paramref name="key"/>.
    /// </param>
    /// <returns>A provider whose commit / open / verify route to the Hyrax extension methods.</returns>
    /// <exception cref="ArgumentNullException">When any argument is null.</exception>
    public static PolynomialCommitmentProvider Create(
        HyraxCommitmentKey key,
        CurveParameterSet curve,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate scalarReduce,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMul,
        ScalarInvertDelegate scalarInvert,
        ScalarRandomDelegate scalarRandom,
        G1AddDelegate g1Add,
        G1ScalarMultiplyDelegate g1ScalarMul,
        G1MultiScalarMultiplyDelegate g1Msm,
        bool ownsKey = false)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(scalarReduce);
        ArgumentNullException.ThrowIfNull(scalarAdd);
        ArgumentNullException.ThrowIfNull(scalarSubtract);
        ArgumentNullException.ThrowIfNull(scalarMul);
        ArgumentNullException.ThrowIfNull(scalarInvert);
        ArgumentNullException.ThrowIfNull(scalarRandom);
        ArgumentNullException.ThrowIfNull(g1Add);
        ArgumentNullException.ThrowIfNull(g1ScalarMul);
        ArgumentNullException.ThrowIfNull(g1Msm);

        PolynomialCommitDelegate commit = (polynomial, pool) =>
        {
            (HyraxCommitment hyraxCommitment, HyraxOpeningWitness hyraxWitness) =
                key.CommitMultilinearExtension(polynomial, scalarRandom, g1Msm, pool);

            using(hyraxCommitment)
            using(hyraxWitness)
            {
                PolynomialCommitment commitment = PolynomialCommitment.FromBytes(
                    hyraxCommitment.AsReadOnlySpan(), curve, CommitmentScheme.Hyrax, pool);
                PolynomialCommitmentBlind blind = PolynomialCommitmentBlind.FromCanonical(
                    hyraxWitness.AsReadOnlySpan(), curve, CommitmentScheme.Hyrax, pool);

                return (commitment, blind);
            }
        };

        PolynomialOpenDelegate open = (commitment, blind, polynomial, evaluationPoint, transcript, pool) =>
        {
            //The committed polynomial's variable count fixes the Hyrax matrix
            //shape; the generic leaf type does not carry it, so re-derive it.
            HyraxCommitmentDimensions dimensions = HyraxCommitmentDimensions.ForVariableCount(polynomial.VariableCount);

            using HyraxCommitment hyraxCommitment = HyraxCommitment.FromBytes(
                commitment.AsReadOnlySpan(),
                dimensions.RowCount,
                dimensions.ColumnCount,
                polynomial.VariableCount,
                curve,
                pool);
            using HyraxOpeningWitness hyraxWitness = HyraxOpeningWitness.FromCanonical(
                blind.AsReadOnlySpan(), curve, pool);

            (HyraxOpeningProof hyraxProof, Scalar claimedValue) = hyraxCommitment.Open(
                hyraxWitness,
                polynomial,
                evaluationPoint,
                key,
                transcript,
                hash,
                squeeze,
                scalarReduce,
                scalarAdd,
                scalarSubtract,
                scalarMul,
                scalarInvert,
                scalarRandom,
                g1Add,
                g1ScalarMul,
                g1Msm,
                pool);

            using(hyraxProof)
            {
                PolynomialOpening opening = PolynomialOpening.FromBytes(
                    hyraxProof.AsReadOnlySpan(), curve, CommitmentScheme.Hyrax, pool);

                return (opening, claimedValue);
            }
        };

        PolynomialVerifyEvaluationDelegate verifyEvaluation = (commitment, evaluationPoint, claimedValue, opening, transcript, pool) =>
        {
            //On the verifier the evaluation point length is the variable count,
            //which fixes the matrix shape and the IPA round count the proof was
            //generated for (rounds = ⌈log2(ColumnCount)⌉ = VariableCount / 2).
            HyraxCommitmentDimensions dimensions = HyraxCommitmentDimensions.ForVariableCount(evaluationPoint.Length);
            int ipaRoundCount = evaluationPoint.Length / 2;

            using HyraxCommitment hyraxCommitment = HyraxCommitment.FromBytes(
                commitment.AsReadOnlySpan(),
                dimensions.RowCount,
                dimensions.ColumnCount,
                evaluationPoint.Length,
                curve,
                pool);
            using HyraxOpeningProof hyraxProof = HyraxOpeningProof.FromBytes(
                opening.AsReadOnlySpan(), ipaRoundCount, curve, pool);

            return hyraxCommitment.VerifyOpening(
                evaluationPoint,
                claimedValue,
                hyraxProof,
                key,
                transcript,
                hash,
                squeeze,
                scalarReduce,
                scalarAdd,
                scalarSubtract,
                scalarMul,
                scalarInvert,
                g1Add,
                g1ScalarMul,
                g1Msm,
                pool);
        };

        //The weighted-opening path (the statistical sumcheck mask's binding,
        //SM.7b): the vector is committed as ONE Pedersen row and the inner
        //product with a public weight vector is proven by the IPA directly —
        //an arbitrary weight vector does not factor through the matrix split
        //the evaluation opening uses.
        PolynomialCommitDelegate commitVector = (vector, pool) =>
        {
            (HyraxCommitment hyraxCommitment, HyraxOpeningWitness hyraxWitness) =
                key.CommitVector(vector, scalarRandom, g1Msm, pool);

            using(hyraxCommitment)
            using(hyraxWitness)
            {
                PolynomialCommitment commitment = PolynomialCommitment.FromBytes(
                    hyraxCommitment.AsReadOnlySpan(), curve, CommitmentScheme.Hyrax, pool);
                PolynomialCommitmentBlind blind = PolynomialCommitmentBlind.FromCanonical(
                    hyraxWitness.AsReadOnlySpan(), curve, CommitmentScheme.Hyrax, pool);

                return (commitment, blind);
            }
        };

        PolynomialOpenWeightedSumDelegate openWeightedSum = (commitment, blind, vector, weights, transcript, pool) =>
        {
            //A vector commitment is a single Pedersen row over every coordinate.
            using HyraxCommitment hyraxCommitment = HyraxCommitment.FromBytes(
                commitment.AsReadOnlySpan(),
                rowCount: 1,
                vector.EvaluationCount,
                vector.VariableCount,
                curve,
                pool);
            using HyraxOpeningWitness hyraxWitness = HyraxOpeningWitness.FromCanonical(
                blind.AsReadOnlySpan(), curve, pool);

            (HyraxOpeningProof hyraxProof, Scalar claimedValue) = hyraxCommitment.OpenWeightedSum(
                hyraxWitness,
                vector,
                weights,
                key,
                transcript,
                hash,
                squeeze,
                scalarReduce,
                scalarAdd,
                scalarSubtract,
                scalarMul,
                scalarInvert,
                scalarRandom,
                g1Add,
                g1ScalarMul,
                g1Msm,
                pool);

            using(hyraxProof)
            {
                PolynomialOpening opening = PolynomialOpening.FromBytes(
                    hyraxProof.AsReadOnlySpan(), curve, CommitmentScheme.Hyrax, pool);

                return (opening, claimedValue);
            }
        };

        PolynomialVerifyWeightedSumDelegate verifyWeightedSum = (commitment, weights, claimedValue, opening, transcript, pool) =>
        {
            //The IPA round count over the full-width single row is the weight
            //vector's variable count.
            using HyraxCommitment hyraxCommitment = HyraxCommitment.FromBytes(
                commitment.AsReadOnlySpan(),
                rowCount: 1,
                weights.EvaluationCount,
                weights.VariableCount,
                curve,
                pool);

            HyraxOpeningProof? hyraxProof = null;
            try
            {
                hyraxProof = HyraxOpeningProof.FromBytes(
                    opening.AsReadOnlySpan(), weights.VariableCount, curve, pool);
            }
            catch(ArgumentException)
            {
                //Malformed opening bytes are a rejection, not a fault.
                return false;
            }

            using(hyraxProof)
            {
                return hyraxCommitment.VerifyWeightedSum(
                    weights,
                    claimedValue,
                    hyraxProof,
                    key,
                    transcript,
                    hash,
                    squeeze,
                    scalarReduce,
                    scalarAdd,
                    scalarSubtract,
                    scalarMul,
                    scalarInvert,
                    g1Add,
                    g1ScalarMul,
                    g1Msm,
                    pool);
            }
        };

        return new PolynomialCommitmentProvider(
            CommitmentScheme.Hyrax, curve, commit, open, verifyEvaluation, ownsKey ? key : null,
            //Hyrax is a Pedersen-family scheme: per-row blinding factors make both
            //the commitment and the IPA opening hiding.
            queryCount: null, digestSizeBytes: null, isAdditivelyHomomorphic: true, isHiding: true,
            extraVariableCount: null, commitVector, openWeightedSum, verifyWeightedSum,
            //The Pedersen/IPA mask-shape ledger: no lift, filler covering the
            //IPA's cleartext functional reveals.
            resolveStatisticalMaskShape: static (d, degree) => BaseFold.WellKnownStatisticalMaskParameters.CreatePedersenIpa(d, degree));
    }
}

using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Verifies a <see cref="MaskedSpartanProof"/>. Replays the prover's
/// transcript schedule, runs the sumcheck verifier against the
/// blended rounds, verifies the witness and error openings and the two
/// mask weighted openings, and checks the masked terminating
/// identities for both sumchecks.
/// </summary>
/// <remarks>
/// <para>
/// The mask values <c>g_outer(r_x)</c> and <c>g_inner(r_y)</c> are not
/// embedded in the proof bytes as separate slots; the verifier derives
/// them algebraically by inverting the terminating-identity equation
/// from each sumcheck's final running claim, then checks ONE weighted
/// opening of the mask's committed coefficient vector against
/// <c>v = g(r) + σ_F</c> under the public weights it builds from the
/// mask basis and its own challenges (design v3 of
/// <c>ZK-STATMASK-DESIGN.md</c>). This keeps the proof wire
/// format compact and the verifier's side derivable from public data.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class MaskedSpartanVerifierExtensions
{
    extension(MaskedSpartanVerifier verifier)
    {
        /// <summary>
        /// Verifies a masked Spartan2 proof against the verifier's R1CS
        /// instance and Hyrax commitment key. Returns <see langword="true"/>
        /// iff every algebraic check passes.
        /// </summary>
        [SuppressMessage("Reliability", "CA2000", Justification = "Intermediate disposables flow through using declarations; the bool return path disposes everything before returning.")]
        public bool Verify(
            MaskedSpartanProof proof,
            RelaxedR1csInstance instance,
            FiatShamirTranscript transcript,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarSubtractDelegate scalarSubtract,
            ScalarInvertDelegate scalarInvert,
            ScalarReduceDelegate scalarReduce,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMultiply,
            G1MultiScalarMultiplyDelegate g1Msm,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(verifier);
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarMultiply);
            ArgumentNullException.ThrowIfNull(scalarSubtract);
            ArgumentNullException.ThrowIfNull(scalarInvert);
            ArgumentNullException.ThrowIfNull(scalarReduce);
            ArgumentNullException.ThrowIfNull(g1Add);
            ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
            ArgumentNullException.ThrowIfNull(g1Msm);
            ArgumentNullException.ThrowIfNull(hash);
            ArgumentNullException.ThrowIfNull(squeeze);
            ArgumentNullException.ThrowIfNull(pool);

            CurveParameterSet curve = instance.Curve;
            if(proof.Curve.Code != curve.Code)
            {
                throw new ArgumentException(
                    $"Proof curve {proof.Curve} does not match verifier curve {curve}.");
            }

            PolynomialCommitmentProvider pcs = verifier.VerifyingKey.Pcs;

            int rows = instance.A.RowCount;
            int columns = instance.A.ColumnCount;
            if(!BitOperations.IsPow2(rows) || !BitOperations.IsPow2(columns))
            {
                throw new ArgumentException(
                    $"Spartan requires power-of-two R1CS dimensions; instance has rows = {rows}, columns = {columns}.");
            }

            int rowVariableCount = BitOperations.Log2((uint)rows);
            int columnVariableCount = BitOperations.Log2((uint)columns);

            if(proof.OuterRoundCount != rowVariableCount)
            {
                throw new ArgumentException(
                    $"Proof outer-round count {proof.OuterRoundCount} does not match instance row variable count {rowVariableCount}.");
            }

            if(proof.InnerRoundCount != columnVariableCount)
            {
                throw new ArgumentException(
                    $"Proof inner-round count {proof.InnerRoundCount} does not match instance column variable count {columnVariableCount}.");
            }

            ThrowIfWeightedOpeningPathMissing(pcs);

            //The Hyrax commitment row counts are fixed by the variable counts;
            //this guard is Hyrax-shaped, so it lives in the Hyrax entry rather
            //than in the scheme-neutral VerifyCore. The masks are single-row
            //vector commitments whose IPA round counts are the policy-resolved
            //coefficient variable counts.
            HyraxCommitmentDimensions witnessDims = HyraxCommitmentDimensions.ForVariableCount(columnVariableCount);
            StatisticalMaskParameters outerMaskShape = pcs.ResolveStatisticalMaskShape!(rowVariableCount, WellKnownMaskedSpartanParameters.OuterMaskPerVariableDegree);
            StatisticalMaskParameters innerMaskShape = pcs.ResolveStatisticalMaskShape!(columnVariableCount, WellKnownMaskedSpartanParameters.InnerMaskPerVariableDegree);
            const int VectorCommitmentRowCount = 1;
            if(proof.WitnessCommitmentRowCount != witnessDims.RowCount
                || proof.OuterMaskCommitmentRowCount != VectorCommitmentRowCount
                || proof.InnerMaskCommitmentRowCount != VectorCommitmentRowCount
                || proof.OuterMaskIpaRoundCount != outerMaskShape.CoefficientVariableCount
                || proof.InnerMaskIpaRoundCount != innerMaskShape.CoefficientVariableCount)
            {
                throw new ArgumentException("Proof commitment dimensions do not match the verifying key's instance shape.");
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.SpartanVerifierVerify, curve);

            try
            {
                return VerifyCore(
                    proof.GetSumcheckPart(), proof, instance, transcript,
                    scalarAdd, scalarMultiply, scalarSubtract, scalarInvert, scalarReduce,
                    hash, squeeze, pool,
                    rowVariableCount, columnVariableCount, pcs, errorPcs: null);
            }
            catch(InvalidOperationException)
            {
                return false;
            }
            catch(ArgumentException)
            {
                return false;
            }
        }


        /// <summary>
        /// Convenience overload that verifies a masked proof against a
        /// <em>raw</em> R1CS instance: prepares the raw instance into its
        /// relaxed equivalent (<c>u = 1</c>, identity error commitment)
        /// and forwards to the relaxed <c>Verify</c>.
        /// </summary>
        [SuppressMessage("Reliability", "CA2000", Justification = "The prepared relaxed instance is disposed in the finally block once Verify returns.")]
        public bool Verify(
            MaskedSpartanProof proof,
            RawR1csInstance instance,
            FiatShamirTranscript transcript,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarSubtractDelegate scalarSubtract,
            ScalarInvertDelegate scalarInvert,
            ScalarReduceDelegate scalarReduce,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMultiply,
            G1MultiScalarMultiplyDelegate g1Msm,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(verifier);
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(pool);

            //Preparation is deterministic — no randomness needed; the
            //verifier reaches the same relaxed instance the prover prepared.
            RelaxedR1csInstance relaxedInstance = instance.Prepare(pool);
            try
            {
                return verifier.Verify(
                    proof, relaxedInstance, transcript,
                    scalarAdd, scalarMultiply, scalarSubtract, scalarInvert, scalarReduce,
                    g1Add, g1ScalarMultiply, g1Msm, hash, squeeze, pool);
            }
            finally
            {
                relaxedInstance.Dispose();
            }
        }


        /// <summary>
        /// Verifies a BaseFold-backed masked Spartan2 proof against a relaxed
        /// R1CS <paramref name="instance"/>. BaseFold is transparent (no group
        /// operations), so only field-arithmetic and transcript backends are
        /// needed; scalar inversion is used to derive the masking-polynomial
        /// values. <b>Hiding caveat:</b> see <see cref="BaseFoldMaskedSpartanProof"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the proof's curve or dimensions do not match the instance.</exception>
        public bool VerifyBaseFoldSound(
            BaseFoldMaskedSpartanProof proof,
            RelaxedR1csInstance instance,
            FiatShamirTranscript transcript,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarSubtractDelegate scalarSubtract,
            ScalarInvertDelegate scalarInvert,
            ScalarReduceDelegate scalarReduce,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(verifier);
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarMultiply);
            ArgumentNullException.ThrowIfNull(scalarSubtract);
            ArgumentNullException.ThrowIfNull(scalarInvert);
            ArgumentNullException.ThrowIfNull(scalarReduce);
            ArgumentNullException.ThrowIfNull(hash);
            ArgumentNullException.ThrowIfNull(squeeze);
            ArgumentNullException.ThrowIfNull(pool);

            CurveParameterSet curve = instance.Curve;
            if(proof.Curve.Code != curve.Code)
            {
                throw new ArgumentException($"Proof curve {proof.Curve} does not match verifier curve {curve}.");
            }

            int rows = instance.A.RowCount;
            int columns = instance.A.ColumnCount;
            if(!BitOperations.IsPow2(rows) || !BitOperations.IsPow2(columns))
            {
                throw new ArgumentException(
                    $"Spartan requires power-of-two R1CS dimensions; instance has rows = {rows}, columns = {columns}.");
            }

            int rowVariableCount = BitOperations.Log2((uint)rows);
            int columnVariableCount = BitOperations.Log2((uint)columns);

            if(proof.OuterRoundCount != rowVariableCount)
            {
                throw new ArgumentException(
                    $"Proof outer-round count {proof.OuterRoundCount} does not match instance row variable count {rowVariableCount}.");
            }

            if(proof.InnerRoundCount != columnVariableCount)
            {
                throw new ArgumentException(
                    $"Proof inner-round count {proof.InnerRoundCount} does not match instance column variable count {columnVariableCount}.");
            }

            PolynomialCommitmentProvider pcs = verifier.VerifyingKey.Pcs;
            ThrowIfWeightedOpeningPathMissing(pcs);

            CryptographicOperationCounters.Increment(CryptographicOperationKind.SpartanVerifierVerify, curve);

            try
            {
                return VerifyCore(
                    proof.GetSumcheckPart(), proof, instance, transcript,
                    scalarAdd, scalarMultiply, scalarSubtract, scalarInvert, scalarReduce,
                    hash, squeeze, pool,
                    rowVariableCount, columnVariableCount, pcs, errorPcs: null);
            }
            catch(InvalidOperationException)
            {
                return false;
            }
            catch(ArgumentException)
            {
                return false;
            }
        }


        /// <summary>
        /// Convenience overload that verifies a BaseFold-backed masked proof
        /// against a <em>raw</em> R1CS instance, preparing it through the same
        /// BaseFold provider the prover used.
        /// </summary>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        [SuppressMessage("Reliability", "CA2000", Justification = "The prepared relaxed instance is disposed in the finally block once VerifyBaseFoldSound returns.")]
        public bool VerifyBaseFoldSound(
            BaseFoldMaskedSpartanProof proof,
            RawR1csInstance instance,
            FiatShamirTranscript transcript,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarSubtractDelegate scalarSubtract,
            ScalarInvertDelegate scalarInvert,
            ScalarReduceDelegate scalarReduce,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(verifier);
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(pool);

            RelaxedR1csInstance relaxedInstance = instance.Prepare(verifier.VerifyingKey.Pcs, pool);
            try
            {
                return verifier.VerifyBaseFoldSound(
                    proof, relaxedInstance, transcript,
                    scalarAdd, scalarMultiply, scalarSubtract, scalarInvert, scalarReduce, hash, squeeze, pool);
            }
            finally
            {
                relaxedInstance.Dispose();
            }
        }


        /// <summary>
        /// Verifies a genuinely zero-knowledge BaseFold-backed masked Spartan2
        /// proof (<see cref="ZkBaseFoldMaskedSpartanProof"/>) against a relaxed R1CS
        /// <paramref name="instance"/>. Identical to
        /// <see cref="VerifyBaseFoldSound(MaskedSpartanVerifier, BaseFoldMaskedSpartanProof, RelaxedR1csInstance, FiatShamirTranscript, ScalarAddDelegate, ScalarMultiplyDelegate, ScalarSubtractDelegate, ScalarInvertDelegate, ScalarReduceDelegate, FiatShamirHashDelegate, FiatShamirSqueezeDelegate, BaseMemoryPool)"/>
        /// except the embedded openings are full-ZK (lifted and masked); the
        /// scheme-neutral verifier core checks them through the verifying key's
        /// full-ZK provider, which routes to the ZK opening verification.
        /// </summary>
        /// <param name="proof">The zero-knowledge BaseFold-backed masked Spartan2 proof to verify.</param>
        /// <param name="instance">The relaxed R1CS instance the proof claims satisfaction of.</param>
        /// <param name="transcript">The Fiat-Shamir transcript.</param>
        /// <param name="scalarAdd">Backend scalar addition.</param>
        /// <param name="scalarMultiply">Backend scalar multiplication.</param>
        /// <param name="scalarSubtract">Backend scalar subtraction.</param>
        /// <param name="scalarInvert">Backend scalar inversion.</param>
        /// <param name="scalarReduce">Backend scalar reduction.</param>
        /// <param name="hash">The Fiat-Shamir hash.</param>
        /// <param name="squeeze">The Fiat-Shamir squeeze.</param>
        /// <param name="errorPcs">A plain (non-hiding) BaseFold provider over the same code parameters, matching the one the prover used for the public zero-error vector.</param>
        /// <param name="pool">The pool to rent the working buffers from.</param>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the proof's curve or dimensions do not match the instance.</exception>
        public bool VerifyZkBaseFold(
            ZkBaseFoldMaskedSpartanProof proof,
            RelaxedR1csInstance instance,
            FiatShamirTranscript transcript,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarSubtractDelegate scalarSubtract,
            ScalarInvertDelegate scalarInvert,
            ScalarReduceDelegate scalarReduce,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            PolynomialCommitmentProvider errorPcs,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(verifier);
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarMultiply);
            ArgumentNullException.ThrowIfNull(scalarSubtract);
            ArgumentNullException.ThrowIfNull(scalarInvert);
            ArgumentNullException.ThrowIfNull(scalarReduce);
            ArgumentNullException.ThrowIfNull(hash);
            ArgumentNullException.ThrowIfNull(squeeze);
            ArgumentNullException.ThrowIfNull(errorPcs);
            ArgumentNullException.ThrowIfNull(pool);

            CurveParameterSet curve = instance.Curve;
            if(proof.Curve.Code != curve.Code)
            {
                throw new ArgumentException($"Proof curve {proof.Curve} does not match verifier curve {curve}.");
            }

            int rows = instance.A.RowCount;
            int columns = instance.A.ColumnCount;
            if(!BitOperations.IsPow2(rows) || !BitOperations.IsPow2(columns))
            {
                throw new ArgumentException(
                    $"Spartan requires power-of-two R1CS dimensions; instance has rows = {rows}, columns = {columns}.");
            }

            int rowVariableCount = BitOperations.Log2((uint)rows);
            int columnVariableCount = BitOperations.Log2((uint)columns);

            if(proof.OuterRoundCount != rowVariableCount)
            {
                throw new ArgumentException(
                    $"Proof outer-round count {proof.OuterRoundCount} does not match instance row variable count {rowVariableCount}.");
            }

            if(proof.InnerRoundCount != columnVariableCount)
            {
                throw new ArgumentException(
                    $"Proof inner-round count {proof.InnerRoundCount} does not match instance column variable count {columnVariableCount}.");
            }

            PolynomialCommitmentProvider pcs = verifier.VerifyingKey.Pcs;
            ThrowIfWeightedOpeningPathMissing(pcs);

            //The full-ZK masked path only achieves zero-knowledge over a hiding
            //provider; a non-hiding provider here is the privacy footgun, so
            //refuse it loudly rather than accepting a sound-only proof as ZK.
            if(!pcs.IsHiding)
            {
                throw new InvalidOperationException(
                    $"VerifyZkBaseFold requires a hiding provider (a full-ZK BaseFold provider); the provider's scheme is {pcs.Scheme}.");
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.SpartanVerifierVerify, curve);

            try
            {
                return VerifyCore(
                    proof.GetSumcheckPart(), proof, instance, transcript,
                    scalarAdd, scalarMultiply, scalarSubtract, scalarInvert, scalarReduce,
                    hash, squeeze, pool,
                    rowVariableCount, columnVariableCount, pcs, errorPcs);
            }
            catch(InvalidOperationException)
            {
                return false;
            }
            catch(ArgumentException)
            {
                return false;
            }
        }


        /// <summary>
        /// Convenience overload that verifies a full-ZK BaseFold-backed masked proof
        /// against a <em>raw</em> R1CS instance, preparing it through the same
        /// full-ZK BaseFold provider the prover used.
        /// </summary>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        [SuppressMessage("Reliability", "CA2000", Justification = "The prepared relaxed instance is disposed in the finally block once VerifyZkBaseFold returns.")]
        public bool VerifyZkBaseFold(
            ZkBaseFoldMaskedSpartanProof proof,
            RawR1csInstance instance,
            FiatShamirTranscript transcript,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarSubtractDelegate scalarSubtract,
            ScalarInvertDelegate scalarInvert,
            ScalarReduceDelegate scalarReduce,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            PolynomialCommitmentProvider errorPcs,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(verifier);
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(errorPcs);
            ArgumentNullException.ThrowIfNull(pool);

            //Recompute the public zero-error commitment through the plain provider,
            //matching the prover, so the deterministic commitment agrees.
            RelaxedR1csInstance relaxedInstance = instance.Prepare(errorPcs, pool);
            try
            {
                return verifier.VerifyZkBaseFold(
                    proof, relaxedInstance, transcript,
                    scalarAdd, scalarMultiply, scalarSubtract, scalarInvert, scalarReduce, hash, squeeze, errorPcs, pool);
            }
            finally
            {
                relaxedInstance.Dispose();
            }
        }
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "Intermediate disposables flow through using declarations.")]
    private static bool VerifyCore(
        SpartanSumcheckProofPart sumcheckPart,
        IMaskedSpartanProofView view,
        RelaxedR1csInstance instance,
        FiatShamirTranscript transcript,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarSubtractDelegate scalarSubtract,
        ScalarInvertDelegate scalarInvert,
        ScalarReduceDelegate scalarReduce,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        BaseMemoryPool pool,
        int rowVariableCount,
        int columnVariableCount,
        PolynomialCommitmentProvider pcs,
        PolynomialCommitmentProvider? errorPcs)
    {
        //The mask-value derivation needs scalar inversion (of the blending
        //scalars); the opening verification's group operations are captured
        //inside the provider's VerifyEvaluation delegate, so the core needs no
        //G1 backends.
        int scalarSize = Scalar.SizeBytes;
        CurveParameterSet curve = instance.Curve;

        //The public zero error is verified through the plain provider (its
        //commitment is recomputed deterministically, see ProveZkBaseFold); the
        //witness and masks use the hiding pcs. Non-ZK callers pass null and the
        //single provider serves both.
        PolynomialCommitmentProvider effectiveErrorPcs = errorPcs ?? pcs;

        transcript.AbsorbRelaxedR1csInstance(instance, hash);

        //Decode the three commitments and absorb them in the order the prover
        //did: witness, outer mask, inner mask.
        using PolynomialCommitment witnessCommitment = PolynomialCommitment.FromBytes(
            view.GetWitnessCommitmentBytes(), curve, pcs.Scheme, pool);
        using PolynomialCommitment outerMaskCommitment = PolynomialCommitment.FromBytes(
            view.GetOuterMaskCommitmentBytes(), curve, pcs.Scheme, pool);
        using PolynomialCommitment innerMaskCommitment = PolynomialCommitment.FromBytes(
            view.GetInnerMaskCommitmentBytes(), curve, pcs.Scheme, pool);

        transcript.AbsorbBytes(
            new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.WitnessCommitment),
            witnessCommitment.AsReadOnlySpan(), hash);
        transcript.AbsorbBytes(
            new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.OuterMaskCommitment),
            outerMaskCommitment.AsReadOnlySpan(), hash);
        transcript.AbsorbBytes(
            new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.InnerMaskCommitment),
            innerMaskCommitment.AsReadOnlySpan(), hash);

        //Absorb σ_outer, σ_inner, and the two filler sums σ_F from the proof
        //bytes — all pre-ρ, mirroring the prover, so the weighted-opening
        //claims are fixed by the commitments.
        ReadOnlySpan<byte> zOuterBytes = view.GetOuterMaskSumBytes();
        ReadOnlySpan<byte> zInnerBytes = view.GetInnerMaskSumBytes();

        transcript.AbsorbBytes(
            new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.OuterMaskSum),
            zOuterBytes, hash);
        transcript.AbsorbBytes(
            new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.InnerMaskSum),
            zInnerBytes, hash);
        transcript.AbsorbBytes(
            new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.OuterMaskFillerSum),
            view.GetOuterMaskFillerSumBytes(), hash);
        transcript.AbsorbBytes(
            new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.InnerMaskFillerSum),
            view.GetInnerMaskFillerSumBytes(), hash);

        using Scalar rhoOuter = transcript.SqueezeScalar(
            new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.OuterBlendingChallenge),
            squeeze, hash, scalarReduce, curve, pool);
        using Scalar rhoInner = transcript.SqueezeScalar(
            new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.InnerBlendingChallenge),
            squeeze, hash, scalarReduce, curve, pool);

        //Squeeze τ.
        Scalar[] tauScalars = SqueezeChallenges(
            transcript, rowVariableCount, WellKnownSpartanTranscriptLabels.OuterTau,
            squeeze, hash, scalarReduce, curve, pool);

        try
        {
            //Initial outer-sumcheck claim = ρ_outer · z_outer (base initial is 0).
            using Scalar zOuter = Scalar.FromCanonical(zOuterBytes, curve, pool);
            using Scalar outerInitialClaim = MultiplyScalars(rhoOuter, zOuter, scalarMultiply, pool);

            ReadOnlySpan<byte> ProofOuterAccessor(int i) => sumcheckPart.GetOuterRoundCompressedBytes(i);

            using SumcheckVerifierResult outer = SumcheckVerifierCore.Run(
                rowVariableCount, expectedDegree: 3,
                ProofOuterAccessor,
                outerInitialClaim, transcript,
                hash, squeeze, scalarReduce,
                scalarAdd, scalarSubtract, scalarMultiply, pool);

            //Absorb the three outer terminating claims, then E(r_x).
            Span<byte> claimsBuffer = stackalloc byte[3 * scalarSize];
            sumcheckPart.GetClaimAzBytes().CopyTo(claimsBuffer[..scalarSize]);
            sumcheckPart.GetClaimBzBytes().CopyTo(claimsBuffer.Slice(scalarSize, scalarSize));
            sumcheckPart.GetClaimCzBytes().CopyTo(claimsBuffer.Slice(2 * scalarSize, scalarSize));
            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.OuterClaimedEvaluations),
                claimsBuffer, hash);

            ReadOnlySpan<byte> errorEvalBytes = sumcheckPart.GetErrorEvaluationBytes();
            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.OuterErrorEvaluation),
                errorEvalBytes, hash);

            using Scalar errorEval = Scalar.FromCanonical(errorEvalBytes, curve, pool);

            using Scalar r = transcript.SqueezeScalar(
                new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.InnerCombinationChallenge),
                squeeze, hash, scalarReduce, curve, pool);

            using Scalar claimAz = Scalar.FromCanonical(sumcheckPart.GetClaimAzBytes(), curve, pool);
            using Scalar claimBz = Scalar.FromCanonical(sumcheckPart.GetClaimBzBytes(), curve, pool);
            using Scalar claimCz = Scalar.FromCanonical(sumcheckPart.GetClaimCzBytes(), curve, pool);

            //joint = claim_Az + r · claim_Bz + r² · claim_Cz.
            using Scalar rSquared = MultiplyScalars(r, r, scalarMultiply, pool);
            using IMemoryOwner<byte> jointBytesOwner = pool.Rent(scalarSize);
            Span<byte> jointBytes = jointBytesOwner.Memory.Span[..scalarSize];
            using IMemoryOwner<byte> termBytesOwner = pool.Rent(scalarSize);
            Span<byte> termBytes = termBytesOwner.Memory.Span[..scalarSize];

            claimAz.AsReadOnlySpan().CopyTo(jointBytes);
            scalarMultiply(r.AsReadOnlySpan(), claimBz.AsReadOnlySpan(), termBytes, curve);
            scalarAdd(jointBytes, termBytes, jointBytes, curve);
            scalarMultiply(rSquared.AsReadOnlySpan(), claimCz.AsReadOnlySpan(), termBytes, curve);
            scalarAdd(jointBytes, termBytes, jointBytes, curve);

            //Initial inner claim = joint + ρ_inner · z_inner.
            using Scalar zInner = Scalar.FromCanonical(zInnerBytes, curve, pool);
            using IMemoryOwner<byte> rhoInnerZInnerOwner = pool.Rent(scalarSize);
            Span<byte> rhoInnerZInner = rhoInnerZInnerOwner.Memory.Span[..scalarSize];
            scalarMultiply(rhoInner.AsReadOnlySpan(), zInner.AsReadOnlySpan(), rhoInnerZInner, curve);
            using IMemoryOwner<byte> innerInitialBytesOwner = pool.Rent(scalarSize);
            Span<byte> innerInitialBytes = innerInitialBytesOwner.Memory.Span[..scalarSize];
            scalarAdd(jointBytes, rhoInnerZInner, innerInitialBytes, curve);
            using Scalar innerInitialClaim = Scalar.FromCanonical(innerInitialBytes, curve, pool);

            ReadOnlySpan<byte> ProofInnerAccessor(int i) => sumcheckPart.GetInnerRoundCompressedBytes(i);

            using SumcheckVerifierResult inner = SumcheckVerifierCore.Run(
                columnVariableCount, expectedDegree: 2,
                ProofInnerAccessor,
                innerInitialClaim, transcript,
                hash, squeeze, scalarReduce,
                scalarAdd, scalarSubtract, scalarMultiply, pool);

            //Absorb eval_W.
            ReadOnlySpan<byte> evalWBytes = sumcheckPart.GetEvalWBytes();
            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.WitnessEvaluation),
                evalWBytes, hash);

            using Scalar evalW = Scalar.FromCanonical(evalWBytes, curve, pool);

            //Reconstruct the four opening proofs (error first, then the
            //two masks, then the witness — the prover's order).
            using PolynomialOpening errorOpeningProof = PolynomialOpening.FromBytes(
                view.GetErrorOpeningProofBytes(), curve, pcs.Scheme, pool);
            using PolynomialOpening outerMaskOpening = PolynomialOpening.FromBytes(
                view.GetOuterMaskOpeningProofBytes(), curve, pcs.Scheme, pool);
            using PolynomialOpening innerMaskOpening = PolynomialOpening.FromBytes(
                view.GetInnerMaskOpeningProofBytes(), curve, pcs.Scheme, pool);
            using PolynomialOpening witnessOpening = PolynomialOpening.FromBytes(
                view.GetWitnessOpeningProofBytes(), curve, pcs.Scheme, pool);

            Scalar[] rxArray = ToScalarArray(outer.Challenges, pool);
            Scalar[] ryArray = ToScalarArray(inner.Challenges, pool);
            try
            {
                //Verify the error commitment opens to E(r_x) at r_x. Runs
                //first on the transcript, matching the prover.
                bool errorCheck = effectiveErrorPcs.VerifyEvaluation(
                    instance.ErrorCommitment, rxArray, errorEval, errorOpeningProof, transcript, pool);

                //Outer terminating identity (relaxed):
                //  outer.FinalClaim == eq(τ, r_x) · (claim_Az · claim_Bz − u · claim_Cz − E(r_x))
                //                      + ρ_outer · g_outer(r_x).
                //Derive g_outer(r_x) by inverting:
                //  ρ_outer · g_outer(r_x) = outer.FinalClaim − eq(τ, r_x) · (claim_Az · claim_Bz − u · claim_Cz − E(r_x)).
                using Scalar eqAtRx = EvaluateEq(
                    tauScalars, rxArray, scalarAdd, scalarSubtract, scalarMultiply, curve, pool);

                using IMemoryOwner<byte> baseOuterTermOwner = pool.Rent(scalarSize);
                Span<byte> baseOuterTerm = baseOuterTermOwner.Memory.Span[..scalarSize];
                scalarMultiply(claimAz.AsReadOnlySpan(), claimBz.AsReadOnlySpan(), termBytes, curve);
                scalarMultiply(instance.GetUBytes(), claimCz.AsReadOnlySpan(), baseOuterTerm, curve);
                scalarSubtract(termBytes, baseOuterTerm, termBytes, curve);
                scalarSubtract(termBytes, errorEval.AsReadOnlySpan(), termBytes, curve);
                scalarMultiply(eqAtRx.AsReadOnlySpan(), termBytes, baseOuterTerm, curve);

                using IMemoryOwner<byte> outerMaskContribOwner = pool.Rent(scalarSize);
                Span<byte> outerMaskContrib = outerMaskContribOwner.Memory.Span[..scalarSize];
                scalarSubtract(outer.FinalClaim.AsReadOnlySpan(), baseOuterTerm, outerMaskContrib, curve);

                using IMemoryOwner<byte> rhoOuterInvOwner = pool.Rent(scalarSize);
                Span<byte> rhoOuterInv = rhoOuterInvOwner.Memory.Span[..scalarSize];
                scalarInvert(rhoOuter.AsReadOnlySpan(), rhoOuterInv, curve);

                //The weighted-opening claim is v = g_outer(r_x) + σ_F: the chain
                //derives the mask's terminal value and the precommitted filler
                //sum shifts it onto the all-ones-weighted filler block (design
                //v3). The weights live at the kernel's REVERSED point (the
                //variable-order convention of MaskedSpartanAlgorithm).
                using IMemoryOwner<byte> derivedOuterClaimOwner = pool.Rent(scalarSize);
                Span<byte> derivedOuterClaim = derivedOuterClaimOwner.Memory.Span[..scalarSize];
                scalarMultiply(outerMaskContrib, rhoOuterInv, derivedOuterClaim, curve);
                scalarAdd(derivedOuterClaim, view.GetOuterMaskFillerSumBytes(), derivedOuterClaim, curve);
                using Scalar outerWeightedClaim = Scalar.FromCanonical(derivedOuterClaim, curve, pool);

                StatisticalMaskParameters outerShape = pcs.ResolveStatisticalMaskShape!(rowVariableCount, WellKnownMaskedSpartanParameters.OuterMaskPerVariableDegree);
                MonomialBasis outerBasis = MonomialBasis.SumOfUnivariatesWithPad(
                    rowVariableCount, padPairCount: 0, WellKnownMaskedSpartanParameters.OuterMaskPerVariableDegree);
                Scalar[] outerKernelPoint = MaskedSpartanAlgorithm.BuildReversedPoint(rxArray);
                using MultilinearExtension outerWeights = MaskedSpartanAlgorithm.BuildMaskWeights(
                    outerBasis, outerShape, outerKernelPoint, scalarMultiply, curve, pool);

                bool outerMaskCheck = pcs.VerifyWeightedSum!(
                    outerMaskCommitment, outerWeights, outerWeightedClaim, outerMaskOpening, transcript, pool);

                //Inner terminating identity:
                //  inner.FinalClaim == [A~(r_x,r_y) + r·B~ + r²·C~] · eval_Z
                //                      + ρ_inner · g_inner(r_y).
                using Scalar evalPublicAndU = EvalPublicAndOneComputation.Compute(
                    instance.GetUBytes(), instance.GetPublicInputsBytes(), instance.PublicInputCount, columnVariableCount, ryArray,
                    scalarAdd, scalarSubtract, scalarMultiply, curve, pool);

                using IMemoryOwner<byte> evalZOwner = pool.Rent(scalarSize);
                Span<byte> evalZBytes = evalZOwner.Memory.Span[..scalarSize];
                scalarAdd(evalW.AsReadOnlySpan(), evalPublicAndU.AsReadOnlySpan(), evalZBytes, curve);

                using MatrixMleEvaluationOwner aMatrix = MatrixMleEvaluationOwner.From(instance.A);
                using MatrixMleEvaluationOwner bMatrix = MatrixMleEvaluationOwner.From(instance.B);
                using MatrixMleEvaluationOwner cMatrix = MatrixMleEvaluationOwner.From(instance.C);

                using Scalar evalA = aMatrix.View.Evaluate(rxArray, ryArray, scalarAdd, scalarSubtract, scalarMultiply, pool);
                using Scalar evalB = bMatrix.View.Evaluate(rxArray, ryArray, scalarAdd, scalarSubtract, scalarMultiply, pool);
                using Scalar evalC = cMatrix.View.Evaluate(rxArray, ryArray, scalarAdd, scalarSubtract, scalarMultiply, pool);

                //evalAbc = evalA + r·evalB + r²·evalC.
                using IMemoryOwner<byte> evalAbcOwner = pool.Rent(scalarSize);
                Span<byte> evalAbcBytes = evalAbcOwner.Memory.Span[..scalarSize];
                evalA.AsReadOnlySpan().CopyTo(evalAbcBytes);
                scalarMultiply(r.AsReadOnlySpan(), evalB.AsReadOnlySpan(), termBytes, curve);
                scalarAdd(evalAbcBytes, termBytes, evalAbcBytes, curve);
                scalarMultiply(rSquared.AsReadOnlySpan(), evalC.AsReadOnlySpan(), termBytes, curve);
                scalarAdd(evalAbcBytes, termBytes, evalAbcBytes, curve);

                using IMemoryOwner<byte> baseInnerTermOwner = pool.Rent(scalarSize);
                Span<byte> baseInnerTerm = baseInnerTermOwner.Memory.Span[..scalarSize];
                scalarMultiply(evalAbcBytes, evalZBytes, baseInnerTerm, curve);

                using IMemoryOwner<byte> innerMaskContribOwner = pool.Rent(scalarSize);
                Span<byte> innerMaskContrib = innerMaskContribOwner.Memory.Span[..scalarSize];
                scalarSubtract(inner.FinalClaim.AsReadOnlySpan(), baseInnerTerm, innerMaskContrib, curve);

                using IMemoryOwner<byte> rhoInnerInvOwner = pool.Rent(scalarSize);
                Span<byte> rhoInnerInv = rhoInnerInvOwner.Memory.Span[..scalarSize];
                scalarInvert(rhoInner.AsReadOnlySpan(), rhoInnerInv, curve);

                //v = g_inner(r_y) + σ_F, bound exactly as the outer mask.
                using IMemoryOwner<byte> derivedInnerClaimOwner = pool.Rent(scalarSize);
                Span<byte> derivedInnerClaim = derivedInnerClaimOwner.Memory.Span[..scalarSize];
                scalarMultiply(innerMaskContrib, rhoInnerInv, derivedInnerClaim, curve);
                scalarAdd(derivedInnerClaim, view.GetInnerMaskFillerSumBytes(), derivedInnerClaim, curve);
                using Scalar innerWeightedClaim = Scalar.FromCanonical(derivedInnerClaim, curve, pool);

                StatisticalMaskParameters innerShape = pcs.ResolveStatisticalMaskShape!(columnVariableCount, WellKnownMaskedSpartanParameters.InnerMaskPerVariableDegree);
                MonomialBasis innerBasis = MonomialBasis.SumOfUnivariatesWithPad(
                    columnVariableCount, padPairCount: 0, WellKnownMaskedSpartanParameters.InnerMaskPerVariableDegree);
                Scalar[] innerKernelPoint = MaskedSpartanAlgorithm.BuildReversedPoint(ryArray);
                using MultilinearExtension innerWeights = MaskedSpartanAlgorithm.BuildMaskWeights(
                    innerBasis, innerShape, innerKernelPoint, scalarMultiply, curve, pool);

                bool innerMaskCheck = pcs.VerifyWeightedSum!(
                    innerMaskCommitment, innerWeights, innerWeightedClaim, innerMaskOpening, transcript, pool);

                bool witnessCheck = pcs.VerifyEvaluation(
                    witnessCommitment, ryArray, evalW, witnessOpening, transcript, pool);

                return errorCheck && outerMaskCheck && innerMaskCheck && witnessCheck;
            }
            finally
            {
                DisposeAll(rxArray);
                DisposeAll(ryArray);
            }
        }
        finally
        {
            DisposeAll(tauScalars);
        }
    }


    private readonly struct MatrixMleEvaluationOwner: IDisposable
    {
        public MatrixMleEvaluation View { get; }
        private MatrixMleEvaluationOwner(MatrixMleEvaluation view) { View = view; }
        public static MatrixMleEvaluationOwner From(R1csMatrix matrix) => new(new MatrixMleEvaluation(matrix));
        public void Dispose() { }
    }


    //The statistical-mask binding needs the provider's weighted-opening path; a
    //missing wiring is a configuration fault to surface loudly, not an
    //adversarial input to reject quietly.
    private static void ThrowIfWeightedOpeningPathMissing(PolynomialCommitmentProvider pcs)
    {
        if(pcs.VerifyWeightedSum is null || pcs.ResolveStatisticalMaskShape is null)
        {
            throw new InvalidOperationException(
                $"Masked Spartan verification requires a provider with a weighted-opening path (VerifyWeightedSum and ResolveStatisticalMaskShape); the provider's scheme is {pcs.Scheme}.");
        }
    }


    private static Scalar[] SqueezeChallenges(
        FiatShamirTranscript transcript,
        int count,
        string label,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        Scalar[] scalars = new Scalar[count];
        for(int i = 0; i < count; i++)
        {
            scalars[i] = transcript.SqueezeScalar(
                new FiatShamirOperationLabel(label),
                squeeze, hash, reduce, curve, pool);
        }

        return scalars;
    }


    private static Scalar[] ToScalarArray(IReadOnlyList<Scalar> source, BaseMemoryPool pool)
    {
        Scalar[] result = new Scalar[source.Count];
        for(int i = 0; i < source.Count; i++)
        {
            result[i] = Scalar.FromCanonical(source[i].AsReadOnlySpan(), source[i].Curve, pool);
        }

        return result;
    }


    private static void DisposeAll(Scalar[] scalars)
    {
        for(int i = 0; i < scalars.Length; i++)
        {
            scalars[i]?.Dispose();
        }
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The returned scalar transfers ownership to the caller.")]
    private static Scalar MultiplyScalars(
        Scalar a,
        Scalar b,
        ScalarMultiplyDelegate scalarMultiply,
        BaseMemoryPool pool)
    {
        int scalarSize = Scalar.SizeBytes;
        IMemoryOwner<byte> owner = pool.Rent(scalarSize);
        scalarMultiply(a.AsReadOnlySpan(), b.AsReadOnlySpan(), owner.Memory.Span[..scalarSize], a.Curve);
        return new Scalar(owner, a.Curve, WellKnownAlgebraicTags.ScalarFor(a.Curve));
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The returned scalar transfers ownership to the caller.")]
    private static Scalar EvaluateEq(
        ReadOnlySpan<Scalar> tau,
        ReadOnlySpan<Scalar> rx,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMultiply,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int scalarSize = Scalar.SizeBytes;

        IMemoryOwner<byte> resultOwner = pool.Rent(scalarSize);
        Span<byte> result = resultOwner.Memory.Span[..scalarSize];
        result.Clear();
        result[^1] = 0x01;

        Span<byte> fieldOne = stackalloc byte[scalarSize];
        fieldOne.Clear();
        fieldOne[^1] = 0x01;

        Span<byte> oneMinusTau = stackalloc byte[scalarSize];
        Span<byte> oneMinusRx = stackalloc byte[scalarSize];
        Span<byte> termA = stackalloc byte[scalarSize];
        Span<byte> termB = stackalloc byte[scalarSize];
        Span<byte> factor = stackalloc byte[scalarSize];

        for(int i = 0; i < tau.Length; i++)
        {
            scalarSubtract(fieldOne, tau[i].AsReadOnlySpan(), oneMinusTau, curve);
            scalarSubtract(fieldOne, rx[i].AsReadOnlySpan(), oneMinusRx, curve);
            scalarMultiply(tau[i].AsReadOnlySpan(), rx[i].AsReadOnlySpan(), termA, curve);
            scalarMultiply(oneMinusTau, oneMinusRx, termB, curve);
            scalarAdd(termA, termB, factor, curve);
            scalarMultiply(result, factor, result, curve);
        }

        return new Scalar(resultOwner, curve, WellKnownAlgebraicTags.ScalarFor(curve));
    }
}
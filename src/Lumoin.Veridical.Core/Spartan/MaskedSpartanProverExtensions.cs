using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Produces a <see cref="MaskedSpartanProof"/> for the masked Spartan2 ZK
/// construction (the statistical sum-of-univariates masks of SM.7b, design v3
/// of <c>ZK-STATMASK-DESIGN.md</c>; lineage CFS 2017 / Libra 2019).
/// </summary>
/// <remarks>
/// <para>
/// The transcript schedule extends the base prover's schedule with the mask
/// commit and open steps interleaved at fixed positions: the two mask
/// coefficient-vector commitments, their sums <c>σ</c>, and their filler sums
/// <c>σ_F</c> are absorbed immediately after the witness commitment, the two
/// blending scalars are squeezed before <c>τ</c>, and the two mask weighted
/// openings happen alongside the witness opening after <c>eval_W</c>. The
/// per-round sumcheck messages occupy the same per-round slot as in the base
/// prover but carry the blended polynomial bytes — including the top
/// coefficient, which the degree-matched kernel mask blankets and the old
/// multilinear mask left bare.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class MaskedSpartanProverExtensions
{
    extension(MaskedSpartanProver prover)
    {
        /// <summary>
        /// Produces a Hyrax-backed masked Spartan2 proof that
        /// <paramref name="witness"/> satisfies the relaxed R1CS
        /// <paramref name="instance"/>. The sumcheck round messages are
        /// statistically masked (the degree-matched kernel masks); the openings
        /// are Pedersen/IPA arguments, so the proof's overall flavor remains
        /// computational zero-knowledge in the random-oracle model rooted in the
        /// discrete-log assumption.
        /// </summary>
        public MaskedSpartanProof Prove(
            RelaxedR1csInstance instance,
            RelaxedR1csWitness witness,
            PolynomialCommitmentBlind errorOpeningWitness,
            FiatShamirTranscript transcript,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            ScalarReduceDelegate scalarReduce,
            ScalarAddDelegate scalarAdd,
            ScalarSubtractDelegate scalarSubtract,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarInvertDelegate scalarInvert,
            ScalarRandomDelegate scalarRandom,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMultiply,
            G1MultiScalarMultiplyDelegate g1Msm,
            MleEvaluateDelegate mleEvaluate,
            MleFoldDelegate mleFold,
            BaseMemoryPool pool,
            ScalarArithmeticBackend? batch = null)
        {
            return prover.ProveMaskedCore(
                instance, witness, errorOpeningWitness, transcript, hash, squeeze,
                scalarReduce, scalarAdd, scalarSubtract, scalarMultiply, scalarInvert,
                scalarRandom, g1Add, g1ScalarMultiply, g1Msm, mleEvaluate, mleFold, errorPcs: null, pool, batch,
                enforceSatisfactionGuard: true,
                static (pcs, c, p) => MaskedSpartanProof.Build(
                    c.WitnessCommitment, c.OuterMaskCommitment, c.InnerMaskCommitment,
                    c.OuterMaskSum, c.InnerMaskSum, c.OuterMaskFillerSum, c.InnerMaskFillerSum, c.Outer.Rounds,
                    c.Outer.TerminatingAz, c.Outer.TerminatingBz, c.Outer.TerminatingCz, c.Outer.TerminatingE,
                    c.Inner.Rounds, c.EvalW, c.ErrorOpening, c.OuterMaskOpening, c.InnerMaskOpening, c.WitnessOpening, p));
        }


        /// <summary>
        /// Produces a BaseFold-backed masked Spartan2 proof. Identical flow to the
        /// Hyrax masked <c>Prove</c> up to the final assembly, which packs a
        /// <see cref="BaseFoldMaskedSpartanProof"/>. <b>Hiding caveat:</b> BaseFold
        /// is not a hiding commitment, so this is a sound argument of knowledge but
        /// does not achieve the masked variant's zero-knowledge privacy; use the
        /// full-ZK provider (<see cref="ProveZkBaseFold(MaskedSpartanProver, RelaxedR1csInstance, RelaxedR1csWitness, PolynomialCommitmentBlind, FiatShamirTranscript, FiatShamirHashDelegate, FiatShamirSqueezeDelegate, ScalarReduceDelegate, ScalarAddDelegate, ScalarSubtractDelegate, ScalarMultiplyDelegate, ScalarInvertDelegate, ScalarRandomDelegate, G1AddDelegate, G1ScalarMultiplyDelegate, G1MultiScalarMultiplyDelegate, MleEvaluateDelegate, MleFoldDelegate, PolynomialCommitmentProvider, BaseMemoryPool, ScalarArithmeticBackend)"/>)
        /// for that. The proving key's provider must be a BaseFold provider.
        /// </summary>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="InvalidOperationException">When the provider does not carry the BaseFold query count and digest size.</exception>
        public BaseFoldMaskedSpartanProof ProveBaseFoldSound(
            RelaxedR1csInstance instance,
            RelaxedR1csWitness witness,
            PolynomialCommitmentBlind errorOpeningWitness,
            FiatShamirTranscript transcript,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            ScalarReduceDelegate scalarReduce,
            ScalarAddDelegate scalarAdd,
            ScalarSubtractDelegate scalarSubtract,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarInvertDelegate scalarInvert,
            ScalarRandomDelegate scalarRandom,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMultiply,
            G1MultiScalarMultiplyDelegate g1Msm,
            MleEvaluateDelegate mleEvaluate,
            MleFoldDelegate mleFold,
            BaseMemoryPool pool,
            ScalarArithmeticBackend? batch = null)
        {
            return prover.ProveMaskedCore(
                instance, witness, errorOpeningWitness, transcript, hash, squeeze,
                scalarReduce, scalarAdd, scalarSubtract, scalarMultiply, scalarInvert,
                scalarRandom, g1Add, g1ScalarMultiply, g1Msm, mleEvaluate, mleFold, errorPcs: null, pool, batch,
                enforceSatisfactionGuard: true,
                static (pcs, c, p) =>
                {
                    (int queryCount, int digestSize) = RequireBaseFoldMetadata(pcs);
                    return BaseFoldMaskedSpartanProof.Build(
                        c.WitnessCommitment, c.OuterMaskCommitment, c.InnerMaskCommitment,
                        c.OuterMaskSum, c.InnerMaskSum, c.OuterMaskFillerSum, c.InnerMaskFillerSum, c.Outer.Rounds,
                        c.Outer.TerminatingAz, c.Outer.TerminatingBz, c.Outer.TerminatingCz, c.Outer.TerminatingE,
                        c.Inner.Rounds, c.EvalW, c.ErrorOpening, c.OuterMaskOpening, c.InnerMaskOpening, c.WitnessOpening,
                        queryCount, digestSize, p);
                });
        }


        /// <summary>
        /// Produces a genuinely zero-knowledge BaseFold-backed masked Spartan2
        /// proof. Identical flow to <see cref="ProveBaseFoldSound(MaskedSpartanProver, RelaxedR1csInstance, RelaxedR1csWitness, PolynomialCommitmentBlind, FiatShamirTranscript, FiatShamirHashDelegate, FiatShamirSqueezeDelegate, ScalarReduceDelegate, ScalarAddDelegate, ScalarSubtractDelegate, ScalarMultiplyDelegate, ScalarInvertDelegate, ScalarRandomDelegate, G1AddDelegate, G1ScalarMultiplyDelegate, G1MultiScalarMultiplyDelegate, MleEvaluateDelegate, MleFoldDelegate, BaseMemoryPool, ScalarArithmeticBackend)"/>,
        /// but the proving key's provider must be a full-ZK BaseFold provider
        /// (<see cref="Commitments.ZkBaseFoldPolynomialCommitmentScheme.CreateFullZeroKnowledge"/>):
        /// the witness and error openings are then hiding, simulatable full-ZK
        /// openings, the mask coefficient vectors are committed salted-and-lifted,
        /// and their weighted openings are filler-laundered — the statistical-ZK
        /// flavor of design v3. It packs a <see cref="ZkBaseFoldMaskedSpartanProof"/>.
        /// </summary>
        /// <param name="instance">The relaxed R1CS instance to prove satisfaction of.</param>
        /// <param name="witness">The relaxed R1CS witness (witness scalars plus the error vector).</param>
        /// <param name="errorOpeningWitness">The commitment blind (per-row blinding factors) for the instance's error commitment. For a raw-prepared instance this is all-zero (<see cref="PolynomialCommitmentBlind.CreateZero"/>); for a folded instance it is the homomorphic combination of the folded instances' blinding factors.</param>
        /// <param name="transcript">The Fiat-Shamir transcript.</param>
        /// <param name="hash">The Fiat-Shamir hash.</param>
        /// <param name="squeeze">The Fiat-Shamir squeeze.</param>
        /// <param name="scalarReduce">Backend scalar reduction.</param>
        /// <param name="scalarAdd">Backend scalar addition.</param>
        /// <param name="scalarSubtract">Backend scalar subtraction.</param>
        /// <param name="scalarMultiply">Backend scalar multiplication.</param>
        /// <param name="scalarInvert">Backend scalar inversion.</param>
        /// <param name="scalarRandom">Backend random scalar generation.</param>
        /// <param name="g1Add">Backend G1 addition.</param>
        /// <param name="g1ScalarMultiply">Backend G1 scalar multiplication.</param>
        /// <param name="g1Msm">Backend G1 multi-scalar multiplication.</param>
        /// <param name="mleEvaluate">Backend multilinear-extension evaluation.</param>
        /// <param name="mleFold">Backend multilinear-extension fold.</param>
        /// <param name="errorPcs">A plain (non-hiding) BaseFold provider over the same code parameters, used to commit and open the public zero-error vector deterministically while the witness and masks use the hiding provider.</param>
        /// <param name="pool">The pool to rent the working buffers from.</param>
        /// <param name="batch">The optional batched scalar-arithmetic backend.</param>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="InvalidOperationException">When the provider does not carry the BaseFold query count, digest size, and dimension-lift count (i.e. is not a full-ZK BaseFold provider).</exception>
        public ZkBaseFoldMaskedSpartanProof ProveZkBaseFold(
            RelaxedR1csInstance instance,
            RelaxedR1csWitness witness,
            PolynomialCommitmentBlind errorOpeningWitness,
            FiatShamirTranscript transcript,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            ScalarReduceDelegate scalarReduce,
            ScalarAddDelegate scalarAdd,
            ScalarSubtractDelegate scalarSubtract,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarInvertDelegate scalarInvert,
            ScalarRandomDelegate scalarRandom,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMultiply,
            G1MultiScalarMultiplyDelegate g1Msm,
            MleEvaluateDelegate mleEvaluate,
            MleFoldDelegate mleFold,
            PolynomialCommitmentProvider errorPcs,
            BaseMemoryPool pool,
            ScalarArithmeticBackend? batch = null)
        {
            ArgumentNullException.ThrowIfNull(errorPcs);

            //Fail fast before the expensive masked prove: the witness and masks require a hiding provider, so
            //reject a non-hiding one here rather than only at final assembly. The hiding provider is the
            //proving-key provider; errorPcs is deliberately the plain error provider, so it is not the one checked.
            ThrowIfProviderNotHiding(prover.ProvingKey.Pcs);

            return prover.ProveMaskedCore(
                instance, witness, errorOpeningWitness, transcript, hash, squeeze,
                scalarReduce, scalarAdd, scalarSubtract, scalarMultiply, scalarInvert,
                scalarRandom, g1Add, g1ScalarMultiply, g1Msm, mleEvaluate, mleFold, errorPcs, pool, batch,
                enforceSatisfactionGuard: true, AssembleZkBaseFoldProof);
        }


        private static ZkBaseFoldMaskedSpartanProof AssembleZkBaseFoldProof(
            PolynomialCommitmentProvider pcs, MaskedProofComponents c, BaseMemoryPool p)
        {
            (int queryCount, int digestSize, int extraVariableCount) = RequireZkBaseFoldMetadata(pcs);

            return ZkBaseFoldMaskedSpartanProof.Build(
                c.WitnessCommitment, c.OuterMaskCommitment, c.InnerMaskCommitment,
                c.OuterMaskSum, c.InnerMaskSum, c.OuterMaskFillerSum, c.InnerMaskFillerSum, c.Outer.Rounds,
                c.Outer.TerminatingAz, c.Outer.TerminatingBz, c.Outer.TerminatingCz, c.Outer.TerminatingE,
                c.Inner.Rounds, c.EvalW, c.ErrorOpening, c.OuterMaskOpening, c.InnerMaskOpening, c.WitnessOpening,
                queryCount, digestSize, extraVariableCount, p);
        }


        //The scheme-neutral masked Spartan orchestration. Identical across schemes
        //(commit witness + two mask coefficient vectors, run both masked
        //sumchecks, open the error and witness commitments and the two mask
        //weighted openings); differs only in the final assembly supplied as the
        //scheme-shaped assemble callback. The components are alive in the
        //using-scope when assemble runs, so it copies their bytes before disposal.
        [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers via using declarations and the assemble callback; the assembled proof transfers to the caller.")]
        private TProof ProveMaskedCore<TProof>(
            RelaxedR1csInstance instance,
            RelaxedR1csWitness witness,
            PolynomialCommitmentBlind errorOpeningWitness,
            FiatShamirTranscript transcript,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            ScalarReduceDelegate scalarReduce,
            ScalarAddDelegate scalarAdd,
            ScalarSubtractDelegate scalarSubtract,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarInvertDelegate scalarInvert,
            ScalarRandomDelegate scalarRandom,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMultiply,
            G1MultiScalarMultiplyDelegate g1Msm,
            MleEvaluateDelegate mleEvaluate,
            MleFoldDelegate mleFold,
            PolynomialCommitmentProvider? errorPcs,
            BaseMemoryPool pool,
            ScalarArithmeticBackend? batch,
            bool enforceSatisfactionGuard,
            Func<PolynomialCommitmentProvider, MaskedProofComponents, BaseMemoryPool, TProof> assemble)
        {
            ArgumentNullException.ThrowIfNull(prover);
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(witness);
            ArgumentNullException.ThrowIfNull(errorOpeningWitness);
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(hash);
            ArgumentNullException.ThrowIfNull(squeeze);
            ArgumentNullException.ThrowIfNull(scalarReduce);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarSubtract);
            ArgumentNullException.ThrowIfNull(scalarMultiply);
            ArgumentNullException.ThrowIfNull(scalarInvert);
            ArgumentNullException.ThrowIfNull(scalarRandom);
            ArgumentNullException.ThrowIfNull(g1Add);
            ArgumentNullException.ThrowIfNull(g1ScalarMultiply);
            ArgumentNullException.ThrowIfNull(g1Msm);
            ArgumentNullException.ThrowIfNull(mleEvaluate);
            ArgumentNullException.ThrowIfNull(mleFold);
            ArgumentNullException.ThrowIfNull(pool);

            CurveParameterSet curve = instance.Curve;
            PolynomialCommitmentProvider pcs = prover.ProvingKey.Pcs;

            //The error is the public zero vector. Most schemes commit and open it
            //through the same provider, but a hiding (ZK) provider would randomise
            //its commitment — which the verifier recomputes rather than receives, so
            //it must stay deterministic. ProveZkBaseFold supplies a plain provider
            //here for the error while the witness and masks use the hiding pcs.
            PolynomialCommitmentProvider effectiveErrorPcs = errorPcs ?? pcs;

            //The statistical-mask binding needs the provider's weighted-opening
            //path; refuse loudly when it is absent rather than silently degrading.
            PolynomialCommitDelegate commitVector = pcs.CommitVector
                ?? throw new InvalidOperationException($"Masked Spartan requires a provider with a weighted-opening path (CommitVector); the provider's scheme is {pcs.Scheme}.");
            PolynomialOpenWeightedSumDelegate openWeightedSum = pcs.OpenWeightedSum
                ?? throw new InvalidOperationException($"Masked Spartan requires a provider with a weighted-opening path (OpenWeightedSum); the provider's scheme is {pcs.Scheme}.");
            StatisticalMaskShapeDelegate resolveMaskShape = pcs.ResolveStatisticalMaskShape
                ?? throw new InvalidOperationException($"Masked Spartan requires a provider with a statistical-mask shape resolution; the provider's scheme is {pcs.Scheme}.");

            int rows = instance.A.RowCount;
            int columns = instance.A.ColumnCount;
            if(!BitOperations.IsPow2(rows) || !BitOperations.IsPow2(columns))
            {
                throw new ArgumentException(
                    $"Spartan requires power-of-two R1CS dimensions; received rows = {rows}, columns = {columns}.");
            }

            int rowVariableCount = BitOperations.Log2((uint)rows);
            int columnVariableCount = BitOperations.Log2((uint)columns);
            int scalarSize = Scalar.SizeBytes;

            //Relaxed witness satisfaction check (same role as the base prover).
            //An honest-prover fail-fast, not a soundness control — soundness is
            //the verifier's. The zero-knowledge simulator runs this honest
            //prover over a deliberately non-satisfying witness (the masked
            //sumcheck algebra never requires satisfaction) and enters through
            //the unguarded internal entry.
            if(enforceSatisfactionGuard)
            {
                using R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, scalarAdd, scalarMultiply, pool);
                if(satisfaction is R1csSatisfaction.Violated violated)
                {
                    throw new R1csNotSatisfiedException(violated);
                }
            }

            //Bind the relaxed instance to the transcript.
            transcript.AbsorbRelaxedR1csInstance(instance, hash);

            //Build the witness MLE z_W and commit it (same as base).
            using IMemoryOwner<byte> zWBufferOwner = pool.Rent(columns * scalarSize);
            Span<byte> zWBuffer = zWBufferOwner.Memory.Span[..(columns * scalarSize)];
            zWBuffer.Clear();
            int witnessOffset = (1 + instance.PublicInputCount) * scalarSize;
            witness.GetWitnessBytes().CopyTo(zWBuffer[witnessOffset..]);

            using MultilinearExtension zWMle = MultilinearExtension.FromEvaluations(
                zWBuffer, columnVariableCount, curve, pool);

            (PolynomialCommitment witnessCommitment, PolynomialCommitmentBlind witnessOpeningWitness) =
                pcs.Commit(zWMle, pool);

            using(witnessCommitment)
            using(witnessOpeningWitness)
            {
                transcript.AbsorbBytes(
                    new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.WitnessCommitment),
                    witnessCommitment.AsReadOnlySpan(),
                    hash);

                //Sample the two statistical sum-of-univariates masks, degree-matched
                //to each sumcheck's round format (design v3): the outer cubic over
                //log_2(rows) variables, the inner quadratic over log_2(columns).
                StatisticalMaskParameters outerShape = resolveMaskShape(rowVariableCount, WellKnownMaskedSpartanParameters.OuterMaskPerVariableDegree);
                StatisticalMaskParameters innerShape = resolveMaskShape(columnVariableCount, WellKnownMaskedSpartanParameters.InnerMaskPerVariableDegree);

                MonomialBasis outerBasis = MonomialBasis.SumOfUnivariatesWithPad(
                    rowVariableCount, padPairCount: 0, WellKnownMaskedSpartanParameters.OuterMaskPerVariableDegree);
                MonomialBasis innerBasis = MonomialBasis.SumOfUnivariatesWithPad(
                    columnVariableCount, padPairCount: 0, WellKnownMaskedSpartanParameters.InnerMaskPerVariableDegree);

                using MonomialBasisMask outerMask = MonomialBasisMask.Sample(outerBasis, scalarRandom, curve, pool);
                using MonomialBasisMask innerMask = MonomialBasisMask.Sample(innerBasis, scalarRandom, curve, pool);

                //The committed vectors C* = (coefficients ‖ random filler) and the
                //precommitted sums: σ closed-form from the kernel, σ_F over the
                //filler block.
                using MultilinearExtension outerVector = BuildMaskVector(outerMask, outerShape, scalarRandom, curve, pool);
                using MultilinearExtension innerVector = BuildMaskVector(innerMask, innerShape, scalarRandom, curve, pool);

                using Scalar outerSigma = outerMask.ComputeSigma(scalarAdd, scalarMultiply, pool);
                using Scalar innerSigma = innerMask.ComputeSigma(scalarAdd, scalarMultiply, pool);
                using Scalar outerFillerSum = SumCoordinateRange(outerVector, outerShape.MaskCoefficientCount, outerShape.FillerCount, scalarAdd, pool);
                using Scalar innerFillerSum = SumCoordinateRange(innerVector, innerShape.MaskCoefficientCount, innerShape.FillerCount, scalarAdd, pool);

                (PolynomialCommitment outerMaskCommitment, PolynomialCommitmentBlind outerMaskOpeningWitness) =
                    commitVector(outerVector, pool);
                (PolynomialCommitment innerMaskCommitment, PolynomialCommitmentBlind innerMaskOpeningWitness) =
                    commitVector(innerVector, pool);

                using(outerMaskCommitment)
                using(outerMaskOpeningWitness)
                using(innerMaskCommitment)
                using(innerMaskOpeningWitness)
                {
                    //Absorb com(C*), σ, and σ_F for both masks BEFORE squeezing the
                    //blending scalars — the CFS blend soundness and the v3 binding
                    //both require every mask artifact fixed pre-ρ.
                    transcript.AbsorbBytes(
                        new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.OuterMaskCommitment),
                        outerMaskCommitment.AsReadOnlySpan(),
                        hash);
                    transcript.AbsorbBytes(
                        new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.InnerMaskCommitment),
                        innerMaskCommitment.AsReadOnlySpan(),
                        hash);
                    transcript.AbsorbBytes(
                        new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.OuterMaskSum),
                        outerSigma.AsReadOnlySpan(),
                        hash);
                    transcript.AbsorbBytes(
                        new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.InnerMaskSum),
                        innerSigma.AsReadOnlySpan(),
                        hash);
                    transcript.AbsorbBytes(
                        new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.OuterMaskFillerSum),
                        outerFillerSum.AsReadOnlySpan(),
                        hash);
                    transcript.AbsorbBytes(
                        new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.InnerMaskFillerSum),
                        innerFillerSum.AsReadOnlySpan(),
                        hash);

                    using Scalar rhoOuter = transcript.SqueezeScalar(
                        new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.OuterBlendingChallenge),
                        squeeze, hash, scalarReduce, curve, pool);
                    using Scalar rhoInner = transcript.SqueezeScalar(
                        new FiatShamirOperationLabel(WellKnownMaskedSpartanTranscriptLabels.InnerBlendingChallenge),
                        squeeze, hash, scalarReduce, curve, pool);

                    //Squeeze τ for the outer-sumcheck eq factor.
                    Scalar[] tauScalars = SqueezeChallenges(
                        transcript, rowVariableCount,
                        WellKnownSpartanTranscriptLabels.OuterTau,
                        squeeze, hash, scalarReduce, curve, pool);

                    try
                    {
                        //Build z = (u, public_inputs, witness) padded to columns.
                        //The constant slot carries u (relaxed convention); for a
                        //prepared instance u = 1 so z[0] = 1 as before.
                        using IMemoryOwner<byte> zBufferOwner = pool.Rent(columns * scalarSize);
                        Span<byte> zBuffer = zBufferOwner.Memory.Span[..(columns * scalarSize)];
                        zBuffer.Clear();
                        instance.GetUBytes().CopyTo(zBuffer[..scalarSize]);
                        instance.GetPublicInputsBytes().CopyTo(zBuffer[scalarSize..]);
                        witness.GetWitnessBytes().CopyTo(zBuffer[witnessOffset..]);

                        using MultilinearExtension zMle = MultilinearExtension.FromEvaluations(
                            zBuffer, columnVariableCount, curve, pool);

                        using MultilinearExtension azMle = ComputeMatrixVectorProductMle(
                            instance.A, zBuffer, rowVariableCount, scalarAdd, scalarMultiply, pool);
                        using MultilinearExtension bzMle = ComputeMatrixVectorProductMle(
                            instance.B, zBuffer, rowVariableCount, scalarAdd, scalarMultiply, pool);
                        using MultilinearExtension czMle = ComputeMatrixVectorProductMle(
                            instance.C, zBuffer, rowVariableCount, scalarAdd, scalarMultiply, pool);

                        //Error MLE over the row variables, from the witness's
                        //error vector. E(r_x) is opened against the instance's
                        //error commitment at r_x.
                        using MultilinearExtension eMle = MultilinearExtension.FromEvaluations(
                            witness.GetErrorBytes(), rowVariableCount, curve, pool);

                        //Run the masked relaxed outer sumcheck on
                        //(Az·Bz − u·Cz − E) blended with rho_outer·g_outer.
                        using MaskedSpartanAlgorithm.OuterResult outer = MaskedSpartanAlgorithm.RunMaskedOuterSumcheck(
                            azMle, bzMle, czMle, eMle, instance.GetUBytes(), tauScalars, outerMask, rhoOuter,
                            transcript, hash, squeeze, scalarReduce,
                            scalarAdd, scalarSubtract, scalarMultiply, mleFold, pool, batch);

                        //Absorb the three terminating claims, then E(r_x).
                        Span<byte> claimsBuffer = stackalloc byte[3 * scalarSize];
                        outer.TerminatingAz.AsReadOnlySpan().CopyTo(claimsBuffer[..scalarSize]);
                        outer.TerminatingBz.AsReadOnlySpan().CopyTo(claimsBuffer.Slice(scalarSize, scalarSize));
                        outer.TerminatingCz.AsReadOnlySpan().CopyTo(claimsBuffer.Slice(2 * scalarSize, scalarSize));
                        transcript.AbsorbBytes(
                            new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.OuterClaimedEvaluations),
                            claimsBuffer,
                            hash);
                        transcript.AbsorbBytes(
                            new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.OuterErrorEvaluation),
                            outer.TerminatingE.AsReadOnlySpan(),
                            hash);

                        using Scalar r = transcript.SqueezeScalar(
                            new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.InnerCombinationChallenge),
                            squeeze, hash, scalarReduce, curve, pool);

                        //Build the ABC slice at r_x (same approach as the base prover).
                        Scalar[] rxArray = ToScalarArray(outer.Challenges, pool);
                        try
                        {
                            var aEvaluation = new MatrixMleEvaluation(instance.A);
                            var bEvaluation = new MatrixMleEvaluation(instance.B);
                            var cEvaluation = new MatrixMleEvaluation(instance.C);

                            using MultilinearExtension aSlice = aEvaluation.EvaluateRowSlice(
                                rxArray, scalarAdd, scalarSubtract, scalarMultiply, pool);
                            using MultilinearExtension bSlice = bEvaluation.EvaluateRowSlice(
                                rxArray, scalarAdd, scalarSubtract, scalarMultiply, pool);
                            using MultilinearExtension cSlice = cEvaluation.EvaluateRowSlice(
                                rxArray, scalarAdd, scalarSubtract, scalarMultiply, pool);

                            using MultilinearExtension polyAbc = LinearCombineAbcSlices(
                                aSlice, bSlice, cSlice, r, columnVariableCount, scalarAdd, scalarMultiply, pool);

                            using MaskedSpartanAlgorithm.InnerResult inner = MaskedSpartanAlgorithm.RunMaskedInnerSumcheck(
                                polyAbc, zMle, innerMask, rhoInner,
                                transcript, hash, squeeze, scalarReduce,
                                scalarAdd, scalarSubtract, scalarMultiply, mleFold, pool, batch);

                            Scalar[] ryArray = ToScalarArray(inner.Challenges, pool);
                            try
                            {
                                using Scalar evalW = zWMle.Evaluate(ryArray, mleEvaluate, pool);
                                transcript.AbsorbBytes(
                                    new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.WitnessEvaluation),
                                    evalW.AsReadOnlySpan(),
                                    hash);

                                //Open the four commitments at fixed transcript positions
                                //so the verifier replays identically: error commitment at
                                //r_x first, then the outer mask's weighted opening, then
                                //the inner mask's, then the witness at r_y. The mask
                                //weights live at the kernel's REVERSED point (the
                                //variable-order convention of MaskedSpartanAlgorithm).
                                (PolynomialOpening errorOpening, Scalar errorClaimed) = effectiveErrorPcs.Open(
                                    instance.ErrorCommitment, errorOpeningWitness, eMle, rxArray, transcript, pool);

                                using(errorOpening)
                                using(errorClaimed)
                                {
                                    Scalar[] outerKernelPoint = MaskedSpartanAlgorithm.BuildReversedPoint(rxArray);
                                    using MultilinearExtension outerWeights = MaskedSpartanAlgorithm.BuildMaskWeights(
                                        outerBasis, outerShape, outerKernelPoint, scalarMultiply, curve, pool);

                                    (PolynomialOpening outerMaskOpening, Scalar outerMaskClaimed) = openWeightedSum(
                                        outerMaskCommitment, outerMaskOpeningWitness, outerVector, outerWeights, transcript, pool);

                                    using(outerMaskOpening)
                                    using(outerMaskClaimed)
                                    {
                                        Scalar[] innerKernelPoint = MaskedSpartanAlgorithm.BuildReversedPoint(ryArray);
                                        using MultilinearExtension innerWeights = MaskedSpartanAlgorithm.BuildMaskWeights(
                                            innerBasis, innerShape, innerKernelPoint, scalarMultiply, curve, pool);

                                        (PolynomialOpening innerMaskOpening, Scalar innerMaskClaimed) = openWeightedSum(
                                            innerMaskCommitment, innerMaskOpeningWitness, innerVector, innerWeights, transcript, pool);

                                        using(innerMaskOpening)
                                        using(innerMaskClaimed)
                                        {
                                            (PolynomialOpening witnessOpening, Scalar witnessClaimed) = pcs.Open(
                                                witnessCommitment, witnessOpeningWitness, zWMle, ryArray, transcript, pool);

                                            using(witnessOpening)
                                            using(witnessClaimed)
                                            {
                                                var components = new MaskedProofComponents(
                                                    witnessCommitment, outerMaskCommitment, innerMaskCommitment,
                                                    outerSigma, innerSigma, outerFillerSum, innerFillerSum,
                                                    outer, inner, evalW,
                                                    errorOpening, outerMaskOpening, innerMaskOpening, witnessOpening);

                                                return assemble(pcs, components, pool);
                                            }
                                        }
                                    }
                                }
                            }
                            finally
                            {
                                DisposeAll(ryArray);
                            }
                        }
                        finally
                        {
                            DisposeAll(rxArray);
                        }
                    }
                    finally
                    {
                        DisposeAll(tauScalars);
                    }
                }
            }
        }


        /// <summary>
        /// Convenience overload that proves a <em>raw</em> R1CS instance:
        /// prepares the raw instance and witness into their relaxed
        /// equivalents (<c>u = 1</c>, zero error vector, identity error
        /// commitment with zero blinding) and forwards to the relaxed
        /// masked <c>Prove</c>.
        /// </summary>
        [SuppressMessage("Reliability", "CA2000", Justification = "The prepared relaxed instance, witness, and error opening witness are disposed in the finally block once the proof has copied every byte it needs; MaskedSpartanProof transfers to the caller.")]
        public MaskedSpartanProof Prove(
            RawR1csInstance instance,
            RawR1csWitness witness,
            FiatShamirTranscript transcript,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            ScalarReduceDelegate scalarReduce,
            ScalarAddDelegate scalarAdd,
            ScalarSubtractDelegate scalarSubtract,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarInvertDelegate scalarInvert,
            ScalarRandomDelegate scalarRandom,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMultiply,
            G1MultiScalarMultiplyDelegate g1Msm,
            MleEvaluateDelegate mleEvaluate,
            MleFoldDelegate mleFold,
            BaseMemoryPool pool,
            ScalarArithmeticBackend? batch = null)
        {
            ArgumentNullException.ThrowIfNull(prover);
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(witness);
            ArgumentNullException.ThrowIfNull(pool);

            PolynomialCommitmentProvider pcs = prover.ProvingKey.Pcs;

            RelaxedR1csInstance relaxedInstance = instance.Prepare(pcs, scalarRandom, g1Msm, pool);
            RelaxedR1csWitness? relaxedWitness = null;
            PolynomialCommitmentBlind? errorOpeningWitness = null;
            try
            {
                relaxedWitness = witness.Prepare(instance.A.RowCount, pool);

                //The zero error blind matches the identity error commitment: one
                //blinding scalar per commitment row, recovered from the
                //commitment's byte length (rows × compressed-G1 size).
                int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(instance.Curve);
                int errorRowCount = relaxedInstance.ErrorCommitment.AsReadOnlySpan().Length / g1Size;
                errorOpeningWitness = PolynomialCommitmentBlind.CreateZero(
                    errorRowCount * Scalar.SizeBytes, instance.Curve, pcs.Scheme, pool);

                return prover.Prove(
                    relaxedInstance, relaxedWitness, errorOpeningWitness, transcript,
                    hash, squeeze, scalarReduce, scalarAdd, scalarSubtract, scalarMultiply,
                    scalarInvert, scalarRandom, g1Add, g1ScalarMultiply, g1Msm,
                    mleEvaluate, mleFold, pool, batch);
            }
            finally
            {
                relaxedInstance.Dispose();
                relaxedWitness?.Dispose();
                errorOpeningWitness?.Dispose();
            }
        }


        /// <summary>
        /// Convenience overload that proves a <em>raw</em> R1CS instance under a
        /// BaseFold provider and forwards to the relaxed masked
        /// <see cref="ProveBaseFoldSound(MaskedSpartanProver, RelaxedR1csInstance, RelaxedR1csWitness, PolynomialCommitmentBlind, FiatShamirTranscript, FiatShamirHashDelegate, FiatShamirSqueezeDelegate, ScalarReduceDelegate, ScalarAddDelegate, ScalarSubtractDelegate, ScalarMultiplyDelegate, ScalarInvertDelegate, ScalarRandomDelegate, G1AddDelegate, G1ScalarMultiplyDelegate, G1MultiScalarMultiplyDelegate, MleEvaluateDelegate, MleFoldDelegate, BaseMemoryPool, ScalarArithmeticBackend)"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        [SuppressMessage("Reliability", "CA2000", Justification = "The prepared relaxed instance, witness, and error opening witness are disposed in the finally block once the proof has copied every byte it needs; the proof transfers to the caller.")]
        public BaseFoldMaskedSpartanProof ProveBaseFoldSound(
            RawR1csInstance instance,
            RawR1csWitness witness,
            FiatShamirTranscript transcript,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            ScalarReduceDelegate scalarReduce,
            ScalarAddDelegate scalarAdd,
            ScalarSubtractDelegate scalarSubtract,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarInvertDelegate scalarInvert,
            ScalarRandomDelegate scalarRandom,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMultiply,
            G1MultiScalarMultiplyDelegate g1Msm,
            MleEvaluateDelegate mleEvaluate,
            MleFoldDelegate mleFold,
            BaseMemoryPool pool,
            ScalarArithmeticBackend? batch = null)
        {
            ArgumentNullException.ThrowIfNull(prover);
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(witness);
            ArgumentNullException.ThrowIfNull(pool);

            PolynomialCommitmentProvider pcs = prover.ProvingKey.Pcs;

            //BaseFold commits the zero error vector through the provider (a
            //deterministic Merkle root), not the pairing-group identity.
            RelaxedR1csInstance relaxedInstance = instance.Prepare(pcs, pool);
            RelaxedR1csWitness? relaxedWitness = null;
            PolynomialCommitmentBlind? errorOpeningWitness = null;
            try
            {
                relaxedWitness = witness.Prepare(instance.A.RowCount, pool);

                //BaseFold's Open re-derives the codeword and ignores the blind, so
                //a zero placeholder the length of the error commitment suffices.
                errorOpeningWitness = PolynomialCommitmentBlind.CreateZero(
                    relaxedInstance.ErrorCommitment.AsReadOnlySpan().Length, instance.Curve, pcs.Scheme, pool);

                return prover.ProveBaseFoldSound(
                    relaxedInstance, relaxedWitness, errorOpeningWitness, transcript,
                    hash, squeeze, scalarReduce, scalarAdd, scalarSubtract, scalarMultiply,
                    scalarInvert, scalarRandom, g1Add, g1ScalarMultiply, g1Msm,
                    mleEvaluate, mleFold, pool, batch);
            }
            finally
            {
                relaxedInstance.Dispose();
                relaxedWitness?.Dispose();
                errorOpeningWitness?.Dispose();
            }
        }


        /// <summary>
        /// Convenience overload that proves a <em>raw</em> R1CS instance under a
        /// full-ZK BaseFold provider and forwards to the relaxed masked
        /// <see cref="ProveZkBaseFold(MaskedSpartanProver, RelaxedR1csInstance, RelaxedR1csWitness, PolynomialCommitmentBlind, FiatShamirTranscript, FiatShamirHashDelegate, FiatShamirSqueezeDelegate, ScalarReduceDelegate, ScalarAddDelegate, ScalarSubtractDelegate, ScalarMultiplyDelegate, ScalarInvertDelegate, ScalarRandomDelegate, G1AddDelegate, G1ScalarMultiplyDelegate, G1MultiScalarMultiplyDelegate, MleEvaluateDelegate, MleFoldDelegate, PolynomialCommitmentProvider, BaseMemoryPool, ScalarArithmeticBackend)"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        [SuppressMessage("Reliability", "CA2000", Justification = "The prepared relaxed instance, witness, and error opening witness are disposed in the finally block once the proof has copied every byte it needs; the proof transfers to the caller.")]
        public ZkBaseFoldMaskedSpartanProof ProveZkBaseFold(
            RawR1csInstance instance,
            RawR1csWitness witness,
            FiatShamirTranscript transcript,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            ScalarReduceDelegate scalarReduce,
            ScalarAddDelegate scalarAdd,
            ScalarSubtractDelegate scalarSubtract,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarInvertDelegate scalarInvert,
            ScalarRandomDelegate scalarRandom,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMultiply,
            G1MultiScalarMultiplyDelegate g1Msm,
            MleEvaluateDelegate mleEvaluate,
            MleFoldDelegate mleFold,
            PolynomialCommitmentProvider errorPcs,
            BaseMemoryPool pool,
            ScalarArithmeticBackend? batch = null)
        {
            return prover.ProveZkBaseFoldRawCore(
                instance, witness, transcript, hash, squeeze, scalarReduce, scalarAdd,
                scalarSubtract, scalarMultiply, scalarInvert, scalarRandom,
                g1Add, g1ScalarMultiply, g1Msm, mleEvaluate, mleFold, errorPcs, pool, batch,
                enforceSatisfactionGuard: true);
        }


        /// <summary>
        /// The unguarded variant of
        /// <see cref="ProveZkBaseFold(MaskedSpartanProver, RawR1csInstance, RawR1csWitness, FiatShamirTranscript, FiatShamirHashDelegate, FiatShamirSqueezeDelegate, ScalarReduceDelegate, ScalarAddDelegate, ScalarSubtractDelegate, ScalarMultiplyDelegate, ScalarInvertDelegate, ScalarRandomDelegate, G1AddDelegate, G1ScalarMultiplyDelegate, G1MultiScalarMultiplyDelegate, MleEvaluateDelegate, MleFoldDelegate, PolynomialCommitmentProvider, BaseMemoryPool, ScalarArithmeticBackend)"/>:
        /// the witness-satisfaction fail-fast is skipped. The fail-fast is an
        /// honest-prover convenience, not a soundness control (soundness is the
        /// verifier's), and the zero-knowledge simulator in
        /// <c>Lumoin.Veridical.Analysis</c> legitimately runs this honest prover
        /// over a deliberately non-satisfying witness — the masked sumcheck
        /// algebra never requires satisfaction — before retargeting the public
        /// claim through a programmed Fiat-Shamir oracle. A proof produced this
        /// way is rejected by every honest verifier; only a verifier whose
        /// oracle has been programmed accepts it, which is exactly the
        /// random-oracle-model capability the ZK simulation theorem grants.
        /// </summary>
        internal ZkBaseFoldMaskedSpartanProof ProveZkBaseFoldWithoutSatisfactionGuard(
            RawR1csInstance instance,
            RawR1csWitness witness,
            FiatShamirTranscript transcript,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            ScalarReduceDelegate scalarReduce,
            ScalarAddDelegate scalarAdd,
            ScalarSubtractDelegate scalarSubtract,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarInvertDelegate scalarInvert,
            ScalarRandomDelegate scalarRandom,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMultiply,
            G1MultiScalarMultiplyDelegate g1Msm,
            MleEvaluateDelegate mleEvaluate,
            MleFoldDelegate mleFold,
            PolynomialCommitmentProvider errorPcs,
            BaseMemoryPool pool,
            ScalarArithmeticBackend? batch = null)
        {
            return prover.ProveZkBaseFoldRawCore(
                instance, witness, transcript, hash, squeeze, scalarReduce, scalarAdd,
                scalarSubtract, scalarMultiply, scalarInvert, scalarRandom,
                g1Add, g1ScalarMultiply, g1Msm, mleEvaluate, mleFold, errorPcs, pool, batch,
                enforceSatisfactionGuard: false);
        }


        private ZkBaseFoldMaskedSpartanProof ProveZkBaseFoldRawCore(
            RawR1csInstance instance,
            RawR1csWitness witness,
            FiatShamirTranscript transcript,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            ScalarReduceDelegate scalarReduce,
            ScalarAddDelegate scalarAdd,
            ScalarSubtractDelegate scalarSubtract,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarInvertDelegate scalarInvert,
            ScalarRandomDelegate scalarRandom,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMultiply,
            G1MultiScalarMultiplyDelegate g1Msm,
            MleEvaluateDelegate mleEvaluate,
            MleFoldDelegate mleFold,
            PolynomialCommitmentProvider errorPcs,
            BaseMemoryPool pool,
            ScalarArithmeticBackend? batch,
            bool enforceSatisfactionGuard)
        {
            ArgumentNullException.ThrowIfNull(prover);
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(witness);
            ArgumentNullException.ThrowIfNull(errorPcs);
            ArgumentNullException.ThrowIfNull(pool);

            //Fail fast before the expensive masked prove (see ProveZkBaseFold): the hiding provider is the
            //proving-key provider, not the plain errorPcs supplied here.
            ThrowIfProviderNotHiding(prover.ProvingKey.Pcs);

            //The public zero-error vector is committed and opened through the plain
            //provider so the verifier's independent recomputation reaches the same
            //(deterministic) commitment; the witness and masks use the hiding pcs.
            RelaxedR1csInstance relaxedInstance = instance.Prepare(errorPcs, pool);
            RelaxedR1csWitness? relaxedWitness = null;
            PolynomialCommitmentBlind? errorOpeningWitness = null;
            try
            {
                relaxedWitness = witness.Prepare(instance.A.RowCount, pool);

                errorOpeningWitness = PolynomialCommitmentBlind.CreateZero(
                    relaxedInstance.ErrorCommitment.AsReadOnlySpan().Length, instance.Curve, errorPcs.Scheme, pool);

                return prover.ProveMaskedCore(
                    relaxedInstance, relaxedWitness, errorOpeningWitness, transcript,
                    hash, squeeze, scalarReduce, scalarAdd, scalarSubtract, scalarMultiply,
                    scalarInvert, scalarRandom, g1Add, g1ScalarMultiply, g1Msm,
                    mleEvaluate, mleFold, errorPcs, pool, batch, enforceSatisfactionGuard, AssembleZkBaseFoldProof);
            }
            finally
            {
                relaxedInstance.Dispose();
                relaxedWitness?.Dispose();
                errorOpeningWitness?.Dispose();
            }
        }
    }


    //Carries the broad components the masked proof assembly needs, kept alive in
    //the prover's innermost using-scope while the scheme-shaped assemble callback
    //copies their bytes into the proof.
    private sealed class MaskedProofComponents(
        PolynomialCommitment witnessCommitment,
        PolynomialCommitment outerMaskCommitment,
        PolynomialCommitment innerMaskCommitment,
        Scalar outerMaskSum,
        Scalar innerMaskSum,
        Scalar outerMaskFillerSum,
        Scalar innerMaskFillerSum,
        MaskedSpartanAlgorithm.OuterResult outer,
        MaskedSpartanAlgorithm.InnerResult inner,
        Scalar evalW,
        PolynomialOpening errorOpening,
        PolynomialOpening outerMaskOpening,
        PolynomialOpening innerMaskOpening,
        PolynomialOpening witnessOpening)
    {
        public PolynomialCommitment WitnessCommitment => witnessCommitment;
        public PolynomialCommitment OuterMaskCommitment => outerMaskCommitment;
        public PolynomialCommitment InnerMaskCommitment => innerMaskCommitment;
        public Scalar OuterMaskSum => outerMaskSum;
        public Scalar InnerMaskSum => innerMaskSum;
        public Scalar OuterMaskFillerSum => outerMaskFillerSum;
        public Scalar InnerMaskFillerSum => innerMaskFillerSum;
        public MaskedSpartanAlgorithm.OuterResult Outer => outer;
        public MaskedSpartanAlgorithm.InnerResult Inner => inner;
        public Scalar EvalW => evalW;
        public PolynomialOpening ErrorOpening => errorOpening;
        public PolynomialOpening OuterMaskOpening => outerMaskOpening;
        public PolynomialOpening InnerMaskOpening => innerMaskOpening;
        public PolynomialOpening WitnessOpening => witnessOpening;
    }


    //Reads the BaseFold query count and digest size the provider was built with.
    private static (int QueryCount, int DigestSize) RequireBaseFoldMetadata(PolynomialCommitmentProvider pcs)
    {
        if(pcs.QueryCount is not int queryCount || pcs.DigestSizeBytes is not int digestSize)
        {
            throw new InvalidOperationException(
                $"ProveBaseFoldSound requires a BaseFold provider carrying a query count and digest size; the provider's scheme is {pcs.Scheme}.");
        }

        return (queryCount, digestSize);
    }


    //Throws when the provider is not hiding. Masked Spartan only achieves zero-knowledge over a hiding
    //provider, so a non-hiding one is the privacy footgun: refuse it loudly rather than silently degrading
    //ZK to a sound-only argument. Called fail-fast at the ProveZkBaseFold entries and again here at metadata
    //extraction (defense in depth).
    private static void ThrowIfProviderNotHiding(PolynomialCommitmentProvider pcs)
    {
        if(!pcs.IsHiding)
        {
            throw new InvalidOperationException(
                $"ProveZkBaseFold requires a hiding provider (a full-ZK BaseFold provider); the provider's scheme is {pcs.Scheme}.");
        }
    }


    //Reads the query count, digest size, and dimension-lift count of a full-ZK
    //BaseFold provider; the lift count sizes the lifted witness opening.
    private static (int QueryCount, int DigestSize, int ExtraVariableCount) RequireZkBaseFoldMetadata(PolynomialCommitmentProvider pcs)
    {
        ThrowIfProviderNotHiding(pcs);

        if(pcs.QueryCount is not int queryCount || pcs.DigestSizeBytes is not int digestSize || pcs.ExtraVariableCount is not int extraVariableCount)
        {
            throw new InvalidOperationException(
                $"ProveZkBaseFold requires a full-ZK BaseFold provider carrying a query count, digest size, and dimension-lift count; the provider's scheme is {pcs.Scheme}.");
        }

        return (queryCount, digestSize, extraVariableCount);
    }


    //The committed mask vector C* = (kernel coefficients ‖ random filler) over
    //2^ℓ₂ coordinates — every coordinate beyond the coefficients is laundering
    //entropy (design v3; the policy leaves no zero-weight real coordinates).
    [SuppressMessage("Reliability", "CA2000", Justification = "The rented buffer transfers ownership to the returned MLE.")]
    private static MultilinearExtension BuildMaskVector(
        MonomialBasisMask mask,
        StatisticalMaskParameters shape,
        ScalarRandomDelegate scalarRandom,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int scalarSize = Scalar.SizeBytes;
        int coordinateCount = shape.CoefficientCount;
        using IMemoryOwner<byte> vectorOwner = pool.Rent(coordinateCount * scalarSize);
        Span<byte> vector = vectorOwner.Memory.Span[..(coordinateCount * scalarSize)];
        mask.CopyCoefficientsTo(vector);

        Tag scalarTag = WellKnownAlgebraicTags.ScalarFor(curve);
        for(int i = shape.MaskCoefficientCount; i < coordinateCount; i++)
        {
            _ = scalarRandom(vector.Slice(i * scalarSize, scalarSize), curve, scalarTag);
        }

        return MultilinearExtension.FromEvaluations(vector, shape.CoefficientVariableCount, curve, pool);
    }


    //σ_F = the sum of the filler block's coordinates; absorbed pre-ρ so the
    //weighted-opening claim s(r) + σ_F is fixed by the commitment.
    [SuppressMessage("Reliability", "CA2000", Justification = "The rented buffer transfers ownership to the returned scalar.")]
    private static Scalar SumCoordinateRange(
        MultilinearExtension vector,
        int start,
        int count,
        ScalarAddDelegate add,
        BaseMemoryPool pool)
    {
        int scalarSize = Scalar.SizeBytes;
        CurveParameterSet curve = vector.Curve;
        IMemoryOwner<byte> resultOwner = pool.Rent(scalarSize);
        Span<byte> result = resultOwner.Memory.Span[..scalarSize];
        result.Clear();

        ReadOnlySpan<byte> bytes = vector.AsReadOnlySpan();
        for(int i = start; i < start + count; i++)
        {
            add(result, bytes.Slice(i * scalarSize, scalarSize), result, curve);
        }

        return new Scalar(resultOwner, curve, WellKnownAlgebraicTags.ScalarFor(curve));
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


    [SuppressMessage("Reliability", "CA2000", Justification = "The returned MLE takes ownership of its rented buffer and transfers to the caller.")]
    private static MultilinearExtension ComputeMatrixVectorProductMle(
        R1csMatrix matrix,
        ReadOnlySpan<byte> zBytes,
        int rowVariableCount,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMultiply,
        BaseMemoryPool pool)
    {
        int rows = matrix.RowCount;
        int scalarSize = Scalar.SizeBytes;
        int bufferSize = rows * scalarSize;

        using IMemoryOwner<byte> productOwner = pool.Rent(bufferSize);
        Span<byte> product = productOwner.Memory.Span[..bufferSize];
        matrix.MatrixVectorProduct(zBytes, product, scalarAdd, scalarMultiply, pool);

        return MultilinearExtension.FromEvaluations(product, rowVariableCount, matrix.Curve, pool);
    }


    [SuppressMessage("Reliability", "CA2000", Justification = "The returned MLE takes ownership of its rented buffer and transfers to the caller.")]
    private static MultilinearExtension LinearCombineAbcSlices(
        MultilinearExtension aSlice,
        MultilinearExtension bSlice,
        MultilinearExtension cSlice,
        Scalar r,
        int variableCount,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMultiply,
        BaseMemoryPool pool)
    {
        int scalarSize = Scalar.SizeBytes;
        int evaluationCount = 1 << variableCount;
        int bufferSize = evaluationCount * scalarSize;
        CurveParameterSet curve = aSlice.Curve;

        using IMemoryOwner<byte> rSquaredOwner = pool.Rent(scalarSize);
        Span<byte> rSquared = rSquaredOwner.Memory.Span[..scalarSize];
        scalarMultiply(r.AsReadOnlySpan(), r.AsReadOnlySpan(), rSquared, curve);

        using IMemoryOwner<byte> outputOwner = pool.Rent(bufferSize);
        Span<byte> output = outputOwner.Memory.Span[..bufferSize];

        using IMemoryOwner<byte> termOwner = pool.Rent(scalarSize);
        Span<byte> term = termOwner.Memory.Span[..scalarSize];

        ReadOnlySpan<byte> aBytes = aSlice.AsReadOnlySpan();
        ReadOnlySpan<byte> bBytes = bSlice.AsReadOnlySpan();
        ReadOnlySpan<byte> cBytes = cSlice.AsReadOnlySpan();

        for(int j = 0; j < evaluationCount; j++)
        {
            ReadOnlySpan<byte> aj = aBytes.Slice(j * scalarSize, scalarSize);
            ReadOnlySpan<byte> bj = bBytes.Slice(j * scalarSize, scalarSize);
            ReadOnlySpan<byte> cj = cBytes.Slice(j * scalarSize, scalarSize);
            Span<byte> outJ = output.Slice(j * scalarSize, scalarSize);

            scalarMultiply(r.AsReadOnlySpan(), bj, term, curve);
            scalarAdd(aj, term, outJ, curve);
            scalarMultiply(rSquared, cj, term, curve);
            scalarAdd(outJ, term, outJ, curve);
        }

        return MultilinearExtension.FromEvaluations(output, variableCount, curve, pool);
    }
}

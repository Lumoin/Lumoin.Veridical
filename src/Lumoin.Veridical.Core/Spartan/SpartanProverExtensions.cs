using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Produces a <see cref="SpartanProof"/> from a relaxed R1CS instance,
/// its witness, an initialised transcript, and the backend delegates
/// Spartan needs.
/// </summary>
/// <remarks>
/// <para>
/// The unified prover proves the <em>relaxed</em> R1CS identity
/// <c>(A·z) ∘ (B·z) = u · (C·z) + E</c> over <c>z = (u, public, witness)</c>.
/// Standard R1CS is the special case <c>u = 1</c>, <c>E = 0</c> — a raw
/// instance reaches this prover through <see cref="RawR1csInstanceExtensions.Prepare"/>
/// (or the raw convenience overload), which produces <c>u = 1</c> and
/// the identity error commitment.
/// </para>
/// <para>
/// The flow follows the transcript schedule pinned in
/// <c>SPARTAN2.md</c>:
/// </para>
/// <list type="number">
///   <item><description>Run the relaxed witness satisfaction check; throw <see cref="R1csNotSatisfiedException"/> on the first violated constraint.</description></item>
///   <item><description>Absorb the relaxed R1CS instance (dimensions, matrices, public inputs, <c>u</c>, error commitment) into the transcript.</description></item>
///   <item><description>Build the witness MLE <c>z_W</c> (the witness placed at its column positions, zeros at non-witness positions, padded to <c>n</c>). Commit it under Hyrax. Absorb the commitment.</description></item>
///   <item><description>Squeeze the outer-sumcheck τ vector.</description></item>
///   <item><description>Compute <c>(Az, Bz, Cz)</c> as MLEs via matrix-vector products against the full assignment <c>z = (u, public, witness)</c>, and build the error MLE <c>E</c> from the witness's error vector.</description></item>
///   <item><description>Run the relaxed outer sumcheck driver (folding <c>E</c> and carrying <c>u</c>). Absorb the three terminating claims, then <c>E(r_x)</c>.</description></item>
///   <item><description>Squeeze the inner-batching scalar <c>r</c>. Compute the slice <c>ABC = A~(r_x, ·) + r · B~(r_x, ·) + r² · C~(r_x, ·)</c>.</description></item>
///   <item><description>Run the inner sumcheck driver against <c>(ABC, z)</c> — proving pure matrix products, unchanged by the relaxation.</description></item>
///   <item><description>Evaluate <c>z_W</c> at <c>r_y</c>; absorb it. Open the error commitment at <c>r_x</c>, then the witness commitment at <c>r_y</c>.</description></item>
///   <item><description>Pack everything into a <see cref="SpartanProof"/> wire-format buffer.</description></item>
/// </list>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class SpartanProverExtensions
{
    extension(SpartanProver prover)
    {
        /// <summary>
        /// Produces a Hyrax-backed Spartan2 proof that <paramref name="witness"/>
        /// satisfies the relaxed R1CS <paramref name="instance"/>.
        /// </summary>
        /// <param name="instance">The relaxed R1CS instance to prove satisfaction of.</param>
        /// <param name="witness">The relaxed R1CS witness (witness scalars plus the error vector).</param>
        /// <param name="errorOpeningWitness">The commitment blind (per-row blinding factors) for the instance's error commitment. For a raw-prepared instance this is all-zero (<see cref="PolynomialCommitmentBlind.CreateZero"/>); for a folded instance it is the homomorphic combination of the folded instances' blinding factors.</param>
        /// <param name="transcript">A fresh <see cref="FiatShamirTranscript"/> initialised with the Spartan2 domain label and the empty seed bytes.</param>
        /// <param name="hash">The fixed-output hash delegate used by the transcript.</param>
        /// <param name="squeeze">The XOF squeeze delegate used by the transcript.</param>
        /// <param name="scalarReduce">The scalar-reduce delegate used when converting squeezed wide bytes to canonical scalars.</param>
        /// <param name="scalarAdd">The scalar-add backend.</param>
        /// <param name="scalarSubtract">The scalar-subtract backend.</param>
        /// <param name="scalarMultiply">The scalar-multiply backend.</param>
        /// <param name="scalarInvert">The scalar-invert backend (used inside the embedded IPA).</param>
        /// <param name="scalarRandom">The scalar-random backend (used for Hyrax blinding factors).</param>
        /// <param name="g1Add">The G1-add backend.</param>
        /// <param name="g1ScalarMultiply">The G1 scalar-multiply backend.</param>
        /// <param name="g1Msm">The G1 multi-scalar-multiplication backend.</param>
        /// <param name="mleEvaluate">The MLE evaluation delegate.</param>
        /// <param name="mleFold">The MLE fold delegate.</param>
        /// <param name="pool">The pool to rent every buffer from.</param>
        /// <returns>A Spartan2 wire-format proof. The caller owns its disposal.</returns>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="R1csNotSatisfiedException">When the witness does not satisfy the relaxed R1CS instance.</exception>
        public SpartanProof Prove(
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
            return prover.ProveRelaxedCore(
                instance, witness, errorOpeningWitness, transcript, hash, squeeze,
                scalarReduce, scalarAdd, scalarSubtract, scalarMultiply, scalarInvert,
                scalarRandom, g1Add, g1ScalarMultiply, g1Msm, mleEvaluate, mleFold, pool, batch,
                static (pcs, witnessCommitment, outer, inner, evalW, errorProof, hyraxProof, p) =>
                    SpartanProof.Build(
                        witnessCommitment, outer.Rounds, outer.TerminatingAz, outer.TerminatingBz,
                        outer.TerminatingCz, outer.TerminatingE, inner.Rounds, evalW, errorProof, hyraxProof, p));
        }


        /// <summary>
        /// Produces a BaseFold-backed Spartan2 proof that <paramref name="witness"/>
        /// satisfies the relaxed R1CS <paramref name="instance"/>. Identical flow
        /// to <see cref="Prove(RelaxedR1csInstance, RelaxedR1csWitness, PolynomialCommitmentBlind, FiatShamirTranscript, FiatShamirHashDelegate, FiatShamirSqueezeDelegate, ScalarReduceDelegate, ScalarAddDelegate, ScalarSubtractDelegate, ScalarMultiplyDelegate, ScalarInvertDelegate, ScalarRandomDelegate, G1AddDelegate, G1ScalarMultiplyDelegate, G1MultiScalarMultiplyDelegate, MleEvaluateDelegate, MleFoldDelegate, BaseMemoryPool)"/>
        /// up to the final assembly, which packs a BaseFold-shaped
        /// <see cref="BaseFoldSpartanProof"/>. The proving key's provider must be a
        /// BaseFold provider (carrying its query count and digest size).
        /// </summary>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="InvalidOperationException">When the provider does not carry the BaseFold query count and digest size.</exception>
        /// <exception cref="R1csNotSatisfiedException">When the witness does not satisfy the relaxed R1CS instance.</exception>
        public BaseFoldSpartanProof ProveBaseFold(
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
            return prover.ProveRelaxedCore(
                instance, witness, errorOpeningWitness, transcript, hash, squeeze,
                scalarReduce, scalarAdd, scalarSubtract, scalarMultiply, scalarInvert,
                scalarRandom, g1Add, g1ScalarMultiply, g1Msm, mleEvaluate, mleFold, pool, batch,
                static (pcs, witnessCommitment, outer, inner, evalW, errorProof, witnessProof, p) =>
                {
                    (int queryCount, int digestSize) = RequireBaseFoldMetadata(pcs);
                    return BaseFoldSpartanProof.Build(
                        witnessCommitment, outer.Rounds, outer.TerminatingAz, outer.TerminatingBz,
                        outer.TerminatingCz, outer.TerminatingE, inner.Rounds, evalW, errorProof, witnessProof,
                        queryCount, digestSize, p);
                });
        }


        /// <summary>
        /// Produces a Ligero-backed Spartan2 proof that <paramref name="witness"/>
        /// satisfies the relaxed R1CS <paramref name="instance"/>. Identical flow to
        /// <see cref="ProveBaseFold"/> up to the final assembly, which packs a
        /// Ligero-shaped <see cref="LigeroSpartanProof"/>. The proving key's provider
        /// must be a Ligero provider (carrying its query count and digest size). The
        /// group backends are unused by the hash-based Ligero scheme but are accepted
        /// for signature parity with the other prover entry points.
        /// </summary>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="InvalidOperationException">When the provider does not carry the query count and digest size.</exception>
        /// <exception cref="R1csNotSatisfiedException">When the witness does not satisfy the relaxed R1CS instance.</exception>
        public LigeroSpartanProof ProveLigero(
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
            return prover.ProveRelaxedCore(
                instance, witness, errorOpeningWitness, transcript, hash, squeeze,
                scalarReduce, scalarAdd, scalarSubtract, scalarMultiply, scalarInvert,
                scalarRandom, g1Add, g1ScalarMultiply, g1Msm, mleEvaluate, mleFold, pool, batch,
                static (pcs, witnessCommitment, outer, inner, evalW, errorProof, witnessProof, p) =>
                {
                    (int queryCount, int digestSize) = RequireBaseFoldMetadata(pcs);
                    return LigeroSpartanProof.Build(
                        witnessCommitment, outer.Rounds, outer.TerminatingAz, outer.TerminatingBz,
                        outer.TerminatingCz, outer.TerminatingE, inner.Rounds, evalW, errorProof, witnessProof,
                        queryCount, digestSize, p);
                });
        }


        //The scheme-neutral relaxed Spartan orchestration. The body is identical
        //across commitment schemes — it commits, runs both sumchecks, and opens —
        //differing only in the final assembly, supplied as the scheme-shaped
        //assemble callback. The artifacts (witness commitment, sumcheck results,
        //eval_W, the two openings) are alive in the using-scope when assemble
        //runs, so it copies their bytes into the returned proof before disposal.
        [SuppressMessage("Reliability", "CA2000", Justification = "Ownership of intermediate disposables transfers via using declarations and the assemble callback; the assembled proof transfers to the caller.")]
        private TProof ProveRelaxedCore<TProof>(
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
            ScalarArithmeticBackend? batch,
            Func<PolynomialCommitmentProvider, PolynomialCommitment, OuterSumcheckProverResult, InnerSumcheckProverResult, Scalar, PolynomialOpening, PolynomialOpening, BaseMemoryPool, TProof> assemble)
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

            //Witness satisfaction check runs before any cryptographic work.
            //Catches witness-generation bugs in caller code with the diagnostic
            //precision of R1csSatisfaction.Violated; soundness against malicious
            //provers comes from the verifier's cryptographic checks, not this
            //pre-flight check.
            using(R1csSatisfaction satisfaction = instance.CheckSatisfiedBy(witness, scalarAdd, scalarMultiply, pool))
            {
                if(satisfaction is R1csSatisfaction.Violated violated)
                {
                    throw new R1csNotSatisfiedException(violated);
                }
            }

            //Bind the relaxed instance to the transcript before any per-proof
            //bytes: dimensions, matrices, public inputs, then u and the error
            //commitment.
            transcript.AbsorbRelaxedR1csInstance(instance, hash);

            //Construct z_W: the witness placed at its column positions, zeros
            //at non-witness positions. Length matches the instance column
            //count so the resulting MLE has column-variable count.
            using IMemoryOwner<byte> zWBufferOwner = pool.Rent(columns * scalarSize);
            Span<byte> zWBuffer = zWBufferOwner.Memory.Span[..(columns * scalarSize)];
            zWBuffer.Clear();
            int witnessOffset = (1 + instance.PublicInputCount) * scalarSize;
            witness.GetWitnessBytes().CopyTo(zWBuffer[witnessOffset..]);

            using MultilinearExtension zWMle = MultilinearExtension.FromEvaluations(
                zWBuffer, columnVariableCount, curve, pool);

            (PolynomialCommitment witnessCommitment, PolynomialCommitmentBlind openingWitness) =
                pcs.Commit(zWMle, pool);

            using(witnessCommitment)
            using(openingWitness)
            {
                transcript.AbsorbBytes(
                    new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.WitnessCommitment),
                    witnessCommitment.AsReadOnlySpan(),
                    hash);

                //Squeeze τ, the binding for the outer-sumcheck eq factor.
                Scalar[] tauScalars = SqueezeChallenges(
                    transcript, rowVariableCount,
                    WellKnownSpartanTranscriptLabels.OuterTau,
                    squeeze, hash, scalarReduce, curve, pool);

                try
                {
                    //Build z = (u, public_inputs, witness) padded to columns
                    //and wrap as an MLE for the inner sumcheck. The constant
                    //slot is u (the Nova relaxed-R1CS convention), not literal
                    //1; for a prepared instance u = 1 so z[0] = 1 as before.
                    using IMemoryOwner<byte> zBufferOwner = pool.Rent(columns * scalarSize);
                    Span<byte> zBuffer = zBufferOwner.Memory.Span[..(columns * scalarSize)];
                    zBuffer.Clear();
                    instance.GetUBytes().CopyTo(zBuffer[..scalarSize]);
                    instance.GetPublicInputsBytes().CopyTo(zBuffer[scalarSize..]);
                    witness.GetWitnessBytes().CopyTo(zBuffer[witnessOffset..]);

                    using MultilinearExtension zMle = MultilinearExtension.FromEvaluations(
                        zBuffer, columnVariableCount, curve, pool);

                    //Compute Az, Bz, Cz as MLEs (pure matrix products).
                    using MultilinearExtension azMle = ComputeMatrixVectorProductMle(
                        instance.A, zBuffer, rowVariableCount, scalarAdd, scalarMultiply, pool);
                    using MultilinearExtension bzMle = ComputeMatrixVectorProductMle(
                        instance.B, zBuffer, rowVariableCount, scalarAdd, scalarMultiply, pool);
                    using MultilinearExtension czMle = ComputeMatrixVectorProductMle(
                        instance.C, zBuffer, rowVariableCount, scalarAdd, scalarMultiply, pool);

                    //Build the error MLE E over the row variables from the
                    //witness's error vector. Its terminating fold value E(r_x)
                    //is proven via a Hyrax opening of the instance's error
                    //commitment at r_x.
                    using MultilinearExtension eMle = MultilinearExtension.FromEvaluations(
                        witness.GetErrorBytes(), rowVariableCount, curve, pool);

                    using OuterSumcheckProverResult outer = OuterSumcheckProver.Run(
                        azMle, bzMle, czMle, eMle, instance.GetUBytes(), tauScalars,
                        transcript, hash, squeeze, scalarReduce,
                        scalarAdd, scalarSubtract, scalarMultiply, mleFold, pool, batch);

                    //Absorb the three terminating claims as one block, then
                    //E(r_x) under its own label.
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

                    //Build the ABC slice at r_x for the inner sumcheck:
                    //  ABC(y) = A~(r_x, y) + r · B~(r_x, y) + r² · C~(r_x, y).
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

                        using InnerSumcheckProverResult inner = InnerSumcheckProver.Run(
                            polyAbc, zMle, transcript, hash, squeeze, scalarReduce,
                            scalarAdd, scalarSubtract, scalarMultiply, mleFold, pool, batch);

                        //Compute eval_W = z_W(r_y) and absorb.
                        Scalar[] ryArray = ToScalarArray(inner.Challenges, pool);
                        try
                        {
                            using Scalar evalW = zWMle.Evaluate(ryArray, mleEvaluate, pool);
                            transcript.AbsorbBytes(
                                new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.WitnessEvaluation),
                                evalW.AsReadOnlySpan(),
                                hash);

                            //Open the error commitment at r_x (proves E(r_x))
                            //then the witness commitment at r_y. The order is
                            //fixed so the verifier replays it identically.
                            (PolynomialOpening errorProof, Scalar errorClaimedValue) = pcs.Open(
                                instance.ErrorCommitment,
                                errorOpeningWitness,
                                eMle,
                                rxArray,
                                transcript,
                                pool);

                            using(errorProof)
                            using(errorClaimedValue)
                            {
                                (PolynomialOpening hyraxProof, Scalar hyraxClaimedValue) = pcs.Open(
                                    witnessCommitment,
                                    openingWitness,
                                    zWMle,
                                    ryArray,
                                    transcript,
                                    pool);

                                using(hyraxProof)
                                using(hyraxClaimedValue)
                                {
                                    return assemble(pcs, witnessCommitment, outer, inner, evalW, errorProof, hyraxProof, pool);
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


        /// <summary>
        /// Convenience overload that proves a <em>raw</em> R1CS instance:
        /// prepares the raw instance and witness into their relaxed
        /// equivalents (<c>u = 1</c>, zero error vector, identity error
        /// commitment with zero blinding) and forwards to the relaxed
        /// <c>Prove</c>.
        /// </summary>
        /// <param name="instance">The raw R1CS instance.</param>
        /// <param name="witness">The raw R1CS witness.</param>
        /// <param name="transcript">A fresh transcript (see the relaxed overload).</param>
        /// <param name="hash">The fixed-output hash delegate.</param>
        /// <param name="squeeze">The XOF squeeze delegate.</param>
        /// <param name="scalarReduce">The scalar-reduce backend.</param>
        /// <param name="scalarAdd">The scalar-add backend.</param>
        /// <param name="scalarSubtract">The scalar-subtract backend.</param>
        /// <param name="scalarMultiply">The scalar-multiply backend.</param>
        /// <param name="scalarInvert">The scalar-invert backend.</param>
        /// <param name="scalarRandom">The scalar-random backend.</param>
        /// <param name="g1Add">The G1-add backend.</param>
        /// <param name="g1ScalarMultiply">The G1 scalar-multiply backend.</param>
        /// <param name="g1Msm">The G1 MSM backend.</param>
        /// <param name="mleEvaluate">The MLE evaluation delegate.</param>
        /// <param name="mleFold">The MLE fold delegate.</param>
        /// <param name="pool">The pool to rent every buffer from.</param>
        /// <returns>A Spartan2 wire-format proof. The caller owns its disposal.</returns>
        [SuppressMessage("Reliability", "CA2000", Justification = "The prepared relaxed instance, witness, and error opening witness are disposed in the finally block once the proof has copied every byte it needs; SpartanProof transfers to the caller.")]
        public SpartanProof Prove(
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
                //blinding scalar per commitment row. Recover the row count from
                //the commitment's byte length (rows × compressed-G1 size).
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
        /// BaseFold provider: prepares the raw instance/witness into their
        /// relaxed equivalents (<c>u = 1</c>, zero error vector, identity error
        /// commitment) and forwards to <see cref="ProveBaseFold(RelaxedR1csInstance, RelaxedR1csWitness, PolynomialCommitmentBlind, FiatShamirTranscript, FiatShamirHashDelegate, FiatShamirSqueezeDelegate, ScalarReduceDelegate, ScalarAddDelegate, ScalarSubtractDelegate, ScalarMultiplyDelegate, ScalarInvertDelegate, ScalarRandomDelegate, G1AddDelegate, G1ScalarMultiplyDelegate, G1MultiScalarMultiplyDelegate, MleEvaluateDelegate, MleFoldDelegate, BaseMemoryPool)"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        [SuppressMessage("Reliability", "CA2000", Justification = "The prepared relaxed instance, witness, and error opening witness are disposed in the finally block once the proof has copied every byte it needs; the proof transfers to the caller.")]
        public BaseFoldSpartanProof ProveBaseFold(
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

                //BaseFold is not hiding: its Open re-derives the codeword from the
                //polynomial and ignores the blind, so a zero placeholder the length
                //of the error commitment suffices.
                errorOpeningWitness = PolynomialCommitmentBlind.CreateZero(
                    relaxedInstance.ErrorCommitment.AsReadOnlySpan().Length, instance.Curve, pcs.Scheme, pool);

                return prover.ProveBaseFold(
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
        /// Ligero provider: prepares the raw instance/witness into their relaxed
        /// equivalents (<c>u = 1</c>, zero error vector, deterministic error
        /// commitment) and forwards to the relaxed <c>ProveLigero</c>.
        /// </summary>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        [SuppressMessage("Reliability", "CA2000", Justification = "The prepared relaxed instance, witness, and error opening witness are disposed in the finally block once the proof has copied every byte it needs; the proof transfers to the caller.")]
        public LigeroSpartanProof ProveLigero(
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

            RelaxedR1csInstance relaxedInstance = instance.Prepare(pcs, pool);
            RelaxedR1csWitness? relaxedWitness = null;
            PolynomialCommitmentBlind? errorOpeningWitness = null;
            try
            {
                relaxedWitness = witness.Prepare(instance.A.RowCount, pool);

                //Ligero is not hiding: its Open re-derives the codeword from the
                //polynomial and ignores the blind, so a zero placeholder the length
                //of the error commitment suffices.
                errorOpeningWitness = PolynomialCommitmentBlind.CreateZero(
                    relaxedInstance.ErrorCommitment.AsReadOnlySpan().Length, instance.Curve, pcs.Scheme, pool);

                return prover.ProveLigero(
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
    }


    //Reads the query count and digest size the provider was built with, throwing
    //a clear error if the provider is not a hash-tree scheme that carries them
    //(BaseFold or Ligero).
    private static (int QueryCount, int DigestSize) RequireBaseFoldMetadata(PolynomialCommitmentProvider pcs)
    {
        if(pcs.QueryCount is not int queryCount || pcs.DigestSizeBytes is not int digestSize)
        {
            throw new InvalidOperationException(
                $"A hash-tree-backed Spartan proof requires a provider carrying a query count and digest size; the provider's scheme is {pcs.Scheme}.");
        }

        return (queryCount, digestSize);
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


    private static Scalar[] ToScalarArray(System.Collections.Generic.IReadOnlyList<Scalar> source, BaseMemoryPool pool)
    {
        Scalar[] result = new Scalar[source.Count];
        for(int i = 0; i < source.Count; i++)
        {
            //Make fresh leaf-typed handles backed by their own buffers so the
            //array's lifetime is independent of the source list's. The source
            //list owns its own handles separately.
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


    /// <summary>
    /// Computes <c>matrix · z</c> as a length-rows vector and wraps the
    /// result as a multilinear extension of <c>log_2(rows)</c> variables.
    /// </summary>
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


    /// <summary>
    /// Computes the linear combination
    /// <c>polyAbc[j] = aSlice[j] + r · bSlice[j] + r² · cSlice[j]</c>
    /// slot-by-slot and wraps the result as a multilinear extension.
    /// </summary>
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

        //Precompute r².
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

            //outJ = aj + r * bj + r² * cj.
            scalarMultiply(r.AsReadOnlySpan(), bj, term, curve);
            scalarAdd(aj, term, outJ, curve);
            scalarMultiply(rSquared, cj, term, curve);
            scalarAdd(outJ, term, outJ, curve);
        }


        return MultilinearExtension.FromEvaluations(output, variableCount, curve, pool);
    }
}
using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.ConstraintSystems;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Verifies a <see cref="SpartanProof"/> against the verifier's
/// <see cref="SpartanVerifyingKey"/>. The verifier replays the prover's
/// transcript schedule, decompresses each sumcheck round polynomial
/// against the running claim, independently evaluates the three matrix
/// MLEs at the squeezed points, and checks the Hyrax opening of the
/// witness commitment at the inner-sumcheck challenge vector.
/// </summary>
/// <remarks>
/// <para>
/// The implementation is exception-safe against malformed proof bytes
/// — bytes that fail length or canonical-decoding checks cause a
/// <c>false</c> return, not a thrown exception. The only exceptions the
/// verifier raises are from argument-validation paths (null
/// arguments, mismatched curve in the proof versus the verifying key,
/// dimension mismatches) where the caller is at fault.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class SpartanVerifierExtensions
{
    extension(SpartanVerifier verifier)
    {
        /// <summary>
        /// Verifies a Spartan2 proof against a relaxed R1CS
        /// <paramref name="instance"/> and the verifier's Hyrax
        /// commitment key. Returns <c>true</c> iff every algebraic check
        /// passes.
        /// </summary>
        /// <param name="proof">The Spartan2 proof to verify.</param>
        /// <param name="instance">The relaxed R1CS instance the proof claims satisfaction of.</param>
        /// <param name="transcript">A fresh <see cref="FiatShamirTranscript"/> initialised with the Spartan2 domain label and the empty seed bytes (matching the prover's setup).</param>
        /// <param name="scalarAdd">Scalar-add backend.</param>
        /// <param name="scalarMultiply">Scalar-multiply backend.</param>
        /// <param name="scalarSubtract">Scalar-subtract backend.</param>
        /// <param name="scalarInvert">Scalar-invert backend (used inside the embedded IPA verify).</param>
        /// <param name="scalarReduce">Scalar-reduce backend.</param>
        /// <param name="g1Add">G1-add backend.</param>
        /// <param name="g1ScalarMultiply">G1 scalar-multiply backend.</param>
        /// <param name="g1Msm">G1 MSM backend.</param>
        /// <param name="hash">Fixed-output hash backend used by the transcript.</param>
        /// <param name="squeeze">XOF squeeze backend used by the transcript.</param>
        /// <param name="pool">The pool to rent every buffer from.</param>
        /// <returns><c>true</c> iff the proof verifies; <c>false</c> otherwise.</returns>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the proof's curve disagrees with the verifying key's, or the proof's dimensions do not match the instance.</exception>
        [SuppressMessage("Reliability", "CA2000", Justification = "Intermediate disposables flow through using declarations; the bool return path disposes everything before returning.")]
        public bool Verify(
            SpartanProof proof,
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

            //The Hyrax witness-commitment row count is fixed by the column
            //variable count; this guard is Hyrax-shaped, so it lives here rather
            //than in the scheme-neutral VerifyCore.
            HyraxCommitmentDimensions commitmentDimensions = HyraxCommitmentDimensions.ForVariableCount(columnVariableCount);
            if(proof.WitnessCommitmentRowCount != commitmentDimensions.RowCount)
            {
                throw new ArgumentException(
                    $"Proof witness-commitment row count {proof.WitnessCommitmentRowCount} does not match the expected {commitmentDimensions.RowCount} for column variable count {columnVariableCount}.");
            }

            CryptographicOperationCounters.Increment(CryptographicOperationKind.SpartanVerifierVerify, curve);

            //Malformed proof bytes are caught and converted to a false return so the
            //verifier surface stays exception-safe against tampering: a bit-flipped
            //G1 point that fails on-curve or subgroup decoding surfaces as
            //InvalidOperationException from the crypto backends, and a non-canonical
            //scalar — a round-polynomial coefficient at or above the field order —
            //surfaces as ArgumentException from round-polynomial reconstruction.
            try
            {
                return VerifyCore(
                    proof.GetSumcheckPart(),
                    proof.GetWitnessCommitmentBytes(),
                    proof.GetErrorOpeningProofBytes(),
                    proof.GetHyraxOpeningProofBytes(),
                    instance, transcript, scalarAdd, scalarMultiply, scalarSubtract, scalarReduce, hash, squeeze, pool, rowVariableCount, columnVariableCount, pcs);
            }
            catch(Exception ex) when (ex is InvalidOperationException or ArgumentException)
            {
                return false;
            }
        }


        /// <summary>
        /// Convenience overload that verifies a proof against a
        /// <em>raw</em> R1CS instance: prepares the raw instance into its
        /// relaxed equivalent (<c>u = 1</c>, identity error commitment)
        /// and forwards to the relaxed <c>Verify</c>.
        /// </summary>
        /// <param name="proof">The Spartan2 proof to verify.</param>
        /// <param name="instance">The raw R1CS instance.</param>
        /// <param name="transcript">A fresh transcript (see the relaxed overload).</param>
        /// <param name="scalarAdd">Scalar-add backend.</param>
        /// <param name="scalarMultiply">Scalar-multiply backend.</param>
        /// <param name="scalarSubtract">Scalar-subtract backend.</param>
        /// <param name="scalarInvert">Scalar-invert backend.</param>
        /// <param name="scalarReduce">Scalar-reduce backend.</param>
        /// <param name="g1Add">G1-add backend.</param>
        /// <param name="g1ScalarMultiply">G1 scalar-multiply backend.</param>
        /// <param name="g1Msm">G1 MSM backend.</param>
        /// <param name="hash">Fixed-output hash backend.</param>
        /// <param name="squeeze">XOF squeeze backend.</param>
        /// <param name="pool">The pool to rent every buffer from.</param>
        /// <returns><c>true</c> iff the proof verifies; <c>false</c> otherwise.</returns>
        [SuppressMessage("Reliability", "CA2000", Justification = "The prepared relaxed instance is disposed in the finally block once Verify returns.")]
        public bool Verify(
            SpartanProof proof,
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

            //Preparation is deterministic — the verifier reaches the same
            //relaxed instance (u = 1, identity error commitment) the prover
            //prepared, with no randomness needed.
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
        /// Verifies a BaseFold-backed Spartan2 proof against a relaxed R1CS
        /// <paramref name="instance"/>. BaseFold is hash-based and transparent —
        /// no group operations — so this surface needs only the field-arithmetic
        /// backends plus the transcript backends; the opening verification's
        /// hashing is captured inside the verifying key's BaseFold provider.
        /// </summary>
        /// <param name="proof">The BaseFold Spartan proof to verify.</param>
        /// <param name="instance">The relaxed R1CS instance the proof claims satisfaction of.</param>
        /// <param name="transcript">A fresh transcript matching the prover's setup.</param>
        /// <param name="scalarAdd">Scalar-add backend.</param>
        /// <param name="scalarMultiply">Scalar-multiply backend.</param>
        /// <param name="scalarSubtract">Scalar-subtract backend.</param>
        /// <param name="scalarReduce">Scalar-reduce backend.</param>
        /// <param name="hash">Fixed-output hash backend used by the transcript.</param>
        /// <param name="squeeze">XOF squeeze backend used by the transcript.</param>
        /// <param name="pool">The pool to rent every buffer from.</param>
        /// <returns><c>true</c> iff the proof verifies; <c>false</c> otherwise.</returns>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the proof's curve or dimensions do not match the instance.</exception>
        public bool VerifyBaseFold(
            BaseFoldSpartanProof proof,
            RelaxedR1csInstance instance,
            FiatShamirTranscript transcript,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarSubtractDelegate scalarSubtract,
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

            CryptographicOperationCounters.Increment(CryptographicOperationKind.SpartanVerifierVerify, curve);

            try
            {
                return VerifyCore(
                    proof.GetSumcheckPart(),
                    proof.GetWitnessCommitmentBytes(),
                    proof.GetErrorOpeningProofBytes(),
                    proof.GetWitnessOpeningProofBytes(),
                    instance, transcript, scalarAdd, scalarMultiply, scalarSubtract, scalarReduce, hash, squeeze, pool, rowVariableCount, columnVariableCount, pcs);
            }
            catch(Exception ex) when (ex is InvalidOperationException or ArgumentException)
            {
                return false;
            }
        }


        /// <summary>
        /// Convenience overload that verifies a BaseFold-backed proof against a
        /// <em>raw</em> R1CS instance: prepares the raw instance into its relaxed
        /// equivalent and forwards to the relaxed <c>VerifyBaseFold</c>.
        /// </summary>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        [SuppressMessage("Reliability", "CA2000", Justification = "The prepared relaxed instance is disposed in the finally block once VerifyBaseFold returns.")]
        public bool VerifyBaseFold(
            BaseFoldSpartanProof proof,
            RawR1csInstance instance,
            FiatShamirTranscript transcript,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarSubtractDelegate scalarSubtract,
            ScalarReduceDelegate scalarReduce,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(verifier);
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(instance);
            ArgumentNullException.ThrowIfNull(pool);

            //Prepare the zero-error commitment through the same BaseFold provider
            //the prover used, so both reach the identical (deterministic) relaxed
            //instance.
            RelaxedR1csInstance relaxedInstance = instance.Prepare(verifier.VerifyingKey.Pcs, pool);
            try
            {
                return verifier.VerifyBaseFold(
                    proof, relaxedInstance, transcript,
                    scalarAdd, scalarMultiply, scalarSubtract, scalarReduce, hash, squeeze, pool);
            }
            finally
            {
                relaxedInstance.Dispose();
            }
        }


        /// <summary>
        /// Verifies a Ligero-backed Spartan2 proof against a relaxed R1CS
        /// instance. The Ligero-shaped sibling of <see cref="VerifyBaseFold(SpartanVerifier, BaseFoldSpartanProof, RelaxedR1csInstance, FiatShamirTranscript, ScalarAddDelegate, ScalarMultiplyDelegate, ScalarSubtractDelegate, ScalarReduceDelegate, FiatShamirHashDelegate, FiatShamirSqueezeDelegate, BaseMemoryPool)"/>;
        /// the opening verification lives in the provider's delegate, so the body is the same scheme-neutral core.
        /// </summary>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the proof's curve or dimensions do not match the instance.</exception>
        public bool VerifyLigero(
            LigeroSpartanProof proof,
            RelaxedR1csInstance instance,
            FiatShamirTranscript transcript,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarSubtractDelegate scalarSubtract,
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

            CryptographicOperationCounters.Increment(CryptographicOperationKind.SpartanVerifierVerify, curve);

            try
            {
                return VerifyCore(
                    proof.GetSumcheckPart(),
                    proof.GetWitnessCommitmentBytes(),
                    proof.GetErrorOpeningProofBytes(),
                    proof.GetWitnessOpeningProofBytes(),
                    instance, transcript, scalarAdd, scalarMultiply, scalarSubtract, scalarReduce, hash, squeeze, pool, rowVariableCount, columnVariableCount, pcs);
            }
            catch(Exception ex) when (ex is InvalidOperationException or ArgumentException)
            {
                return false;
            }
        }


        /// <summary>
        /// Convenience overload that verifies a Ligero-backed proof against a
        /// <em>raw</em> R1CS instance: prepares the raw instance into its relaxed
        /// equivalent and forwards to the relaxed <c>VerifyLigero</c>.
        /// </summary>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        [SuppressMessage("Reliability", "CA2000", Justification = "The prepared relaxed instance is disposed in the finally block once VerifyLigero returns.")]
        public bool VerifyLigero(
            LigeroSpartanProof proof,
            RawR1csInstance instance,
            FiatShamirTranscript transcript,
            ScalarAddDelegate scalarAdd,
            ScalarMultiplyDelegate scalarMultiply,
            ScalarSubtractDelegate scalarSubtract,
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
                return verifier.VerifyLigero(
                    proof, relaxedInstance, transcript,
                    scalarAdd, scalarMultiply, scalarSubtract, scalarReduce, hash, squeeze, pool);
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
        ReadOnlySpan<byte> witnessCommitmentBytes,
        ReadOnlySpan<byte> errorOpeningBytes,
        ReadOnlySpan<byte> witnessOpeningBytes,
        RelaxedR1csInstance instance,
        FiatShamirTranscript transcript,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMultiply,
        ScalarSubtractDelegate scalarSubtract,
        ScalarReduceDelegate scalarReduce,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        BaseMemoryPool pool,
        int rowVariableCount,
        int columnVariableCount,
        PolynomialCommitmentProvider pcs)
    {
        //The embedded opening verification (group operations, scalar inversion)
        //is captured inside the provider's VerifyEvaluation delegate, so the
        //scheme-neutral core needs only the field arithmetic for the sumcheck
        //replay and the terminating identity checks.
        int scalarSize = Scalar.SizeBytes;
        CurveParameterSet curve = instance.Curve;
        //Bind the relaxed instance and absorb the witness commitment,
        //mirroring the prover's steps 1 and 1b of the SPARTAN2.md
        //transcript schedule (dimensions, matrices, public inputs, u,
        //error commitment).
        transcript.AbsorbRelaxedR1csInstance(instance, hash);

        using PolynomialCommitment witnessCommitment = PolynomialCommitment.FromBytes(
            witnessCommitmentBytes,
            curve,
            pcs.Scheme,
            pool);

        transcript.AbsorbBytes(
            new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.WitnessCommitment),
            witnessCommitment.AsReadOnlySpan(),
            hash);

        //Squeeze τ for the outer-sumcheck eq factor.
        Scalar[] tauScalars = SqueezeChallenges(
            transcript, rowVariableCount,
            WellKnownSpartanTranscriptLabels.OuterTau,
            squeeze, hash, scalarReduce, curve, pool);

        try
        {
            //Initial outer-sumcheck claim is the field zero.
            using IMemoryOwner<byte> zeroOwner = pool.Rent(scalarSize);
            Span<byte> zeroBytes = zeroOwner.Memory.Span[..scalarSize];
            zeroBytes.Clear();
            using Scalar initialOuterClaim = Scalar.FromCanonical(zeroBytes, curve, pool);

            using SumcheckVerifierResult outer = OuterSumcheckVerifier.Run(
                sumcheckPart, rowVariableCount, initialOuterClaim, transcript,
                hash, squeeze, scalarReduce,
                scalarAdd, scalarSubtract, scalarMultiply, pool);

            //Absorb the three outer terminating claims as one block, then
            //E(r_x) under its own label — mirroring the prover.
            Span<byte> claimsBuffer = stackalloc byte[3 * scalarSize];
            sumcheckPart.GetClaimAzBytes().CopyTo(claimsBuffer[..scalarSize]);
            sumcheckPart.GetClaimBzBytes().CopyTo(claimsBuffer.Slice(scalarSize, scalarSize));
            sumcheckPart.GetClaimCzBytes().CopyTo(claimsBuffer.Slice(2 * scalarSize, scalarSize));
            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.OuterClaimedEvaluations),
                claimsBuffer,
                hash);

            ReadOnlySpan<byte> errorEvalBytes = sumcheckPart.GetErrorEvaluationBytes();
            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.OuterErrorEvaluation),
                errorEvalBytes,
                hash);

            using Scalar errorEval = Scalar.FromCanonical(errorEvalBytes, curve, pool);

            using Scalar r = transcript.SqueezeScalar(
                new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.InnerCombinationChallenge),
                squeeze, hash, scalarReduce, curve, pool);

            //Materialise claim_Az / Bz / Cz from the proof bytes.
            using Scalar claimAz = Scalar.FromCanonical(sumcheckPart.GetClaimAzBytes(), curve, pool);
            using Scalar claimBz = Scalar.FromCanonical(sumcheckPart.GetClaimBzBytes(), curve, pool);
            using Scalar claimCz = Scalar.FromCanonical(sumcheckPart.GetClaimCzBytes(), curve, pool);

            //Compute the joint inner claim: claim_Az + r · claim_Bz + r² · claim_Cz.
            using Scalar rSquared = MultiplyScalars(r, r, scalarMultiply, pool);
            using IMemoryOwner<byte> jointBytesOwner = pool.Rent(scalarSize);
            Span<byte> jointBytes = jointBytesOwner.Memory.Span[..scalarSize];
            using IMemoryOwner<byte> termBytesOwner = pool.Rent(scalarSize);
            Span<byte> termBytes = termBytesOwner.Memory.Span[..scalarSize];
            using IMemoryOwner<byte> term2BytesOwner = pool.Rent(scalarSize);
            Span<byte> term2Bytes = term2BytesOwner.Memory.Span[..scalarSize];

            claimAz.AsReadOnlySpan().CopyTo(jointBytes);
            scalarMultiply(r.AsReadOnlySpan(), claimBz.AsReadOnlySpan(), termBytes, curve);
            scalarAdd(jointBytes, termBytes, jointBytes, curve);
            scalarMultiply(rSquared.AsReadOnlySpan(), claimCz.AsReadOnlySpan(), termBytes, curve);
            scalarAdd(jointBytes, termBytes, jointBytes, curve);

            using Scalar jointClaim = Scalar.FromCanonical(jointBytes, curve, pool);

            using SumcheckVerifierResult inner = InnerSumcheckVerifier.Run(
                sumcheckPart, columnVariableCount, jointClaim, transcript,
                hash, squeeze, scalarReduce,
                scalarAdd, scalarSubtract, scalarMultiply, pool);

            //Absorb eval_W.
            ReadOnlySpan<byte> evalWBytes = sumcheckPart.GetEvalWBytes();
            transcript.AbsorbBytes(
                new FiatShamirOperationLabel(WellKnownSpartanTranscriptLabels.WitnessEvaluation),
                evalWBytes,
                hash);

            using Scalar evalW = Scalar.FromCanonical(evalWBytes, curve, pool);

            //Reconstruct the error-commitment opening proof (at r_x) and the
            //witness opening proof (at r_y), in the prover's order.
            using PolynomialOpening errorOpeningProof = PolynomialOpening.FromBytes(
                errorOpeningBytes,
                curve,
                pcs.Scheme,
                pool);

            using PolynomialOpening openingProof = PolynomialOpening.FromBytes(
                witnessOpeningBytes,
                curve,
                pcs.Scheme,
                pool);

            Scalar[] rxArray = ToScalarArray(outer.Challenges, pool);
            Scalar[] ryArray = ToScalarArray(inner.Challenges, pool);
            try
            {
                //Verify the error commitment opens to E(r_x) at r_x. This
                //runs first on the transcript, matching the prover.
                bool errorCheck = pcs.VerifyEvaluation(
                    instance.ErrorCommitment,
                    rxArray,
                    errorEval,
                    errorOpeningProof,
                    transcript,
                    pool);

                //Compute eval_PublicAndU and eval_Z = eval_W + eval_PublicAndU,
                //where the constant slot carries u (the relaxed convention).
                using Scalar evalPublicAndU = EvalPublicAndOneComputation.Compute(
                    instance.GetUBytes(),
                    instance.GetPublicInputsBytes(),
                    instance.PublicInputCount,
                    columnVariableCount,
                    ryArray,
                    scalarAdd, scalarSubtract, scalarMultiply,
                    curve,
                    pool);

                using IMemoryOwner<byte> evalZOwner = pool.Rent(scalarSize);
                Span<byte> evalZBytes = evalZOwner.Memory.Span[..scalarSize];
                scalarAdd(evalW.AsReadOnlySpan(), evalPublicAndU.AsReadOnlySpan(), evalZBytes, curve);

                //Hyrax verify the witness opening (claimed value = eval_W).
                bool hyraxCheck = pcs.VerifyEvaluation(
                    witnessCommitment,
                    ryArray,
                    evalW,
                    openingProof,
                    transcript,
                    pool);

                //Outer terminating identity (relaxed):
                //  outer.FinalClaim == eq(τ, r_x) · (claim_Az · claim_Bz − u · claim_Cz − E(r_x)).
                using Scalar eqAtRx = EvaluateEq(
                    tauScalars, rxArray, scalarAdd, scalarSubtract, scalarMultiply, curve, pool);

                using IMemoryOwner<byte> outerExpectedOwner = pool.Rent(scalarSize);
                Span<byte> outerExpected = outerExpectedOwner.Memory.Span[..scalarSize];
                scalarMultiply(claimAz.AsReadOnlySpan(), claimBz.AsReadOnlySpan(), termBytes, curve);
                scalarMultiply(instance.GetUBytes(), claimCz.AsReadOnlySpan(), term2Bytes, curve);
                scalarSubtract(termBytes, term2Bytes, termBytes, curve);
                scalarSubtract(termBytes, errorEval.AsReadOnlySpan(), termBytes, curve);
                scalarMultiply(eqAtRx.AsReadOnlySpan(), termBytes, outerExpected, curve);
                bool outerCheck = outerExpected.SequenceEqual(outer.FinalClaim.AsReadOnlySpan());

                //Inner terminating identity:
                //  inner.FinalClaim == [A~(r_x, r_y) + r · B~(r_x, r_y) + r² · C~(r_x, r_y)] · eval_Z.
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

                using IMemoryOwner<byte> innerExpectedOwner = pool.Rent(scalarSize);
                Span<byte> innerExpected = innerExpectedOwner.Memory.Span[..scalarSize];
                scalarMultiply(evalAbcBytes, evalZBytes, innerExpected, curve);
                bool innerCheck = innerExpected.SequenceEqual(inner.FinalClaim.AsReadOnlySpan());

                return errorCheck && hyraxCheck && outerCheck && innerCheck;
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


    /// <summary>
    /// Disposable wrapper around a <see cref="MatrixMleEvaluation"/>
    /// view used by the verifier for the three matrix-MLE evaluations.
    /// The view itself does not own the matrix; this wrapper exists
    /// only to give every algebraic-evaluation handle inside Verify a
    /// uniform <c>using</c>-disposable shape.
    /// </summary>
    private readonly struct MatrixMleEvaluationOwner: IDisposable
    {
        public MatrixMleEvaluation View { get; }

        private MatrixMleEvaluationOwner(MatrixMleEvaluation view) { View = view; }

        public static MatrixMleEvaluationOwner From(R1csMatrix matrix) => new(new MatrixMleEvaluation(matrix));

        public void Dispose() { }
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


    /// <summary>
    /// Evaluates <c>eq(τ, r_x) = Π_i [τ_i · r_x_i + (1 − τ_i) · (1 − r_x_i)]</c>.
    /// Small inline loop used only by Verify for the outer terminating
    /// identity check.
    /// </summary>
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
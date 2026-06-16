using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// The Hyrax weighted opening: commit a vector as a <em>single-row</em>
/// Pedersen vector commitment and prove the inner product
/// <c>v = ⟨vector, W⟩</c> against a <em>public</em> weight vector <c>W</c> —
/// the Pedersen/IPA analogue of BaseFold's <c>ProveWeightedSum</c> /
/// <c>VerifyWeightedSum</c> (SM.1). An evaluation opening factors its
/// <c>eq</c> weights through the matrix split <c>L ⊗ R</c>; an arbitrary
/// public weight vector does not factor, so the weighted opening commits the
/// whole vector as one row (the row combination is trivially the identity)
/// and runs the inner-product argument with <c>W</c> in the public-vector
/// seat the evaluation path gives <c>R</c>.
/// </summary>
/// <remarks>
/// <para>
/// This is how the statistical-mask construction binds its sumcheck-mask
/// coefficients over the Hyrax path (<c>ZK-STATMASK-DESIGN.md</c> §2
/// v3): the committed vector is <c>C* = (mask coefficients ‖ filler)</c> and
/// the weights are the mask basis's monomials at the bound challenges with
/// field one on the filler block. The weight vector must be public and known
/// to the verifier — the protocol neither commits nor transmits it, exactly
/// as the evaluation path's point is the consumer's to bind.
/// </para>
/// <para>
/// The proof reuses the <see cref="HyraxOpeningProof"/> wire layout
/// (<c>C_f</c>, IPA round pairs, final scalar, final blinding, blinding
/// correction) with <c>log₂(vector length)</c> IPA rounds, under
/// weighted-opening transcript labels so the two protocols stay
/// domain-separated.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class HyraxWeightedOpeningExtensions
{
    private const string WeightedIpaRoundLabelPrefix = "hyrax.weighted.ipa.round";
    private const string WeightedFCommitmentLabel = "hyrax.weighted.f-commitment";

    //A single-row commitment: the vector is one Pedersen row, so the row
    //combination step of the evaluation path degenerates to the identity.
    private const int SingleRowCount = 1;


    extension(HyraxCommitment commitment)
    {
        /// <summary>
        /// Produces a weighted-opening proof attesting that the single-row
        /// committed vector has the inner product <c>⟨vector, W⟩</c> with the
        /// public weight vector <paramref name="weights"/> (returned alongside
        /// the proof so the caller does not need to recompute it).
        /// </summary>
        /// <remarks>
        /// The caller is responsible for the transcript already being bound to
        /// the statement (the weight vector's identity and the claimed value's
        /// role) before opening, exactly as with the evaluation opening's point.
        /// </remarks>
        /// <param name="witness">The single-row commitment witness from <c>CommitVector</c>.</param>
        /// <param name="vector">The committed vector, carried as an MLE.</param>
        /// <param name="weights">The public weight vector <c>W</c>, carried as an MLE of the same shape.</param>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the commitment is not single-row or a shape does not match.</exception>
        [SuppressMessage("Reliability", "CA2000", Justification = "Both returned disposables (the proof and the claimed-value scalar) transfer ownership to the caller.")]
        public (HyraxOpeningProof Proof, Scalar ClaimedValue) OpenWeightedSum(
            HyraxOpeningWitness witness,
            MultilinearExtension vector,
            MultilinearExtension weights,
            HyraxCommitmentKey key,
            FiatShamirTranscript transcript,
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
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(commitment);
            ArgumentNullException.ThrowIfNull(witness);
            ArgumentNullException.ThrowIfNull(vector);
            ArgumentNullException.ThrowIfNull(weights);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(transcript);
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
            ArgumentNullException.ThrowIfNull(pool);

            ValidateWeightedOpenShape(commitment, witness, vector, weights, key);

            int columnCount = commitment.ColumnCount;
            int scalarSize = Scalar.SizeBytes;
            var curve = key.Curve;
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);

            //claimed_value = ⟨vector, W⟩.
            using IMemoryOwner<byte> claimedValueOwner = pool.Rent(scalarSize);
            Span<byte> claimedValueBytes = claimedValueOwner.Memory.Span[..scalarSize];
            HyraxOpeningProofExtensions.ComputeScalarInnerProduct(
                vector.AsReadOnlySpan(), weights.AsReadOnlySpan(), columnCount, scalarSize, claimedValueBytes, scalarAdd, scalarMul, curve, pool);

            //Sample r_f, compute Δr = r_f − b₀. The single row makes the
            //evaluation path's L-combined blind the row blind itself.
            using IMemoryOwner<byte> rFOwner = pool.Rent(scalarSize);
            using IMemoryOwner<byte> deltaROwner = pool.Rent(scalarSize);
            Span<byte> rFBytes = rFOwner.Memory.Span[..scalarSize];
            Span<byte> deltaRBytes = deltaROwner.Memory.Span[..scalarSize];
            _ = scalarRandom(rFBytes, curve, Tag.Empty);
            scalarSubtract(rFBytes, witness.AsReadOnlySpan()[..scalarSize], deltaRBytes, curve);

            //Commit the vector freshly: C_f = ⟨vector, G⟩ + r_f·H, absorbed
            //before the IPA so its challenges depend on the committed vector.
            using IMemoryOwner<byte> cFOwner = pool.Rent(g1Size);
            Span<byte> cFBytes = cFOwner.Memory.Span[..g1Size];
            HyraxOpeningProofExtensions.ComputePedersenCommitment(
                vector.AsReadOnlySpan(), rFBytes, key, columnCount, cFBytes, g1Msm, pool);

            transcript.AbsorbBytes(new FiatShamirOperationLabel(WeightedFCommitmentLabel), cFBytes, hash);

            int roundCount = InnerProductArgument.GetRoundCount(columnCount);
            int proofBufferSize = HyraxOpeningProof.GetBufferSizeBytes(roundCount, curve);
            IMemoryOwner<byte> proofOwner = pool.Rent(proofBufferSize);
            Span<byte> proofBuffer = proofOwner.Memory.Span[..proofBufferSize];
            cFBytes.CopyTo(proofBuffer[..g1Size]);

            //IPA working buffers: the generators, the secret vector, and the
            //public weights in the seat the evaluation path gives R.
            using IMemoryOwner<byte> gWorkingOwner = pool.Rent(columnCount * g1Size);
            using IMemoryOwner<byte> fWorkingOwner = pool.Rent(columnCount * scalarSize);
            using IMemoryOwner<byte> wWorkingOwner = pool.Rent(columnCount * scalarSize);
            Span<byte> gWorking = gWorkingOwner.Memory.Span[..(columnCount * g1Size)];
            Span<byte> fWorking = fWorkingOwner.Memory.Span[..(columnCount * scalarSize)];
            Span<byte> wWorking = wWorkingOwner.Memory.Span[..(columnCount * scalarSize)];

            for(int j = 0; j < columnCount; j++)
            {
                key.GetGenerator(j).CopyTo(gWorking.Slice(j * g1Size, g1Size));
            }

            vector.AsReadOnlySpan().CopyTo(fWorking);
            weights.AsReadOnlySpan().CopyTo(wWorking);

            int roundPairsOffset = g1Size;
            int roundPairsLength = roundCount * 2 * g1Size;
            int finalScalarOffset = roundPairsOffset + roundPairsLength;
            int finalBlindingOffset = finalScalarOffset + scalarSize;
            int blindingCorrectionOffset = finalBlindingOffset + scalarSize;

            InnerProductArgument.Prove(
                fWorking,
                gWorking,
                wWorking,
                key.GetBlindingGenerator(),
                key.GetValueGenerator(),
                proofBuffer.Slice(roundPairsOffset, roundPairsLength),
                proofBuffer.Slice(finalScalarOffset, scalarSize),
                columnCount,
                WeightedIpaRoundLabelPrefix,
                transcript,
                scalarAdd,
                scalarMul,
                scalarInvert,
                scalarReduce,
                g1Add,
                g1ScalarMul,
                g1Msm,
                hash,
                squeeze,
                curve,
                pool);

            rFBytes.CopyTo(proofBuffer.Slice(finalBlindingOffset, scalarSize));
            deltaRBytes.CopyTo(proofBuffer.Slice(blindingCorrectionOffset, scalarSize));

            CryptographicOperationCounters.Increment(CryptographicOperationKind.HyraxOpen, curve);

            Tag proofTag = Tag.Create(
                (typeof(AlgebraicRole), (object)AlgebraicRole.OpeningProof),
                (typeof(CurveParameterSet), (object)curve),
                (typeof(CommitmentScheme), (object)CommitmentScheme.Hyrax));

            var proof = new HyraxOpeningProof(proofOwner, roundCount, curve, proofTag);
            var claimedValueScalar = Scalar.FromCanonical(claimedValueBytes, curve, pool);

            return (proof, claimedValueScalar);
        }


        /// <summary>
        /// Verifies a weighted-opening proof against the receiver single-row
        /// commitment, the public weight vector, and the claimed inner-product
        /// value. Returns <see langword="true"/> iff every algebraic check
        /// passes.
        /// </summary>
        /// <exception cref="ArgumentNullException">When a reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the commitment is not single-row or a shape does not match.</exception>
        public bool VerifyWeightedSum(
            MultilinearExtension weights,
            Scalar claimedValue,
            HyraxOpeningProof proof,
            HyraxCommitmentKey key,
            FiatShamirTranscript transcript,
            FiatShamirHashDelegate hash,
            FiatShamirSqueezeDelegate squeeze,
            ScalarReduceDelegate scalarReduce,
            ScalarAddDelegate scalarAdd,
            ScalarSubtractDelegate scalarSubtract,
            ScalarMultiplyDelegate scalarMul,
            ScalarInvertDelegate scalarInvert,
            G1AddDelegate g1Add,
            G1ScalarMultiplyDelegate g1ScalarMul,
            G1MultiScalarMultiplyDelegate g1Msm,
            BaseMemoryPool pool)
        {
            ArgumentNullException.ThrowIfNull(commitment);
            ArgumentNullException.ThrowIfNull(weights);
            ArgumentNullException.ThrowIfNull(claimedValue);
            ArgumentNullException.ThrowIfNull(proof);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(hash);
            ArgumentNullException.ThrowIfNull(squeeze);
            ArgumentNullException.ThrowIfNull(scalarReduce);
            ArgumentNullException.ThrowIfNull(scalarAdd);
            ArgumentNullException.ThrowIfNull(scalarSubtract);
            ArgumentNullException.ThrowIfNull(scalarMul);
            ArgumentNullException.ThrowIfNull(scalarInvert);
            ArgumentNullException.ThrowIfNull(g1Add);
            ArgumentNullException.ThrowIfNull(g1ScalarMul);
            ArgumentNullException.ThrowIfNull(g1Msm);
            ArgumentNullException.ThrowIfNull(pool);

            ValidateWeightedVerifyShape(commitment, proof, weights, key);

            int columnCount = commitment.ColumnCount;
            int scalarSize = Scalar.SizeBytes;
            var curve = key.Curve;
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);

            //The single row makes the combined commitment the row itself:
            //blinding-correction check C_f ?= C₀ + Δr·H.
            ReadOnlySpan<byte> cFBytes = proof.GetFCommitment();
            ReadOnlySpan<byte> deltaRBytes = proof.GetBlindingCorrection();
            using IMemoryOwner<byte> deltaRTimesHOwner = pool.Rent(g1Size);
            using IMemoryOwner<byte> cExpectedOwner = pool.Rent(g1Size);
            Span<byte> deltaRTimesH = deltaRTimesHOwner.Memory.Span[..g1Size];
            Span<byte> cExpected = cExpectedOwner.Memory.Span[..g1Size];
            g1ScalarMul(key.GetBlindingGenerator(), deltaRBytes, deltaRTimesH, curve);
            g1Add(commitment.GetRowCommitment(0), deltaRTimesH, cExpected, curve);

            if(!cExpected.SequenceEqual(cFBytes))
            {
                CryptographicOperationCounters.Increment(CryptographicOperationKind.HyraxVerify, curve);

                return false;
            }

            transcript.AbsorbBytes(new FiatShamirOperationLabel(WeightedFCommitmentLabel), cFBytes, hash);

            using IMemoryOwner<byte> gWorkingOwner = pool.Rent(columnCount * g1Size);
            using IMemoryOwner<byte> wWorkingOwner = pool.Rent(columnCount * scalarSize);
            Span<byte> gWorking = gWorkingOwner.Memory.Span[..(columnCount * g1Size)];
            Span<byte> wWorking = wWorkingOwner.Memory.Span[..(columnCount * scalarSize)];

            for(int j = 0; j < columnCount; j++)
            {
                key.GetGenerator(j).CopyTo(gWorking.Slice(j * g1Size, g1Size));
            }

            weights.AsReadOnlySpan().CopyTo(wWorking);

            int roundPairsLength = proof.IpaRoundCount * 2 * g1Size;
            int roundPairsOffset = g1Size;

            bool ipaOk = InnerProductArgument.Verify(
                initialCommitment: cFBytes,
                claimedValueBytes: claimedValue.AsReadOnlySpan(),
                rBlindingBytes: proof.GetFinalBlinding(),
                finalScalarBytes: proof.GetFinalScalar(),
                roundPairs: proof.AsReadOnlySpan().Slice(roundPairsOffset, roundPairsLength),
                hPoint: key.GetBlindingGenerator(),
                uPoint: key.GetValueGenerator(),
                gWorking: gWorking,
                rWorking: wWorking,
                initialLength: columnCount,
                ipaRoundLabelPrefix: WeightedIpaRoundLabelPrefix,
                transcript: transcript,
                scalarAdd: scalarAdd,
                scalarMul: scalarMul,
                scalarInvert: scalarInvert,
                scalarReduce: scalarReduce,
                g1Add: g1Add,
                g1ScalarMul: g1ScalarMul,
                hash: hash,
                squeeze: squeeze,
                curve: curve,
                pool: pool);

            CryptographicOperationCounters.Increment(CryptographicOperationKind.HyraxVerify, curve);

            return ipaOk;
        }
    }


    private static void ValidateWeightedOpenShape(
        HyraxCommitment commitment,
        HyraxOpeningWitness witness,
        MultilinearExtension vector,
        MultilinearExtension weights,
        HyraxCommitmentKey key)
    {
        if(commitment.Curve.Code != vector.Curve.Code || vector.Curve.Code != key.Curve.Code || weights.Curve.Code != key.Curve.Code)
        {
            throw new ArgumentException(
                $"OpenWeightedSum requires commitment / vector / weights / key to share a curve; got {commitment.Curve}, {vector.Curve}, {weights.Curve}, {key.Curve}.");
        }

        if(commitment.RowCount != SingleRowCount)
        {
            throw new ArgumentException(
                $"A weighted opening requires a single-row vector commitment (CommitVector); the commitment has {commitment.RowCount} rows.");
        }

        if(witness.RowCount != SingleRowCount)
        {
            throw new ArgumentException(
                $"A weighted opening requires the single-row commitment witness; the witness has {witness.RowCount} rows.");
        }

        if(vector.EvaluationCount != commitment.ColumnCount)
        {
            throw new ArgumentException(
                $"The vector carries {vector.EvaluationCount} coordinates; the commitment was built over {commitment.ColumnCount}.");
        }

        if(weights.EvaluationCount != vector.EvaluationCount)
        {
            throw new ArgumentException(
                $"The weight vector carries {weights.EvaluationCount} coordinates; the committed vector has {vector.EvaluationCount}.");
        }

        if(key.VectorLength < commitment.ColumnCount)
        {
            throw new ArgumentException(
                $"Commitment key has VectorLength = {key.VectorLength}; opening this commitment requires at least {commitment.ColumnCount} generators.");
        }
    }


    private static void ValidateWeightedVerifyShape(
        HyraxCommitment commitment,
        HyraxOpeningProof proof,
        MultilinearExtension weights,
        HyraxCommitmentKey key)
    {
        if(commitment.Curve.Code != key.Curve.Code || commitment.Curve.Code != proof.Curve.Code || weights.Curve.Code != key.Curve.Code)
        {
            throw new ArgumentException(
                $"VerifyWeightedSum requires commitment / proof / weights / key to share a curve; got {commitment.Curve}, {proof.Curve}, {weights.Curve}, {key.Curve}.");
        }

        if(commitment.RowCount != SingleRowCount)
        {
            throw new ArgumentException(
                $"A weighted opening verifies against a single-row vector commitment; the commitment has {commitment.RowCount} rows.");
        }

        if(weights.EvaluationCount != commitment.ColumnCount)
        {
            throw new ArgumentException(
                $"The weight vector carries {weights.EvaluationCount} coordinates; the commitment was built over {commitment.ColumnCount}.");
        }

        int expectedRoundCount = InnerProductArgument.GetRoundCount(commitment.ColumnCount);
        if(proof.IpaRoundCount != expectedRoundCount)
        {
            throw new ArgumentException(
                $"Proof has {proof.IpaRoundCount} IPA rounds; commitment column count {commitment.ColumnCount} requires {expectedRoundCount}.");
        }

        if(key.VectorLength < commitment.ColumnCount)
        {
            throw new ArgumentException(
                $"Commitment key has VectorLength = {key.VectorLength}; verifying this proof requires at least {commitment.ColumnCount} generators.");
        }
    }
}

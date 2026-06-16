using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Telemetry;
using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Open / verify extension methods on
/// <see cref="HyraxCommitment"/>. Produces and checks the Hyrax
/// opening proof against a committed MLE and an evaluation point.
/// </summary>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class HyraxOpeningProofExtensions
{
    private const string IpaRoundLabelPrefix = "hyrax.ipa.round";
    private const string FCommitmentLabel = "hyrax.open.f-commitment";


    extension(HyraxCommitment commitment)
    {
        /// <summary>
        /// Produces an opening proof attesting that the committed MLE
        /// evaluates at <paramref name="evaluationPoint"/> to a specific
        /// value (returned alongside the proof so the caller does not
        /// need to recompute it).
        /// </summary>
        [SuppressMessage("Reliability", "CA2000", Justification = "Both returned disposables (the proof and the claimed-value scalar) transfer ownership to the caller; their backing pool-rented buffers are released when the caller disposes them.")]
        public (HyraxOpeningProof Proof, Scalar ClaimedValue) Open(
            HyraxOpeningWitness witness,
            MultilinearExtension mle,
            ReadOnlySpan<Scalar> evaluationPoint,
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
            ArgumentNullException.ThrowIfNull(mle);
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

            ValidateOpenShape(commitment, witness, mle, evaluationPoint, key);

            int rowCount = commitment.RowCount;
            int columnCount = commitment.ColumnCount;
            int scalarSize = Scalar.SizeBytes;
            var curve = key.Curve;
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);

            int rowVarCount = (mle.VariableCount + 1) / 2;
            int colVarCount = mle.VariableCount / 2;

            //Lagrange basis L (length rowCount) from the upper rowVarCount variables
            //and R (length columnCount) from the lower colVarCount variables.
            using IMemoryOwner<byte> lOwner = pool.Rent(rowCount * scalarSize);
            using IMemoryOwner<byte> rOwner = pool.Rent(columnCount * scalarSize);
            Span<byte> lVector = lOwner.Memory.Span[..(rowCount * scalarSize)];
            Span<byte> rVector = rOwner.Memory.Span[..(columnCount * scalarSize)];

            ComputeLagrangeVector(evaluationPoint, colVarCount, rowVarCount, lVector, scalarAdd, scalarSubtract, scalarMul, curve, pool);
            ComputeLagrangeVector(evaluationPoint, 0, colVarCount, rVector, scalarAdd, scalarSubtract, scalarMul, curve, pool);

            //f = L · M, where M is the row-major matrix of MLE evaluations.
            using IMemoryOwner<byte> fOwner = pool.Rent(columnCount * scalarSize);
            Span<byte> fVector = fOwner.Memory.Span[..(columnCount * scalarSize)];
            ComputeMatrixVectorProduct(lVector, mle.AsReadOnlySpan(), rowCount, columnCount, scalarSize, fVector, scalarAdd, scalarMul, curve, pool);

            //r_combined = ⟨L, row_blindings⟩.
            using IMemoryOwner<byte> rCombinedOwner = pool.Rent(scalarSize);
            Span<byte> rCombined = rCombinedOwner.Memory.Span[..scalarSize];
            ComputeScalarInnerProduct(lVector, witness.AsReadOnlySpan(), rowCount, scalarSize, rCombined, scalarAdd, scalarMul, curve, pool);

            //claimed_value = ⟨f, R⟩.
            using IMemoryOwner<byte> claimedValueOwner = pool.Rent(scalarSize);
            Span<byte> claimedValueBytes = claimedValueOwner.Memory.Span[..scalarSize];
            ComputeScalarInnerProduct(fVector, rVector, columnCount, scalarSize, claimedValueBytes, scalarAdd, scalarMul, curve, pool);

            //Sample r_f, compute Δr = r_f - r_combined.
            using IMemoryOwner<byte> rFOwner = pool.Rent(scalarSize);
            using IMemoryOwner<byte> deltaROwner = pool.Rent(scalarSize);
            Span<byte> rFBytes = rFOwner.Memory.Span[..scalarSize];
            Span<byte> deltaRBytes = deltaROwner.Memory.Span[..scalarSize];
            _ = scalarRandom(rFBytes, curve, Tag.Empty);
            scalarSubtract(rFBytes, rCombined, deltaRBytes, curve);

            //Commit f freshly: C_f = ⟨f, G⟩ + r_f · H using the first columnCount
            //generators and the blinding generator. We assemble the MSM directly
            //since the existing PedersenVectorCommitmentExtensions.Commit takes
            //scalar objects and we already have raw bytes.
            using IMemoryOwner<byte> cFOwner = pool.Rent(g1Size);
            Span<byte> cFBytes = cFOwner.Memory.Span[..g1Size];
            ComputePedersenCommitment(fVector, rFBytes, key, columnCount, cFBytes, g1Msm, pool);

            //Absorb C_f into the transcript before running the IPA so the IPA's
            //challenges depend on the prover's committed f.
            transcript.AbsorbBytes(new FiatShamirOperationLabel(FCommitmentLabel), cFBytes, hash);

            //Allocate the proof buffer and copy C_f into its leading slot.
            int roundCount = InnerProductArgument.GetRoundCount(columnCount);
            int proofBufferSize = HyraxOpeningProof.GetBufferSizeBytes(roundCount, curve);
            IMemoryOwner<byte> proofOwner = pool.Rent(proofBufferSize);
            Span<byte> proofBuffer = proofOwner.Memory.Span[..proofBufferSize];
            cFBytes.CopyTo(proofBuffer[..g1Size]);

            //IPA working buffers: G_working (copy of the first columnCount generators), f_working (copy of f), r_working (copy of R).
            using IMemoryOwner<byte> gWorkingOwner = pool.Rent(columnCount * g1Size);
            using IMemoryOwner<byte> fWorkingOwner = pool.Rent(columnCount * scalarSize);
            using IMemoryOwner<byte> rWorkingOwner = pool.Rent(columnCount * scalarSize);
            Span<byte> gWorking = gWorkingOwner.Memory.Span[..(columnCount * g1Size)];
            Span<byte> fWorking = fWorkingOwner.Memory.Span[..(columnCount * scalarSize)];
            Span<byte> rWorking = rWorkingOwner.Memory.Span[..(columnCount * scalarSize)];

            for(int j = 0; j < columnCount; j++)
            {
                key.GetGenerator(j).CopyTo(gWorking.Slice(j * g1Size, g1Size));
            }

            fVector.CopyTo(fWorking);
            rVector.CopyTo(rWorking);

            int roundPairsOffset = g1Size;
            int roundPairsLength = roundCount * 2 * g1Size;
            int finalScalarOffset = roundPairsOffset + roundPairsLength;
            int finalBlindingOffset = finalScalarOffset + scalarSize;
            int blindingCorrectionOffset = finalBlindingOffset + scalarSize;

            InnerProductArgument.Prove(
                fWorking,
                gWorking,
                rWorking,
                key.GetBlindingGenerator(),
                key.GetValueGenerator(),
                proofBuffer.Slice(roundPairsOffset, roundPairsLength),
                proofBuffer.Slice(finalScalarOffset, scalarSize),
                columnCount,
                IpaRoundLabelPrefix,
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
        /// Verifies an opening proof against the receiver commitment, a
        /// claimed evaluation value, and the evaluation point. Returns
        /// true iff every algebraic check passes.
        /// </summary>
        public bool VerifyOpening(
            ReadOnlySpan<Scalar> evaluationPoint,
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

            ValidateVerifyShape(commitment, proof, evaluationPoint, key);

            int rowCount = commitment.RowCount;
            int columnCount = commitment.ColumnCount;
            int scalarSize = Scalar.SizeBytes;
            var curve = key.Curve;
            int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);

            int rowVarCount = (commitment.VariableCount + 1) / 2;
            int colVarCount = commitment.VariableCount / 2;

            //Reconstruct L and R from the evaluation point.
            using IMemoryOwner<byte> lOwner = pool.Rent(rowCount * scalarSize);
            using IMemoryOwner<byte> rOwner = pool.Rent(columnCount * scalarSize);
            Span<byte> lVector = lOwner.Memory.Span[..(rowCount * scalarSize)];
            Span<byte> rVector = rOwner.Memory.Span[..(columnCount * scalarSize)];
            ComputeLagrangeVector(evaluationPoint, colVarCount, rowVarCount, lVector, scalarAdd, scalarSubtract, scalarMul, curve, pool);
            ComputeLagrangeVector(evaluationPoint, 0, colVarCount, rVector, scalarAdd, scalarSubtract, scalarMul, curve, pool);

            //Row-combined commitment C_combined = Σ L[i] · C_rows[i] via MSM.
            using IMemoryOwner<byte> cCombinedOwner = pool.Rent(g1Size);
            Span<byte> cCombined = cCombinedOwner.Memory.Span[..g1Size];
            g1Msm(commitment.AsReadOnlySpan(), lVector, rowCount, cCombined, curve);

            //Blinding-correction check: C_f - C_combined ?= Δr · H.
            ReadOnlySpan<byte> cFBytes = proof.GetFCommitment();
            ReadOnlySpan<byte> deltaRBytes = proof.GetBlindingCorrection();
            using IMemoryOwner<byte> deltaRTimesHOwner = pool.Rent(g1Size);
            using IMemoryOwner<byte> cCombinedPlusOwner = pool.Rent(g1Size);
            Span<byte> deltaRTimesH = deltaRTimesHOwner.Memory.Span[..g1Size];
            Span<byte> cCombinedPlus = cCombinedPlusOwner.Memory.Span[..g1Size];
            g1ScalarMul(key.GetBlindingGenerator(), deltaRBytes, deltaRTimesH, curve);
            g1Add(cCombined, deltaRTimesH, cCombinedPlus, curve);

            bool blindingCheck = cCombinedPlus.SequenceEqual(cFBytes);
            if(!blindingCheck)
            {
                CryptographicOperationCounters.Increment(CryptographicOperationKind.HyraxVerify, curve);
                return false;
            }

            //Absorb C_f into transcript (same operation label the prover used).
            transcript.AbsorbBytes(new FiatShamirOperationLabel(FCommitmentLabel), cFBytes, hash);

            //IPA working buffers seeded with the first columnCount generators and R.
            using IMemoryOwner<byte> gWorkingOwner = pool.Rent(columnCount * g1Size);
            using IMemoryOwner<byte> rWorkingOwner = pool.Rent(columnCount * scalarSize);
            Span<byte> gWorking = gWorkingOwner.Memory.Span[..(columnCount * g1Size)];
            Span<byte> rWorking = rWorkingOwner.Memory.Span[..(columnCount * scalarSize)];

            for(int j = 0; j < columnCount; j++)
            {
                key.GetGenerator(j).CopyTo(gWorking.Slice(j * g1Size, g1Size));
            }

            rVector.CopyTo(rWorking);

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
                rWorking: rWorking,
                initialLength: columnCount,
                ipaRoundLabelPrefix: IpaRoundLabelPrefix,
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


    private static void ValidateOpenShape(
        HyraxCommitment commitment,
        HyraxOpeningWitness witness,
        MultilinearExtension mle,
        ReadOnlySpan<Scalar> evaluationPoint,
        HyraxCommitmentKey key)
    {
        if(commitment.Curve.Code != mle.Curve.Code || mle.Curve.Code != key.Curve.Code)
        {
            throw new ArgumentException(
                $"Open requires commitment / MLE / key to share a curve; got {commitment.Curve}, {mle.Curve}, {key.Curve}.");
        }

        if(commitment.VariableCount != mle.VariableCount)
        {
            throw new ArgumentException(
                $"Commitment was built for VariableCount = {commitment.VariableCount}; MLE has VariableCount = {mle.VariableCount}.");
        }

        if(witness.RowCount != commitment.RowCount)
        {
            throw new ArgumentException(
                $"Witness RowCount = {witness.RowCount} does not match commitment RowCount = {commitment.RowCount}.");
        }

        if(evaluationPoint.Length != mle.VariableCount)
        {
            throw new ArgumentException(
                $"Evaluation point must have exactly {mle.VariableCount} scalars; received {evaluationPoint.Length}.");
        }

        if(key.VectorLength < commitment.ColumnCount)
        {
            throw new ArgumentException(
                $"Commitment key has VectorLength = {key.VectorLength}; opening this commitment requires at least {commitment.ColumnCount} generators.");
        }
    }


    private static void ValidateVerifyShape(
        HyraxCommitment commitment,
        HyraxOpeningProof proof,
        ReadOnlySpan<Scalar> evaluationPoint,
        HyraxCommitmentKey key)
    {
        if(commitment.Curve.Code != key.Curve.Code || commitment.Curve.Code != proof.Curve.Code)
        {
            throw new ArgumentException(
                $"Verify requires commitment / proof / key to share a curve; got {commitment.Curve}, {proof.Curve}, {key.Curve}.");
        }

        if(evaluationPoint.Length != commitment.VariableCount)
        {
            throw new ArgumentException(
                $"Evaluation point must have {commitment.VariableCount} scalars; received {evaluationPoint.Length}.");
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


    /// <summary>
    /// Iteratively builds the Lagrange-basis vector
    /// <c>L[i] = ∏_k (i_k ? var[k] : (1 − var[k]))</c> from the
    /// supplied range of point variables. Bit <c>k</c> of <c>i</c> is
    /// taken with bit 0 as the LSB.
    /// </summary>
    private static void ComputeLagrangeVector(
        ReadOnlySpan<Scalar> evaluationPoint,
        int variableOffset,
        int variableCount,
        Span<byte> destination,
        ScalarAddDelegate scalarAdd,
        ScalarSubtractDelegate scalarSubtract,
        ScalarMultiplyDelegate scalarMul,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        int scalarSize = Scalar.SizeBytes;
        int expectedLength = (1 << variableCount) * scalarSize;
        if(destination.Length != expectedLength)
        {
            throw new ArgumentException(
                $"Destination must be {expectedLength} bytes for {variableCount} variables; received {destination.Length}.");
        }

        //Initialise L = [1].
        destination.Clear();
        destination[scalarSize - 1] = 0x01;
        int currentLength = 1;

        //Pre-allocate "one" for the (1 − var) computation.
        using IMemoryOwner<byte> oneOwner = pool.Rent(scalarSize);
        using IMemoryOwner<byte> oneMinusVarOwner = pool.Rent(scalarSize);
        using IMemoryOwner<byte> productOwner = pool.Rent(scalarSize);
        Span<byte> one = oneOwner.Memory.Span[..scalarSize];
        Span<byte> oneMinusVar = oneMinusVarOwner.Memory.Span[..scalarSize];
        Span<byte> product = productOwner.Memory.Span[..scalarSize];
        one.Clear();
        one[scalarSize - 1] = 0x01;

        //Iterate the point's variables in reverse so the final L[i] has
        //bit_0(i) encoding the factor of the FIRST variable in the
        //point slice — matching the matrix decomposition's row-index
        //convention (bit_0 of the row index encodes the lower row
        //variable in the MLE's storage order).
        for(int k = 0; k < variableCount; k++)
        {
            Scalar var = evaluationPoint[variableOffset + variableCount - 1 - k];
            ArgumentNullException.ThrowIfNull(var);
            ReadOnlySpan<byte> varBytes = var.AsReadOnlySpan();
            scalarSubtract(one, varBytes, oneMinusVar, curve);

            //Expand: for i in [0, currentLength) (reversed so we don't overwrite),
            //write new[2i] = L[i]·(1−var), new[2i+1] = L[i]·var.
            for(int i = currentLength - 1; i >= 0; i--)
            {
                ReadOnlySpan<byte> slot = destination.Slice(i * scalarSize, scalarSize);
                scalarMul(slot, varBytes, product, curve);
                Span<byte> rightDest = destination.Slice((2 * i + 1) * scalarSize, scalarSize);
                product.CopyTo(rightDest);

                scalarMul(slot, oneMinusVar, product, curve);
                Span<byte> leftDest = destination.Slice(2 * i * scalarSize, scalarSize);
                product.CopyTo(leftDest);
            }

            currentLength <<= 1;
        }
    }


    /// <summary>
    /// Computes <c>f[j] = Σ_i L[i] · M[i][j]</c> for the row-major
    /// matrix <c>M</c> represented as <paramref name="mleBytes"/>.
    /// </summary>
    private static void ComputeMatrixVectorProduct(
        ReadOnlySpan<byte> lVector,
        ReadOnlySpan<byte> mleBytes,
        int rowCount,
        int columnCount,
        int scalarSize,
        Span<byte> destination,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMul,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        destination.Clear();
        using IMemoryOwner<byte> termOwner = pool.Rent(scalarSize);
        Span<byte> term = termOwner.Memory.Span[..scalarSize];

        for(int j = 0; j < columnCount; j++)
        {
            Span<byte> fSlot = destination.Slice(j * scalarSize, scalarSize);
            for(int i = 0; i < rowCount; i++)
            {
                ReadOnlySpan<byte> lSlot = lVector.Slice(i * scalarSize, scalarSize);
                ReadOnlySpan<byte> mSlot = mleBytes.Slice((i * columnCount + j) * scalarSize, scalarSize);
                scalarMul(lSlot, mSlot, term, curve);
                scalarAdd(fSlot, term, fSlot, curve);
            }
        }
    }


    /// <summary>Computes the scalar inner product <c>Σ a[i] · b[i]</c>. Internal so the weighted-opening sibling reuses the exact byte-level routine.</summary>
    internal static void ComputeScalarInnerProduct(
        ReadOnlySpan<byte> a,
        ReadOnlySpan<byte> b,
        int count,
        int scalarSize,
        Span<byte> destination,
        ScalarAddDelegate scalarAdd,
        ScalarMultiplyDelegate scalarMul,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        destination.Clear();
        using IMemoryOwner<byte> termOwner = pool.Rent(scalarSize);
        Span<byte> term = termOwner.Memory.Span[..scalarSize];
        for(int i = 0; i < count; i++)
        {
            scalarMul(a.Slice(i * scalarSize, scalarSize), b.Slice(i * scalarSize, scalarSize), term, curve);
            scalarAdd(destination, term, destination, curve);
        }
    }


    /// <summary>Computes <c>⟨f, G_{0..columnCount-1}⟩ + r_f · H</c> via one MSM call. Internal so the weighted-opening sibling reuses the exact byte-level routine.</summary>
    internal static void ComputePedersenCommitment(
        ReadOnlySpan<byte> fVector,
        ReadOnlySpan<byte> rFBytes,
        HyraxCommitmentKey key,
        int columnCount,
        Span<byte> destination,
        G1MultiScalarMultiplyDelegate g1Msm,
        BaseMemoryPool pool)
    {
        int scalarSize = Scalar.SizeBytes;
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(key.Curve);
        int operandCount = columnCount + 1;

        using IMemoryOwner<byte> pointsOwner = pool.Rent(operandCount * g1Size);
        using IMemoryOwner<byte> scalarsOwner = pool.Rent(operandCount * scalarSize);
        Span<byte> points = pointsOwner.Memory.Span[..(operandCount * g1Size)];
        Span<byte> scalars = scalarsOwner.Memory.Span[..(operandCount * scalarSize)];

        for(int j = 0; j < columnCount; j++)
        {
            key.GetGenerator(j).CopyTo(points.Slice(j * g1Size, g1Size));
        }

        key.GetBlindingGenerator().CopyTo(points.Slice(columnCount * g1Size, g1Size));
        fVector.CopyTo(scalars[..(columnCount * scalarSize)]);
        rFBytes.CopyTo(scalars.Slice(columnCount * scalarSize, scalarSize));

        g1Msm(points, scalars, operandCount, destination, key.Curve);
    }
}
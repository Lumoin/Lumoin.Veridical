using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments;
using Lumoin.Veridical.Core.Gkr;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Lookup;

/// <summary>
/// The LogUp-GKR lookup-argument verifier: checks the root's zero-numerator
/// and nonzero-denominator conditions, replays every layer's batched
/// sumcheck and line merge, reconstructs the input-layer fractions at the
/// terminal point from the openings and its own table evaluation, and
/// verifies the commitment openings.
/// </summary>
/// <remarks>
/// Hostile proof content yields <see langword="false"/>; only programmer
/// errors (null arguments, a table whose length contradicts the proof's
/// shape) throw. The verifier's per-layer work is <c>O(layer)</c> plus one
/// three-way product per round message, and the whole run needs field
/// inversions only for the four constant Lagrange denominators of the round
/// interpolation.
/// </remarks>
public static class LogUpGkrVerifier
{
    private const int ScalarSize = Scalar.SizeBytes;


    /// <summary>
    /// Verifies a LogUp-GKR proof against the public
    /// <paramref name="tableEvaluations"/>.
    /// </summary>
    /// <param name="tableEvaluations">The public table column — the same bytes the prover absorbed.</param>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="pcs">The polynomial-commitment provider matching the prover's.</param>
    /// <param name="transcript">A fresh transcript over the same domain the prover used.</param>
    /// <param name="hash">The transcript hash backend.</param>
    /// <param name="squeeze">The transcript XOF backend.</param>
    /// <param name="reduce">The wide-bytes-to-scalar reduction backend.</param>
    /// <param name="add">Scalar-add delegate.</param>
    /// <param name="subtract">Scalar-subtract delegate.</param>
    /// <param name="multiply">Scalar-multiply delegate.</param>
    /// <param name="invert">Scalar-invert delegate, used only for the constant Lagrange denominators of the round interpolation.</param>
    /// <param name="mleEvaluate">The multilinear-evaluation backend for the verifier's own table evaluation.</param>
    /// <param name="pool">The pool every buffer is rented from.</param>
    /// <returns><see langword="true"/> when every check passes.</returns>
    public static bool Verify(
        ReadOnlySpan<byte> tableEvaluations,
        LogUpGkrProof proof,
        PolynomialCommitmentProvider pcs,
        FiatShamirTranscript transcript,
        FiatShamirHashDelegate hash,
        FiatShamirSqueezeDelegate squeeze,
        ScalarReduceDelegate reduce,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        MleEvaluateDelegate mleEvaluate,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(pcs);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(hash);
        ArgumentNullException.ThrowIfNull(squeeze);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(mleEvaluate);
        ArgumentNullException.ThrowIfNull(pool);

        int variableCount = proof.VariableCount;
        int witnessColumnCount = proof.WitnessColumnCount;
        int selectorVariableCount = proof.SelectorVariableCount;
        int totalVariableCount = variableCount + selectorVariableCount;
        long expectedTableBytes = (1L << variableCount) * ScalarSize;
        if(tableEvaluations.Length != expectedTableBytes)
        {
            throw new ArgumentException($"The proof binds a {variableCount}-variable table of {expectedTableBytes} bytes; received {tableEvaluations.Length}.", nameof(tableEvaluations));
        }

        CurveParameterSet curve = pcs.Curve;
        if(curve.Code != proof.Curve.Code)
        {
            throw new ArgumentException($"The proof was produced over {proof.Curve} but the provider works over {curve}.", nameof(pcs));
        }

        LogUpProver.ThrowIfNonCanonical(tableEvaluations, curve, nameof(tableEvaluations));

        //Replay the pre-challenge absorbs.
        LogUpProver.AbsorbGkrInstanceShape(transcript, variableCount, witnessColumnCount, curve, hash);
        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.TableEvaluations), tableEvaluations, hash);
        for(int column = 0; column < witnessColumnCount; column++)
        {
            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.WitnessCommitment), proof.WitnessCommitments[column].AsReadOnlySpan(), hash);
        }

        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.MultiplicityCommitment), proof.MultiplicityCommitment.AsReadOnlySpan(), hash);

        Span<byte> denominatorChallenge = stackalloc byte[ScalarSize];
        LogUpProver.SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.GkrDenominatorChallenge, denominatorChallenge, squeeze, hash, reduce, curve);

        bool accepted = true;

        //Root: the projective sum of the two top fractions must be the zero
        //fraction with a nonzero denominator.
        ReadOnlySpan<byte> rootValues = proof.GetRootValueBytes();
        ReadOnlySpan<byte> rootNumeratorLow = rootValues[..ScalarSize];
        ReadOnlySpan<byte> rootNumeratorHigh = rootValues.Slice(ScalarSize, ScalarSize);
        ReadOnlySpan<byte> rootDenominatorLow = rootValues.Slice(2 * ScalarSize, ScalarSize);
        ReadOnlySpan<byte> rootDenominatorHigh = rootValues.Slice(3 * ScalarSize, ScalarSize);
        Span<byte> temp1 = stackalloc byte[ScalarSize];
        Span<byte> temp2 = stackalloc byte[ScalarSize];
        multiply(rootNumeratorLow, rootDenominatorHigh, temp1, curve);
        multiply(rootNumeratorHigh, rootDenominatorLow, temp2, curve);
        add(temp1, temp2, temp1, curve);
        if(temp1.ContainsAnyExcept((byte)0))
        {
            accepted = false;
        }

        multiply(rootDenominatorLow, rootDenominatorHigh, temp1, curve);
        if(!temp1.ContainsAnyExcept((byte)0))
        {
            accepted = false;
        }

        transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.GkrRootValues), rootValues, hash);

        //Interpolation denominators for the fixed four-point round messages.
        Span<byte> inverseDenominators = stackalloc byte[LogUpGkrSumcheck.RoundEvaluationCount * ScalarSize];
        SumcheckInterpolation.ComputeInverseDenominators(inverseDenominators, LogUpGkrSumcheck.RoundEvaluationCount, subtract, multiply, invert, curve);

        using IMemoryOwner<byte> pointOwner = pool.Rent(totalVariableCount * ScalarSize);
        Span<byte> point = pointOwner.Memory.Span[..(totalVariableCount * ScalarSize)];
        using IMemoryOwner<byte> previousPointOwner = pool.Rent(totalVariableCount * ScalarSize);
        Span<byte> previousPoint = previousPointOwner.Memory.Span[..(totalVariableCount * ScalarSize)];

        Span<byte> lineChallenge = stackalloc byte[ScalarSize];
        LogUpProver.SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.GkrLineChallenge, lineChallenge, squeeze, hash, reduce, curve);
        lineChallenge.CopyTo(point[..ScalarSize]);

        //Merged running claims: P = low + μ·(high − low), Q likewise.
        Span<byte> numeratorClaim = stackalloc byte[ScalarSize];
        Span<byte> denominatorClaim = stackalloc byte[ScalarSize];
        MergeOnLine(rootNumeratorLow, rootNumeratorHigh, lineChallenge, numeratorClaim, add, subtract, multiply, curve);
        MergeOnLine(rootDenominatorLow, rootDenominatorHigh, lineChallenge, denominatorClaim, add, subtract, multiply, curve);

        ReadOnlySpan<byte> layerMessages = proof.GetLayerMessageBytes();
        int layerMessageOffset = 0;
        Span<byte> foldingChallenge = stackalloc byte[ScalarSize];
        Span<byte> claim = stackalloc byte[ScalarSize];
        Span<byte> sum = stackalloc byte[ScalarSize];
        Span<byte> kernelValue = stackalloc byte[ScalarSize];
        for(int layer = 1; layer < totalVariableCount; layer++)
        {
            LogUpProver.SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.GkrLayerFoldingChallenge, foldingChallenge, squeeze, hash, reduce, curve);

            //The layer's sumcheck target: P + λ·Q at the current point.
            multiply(foldingChallenge, denominatorClaim, temp1, curve);
            add(numeratorClaim, temp1, claim, curve);

            point[..(layer * ScalarSize)].CopyTo(previousPoint[..(layer * ScalarSize)]);

            for(int round = 0; round < layer; round++)
            {
                ReadOnlySpan<byte> roundMessage = layerMessages.Slice(layerMessageOffset, LogUpGkrSumcheck.RoundEvaluationCount * ScalarSize);
                add(roundMessage[..ScalarSize], roundMessage.Slice(ScalarSize, ScalarSize), sum, curve);
                if(!sum.SequenceEqual(claim))
                {
                    accepted = false;
                }

                transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.GkrLayerRoundPolynomial), roundMessage, hash);
                Span<byte> roundChallenge = point.Slice(round * ScalarSize, ScalarSize);
                LogUpProver.SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.GkrLayerRoundChallenge, roundChallenge, squeeze, hash, reduce, curve);

                SumcheckInterpolation.Interpolate(roundMessage, LogUpGkrSumcheck.RoundEvaluationCount, roundChallenge, inverseDenominators, claim, add, subtract, multiply, curve);
                layerMessageOffset += LogUpGkrSumcheck.RoundEvaluationCount * ScalarSize;
            }

            //The reduced claim must equal eq(r, ρ)·(A·D + B·C + λ·C·D) over
            //the prover's terminating quad.
            ReadOnlySpan<byte> quad = layerMessages.Slice(layerMessageOffset, LogUpGkrProof.QuadScalarCount * ScalarSize);
            ReadOnlySpan<byte> numeratorLow = quad[..ScalarSize];
            ReadOnlySpan<byte> numeratorHigh = quad.Slice(ScalarSize, ScalarSize);
            ReadOnlySpan<byte> denominatorLow = quad.Slice(2 * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> denominatorHigh = quad.Slice(3 * ScalarSize, ScalarSize);

            LogUpGkrSumcheck.EvaluateKernel(previousPoint[..(layer * ScalarSize)], point[..(layer * ScalarSize)], layer, kernelValue, add, subtract, multiply, curve);
            multiply(numeratorLow, denominatorHigh, temp1, curve);
            multiply(numeratorHigh, denominatorLow, temp2, curve);
            add(temp1, temp2, temp1, curve);
            multiply(denominatorLow, denominatorHigh, temp2, curve);
            multiply(foldingChallenge, temp2, temp2, curve);
            add(temp1, temp2, temp1, curve);
            multiply(kernelValue, temp1, temp1, curve);
            if(!temp1.SequenceEqual(claim))
            {
                accepted = false;
            }

            transcript.AbsorbBytes(new FiatShamirOperationLabel(WellKnownLogUpTranscriptLabels.GkrLayerTerminatingValues), quad, hash);
            layerMessageOffset += LogUpGkrProof.QuadScalarCount * ScalarSize;

            LogUpProver.SqueezeChallenge(transcript, WellKnownLogUpTranscriptLabels.GkrLineChallenge, lineChallenge, squeeze, hash, reduce, curve);
            lineChallenge.CopyTo(point.Slice(layer * ScalarSize, ScalarSize));
            MergeOnLine(numeratorLow, numeratorHigh, lineChallenge, numeratorClaim, add, subtract, multiply, curve);
            MergeOnLine(denominatorLow, denominatorHigh, lineChallenge, denominatorClaim, add, subtract, multiply, curve);
        }

        //Absorb the claimed terminal evaluations, then verify the openings at
        //the row part of the final point.
        ReadOnlySpan<byte> claimedEvaluations = proof.GetClaimedEvaluationBytes();
        for(int column = 0; column <= witnessColumnCount; column++)
        {
            string label = column < witnessColumnCount
                ? WellKnownLogUpTranscriptLabels.GkrWitnessEvaluation
                : WellKnownLogUpTranscriptLabels.GkrMultiplicityEvaluation;
            transcript.AbsorbBytes(new FiatShamirOperationLabel(label), claimedEvaluations.Slice(column * ScalarSize, ScalarSize), hash);
        }

        Scalar[] rowPoint = LogUpProver.ToScalarArray(point[..(variableCount * ScalarSize)], variableCount, curve, pool);
        try
        {
            for(int column = 0; column <= witnessColumnCount; column++)
            {
                (PolynomialCommitment commitment, PolynomialOpening opening) = column < witnessColumnCount
                    ? (proof.WitnessCommitments[column], proof.WitnessOpenings[column])
                    : (proof.MultiplicityCommitment, proof.MultiplicityOpening);
                using Scalar claimedValue = Scalar.FromCanonical(claimedEvaluations.Slice(column * ScalarSize, ScalarSize), curve, pool);
                if(!pcs.VerifyEvaluation(commitment, rowPoint, claimedValue, opening, transcript, pool))
                {
                    accepted = false;
                }
            }

            //Reconstruct the input-layer fractions at the terminal point from
            //the openings, the verifier's own table evaluation, and the
            //self-computed selector weights, and check the final claims.
            using MultilinearExtension tableMle = MultilinearExtension.FromEvaluations(tableEvaluations, variableCount, curve, pool);
            using Scalar tableAtPoint = tableMle.Evaluate(rowPoint, mleEvaluate, pool);

            int selectorCount = 1 << selectorVariableCount;
            using IMemoryOwner<byte> selectorWeightsOwner = pool.Rent(selectorCount * ScalarSize);
            Span<byte> selectorWeights = selectorWeightsOwner.Memory.Span[..(selectorCount * ScalarSize)];
            LogUpGkrSumcheck.BuildKernelTable(point.Slice(variableCount * ScalarSize, selectorVariableCount * ScalarSize), selectorVariableCount, selectorWeights, subtract, multiply, curve);

            Span<byte> expectedNumerator = stackalloc byte[ScalarSize];
            Span<byte> expectedDenominator = stackalloc byte[ScalarSize];
            ReconstructLeafFractions(
                claimedEvaluations, tableAtPoint.AsReadOnlySpan(), denominatorChallenge, selectorWeights,
                witnessColumnCount, selectorCount,
                expectedNumerator, expectedDenominator, add, subtract, multiply, curve);

            if(!expectedNumerator.SequenceEqual(numeratorClaim) || !expectedDenominator.SequenceEqual(denominatorClaim))
            {
                accepted = false;
            }

            return accepted;
        }
        finally
        {
            foreach(Scalar coordinate in rowPoint)
            {
                coordinate.Dispose();
            }
        }
    }


    //destination = low + μ·(high − low): evaluation on the line through the
    //two split-point children at the merge challenge.
    private static void MergeOnLine(
        ReadOnlySpan<byte> low,
        ReadOnlySpan<byte> high,
        ReadOnlySpan<byte> lineChallenge,
        Span<byte> destination,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> slope = stackalloc byte[ScalarSize];
        Span<byte> scaled = stackalloc byte[ScalarSize];
        subtract(high, low, slope, curve);
        multiply(lineChallenge, slope, scaled, curve);
        add(low, scaled, destination, curve);
    }


    //p(r) = w₀·m(r) − Σ_{s=1..M} w_s;  q(r) = w₀·(α − t(r)) +
    //Σ_{s=1..M} w_s·(α − w_s(r)) + Σ_{padding} w_s — the padding slots carry
    //the neutral fraction 0/1.
    private static void ReconstructLeafFractions(
        ReadOnlySpan<byte> claimedEvaluations,
        ReadOnlySpan<byte> tableAtPoint,
        ReadOnlySpan<byte> denominatorChallenge,
        ReadOnlySpan<byte> selectorWeights,
        int witnessColumnCount,
        int selectorCount,
        Span<byte> numerator,
        Span<byte> denominator,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> temp1 = stackalloc byte[ScalarSize];
        Span<byte> temp2 = stackalloc byte[ScalarSize];

        //Table slot 0: numerator w₀·m(r), denominator w₀·(α − t(r)).
        ReadOnlySpan<byte> multiplicityValue = claimedEvaluations.Slice(witnessColumnCount * ScalarSize, ScalarSize);
        multiply(selectorWeights[..ScalarSize], multiplicityValue, numerator, curve);
        subtract(denominatorChallenge, tableAtPoint, temp1, curve);
        multiply(selectorWeights[..ScalarSize], temp1, denominator, curve);

        for(int selector = 1; selector < selectorCount; selector++)
        {
            ReadOnlySpan<byte> weight = selectorWeights.Slice(selector * ScalarSize, ScalarSize);
            if(selector <= witnessColumnCount)
            {
                //Witness slot: numerator −w_s, denominator w_s·(α − w_s(r)).
                subtract(numerator, weight, temp1, curve);
                temp1.CopyTo(numerator);
                subtract(denominatorChallenge, claimedEvaluations.Slice((selector - 1) * ScalarSize, ScalarSize), temp1, curve);
                multiply(weight, temp1, temp2, curve);
                add(denominator, temp2, temp1, curve);
                temp1.CopyTo(denominator);
            }
            else
            {
                //Neutral padding slot 0/1: only the denominator accumulates.
                add(denominator, weight, temp1, curve);
                temp1.CopyTo(denominator);
            }
        }
    }
}

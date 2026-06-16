using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// The data-parallel GKR verifier: replays the copy-variable rounds (degree-3, reduced by
/// Lagrange interpolation) and the hand sumcheck per layer, recomputes the bound wiring value
/// from the public per-copy circuit — scaled by <c>eq~(z_c, r_c)</c> between the layer's copy
/// point and the copy-round challenges — and checks the final wire claims against the
/// copy×wire input table's multilinear extension at the tensor points. Verifier work is linear
/// in the per-copy circuit description plus <c>log(copyCount)</c> per layer — it never touches
/// the per-copy evaluations.
/// </summary>
internal static class GkrDataParallelVerifier
{
    private const int ScalarSize = SumcheckChallenge.ScalarSize;
    private const int CopyRoundEvaluations = 4;


    //The plain public-input mode: the GKR walk, then the final wire claims checked against the
    //public copy×wire input table. The caller absorbs the statement (here the public inputs)
    //before calling, exactly as it did for the prover.
    public static bool Verify(
        GkrCircuit circuit,
        ReadOnlySpan<byte> inputs,
        ReadOnlySpan<byte> outputs,
        int copyCount,
        GkrDataParallelProof proof,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        FiatShamirTranscript transcript,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(pool);
        if(inputs.Length != copyCount * circuit.InputCount * ScalarSize)
        {
            throw new ArgumentException($"{copyCount} copies of {circuit.InputCount} inputs need {copyCount * circuit.InputCount * ScalarSize} bytes; received {inputs.Length}.", nameof(inputs));
        }

        int logCopies = BitOperations.Log2((uint)copyCount);
        int inputLogWidth = BitOperations.Log2((uint)circuit.InputCount);
        using IMemoryOwner<byte> claimOwner = pool.Rent(((logCopies + (2 * inputLogWidth)) * ScalarSize) + (2 * ScalarSize));
        Span<byte> copyPoint = claimOwner.Memory.Span[..(logCopies * ScalarSize)];
        Span<byte> leftPoint = claimOwner.Memory.Span.Slice(logCopies * ScalarSize, inputLogWidth * ScalarSize);
        Span<byte> rightPoint = claimOwner.Memory.Span.Slice((logCopies + inputLogWidth) * ScalarSize, inputLogWidth * ScalarSize);
        Span<byte> leftClaim = claimOwner.Memory.Span.Slice((logCopies + (2 * inputLogWidth)) * ScalarSize, ScalarSize);
        Span<byte> rightClaim = claimOwner.Memory.Span.Slice(((logCopies + (2 * inputLogWidth)) * ScalarSize) + ScalarSize, ScalarSize);

        if(!VerifyToInputClaims(circuit, outputs, copyCount, proof, copyPoint, leftPoint, rightPoint, leftClaim, rightClaim,
            add, subtract, multiply, invert, reduce, curve, transcript, squeeze, hash, pool))
        {
            return false;
        }

        //The wire claims address the copy×wire input table at the tensor points.
        using IMemoryOwner<byte> tableOwner = pool.Rent((copyCount + circuit.InputCount) * ScalarSize);
        Span<byte> copyTable = tableOwner.Memory.Span[..(copyCount * ScalarSize)];
        Span<byte> wireTable = tableOwner.Memory.Span.Slice(copyCount * ScalarSize, circuit.InputCount * ScalarSize);
        Span<byte> evaluated = stackalloc byte[ScalarSize];

        EqualityPolynomial.BuildTable(copyPoint, logCopies, copyTable, subtract, multiply, curve);
        EqualityPolynomial.BuildTable(leftPoint, inputLogWidth, wireTable, subtract, multiply, curve);
        GkrEvaluation.TensorDot(copyTable, wireTable, inputs, evaluated, add, multiply, curve);
        if(!evaluated.SequenceEqual(leftClaim))
        {
            return false;
        }

        EqualityPolynomial.BuildTable(rightPoint, inputLogWidth, wireTable, subtract, multiply, curve);
        GkrEvaluation.TensorDot(copyTable, wireTable, inputs, evaluated, add, multiply, curve);

        return evaluated.SequenceEqual(rightClaim);
    }


    //The GKR walk alone: verifies every layer's copy rounds and hand sumcheck and the recomputed
    //wiring values, writing the final input-claim points (copy point r_c, the two hand points,
    //eq convention) and the two wire claims. The caller completes the proof by checking the
    //claims against the input table — directly for public inputs, or via a witness-commitment
    //opening at the tensor points for private ones.
    public static bool VerifyToInputClaims(
        GkrCircuit circuit,
        ReadOnlySpan<byte> outputs,
        int copyCount,
        GkrDataParallelProof proof,
        Span<byte> copyPointOut,
        Span<byte> leftPointOut,
        Span<byte> rightPointOut,
        Span<byte> leftClaimOut,
        Span<byte> rightClaimOut,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        FiatShamirTranscript transcript,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(pool);
        if(copyCount < 2 || !BitOperations.IsPow2(copyCount))
        {
            throw new ArgumentOutOfRangeException(nameof(copyCount), copyCount, "The copy count must be a power of two of at least 2.");
        }

        if(outputs.Length != copyCount * circuit.Layers[0].OutputCount * ScalarSize)
        {
            throw new ArgumentException($"{copyCount} copies of {circuit.Layers[0].OutputCount} outputs need {copyCount * circuit.Layers[0].OutputCount * ScalarSize} bytes; received {outputs.Length}.", nameof(outputs));
        }

        int layerCount = circuit.Layers.Length;
        int logCopies = BitOperations.Log2((uint)copyCount);
        if(proof.LayerProofs.Length != layerCount)
        {
            return false;
        }

        transcript.AbsorbBytes(GkrTranscriptLabels.Outputs, outputs, hash);

        //The output layer's own width participates in the scratch: its equality table lands in
        //the wire scratch and may exceed every width below it (a circuit may widen toward its
        //outputs, e.g. several word functions of one input word).
        int maxWidth = Math.Max(circuit.InputCount, circuit.Layers[0].OutputCount);
        for(int l = 0; l < layerCount; l++)
        {
            maxWidth = Math.Max(maxWidth, circuit.WidthBelow(l));
        }

        int maxLogWidth = BitOperations.Log2((uint)maxWidth);
        using IMemoryOwner<byte> handPointOwner = pool.Rent(4 * maxLogWidth * ScalarSize);
        using IMemoryOwner<byte> copyPointOwner = pool.Rent(2 * logCopies * ScalarSize);
        using IMemoryOwner<byte> tableScratchOwner = pool.Rent((Math.Max(copyCount, maxWidth) + maxWidth) * ScalarSize);
        using IMemoryOwner<byte> inverseDenominatorOwner = pool.Rent(CopyRoundEvaluations * ScalarSize);

        Span<byte> inverseDenominators = inverseDenominatorOwner.Memory.Span[..(CopyRoundEvaluations * ScalarSize)];
        SumcheckInterpolation.ComputeInverseDenominators(inverseDenominators, CopyRoundEvaluations, subtract, multiply, invert, curve);

        //The output point: the copy coordinates z_c then the per-copy output coordinates z_g; the
        //initial claim is the outputs' multilinear extension at the tensor point.
        Span<byte> copyPoint = copyPointOwner.Memory.Span[..(logCopies * ScalarSize)];
        Span<byte> copyChallenges = copyPointOwner.Memory.Span.Slice(logCopies * ScalarSize, logCopies * ScalarSize);
        GkrEvaluation.SqueezePoint(transcript, GkrTranscriptLabels.OutputPoint, logCopies, copyPoint, squeeze, hash, reduce, curve);

        int logv = BitOperations.Log2((uint)circuit.Layers[0].OutputCount);
        using IMemoryOwner<byte> outputPointOwner = pool.Rent(logv * ScalarSize);
        Span<byte> outputPoint = outputPointOwner.Memory.Span[..(logv * ScalarSize)];
        GkrEvaluation.SqueezePoint(transcript, GkrTranscriptLabels.OutputPoint, logv, outputPoint, squeeze, hash, reduce, curve);

        Span<byte> copyTable = tableScratchOwner.Memory.Span[..(copyCount * ScalarSize)];
        Span<byte> wireTable = tableScratchOwner.Memory.Span.Slice(Math.Max(copyCount, maxWidth) * ScalarSize, maxWidth * ScalarSize);
        EqualityPolynomial.BuildTable(copyPoint, logCopies, copyTable, subtract, multiply, curve);
        EqualityPolynomial.BuildTable(outputPoint, logv, wireTable[..(circuit.Layers[0].OutputCount * ScalarSize)], subtract, multiply, curve);

        Span<byte> claim = stackalloc byte[ScalarSize];
        GkrEvaluation.TensorDot(copyTable, wireTable[..(circuit.Layers[0].OutputCount * ScalarSize)], outputs, claim, add, multiply, curve);

        bool atOutputLayer = true;
        int previousLogWidth = 0;
        Span<byte> previousLeft = handPointOwner.Memory.Span[..(maxLogWidth * ScalarSize)];
        Span<byte> previousRight = handPointOwner.Memory.Span.Slice(maxLogWidth * ScalarSize, maxLogWidth * ScalarSize);
        Span<byte> currentLeft = handPointOwner.Memory.Span.Slice(2 * maxLogWidth * ScalarSize, maxLogWidth * ScalarSize);
        Span<byte> currentRight = handPointOwner.Memory.Span.Slice(3 * maxLogWidth * ScalarSize, maxLogWidth * ScalarSize);
        Span<byte> alpha = stackalloc byte[ScalarSize];
        Span<byte> beta = stackalloc byte[ScalarSize];

        Span<byte> sum = stackalloc byte[ScalarSize];
        Span<byte> challenge = stackalloc byte[ScalarSize];
        Span<byte> coefficient = stackalloc byte[ScalarSize];
        Span<byte> eqLeft = stackalloc byte[ScalarSize];
        Span<byte> eqRight = stackalloc byte[ScalarSize];
        Span<byte> eqOutput = stackalloc byte[ScalarSize];
        Span<byte> combined = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> expectedWiring = stackalloc byte[ScalarSize];
        Span<byte> equalityScalar = stackalloc byte[ScalarSize];

        for(int l = 0; l < layerCount; l++)
        {
            GkrLayer layer = circuit.Layers[l];
            int width = circuit.WidthBelow(l);
            int logWidth = BitOperations.Log2((uint)width);
            GkrDataParallelLayerProof layerProof = proof.LayerProofs[l];
            if(layerProof.CopyRoundCount != logCopies || layerProof.HandProof.FactorCount != 3 || layerProof.HandProof.VariableCount != 2 * logWidth)
            {
                return false;
            }

            //Phase 1: the copy rounds — degree-3 consistency and Lagrange reduction of the claim.
            ReadOnlySpan<byte> copyRounds = layerProof.CopyRoundPolynomials.Span;
            for(int round = 0; round < logCopies; round++)
            {
                ReadOnlySpan<byte> evaluations = copyRounds.Slice(round * CopyRoundEvaluations * ScalarSize, CopyRoundEvaluations * ScalarSize);
                add(evaluations[..ScalarSize], evaluations.Slice(ScalarSize, ScalarSize), sum, curve);
                if(!sum.SequenceEqual(claim))
                {
                    return false;
                }

                SumcheckChallenge.AbsorbAndSqueeze(transcript, evaluations, challenge, squeeze, hash, reduce, curve);
                challenge.CopyTo(copyChallenges.Slice(round * ScalarSize, ScalarSize));
                SumcheckInterpolation.Interpolate(evaluations, CopyRoundEvaluations, challenge, inverseDenominators, claim, add, subtract, multiply, curve);
            }

            //Phase 2: the hand sumcheck continues from the reduced claim.
            using MultilinearSumcheckVerification verification = ProductSumcheck.Verify(
                claim, layerProof.HandProof, add, subtract, multiply, invert, reduce, curve, transcript, squeeze, hash, pool);
            if(!verification.Accepted)
            {
                return false;
            }

            GkrEvaluation.SplitJointPoint(verification.Point.Span, logWidth, currentLeft[..(logWidth * ScalarSize)], currentRight[..(logWidth * ScalarSize)]);

            //The bound wiring value: eq~(z_c, r_c)·Σ_t v_t·E[output_t]·eq(left_t)·eq(right_t),
            //from the public per-copy circuit — the prover's folded factor 0 must equal it.
            Span<byte> reversedCopyChallenges = copyChallenges;
            GkrEvaluation.ReversePoint(copyChallenges, logCopies, copyTable[..(logCopies * ScalarSize)]);
            copyTable[..(logCopies * ScalarSize)].CopyTo(reversedCopyChallenges);
            GkrEvaluation.EvaluateEqBetween(copyPoint, reversedCopyChallenges, equalityScalar, add, subtract, multiply, curve);

            expectedWiring.Clear();
            foreach(GkrLayerTerm gate in layer.Terms)
            {
                if(atOutputLayer)
                {
                    GkrEvaluation.EvaluateEqAt(gate.OutputWire, outputPoint, coefficient, subtract, multiply, curve);
                }
                else
                {
                    GkrEvaluation.EvaluateEqAt(gate.OutputWire, previousLeft[..(previousLogWidth * ScalarSize)], eqOutput, subtract, multiply, curve);
                    GkrEvaluation.EvaluateEqAt(gate.OutputWire, previousRight[..(previousLogWidth * ScalarSize)], combined, subtract, multiply, curve);
                    GkrEvaluation.CombinePair(alpha, eqOutput, beta, combined, coefficient, add, multiply, curve);
                }

                GkrEvaluation.EvaluateEqAt(gate.LeftWire, currentLeft[..(logWidth * ScalarSize)], eqLeft, subtract, multiply, curve);
                GkrEvaluation.EvaluateEqAt(gate.RightWire, currentRight[..(logWidth * ScalarSize)], eqRight, subtract, multiply, curve);

                multiply(gate.Coefficient.Span, coefficient, term, curve);
                multiply(term, eqLeft, combined, curve);
                multiply(combined, eqRight, term, curve);
                add(expectedWiring, term, sum, curve);
                sum.CopyTo(expectedWiring);
            }

            multiply(expectedWiring, equalityScalar, term, curve);
            term.CopyTo(expectedWiring);

            ReadOnlySpan<byte> finalValues = layerProof.HandProof.FinalValues.Span;
            if(!expectedWiring.SequenceEqual(finalValues[..ScalarSize]))
            {
                return false;
            }

            ReadOnlySpan<byte> leftClaim = finalValues.Slice(ScalarSize, ScalarSize);
            ReadOnlySpan<byte> rightClaim = finalValues.Slice(2 * ScalarSize, ScalarSize);

            transcript.AbsorbBytes(GkrTranscriptLabels.LayerClaims, finalValues, hash);

            //The copy point walks down: the next layer's copies are pinned at r_c.
            reversedCopyChallenges.CopyTo(copyPoint);

            if(l < layerCount - 1)
            {
                SumcheckChallenge.Squeeze(transcript, GkrTranscriptLabels.LayerCombination, alpha, squeeze, hash, reduce, curve);
                SumcheckChallenge.Squeeze(transcript, GkrTranscriptLabels.LayerCombination, beta, squeeze, hash, reduce, curve);
                GkrEvaluation.CombinePair(alpha, leftClaim, beta, rightClaim, claim, add, multiply, curve);
                currentLeft[..(logWidth * ScalarSize)].CopyTo(previousLeft);
                currentRight[..(logWidth * ScalarSize)].CopyTo(previousRight);
                previousLogWidth = logWidth;
                atOutputLayer = false;
            }
            else
            {
                //The walk ends: hand the input-claim points and the wire claims to the caller,
                //which checks them against the input table (directly, or via a commitment opening).
                copyPoint.CopyTo(copyPointOut);
                currentLeft[..(logWidth * ScalarSize)].CopyTo(leftPointOut);
                currentRight[..(logWidth * ScalarSize)].CopyTo(rightPointOut);
                leftClaim.CopyTo(leftClaimOut);
                rightClaim.CopyTo(rightClaimOut);
            }
        }

        return true;
    }
}

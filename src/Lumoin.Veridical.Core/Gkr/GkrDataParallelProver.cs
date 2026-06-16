using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// The data-parallel GKR prover: <c>copyCount</c> copies of the same per-copy circuit proven with
/// the copy variable bound <em>once</em> — the Longfellow efficiency that makes uniform circuits
/// (SHA rounds, EC ladder steps) cheap. Per layer the claim
/// <c>Σ_c eq_zc(c) · Σ_t v_t·E[g_t]·W(c,h0_t)·W(c,h1_t)</c> is proven in two phases: first
/// <c>log(copyCount)</c> degree-3 rounds bind the copy index (cost <c>O(copies·terms)</c>, with
/// the wire tables folding in half each round — the per-copy wiring is never replicated), then the
/// ordinary hand sumcheck runs over the copy-folded wires. The wire claims come out at
/// <c>(r_c, r_left)</c> / <c>(r_c, r_right)</c> and the copy point <c>r_c</c> walks down the
/// layers with the claim.
/// </summary>
internal static class GkrDataParallelProver
{
    private const int ScalarSize = SumcheckChallenge.ScalarSize;
    private const int CopyRoundEvaluations = 4;


    public static GkrDataParallelProverResult Prove(
        GkrCircuit circuit,
        ReadOnlySpan<byte> inputs,
        int copyCount,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarReduceDelegate reduce,
        CurveParameterSet curve,
        FiatShamirTranscript transcript,
        FiatShamirSqueezeDelegate squeeze,
        FiatShamirHashDelegate hash,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(reduce);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(pool);

        using GkrWireTables tables = circuit.EvaluateDataParallel(inputs, copyCount, add, multiply, curve, pool);

        //The statement binding (public inputs, or a witness-commitment root) is the caller's:
        //absorb it into the transcript before calling. The claimed outputs are bound here.
        transcript.AbsorbBytes(GkrTranscriptLabels.Outputs, tables.Table(0).Span, hash);

        int layerCount = circuit.Layers.Length;
        int logCopies = BitOperations.Log2((uint)copyCount);
        int inputLogWidth = BitOperations.Log2((uint)circuit.InputCount);
        var layerProofs = new GkrDataParallelLayerProof[layerCount];

        //The result owns this buffer: [final copy point | input left point | input right point].
        IMemoryOwner<byte> resultPointBuffer = pool.Rent((logCopies + (2 * inputLogWidth)) * ScalarSize);

        int maxWidth = circuit.InputCount;
        int maxOutput = circuit.Layers[0].OutputCount;
        int maxTerms = 0;
        for(int l = 0; l < layerCount; l++)
        {
            maxWidth = Math.Max(maxWidth, circuit.WidthBelow(l));
            maxOutput = Math.Max(maxOutput, circuit.Layers[l].OutputCount);
            maxTerms = Math.Max(maxTerms, circuit.Layers[l].Terms.Length);
        }

        int maxLogWidth = BitOperations.Log2((uint)maxWidth);
        using IMemoryOwner<byte> coefficientOwner = pool.Rent(maxOutput * ScalarSize);
        using IMemoryOwner<byte> termOwner = pool.Rent(maxTerms * ScalarSize);
        using IMemoryOwner<byte> equalityWorkOwner = pool.Rent(copyCount * ScalarSize);
        using IMemoryOwner<byte> wireWorkOwner = pool.Rent(copyCount * maxWidth * ScalarSize);
        using IMemoryOwner<byte> factorOwner = pool.Rent(3 * maxWidth * maxWidth * ScalarSize);
        using IMemoryOwner<byte> handPointOwner = pool.Rent(2 * maxLogWidth * ScalarSize);
        using IMemoryOwner<byte> equalityScratchOwner = pool.Rent(2 * maxWidth * ScalarSize);
        using IMemoryOwner<byte> copyPointOwner = pool.Rent(logCopies * ScalarSize);
        using IMemoryOwner<byte> copyChallengeOwner = pool.Rent(logCopies * ScalarSize);

        //The output point: the copy coordinates z_c then the per-copy output coordinates z_g.
        Span<byte> copyPoint = copyPointOwner.Memory.Span[..(logCopies * ScalarSize)];
        GkrEvaluation.SqueezePoint(transcript, GkrTranscriptLabels.OutputPoint, logCopies, copyPoint, squeeze, hash, reduce, curve);

        int logv = BitOperations.Log2((uint)circuit.Layers[0].OutputCount);
        using IMemoryOwner<byte> outputPointOwner = pool.Rent(logv * ScalarSize);
        Span<byte> outputPoint = outputPointOwner.Memory.Span[..(logv * ScalarSize)];
        GkrEvaluation.SqueezePoint(transcript, GkrTranscriptLabels.OutputPoint, logv, outputPoint, squeeze, hash, reduce, curve);

        Span<byte> coefficients = coefficientOwner.Memory.Span[..(maxOutput * ScalarSize)];
        EqualityPolynomial.BuildTable(outputPoint, logv, coefficients[..(circuit.Layers[0].OutputCount * ScalarSize)], subtract, multiply, curve);

        Span<byte> termCoefficients = termOwner.Memory.Span[..(maxTerms * ScalarSize)];
        Span<byte> equalityWork = equalityWorkOwner.Memory.Span[..(copyCount * ScalarSize)];
        Span<byte> copyChallenges = copyChallengeOwner.Memory.Span[..(logCopies * ScalarSize)];

        //The four integer evaluation points 0..3 the copy rounds are sent at.
        Span<byte> evaluationPoints = stackalloc byte[CopyRoundEvaluations * ScalarSize];
        for(int t = 0; t < CopyRoundEvaluations; t++)
        {
            SumcheckChallenge.EncodeConstant((uint)t, evaluationPoints.Slice(t * ScalarSize, ScalarSize));
        }

        Span<byte> one = stackalloc byte[ScalarSize];
        SumcheckChallenge.EncodeOne(one);
        Span<byte> alpha = stackalloc byte[ScalarSize];
        Span<byte> beta = stackalloc byte[ScalarSize];
        Span<byte> challenge = stackalloc byte[ScalarSize];
        Span<byte> oneMinusChallenge = stackalloc byte[ScalarSize];
        Span<byte> scratch = stackalloc byte[ScalarSize];
        Span<byte> scratch2 = stackalloc byte[ScalarSize];
        Span<byte> valueLeft = stackalloc byte[ScalarSize];
        Span<byte> valueRight = stackalloc byte[ScalarSize];
        Span<byte> rowSum = stackalloc byte[ScalarSize];
        Span<byte> equalityAt = stackalloc byte[ScalarSize];

        for(int l = 0; l < layerCount; l++)
        {
            GkrLayer layer = circuit.Layers[l];
            ReadOnlySpan<byte> below = tables.Table(l + 1).Span;
            int width = circuit.WidthBelow(l);
            int logWidth = BitOperations.Log2((uint)width);
            GkrLayerTerm[] terms = layer.Terms;

            //Per-term coefficient d_t = v_t·E[output_t], shared by the copy rounds and the hand phase.
            for(int t = 0; t < terms.Length; t++)
            {
                multiply(terms[t].Coefficient.Span, coefficients.Slice(terms[t].OutputWire * ScalarSize, ScalarSize), termCoefficients.Slice(t * ScalarSize, ScalarSize), curve);
            }

            //Working copies the copy rounds fold in half: the eq table over copies and the wires.
            EqualityPolynomial.BuildTable(copyPoint, logCopies, equalityWork, subtract, multiply, curve);
            Span<byte> wireWork = wireWorkOwner.Memory.Span[..(copyCount * width * ScalarSize)];
            below.CopyTo(wireWork);

            //Phase 1: bind the copy variable, most-significant bit first. Round polynomial
            //s(t) = Σ_c' eq_t(c')·Σ_terms d·W_t(c',h0)·W_t(c',h1), degree 3, four evaluations.
            IMemoryOwner<byte> copyRoundBuffer = pool.Rent(GkrDataParallelLayerProof.GetCopyRoundBufferSizeBytes(logCopies));
            Span<byte> copyRounds = copyRoundBuffer.Memory.Span[..(logCopies * CopyRoundEvaluations * ScalarSize)];

            int halves = copyCount;
            for(int round = 0; round < logCopies; round++)
            {
                halves >>= 1;
                Span<byte> roundEvaluations = copyRounds.Slice(round * CopyRoundEvaluations * ScalarSize, CopyRoundEvaluations * ScalarSize);
                roundEvaluations.Clear();

                for(int t = 0; t < CopyRoundEvaluations; t++)
                {
                    ReadOnlySpan<byte> point = evaluationPoints.Slice(t * ScalarSize, ScalarSize);
                    Span<byte> evaluation = roundEvaluations.Slice(t * ScalarSize, ScalarSize);
                    for(int c = 0; c < halves; c++)
                    {
                        ReadOnlySpan<byte> rowLow = wireWork.Slice(c * width * ScalarSize, width * ScalarSize);
                        ReadOnlySpan<byte> rowHigh = wireWork.Slice((c + halves) * width * ScalarSize, width * ScalarSize);

                        rowSum.Clear();
                        for(int k = 0; k < terms.Length; k++)
                        {
                            ExtendAt(rowLow, rowHigh, terms[k].LeftWire, point, valueLeft, add, subtract, multiply, curve, scratch);
                            ExtendAt(rowLow, rowHigh, terms[k].RightWire, point, valueRight, add, subtract, multiply, curve, scratch);
                            multiply(termCoefficients.Slice(k * ScalarSize, ScalarSize), valueLeft, scratch, curve);
                            multiply(scratch, valueRight, scratch2, curve);
                            add(rowSum, scratch2, scratch, curve);
                            scratch.CopyTo(rowSum);
                        }

                        ExtendAt(equalityWork[..(halves * ScalarSize)], equalityWork.Slice(halves * ScalarSize, halves * ScalarSize), c, point, equalityAt, add, subtract, multiply, curve, scratch);
                        multiply(equalityAt, rowSum, scratch, curve);
                        add(evaluation, scratch, scratch2, curve);
                        scratch2.CopyTo(evaluation);
                    }
                }

                SumcheckChallenge.AbsorbAndSqueeze(transcript, roundEvaluations, challenge, squeeze, hash, reduce, curve);
                challenge.CopyTo(copyChallenges.Slice(round * ScalarSize, ScalarSize));
                subtract(one, challenge, oneMinusChallenge, curve);

                //Fold the eq table and every wire row by the challenge.
                for(int c = 0; c < halves; c++)
                {
                    FoldPair(equalityWork.Slice(c * ScalarSize, ScalarSize), equalityWork.Slice((c + halves) * ScalarSize, ScalarSize), challenge, oneMinusChallenge, add, multiply, curve, scratch, scratch2);
                    for(int h = 0; h < width; h++)
                    {
                        FoldPair(
                            wireWork.Slice(((c * width) + h) * ScalarSize, ScalarSize),
                            wireWork.Slice((((c + halves) * width) + h) * ScalarSize, ScalarSize),
                            challenge, oneMinusChallenge, add, multiply, curve, scratch, scratch2);
                    }
                }
            }

            //Phase 2: the hand sumcheck over the copy-folded wires. The eq factor has folded to a
            //scalar, absorbed into the scattered wiring table.
            ReadOnlySpan<byte> equalityScalar = equalityWork[..ScalarSize];
            ReadOnlySpan<byte> foldedWires = wireWork[..(width * ScalarSize)];
            int jointCount = width * width;

            Span<byte> factors = factorOwner.Memory.Span[..(3 * jointCount * ScalarSize)];
            Span<byte> wiring = factors[..(jointCount * ScalarSize)];
            Span<byte> left = factors.Slice(jointCount * ScalarSize, jointCount * ScalarSize);
            Span<byte> right = factors.Slice(2 * jointCount * ScalarSize, jointCount * ScalarSize);

            wiring.Clear();
            for(int k = 0; k < terms.Length; k++)
            {
                multiply(termCoefficients.Slice(k * ScalarSize, ScalarSize), equalityScalar, scratch, curve);
                Span<byte> cell = wiring.Slice(((terms[k].LeftWire * width) + terms[k].RightWire) * ScalarSize, ScalarSize);
                add(cell, scratch, scratch2, curve);
                scratch2.CopyTo(cell);
            }

            for(int j = 0; j < jointCount; j++)
            {
                int h0 = j >> logWidth;
                int h1 = j & (width - 1);
                foldedWires.Slice(h0 * ScalarSize, ScalarSize).CopyTo(left.Slice(j * ScalarSize, ScalarSize));
                foldedWires.Slice(h1 * ScalarSize, ScalarSize).CopyTo(right.Slice(j * ScalarSize, ScalarSize));
            }

            //The last layer's hand points land in the result buffer — they are the input-claim
            //points a committed-witness wrapper opens the commitment at.
            bool lastLayer = l == layerCount - 1;
            Span<byte> leftPoint = lastLayer
                ? resultPointBuffer.Memory.Span.Slice(logCopies * ScalarSize, logWidth * ScalarSize)
                : handPointOwner.Memory.Span[..(logWidth * ScalarSize)];
            Span<byte> rightPoint = lastLayer
                ? resultPointBuffer.Memory.Span.Slice((logCopies + inputLogWidth) * ScalarSize, logWidth * ScalarSize)
                : handPointOwner.Memory.Span.Slice(maxLogWidth * ScalarSize, logWidth * ScalarSize);

            //The hand proof's ownership moves into the layer proof; the prover result owns only
            //the challenge point, copied out before its scope ends.
            ProductSumcheckProof handProof;
            using(ProductSumcheckProverResult result = ProductSumcheck.Prove(
                factors, 3, 2 * logWidth, add, subtract, multiply, reduce, curve, transcript, squeeze, hash, pool))
            {
                handProof = result.Proof;
                GkrEvaluation.SplitJointPoint(result.ChallengePoint.Span, logWidth, leftPoint, rightPoint);
            }

            layerProofs[l] = new GkrDataParallelLayerProof(copyRoundBuffer, logCopies, handProof);

            transcript.AbsorbBytes(GkrTranscriptLabels.LayerClaims, handProof.FinalValues.Span, hash);

            //The copy point walks down: the next layer's copies are pinned at r_c.
            GkrEvaluation.ReversePoint(copyChallenges, logCopies, copyPoint);

            if(l < layerCount - 1)
            {
                SumcheckChallenge.Squeeze(transcript, GkrTranscriptLabels.LayerCombination, alpha, squeeze, hash, reduce, curve);
                SumcheckChallenge.Squeeze(transcript, GkrTranscriptLabels.LayerCombination, beta, squeeze, hash, reduce, curve);

                Span<byte> leftTable = equalityScratchOwner.Memory.Span[..(width * ScalarSize)];
                Span<byte> rightTable = equalityScratchOwner.Memory.Span.Slice(maxWidth * ScalarSize, width * ScalarSize);
                EqualityPolynomial.BuildTable(leftPoint, logWidth, leftTable, subtract, multiply, curve);
                EqualityPolynomial.BuildTable(rightPoint, logWidth, rightTable, subtract, multiply, curve);
                GkrEvaluation.CombineTables(alpha, leftTable, beta, rightTable, coefficients[..(width * ScalarSize)], add, multiply, curve);
            }
        }

        copyPoint.CopyTo(resultPointBuffer.Memory.Span[..(logCopies * ScalarSize)]);

        return new GkrDataParallelProverResult(new GkrDataParallelProof(layerProofs), resultPointBuffer, logCopies, inputLogWidth);
    }


    //destination = low[index] + point·(high[index] − low[index]) — one wire (or eq entry) of the
    //bound variable's degree-1 extension at the integer evaluation point.
    private static void ExtendAt(
        ReadOnlySpan<byte> low, ReadOnlySpan<byte> high, int index, ReadOnlySpan<byte> point, Span<byte> destination,
        ScalarAddDelegate add, ScalarSubtractDelegate subtract, ScalarMultiplyDelegate multiply, CurveParameterSet curve, Span<byte> scratch)
    {
        ReadOnlySpan<byte> lowValue = low.Slice(index * ScalarSize, ScalarSize);
        subtract(high.Slice(index * ScalarSize, ScalarSize), lowValue, scratch, curve);
        multiply(point, scratch, destination, curve);
        add(lowValue, destination, scratch, curve);
        scratch.CopyTo(destination);
    }


    //low = low·(1−r) + high·r, the in-place sumcheck fold of one pair.
    private static void FoldPair(
        Span<byte> low, ReadOnlySpan<byte> high, ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> oneMinusChallenge,
        ScalarAddDelegate add, ScalarMultiplyDelegate multiply, CurveParameterSet curve, Span<byte> scratch, Span<byte> scratch2)
    {
        multiply(low, oneMinusChallenge, scratch, curve);
        multiply(high, challenge, scratch2, curve);
        add(scratch, scratch2, low, curve);
    }
}

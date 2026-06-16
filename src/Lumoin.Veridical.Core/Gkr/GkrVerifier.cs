using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// The layered GKR verifier: replays the prover's transcript walk and checks, per layer, that the
/// product sumcheck is internally consistent, that the bound wiring value the prover folded
/// matches an independent evaluation from the public circuit description, and that the final wire
/// claims against the inputs equal the input table's multilinear extension at the derived points.
/// Verifier work is linear in the circuit description (terms), not in the evaluation tables — the
/// asymmetry that makes GKR a succinct-verifier protocol. Working storage is rented from the pool
/// up front and reused across layers.
/// </summary>
internal static class GkrVerifier
{
    private const int ScalarSize = SumcheckChallenge.ScalarSize;


    public static bool Verify(
        GkrCircuit circuit,
        ReadOnlySpan<byte> inputs,
        ReadOnlySpan<byte> outputs,
        GkrProof proof,
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
        if(inputs.Length != circuit.InputCount * ScalarSize)
        {
            throw new ArgumentException($"The circuit takes {circuit.InputCount} inputs ({circuit.InputCount * ScalarSize} bytes); received {inputs.Length}.", nameof(inputs));
        }

        if(outputs.Length != circuit.Layers[0].OutputCount * ScalarSize)
        {
            throw new ArgumentException($"The circuit has {circuit.Layers[0].OutputCount} outputs ({circuit.Layers[0].OutputCount * ScalarSize} bytes); received {outputs.Length}.", nameof(outputs));
        }

        int layerCount = circuit.Layers.Length;
        if(proof.LayerProofs.Length != layerCount)
        {
            return false;
        }

        transcript.AbsorbBytes(GkrTranscriptLabels.Inputs, inputs, hash);
        transcript.AbsorbBytes(GkrTranscriptLabels.Outputs, outputs, hash);

        int maxWidth = circuit.InputCount;
        for(int l = 0; l < layerCount; l++)
        {
            maxWidth = Math.Max(maxWidth, circuit.WidthBelow(l));
        }

        int maxLogWidth = BitOperations.Log2((uint)maxWidth);
        using IMemoryOwner<byte> pointOwner = pool.Rent(4 * maxLogWidth * ScalarSize);
        using IMemoryOwner<byte> equalityScratchOwner = pool.Rent(maxWidth * ScalarSize);

        //The initial claim: the outputs' multilinear extension at the transcript point z.
        int logv = BitOperations.Log2((uint)circuit.Layers[0].OutputCount);
        using IMemoryOwner<byte> outputPointOwner = pool.Rent(logv * ScalarSize);
        Span<byte> z = outputPointOwner.Memory.Span[..(logv * ScalarSize)];
        GkrEvaluation.SqueezePoint(transcript, GkrTranscriptLabels.OutputPoint, logv, z, squeeze, hash, reduce, curve);

        Span<byte> outputTable = equalityScratchOwner.Memory.Span[..(circuit.Layers[0].OutputCount * ScalarSize)];
        EqualityPolynomial.BuildTable(z, logv, outputTable, subtract, multiply, curve);

        Span<byte> claim = stackalloc byte[ScalarSize];
        GkrEvaluation.Dot(outputTable, outputs, claim, add, multiply, curve);

        //How the current layer's output-coefficient E[g] is evaluated: at z for the output layer,
        //then α·eq_{r_left}(g) + β·eq_{r_right}(g) for the combined wire claims of the layer above.
        bool atOutputLayer = true;
        int previousLogWidth = 0;
        Span<byte> previousLeft = pointOwner.Memory.Span[..(maxLogWidth * ScalarSize)];
        Span<byte> previousRight = pointOwner.Memory.Span.Slice(maxLogWidth * ScalarSize, maxLogWidth * ScalarSize);
        Span<byte> currentLeft = pointOwner.Memory.Span.Slice(2 * maxLogWidth * ScalarSize, maxLogWidth * ScalarSize);
        Span<byte> currentRight = pointOwner.Memory.Span.Slice(3 * maxLogWidth * ScalarSize, maxLogWidth * ScalarSize);
        Span<byte> alpha = stackalloc byte[ScalarSize];
        Span<byte> beta = stackalloc byte[ScalarSize];

        Span<byte> coefficient = stackalloc byte[ScalarSize];
        Span<byte> eqLeft = stackalloc byte[ScalarSize];
        Span<byte> eqRight = stackalloc byte[ScalarSize];
        Span<byte> eqOutput = stackalloc byte[ScalarSize];
        Span<byte> combined = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> expectedWiring = stackalloc byte[ScalarSize];
        Span<byte> sum = stackalloc byte[ScalarSize];

        for(int l = 0; l < layerCount; l++)
        {
            GkrLayer layer = circuit.Layers[l];
            int width = circuit.WidthBelow(l);
            int logWidth = BitOperations.Log2((uint)width);
            ProductSumcheckProof layerProof = proof.LayerProofs[l];
            if(layerProof.FactorCount != 3 || layerProof.VariableCount != 2 * logWidth)
            {
                return false;
            }

            using MultilinearSumcheckVerification verification = ProductSumcheck.Verify(
                claim, layerProof, add, subtract, multiply, invert, reduce, curve, transcript, squeeze, hash, pool);
            if(!verification.Accepted)
            {
                return false;
            }

            GkrEvaluation.SplitJointPoint(verification.Point.Span, logWidth, currentLeft[..(logWidth * ScalarSize)], currentRight[..(logWidth * ScalarSize)]);

            //The bound wiring value: Σ_t coeff_t·E[output_t]·eq(left_t at r_left)·eq(right_t at r_right),
            //computed from the public circuit — the prover's folded factor 0 must equal it.
            expectedWiring.Clear();
            foreach(GkrLayerTerm gate in layer.Terms)
            {
                if(atOutputLayer)
                {
                    GkrEvaluation.EvaluateEqAt(gate.OutputWire, z, coefficient, subtract, multiply, curve);
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

            ReadOnlySpan<byte> finalValues = layerProof.FinalValues.Span;
            if(!expectedWiring.SequenceEqual(finalValues[..ScalarSize]))
            {
                return false;
            }

            ReadOnlySpan<byte> leftClaim = finalValues.Slice(ScalarSize, ScalarSize);
            ReadOnlySpan<byte> rightClaim = finalValues.Slice(2 * ScalarSize, ScalarSize);

            transcript.AbsorbBytes(GkrTranscriptLabels.LayerClaims, finalValues, hash);

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
                //The wire claims now address the public inputs: check them against the input
                //table's multilinear extension at the derived points.
                Span<byte> inputTable = equalityScratchOwner.Memory.Span[..(width * ScalarSize)];
                EqualityPolynomial.BuildTable(currentLeft[..(logWidth * ScalarSize)], logWidth, inputTable, subtract, multiply, curve);
                GkrEvaluation.Dot(inputTable, inputs, combined, add, multiply, curve);
                if(!combined.SequenceEqual(leftClaim))
                {
                    return false;
                }

                EqualityPolynomial.BuildTable(currentRight[..(logWidth * ScalarSize)], logWidth, inputTable, subtract, multiply, curve);
                GkrEvaluation.Dot(inputTable, inputs, combined, add, multiply, curve);
                if(!combined.SequenceEqual(rightClaim))
                {
                    return false;
                }
            }
        }

        return true;
    }
}

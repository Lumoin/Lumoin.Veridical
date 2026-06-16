using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Numerics;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// The layered GKR prover over a delegate-supplied field: proves a <see cref="GkrCircuit"/>
/// evaluates to its outputs by walking the layers from the outputs down, one product sumcheck per
/// layer. The verifier's claim about a layer's outputs — initially <c>OUT~(z)</c> at a transcript
/// point <c>z</c>, then <c>α·W~(r_left) + β·W~(r_right)</c> for the combined wire claims — equals
/// <c>Σ_{h0,h1} P_E(h0,h1)·W(h0)·W(h1)</c>, where <c>P_E</c> scatters each term's
/// <c>coefficient·E[output]</c> to its <c>(left, right)</c> wire pair (<c>E</c> the equality/
/// combination table over the layer's outputs). The sumcheck reduces that to the two wire claims
/// <c>W(r_left)</c>, <c>W(r_right)</c> the next layer takes over, ending at the inputs. Prover
/// work is linear in circuit size per layer — the topology that replaces the super-linear
/// Ligero-over-the-whole-R1CS prove. All working storage is rented from the pool up front and
/// reused across layers.
/// </summary>
internal static class GkrProver
{
    private const int ScalarSize = SumcheckChallenge.ScalarSize;


    public static GkrProof Prove(
        GkrCircuit circuit,
        ReadOnlySpan<byte> inputs,
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

        using GkrWireTables tables = circuit.Evaluate(inputs, add, multiply, curve, pool);

        //Bind the statement: the public inputs and the claimed outputs.
        transcript.AbsorbBytes(GkrTranscriptLabels.Inputs, inputs, hash);
        transcript.AbsorbBytes(GkrTranscriptLabels.Outputs, tables.Table(0).Span, hash);

        int layerCount = circuit.Layers.Length;
        var layerProofs = new ProductSumcheckProof[layerCount];

        //Working storage, rented once and reused across layers at each layer's width.
        int maxWidth = circuit.InputCount;
        int maxOutput = circuit.Layers[0].OutputCount;
        for(int l = 0; l < layerCount; l++)
        {
            maxWidth = Math.Max(maxWidth, circuit.WidthBelow(l));
            maxOutput = Math.Max(maxOutput, circuit.Layers[l].OutputCount);
        }

        int maxLogWidth = BitOperations.Log2((uint)maxWidth);
        using IMemoryOwner<byte> coefficientOwner = pool.Rent(maxOutput * ScalarSize);
        using IMemoryOwner<byte> factorOwner = pool.Rent(3 * maxWidth * maxWidth * ScalarSize);
        using IMemoryOwner<byte> pointOwner = pool.Rent(2 * maxLogWidth * ScalarSize);
        using IMemoryOwner<byte> equalityScratchOwner = pool.Rent(2 * maxWidth * ScalarSize);

        //The initial coefficient table over the output wires: eq at the transcript point z.
        int logv = BitOperations.Log2((uint)circuit.Layers[0].OutputCount);
        using IMemoryOwner<byte> outputPointOwner = pool.Rent(logv * ScalarSize);
        Span<byte> z = outputPointOwner.Memory.Span[..(logv * ScalarSize)];
        GkrEvaluation.SqueezePoint(transcript, GkrTranscriptLabels.OutputPoint, logv, z, squeeze, hash, reduce, curve);

        Span<byte> coefficients = coefficientOwner.Memory.Span[..(maxOutput * ScalarSize)];
        EqualityPolynomial.BuildTable(z, logv, coefficients[..(circuit.Layers[0].OutputCount * ScalarSize)], subtract, multiply, curve);

        Span<byte> scaled = stackalloc byte[ScalarSize];
        Span<byte> sum = stackalloc byte[ScalarSize];
        Span<byte> alpha = stackalloc byte[ScalarSize];
        Span<byte> beta = stackalloc byte[ScalarSize];

        for(int l = 0; l < layerCount; l++)
        {
            GkrLayer layer = circuit.Layers[l];
            ReadOnlySpan<byte> below = tables.Table(l + 1).Span;
            int width = below.Length / ScalarSize;
            int logWidth = BitOperations.Log2((uint)width);
            int jointCount = width * width;

            Span<byte> factors = factorOwner.Memory.Span[..(3 * jointCount * ScalarSize)];
            Span<byte> wiring = factors[..(jointCount * ScalarSize)];
            Span<byte> left = factors.Slice(jointCount * ScalarSize, jointCount * ScalarSize);
            Span<byte> right = factors.Slice(2 * jointCount * ScalarSize, jointCount * ScalarSize);

            //P_E: scatter coefficient·E[output] onto the (left, right) wire pair of each term.
            wiring.Clear();
            foreach(GkrLayerTerm term in layer.Terms)
            {
                multiply(term.Coefficient.Span, coefficients.Slice(term.OutputWire * ScalarSize, ScalarSize), scaled, curve);
                Span<byte> cell = wiring.Slice(((term.LeftWire * width) + term.RightWire) * ScalarSize, ScalarSize);
                add(cell, scaled, sum, curve);
                sum.CopyTo(cell);
            }

            //W_left(h0, h1) = W[h0] (constant in the low bits); W_right(h0, h1) = W[h1].
            for(int j = 0; j < jointCount; j++)
            {
                int h0 = j >> logWidth;
                int h1 = j & (width - 1);
                below.Slice(h0 * ScalarSize, ScalarSize).CopyTo(left.Slice(j * ScalarSize, ScalarSize));
                below.Slice(h1 * ScalarSize, ScalarSize).CopyTo(right.Slice(j * ScalarSize, ScalarSize));
            }

            using ProductSumcheckProverResult result = ProductSumcheck.Prove(
                factors, 3, 2 * logWidth, add, subtract, multiply, reduce, curve, transcript, squeeze, hash, pool);
            layerProofs[l] = result.Proof;

            //Bind the layer's claims before the combination coefficients are drawn.
            transcript.AbsorbBytes(GkrTranscriptLabels.LayerClaims, result.Proof.FinalValues.Span, hash);

            if(l < layerCount - 1)
            {
                Span<byte> leftPoint = pointOwner.Memory.Span[..(logWidth * ScalarSize)];
                Span<byte> rightPoint = pointOwner.Memory.Span.Slice(maxLogWidth * ScalarSize, logWidth * ScalarSize);
                GkrEvaluation.SplitJointPoint(result.ChallengePoint.Span, logWidth, leftPoint, rightPoint);

                SumcheckChallenge.Squeeze(transcript, GkrTranscriptLabels.LayerCombination, alpha, squeeze, hash, reduce, curve);
                SumcheckChallenge.Squeeze(transcript, GkrTranscriptLabels.LayerCombination, beta, squeeze, hash, reduce, curve);

                //The next layer's coefficient table: α·eq_{r_left} + β·eq_{r_right} over its outputs.
                Span<byte> leftTable = equalityScratchOwner.Memory.Span[..(width * ScalarSize)];
                Span<byte> rightTable = equalityScratchOwner.Memory.Span.Slice(maxWidth * ScalarSize, width * ScalarSize);
                EqualityPolynomial.BuildTable(leftPoint, logWidth, leftTable, subtract, multiply, curve);
                EqualityPolynomial.BuildTable(rightPoint, logWidth, rightTable, subtract, multiply, curve);
                GkrEvaluation.CombineTables(alpha, leftTable, beta, rightTable, coefficients[..(width * ScalarSize)], add, multiply, curve);
            }
        }

        return new GkrProof(layerProofs);
    }
}

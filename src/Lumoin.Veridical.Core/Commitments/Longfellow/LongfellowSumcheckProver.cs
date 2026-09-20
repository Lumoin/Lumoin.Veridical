using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The wire-format-conformant sumcheck PROVER, a faithful port of the <c>logc == 0</c> subset of
/// google/longfellow-zk's <c>ProverLayers&lt;Field&gt;</c> (<c>lib/sumcheck/prover_layers.h</c>) driving
/// the layered sumcheck the ZK argument runs over. It evaluates the circuit on the witness column to
/// recover each layer's input wire table (<c>eval_circuit</c>), then per layer engages in the single-layer
/// sumcheck over <c>EQ[c]·QUAD[r,l]·W[r,c]·W[l,c]</c> — but with <c>logc == 0</c> there are no copy rounds,
/// so the walk is the hand-round binding alone: per round per hand it computes the degree-2 round
/// polynomial, subtracts the matching proof pad, writes the padded points into the
/// <see cref="LongfellowSumcheckProof"/>, and squeezes the hand challenge from the transcript.
/// </summary>
/// <remarks>
/// <para>
/// The circuit's quadratic form a layer computes is <c>V[g,c] = Σ_term v·W[h0,c]·W[h1,c]</c>; the wire
/// format requires a single copy (<c>nc == 1</c>, <c>logc == 0</c>), so every wire table is one column
/// and <c>EQ</c> binds to the scalar one. <see cref="EvaluateCircuit"/> walks the layers from the input
/// layer down to the output, materializing each layer's input table; the output table is asserted
/// all-zero (the assert-zero circuit the ZK relation compiles to).
/// </para>
/// <para>
/// Per layer the sumcheck (<see cref="ProveLayer"/>) mirrors the reference's <c>layer()</c> with the copy
/// loop elided: it reconstructs the running sum from the previous layer's two claims
/// (<c>sum = WC[0] + alpha·WC[1]</c>), binds <c>g</c> into a per-layer <c>HQUAD</c> coefficient table
/// (<see cref="LongfellowSumcheckHQuad.BindG"/>), then alternates the two hands across <c>logw</c>
/// rounds. Each round precomputes <c>QW[l] = Σ_r Q[l,r]·W_other[r]</c> through the bound quad
/// (<see cref="LongfellowSumcheckHQuad.AccumulateQuadWeighted"/>), computes the round polynomial's points
/// <c>{0, 1, g}</c> (<see cref="RoundPolynomial"/>, the reference's <c>evaluations</c>), subtracts the
/// pad, emits the padded points, squeezes the challenge, folds the sum, and binds the hand variable in
/// <c>W</c> and <c>HQUAD</c>. The two final wire claims <c>WC[0]</c>, <c>WC[1]</c> are padded and written
/// by <see cref="EndLayer"/>.
/// </para>
/// <para>
/// The transcript schedule matches the sumcheck-segment verifier replay exactly: <c>begin_circuit</c> squeezes
/// <c>Q</c>/<c>G</c>, then per layer <c>begin_layer</c> squeezes <c>alpha</c>/<c>beta</c>, each round
/// absorbs the two transmitted points <c>(p(0), p(2))</c> and squeezes the hand challenge, and the two
/// padded <c>wc</c> claims are absorbed. The non-ZK prover would absorb the input column first
/// (<c>write_input</c>); the ZK composition does NOT — its Fiat–Shamir setup is the caller's
/// <c>initialize_sumcheck_fiat_shamir</c>.
/// </para>
/// <para>
/// The arithmetic is field-generic: the differences and affine folds subtract through the threaded
/// delegate (over GF(2^128) subtraction coincides with addition and negation is the identity; over Fp256
/// both are genuine field operations), and the round-polynomial evaluation points are <c>{zero, one, t}</c>
/// where the third point <c>t</c> is the field's <c>poly_evaluation_point(2)</c> carried by the profile
/// (<c>g = BasisElement(1)</c> for GF(2^128), <c>2</c> for Fp256). The delegates are injected to match the
/// library's primitive-agnostic commitment infrastructure; all working storage is pool-rented and cleared
/// on return.
/// </para>
/// </remarks>
internal static class LongfellowSumcheckProver
{
    /// <summary>The in-memory canonical scalar width in bytes.</summary>
    private const int ScalarSize = Scalar.SizeBytes;

    /// <summary>The reference's <c>Challenge::kMaxBindings</c>: <c>Q</c> and <c>G</c> are squeezed as <c>kMaxBindings</c>-element arrays.</summary>
    private const int MaxBindings = 40;

    /// <summary>The number of evaluation points a round polynomial carries (<c>{0, 1, g}</c>); the wire transmits only points 0 and 2.</summary>
    private const int RoundPolynomialPoints = LongfellowSumcheckProof.RoundPolynomialPoints;

    /// <summary>The number of hands (left, right) a per-round binding alternates across.</summary>
    private const int HandCount = LongfellowSumcheckProof.HandCount;


    /// <summary>
    /// Evaluates the circuit on the witness column, returning the per-layer input wire tables (the
    /// reference's <c>eval_circuit</c> output <c>in</c>). Each table is <see cref="LongfellowSumcheckLayer.InputCount"/>
    /// canonical scalars (one copy, <c>nc == 1</c>). The caller owns and disposes the result; the output
    /// table (the circuit output) is asserted all-zero.
    /// </summary>
    /// <param name="circuit">The circuit shape with its per-layer Quad terms; must have <c>nc == 1</c>, <c>logc == 0</c>.</param>
    /// <param name="witnessColumn">The full input wire column <c>W</c>, <see cref="LongfellowSumcheckCircuit.InputCount"/> · 32 canonical bytes.</param>
    /// <param name="multiply">GF(2^128) multiplication.</param>
    /// <param name="add">GF(2^128) addition (XOR).</param>
    /// <param name="curve">The curve parameter the delegates take.</param>
    /// <param name="pool">The pool the wire tables rent from.</param>
    /// <returns>The per-layer input tables; index <c>ly</c> is the input wires of layer <c>ly</c>.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit has copies, a layer lacks quad terms, or a length is wrong.</exception>
    /// <exception cref="InvalidOperationException">When the circuit output is not all-zero (an unsatisfying witness).</exception>
    public static LongfellowWireTables EvaluateCircuit(
        LongfellowSumcheckCircuit circuit,
        ReadOnlySpan<byte> witnessColumn,
        ScalarMultiplyDelegate multiply,
        ScalarAddDelegate add,
        CurveParameterSet curve,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(pool);

        RequireSingleCopy(circuit);

        if(witnessColumn.Length != circuit.InputCount * ScalarSize)
        {
            throw new ArgumentException($"Expected {circuit.InputCount * ScalarSize} witness-column bytes; received {witnessColumn.Length}.", nameof(witnessColumn));
        }

        var tables = new LongfellowWireTables(circuit, pool);
        try
        {
            //in[nl-1] = W0 (the full circuit input).
            int inputLayer = circuit.LayerCount - 1;
            witnessColumn.CopyTo(tables.Table(inputLayer));

            //Evaluate each layer l on its input W (= in[l]) producing V (= in[l-1] for l > 0, else the
            //circuit output). The layer's quad form V[g] = Σ_term v·W[h0]·W[h1] over the single copy.
            Span<byte> product = stackalloc byte[ScalarSize];

            for(int l = circuit.LayerCount; l-- > 0;)
            {
                LongfellowSumcheckLayer layer = circuit.Layers[l];
                RequireQuadTerms(circuit, layer, l);

                ReadOnlySpan<byte> input = tables.Table(l);

                if(l > 0)
                {
                    Span<byte> next = tables.Table(l - 1);
                    next.Clear();
                    EvaluateQuad(layer, input, next, multiply, add, product, curve);
                }
                else
                {
                    //The circuit output: the assert-zero relation requires every output wire to be zero.
                    Span<byte> finalOutput = tables.OutputTable();
                    finalOutput.Clear();
                    EvaluateQuad(layer, input, finalOutput, multiply, add, product, curve);

                    for(int g = 0; g < circuit.OutputCount; g++)
                    {
                        if(!IsZeroScalar(finalOutput.Slice(g * ScalarSize, ScalarSize)))
                        {
                            throw new InvalidOperationException($"The circuit output wire {g} is non-zero; the witness does not satisfy the circuit.");
                        }
                    }
                }
            }

            return tables;
        }
        catch
        {
            tables.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Runs the layered sumcheck over the evaluated wire tables, writing the padded round polynomials and
    /// wire claims into <paramref name="proof"/> and driving <paramref name="transcript"/> through the
    /// layer walk. The reference's <c>ProverLayers::prove</c> with the copy loop elided (<c>logc == 0</c>).
    /// </summary>
    /// <param name="circuit">The circuit shape with its per-layer Quad terms; must have <c>nc == 1</c>, <c>logc == 0</c>.</param>
    /// <param name="tables">The per-layer input wire tables from <see cref="EvaluateCircuit"/>.</param>
    /// <param name="pad">The proof pad; per layer the round polynomials' transmitted points and the two wire claims are subtracted.</param>
    /// <param name="proof">Receives the padded round polynomials and wire claims.</param>
    /// <param name="transcript">The transcript, already seeded and with the Fiat–Shamir setup performed; this call drives <c>begin_circuit</c>, the layer walk and the wc absorbs.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction (the round-polynomial differences and the affine folds).</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="invert">Field inversion (the Lagrange-fold weights).</param>
    /// <param name="profile">The field profile supplying the on-wire element width and the third evaluation point <c>poly_evaluation_point(2)</c> (<c>g</c> for GF(2^128), <c>2</c> for Fp256).</param>
    /// <param name="curve">The curve parameter the delegates take.</param>
    /// <param name="pool">The pool the working buffers rent from.</param>
    /// <param name="gatherMultiplyAccumulate">The optional gather/scatter fused multiply-accumulate primitive the per-round <c>QW</c> corner precompute routes through; the GF(2^128) hash side supplies it, the Fp256 sig side leaves it <see langword="null"/> for the scalar fallback.</param>
    /// <param name="broadcastMultiplyAccumulate">The optional broadcast-scalar fused multiply-accumulate primitive the per-layer <c>bind_g</c> routes through; <see langword="null"/> selects the scalar fallback.</param>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit has copies or a length is wrong.</exception>
    public static void Prove(
        LongfellowSumcheckCircuit circuit,
        LongfellowWireTables tables,
        LongfellowProofPad pad,
        LongfellowSumcheckProof proof,
        LongfellowTranscript transcript,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        LongfellowFieldProfile profile,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarGatherMultiplyAccumulateDelegate? gatherMultiplyAccumulate = null,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(tables);
        ArgumentNullException.ThrowIfNull(pad);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(pool);

        RequireSingleCopy(circuit);

        int elementBytes = profile.ElementBytes;

        //The field multiplicative one in the working domain, sourced from the profile (Foundation-A): the
        //canonical 0x01 for GF / the canonical Fp profile, to_montgomery(1) for the Montgomery Fp profile.
        Span<byte> one = stackalloc byte[ScalarSize];
        profile.CopyWorkingOne(one);

        //The round-polynomial evaluation points {0, 1, t}: point 0 = zero, point 1 = one, point 2 = the
        //field's poly_evaluation_point(2) (g for GF(2^128), 2 for Fp256), carried by the profile.
        Span<byte> evalPoints = stackalloc byte[RoundPolynomialPoints * ScalarSize];
        evalPoints.Clear();
        one.CopyTo(evalPoints.Slice(ScalarSize, ScalarSize));
        profile.CopyThirdEvaluationPoint(evalPoints.Slice(2 * ScalarSize, ScalarSize));

        //begin_circuit: squeeze Q (kMaxBindings) then G (kMaxBindings). The g[0] binding is the initial
        //output point; g[1] is duplicated from g[0] (the first layer has only one output claim). Q is
        //squeezed but unused when logc == 0; consume it to keep the transcript in step.
        using IMemoryOwner<byte> gOwner = pool.Rent(2 * MaxBindings * ScalarSize);
        Span<byte> g = gOwner.Memory.Span[..(2 * MaxBindings * ScalarSize)];
        g.Clear();
        Span<byte> g0 = g[..(MaxBindings * ScalarSize)];
        Span<byte> g1 = g.Slice(MaxBindings * ScalarSize, MaxBindings * ScalarSize);

        Span<byte> squeezed = stackalloc byte[ScalarSize];
        for(int i = 0; i < MaxBindings; i++)
        {
            transcript.SqueezeFieldElement(profile, squeezed);
        }

        for(int i = 0; i < MaxBindings; i++)
        {
            transcript.SqueezeFieldElement(profile, g0.Slice(i * ScalarSize, ScalarSize));
        }

        g0.CopyTo(g1);

        try
        {
            WalkLayers(circuit, tables, pad, proof, transcript, g0, g1, evalPoints, one, profile, elementBytes, add, subtract, multiply, invert, curve, pool, gatherMultiplyAccumulate, broadcastMultiplyAccumulate);
        }
        finally
        {
            evalPoints.Clear();
            one.Clear();
            g.Clear();
        }
    }


    /// <summary>Walks every circuit layer from the output down to the input, squeezing each layer's <c>alpha</c>/<c>beta</c> and proving it (<see cref="ProveLayer"/>), then advancing the output binding <c>g</c> to the layer's hand challenges for the next layer.</summary>
    /// <param name="circuit">The circuit shape.</param>
    /// <param name="tables">The per-layer input wire tables from <see cref="EvaluateCircuit"/>.</param>
    /// <param name="pad">The statistical mask's proof pad.</param>
    /// <param name="proof">The sumcheck proof being written.</param>
    /// <param name="transcript">The shared Fiat-Shamir transcript.</param>
    /// <param name="g0">The output binding's first challenge set; updated in place across layers.</param>
    /// <param name="g1">The output binding's second challenge set; updated in place across layers.</param>
    /// <param name="evalPoints">The three round-polynomial evaluation points <c>{0, 1, g}</c>.</param>
    /// <param name="one">The field's multiplicative identity.</param>
    /// <param name="profile">The field profile giving the wire element width and conversions.</param>
    /// <param name="elementBytes">The on-wire element width in bytes.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="invert">Field inversion.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">The pool the working buffers rent from.</param>
    /// <param name="gatherMultiplyAccumulate">The optional fused gather-multiply-accumulate primitive.</param>
    /// <param name="broadcastMultiplyAccumulate">The optional fused broadcast-multiply-accumulate primitive.</param>
    private static void WalkLayers(
        LongfellowSumcheckCircuit circuit,
        LongfellowWireTables tables,
        LongfellowProofPad pad,
        LongfellowSumcheckProof proof,
        LongfellowTranscript transcript,
        Span<byte> g0,
        Span<byte> g1,
        ReadOnlySpan<byte> evalPoints,
        ReadOnlySpan<byte> one,
        LongfellowFieldProfile profile,
        int elementBytes,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarGatherMultiplyAccumulateDelegate? gatherMultiplyAccumulate = null,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null)
    {
        int outputLogCount = circuit.OutputLogCount;

        //The two outgoing wire claims (the unpadded WC[0], WC[1]); initially zero.
        Span<byte> wc = stackalloc byte[2 * ScalarSize];
        wc.Clear();

        Span<byte> alpha = stackalloc byte[ScalarSize];
        Span<byte> beta = stackalloc byte[ScalarSize];

        //The per-layer hand challenges (hb[hand][round]) feeding the next layer's g[0]/g[1].
        using IMemoryOwner<byte> handOwner = pool.Rent(2 * MaxBindings * ScalarSize);
        Span<byte> handChallenges = handOwner.Memory.Span[..(2 * MaxBindings * ScalarSize)];

        try
        {
            for(int layer = 0; layer < circuit.LayerCount; layer++)
            {
                LongfellowSumcheckLayer layerShape = circuit.Layers[layer];
                int handRounds = layerShape.HandRounds;

                //begin_layer: squeeze alpha then beta.
                transcript.SqueezeFieldElement(profile, alpha);
                transcript.SqueezeFieldElement(profile, beta);

                handChallenges.Clear();
                ProveLayer(
                    layerShape, layer, tables.Table(layer), pad, proof, transcript,
                    outputLogCount, g0, g1, alpha, beta, handRounds, handChallenges,
                    evalPoints, one, profile, elementBytes, wc, add, subtract, multiply, invert, curve, pool, gatherMultiplyAccumulate, broadcastMultiplyAccumulate);

                //Advance the output binding for the next layer: g[0] = hb[0], g[1] = hb[1], logv = logw.
                handChallenges[..(MaxBindings * ScalarSize)].CopyTo(g0);
                handChallenges.Slice(MaxBindings * ScalarSize, MaxBindings * ScalarSize).CopyTo(g1);
                outputLogCount = handRounds;
            }
        }
        finally
        {
            handChallenges.Clear();
            wc.Clear();
            alpha.Clear();
            beta.Clear();
        }
    }


    /// <summary>
    /// Engages in the single-layer sumcheck on <c>EQ[c]·QUAD[r,l]·W[r,c]·W[l,c]</c> with <c>logc == 0</c>
    /// (no copy rounds): binds <c>r</c> and <c>l</c> in alternating hands. Stores the padded round
    /// polynomials and the padded wire claims <c>W[R]</c>, <c>W[L]</c> into the proof, and sets
    /// <paramref name="wc"/> to the new (unpadded) claims for the next layer.
    /// </summary>
    /// <param name="layer">The layer shape.</param>
    /// <param name="layerIndex">The layer's index, for the proof and pad lookups.</param>
    /// <param name="wireTable">The layer's input wire table.</param>
    /// <param name="pad">The statistical mask's proof pad.</param>
    /// <param name="proof">The sumcheck proof being written.</param>
    /// <param name="transcript">The shared Fiat-Shamir transcript.</param>
    /// <param name="outputLogCount">The output binding's round count.</param>
    /// <param name="g0">The output binding's first challenge set.</param>
    /// <param name="g1">The output binding's second challenge set.</param>
    /// <param name="alpha">This layer's squeezed <c>alpha</c> challenge.</param>
    /// <param name="beta">This layer's squeezed <c>beta</c> challenge.</param>
    /// <param name="handRounds">The number of hand-binding rounds this layer runs.</param>
    /// <param name="handChallenges">Receives the per-hand, per-round challenges for the next layer's output binding.</param>
    /// <param name="evalPoints">The three round-polynomial evaluation points <c>{0, 1, g}</c>.</param>
    /// <param name="one">The field's multiplicative identity.</param>
    /// <param name="profile">The field profile giving the wire element width and conversions.</param>
    /// <param name="elementBytes">The on-wire element width in bytes.</param>
    /// <param name="wc">On entry, the previous layer's two claims; on return, this layer's two claims.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="invert">Field inversion.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="pool">The pool the working buffers rent from.</param>
    /// <param name="gatherMultiplyAccumulate">The optional fused gather-multiply-accumulate primitive.</param>
    /// <param name="broadcastMultiplyAccumulate">The optional fused broadcast-multiply-accumulate primitive.</param>
    private static void ProveLayer(
        LongfellowSumcheckLayer layer,
        int layerIndex,
        ReadOnlySpan<byte> wireTable,
        LongfellowProofPad pad,
        LongfellowSumcheckProof proof,
        LongfellowTranscript transcript,
        int outputLogCount,
        ReadOnlySpan<byte> g0,
        ReadOnlySpan<byte> g1,
        ReadOnlySpan<byte> alpha,
        ReadOnlySpan<byte> beta,
        int handRounds,
        Span<byte> handChallenges,
        ReadOnlySpan<byte> evalPoints,
        ReadOnlySpan<byte> one,
        LongfellowFieldProfile profile,
        int elementBytes,
        Span<byte> wc,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarGatherMultiplyAccumulateDelegate? gatherMultiplyAccumulate = null,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null)
    {
        int nw = layer.InputCount;

        //Reconstruct the running sum from the previous layer's claims: sum = WC[0] + alpha·WC[1].
        Span<byte> sum = stackalloc byte[ScalarSize];
        multiply(alpha, wc.Slice(ScalarSize, ScalarSize), sum, curve);
        AddInPlace(sum, wc[..ScalarSize], add, curve);

        //Bind g into the layer's quad to produce the HQUAD coefficient table (the reference's bind_g).
        using LongfellowSumcheckHQuad hquad = LongfellowSumcheckHQuad.BindG(layer, outputLogCount, g0, g1, alpha, beta, add, subtract, multiply, curve, one, pool, broadcastMultiplyAccumulate);

        //W is the single-copy wire column; copy it into two hand buffers the hand bindings fold in place.
        using IMemoryOwner<byte> wLeftOwner = pool.Rent(nw * ScalarSize);
        using IMemoryOwner<byte> wRightOwner = pool.Rent(nw * ScalarSize);
        using IMemoryOwner<byte> qwBufferOwner = pool.Rent(nw * ScalarSize);
        Span<byte> wLeft = wLeftOwner.Memory.Span[..(nw * ScalarSize)];
        Span<byte> wRight = wRightOwner.Memory.Span[..(nw * ScalarSize)];
        Span<byte> qwBuffer = qwBufferOwner.Memory.Span[..(nw * ScalarSize)];
        wireTable.CopyTo(wLeft);
        wireTable.CopyTo(wRight);

        int leftLength = nw;
        int rightLength = nw;

        Span<byte> qwScratch = stackalloc byte[ScalarSize];
        Span<byte> polyBuffer = stackalloc byte[RoundPolynomialPoints * ScalarSize];
        Span<byte> challenge = stackalloc byte[ScalarSize];

        try
        {
            for(int round = 0; round < handRounds; round++)
            {
                for(int hand = 0; hand < HandCount; hand++)
                {
                    Span<byte> bindHand = hand == 0 ? wLeft : wRight;
                    Span<byte> otherHand = hand == 0 ? wRight : wLeft;
                    int bindLength = hand == 0 ? leftLength : rightLength;

                    //QW[p0] = Σ Q-cell·W_other[p1] over the bound quad's corners.
                    Span<byte> qw = qwBuffer[..(bindLength * ScalarSize)];
                    qw.Clear();
                    hquad.AccumulateQuadWeighted(hand, otherHand, qw, qwScratch, add, multiply, curve, gatherMultiplyAccumulate);

                    //Compute the round polynomial p(t) = Σ_l QW[l]·W[l], evaluated at {0, 1, t}.
                    RoundPolynomial(bindLength, qw, bindHand, sum, evalPoints, add, subtract, multiply, curve, polyBuffer);

                    //round_h: subtract the pad's poly pad, write the padded points, squeeze the challenge.
                    RoundHand(layerIndex, hand, round, polyBuffer, pad, proof, transcript, profile, elementBytes, subtract, curve, challenge);

                    //Fold the running sum at the challenge and store the hand challenge for the next layer.
                    SumcheckInterpolate(polyBuffer, challenge, evalPoints, one, sum, add, subtract, multiply, invert, curve);
                    challenge.CopyTo(handChallenges.Slice(((hand * MaxBindings) + round) * ScalarSize, ScalarSize));

                    //Bind the hand variable in W[hand] and HQUAD.
                    BindHand(bindHand, bindLength, challenge, add, subtract, multiply, curve);
                    if(hand == 0)
                    {
                        leftLength = (bindLength + 1) / 2;
                    }
                    else
                    {
                        rightLength = (bindLength + 1) / 2;
                    }

                    hquad.BindHand(hand, challenge, add, subtract, multiply, curve);
                }
            }

            //WC[0] = W_left scalar, WC[1] = W_right scalar (both folded to one element).
            wLeft[..ScalarSize].CopyTo(wc[..ScalarSize]);
            wRight[..ScalarSize].CopyTo(wc.Slice(ScalarSize, ScalarSize));

            //end_layer: subtract the pad's wc pad, write the padded claims, absorb them.
            EndLayer(layerIndex, wc, pad, proof, transcript, profile, elementBytes, subtract, curve);
        }
        finally
        {
            wLeft.Clear();
            wRight.Clear();
            qwBuffer.Clear();
            sum.Clear();
            polyBuffer.Clear();
        }
    }


    /// <summary>
    /// Evaluates the layer's quadratic form <c>V[g] = Σ_term v·W[h0]·W[h1]</c> over the single copy. An
    /// assert-zero term (<c>v == 0</c>) is a check the output-zero verification enforces; the reference's
    /// <c>eval_quad</c> does not accumulate it into <c>V</c>, so it is skipped here too.
    /// </summary>
    /// <param name="layer">The layer whose quad terms are evaluated.</param>
    /// <param name="input">The layer's input wire table.</param>
    /// <param name="output">Accumulates the evaluated output wires.</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="product">Scratch space for one term's product.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <exception cref="InvalidOperationException">When an assert-zero gate's wired product is nonzero.</exception>
    private static void EvaluateQuad(
        LongfellowSumcheckLayer layer,
        ReadOnlySpan<byte> input,
        Span<byte> output,
        ScalarMultiplyDelegate multiply,
        ScalarAddDelegate add,
        Span<byte> product,
        CurveParameterSet curve)
    {
        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();

        foreach(LongfellowSumcheckQuadTerm term in layer.QuadTerms)
        {
            ReadOnlySpan<byte> coefficient = term.Coefficient.Span;
            if(coefficient.SequenceEqual(zero))
            {
                //An assert-zero gate (the reference's eval_quad v == 0 branch): the term contributes
                //nothing to V, but the wired product MUST vanish — the reference returns false and the
                //prove refuses. The deployed mdoc and ECDSA arithmetizations carry these internally.
                multiply(input.Slice(term.LeftIndex * ScalarSize, ScalarSize), input.Slice(term.RightIndex * ScalarSize, ScalarSize), product, curve);
                if(!product.SequenceEqual(zero))
                {
                    throw new InvalidOperationException($"The witness violates an assert-zero gate at layer output {term.GateIndex}: W[{term.LeftIndex}]·W[{term.RightIndex}] is non-zero.");
                }

                continue;
            }

            //product = v·W[l]·W[r]; the reference multiplies v, then W[l], then W[r].
            multiply(coefficient, input.Slice(term.LeftIndex * ScalarSize, ScalarSize), product, curve);
            multiply(product, input.Slice(term.RightIndex * ScalarSize, ScalarSize), product, curve);
            AddInPlace(output.Slice(term.GateIndex * ScalarSize, ScalarSize), product, add, curve);
        }
    }


    /// <summary>
    /// The reference's <c>evaluations()</c>: computes <c>p(t) = Σ_l QW[l]·W[l]</c> as a degree-2 polynomial,
    /// evaluated at <c>{0, 1, t}</c>. With <c>logc == 0</c>, <c>eq0 = 1</c>. Computes the monomial
    /// coefficients <c>a0</c> (constant) and <c>a2</c> (quadratic), reconstructs <c>a1</c> from the running
    /// sum (<c>sum = p(0) + p(1) = 2·a0 + a1 + a2</c>), then evaluates via Horner at the points.
    /// </summary>
    /// <param name="n">The number of entries in <paramref name="qw"/> and <paramref name="w"/>.</param>
    /// <param name="qw">The bound quad's weighted-sum table <c>QW</c>.</param>
    /// <param name="w">The hand's wire values.</param>
    /// <param name="sum">The running claim sum <c>p(0) + p(1)</c>.</param>
    /// <param name="evalPoints">The three round-polynomial evaluation points <c>{0, 1, g}</c>.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="evals">Receives the polynomial's three evaluations, one per evaluation point.</param>
    private static void RoundPolynomial(
        int n,
        ReadOnlySpan<byte> qw,
        ReadOnlySpan<byte> w,
        ReadOnlySpan<byte> sum,
        ReadOnlySpan<byte> evalPoints,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        Span<byte> evals)
    {
        Span<byte> a0 = stackalloc byte[ScalarSize];
        Span<byte> a1 = stackalloc byte[ScalarSize];
        Span<byte> a2 = stackalloc byte[ScalarSize];
        a0.Clear();
        a2.Clear();

        Span<byte> dqw = stackalloc byte[ScalarSize];
        Span<byte> dw = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];

        int nodd = n / 2;
        for(int i = 0; i < nodd; i++)
        {
            ReadOnlySpan<byte> qw0 = qw.Slice(2 * i * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> qw1 = qw.Slice(((2 * i) + 1) * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> w0 = w.Slice(2 * i * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> w1 = w.Slice(((2 * i) + 1) * ScalarSize, ScalarSize);

            //a0 += qw0·w0.
            multiply(qw0, w0, term, curve);
            AddInPlace(a0, term, add, curve);

            //a2 += (qw1 - qw0)·(w1 - w0).
            subtract(qw1, qw0, dqw, curve);
            subtract(w1, w0, dw, curve);
            multiply(dqw, dw, term, curve);
            AddInPlace(a2, term, add, curve);
        }

        if(2 * nodd < n)
        {
            //The trailing odd element: a0 += qw0·w0; a2 += qw0·w0 (the reference's odd-tail branch).
            ReadOnlySpan<byte> qw0 = qw.Slice(2 * nodd * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> w0 = w.Slice(2 * nodd * ScalarSize, ScalarSize);
            multiply(qw0, w0, term, curve);
            AddInPlace(a0, term, add, curve);
            AddInPlace(a2, term, add, curve);
        }

        //SUM = p(0) + p(1) = 2·a0 + a1 + a2, so a1 = sum - a0 - a0 - a2 (the reference's literal form).
        sum.CopyTo(a1);
        SubInPlace(a1, a0, subtract, curve);
        SubInPlace(a1, a0, subtract, curve);
        SubInPlace(a1, a2, subtract, curve);

        //Evaluate the monomial polynomial a0 + a1·x + a2·x² at the three points {0, 1, t}.
        for(int k = 0; k < RoundPolynomialPoints; k++)
        {
            ReadOnlySpan<byte> x = evalPoints.Slice(k * ScalarSize, ScalarSize);
            EvaluateMonomial(a0, a1, a2, x, multiply, add, curve, evals.Slice(k * ScalarSize, ScalarSize));
        }

        a0.Clear();
        a1.Clear();
        a2.Clear();
    }


    /// <summary>Horner evaluation of <c>a0 + a1·x + a2·x²</c> (the reference's <c>Poly::eval_monomial</c> over 3 coefficients).</summary>
    /// <param name="a0">The constant coefficient.</param>
    /// <param name="a1">The linear coefficient.</param>
    /// <param name="a2">The quadratic coefficient.</param>
    /// <param name="x">The point to evaluate at.</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="result">Receives the evaluated value.</param>
    private static void EvaluateMonomial(
        ReadOnlySpan<byte> a0,
        ReadOnlySpan<byte> a1,
        ReadOnlySpan<byte> a2,
        ReadOnlySpan<byte> x,
        ScalarMultiplyDelegate multiply,
        ScalarAddDelegate add,
        CurveParameterSet curve,
        Span<byte> result)
    {
        //e = a2; e = e·x + a1; e = e·x + a0.
        Span<byte> e = stackalloc byte[ScalarSize];
        a2.CopyTo(e);
        multiply(e, x, e, curve);
        AddInPlace(e, a1, add, curve);
        multiply(e, x, e, curve);
        AddInPlace(e, a0, add, curve);
        e.CopyTo(result);
    }


    /// <summary>
    /// The reference's <c>round_h</c>: subtracts the pad's poly pad from the round polynomial's
    /// transmitted points (on a copy), stores the padded points into the proof, absorbs
    /// <c>(p(0), p(2))</c> (skipping <c>p(1)</c>), and squeezes the hand challenge from the padded
    /// polynomial. The reference (<c>prover_layers.h round_h</c>) subtracts the pad on a by-value copy
    /// (<c>Xhat = X - dX</c>), so the working polynomial stays unpadded — the sumcheck sum folds the
    /// unpadded polynomial (point 1's pad is the field zero, but only points 0 and 2 are transmitted anyway).
    /// </summary>
    /// <param name="layer">The layer index, for the pad and proof lookups.</param>
    /// <param name="hand">The hand index (0 or 1).</param>
    /// <param name="round">The hand-binding round index.</param>
    /// <param name="poly">The round polynomial's three unpadded evaluations.</param>
    /// <param name="pad">The statistical mask's proof pad.</param>
    /// <param name="proof">The sumcheck proof being written.</param>
    /// <param name="transcript">The shared Fiat-Shamir transcript.</param>
    /// <param name="profile">The field profile giving the wire element width and conversions.</param>
    /// <param name="elementBytes">The on-wire element width in bytes.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="challenge">Receives the squeezed hand challenge.</param>
    private static void RoundHand(
        int layer,
        int hand,
        int round,
        ReadOnlySpan<byte> poly,
        LongfellowProofPad pad,
        LongfellowSumcheckProof proof,
        LongfellowTranscript transcript,
        LongfellowFieldProfile profile,
        int elementBytes,
        ScalarSubtractDelegate subtract,
        CurveParameterSet curve,
        Span<byte> challenge)
    {
        Span<byte> padded0 = stackalloc byte[ScalarSize];
        Span<byte> padded2 = stackalloc byte[ScalarSize];
        subtract(poly[..ScalarSize], pad.PolyPad(layer, hand, round, 0), padded0, curve);
        subtract(poly.Slice(2 * ScalarSize, ScalarSize), pad.PolyPad(layer, hand, round, 2), padded2, curve);

        proof.SetRoundPolynomialPoint(layer, hand, round, 0, padded0);
        proof.SetRoundPolynomialPoint(layer, hand, round, 2, padded2);

        //Absorb the padded points through the profile's to_bytes_field: the transmitted bytes are the wire
        //bytes (canonical), dropped from the working domain (Montgomery->canonical for the Montgomery Fp
        //profile, identity for GF / the canonical Fp profile). Absorbing raw working-domain bytes would
        //diverge the squeezed challenge from the verifier's, which reads the same wire bytes back.
        Span<byte> littleEndianBuffer = stackalloc byte[ScalarSize];
        Span<byte> littleEndian = littleEndianBuffer[..elementBytes];
        profile.ToBytesField(padded0, littleEndian);
        transcript.AbsorbFieldElement(littleEndian, elementBytes);
        profile.ToBytesField(padded2, littleEndian);
        transcript.AbsorbFieldElement(littleEndian, elementBytes);

        //round(): squeeze the hand challenge via elt(F) (the field's sample loop).
        transcript.SqueezeFieldElement(profile, challenge);

        littleEndian.Clear();
    }


    /// <summary>
    /// The reference's <c>end_layer</c>: subtracts the pad's <c>wc</c> pad from the two wire claims, stores
    /// the padded claims, and absorbs them. The reference (<c>prover_layers.h end_layer</c>) subtracts the
    /// pad (<c>tt = wc - pad-&gt;wc</c>), so the transcript carries <c>Xhat = X - dX</c>.
    /// </summary>
    /// <param name="layer">The layer index, for the pad and proof lookups.</param>
    /// <param name="wc">The layer's two unpadded wire claims.</param>
    /// <param name="pad">The statistical mask's proof pad.</param>
    /// <param name="proof">The sumcheck proof being written.</param>
    /// <param name="transcript">The shared Fiat-Shamir transcript.</param>
    /// <param name="profile">The field profile giving the wire element width and conversions.</param>
    /// <param name="elementBytes">The on-wire element width in bytes.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    private static void EndLayer(
        int layer,
        ReadOnlySpan<byte> wc,
        LongfellowProofPad pad,
        LongfellowSumcheckProof proof,
        LongfellowTranscript transcript,
        LongfellowFieldProfile profile,
        int elementBytes,
        ScalarSubtractDelegate subtract,
        CurveParameterSet curve)
    {
        Span<byte> padded = stackalloc byte[2 * ScalarSize];
        subtract(wc[..ScalarSize], pad.ClaimPad(layer, 0), padded[..ScalarSize], curve);
        subtract(wc.Slice(ScalarSize, ScalarSize), pad.ClaimPad(layer, 1), padded.Slice(ScalarSize, ScalarSize), curve);

        proof.SetClaim(layer, 0, padded[..ScalarSize]);
        proof.SetClaim(layer, 1, padded.Slice(ScalarSize, ScalarSize));

        //write(wc, 1, 2): absorb the two padded claims through the profile's to_bytes_field so the wire
        //(canonical) bytes are absorbed, not the raw working-domain residues — the verifier reads these
        //same wire bytes back, so the challenge stream must be seeded from them.
        Span<byte> littleEndianBuffer = stackalloc byte[2 * ScalarSize];
        Span<byte> littleEndian = littleEndianBuffer[..(2 * elementBytes)];
        profile.ToBytesField(padded[..ScalarSize], littleEndian[..elementBytes]);
        profile.ToBytesField(padded.Slice(ScalarSize, ScalarSize), littleEndian.Slice(elementBytes, elementBytes));
        transcript.AbsorbFieldElementArray(littleEndian, 2, elementBytes);

        littleEndian.Clear();
    }


    /// <summary>
    /// The reference's <c>sum = eval_lagrange(poly, challenge)</c>: folds the running claim to the round
    /// polynomial evaluated at the challenge, computed via the Lagrange weights at the three nodes
    /// <c>{0, 1, g}</c>.
    /// </summary>
    /// <param name="poly">The round polynomial's three evaluations.</param>
    /// <param name="challenge">The squeezed hand challenge to evaluate at.</param>
    /// <param name="evalPoints">The three round-polynomial evaluation points <c>{0, 1, g}</c>.</param>
    /// <param name="one">The field's multiplicative identity.</param>
    /// <param name="sum">On entry, unused; on return, the folded claim.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="invert">Field inversion.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    private static void SumcheckInterpolate(
        ReadOnlySpan<byte> poly,
        ReadOnlySpan<byte> challenge,
        ReadOnlySpan<byte> evalPoints,
        ReadOnlySpan<byte> one,
        Span<byte> sum,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve)
    {
        Span<byte> weights = stackalloc byte[RoundPolynomialPoints * ScalarSize];
        LagrangeWeights(challenge, evalPoints, one, subtract, multiply, invert, curve, weights);

        Span<byte> acc = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        acc.Clear();
        for(int k = 0; k < RoundPolynomialPoints; k++)
        {
            multiply(weights.Slice(k * ScalarSize, ScalarSize), poly.Slice(k * ScalarSize, ScalarSize), term, curve);
            AddInPlace(acc, term, add, curve);
        }

        acc.CopyTo(sum);
        weights.Clear();
    }


    /// <summary>
    /// Binds a hand half: <c>W'[i] = affine_interpolation(challenge, W[2i], W[2i+1]) = W[2i] +
    /// challenge·(W[2i+1] - W[2i])</c>; a trailing odd element folds as
    /// <c>affine_interpolation_nz_z = W[2i]·(1 - challenge)</c>.
    /// </summary>
    /// <param name="w">The hand's wire values on entry; overwritten with the folded, half-length values.</param>
    /// <param name="n">The number of entries in <paramref name="w"/> before folding.</param>
    /// <param name="challenge">The hand challenge to fold at.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    private static void BindHand(
        Span<byte> w,
        int n,
        ReadOnlySpan<byte> challenge,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve)
    {
        Span<byte> difference = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];

        int nodd = n / 2;
        for(int i = 0; i < nodd; i++)
        {
            ReadOnlySpan<byte> w0 = w.Slice(2 * i * ScalarSize, ScalarSize);
            ReadOnlySpan<byte> w1 = w.Slice(((2 * i) + 1) * ScalarSize, ScalarSize);

            //W'[i] = w0 + challenge·(w1 - w0).
            subtract(w1, w0, difference, curve);
            multiply(challenge, difference, term, curve);
            add(w0, term, w.Slice(i * ScalarSize, ScalarSize), curve);
        }

        if(2 * nodd < n)
        {
            //affine_interpolation_nz_z(r, v) = v - r·v = v·(1 - r): the second corner is zero.
            ReadOnlySpan<byte> w0 = w.Slice(2 * nodd * ScalarSize, ScalarSize);
            multiply(challenge, w0, term, curve);
            subtract(w0, term, w.Slice(nodd * ScalarSize, ScalarSize), curve);
        }
    }


    /// <summary>
    /// The reference's <c>dot_wpoly.coef(x)</c>: the Lagrange weights of a degree-3 (<c>N = 3</c>)
    /// polynomial at point <paramref name="x"/> over the nodes <c>{0, 1, t}</c>:
    /// <c>weight[k] = Π_{j != k} (x - X[j]) / (X[k] - X[j])</c>.
    /// </summary>
    /// <param name="x">The point to compute the weights at.</param>
    /// <param name="evalPoints">The three round-polynomial evaluation points <c>{0, 1, g}</c>.</param>
    /// <param name="one">The field's multiplicative identity.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="invert">Field inversion.</param>
    /// <param name="curve">The field the delegates operate over.</param>
    /// <param name="weights">Receives the three Lagrange weights.</param>
    private static void LagrangeWeights(
        ReadOnlySpan<byte> x,
        ReadOnlySpan<byte> evalPoints,
        ReadOnlySpan<byte> one,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        Span<byte> weights)
    {
        const int N = RoundPolynomialPoints;

        Span<byte> numerator = stackalloc byte[ScalarSize];
        Span<byte> denominator = stackalloc byte[ScalarSize];
        Span<byte> difference = stackalloc byte[ScalarSize];

        for(int k = 0; k < N; k++)
        {
            one.CopyTo(numerator);
            one.CopyTo(denominator);
            ReadOnlySpan<byte> xk = evalPoints.Slice(k * ScalarSize, ScalarSize);
            for(int j = 0; j < N; j++)
            {
                if(j == k)
                {
                    continue;
                }

                ReadOnlySpan<byte> xj = evalPoints.Slice(j * ScalarSize, ScalarSize);

                subtract(x, xj, difference, curve);
                multiply(numerator, difference, numerator, curve);

                subtract(xk, xj, difference, curve);
                multiply(denominator, difference, denominator, curve);
            }

            invert(denominator, denominator, curve);
            multiply(numerator, denominator, weights.Slice(k * ScalarSize, ScalarSize), curve);
        }
    }


    /// <summary>Throws unless the circuit has exactly one copy and zero copy rounds, the wire-format constraint this prover requires.</summary>
    /// <param name="circuit">The circuit to check.</param>
    /// <exception cref="ArgumentException">When the circuit has more than one copy or a nonzero copy-round count.</exception>
    private static void RequireSingleCopy(LongfellowSumcheckCircuit circuit)
    {
        if(circuit.CopyRounds != 0 || circuit.CopyCount != 1)
        {
            throw new ArgumentException($"The sumcheck prover requires nc == 1 and logc == 0; the circuit has nc = {circuit.CopyCount}, logc = {circuit.CopyRounds}.", nameof(circuit));
        }
    }


    /// <summary>Throws unless a layer carries at least one quad term, since the sumcheck prover needs them to evaluate the circuit.</summary>
    /// <param name="circuit">The owning circuit, reported in the exception.</param>
    /// <param name="layer">The layer to check.</param>
    /// <param name="layerIndex">The layer's index, reported in the exception message.</param>
    /// <exception cref="ArgumentException">When <paramref name="layer"/> carries no quad terms.</exception>
    private static void RequireQuadTerms(LongfellowSumcheckCircuit circuit, LongfellowSumcheckLayer layer, int layerIndex)
    {
        if(layer.QuadTerms.Length == 0)
        {
            throw new ArgumentException($"Layer {layerIndex} carries no quad terms; the sumcheck prover needs them to evaluate the circuit.", nameof(circuit));
        }
    }


    /// <summary>Adds <paramref name="addend"/> into <paramref name="destination"/> in place, through a scratch buffer (the delegate contract does not guarantee in-place safety).</summary>
    /// <param name="destination">The accumulator, overwritten with the sum.</param>
    /// <param name="addend">The value to add.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="curve">The field the delegate operates over.</param>
    private static void AddInPlace(Span<byte> destination, ReadOnlySpan<byte> addend, ScalarAddDelegate add, CurveParameterSet curve)
    {
        Span<byte> scratch = stackalloc byte[ScalarSize];
        add(destination, addend, scratch, curve);
        scratch.CopyTo(destination);
    }


    /// <summary>Subtracts <paramref name="subtrahend"/> from <paramref name="destination"/> in place, through a scratch buffer (the delegate contract does not guarantee in-place safety).</summary>
    /// <param name="destination">The accumulator, overwritten with the difference.</param>
    /// <param name="subtrahend">The value to subtract.</param>
    /// <param name="subtract">Field subtraction.</param>
    /// <param name="curve">The field the delegate operates over.</param>
    private static void SubInPlace(Span<byte> destination, ReadOnlySpan<byte> subtrahend, ScalarSubtractDelegate subtract, CurveParameterSet curve)
    {
        Span<byte> scratch = stackalloc byte[ScalarSize];
        subtract(destination, subtrahend, scratch, curve);
        scratch.CopyTo(destination);
    }


    /// <summary>Reports whether every byte of a canonical scalar is zero.</summary>
    /// <param name="scalar">The scalar bytes to test.</param>
    /// <returns><see langword="true"/> when no byte in <paramref name="scalar"/> is nonzero.</returns>
    private static bool IsZeroScalar(ReadOnlySpan<byte> scalar) => scalar.IndexOfAnyExcept((byte)0) < 0;
}

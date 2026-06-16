using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Commitments.Ligero;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The composition that turns the sumcheck claims into the Ligero linear-constraint system, a faithful
/// port of google/longfellow-zk's <c>ZkCommon&lt;Field&gt;::verifier_constraints</c>
/// (<c>lib/zk/zk_common.h</c>). It mimics, on the transcript, the exact checks the non-ZK sumcheck
/// verifier applies — but instead of testing the claims directly it expresses them as a sparse linear
/// system <c>A·w = b</c> over the committed witness (the private inputs followed by the proof pad), so
/// the Ligero proof system verifies them against the hiding commitment.
/// </summary>
/// <remarks>
/// <para>
/// The witness layout the constraints address: indices <c>[0, n_witness)</c> are the circuit's private
/// inputs; indices <c>[n_witness, n_witness + pad_size)</c> are the proof pad — per layer the pad holds
/// the round polynomials' two transmitted points (the <c>p(1)</c> optimization omits the middle) and a
/// claim pad triple <c>[dWC[0], dWC[1], dWC[0]·dWC[1]]</c>, laid out by <see cref="LongfellowZkPadLayout"/>. Adjacent
/// layers' claim pads overlap (a layer's entering claim pad is the previous layer's outgoing one).
/// </para>
/// <para>
/// Per layer the build mirrors the sumcheck verifier: it folds the entering claim through a symbolic
/// <see cref="LongfellowZkConstraintExpression"/> (<c>claim_{-1} = cl0 + alpha·cl1</c> via <see cref="LongfellowZkConstraintExpression.First"/>,
/// then per round per hand <c>claim_r = ⟨lag_r, p_r⟩</c> via <see cref="LongfellowZkConstraintExpression.Next"/>), and
/// emits one constraint with <see cref="LongfellowZkConstraintExpression.Finalize"/> expressing the quadratic relation
/// <c>claim = eqq · W[R,C] · W[L,C]</c> in <c>A·w = b</c> form. <c>eqq = eqv · bind_quad</c>: <c>bind_quad</c>
/// (<see cref="BindQuad"/>, the port of <c>Quad::bind_gh_all</c>) binds the layer's <c>Quad</c> at the
/// output point and the hand challenges; <c>eqv</c> (<see cref="LongfellowEq.Eval"/>, the port of <c>Eq::eval</c>)
/// binds the copy variables — it is <c>1</c> when <c>logc == 0</c>. The transcript drives identically to
/// the C.7 replay: <c>begin_circuit</c> squeezes <c>Q</c>/<c>G</c>, each layer's <c>begin_layer</c>
/// squeezes <c>alpha</c>/<c>beta</c>, each round absorbs the two transmitted points and squeezes the
/// hand challenge, and the two <c>wc</c> claims are absorbed.
/// </para>
/// <para>
/// After the layers, <see cref="InputConstraint"/> (the port of <c>input_constraint</c>) squeezes the
/// input-binding challenge <c>alpha</c> and adds the final constraint binding the witness inputs:
/// <c>⟨eq0 + alpha·eq1, witness⟩ = (wc[0] + alpha·wc[1]) − public_binding</c>, where the public binding
/// is folded out using the public inputs. The method returns the constraint count <c>cn</c> the Ligero
/// verifier consumes.
/// </para>
/// <para>
/// The arithmetic is field-generic: subtraction and negation thread through the injected delegates (over
/// GF(2^128) subtraction coincides with addition and negation is the identity; over Fp256 both are genuine
/// field operations), and the round-polynomial Lagrange fold uses evaluation points <c>{0, 1, t}</c> where
/// the third point <c>t</c> is the field's <c>poly_evaluation_point(2)</c> carried by the profile (<c>g</c>
/// for GF(2^128), <c>2</c> for Fp256). The delegates are injected so the port stays consistent with the
/// library's primitive-agnostic commitment infrastructure.
/// </para>
/// </remarks>
internal static class LongfellowZkConstraintBuilder
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The reference's Challenge::kMaxBindings: Q and G are squeezed as kMaxBindings-element arrays.
    private const int MaxBindings = 40;

    //A round polynomial has three evaluation points {0, 1, g}; the wire transmits points 0 and 2.
    private const int RoundPolynomialPoints = LongfellowSumcheckProof.RoundPolynomialPoints;
    private const int HandCount = LongfellowSumcheckProof.HandCount;


    /// <summary>
    /// The assembled constraint system: the sparse linear terms <c>A</c>, the targets <c>b</c>, and the
    /// constraint count <c>cn</c>. The buffers are pool-rented and cleared on disposal.
    /// </summary>
    internal sealed class ConstraintSystem: IDisposable
    {
        private readonly BaseMemoryPool pool;
        private readonly List<LigeroLinearConstraint> terms;
        private IMemoryOwner<byte>? targetsOwner;
        private int targetCount;


        /// <summary>The number of constraints <c>cn</c> (the Ligero verifier's constraint count).</summary>
        public int ConstraintCount { get; internal set; }

        /// <summary>The sparse linear terms; each contributes <c>k · W[w]</c> to constraint <c>c</c>.</summary>
        public IReadOnlyList<LigeroLinearConstraint> Terms => terms;

        /// <summary>The constraint targets <c>b</c>: <see cref="ConstraintCount"/> canonical scalars.</summary>
        public ReadOnlySpan<byte> Targets => (targetsOwner ?? throw new ObjectDisposedException(nameof(ConstraintSystem))).Memory.Span[..(targetCount * ScalarSize)];


        internal ConstraintSystem(BaseMemoryPool pool, int constraintCapacity, int termCapacity)
        {
            this.pool = pool;
            terms = new List<LigeroLinearConstraint>(termCapacity);
            targetsOwner = pool.Rent(Math.Max(constraintCapacity, 1) * ScalarSize);
            targetsOwner.Memory.Span[..(Math.Max(constraintCapacity, 1) * ScalarSize)].Clear();
            targetCount = 0;
        }


        internal void AddTerm(int constraintIndex, int witnessIndex, ReadOnlySpan<byte> coefficient)
        {
            byte[] copy = new byte[ScalarSize];
            coefficient.CopyTo(copy);
            terms.Add(new LigeroLinearConstraint(constraintIndex, witnessIndex, copy));
        }


        internal void AddTarget(ReadOnlySpan<byte> target)
        {
            Span<byte> destination = (targetsOwner ?? throw new ObjectDisposedException(nameof(ConstraintSystem))).Memory.Span;
            target.CopyTo(destination.Slice(targetCount * ScalarSize, ScalarSize));
            targetCount++;
        }


        /// <inheritdoc/>
        public void Dispose()
        {
            IMemoryOwner<byte>? local = targetsOwner;
            if(local is not null)
            {
                targetsOwner = null;
                local.Memory.Span.Clear();
                local.Dispose();
            }
        }
    }


    /// <summary>
    /// Builds the Ligero linear-constraint system from the sumcheck proof, driving
    /// <paramref name="transcript"/> exactly as the non-ZK sumcheck verifier would, the reference's
    /// <c>verifier_constraints</c>. The transcript must already have had the Fiat–Shamir setup
    /// (<c>initialize_sumcheck_fiat_shamir</c>) performed by the caller — the input absorb is NOT part of
    /// this method (the ZK verifier does not absorb the input column; it absorbs only public inputs in
    /// the setup).
    /// </summary>
    /// <param name="circuit">The circuit shape with its per-layer <c>Quad</c> terms; must have <c>logc == 0</c>.</param>
    /// <param name="proof">The parsed sumcheck proof to replay.</param>
    /// <param name="publicInputs">The public inputs (the first <c>npub_in</c> witness elements), <c>npub_in</c> · ElementBytes little-endian element bytes.</param>
    /// <param name="firstPadIndex">The witness index of the first pad element (<c>pi</c>, the reference's <c>n_witness</c>).</param>
    /// <param name="transcript">The transcript, already seeded and with the FS setup performed; this call drives the layer walk and the input binding.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction (the symbolic folds, the Lagrange differences and the <c>1 − x</c> eq terms).</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="invert">Field inversion.</param>
    /// <param name="profile">The field profile supplying the on-wire element width and the third evaluation point <c>poly_evaluation_point(2)</c> (<c>g</c> for GF(2^128), <c>2</c> for Fp256).</param>
    /// <param name="curve">The curve parameter the delegates take (<see cref="CurveParameterSet.None"/> for GF(2^128)).</param>
    /// <param name="pool">The pool the working buffers rent from.</param>
    /// <param name="bindQuadReduce">The optional fused <c>bind_quad</c> per-term reduce primitive; supplied for the GF(2^128) hash side, <see langword="null"/> on the Fp256 sig side for the scalar fallback.</param>
    /// <param name="broadcastMultiplyAccumulate">The optional broadcast-scalar fused multiply primitive the <c>filleq</c> eq-array fills route their per-level scalar-times-vector products through; supplied for the GF(2^128) hash side, <see langword="null"/> on the Fp256 sig side for the scalar fallback.</param>
    /// <param name="fp256BatchMultiply">The optional lane-parallel batch Montgomery multiply the <c>bind_quad</c> reduction routes its three-multiply-per-term chain through; supplied for the Fp256 sig side, <see langword="null"/> on the GF(2^128) hash side (which supplies <paramref name="bindQuadReduce"/> instead — the two are mutually exclusive, both bundles passing <c>curve == None</c>).</param>
    /// <returns>The constraint system; the caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit has copies, a layer is missing its quad terms, or a length is wrong.</exception>
    public static ConstraintSystem Build(
        LongfellowSumcheckCircuit circuit,
        LongfellowSumcheckProof proof,
        ReadOnlySpan<byte> publicInputs,
        int firstPadIndex,
        LongfellowTranscript transcript,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        LongfellowFieldProfile profile,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        ScalarBindQuadReduceDelegate? bindQuadReduce = null,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null,
        ScalarBatchMultiplyDelegate? fp256BatchMultiply = null)
    {
        ArgumentNullException.ThrowIfNull(circuit);
        ArgumentNullException.ThrowIfNull(proof);
        ArgumentNullException.ThrowIfNull(transcript);
        ArgumentNullException.ThrowIfNull(add);
        ArgumentNullException.ThrowIfNull(subtract);
        ArgumentNullException.ThrowIfNull(multiply);
        ArgumentNullException.ThrowIfNull(invert);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(pool);

        if(circuit.CopyRounds != 0)
        {
            throw new ArgumentException($"verifier_constraints requires logc == 0; the circuit has logc = {circuit.CopyRounds}.", nameof(circuit));
        }

        int elementBytes = profile.ElementBytes;
        if(publicInputs.Length != circuit.PublicInputCount * elementBytes)
        {
            throw new ArgumentException($"Expected {circuit.PublicInputCount * elementBytes} public-input bytes; received {publicInputs.Length}.", nameof(publicInputs));
        }

        //The field multiplicative one in the working domain, sourced from the profile (Foundation-A): the
        //canonical 0x01 for GF / the canonical Fp profile, to_montgomery(1) for the Montgomery Fp profile.
        using IMemoryOwner<byte> oneOwner = pool.Rent(ScalarSize);
        Span<byte> one = oneOwner.Memory.Span[..ScalarSize];
        profile.CopyWorkingOne(one);

        //The round-polynomial evaluation points {0, 1, t}: point 0 = zero, point 1 = one, point 2 = the
        //field's poly_evaluation_point(2) (g for GF(2^128), 2 for Fp256), carried by the profile.
        using IMemoryOwner<byte> evalPointsOwner = pool.Rent(RoundPolynomialPoints * ScalarSize);
        Span<byte> evalPoints = evalPointsOwner.Memory.Span[..(RoundPolynomialPoints * ScalarSize)];
        evalPoints.Clear();
        one.CopyTo(evalPoints.Slice(ScalarSize, ScalarSize));
        profile.CopyThirdEvaluationPoint(evalPoints.Slice(2 * ScalarSize, ScalarSize));

        //Estimate capacities: one constraint per layer plus the input constraint; the term count is
        //bounded by the total pad layout size plus the input bindings, but a List grows as needed.
        ConstraintSystem? system = new(pool, circuit.LayerCount + 1, (circuit.LayerCount * 8) + circuit.InputCount + 2);
        try
        {
            //begin_circuit: squeeze Q (kMaxBindings) then G (kMaxBindings). Q and G are kept for the final
            //input binding's g-point and the per-layer claim's q-point (the eqv/Eq::eval input).
            using IMemoryOwner<byte> qOwner = pool.Rent(MaxBindings * ScalarSize);
            using IMemoryOwner<byte> gOwner = pool.Rent(MaxBindings * ScalarSize);
            Span<byte> q = qOwner.Memory.Span[..(MaxBindings * ScalarSize)];
            Span<byte> g = gOwner.Memory.Span[..(MaxBindings * ScalarSize)];

            for(int i = 0; i < MaxBindings; i++)
            {
                transcript.SqueezeFieldElement(profile, q.Slice(i * ScalarSize, ScalarSize));
            }

            for(int i = 0; i < MaxBindings; i++)
            {
                transcript.SqueezeFieldElement(profile, g.Slice(i * ScalarSize, ScalarSize));
            }

            WalkLayers(circuit, proof, publicInputs, q, g, firstPadIndex, profile, elementBytes, transcript, add, subtract, multiply, invert, curve, evalPoints, one, pool, system, bindQuadReduce, broadcastMultiplyAccumulate, fp256BatchMultiply);

            ConstraintSystem built = system;
            system = null;

            return built;
        }
        finally
        {
            //On any failure path the partially built system is still owned here and must be released; on
            //success it was handed to the caller and nulled above.
            system?.Dispose();
        }
    }


    //The per-layer claim state mimicking the reference's Claims struct: the two outgoing claims, the
    //g-points (g[0], g[1]) and the q-point of the claim, plus logv (the binding count of the claim).
    private ref struct ClaimState
    {
        public int OutputLogCount;
        public Span<byte> Claim0;
        public Span<byte> Claim1;
        public Span<byte> Q;
        public Span<byte> G0;
        public Span<byte> G1;
    }


    private static void WalkLayers(
        LongfellowSumcheckCircuit circuit,
        LongfellowSumcheckProof proof,
        ReadOnlySpan<byte> publicInputs,
        Span<byte> circuitQ,
        Span<byte> circuitG,
        int firstPadIndex,
        LongfellowFieldProfile profile,
        int elementBytes,
        LongfellowTranscript transcript,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        ReadOnlySpan<byte> evalPoints,
        ReadOnlySpan<byte> one,
        BaseMemoryPool pool,
        ConstraintSystem system,
        ScalarBindQuadReduceDelegate? bindQuadReduce = null,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null,
        ScalarBatchMultiplyDelegate? fp256BatchMultiply = null)
    {
        //The claim state buffers: claim0, claim1, q (logc entries used), g0/g1 (logv entries used).
        using IMemoryOwner<byte> stateOwner = pool.Rent((2 + (3 * MaxBindings)) * ScalarSize);
        Span<byte> stateSpan = stateOwner.Memory.Span[..((2 + (3 * MaxBindings)) * ScalarSize)];
        stateSpan.Clear();

        var claim = new ClaimState
        {
            OutputLogCount = circuit.OutputLogCount,
            Claim0 = stateSpan[..ScalarSize],
            Claim1 = stateSpan.Slice(ScalarSize, ScalarSize),
            Q = stateSpan.Slice(2 * ScalarSize, MaxBindings * ScalarSize),
            G0 = stateSpan.Slice((2 + MaxBindings) * ScalarSize, MaxBindings * ScalarSize),
            G1 = stateSpan.Slice((2 + (2 * MaxBindings)) * ScalarSize, MaxBindings * ScalarSize),
        };

        //Initial claim: (0, 0); q = circuit Q; g[0] = g[1] = circuit G.
        circuitQ.CopyTo(claim.Q);
        circuitG.CopyTo(claim.G0);
        circuitG.CopyTo(claim.G1);

        Span<byte> alpha = stackalloc byte[ScalarSize];
        Span<byte> beta = stackalloc byte[ScalarSize];
        Span<byte> squeezedBuffer = stackalloc byte[ScalarSize];
        Span<byte> squeezed = squeezedBuffer[..elementBytes];

        //Per-layer hand challenges (hb[hand][round]); logw rounds, two hands.
        using IMemoryOwner<byte> handOwner = pool.Rent(2 * MaxBindings * ScalarSize);
        Span<byte> handChallenges = handOwner.Memory.Span[..(2 * MaxBindings * ScalarSize)];

        int constraintIndex = 0;
        int padIndex = firstPadIndex;

        //Per-layer scratch, hoisted out of the loop (the round polynomial buffer, the Lagrange weights,
        //the bind/eqv/eqq scalars, the claim pair and the wc-absorb framing).
        Span<byte> polyBuffer = stackalloc byte[RoundPolynomialPoints * ScalarSize];
        Span<byte> lag = stackalloc byte[RoundPolynomialPoints * ScalarSize];
        Span<byte> bindQuad = stackalloc byte[ScalarSize];
        Span<byte> eqv = stackalloc byte[ScalarSize];
        Span<byte> eqq = stackalloc byte[ScalarSize];
        Span<byte> claimPair = stackalloc byte[2 * ScalarSize];
        Span<byte> wcBytesBuffer = stackalloc byte[2 * ScalarSize];
        Span<byte> wcBytes = wcBytesBuffer[..(2 * elementBytes)];

        for(int layer = 0; layer < circuit.LayerCount; layer++)
        {
            LongfellowSumcheckLayer layerShape = circuit.Layers[layer];
            if(layerShape.QuadTerms.Length == 0)
            {
                throw new ArgumentException($"Layer {layer} carries no quad terms; the ZK constraint composition needs them.", nameof(circuit));
            }

            int handRounds = layerShape.HandRounds;

            //begin_layer: squeeze alpha then beta.
            transcript.SqueezeFieldElement(profile, alpha);
            transcript.SqueezeFieldElement(profile, beta);

            var pad = new LongfellowZkPadLayout(handRounds);
            using var builder = new LongfellowZkConstraintExpression(pad, add, subtract, multiply, curve, one, pool);

            //first(alpha, claim): expr = claim_{-1} = cl0 + alpha*cl1.
            claim.Claim0.CopyTo(claimPair[..ScalarSize]);
            claim.Claim1.CopyTo(claimPair[ScalarSize..]);
            builder.First(alpha, claimPair);

            //The hand-round walk: per round per hand absorb the two transmitted points, squeeze the
            //challenge, and fold the symbolic claim through next().
            for(int round = 0; round < handRounds; round++)
            {
                for(int hand = 0; hand < HandCount; hand++)
                {
                    int r = (2 * round) + hand;

                    ReadOnlySpan<byte> p0 = proof.RoundPolynomialPoint(layer, hand, round, 0);
                    ReadOnlySpan<byte> p2 = proof.RoundPolynomialPoint(layer, hand, round, 2);

                    //round(): absorb (p(0), p(2)) [skip p(1)] through the profile's to_bytes_field so the
                    //wire (canonical) bytes are absorbed — the same bytes the prover absorbed — not the raw
                    //working-domain residues; squeeze the hand challenge.
                    profile.ToBytesField(p0, squeezed);
                    transcript.AbsorbFieldElement(squeezed, elementBytes);
                    profile.ToBytesField(p2, squeezed);
                    transcript.AbsorbFieldElement(squeezed, elementBytes);

                    Span<byte> challenge = handChallenges.Slice(((hand * MaxBindings) + round) * ScalarSize, ScalarSize);
                    transcript.SqueezeFieldElement(profile, challenge);

                    //dot_wpoly.coef(challenge): the Lagrange weights at the challenge point.
                    LagrangeWeights(challenge, evalPoints, one, subtract, multiply, invert, curve, lag);

                    //next(r, lag, hp.t_): hp.t_ holds (p(0), p(1)=0 on the wire, p(2)); next reconstructs
                    //the symbolic claim. Only points 0 and 2 are transmitted; t_[1] is the zero placeholder.
                    p0.CopyTo(polyBuffer[..ScalarSize]);
                    polyBuffer.Slice(ScalarSize, ScalarSize).Clear();
                    p2.CopyTo(polyBuffer.Slice(2 * ScalarSize, ScalarSize));
                    builder.Next(r, lag, polyBuffer);
                }
            }

            //bind_quad and eqv; eqq = eqv * bind_quad. Eval's second argument is the reference's
            //challenge->cb (the copy point of the hand challenges); with logc == 0 asserted the loop
            //body never runs and the result is one regardless, so the entering Q stands in — a copy
            //binding (logc > 0) must pass the genuine cb here.
            BindQuad(layerShape, claim.OutputLogCount, claim.G0, claim.G1, alpha, beta, handRounds, handChallenges, add, subtract, multiply, curve, one, pool, bindQuad, bindQuadReduce, broadcastMultiplyAccumulate, fp256BatchMultiply);
            LongfellowEq.Eval(circuit.CopyRounds, circuit.CopyCount, claim.Q, claim.Q, add, subtract, multiply, curve, one, eqv);
            multiply(eqv, bindQuad, eqq, curve);

            //finalize(wc, eqq, ci, ly, pi): emit the layer constraint.
            ReadOnlySpan<byte> wc0 = proof.Claim(layer, 0);
            ReadOnlySpan<byte> wc1 = proof.Claim(layer, 1);
            builder.Finalize(wc0, wc1, eqq, layer, padIndex, system, constraintIndex);
            constraintIndex++;

            //write(wc[0..2]): absorb the two claims through the profile's to_bytes_field (wire bytes, not raw
            //working-domain residues) as the next layer's pair.
            profile.ToBytesField(wc0, wcBytes[..elementBytes]);
            profile.ToBytesField(wc1, wcBytes.Slice(elementBytes, elementBytes));
            transcript.AbsorbFieldElementArray(wcBytes, 2, elementBytes);

            //Advance the claim state: claim = (wc0, wc1); q = cb (the hand challenges' copy point —
            //here logc == 0 so cb is unused and stays whatever; the reference uses challenge->cb which
            //is empty for logc == 0); g[0] = hb[0], g[1] = hb[1]; logv = logw.
            wc0.CopyTo(claim.Claim0);
            wc1.CopyTo(claim.Claim1);
            handChallenges[..(MaxBindings * ScalarSize)].CopyTo(claim.G0);
            handChallenges.Slice(MaxBindings * ScalarSize, MaxBindings * ScalarSize).CopyTo(claim.G1);
            claim.OutputLogCount = handRounds;

            //pi += pl.layer_size().
            padIndex += pad.LayerSize;
        }

        //input_constraint: the input binding. The challenge alpha = tsv.elt(F) after the last wc.
        InputConstraint(circuit, proof, publicInputs, claim, padIndex, profile, elementBytes, transcript, add, subtract, multiply, curve, one, pool, system, constraintIndex, broadcastMultiplyAccumulate);
        system.ConstraintCount = constraintIndex + 1;
    }


    //binding(inputs, R) = binding(pub, R_p) + binding(witness, R_w). Compute the public binding
    //explicitly, then add the constraint binding(witness, R_w) = got - pub_binding. The reference's
    //input_constraint. The public inputs enter b through the public binding fold-out.
    private static void InputConstraint(
        LongfellowSumcheckCircuit circuit,
        LongfellowSumcheckProof proof,
        ReadOnlySpan<byte> publicInputs,
        ClaimState claim,
        int padIndex,
        LongfellowFieldProfile profile,
        int elementBytes,
        LongfellowTranscript transcript,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        ReadOnlySpan<byte> one,
        BaseMemoryPool pool,
        ConstraintSystem system,
        int constraintIndex,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null)
    {
        int numInputs = circuit.InputCount;
        int pubInputs = circuit.PublicInputCount;
        int logv = claim.OutputLogCount;

        //alpha = tsv.elt(F): the input-binding challenge squeezed after the last wc, via the sample loop.
        Span<byte> alpha = stackalloc byte[ScalarSize];
        transcript.SqueezeFieldElement(profile, alpha);

        //got = wc[0] + alpha*wc[1] of the last layer.
        ReadOnlySpan<byte> lastWc0 = proof.Claim(circuit.LayerCount - 1, 0);
        ReadOnlySpan<byte> lastWc1 = proof.Claim(circuit.LayerCount - 1, 1);
        Span<byte> got = stackalloc byte[ScalarSize];
        multiply(alpha, lastWc1, got, curve);
        AddInPlace(got, lastWc0, add, curve);

        //eq0 = Eqs(logv, num_inputs, g[0]); eq1 = Eqs(logv, num_inputs, g[1]). Fill both arrays. The shared
        //product scratch (ceil(num_inputs/2) scalars, the bound on every level's iStart) routes the GF
        //per-level scalar-times-vector through the broadcast primitive; one rental serves both fills.
        using IMemoryOwner<byte> eq0Owner = pool.Rent(numInputs * ScalarSize);
        using IMemoryOwner<byte> eq1Owner = pool.Rent(numInputs * ScalarSize);
        Span<byte> eq0 = eq0Owner.Memory.Span[..(numInputs * ScalarSize)];
        Span<byte> eq1 = eq1Owner.Memory.Span[..(numInputs * ScalarSize)];
        int productScratchScalars = (numInputs + 1) / 2;
        using IMemoryOwner<byte> productScratchOwner = pool.Rent(Math.Max(productScratchScalars, 1) * ScalarSize);
        Span<byte> productScratch = productScratchOwner.Memory.Span[..(Math.Max(productScratchScalars, 1) * ScalarSize)];
        LongfellowEq.FillEq(logv, numInputs, claim.G0, subtract, multiply, curve, one, eq0, broadcastMultiplyAccumulate, productScratch);
        LongfellowEq.FillEq(logv, numInputs, claim.G1, subtract, multiply, curve, one, eq1, broadcastMultiplyAccumulate, productScratch);

        //pub_binding = Σ_{i<pub_inputs} (eq0[i] + alpha*eq1[i]) * pub[i]; the private inputs become A terms.
        Span<byte> pubBinding = stackalloc byte[ScalarSize];
        pubBinding.Clear();
        Span<byte> bi = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];

        //The public input column: the first pub_inputs elements read through the profile's of_bytes_field —
        //LE wire bytes reversed to canonical, then lifted into the working domain (identity for GF / the
        //canonical Fp profile, to_montgomery for the Montgomery Fp profile). The public inputs are
        //working-domain values the input-binding multiplies against the working-domain b_i, so they MUST cross
        //the profile seam, not bypass it as raw canonical bytes (Perf Increment 1: the public-input boundary).
        using IMemoryOwner<byte> pubScalarsOwner = pool.Rent(Math.Max(numInputs, 1) * ScalarSize);
        Span<byte> pubScalars = pubScalarsOwner.Memory.Span[..(numInputs * ScalarSize)];
        pubScalars.Clear();
        for(int i = 0; i < pubInputs; i++)
        {
            profile.TryFromBytesField(publicInputs.Slice(i * elementBytes, elementBytes), pubScalars.Slice(i * ScalarSize, ScalarSize));
        }

        for(int i = 0; i < numInputs; i++)
        {
            //b_i = eq0[i] + alpha*eq1[i].
            multiply(alpha, ScalarAt(eq1, i), bi, curve);
            AddInPlace(bi, ScalarAt(eq0, i), add, curve);

            if(i < pubInputs)
            {
                //pub_binding += b_i * pub[i].
                multiply(bi, ScalarAt(pubScalars, i), term, curve);
                AddInPlace(pubBinding, term, add, curve);
            }
            else
            {
                //A term: constraint ci selects private witness (i - pub_inputs) with coefficient b_i.
                system.AddTerm(constraintIndex, i - pubInputs, bi);
            }
        }

        //The fake-layer claim_pad_m1: pi - ovp_poly_pad(0,0). PadLayout(0).ovp_poly_pad(0,0) = 3.
        int claimPadM1 = padIndex - LongfellowZkPadLayout.OverlapPolyPad(0, 0);

        //A: -1 * dWC[0], -alpha * dWC[1] — the genuine field negations (over GF(2) -1 = 1 and -alpha =
        //alpha, over Fp256 they are 0 - 1 and 0 - alpha). Negation is 0 - x through the subtract delegate;
        //the one is the working-domain multiplicative one threaded from the profile.
        Span<byte> zero = stackalloc byte[ScalarSize];
        zero.Clear();
        Span<byte> minusOne = stackalloc byte[ScalarSize];
        subtract(zero, one, minusOne, curve);
        Span<byte> minusAlpha = stackalloc byte[ScalarSize];
        subtract(zero, alpha, minusAlpha, curve);
        system.AddTerm(constraintIndex, claimPadM1 + 0, minusOne);
        system.AddTerm(constraintIndex, claimPadM1 + 1, minusAlpha);

        //b = got - pub_binding.
        Span<byte> rhs = stackalloc byte[ScalarSize];
        subtract(got, pubBinding, rhs, curve);
        system.AddTarget(rhs);
    }


    //Below this term count the parallel partition's overhead (task dispatch, the partials rental and
    //the deterministic combine) outweighs the win, so the sequential path runs. The real hash circuit's
    //layers carry millions of terms; small layers stay sequential.
    private const int ParallelTermThreshold = 4096;


    //bind_quad: Quad::bind_gh_all over the layer's terms. Computes
    //   Σ_term prep_v(v, eqg[g], beta) * eqh0[h0] * eqh1[h1]
    //where eqg[i] = EQ(G0, i) + alpha*EQ(G1, i) (raw_eq2), eqh0[i] = EQ(H0, i), eqh1[i] = EQ(H1, i),
    //and prep_v(v, dot, beta) = (v == 0 ? beta : v) * dot. Field add is associative, commutative and
    //exact (GF(2^128) XOR; Fp256 modular add), so the term sum partitions into P chunks summed into
    //their own scratch, then the P partials combine in a fixed partition-index order — byte-identical
    //to the sequential sum. The eq tables fill once before the loop and stay read-only across the
    //partitions; the only per-partition mutable state is its own stack scratch and its own partials slot.
    //Exposed internal (not private) so the Fp256-batch-vs-scalar agreement gate can drive the reduction
    //directly with a synthetic layer + eq inputs, the LongfellowEqFillEqBatchTests pattern.
    internal static void BindQuad(
        LongfellowSumcheckLayer layer,
        int logv,
        ReadOnlySpan<byte> g0,
        ReadOnlySpan<byte> g1,
        ReadOnlySpan<byte> alpha,
        ReadOnlySpan<byte> beta,
        int logw,
        ReadOnlySpan<byte> handChallenges,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        ReadOnlySpan<byte> one,
        BaseMemoryPool pool,
        Span<byte> result,
        ScalarBindQuadReduceDelegate? bindQuadReduce = null,
        ScalarBroadcastMultiplyAccumulateDelegate? broadcastMultiplyAccumulate = null,
        ScalarBatchMultiplyDelegate? fp256BatchMultiply = null)
    {
        int nv = 1 << logv;
        int nw = 1 << logw;

        //One pooled scratch carries the three eq tables: eqg (nv), then eqh0 and eqh1 (nw each).
        using IMemoryOwner<byte> tablesOwner = pool.Rent((nv + (2 * nw)) * ScalarSize);
        Memory<byte> tablesMemory = tablesOwner.Memory[..((nv + (2 * nw)) * ScalarSize)];
        Span<byte> tables = tablesMemory.Span;

        //eqg[i] = EQ(G0, i) + alpha*EQ(G1, i), the de-recursed raw_eq2: two iterative FillEq fills + an
        //alpha-weighted combine. The batched GF path needs a tmp row (nv) plus FillEq's per-level product
        //scratch (ceil(nv/2)); the scalar fallback needs only the tmp row.
        Span<byte> eqg = tables[..(nv * ScalarSize)];
        int rawEq2ScratchScalars = broadcastMultiplyAccumulate is not null && curve == CurveParameterSet.None ? nv + ((nv + 1) / 2) : nv;
        using(IMemoryOwner<byte> rawEq2ScratchOwner = pool.Rent(rawEq2ScratchScalars * ScalarSize))
        {
            LongfellowEq.RawEq2(logv, nv, g0, g1, alpha, add, subtract, multiply, curve, one, eqg, broadcastMultiplyAccumulate, rawEq2ScratchOwner.Memory.Span[..(rawEq2ScratchScalars * ScalarSize)]);
        }

        //eqh0[i] = EQ(H0, i), eqh1[i] = EQ(H1, i) over the two hand challenges. The shared product scratch
        //(ceil(nw/2) scalars, the bound on every level's iStart) routes the GF per-level scalar-times-vector
        //through the broadcast primitive; one rental serves both fills.
        ReadOnlySpan<byte> h0 = handChallenges[..(MaxBindings * ScalarSize)];
        ReadOnlySpan<byte> h1 = handChallenges.Slice(MaxBindings * ScalarSize, MaxBindings * ScalarSize);
        Span<byte> eqh0 = tables.Slice(nv * ScalarSize, nw * ScalarSize);
        Span<byte> eqh1 = tables.Slice((nv + nw) * ScalarSize, nw * ScalarSize);
        int productScratchScalars = (nw + 1) / 2;
        using IMemoryOwner<byte> productScratchOwner = pool.Rent(Math.Max(productScratchScalars, 1) * ScalarSize);
        Span<byte> productScratch = productScratchOwner.Memory.Span[..(Math.Max(productScratchScalars, 1) * ScalarSize)];
        LongfellowEq.FillEq(logw, nw, h0, subtract, multiply, curve, one, eqh0, broadcastMultiplyAccumulate, productScratch);
        LongfellowEq.FillEq(logw, nw, h1, subtract, multiply, curve, one, eqh1, broadcastMultiplyAccumulate, productScratch);

        LongfellowSumcheckQuadTerm[] terms = layer.QuadTerms;
        int termCount = terms.Length;

        //The v == 0 decision per term, precomputed once. The terms reference the circuit's constant
        //table by position, so the same backing byte[] recurs across many terms (the C.10 reader's
        //first-encounter indexing); the 32-byte compare runs once per distinct coefficient object, not
        //per term, and the per-term inner loop reads the cached bool. This does not change which terms
        //are treated as zero.
        bool[] termIsZero = ComputeTermZeroFlags(terms);

        //The fused GF(2^128) path: route the per-term chained reduction through the injected primitive.
        //Built once per layer, the structure-of-arrays mirrors ReduceRange exactly — same scaled-v select,
        //same eqg/eqh0/eqh1 chain, same XOR accumulation — so the result is byte-identical to the scalar
        //fallback while collapsing three delegate calls per term into one primitive call per partition.
        if(bindQuadReduce is not null && curve == CurveParameterSet.None)
        {
            BindQuadFused(terms, termCount, termIsZero, tablesMemory, nv, nw, beta, bindQuadReduce, add, curve, pool, result);

            return;
        }

        //The Fp256 batched path: route the per-term three-multiply chain through the lane-parallel batch
        //multiply. Gathers each term's index-addressed operands into chunked contiguous scratch, runs three
        //batched multiply passes (scaledV·eqg, ·eqh0, ·eqh1) and field-add accumulates — byte-identical to the
        //scalar ReduceRange below (each batch multiply element equals the scalar MultiplyMontgomery, and the
        //field add is exact, associative and commutative so the same term order yields the same residue). The
        //batch multiply is supplied ONLY by the Fp256 sig bundle; the GF hash bundle supplies bindQuadReduce
        //instead, so the two are mutually exclusive (both bundles pass curve == None).
        if(fp256BatchMultiply is not null && curve == CurveParameterSet.None)
        {
            BindQuadFp256Batch(terms, termCount, termIsZero, tablesMemory, nv, nw, beta, fp256BatchMultiply, add, curve, pool, result);

            return;
        }

        if(termCount < ParallelTermThreshold || Environment.ProcessorCount < 2)
        {
            //Sequential path: the existing reduction, now reading the precomputed zero flags.
            Span<byte> accumulator = stackalloc byte[ScalarSize];
            accumulator.Clear();
            ReduceRange(terms, termIsZero, 0, termCount, eqg, eqh0, eqh1, beta, add, multiply, curve, accumulator);
            accumulator.CopyTo(result);

            return;
        }

        //Parallel path: partition [0, termCount) into P contiguous chunks, each reduced into its own
        //partials slot, then combine the P partials in partition-index order with the field add.
        int partitionCount = Math.Min(Environment.ProcessorCount, termCount);

        //beta lands in a stable buffer so the partition workers (which take spans from Memory, not the
        //ref-struct span parameters) can read it; the eq tables are read from tablesMemory directly.
        using IMemoryOwner<byte> partialsOwner = pool.Rent(((partitionCount + 1) * ScalarSize));
        Memory<byte> partialsMemory = partialsOwner.Memory[..((partitionCount + 1) * ScalarSize)];
        partialsMemory.Span.Clear();
        Memory<byte> betaMemory = partialsMemory.Slice(partitionCount * ScalarSize, ScalarSize);
        beta.CopyTo(betaMemory.Span);

        int nvBytes = nv * ScalarSize;
        int nwBytes = nw * ScalarSize;

        Parallel.For(0, partitionCount, new ParallelOptions { MaxDegreeOfParallelism = partitionCount }, partition =>
        {
            int start = (int)((long)partition * termCount / partitionCount);
            int end = (int)((long)(partition + 1) * termCount / partitionCount);

            //Each worker takes read-only views of the shared tables and writes ONLY its own slot.
            ReadOnlySpan<byte> wEqg = tablesMemory.Span[..nvBytes];
            ReadOnlySpan<byte> wEqh0 = tablesMemory.Span.Slice(nvBytes, nwBytes);
            ReadOnlySpan<byte> wEqh1 = tablesMemory.Span.Slice(nvBytes + nwBytes, nwBytes);
            ReadOnlySpan<byte> wBeta = betaMemory.Span;

            Span<byte> partial = stackalloc byte[ScalarSize];
            partial.Clear();
            ReduceRange(terms, termIsZero, start, end, wEqg, wEqh0, wEqh1, wBeta, add, multiply, curve, partial);
            partial.CopyTo(partialsMemory.Span.Slice(partition * ScalarSize, ScalarSize));
        });

        //Combine the partials in partition-index order: a fixed order keeps the bytes reproducible
        //run-to-run (the field add is associative + commutative, so this also equals the sequential sum).
        Span<byte> combined = stackalloc byte[ScalarSize];
        combined.Clear();
        ReadOnlySpan<byte> partialsSpan = partialsMemory.Span;
        for(int partition = 0; partition < partitionCount; partition++)
        {
            AddInPlace(combined, partialsSpan.Slice(partition * ScalarSize, ScalarSize), add, curve);
        }

        combined.CopyTo(result);
    }


    //The fused bind_quad reduction: build the structure-of-arrays once (the per-term gate/left/right
    //indices, a deduped coefficient table + per-term indices, and the term-zero flags reinterpreted as
    //bytes), then drive the injected primitive over it. The same threshold and partition arithmetic as
    //the scalar path: small layers run one un-partitioned call; large layers partition [0, termCount)
    //into P contiguous chunks, each primitive call accumulating into its own partials slot, and the
    //partials combine in partition-index order — byte-identical to the sequential reduction. The SoA and
    //the eq tables ride in pooled Memory (never .Shared), read-only across the partitions; each worker
    //reconstructs its read-only views from the captured Memory handles (the ref-struct spans cannot cross
    //the lambda boundary) and writes ONLY its own partials slot.
    private static void BindQuadFused(
        LongfellowSumcheckQuadTerm[] terms,
        int termCount,
        bool[] termIsZero,
        Memory<byte> tablesMemory,
        int nv,
        int nw,
        ReadOnlySpan<byte> beta,
        ScalarBindQuadReduceDelegate bindQuadReduce,
        ScalarAddDelegate add,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Span<byte> result)
    {
        int nvBytes = nv * ScalarSize;
        int nwBytes = nw * ScalarSize;

        //The index arrays ride in pooled byte memory reinterpreted as int, so they never touch .Shared
        //and are cleared on disposal. Four contiguous int spans of length termCount: gate, left, right,
        //coefficient.
        int indexCount = Math.Max(termCount, 1) * 4;
        using IMemoryOwner<byte> indexOwner = pool.Rent(indexCount * sizeof(int));
        Memory<byte> indexMemory = indexOwner.Memory[..(indexCount * sizeof(int))];

        //No pre-clear: the loop below writes every gate/left/right/coefficient slot the primitive reads,
        //and the pool zeroes the buffer on return — a memset here is pure dead work (tens of MB on the
        //dominant layers).
        Span<int> indexSpan = System.Runtime.InteropServices.MemoryMarshal.Cast<byte, int>(indexMemory.Span)[..indexCount];
        Span<int> gateIndices = indexSpan.Slice(0, termCount);
        Span<int> leftIndices = indexSpan.Slice(termCount, termCount);
        Span<int> rightIndices = indexSpan.Slice(2 * termCount, termCount);
        Span<int> coefficientIndices = indexSpan.Slice(3 * termCount, termCount);

        //The deduped coefficient table: the first-encounter index per distinct backing byte[] exactly the
        //way ComputeTermZeroFlags memoises the zero flags; a non-array-backed coefficient appends a private
        //copy. Sized at termCount slots (the all-distinct worst case); the fill count is the distinct count.
        using IMemoryOwner<byte> coefficientOwner = pool.Rent(Math.Max(termCount, 1) * ScalarSize);
        Memory<byte> coefficientMemory = coefficientOwner.Memory[..(Math.Max(termCount, 1) * ScalarSize)];
        Span<byte> coefficientTable = coefficientMemory.Span;

        //No pre-clear: each distinct coefficient slot is written on first encounter before any term's
        //coefficient index points at it, and the pool zeroes the buffer on return.
        var coefficientSlots = new Dictionary<byte[], int>(ReferenceEqualityComparer.Instance);
        int distinctCount = 0;

        for(int k = 0; k < termCount; k++)
        {
            LongfellowSumcheckQuadTerm term = terms[k];
            gateIndices[k] = term.GateIndex;
            leftIndices[k] = term.LeftIndex;
            rightIndices[k] = term.RightIndex;

            ReadOnlyMemory<byte> coefficient = term.Coefficient;
            int slot;
            if(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(coefficient, out ArraySegment<byte> segment) && segment.Array is byte[] backing && segment.Offset == 0 && segment.Count == backing.Length)
            {
                if(!coefficientSlots.TryGetValue(backing, out slot))
                {
                    slot = distinctCount++;
                    coefficientSlots[backing] = slot;
                    coefficient.Span.CopyTo(coefficientTable.Slice(slot * ScalarSize, ScalarSize));
                }
            }
            else
            {
                slot = distinctCount++;
                coefficient.Span.CopyTo(coefficientTable.Slice(slot * ScalarSize, ScalarSize));
            }

            coefficientIndices[k] = slot;
        }

        //beta lands in a stable buffer the partition workers can read from a Memory handle; the eq tables
        //and the SoA are read from their pooled Memory directly.
        using IMemoryOwner<byte> betaOwner = pool.Rent(ScalarSize);
        Memory<byte> betaMemory = betaOwner.Memory[..ScalarSize];
        beta.CopyTo(betaMemory.Span);

        //isZeroFlags reuses the existing termIsZero bool[] (one byte per term) with no repack.
        ReadOnlySpan<byte> isZeroFlags = System.Runtime.InteropServices.MemoryMarshal.AsBytes<bool>(termIsZero);

        if(termCount < ParallelTermThreshold || Environment.ProcessorCount < 2)
        {
            //Sequential path: one un-partitioned primitive call into a caller-cleared accumulator.
            ReadOnlySpan<byte> eqg = tablesMemory.Span[..nvBytes];
            ReadOnlySpan<byte> eqh0 = tablesMemory.Span.Slice(nvBytes, nwBytes);
            ReadOnlySpan<byte> eqh1 = tablesMemory.Span.Slice(nvBytes + nwBytes, nwBytes);

            Span<byte> accumulator = stackalloc byte[ScalarSize];
            accumulator.Clear();
            bindQuadReduce(coefficientTable, coefficientIndices, betaMemory.Span, eqg, eqh0, eqh1, gateIndices, leftIndices, rightIndices, isZeroFlags, termCount, accumulator, curve);
            accumulator.CopyTo(result);
            betaMemory.Span.Clear();

            return;
        }

        //Parallel path: the same partition arithmetic as the scalar route. Each partition's sub-slices of
        //the SoA feed one primitive call writing into its own partials slot; the partials combine in
        //partition-index order with the field add (byte-identical to the sequential sum).
        int partitionCount = Math.Min(Environment.ProcessorCount, termCount);

        using IMemoryOwner<byte> partialsOwner = pool.Rent(partitionCount * ScalarSize);
        Memory<byte> partialsMemory = partialsOwner.Memory[..(partitionCount * ScalarSize)];
        partialsMemory.Span.Clear();

        Parallel.For(0, partitionCount, new ParallelOptions { MaxDegreeOfParallelism = partitionCount }, partition =>
        {
            int start = (int)((long)partition * termCount / partitionCount);
            int end = (int)((long)(partition + 1) * termCount / partitionCount);
            int count = end - start;

            //Each worker reconstructs read-only views of the shared tables and SoA from the captured
            //Memory handles and writes ONLY its own slot.
            ReadOnlySpan<byte> wEqg = tablesMemory.Span[..nvBytes];
            ReadOnlySpan<byte> wEqh0 = tablesMemory.Span.Slice(nvBytes, nwBytes);
            ReadOnlySpan<byte> wEqh1 = tablesMemory.Span.Slice(nvBytes + nwBytes, nwBytes);
            ReadOnlySpan<int> wIndex = System.Runtime.InteropServices.MemoryMarshal.Cast<byte, int>(indexMemory.Span)[..indexCount];
            ReadOnlySpan<int> wGate = wIndex.Slice(start, count);
            ReadOnlySpan<int> wLeft = wIndex.Slice(termCount + start, count);
            ReadOnlySpan<int> wRight = wIndex.Slice((2 * termCount) + start, count);
            ReadOnlySpan<int> wCoefficient = wIndex.Slice((3 * termCount) + start, count);
            ReadOnlySpan<byte> wIsZero = System.Runtime.InteropServices.MemoryMarshal.AsBytes<bool>(termIsZero).Slice(start, count);

            Span<byte> partial = stackalloc byte[ScalarSize];
            partial.Clear();
            bindQuadReduce(coefficientMemory.Span, wCoefficient, betaMemory.Span, wEqg, wEqh0, wEqh1, wGate, wLeft, wRight, wIsZero, count, partial, curve);
            partial.CopyTo(partialsMemory.Span.Slice(partition * ScalarSize, ScalarSize));
        });

        Span<byte> combined = stackalloc byte[ScalarSize];
        combined.Clear();
        ReadOnlySpan<byte> partialsSpan = partialsMemory.Span;
        for(int partition = 0; partition < partitionCount; partition++)
        {
            AddInPlace(combined, partialsSpan.Slice(partition * ScalarSize, ScalarSize), add, curve);
        }

        combined.CopyTo(result);
        betaMemory.Span.Clear();
    }


    //The number of terms gathered and multiplied per batched pass. Five chunk-sized scratch buffers (the two
    //gathered operands, the two chain intermediates and the product) stay cache-resident at this width
    //(5 · 1024 · 32 bytes ≈ 160 KB). Measured: gather + batch beats the scalar three-multiply chain ~1.25–1.42×
    //per term across small-to-large eq tables (the dev-box back-to-back driver --fp256-bindquad-timing).
    private const int Fp256BatchChunk = 1024;


    //The Fp256 batched bind_quad reduction: the same Σ_term prep_v(v)·eqg[g]·eqh0[h0]·eqh1[h1] as the scalar
    //ReduceRange, but the per-term three-multiply chain runs through the lane-parallel batch multiply. The same
    //threshold and partition arithmetic as the scalar path: small layers run one un-partitioned chunked
    //reduction; large layers partition [0, termCount) into P contiguous chunks, each reduced into its own
    //partials slot, and the partials combine in partition-index order — byte-identical to the sequential sum
    //(Fp256 modular add is exact, associative and commutative). The eq tables ride in pooled Memory
    //(tablesMemory, never .Shared), read-only across the partitions; the per-partition gather scratch is
    //pre-rented ONCE outside the parallel region and sliced one block per partition (so no worker rents from
    //the pool concurrently), and each worker writes ONLY its own scratch block and its own partials slot.
    private static void BindQuadFp256Batch(
        LongfellowSumcheckQuadTerm[] terms,
        int termCount,
        bool[] termIsZero,
        Memory<byte> tablesMemory,
        int nv,
        int nw,
        ReadOnlySpan<byte> beta,
        ScalarBatchMultiplyDelegate fp256BatchMultiply,
        ScalarAddDelegate add,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        Span<byte> result)
    {
        int nvBytes = nv * ScalarSize;
        int nwBytes = nw * ScalarSize;

        //beta lands in a stable buffer the partition workers can read from a Memory handle; the eq tables ride
        //in tablesMemory directly.
        using IMemoryOwner<byte> betaOwner = pool.Rent(ScalarSize);
        Memory<byte> betaMemory = betaOwner.Memory[..ScalarSize];
        beta.CopyTo(betaMemory.Span);

        if(termCount < ParallelTermThreshold || Environment.ProcessorCount < 2)
        {
            //Sequential path: one chunked gather+batch reduction into a caller-cleared accumulator.
            int chunk = Math.Min(Fp256BatchChunk, Math.Max(termCount, 1));
            using IMemoryOwner<byte> scratchOwner = pool.Rent(5 * chunk * ScalarSize);
            Span<byte> scratch = scratchOwner.Memory.Span[..(5 * chunk * ScalarSize)];

            Span<byte> accumulator = stackalloc byte[ScalarSize];
            accumulator.Clear();
            GatherBatchReduceRange(
                terms, termIsZero, 0, termCount,
                tablesMemory.Span[..nvBytes], tablesMemory.Span.Slice(nvBytes, nwBytes), tablesMemory.Span.Slice(nvBytes + nwBytes, nwBytes),
                betaMemory.Span, chunk, scratch, fp256BatchMultiply, add, curve, accumulator);
            accumulator.CopyTo(result);

            betaMemory.Span.Clear();

            return;
        }

        //Parallel path: the same partition arithmetic as the scalar route. Each partition reduces its
        //contiguous sub-range into its own partials slot through a chunked gather+batch; the partials combine
        //in partition-index order with the field add.
        int partitionCount = Math.Min(Environment.ProcessorCount, termCount);
        int maxPartitionTerms = ((termCount + partitionCount) - 1) / partitionCount;
        int chunk2 = Math.Min(Fp256BatchChunk, Math.Max(maxPartitionTerms, 1));
        int scratchBlockBytes = 5 * chunk2 * ScalarSize;

        using IMemoryOwner<byte> partialsOwner = pool.Rent(partitionCount * ScalarSize);
        Memory<byte> partialsMemory = partialsOwner.Memory[..(partitionCount * ScalarSize)];
        partialsMemory.Span.Clear();

        using IMemoryOwner<byte> scratchOwnerParallel = pool.Rent(partitionCount * scratchBlockBytes);
        Memory<byte> scratchMemory = scratchOwnerParallel.Memory[..(partitionCount * scratchBlockBytes)];

        Parallel.For(0, partitionCount, new ParallelOptions { MaxDegreeOfParallelism = partitionCount }, partition =>
        {
            int start = (int)((long)partition * termCount / partitionCount);
            int end = (int)((long)(partition + 1) * termCount / partitionCount);

            //Each worker reconstructs read-only views of the shared tables from the captured Memory handles and
            //writes ONLY its own scratch block and its own partials slot.
            ReadOnlySpan<byte> wEqg = tablesMemory.Span[..nvBytes];
            ReadOnlySpan<byte> wEqh0 = tablesMemory.Span.Slice(nvBytes, nwBytes);
            ReadOnlySpan<byte> wEqh1 = tablesMemory.Span.Slice(nvBytes + nwBytes, nwBytes);
            Span<byte> wScratch = scratchMemory.Span.Slice(partition * scratchBlockBytes, scratchBlockBytes);

            Span<byte> partial = stackalloc byte[ScalarSize];
            partial.Clear();
            GatherBatchReduceRange(terms, termIsZero, start, end, wEqg, wEqh0, wEqh1, betaMemory.Span, chunk2, wScratch, fp256BatchMultiply, add, curve, partial);
            partial.CopyTo(partialsMemory.Span.Slice(partition * ScalarSize, ScalarSize));
        });

        Span<byte> combined = stackalloc byte[ScalarSize];
        combined.Clear();
        ReadOnlySpan<byte> partialsSpan = partialsMemory.Span;
        for(int partition = 0; partition < partitionCount; partition++)
        {
            AddInPlace(combined, partialsSpan.Slice(partition * ScalarSize, ScalarSize), add, curve);
        }

        combined.CopyTo(result);

        betaMemory.Span.Clear();
    }


    //One partition's chunked gather+batch reduction: for each chunk of up to `chunk` terms, gather the
    //index-addressed operands into the contiguous scratch (left = v_k or beta, right = eqg[g_k]), batch-multiply
    //into qv, gather eqh0[h0_k] and batch-multiply into term, gather eqh1[h1_k] and batch-multiply into prod,
    //then field-add accumulate prod[j] in term order. Byte-identical to ReduceRange: each batch multiply element
    //equals the scalar MultiplyMontgomery, and the accumulate order (chunks in order, terms in order within a
    //chunk) matches ReduceRange's per-term accumulate over the same [start, end). `scratch` is five chunk-sized
    //blocks (left, right, qv, term, prod) laid out contiguously.
    private static void GatherBatchReduceRange(
        LongfellowSumcheckQuadTerm[] terms,
        bool[] termIsZero,
        int start,
        int end,
        ReadOnlySpan<byte> eqg,
        ReadOnlySpan<byte> eqh0,
        ReadOnlySpan<byte> eqh1,
        ReadOnlySpan<byte> beta,
        int chunk,
        Span<byte> scratch,
        ScalarBatchMultiplyDelegate batchMultiply,
        ScalarAddDelegate add,
        CurveParameterSet curve,
        Span<byte> accumulator)
    {
        int chunkBytes = chunk * ScalarSize;
        Span<byte> left = scratch[..chunkBytes];
        Span<byte> right = scratch.Slice(chunkBytes, chunkBytes);
        Span<byte> qv = scratch.Slice(2 * chunkBytes, chunkBytes);
        Span<byte> term = scratch.Slice(3 * chunkBytes, chunkBytes);
        Span<byte> prod = scratch.Slice(4 * chunkBytes, chunkBytes);

        Span<byte> sum = stackalloc byte[ScalarSize];

        for(int baseIndex = start; baseIndex < end; baseIndex += chunk)
        {
            int n = Math.Min(chunk, end - baseIndex);
            int nBytes = n * ScalarSize;

            //Pass 1: left = (v == 0 ? beta : v), right = eqg[g].
            for(int j = 0; j < n; j++)
            {
                int k = baseIndex + j;
                LongfellowSumcheckQuadTerm quadTerm = terms[k];
                ReadOnlySpan<byte> scaledV = termIsZero[k] ? beta : quadTerm.Coefficient.Span;
                scaledV.CopyTo(left.Slice(j * ScalarSize, ScalarSize));
                eqg.Slice(quadTerm.GateIndex * ScalarSize, ScalarSize).CopyTo(right.Slice(j * ScalarSize, ScalarSize));
            }

            batchMultiply(left[..nBytes], right[..nBytes], qv[..nBytes], n, curve);

            //Pass 2: right = eqh0[h0], left = qv.
            for(int j = 0; j < n; j++)
            {
                eqh0.Slice(terms[baseIndex + j].LeftIndex * ScalarSize, ScalarSize).CopyTo(right.Slice(j * ScalarSize, ScalarSize));
            }

            batchMultiply(qv[..nBytes], right[..nBytes], term[..nBytes], n, curve);

            //Pass 3: right = eqh1[h1], left = term.
            for(int j = 0; j < n; j++)
            {
                eqh1.Slice(terms[baseIndex + j].RightIndex * ScalarSize, ScalarSize).CopyTo(right.Slice(j * ScalarSize, ScalarSize));
            }

            batchMultiply(term[..nBytes], right[..nBytes], prod[..nBytes], n, curve);

            //Field-add accumulate in term order (matches ReduceRange's per-term accumulate).
            for(int j = 0; j < n; j++)
            {
                add(accumulator, prod.Slice(j * ScalarSize, ScalarSize), sum, curve);
                sum.CopyTo(accumulator);
            }
        }
    }


    //One partition's reduction: Σ_{k in [start, end)} prep_v(v_k) * eqg[g_k] * eqh0[h0_k] * eqh1[h1_k],
    //accumulated into `accumulator` (caller-cleared). prep_v(v) = (v == 0 ? beta : v) * eqg[g]; the
    //v == 0 decision is the precomputed `termIsZero[k]`. The eq tables and the term array are read-only.
    private static void ReduceRange(
        LongfellowSumcheckQuadTerm[] terms,
        bool[] termIsZero,
        int start,
        int end,
        ReadOnlySpan<byte> eqg,
        ReadOnlySpan<byte> eqh0,
        ReadOnlySpan<byte> eqh1,
        ReadOnlySpan<byte> beta,
        ScalarAddDelegate add,
        ScalarMultiplyDelegate multiply,
        CurveParameterSet curve,
        Span<byte> accumulator)
    {
        Span<byte> qv = stackalloc byte[ScalarSize];
        Span<byte> term = stackalloc byte[ScalarSize];
        Span<byte> sum = stackalloc byte[ScalarSize];

        for(int k = start; k < end; k++)
        {
            LongfellowSumcheckQuadTerm quadTerm = terms[k];

            //prep_v: (v == 0 ? beta : v) * eqg[g]. The byte offsets are computed directly to skip the
            //per-slice bounds revalidation; the indices are circuit-bounded by the reader.
            ReadOnlySpan<byte> scaledV = termIsZero[k] ? beta : quadTerm.Coefficient.Span;
            multiply(scaledV, eqg.Slice(quadTerm.GateIndex * ScalarSize, ScalarSize), qv, curve);

            //q *= eqh0[h0]; q *= eqh1[h1]; accumulator += q.
            multiply(qv, eqh0.Slice(quadTerm.LeftIndex * ScalarSize, ScalarSize), term, curve);
            multiply(term, eqh1.Slice(quadTerm.RightIndex * ScalarSize, ScalarSize), term, curve);

            add(accumulator, term, sum, curve);
            sum.CopyTo(accumulator);
        }
    }


    //The per-term v == 0 flags. The same constant-table byte[] backs many terms, so the 32-byte compare
    //is memoised by the coefficient's backing array identity (reference equality); a term whose coefficient
    //is not array-backed falls back to the direct span compare. Byte-identical to comparing every term.
    private static bool[] ComputeTermZeroFlags(LongfellowSumcheckQuadTerm[] terms)
    {
        bool[] flags = new bool[terms.Length];
        var cache = new Dictionary<byte[], bool>(ReferenceEqualityComparer.Instance);
        for(int k = 0; k < terms.Length; k++)
        {
            ReadOnlyMemory<byte> coefficient = terms[k].Coefficient;
            if(System.Runtime.InteropServices.MemoryMarshal.TryGetArray(coefficient, out ArraySegment<byte> segment) && segment.Array is byte[] backing && segment.Offset == 0 && segment.Count == backing.Length)
            {
                if(!cache.TryGetValue(backing, out bool isZero))
                {
                    isZero = IsAllZero(coefficient.Span);
                    cache[backing] = isZero;
                }

                flags[k] = isZero;
            }
            else
            {
                flags[k] = IsAllZero(coefficient.Span);
            }
        }

        return flags;
    }


    private static bool IsAllZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;


    //dot_wpoly.coef(x): the Lagrange weights of a degree-3 (N = 3) polynomial at point x over the
    //evaluation nodes {0, 1, t}. weight[k] = Π_{j != k} (x - X[j]) / (X[k] - X[j]). The reference's
    //Poly<3>::dot_interpolation precomputes these; here they are computed per challenge.
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

                //numerator *= (x - X[j]).
                subtract(x, xj, difference, curve);
                multiply(numerator, difference, numerator, curve);

                //denominator *= (X[k] - X[j]).
                subtract(xk, xj, difference, curve);
                multiply(denominator, difference, denominator, curve);
            }

            invert(denominator, denominator, curve);
            multiply(numerator, denominator, weights.Slice(k * ScalarSize, ScalarSize), curve);
        }
    }


    //destination += addend, via a scratch.
    private static void AddInPlace(Span<byte> destination, ReadOnlySpan<byte> addend, ScalarAddDelegate add, CurveParameterSet curve)
    {
        Span<byte> scratch = stackalloc byte[ScalarSize];
        add(destination, addend, scratch, curve);
        scratch.CopyTo(destination);
    }


    private static ReadOnlySpan<byte> ScalarAt(ReadOnlySpan<byte> buffer, int index) => buffer.Slice(index * ScalarSize, ScalarSize);
}

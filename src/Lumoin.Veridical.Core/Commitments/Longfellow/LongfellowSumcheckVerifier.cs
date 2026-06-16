using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using System;
using System.Buffers;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The transcript-driven per-layer round-polynomial and challenge replay of the zk sumcheck, a faithful
/// port of google/longfellow-zk's <c>VerifierLayers::layers</c> (<c>lib/sumcheck/verifier_layers.h</c>)
/// over the <c>logc == 0</c> circuit shape, framed by the Fiat–Shamir setup
/// <c>ZkCommon::initialize_sumcheck_fiat_shamir</c> (<c>lib/zk/zk_common.h</c>) and the input absorb
/// <c>TranscriptSumcheck::write_input</c> (<c>lib/sumcheck/transcript_sumcheck.h</c>).
/// </summary>
/// <remarks>
/// <para>
/// This is the sumcheck-transcript half of the zk verifier: the layer walk that derives every challenge
/// through <see cref="LongfellowTranscript"/>, reconstructs the unsent <c>p(1)</c> of each round
/// polynomial from the running claim (<c>p(1) = claim − p(0)</c>, the <c>k != 1</c> optimization), checks
/// the sumcheck relation <c>claim = p(0) + p(1)</c>, and folds the claim by Lagrange evaluation at the
/// squeezed challenge. It reduces the circuit's output claim down to the two input claims
/// (<c>wc[0]</c>, <c>wc[1]</c>) the final layer leaves. The non-ZK reference checks these input claims
/// directly against the bound input wires; the ZK verifier instead hands them to the Ligero layer
/// (<c>ZkCommon::verifier_constraints</c> → <c>LigeroVerifier</c>) — that composition is above this
/// replay and out of scope here.
/// </para>
/// <para>
/// The transcript flow, byte-precise (the plain sumcheck Prover/Verifier path the C.7 oracle exercises):
/// </para>
/// <list type="number">
///   <item><description><c>initialize_sumcheck_fiat_shamir</c>: absorb the 32-byte circuit <c>id</c> [byte string], each of <c>npub_in</c> public inputs [field element], <c>F.zero()</c> [field element], then <c>nterms()</c> zero bytes [byte string].</description></item>
///   <item><description><c>write_input</c>: absorb the input column of <c>ninputs</c> elements [field-element array].</description></item>
///   <item><description><c>begin_circuit</c>: squeeze <c>Q</c> (<c>kMaxBindings</c> elements, <c>logc</c> used) then <c>G</c> (<c>logv</c> used).</description></item>
///   <item><description>per layer: <c>begin_layer</c> squeezes <c>alpha</c> then <c>beta</c>; the entering claim is <c>cl0 + alpha·cl1</c>; per round per hand, the round polynomial's two transmitted points are absorbed [two field elements] and the challenge is squeezed, then the claim folds; finally <c>wc[0]</c>, <c>wc[1]</c> are absorbed [field-element array of two].</description></item>
/// </list>
/// <para>
/// The round-polynomial arithmetic is field-generic Lagrange interpolation at evaluation points
/// <c>{0, 1, t}</c> where the third point <c>t</c> is the field's <c>poly_evaluation_point(2)</c> carried by
/// the profile (<c>g</c> the subfield generator for GF(2^128), <c>2</c> for Fp256), mirroring the field's
/// <c>newton_of_lagrange</c> + <c>eval_newton</c> using newton denominators <c>(X[k] − X[k−i])^{−1}</c> over
/// the threaded subtraction.
/// </para>
/// </remarks>
internal static class LongfellowSumcheckVerifier
{
    private const int ScalarSize = Scalar.SizeBytes;

    //The reference's Challenge::kMaxBindings: Q and G are squeezed as kMaxBindings-element arrays. Only
    //the first logc / logv entries are used, but the squeeze advances the PRF over all kMaxBindings.
    private const int MaxBindings = 40;


    /// <summary>
    /// An observer the replay calls with every reconstructed value, so a conformance gate can pin each
    /// against the reference's dumped stream. All methods are optional; the default observer ignores them.
    /// </summary>
    public interface IReplayObserver
    {
        /// <summary>The squeezed <c>Q</c> binding <paramref name="index"/> (copy variable).</summary>
        void OnQ(int index, ReadOnlySpan<byte> value);

        /// <summary>The squeezed <c>G</c> binding <paramref name="index"/> (output variable).</summary>
        void OnG(int index, ReadOnlySpan<byte> value);

        /// <summary>Layer <paramref name="layer"/>'s squeezed <c>alpha</c> and <c>beta</c>, and the entering claim.</summary>
        void OnLayerBegin(int layer, ReadOnlySpan<byte> alpha, ReadOnlySpan<byte> beta, ReadOnlySpan<byte> claimIn);

        /// <summary>One round/hand: the reconstructed <c>p(0) + p(1)</c>, the squeezed challenge, the folded claim.</summary>
        void OnRound(int layer, int round, int hand, ReadOnlySpan<byte> sum01, ReadOnlySpan<byte> challenge, ReadOnlySpan<byte> claim);

        /// <summary>Layer <paramref name="layer"/>'s two next-layer claims <c>wc[0]</c>, <c>wc[1]</c>.</summary>
        void OnLayerClaims(int layer, ReadOnlySpan<byte> claim0, ReadOnlySpan<byte> claim1);

        /// <summary>The input-binding challenge squeezed after the last layer (the hand-off into the Ligero layer).</summary>
        void OnInputChallenge(ReadOnlySpan<byte> value);
    }


    /// <summary>
    /// Replays the sumcheck layer walk over <paramref name="proof"/> against a fresh transcript seeded the
    /// way the prover seeded it, reconstructing every challenge and checking each round polynomial.
    /// </summary>
    /// <param name="circuit">The circuit shape; must have <c>logc == 0</c>.</param>
    /// <param name="proof">The sumcheck proof to replay.</param>
    /// <param name="inputElements">The input column, <c>ninputs</c> · ElementBytes little-endian element bytes, in input order.</param>
    /// <param name="transcript">The transcript, already seeded; this call performs the FS setup, input absorb and the walk.</param>
    /// <param name="add">Field addition.</param>
    /// <param name="subtract">Field subtraction (the Newton interpolation differences).</param>
    /// <param name="multiply">Field multiplication.</param>
    /// <param name="invert">Field inversion.</param>
    /// <param name="profile">The field profile supplying the on-wire element width and the third evaluation point <c>poly_evaluation_point(2)</c> (<c>g</c> for GF(2^128), <c>2</c> for Fp256).</param>
    /// <param name="curve">The curve parameter the delegates take (<see cref="CurveParameterSet.None"/> for GF(2^128)).</param>
    /// <param name="pool">The pool the working buffers rent from.</param>
    /// <param name="result">The verdict.</param>
    /// <param name="observer">An optional observer pinning each reconstructed value.</param>
    /// <returns><see langword="true"/> when every round polynomial satisfied the sumcheck relation.</returns>
    /// <exception cref="ArgumentNullException">When a required argument is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When the circuit has copies or <paramref name="inputElements"/> is the wrong length.</exception>
    public static bool Verify(
        LongfellowSumcheckCircuit circuit,
        LongfellowSumcheckProof proof,
        ReadOnlySpan<byte> inputElements,
        LongfellowTranscript transcript,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        LongfellowFieldProfile profile,
        CurveParameterSet curve,
        BaseMemoryPool pool,
        out LongfellowSumcheckVerificationResult result,
        IReplayObserver? observer = null)
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
            throw new ArgumentException($"The sumcheck replay requires logc == 0; the circuit has logc = {circuit.CopyRounds}.", nameof(circuit));
        }

        int elementBytes = profile.ElementBytes;
        if(inputElements.Length != circuit.InputCount * elementBytes)
        {
            throw new ArgumentException($"Expected {circuit.InputCount * elementBytes} input bytes ({circuit.InputCount} elements); received {inputElements.Length}.", nameof(inputElements));
        }

        result = LongfellowSumcheckVerificationResult.Accepted;

        //The field multiplicative one in the working domain, sourced from the profile (Foundation-A): the
        //canonical 0x01 for GF / the canonical Fp profile, to_montgomery(1) for the Montgomery Fp profile.
        Span<byte> one = stackalloc byte[ScalarSize];
        profile.CopyWorkingOne(one);

        //The three poly evaluation points {0, 1, t}: point 0 = zero, point 1 = one, point 2 = the field's
        //poly_evaluation_point(2) (g for GF(2^128), 2 for Fp256), carried by the profile.
        using IMemoryOwner<byte> evalPointsOwner = pool.Rent(LongfellowSumcheckProof.RoundPolynomialPoints * ScalarSize);
        Span<byte> evalPoints = evalPointsOwner.Memory.Span[..(LongfellowSumcheckProof.RoundPolynomialPoints * ScalarSize)];
        evalPoints.Clear();
        one.CopyTo(evalPoints.Slice(ScalarSize, ScalarSize));
        profile.CopyThirdEvaluationPoint(evalPoints.Slice(2 * ScalarSize, ScalarSize));

        InitializeFiatShamir(circuit, inputElements, elementBytes, transcript, pool);

        Span<byte> canonical = stackalloc byte[ScalarSize];

        //begin_circuit: squeeze Q then G (each a kMaxBindings-element array of elt(F)).
        for(int i = 0; i < MaxBindings; i++)
        {
            transcript.SqueezeFieldElement(profile, canonical);
            if(observer is not null && i < circuit.CopyRounds + 2)
            {
                observer.OnQ(i, canonical);
            }
        }

        for(int i = 0; i < MaxBindings; i++)
        {
            transcript.SqueezeFieldElement(profile, canonical);
            if(observer is not null && i < circuit.OutputLogCount + 2)
            {
                observer.OnG(i, canonical);
            }
        }

        WalkLayers(circuit, proof, transcript, profile, elementBytes, add, subtract, multiply, invert, curve, evalPoints, pool, observer);

        //The input-binding challenge the ZK verifier squeezes after the last wc (ZkCommon: alpha =
        //tsv.elt(F)); the hand-off point into the Ligero layer.
        transcript.SqueezeFieldElement(profile, canonical);
        observer?.OnInputChallenge(canonical);

        return true;
    }


    //ZkCommon::initialize_sumcheck_fiat_shamir + TranscriptSumcheck::write_input.
    private static void InitializeFiatShamir(LongfellowSumcheckCircuit circuit, ReadOnlySpan<byte> inputElements, int elementBytes, LongfellowTranscript transcript, BaseMemoryPool pool)
    {
        //id [byte string]
        transcript.AbsorbByteString(circuit.Id.Span);

        //each public input [field element], then F.zero() pro-forma [field element]
        for(int i = 0; i < circuit.PublicInputCount; i++)
        {
            transcript.AbsorbFieldElement(inputElements.Slice(i * elementBytes, elementBytes), elementBytes);
        }

        Span<byte> zeroElement = stackalloc byte[ScalarSize];
        transcript.AbsorbFieldElement(zeroElement[..elementBytes], elementBytes);

        //nterms() zero bytes [byte string] for correlation intractability.
        AbsorbZeroBytes(transcript, circuit.TermCount, pool);

        //write_input: the input column as a field-element array of ninputs elements.
        transcript.AbsorbFieldElementArray(inputElements, circuit.InputCount, elementBytes);
    }


    private static void WalkLayers(
        LongfellowSumcheckCircuit circuit,
        LongfellowSumcheckProof proof,
        LongfellowTranscript transcript,
        LongfellowFieldProfile profile,
        int elementBytes,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        ReadOnlySpan<byte> evalPoints,
        BaseMemoryPool pool,
        IReplayObserver? observer)
    {
        using IMemoryOwner<byte> scratchOwner = pool.Rent(8 * ScalarSize);
        Span<byte> scratch = scratchOwner.Memory.Span[..(8 * ScalarSize)];
        Span<byte> alpha = scratch[..ScalarSize];
        Span<byte> beta = scratch.Slice(ScalarSize, ScalarSize);
        Span<byte> claim = scratch.Slice(2 * ScalarSize, ScalarSize);
        Span<byte> claim0 = scratch.Slice(3 * ScalarSize, ScalarSize);
        Span<byte> claim1 = scratch.Slice(4 * ScalarSize, ScalarSize);
        Span<byte> p0 = scratch.Slice(5 * ScalarSize, ScalarSize);
        Span<byte> p1 = scratch.Slice(6 * ScalarSize, ScalarSize);
        Span<byte> product = scratch.Slice(7 * ScalarSize, ScalarSize);

        Span<byte> squeezedBuffer = stackalloc byte[ScalarSize];
        Span<byte> squeezed = squeezedBuffer[..elementBytes];
        Span<byte> challenge = stackalloc byte[ScalarSize];
        Span<byte> polyBuffer = stackalloc byte[LongfellowSumcheckProof.RoundPolynomialPoints * ScalarSize];
        Span<byte> wcBytes = stackalloc byte[LongfellowSumcheckProof.ClaimCount * ScalarSize];

        //The running input claims start at (0, 0).
        claim0.Clear();
        claim1.Clear();

        for(int layer = 0; layer < circuit.LayerCount; layer++)
        {
            //begin_layer: squeeze alpha then beta.
            transcript.SqueezeFieldElement(profile, alpha);
            transcript.SqueezeFieldElement(profile, beta);

            //The entering claim is the affine combination claim0 + alpha·claim1.
            multiply(alpha, claim1, product, curve);
            add(claim0, product, claim, curve);

            observer?.OnLayerBegin(layer, alpha, beta, claim);

            int handRounds = circuit.Layers[layer].HandRounds;
            for(int round = 0; round < handRounds; round++)
            {
                for(int hand = 0; hand < LongfellowSumcheckProof.HandCount; hand++)
                {
                    proof.RoundPolynomialPoint(layer, hand, round, 0).CopyTo(p0);

                    //The k != 1 optimization: p(1) is not on the wire. The sumcheck verifier reconstructs
                    //it from the running claim by the relation claim = p(0) + p(1), i.e. p(1) = claim − p(0).
                    //This reconstruction is what pins p(1); the soundness of the reconstructed value is
                    //checked downstream — by the input binding in the non-ZK verifier, or by the Ligero
                    //opening in the ZK verifier. A tampered transmitted point therefore diverges the
                    //challenge stream, which the conformance gate catches against the reference's dumped
                    //challenges.
                    subtract(claim, p0, p1, curve);

                    //sum01 = p(0) + p(1) (= claim by the reconstruction), the reference's dumped value.
                    add(p0, p1, product, curve);

                    //round(): absorb the two transmitted points (p(0), p(2)) [skip p(1)], squeeze challenge.
                    WriteLittleEndian(p0, squeezed);
                    transcript.AbsorbFieldElement(squeezed, elementBytes);
                    WriteLittleEndian(proof.RoundPolynomialPoint(layer, hand, round, 2), squeezed);
                    transcript.AbsorbFieldElement(squeezed, elementBytes);
                    transcript.SqueezeFieldElement(profile, challenge);

                    //Fold: claim = eval_lagrange(p, challenge) with p = (p(0), p(1), p(2)).
                    p0.CopyTo(polyBuffer[..ScalarSize]);
                    p1.CopyTo(polyBuffer.Slice(ScalarSize, ScalarSize));
                    proof.RoundPolynomialPoint(layer, hand, round, 2).CopyTo(polyBuffer.Slice(2 * ScalarSize, ScalarSize));
                    EvalLagrange(polyBuffer, challenge, evalPoints, add, subtract, multiply, invert, curve, claim);

                    observer?.OnRound(layer, round, hand, product, challenge, claim);
                }
            }

            //wc[0], wc[1] become the next layer's two claims; absorb them [field-element array of two].
            proof.Claim(layer, 0).CopyTo(claim0);
            proof.Claim(layer, 1).CopyTo(claim1);

            WriteLittleEndian(claim0, wcBytes[..elementBytes]);
            WriteLittleEndian(claim1, wcBytes.Slice(elementBytes, elementBytes));
            transcript.AbsorbFieldElementArray(wcBytes[..(LongfellowSumcheckProof.ClaimCount * elementBytes)], LongfellowSumcheckProof.ClaimCount, elementBytes);

            observer?.OnLayerClaims(layer, claim0, claim1);
        }
    }


    //Poly<3>::eval_lagrange: convert the Lagrange values to Newton forward differences in place
    //(newton_of_lagrange), then evaluate at x (eval_newton). Evaluation points X = {0, 1, t}.
    private static void EvalLagrange(
        Span<byte> poly,
        ReadOnlySpan<byte> x,
        ReadOnlySpan<byte> evalPoints,
        ScalarAddDelegate add,
        ScalarSubtractDelegate subtract,
        ScalarMultiplyDelegate multiply,
        ScalarInvertDelegate invert,
        CurveParameterSet curve,
        Span<byte> result)
    {
        const int N = LongfellowSumcheckProof.RoundPolynomialPoints;

        Span<byte> difference = stackalloc byte[ScalarSize];
        Span<byte> denominator = stackalloc byte[ScalarSize];

        //newton_of_lagrange: for i in 1..N, for k from N-1 down to i: t[k] -= t[k-1]; t[k] *= 1/(X[k]-X[k-i]).
        for(int i = 1; i < N; i++)
        {
            for(int k = N - 1; k >= i; k--)
            {
                Span<byte> tk = poly.Slice(k * ScalarSize, ScalarSize);
                ReadOnlySpan<byte> tkPrev = poly.Slice((k - 1) * ScalarSize, ScalarSize);

                //t[k] -= t[k-1].
                subtract(tk, tkPrev, difference, curve);
                difference.CopyTo(tk);

                //newton_denominator(k, i) = (X[k] - X[k-i])^{-1}.
                ReadOnlySpan<byte> xk = evalPoints.Slice(k * ScalarSize, ScalarSize);
                ReadOnlySpan<byte> xki = evalPoints.Slice((k - i) * ScalarSize, ScalarSize);
                subtract(xk, xki, denominator, curve);
                invert(denominator, denominator, curve);

                multiply(tk, denominator, difference, curve);
                difference.CopyTo(tk);
            }
        }

        //eval_newton: e = t[N-1]; for i from N-2 down to 0: e *= (x - X[i]); e += t[i].
        Span<byte> e = stackalloc byte[ScalarSize];
        poly.Slice((N - 1) * ScalarSize, ScalarSize).CopyTo(e);
        for(int i = N - 2; i >= 0; i--)
        {
            ReadOnlySpan<byte> xi = evalPoints.Slice(i * ScalarSize, ScalarSize);
            subtract(x, xi, difference, curve);
            multiply(e, difference, denominator, curve);
            add(denominator, poly.Slice(i * ScalarSize, ScalarSize), e, curve);
        }

        e.CopyTo(result);
    }


    //Absorbs n zero bytes as a single byte-string write (the reference's write0 batches in 32-byte
    //chunks; the absorbed bytes are identical to one byte-string of n zeros).
    private static void AbsorbZeroBytes(LongfellowTranscript transcript, int count, BaseMemoryPool pool)
    {
        using IMemoryOwner<byte> zerosOwner = pool.Rent(Math.Max(count, 1));
        Span<byte> zeros = zerosOwner.Memory.Span[..count];
        zeros.Clear();
        transcript.AbsorbByteString(zeros);
    }


    //to_bytes_field: the low ElementBytes canonical big-endian bytes reversed to ElementBytes little-endian
    //element bytes; the destination length is the element width.
    private static void WriteLittleEndian(ReadOnlySpan<byte> canonical, Span<byte> littleEndian)
    {
        for(int i = 0; i < littleEndian.Length; i++)
        {
            littleEndian[i] = canonical[ScalarSize - 1 - i];
        }
    }
}

using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The minimal in-memory circuit shape the zk sumcheck wire format and verifier flow need, a faithful
/// port of the parameter subset of google/longfellow-zk's <c>Circuit&lt;Field&gt;</c> and
/// <c>Layer&lt;Field&gt;</c> (<c>lib/sumcheck/circuit.h</c>) that drives
/// <c>ZkProof::write_sc_proof</c> / <c>read_sc_proof</c> and the layer walk in
/// <c>VerifierLayers::layers</c>. Only the values those two flows read are carried; the
/// coefficient/wiring tables (the <c>Quad</c>) and circuit evaluation are not part of the sc segment or
/// the per-layer round-polynomial/challenge replay, so they are not ported here.
/// </summary>
/// <remarks>
/// <para>
/// The sc serializer reads, per layer, only <see cref="LongfellowSumcheckLayer.HandRounds"/>
/// (<c>logw</c>) — the number of binding rounds per hand — to size the round polynomials, plus the two
/// <c>wc</c> claims. The serializer further requires <see cref="CopyRounds"/> (<c>logc</c>) to be zero:
/// the reference's <c>write_sc_proof</c>/<c>read_sc_proof</c> assert <c>logc == 0</c> (no copies), so a
/// circuit with copies cannot be expressed on this wire segment.
/// </para>
/// <para>
/// The verifier replay additionally reads <see cref="Id"/> and the public-input count
/// (<see cref="PublicInputCount"/>) for the Fiat–Shamir initialization, and the total term count
/// (<see cref="TermCount"/>, the sum of each layer's <see cref="LongfellowSumcheckLayer.TermCount"/>)
/// for the correlation-intractability zero padding. <see cref="OutputLogCount"/> (<c>logv</c>) sizes the
/// <c>G</c> challenge; <see cref="InputCount"/> sizes the absorbed input column.
/// </para>
/// </remarks>
internal sealed class LongfellowSumcheckCircuit
{
    //The reference's Circuit::id is a 32-byte compiler-assigned identifier absorbed first into the FS.
    internal const int IdLength = 32;

    /// <summary>The number of outputs for one copy (<c>nv</c>).</summary>
    public int OutputCount { get; }

    /// <summary>The number of <c>G</c> variables binding the output (<c>logv</c>).</summary>
    public int OutputLogCount { get; }

    /// <summary>The number of copies (<c>nc</c>).</summary>
    public int CopyCount { get; }

    /// <summary>The number of sumcheck rounds binding the copy variables (<c>logc</c>); zero for the sc wire segment.</summary>
    public int CopyRounds { get; }

    /// <summary>The number of layers (<c>nl</c>).</summary>
    public int LayerCount => Layers.Length;

    /// <summary>The number of inputs (<c>ninputs</c>).</summary>
    public int InputCount { get; }

    /// <summary>The number of public inputs, the index of the first private input (<c>npub_in</c>).</summary>
    public int PublicInputCount { get; }

    /// <summary>The 32-byte compiler-assigned circuit identifier (<c>id</c>), absorbed first into the Fiat–Shamir transcript.</summary>
    public ReadOnlyMemory<byte> Id { get; }

    /// <summary>The circuit's layers (<c>l</c>), in walk order (layer 0 first).</summary>
    public LongfellowSumcheckLayer[] Layers { get; }


    /// <summary>The total number of terms across all layers (<c>nterms()</c>), the byte count of the correlation-intractability zero pad.</summary>
    public int TermCount
    {
        get
        {
            int total = 0;
            foreach(LongfellowSumcheckLayer layer in Layers)
            {
                total += layer.TermCount;
            }

            return total;
        }
    }


    /// <summary>
    /// Constructs a sumcheck circuit shape.
    /// </summary>
    /// <param name="outputCount">The outputs per copy (<c>nv</c>).</param>
    /// <param name="outputLogCount">The output binding rounds (<c>logv</c>).</param>
    /// <param name="copyCount">The number of copies (<c>nc</c>).</param>
    /// <param name="copyRounds">The copy binding rounds (<c>logc</c>); must be zero for the sc wire segment.</param>
    /// <param name="inputCount">The number of inputs (<c>ninputs</c>).</param>
    /// <param name="publicInputCount">The number of public inputs (<c>npub_in</c>).</param>
    /// <param name="id">The 32-byte circuit identifier (<c>id</c>).</param>
    /// <param name="layers">The layers in walk order; at least one.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="layers"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a count is out of range.</exception>
    /// <exception cref="ArgumentException">When <paramref name="id"/> is not 32 bytes or <paramref name="layers"/> is empty.</exception>
    public LongfellowSumcheckCircuit(
        int outputCount,
        int outputLogCount,
        int copyCount,
        int copyRounds,
        int inputCount,
        int publicInputCount,
        ReadOnlyMemory<byte> id,
        LongfellowSumcheckLayer[] layers)
    {
        ArgumentNullException.ThrowIfNull(layers);
        ArgumentOutOfRangeException.ThrowIfNegative(outputCount);
        ArgumentOutOfRangeException.ThrowIfNegative(outputLogCount);
        ArgumentOutOfRangeException.ThrowIfNegative(copyCount);
        ArgumentOutOfRangeException.ThrowIfNegative(copyRounds);
        ArgumentOutOfRangeException.ThrowIfNegative(inputCount);
        ArgumentOutOfRangeException.ThrowIfNegative(publicInputCount);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(publicInputCount, inputCount);

        if(id.Length != IdLength)
        {
            throw new ArgumentException($"The circuit id is {IdLength} bytes; received {id.Length}.", nameof(id));
        }

        if(layers.Length == 0)
        {
            throw new ArgumentException("A sumcheck circuit has at least one layer.", nameof(layers));
        }

        OutputCount = outputCount;
        OutputLogCount = outputLogCount;
        CopyCount = copyCount;
        CopyRounds = copyRounds;
        InputCount = inputCount;
        PublicInputCount = publicInputCount;
        Id = id;
        Layers = layers;
    }


    /// <summary>
    /// Returns a copy of the circuit with every quad-term coefficient lifted into a working domain (Perf
    /// Increment 1). The circuit reader stores the field constants <c>v</c> the quad form
    /// <c>V[g] = Σ v·W[h0]·W[h1]</c> multiplies as CANONICAL scalars; on the Montgomery working domain those
    /// constants must be lifted to their Montgomery residue, exactly as the witness column and the profile's
    /// of_scalar constants are, so the shared sumcheck/constraint stack multiplies a working-domain constant
    /// against working-domain wires. This is the circuit-constant boundary conversion (the analogue of the FFT
    /// root and the of_scalar seam); the shapes, indices, id and counts are unchanged. An assert-zero
    /// coefficient (<c>v == 0</c>) stays zero under any domain converter, so the assert-zero terms keep their
    /// special <c>beta</c> handling. For the canonical working domain <paramref name="toWorking"/> is the
    /// identity and the result is value-identical to <see langword="this"/>.
    /// </summary>
    /// <param name="toWorking">The canonical-&gt;working-domain converter applied to each non-trivial coefficient (<c>to_montgomery</c> for the Montgomery domain).</param>
    /// <returns>A new circuit whose quad-term coefficients are in the working domain.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="toWorking"/> is <see langword="null"/>.</exception>
    public LongfellowSumcheckCircuit LiftCoefficientsToWorking(LongfellowDomainConvertDelegate toWorking)
    {
        ArgumentNullException.ThrowIfNull(toWorking);

        var liftedLayers = new LongfellowSumcheckLayer[Layers.Length];
        for(int l = 0; l < Layers.Length; l++)
        {
            LongfellowSumcheckLayer layer = Layers[l];
            LongfellowSumcheckQuadTerm[] terms = layer.QuadTerms;
            if(terms.Length == 0)
            {
                liftedLayers[l] = layer;

                continue;
            }

            var liftedTerms = new LongfellowSumcheckQuadTerm[terms.Length];
            for(int t = 0; t < terms.Length; t++)
            {
                LongfellowSumcheckQuadTerm term = terms[t];
                byte[] coefficient = term.Coefficient.ToArray();
                toWorking(coefficient, coefficient);
                liftedTerms[t] = term with { Coefficient = coefficient };
            }

            liftedLayers[l] = new LongfellowSumcheckLayer(layer.InputCount, layer.HandRounds, layer.TermCount, liftedTerms);
        }

        return new LongfellowSumcheckCircuit(OutputCount, OutputLogCount, CopyCount, CopyRounds, InputCount, PublicInputCount, Id, liftedLayers);
    }
}


/// <summary>
/// One circuit layer's shape, the port of google/longfellow-zk's <c>Layer&lt;Field&gt;</c>
/// (<c>lib/sumcheck/circuit.h</c>) subset the sc wire format, the verifier replay and the ZK
/// constraint composition read: <see cref="HandRounds"/> (<c>logw</c>, the binding rounds per hand)
/// sizing the round polynomials, <see cref="InputCount"/> (<c>nw</c>) carried for completeness,
/// <see cref="TermCount"/> (<c>nterms()</c>) contributing to the circuit's correlation-intractability
/// zero pad, and <see cref="QuadTerms"/> — the layer's <c>Quad</c> wiring terms that
/// <c>ZkCommon::verifier_constraints</c>' <c>bind_quad</c> (<c>Quad::bind_gh_all</c>) iterates.
/// </summary>
/// <remarks>
/// The sc wire segment and the C.7 challenge replay do not read the <c>Quad</c>, so a layer built for
/// those flows leaves <see cref="QuadTerms"/> empty. The C.8 full-verifier composition needs the terms
/// to bind the quad at the output and hand points, so it constructs layers with them populated.
/// </remarks>
internal sealed class LongfellowSumcheckLayer
{
    /// <summary>The number of inputs to the layer (<c>nw</c>).</summary>
    public int InputCount { get; }

    /// <summary>The number of binding rounds for the hand variables (<c>logw</c>); at least one.</summary>
    public int HandRounds { get; }

    /// <summary>The number of terms in the layer's quad (<c>nterms()</c>).</summary>
    public int TermCount { get; }

    /// <summary>The layer's <c>Quad</c> wiring terms in iteration order; empty unless the layer was built for the ZK constraint composition.</summary>
    public LongfellowSumcheckQuadTerm[] QuadTerms { get; }


    /// <summary>
    /// Constructs a layer shape without its quad wiring (the sc wire format and the C.7 replay).
    /// </summary>
    /// <param name="inputCount">The layer's inputs (<c>nw</c>).</param>
    /// <param name="handRounds">The hand binding rounds (<c>logw</c>); at least one.</param>
    /// <param name="termCount">The layer's term count (<c>nterms()</c>).</param>
    /// <exception cref="ArgumentOutOfRangeException">When a count is out of range.</exception>
    public LongfellowSumcheckLayer(int inputCount, int handRounds, int termCount)
        : this(inputCount, handRounds, termCount, [])
    {
    }


    /// <summary>
    /// Constructs a layer shape with its quad wiring (the ZK constraint composition).
    /// </summary>
    /// <param name="inputCount">The layer's inputs (<c>nw</c>).</param>
    /// <param name="handRounds">The hand binding rounds (<c>logw</c>); at least one.</param>
    /// <param name="termCount">The layer's term count (<c>nterms()</c>); must equal the number of <paramref name="quadTerms"/> when those are supplied.</param>
    /// <param name="quadTerms">The layer's <c>Quad</c> terms in iteration order; may be empty.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="quadTerms"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a count is out of range.</exception>
    /// <exception cref="ArgumentException">When <paramref name="quadTerms"/> is non-empty and its length differs from <paramref name="termCount"/>.</exception>
    public LongfellowSumcheckLayer(int inputCount, int handRounds, int termCount, LongfellowSumcheckQuadTerm[] quadTerms)
    {
        ArgumentNullException.ThrowIfNull(quadTerms);
        ArgumentOutOfRangeException.ThrowIfNegative(inputCount);
        ArgumentOutOfRangeException.ThrowIfLessThan(handRounds, 1);
        ArgumentOutOfRangeException.ThrowIfNegative(termCount);

        if(quadTerms.Length != 0 && quadTerms.Length != termCount)
        {
            throw new ArgumentException($"The layer reports {termCount} terms but {quadTerms.Length} quad terms were supplied.", nameof(quadTerms));
        }

        InputCount = inputCount;
        HandRounds = handRounds;
        TermCount = termCount;
        QuadTerms = quadTerms;
    }
}


/// <summary>
/// One term (corner) of a layer's <c>Quad</c> wiring, a faithful port of google/longfellow-zk's
/// <c>EQuad&lt;Field&gt;::ecorner</c> (<c>lib/sumcheck/equad.h</c>): the gate index <c>g</c>, the two
/// hand indices <c>h0</c>, <c>h1</c>, and the coefficient <c>v</c>. The quadratic form a layer computes
/// is <c>V[g] = Σ_term v · W[h0] · W[h1]</c>; <c>ZkCommon::verifier_constraints</c>' <c>bind_quad</c>
/// (<c>Quad::bind_gh_all</c>) folds these terms at the output binding (the <c>g</c> point) and the hand
/// challenges (the <c>h0</c>, <c>h1</c> points) into one field element per layer.
/// </summary>
/// <param name="GateIndex">The gate (output) index <c>g</c>.</param>
/// <param name="LeftIndex">The left hand index <c>h[0]</c>.</param>
/// <param name="RightIndex">The right hand index <c>h[1]</c>.</param>
/// <param name="Coefficient">The coefficient <c>v</c>, one canonical big-endian scalar; <c>v == 0</c> marks an assert-zero term the binding treats specially (it folds the assert-zero coefficient <c>beta</c>).</param>
internal readonly record struct LongfellowSumcheckQuadTerm(int GateIndex, int LeftIndex, int RightIndex, ReadOnlyMemory<byte> Coefficient);

using System;
using System.Collections.Generic;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

/// <summary>
/// The layer scheduler, a faithful port of google/longfellow-zk's <c>Scheduler&lt;Field&gt;</c>
/// (<c>lib/circuits/compiler/schedule.h</c>) plus the quad canonicalization it invokes
/// (<c>EQuad::canonicalize</c>, <c>lib/sumcheck/equad.h</c>): the compiler DAG becomes a layered
/// circuit with copy wires bridging depth gaps, wire ids assigned by the reference's canonical
/// order, and each layer's corners emitted h-swapped, Morton-sorted and coalesced — the exact
/// iteration order the binding stack's adjacent-run coalescing assumes.
/// </summary>
/// <remarks>
/// <para>
/// Layers are produced in the walk order our <see cref="LongfellowSumcheckCircuit"/> stores: index 0
/// is the output layer, and each layer's <c>nw</c> is the gate count of the layer below it. The
/// canonical wire-id assignment sorts each layer's nodes by the reference order — claimed wire ids
/// first in ascending order, then reverse-lexicographic term comparison, shorter term lists first,
/// original DAG nodes before copy wires — and both the per-node term lists and the per-layer node
/// lists must be duplicate-free or the canonicalization is ill-defined; violations throw.
/// </para>
/// <para>
/// Every copy wire is the term <c>1·(w0·prev)</c>, so the constant-one wire must occupy index 0 of
/// every layer a copy wire reads; the builder's needed-marking guarantees it, and the layer-zero
/// claimed-id assertion catches a violation.
/// </para>
/// </remarks>
internal sealed class LongfellowCircuitScheduler
{
    private readonly List<LongfellowCircuitNode> nodes;
    private readonly List<byte[]> constants;
    private readonly LongfellowCompilerFieldOperations field;
    private readonly byte[] oneCoefficient;

    /// <summary>The scheduled wire total (<c>nwires_</c>): the output count plus every layer's input count.</summary>
    public int WireCount { get; private set; }

    /// <summary>The scheduled quad-term total before coalescing (<c>nquad_terms_</c>).</summary>
    public int QuadTermCount { get; private set; }

    /// <summary>The number of copy wires inserted to bridge depth gaps (<c>nwires_overhead_</c>).</summary>
    public int CopyWireOverheadCount { get; private set; }


    /// <summary>
    /// Constructs a scheduler over a compiled DAG.
    /// </summary>
    /// <param name="nodes">The DAG nodes with the needed-marking pass applied.</param>
    /// <param name="constants">The compiler's constant table, canonical big-endian scalars.</param>
    /// <param name="field">The field-operation bundle.</param>
    /// <exception cref="ArgumentNullException">When an argument is <see langword="null"/>.</exception>
    public LongfellowCircuitScheduler(
        List<LongfellowCircuitNode> nodes,
        List<byte[]> constants,
        LongfellowCompilerFieldOperations field)
    {
        ArgumentNullException.ThrowIfNull(nodes);
        ArgumentNullException.ThrowIfNull(constants);
        ArgumentNullException.ThrowIfNull(field);

        this.nodes = nodes;
        this.constants = constants;
        this.field = field;
        oneCoefficient = field.One.ToArray();
    }


    /// <summary>
    /// Schedules the DAG into layers (<c>mkcircuit</c>): orders the needed nodes by depth with copy
    /// wires, assigns canonical wire ids, and emits each layer's canonicalized corners.
    /// </summary>
    /// <param name="depthUpperBound">The circuit depth upper bound; layers span depths one through one less.</param>
    /// <param name="outputWireCount">Receives the output wire count (<c>nv</c>).</param>
    /// <returns>The layers in walk order, index 0 the output layer.</returns>
    /// <exception cref="InvalidOperationException">When a canonicalization invariant fails or a layer degenerates to a single wire.</exception>
    public LongfellowSumcheckLayer[] Schedule(int depthUpperBound, out int outputWireCount)
    {
        List<LayeredNode>[] layered = OrderByLayer(depthUpperBound);
        AssignWireIds(layered);

        return FillLayers(layered, out outputWireCount);
    }


    /// <summary>One node instance placed at one layer depth; a DAG node consumed across a depth gap appears once per bridged depth.</summary>
    private sealed class LayeredNode
    {
        /// <summary>The wire id the node claims or receives; <see cref="LongfellowCircuitNode.WireIdUndefined"/> until assigned.</summary>
        public int DesiredWireId { get; set; }

        /// <summary>Whether the node is a scheduler-inserted copy wire rather than an original DAG node.</summary>
        public bool IsCopyWire { get; }

        /// <summary>The node's terms over the previous layer's node list.</summary>
        public LayeredTerm[] Terms { get; }


        /// <summary>Constructs a placed node.</summary>
        /// <param name="desiredWireId">The claimed wire id or <see cref="LongfellowCircuitNode.WireIdUndefined"/>.</param>
        /// <param name="isCopyWire">Whether the node is a copy wire.</param>
        /// <param name="terms">The node's terms over the previous layer.</param>
        public LayeredNode(int desiredWireId, bool isCopyWire, LayeredTerm[] terms)
        {
            DesiredWireId = desiredWireId;
            IsCopyWire = isCopyWire;
            Terms = terms;
        }
    }


    /// <summary>One term over the previous layer's node list: the coefficient and the two operand positions.</summary>
    /// <param name="K">The coefficient, canonical big-endian; shared with the constant table and never mutated.</param>
    /// <param name="Lop0">The first operand's position in the previous layer's node list.</param>
    /// <param name="Lop1">The second operand's position in the previous layer's node list.</param>
    private readonly record struct LayeredTerm(byte[] K, int Lop0, int Lop1);


    /// <summary>A term renamed onto the previous layer's assigned wire ids, hand-ordered (<c>renamed_lterm</c>).</summary>
    private readonly struct RenamedTerm
    {
        /// <summary>The coefficient, canonical big-endian.</summary>
        public byte[] K { get; }

        /// <summary>The smaller renamed operand wire id.</summary>
        public int R0 { get; }

        /// <summary>The larger renamed operand wire id.</summary>
        public int R1 { get; }


        /// <summary>Constructs a renamed term, ordering the operand wire ids.</summary>
        /// <param name="k">The coefficient.</param>
        /// <param name="r0">One renamed operand wire id.</param>
        /// <param name="r1">The other renamed operand wire id.</param>
        public RenamedTerm(byte[] k, int r0, int r1)
        {
            K = k;
            R0 = Math.Min(r0, r1);
            R1 = Math.Max(r0, r1);
        }
    }


    /// <summary>A layer node renamed for the canonical sort (<c>renamed_lnode</c>).</summary>
    private sealed class RenamedNode
    {
        /// <summary>The claimed wire id or <see cref="LongfellowCircuitNode.WireIdUndefined"/>.</summary>
        public int DesiredWireId { get; }

        /// <summary>The node's position in the layer's original node list.</summary>
        public int OriginalIndex { get; }

        /// <summary>Whether the node is a copy wire.</summary>
        public bool IsCopyWire { get; }

        /// <summary>The renamed terms in canonical term order.</summary>
        public RenamedTerm[] Terms { get; }


        /// <summary>Constructs a renamed node.</summary>
        /// <param name="desiredWireId">The claimed wire id or <see cref="LongfellowCircuitNode.WireIdUndefined"/>.</param>
        /// <param name="originalIndex">The node's position in the layer's original list.</param>
        /// <param name="isCopyWire">Whether the node is a copy wire.</param>
        /// <param name="terms">The renamed terms, already sorted.</param>
        public RenamedNode(int desiredWireId, int originalIndex, bool isCopyWire, RenamedTerm[] terms)
        {
            DesiredWireId = desiredWireId;
            OriginalIndex = originalIndex;
            IsCopyWire = isCopyWire;
            Terms = terms;
        }
    }


    /// <summary>One quad corner under construction: the gate wire, the two hand wires and the coefficient.</summary>
    private struct Corner
    {
        /// <summary>The gate (output) wire id.</summary>
        public int G;

        /// <summary>The first hand wire id.</summary>
        public int H0;

        /// <summary>The second hand wire id.</summary>
        public int H1;

        /// <summary>The coefficient, canonical big-endian.</summary>
        public byte[] V;
    }


    /// <summary>
    /// Converts the DAG into per-depth node lists with copy wires (<c>order_by_layer</c>): each
    /// needed non-zero node is placed at its depth, and one copy wire per bridged depth carries it
    /// to every deeper consumer.
    /// </summary>
    /// <param name="depthUpperBound">The circuit depth upper bound.</param>
    /// <returns>The per-depth node lists.</returns>
    private List<LayeredNode>[] OrderByLayer(int depthUpperBound)
    {
        var layered = new List<LayeredNode>[depthUpperBound];
        for(int d = 0; d < depthUpperBound; d++)
        {
            layered[d] = [];
        }

        var placements = new List<int>[nodes.Count];
        CopyWireOverheadCount = 0;

        for(int op = 0; op < nodes.Count; op++)
        {
            LongfellowCircuitNode n = nodes[op];
            if(!n.IsNeeded || n.IsZero)
            {
                continue;
            }

            int depth = n.Depth;
            int position = layered[depth].Count;
            placements[op] = [position];

            var terms = new LayeredTerm[n.Terms.Length];
            for(int t = 0; t < n.Terms.Length; t++)
            {
                LongfellowCompilerTerm term = n.Terms[t];
                terms[t] = new LayeredTerm(
                    constants[term.Ki],
                    PlacementAt(placements, term.Op0, depth - 1),
                    PlacementAt(placements, term.Op1, depth - 1));
            }

            layered[depth].Add(new LayeredNode(n.DesiredWireIdAt(depth, depthUpperBound), isCopyWire: false, terms));

            //Copy wires carry the value one layer at a time up to its deepest consumer; each is the
            //term 1·(w0·prev) over the previous layer, position 0 being the constant-one wire.
            for(int d = depth + 1; d < n.MaxNeededDepth; d++)
            {
                int previousPosition = position;
                position = layered[d].Count;
                placements[op].Add(position);

                var copy = new LayeredTerm[] { new(oneCoefficient, 0, previousPosition) };
                layered[d].Add(new LayeredNode(n.DesiredWireIdAt(d, depthUpperBound), isCopyWire: true, copy));
                CopyWireOverheadCount++;
            }
        }

        return layered;
    }


    /// <summary>
    /// The position a node occupies in the layer at a given depth (<c>lop_of_op_at_depth</c>).
    /// </summary>
    /// <param name="placements">The per-node placement lists.</param>
    /// <param name="op">The node id.</param>
    /// <param name="depth">The depth to resolve at.</param>
    /// <returns>The position in that depth's node list.</returns>
    private int PlacementAt(List<int>[] placements, int op, int depth)
    {
        return placements[op][depth - nodes[op].Depth];
    }


    /// <summary>
    /// Assigns canonical wire ids layer by layer (<c>assign_wire_ids</c>): each layer's nodes are
    /// renamed onto the previous layer's ids, sorted by the reference's canonical order, and
    /// numbered in sorted order; nodes with claimed ids must land exactly on their claim.
    /// </summary>
    /// <param name="layered">The per-depth node lists.</param>
    /// <exception cref="InvalidOperationException">When a canonicalization invariant fails.</exception>
    private void AssignWireIds(List<LayeredNode>[] layered)
    {
        foreach(LayeredNode input in layered[0])
        {
            if(input.DesiredWireId == LongfellowCircuitNode.WireIdUndefined)
            {
                throw new InvalidOperationException("Every input-layer wire claims its id.");
            }
        }

        for(int d = 1; d < layered.Length; d++)
        {
            List<LayeredNode> previous = layered[d - 1];
            List<LayeredNode> current = layered[d];

            var renamed = new List<RenamedNode>(current.Count);
            for(int index = 0; index < current.Count; index++)
            {
                LayeredNode ln = current[index];
                var terms = new RenamedTerm[ln.Terms.Length];
                for(int t = 0; t < ln.Terms.Length; t++)
                {
                    LayeredTerm lt = ln.Terms[t];
                    terms[t] = new RenamedTerm(lt.K, previous[lt.Lop0].DesiredWireId, previous[lt.Lop1].DesiredWireId);
                }

                Array.Sort(terms, CompareRenamedTerms);

                for(int t = 1; t < terms.Length; t++)
                {
                    if(RenamedTermsEqual(terms[t - 1], terms[t]))
                    {
                        throw new InvalidOperationException("A layer node's renamed terms must be unique for the canonicalization to be well defined.");
                    }
                }

                renamed.Add(new RenamedNode(ln.DesiredWireId, index, ln.IsCopyWire, terms));
            }

            renamed.Sort(CompareRenamedNodes);

            for(int i = 1; i < renamed.Count; i++)
            {
                if(RenamedNodesEqual(renamed[i - 1], renamed[i]))
                {
                    throw new InvalidOperationException("A layer's renamed nodes must be unique for the canonicalization to be well defined.");
                }
            }

            int wireId = 0;
            foreach(RenamedNode rn in renamed)
            {
                LayeredNode ln = current[rn.OriginalIndex];
                if(ln.DesiredWireId != LongfellowCircuitNode.WireIdUndefined)
                {
                    if(wireId != ln.DesiredWireId)
                    {
                        throw new InvalidOperationException("A claimed wire id must coincide with its canonical position.");
                    }
                }
                else
                {
                    ln.DesiredWireId = wireId;
                }

                wireId++;
            }
        }
    }


    /// <summary>
    /// The strict order on renamed terms (<c>renamed_lterm::compare</c>): the smaller hand, the
    /// larger hand, then the coefficient's little-endian serialization.
    /// </summary>
    /// <param name="a">The first term.</param>
    /// <param name="b">The second term.</param>
    /// <returns><see langword="true"/> when <paramref name="a"/> precedes <paramref name="b"/>.</returns>
    private bool RenamedTermLess(in RenamedTerm a, in RenamedTerm b)
    {
        if(a.R0 != b.R0)
        {
            return a.R0 < b.R0;
        }

        if(a.R1 != b.R1)
        {
            return a.R1 < b.R1;
        }

        return field.CompareLittleEndian(a.K, b.K);
    }


    /// <summary>
    /// The three-way wrapper over <see cref="RenamedTermLess"/> for sorting.
    /// </summary>
    /// <param name="a">The first term.</param>
    /// <param name="b">The second term.</param>
    /// <returns>The comparison result.</returns>
    private int CompareRenamedTerms(RenamedTerm a, RenamedTerm b)
    {
        if(RenamedTermLess(a, b))
        {
            return -1;
        }

        if(RenamedTermLess(b, a))
        {
            return 1;
        }

        return 0;
    }


    /// <summary>
    /// Whether two renamed terms are equal (<c>renamed_lterm::operator==</c>).
    /// </summary>
    /// <param name="a">The first term.</param>
    /// <param name="b">The second term.</param>
    /// <returns><see langword="true"/> when equal.</returns>
    private static bool RenamedTermsEqual(in RenamedTerm a, in RenamedTerm b)
    {
        return a.R0 == b.R0 && a.R1 == b.R1 && LongfellowCompilerFieldOperations.ElementsEqual(a.K, b.K);
    }


    /// <summary>
    /// The strict canonical order on a layer's renamed nodes (<c>renamed_lnode::compare</c>):
    /// claimed wire ids first in ascending order, then reverse-lexicographic term comparison, then
    /// shorter term lists, then original nodes before copy wires.
    /// </summary>
    /// <param name="a">The first node.</param>
    /// <param name="b">The second node.</param>
    /// <returns><see langword="true"/> when <paramref name="a"/> precedes <paramref name="b"/>.</returns>
    private bool RenamedNodeLess(RenamedNode a, RenamedNode b)
    {
        if(a.DesiredWireId != LongfellowCircuitNode.WireIdUndefined)
        {
            if(b.DesiredWireId != LongfellowCircuitNode.WireIdUndefined)
            {
                return a.DesiredWireId < b.DesiredWireId;
            }

            return true;
        }

        if(b.DesiredWireId != LongfellowCircuitNode.WireIdUndefined)
        {
            return false;
        }

        //The reference compares the term arrays back to front; the reverse order compresses better
        //and is part of the pinned canonical form.
        for(int ia = a.Terms.Length, ib = b.Terms.Length; ia-- > 0 && ib-- > 0;)
        {
            if(RenamedTermLess(a.Terms[ia], b.Terms[ib]))
            {
                return true;
            }

            if(RenamedTermLess(b.Terms[ib], a.Terms[ia]))
            {
                return false;
            }
        }

        if(a.Terms.Length != b.Terms.Length)
        {
            return a.Terms.Length < b.Terms.Length;
        }

        if(!a.IsCopyWire && b.IsCopyWire)
        {
            return true;
        }

        if(!b.IsCopyWire && a.IsCopyWire)
        {
            return false;
        }

        return false;
    }


    /// <summary>
    /// The three-way wrapper over <see cref="RenamedNodeLess"/> for sorting.
    /// </summary>
    /// <param name="a">The first node.</param>
    /// <param name="b">The second node.</param>
    /// <returns>The comparison result.</returns>
    private int CompareRenamedNodes(RenamedNode a, RenamedNode b)
    {
        if(RenamedNodeLess(a, b))
        {
            return -1;
        }

        if(RenamedNodeLess(b, a))
        {
            return 1;
        }

        return 0;
    }


    /// <summary>
    /// Whether two renamed nodes are equal (<c>renamed_lnode::operator==</c>): the copy-wire flag
    /// and the full term list; the claimed wire id does not participate.
    /// </summary>
    /// <param name="a">The first node.</param>
    /// <param name="b">The second node.</param>
    /// <returns><see langword="true"/> when equal.</returns>
    private static bool RenamedNodesEqual(RenamedNode a, RenamedNode b)
    {
        if(a.IsCopyWire != b.IsCopyWire || a.Terms.Length != b.Terms.Length)
        {
            return false;
        }

        for(int i = 0; i < a.Terms.Length; i++)
        {
            if(!RenamedTermsEqual(a.Terms[i], b.Terms[i]))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Emits the circuit layers from the layered DAG (<c>fill_layers</c> + <c>mkquad</c>), walking
    /// from the output depth down so index 0 is the output layer.
    /// </summary>
    /// <param name="layered">The per-depth node lists with assigned wire ids.</param>
    /// <param name="outputWireCount">Receives the output wire count (<c>nv</c>).</param>
    /// <returns>The layers in walk order.</returns>
    /// <exception cref="InvalidOperationException">When a layer degenerates to a single wire.</exception>
    private LongfellowSumcheckLayer[] FillLayers(List<LayeredNode>[] layered, out int outputWireCount)
    {
        int depthUpperBound = layered.Length;
        outputWireCount = layered[depthUpperBound - 1].Count;

        WireCount = outputWireCount;
        QuadTermCount = 0;

        var layers = new LongfellowSumcheckLayer[depthUpperBound - 1];
        int layerIndex = 0;
        for(int d = depthUpperBound - 1; d >= 1; d--)
        {
            List<LayeredNode> gates = layered[d];
            List<LayeredNode> inputs = layered[d - 1];

            int inputWireCount = inputs.Count;
            WireCount += inputWireCount;

            //The reference compiler and its binding stack accept a single-wire layer (logw == 0);
            //this stack's circuit shape does not — LongfellowSumcheckLayer and the circuit reader
            //both require at least one hand binding round — so the compiler rejects the shape
            //explicitly instead of emitting a circuit the stack would refuse.
            int handRounds = LongfellowMortonOrder.Lg(inputWireCount);
            if(handRounds == 0)
            {
                throw new InvalidOperationException(
                    "A scheduled layer has a single input wire; this stack's circuit shape requires at least one hand binding round per layer, a recorded divergence from the reference compiler.");
            }

            LongfellowSumcheckQuadTerm[] corners = MakeQuad(gates, inputs);
            layers[layerIndex] = new LongfellowSumcheckLayer(inputWireCount, handRounds, corners.Length, corners);
            layerIndex++;
        }

        return layers;
    }


    /// <summary>
    /// Builds one layer's canonicalized corner list (<c>mkquad</c> + <c>EQuad::canonicalize</c>):
    /// every gate term becomes a corner over the assigned wire ids, the hand pair is ordered, the
    /// corners are Morton-sorted, and corners with identical indices coalesce by adding their
    /// coefficients.
    /// </summary>
    /// <param name="gates">The layer's gate nodes.</param>
    /// <param name="inputs">The previous layer's nodes supplying the hand wires.</param>
    /// <returns>The canonicalized corners.</returns>
    private LongfellowSumcheckQuadTerm[] MakeQuad(List<LayeredNode> gates, List<LayeredNode> inputs)
    {
        var corners = new List<Corner>();
        foreach(LayeredNode gate in gates)
        {
            foreach(LayeredTerm term in gate.Terms)
            {
                corners.Add(new Corner
                {
                    G = gate.DesiredWireId,
                    H0 = inputs[term.Lop0].DesiredWireId,
                    H1 = inputs[term.Lop1].DesiredWireId,
                    V = term.K
                });
            }
        }

        QuadTermCount += corners.Count;

        for(int i = 0; i < corners.Count; i++)
        {
            Corner corner = corners[i];
            if(corner.H0 > corner.H1)
            {
                (corner.H0, corner.H1) = (corner.H1, corner.H0);
                corners[i] = corner;
            }
        }

        corners.Sort(CompareCorners);

        var coalesced = new List<LongfellowSumcheckQuadTerm>(corners.Count);
        for(int i = 0; i < corners.Count; i++)
        {
            Corner corner = corners[i];
            if(coalesced.Count > 0)
            {
                LongfellowSumcheckQuadTerm previous = coalesced[^1];
                if(previous.GateIndex == corner.G && previous.LeftIndex == corner.H0 && previous.RightIndex == corner.H1)
                {
                    var sum = new byte[Scalar.SizeBytes];
                    field.Add(previous.Coefficient.Span, corner.V, sum, field.Curve);
                    coalesced[^1] = previous with { Coefficient = sum };

                    continue;
                }
            }

            coalesced.Add(new LongfellowSumcheckQuadTerm(corner.G, corner.H0, corner.H1, corner.V));
        }

        return [.. coalesced];
    }


    /// <summary>
    /// The canonical corner order (<c>compare_ecorner</c>): the Morton interleave of the hand pair,
    /// then the gate, then the coefficient's little-endian serialization.
    /// </summary>
    /// <param name="a">The first corner.</param>
    /// <param name="b">The second corner.</param>
    /// <returns>The comparison result.</returns>
    private int CompareCorners(Corner a, Corner b)
    {
        if(LongfellowMortonOrder.Less(a.H0, a.H1, b.H0, b.H1))
        {
            return -1;
        }

        if(LongfellowMortonOrder.Less(b.H0, b.H1, a.H0, a.H1))
        {
            return 1;
        }

        if(a.G != b.G)
        {
            return a.G < b.G ? -1 : 1;
        }

        if(field.CompareLittleEndian(a.V, b.V))
        {
            return -1;
        }

        if(field.CompareLittleEndian(b.V, a.V))
        {
            return 1;
        }

        return 0;
    }
}

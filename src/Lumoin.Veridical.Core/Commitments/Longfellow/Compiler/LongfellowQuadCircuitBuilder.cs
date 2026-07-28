using System;
using System.Collections.Generic;
using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

/// <summary>
/// The Longfellow circuit compiler front end, a faithful port of google/longfellow-zk's
/// <c>QuadCircuit&lt;Field&gt;</c> (<c>lib/circuits/compiler/compiler.h</c>): arithmetic circuit
/// construction over abstract wire labels with inline constant propagation and common-subexpression
/// elimination, compiled by <see cref="MakeCircuit"/> through the layer scheduler into the in-memory
/// <see cref="LongfellowSumcheckCircuit"/> the existing sumcheck prover, verifier and ZK composition
/// consume.
/// </summary>
/// <remarks>
/// <para>
/// Wire handles are node ids into the compiler's DAG, dense in creation order. The constructor pins
/// the constant table so index 0 is the field zero and index 1 the field one, and creates node 0 as
/// the implicit constant-one input wire, so a caller's first <see cref="InputWire"/> receives input
/// position 1 and the witness column starts <c>[one ‖ public ‖ private]</c> exactly as the prover
/// expects.
/// </para>
/// <para>
/// The algebraic rewrites (zero and identity elision, constant folding, peeking through linear
/// nodes, the depth-mismatch <see cref="Linear(int)"/> wrap in <see cref="Add"/>, the sorted term
/// merge dropping cancelled coefficients) are transcribed branch for branch from the reference, as
/// is the dead-node bookkeeping (<c>compute_depth_ub</c>, <c>fixup_last_layer_assertions</c>,
/// <c>compute_needed</c>); the emitted layer structure and the structural circuit id depend on them.
/// The common-subexpression and constant tables bin by a content hash but decide by full equality,
/// so the hash functions themselves do not shape the output.
/// </para>
/// </remarks>
internal sealed class LongfellowQuadCircuitBuilder
{
    private readonly LongfellowCompilerFieldOperations field;
    private readonly List<byte[]> constants = [];
    private readonly Dictionary<ulong, List<int>> constantTable = [];
    private readonly List<LongfellowCircuitNode> nodes = [];
    private readonly Dictionary<ulong, List<int>> subexpressionTable = [];
    private bool isCompiled;

    /// <summary>The number of input wires declared so far (<c>ninput_</c>), including the implicit constant-one wire.</summary>
    public int InputCount { get; private set; }

    /// <summary>The number of public inputs (<c>npub_input_</c>), the index of the first private input; zero until <see cref="PrivateInput"/>.</summary>
    public int PublicInputCount { get; private set; }

    /// <summary>The least input wire not known to lie in the subfield (<c>subfield_boundary_</c>); zero until <see cref="BeginFullField"/>.</summary>
    public int SubfieldBoundary { get; private set; }

    /// <summary>The number of output claims registered (<c>noutput_</c>).</summary>
    public int OutputCount { get; private set; }

    /// <summary>The circuit depth upper bound (<c>depth_</c>), set by <see cref="MakeCircuit"/>.</summary>
    public int DepthUpperBound { get; private set; }

    /// <summary>The number of non-linear nodes the common-subexpression table absorbed (<c>nwires_cse_eliminated_</c>).</summary>
    public int EliminatedSubexpressionCount { get; private set; }

    /// <summary>The number of nodes dead-code elimination discarded (<c>nwires_not_needed_</c>), set by <see cref="MakeCircuit"/>.</summary>
    public int NotNeededCount { get; private set; }

    /// <summary>The scheduled wire total (<c>nwires_</c>), set by <see cref="MakeCircuit"/>.</summary>
    public int WireCount { get; private set; }

    /// <summary>The scheduled quad-term total before coalescing (<c>nquad_terms_</c>), set by <see cref="MakeCircuit"/>.</summary>
    public int QuadTermCount { get; private set; }

    /// <summary>The copy wires the scheduler inserted (<c>nwires_overhead_</c>), set by <see cref="MakeCircuit"/>.</summary>
    public int CopyWireOverheadCount { get; private set; }


    /// <summary>
    /// Constructs a builder over a field, pinning constant indices 0 (zero) and 1 (one) and creating
    /// the implicit constant-one input wire as node 0.
    /// </summary>
    /// <param name="field">The field-operation bundle.</param>
    /// <exception cref="ArgumentNullException">When <paramref name="field"/> is <see langword="null"/>.</exception>
    public LongfellowQuadCircuitBuilder(LongfellowCompilerFieldOperations field)
    {
        ArgumentNullException.ThrowIfNull(field);

        this.field = field;

        int zeroIndex = StoreConstant(field.Zero.Span);
        int oneIndex = StoreConstant(field.One.Span);
        if(zeroIndex != 0 || oneIndex != 1)
        {
            throw new InvalidOperationException("The constant table pins zero at index 0 and one at index 1.");
        }

        _ = InputWire();
    }


    /// <summary>
    /// Declares the next input wire and returns its node id. Input positions are dense in call
    /// order; the constructor claims position 0 for the constant-one wire.
    /// </summary>
    /// <returns>The input node id.</returns>
    public int InputWire()
    {
        ThrowIfCompiled();

        int position = InputCount;
        InputCount++;

        return PushNode(LongfellowCircuitNode.CreateInput(position));
    }


    /// <summary>
    /// Demarcates the end of the public inputs and the beginning of the private inputs; callable
    /// once.
    /// </summary>
    /// <exception cref="InvalidOperationException">When called twice.</exception>
    public void PrivateInput()
    {
        ThrowIfCompiled();

        if(PublicInputCount != 0)
        {
            throw new InvalidOperationException("The public/private input boundary can be set only once.");
        }

        PublicInputCount = InputCount;
    }


    /// <summary>
    /// Demarcates the end of the subfield private inputs and the beginning of the full-field private
    /// inputs; callable once.
    /// </summary>
    /// <exception cref="InvalidOperationException">When called twice.</exception>
    public void BeginFullField()
    {
        ThrowIfCompiled();

        if(SubfieldBoundary != 0)
        {
            throw new InvalidOperationException("The subfield/full-field boundary can be set only once.");
        }

        SubfieldBoundary = InputCount;
    }


    /// <summary>
    /// A linear barrier <c>1·(w0·op)</c> the simplifier does not fold away, protecting a common
    /// subexpression from being absorbed into a parent term.
    /// </summary>
    /// <param name="op">The node to wrap.</param>
    /// <returns>The barrier node id.</returns>
    public int Linear(int op)
    {
        return Mul(0, op);
    }


    /// <summary>
    /// A scaled linear barrier <c>k·(w0·op)</c>.
    /// </summary>
    /// <param name="k">The coefficient, canonical big-endian.</param>
    /// <param name="op">The node to wrap.</param>
    /// <returns>The barrier node id.</returns>
    public int Linear(ReadOnlySpan<byte> k, int op)
    {
        return Mul(k, 0, op);
    }


    /// <summary>
    /// Scales a node by a constant: <c>k · op</c>, folding the zero and one cases.
    /// </summary>
    /// <param name="k">The coefficient, canonical big-endian.</param>
    /// <param name="op">The node to scale.</param>
    /// <returns>The scaled node id.</returns>
    public int Mul(ReadOnlySpan<byte> k, int op)
    {
        ThrowIfCompiled();

        if(LongfellowCompilerFieldOperations.ElementsEqual(k, field.Zero.Span))
        {
            return Konst(k);
        }

        if(LongfellowCompilerFieldOperations.ElementsEqual(k, field.One.Span) || nodes[op].IsZero)
        {
            return op;
        }

        return PushNode(Scale(k, op));
    }


    /// <summary>
    /// Multiplies two nodes: <c>op0 · op1</c>.
    /// </summary>
    /// <param name="op0">The first operand node.</param>
    /// <param name="op1">The second operand node.</param>
    /// <returns>The product node id.</returns>
    public int Mul(int op0, int op1)
    {
        return Mul(field.One.Span, op0, op1);
    }


    /// <summary>
    /// A scaled product <c>k · op0 · op1</c>, folding zero, constant and linear operands into the
    /// coefficient before emitting a general quad term.
    /// </summary>
    /// <param name="k">The coefficient, canonical big-endian.</param>
    /// <param name="op0">The first operand node.</param>
    /// <param name="op1">The second operand node.</param>
    /// <returns>The product node id.</returns>
    public int Mul(ReadOnlySpan<byte> k, int op0, int op1)
    {
        ThrowIfCompiled();

        var coefficient = new byte[Scalar.SizeBytes];
        k.CopyTo(coefficient);

        //The reference recurses through the fold arms; each pass either folds a constant or linear
        //left operand into the coefficient, swaps a foldable right operand into position, or exits.
        while(true)
        {
            LongfellowCircuitNode n0 = nodes[op0];
            LongfellowCircuitNode n1 = nodes[op1];

            if(n0.IsZero)
            {
                return op0;
            }

            if(n0.IsConstant)
            {
                MultiplyInto(coefficient, constants[n0.Terms[0].Ki]);

                return Mul(coefficient, op1);
            }

            if(n0.IsLinear)
            {
                MultiplyInto(coefficient, constants[n0.Terms[0].Ki]);
                op0 = n0.Terms[0].Op1;

                continue;
            }

            if(n1.IsZero || n1.IsConstant || n1.IsLinear)
            {
                (op0, op1) = (op1, op0);

                continue;
            }

            return PushNode(LongfellowCircuitNode.CreateTerm(StoreConstant(coefficient), op0, op1));
        }
    }


    /// <summary>
    /// Adds two nodes. Addends of unequal depth are not merged directly: the shallower one is
    /// wrapped in a <see cref="Linear(int)"/> barrier first, the reference's layer-packing
    /// heuristic.
    /// </summary>
    /// <param name="op0">The first addend node.</param>
    /// <param name="op1">The second addend node.</param>
    /// <returns>The sum node id.</returns>
    public int Add(int op0, int op1)
    {
        ThrowIfCompiled();

        if(nodes[op0].IsZero)
        {
            return op1;
        }

        if(nodes[op1].IsZero)
        {
            return op0;
        }

        if(nodes[op0].Depth < nodes[op1].Depth)
        {
            op0 = Linear(op0);
        }
        else if(nodes[op1].Depth < nodes[op0].Depth)
        {
            op1 = Linear(op1);
        }

        return PushNode(Merge(op0, op1));
    }


    /// <summary>
    /// Subtracts <paramref name="op1"/> from <paramref name="op0"/> as <c>op0 + (−1)·op1</c>.
    /// </summary>
    /// <param name="op0">The minuend node.</param>
    /// <param name="op1">The subtrahend node.</param>
    /// <returns>The difference node id.</returns>
    public int Sub(int op0, int op1)
    {
        return Add(op0, Mul(field.MinusOne.Span, op1));
    }


    /// <summary>
    /// A constant node <c>k·(w0·w0)</c>; the field zero yields the shared zero node.
    /// </summary>
    /// <param name="k">The constant, canonical big-endian.</param>
    /// <returns>The constant node id.</returns>
    public int Konst(ReadOnlySpan<byte> k)
    {
        ThrowIfCompiled();

        return PushNode(LongfellowCircuitNode.CreateTerm(StoreConstant(k), 0, 0));
    }


    /// <summary>
    /// Fused multiply-add <c>y + a·x</c> through a linear barrier, skipping the work when
    /// <paramref name="a"/> is zero.
    /// </summary>
    /// <param name="y">The accumulator node.</param>
    /// <param name="a">The coefficient, canonical big-endian.</param>
    /// <param name="x">The scaled node.</param>
    /// <returns>The result node id.</returns>
    public int Axpy(int y, ReadOnlySpan<byte> a, int x)
    {
        if(LongfellowCompilerFieldOperations.ElementsEqual(a, field.Zero.Span))
        {
            return y;
        }

        return Add(y, Linear(a, x));
    }


    /// <summary>
    /// Adds a constant, <c>y + a</c>, skipping the work when <paramref name="a"/> is zero.
    /// </summary>
    /// <param name="y">The accumulator node.</param>
    /// <param name="a">The constant, canonical big-endian.</param>
    /// <returns>The result node id.</returns>
    public int Apy(int y, ReadOnlySpan<byte> a)
    {
        if(LongfellowCompilerFieldOperations.ElementsEqual(a, field.Zero.Span))
        {
            return y;
        }

        return Add(y, Konst(a));
    }


    /// <summary>
    /// Asserts that a node's value is zero via the special <c>0·(1·op)</c> form. Linear nodes reduce
    /// to an assertion on their operand; the identically-zero node needs no assertion at all.
    /// </summary>
    /// <param name="op">The node whose value must be zero.</param>
    /// <returns>The assertion node id, or <paramref name="op"/> when no assertion is generated.</returns>
    public int AssertZero(int op)
    {
        ThrowIfCompiled();

        while(true)
        {
            LongfellowCircuitNode n = nodes[op];
            if(n.IsZero)
            {
                return op;
            }

            if(n.IsLinear)
            {
                if(n.Terms[0].Ki == 0)
                {
                    return op;
                }

                op = n.Terms[0].Op1;

                continue;
            }

            var assertion = new LongfellowCircuitNode([LongfellowCompilerTerm.CreateAssertZero(op)])
            {
                IsAssertZero = true
            };

            return PushNode(assertion);
        }
    }


    /// <summary>
    /// Registers a node as a circuit output at a given output wire position.
    /// </summary>
    /// <param name="node">The node whose value is the output.</param>
    /// <param name="outputWireId">The output wire position the value claims in the last layer.</param>
    public void OutputWire(int node, int outputWireId)
    {
        ThrowIfCompiled();
        ArgumentOutOfRangeException.ThrowIfNegative(outputWireId);

        MarkOutput(node, outputWireId);
    }


    /// <summary>
    /// Compiles the DAG: computes the depth bound, converts last-layer assertions into outputs,
    /// runs dead-code elimination, schedules the layers, computes the structural circuit id, and
    /// emits the in-memory circuit. Callable once; the builder rejects further construction
    /// afterwards.
    /// </summary>
    /// <param name="copyCount">The number of circuit copies (<c>nc</c>); the sc wire segment requires one.</param>
    /// <param name="hashFactory">The incremental SHA-256 factory the structural id streams through.</param>
    /// <returns>The compiled circuit.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="hashFactory"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="copyCount"/> is not positive.</exception>
    /// <exception cref="InvalidOperationException">When called twice, when no output or assertion exists, or when a scheduled layer degenerates.</exception>
    public LongfellowSumcheckCircuit MakeCircuit(int copyCount, LongfellowIncrementalHashFactory hashFactory)
    {
        ThrowIfCompiled();
        ArgumentNullException.ThrowIfNull(hashFactory);
        ArgumentOutOfRangeException.ThrowIfLessThan(copyCount, 1);

        isCompiled = true;

        int depthUpperBound = ComputeDepthUpperBound();
        if(depthUpperBound < 2)
        {
            throw new InvalidOperationException("The circuit needs at least one output or assertion above the input layer.");
        }

        FixupLastLayerAssertions(depthUpperBound);
        ComputeNeeded(depthUpperBound);

        var scheduler = new LongfellowCircuitScheduler(nodes, constants, field);
        LongfellowSumcheckLayer[] layers = scheduler.Schedule(depthUpperBound, out int outputWireCount);

        WireCount = scheduler.WireCount;
        QuadTermCount = scheduler.QuadTermCount;
        CopyWireOverheadCount = scheduler.CopyWireOverheadCount;

        int outputLogCount = LongfellowMortonOrder.Lg(outputWireCount);
        int copyRounds = LongfellowMortonOrder.Lg(copyCount);

        byte[] id = LongfellowCircuitIdentifier.Compute(
            field,
            outputWireCount,
            outputLogCount,
            copyCount,
            copyRounds,
            InputCount,
            PublicInputCount,
            SubfieldBoundary,
            layers,
            hashFactory);

        return new LongfellowSumcheckCircuit(
            outputWireCount,
            outputLogCount,
            copyCount,
            copyRounds,
            InputCount,
            PublicInputCount,
            id,
            layers);
    }


    /// <summary>
    /// Marks a node as an output claiming a wire position (<c>output_internal</c>); the last-layer
    /// assertion fixup passes <see cref="LongfellowCircuitNode.WireIdUndefined"/>.
    /// </summary>
    /// <param name="node">The node id.</param>
    /// <param name="outputWireId">The claimed position, or <see cref="LongfellowCircuitNode.WireIdUndefined"/>.</param>
    /// <exception cref="InvalidOperationException">When the node is already an output.</exception>
    private void MarkOutput(int node, int outputWireId)
    {
        LongfellowCircuitNode n = nodes[node];
        if(n.IsOutput)
        {
            throw new InvalidOperationException("The node is already registered as an output.");
        }

        n.IsOutput = true;
        n.DesiredWireIdForOutput = outputWireId;
        OutputCount++;
    }


    /// <summary>
    /// Pushes a node into the DAG, returning an existing equal node's id instead when the
    /// common-subexpression table holds one; otherwise assigns the node's depth and id.
    /// </summary>
    /// <param name="candidate">The node to push.</param>
    /// <returns>The node id.</returns>
    private int PushNode(LongfellowCircuitNode candidate)
    {
        ulong hash = candidate.ContentHash();
        if(subexpressionTable.TryGetValue(hash, out List<int>? bucket))
        {
            foreach(int existing in bucket)
            {
                if(candidate.ContentEquals(nodes[existing]))
                {
                    //Linear barriers are placeholders the next layer absorbs, so they do not count
                    //as eliminated wires.
                    if(!candidate.IsLinear)
                    {
                        EliminatedSubexpressionCount++;
                    }

                    return existing;
                }
            }
        }

        int depth = 0;
        foreach(LongfellowCompilerTerm term in candidate.Terms)
        {
            depth = Math.Max(depth, 1 + Math.Max(nodes[term.Op0].Depth, nodes[term.Op1].Depth));
        }

        candidate.Depth = depth;

        int id = nodes.Count;
        nodes.Add(candidate);

        if(bucket is null)
        {
            bucket = [];
            subexpressionTable.Add(hash, bucket);
        }

        bucket.Add(id);

        return id;
    }


    /// <summary>
    /// The materialized term view of a node (<c>materialize_input</c>): an input wire becomes the
    /// single term <c>1·(w0·op)</c>; any other node contributes its own terms. A node already
    /// registered as an output cannot be absorbed into a new expression.
    /// </summary>
    /// <param name="op">The node id.</param>
    /// <returns>The term list.</returns>
    /// <exception cref="InvalidOperationException">When a non-input output node is materialized.</exception>
    private LongfellowCompilerTerm[] MaterializeTerms(int op)
    {
        LongfellowCircuitNode n = nodes[op];
        if(n.IsInput)
        {
            return [new LongfellowCompilerTerm(1, 0, op)];
        }

        if(n.IsOutput)
        {
            throw new InvalidOperationException("An output node cannot be absorbed into a new expression.");
        }

        return n.Terms;
    }


    /// <summary>
    /// Scales a node's materialized terms by a constant (<c>scale</c>), folding each coefficient
    /// through the constant table.
    /// </summary>
    /// <param name="k">The coefficient, canonical big-endian.</param>
    /// <param name="op">The node id.</param>
    /// <returns>The scaled node.</returns>
    private LongfellowCircuitNode Scale(ReadOnlySpan<byte> k, int op)
    {
        LongfellowCompilerTerm[] source = MaterializeTerms(op);
        var scaled = new LongfellowCompilerTerm[source.Length];
        var product = new byte[Scalar.SizeBytes];
        for(int i = 0; i < source.Length; i++)
        {
            field.Multiply(constants[source[i].Ki], k, product, field.Curve);
            scaled[i] = source[i].WithCoefficientIndex(StoreConstant(product));
        }

        return new LongfellowCircuitNode(scaled);
    }


    /// <summary>
    /// Merges two nodes' materialized terms into one sorted sum (<c>merge</c>), adding coefficients
    /// on equal operand pairs and dropping terms whose coefficients cancel to zero.
    /// </summary>
    /// <param name="op0">The first node id.</param>
    /// <param name="op1">The second node id.</param>
    /// <returns>The merged node.</returns>
    private LongfellowCircuitNode Merge(int op0, int op1)
    {
        LongfellowCompilerTerm[] t0 = MaterializeTerms(op0);
        LongfellowCompilerTerm[] t1 = MaterializeTerms(op1);
        var merged = new List<LongfellowCompilerTerm>(t0.Length + t1.Length);
        var sum = new byte[Scalar.SizeBytes];

        int i0 = 0;
        int i1 = 0;
        while(i0 < t0.Length && i1 < t1.Length)
        {
            LongfellowCompilerTerm term;
            if(t0[i0].SameIndex(t1[i1]))
            {
                field.Add(constants[t0[i0].Ki], constants[t1[i1].Ki], sum, field.Curve);
                term = t0[i0].WithCoefficientIndex(StoreConstant(sum));
                i0++;
                i1++;
            }
            else if(t0[i0].PrecedesByIndex(t1[i1]))
            {
                term = t0[i0];
                i0++;
            }
            else
            {
                term = t1[i1];
                i1++;
            }

            AddUnlessZero(merged, term);
        }

        while(i0 < t0.Length)
        {
            AddUnlessZero(merged, t0[i0]);
            i0++;
        }

        while(i1 < t1.Length)
        {
            AddUnlessZero(merged, t1[i1]);
            i1++;
        }

        return new LongfellowCircuitNode([.. merged]);
    }


    /// <summary>
    /// Appends a term unless its coefficient is the zero constant (<c>push_back_unless_zero</c>).
    /// </summary>
    /// <param name="terms">The term list under construction.</param>
    /// <param name="term">The candidate term.</param>
    private static void AddUnlessZero(List<LongfellowCompilerTerm> terms, in LongfellowCompilerTerm term)
    {
        if(term.Ki != 0)
        {
            terms.Add(term);
        }
    }


    /// <summary>
    /// Stores a constant once and returns its table index (<c>kstore</c>); lookups bin by a content
    /// hash and decide by byte equality.
    /// </summary>
    /// <param name="k">The constant, canonical big-endian.</param>
    /// <returns>The constant-table index.</returns>
    private int StoreConstant(ReadOnlySpan<byte> k)
    {
        ulong hash = HashElement(k);
        if(constantTable.TryGetValue(hash, out List<int>? bucket))
        {
            foreach(int existing in bucket)
            {
                if(LongfellowCompilerFieldOperations.ElementsEqual(k, constants[existing]))
                {
                    return existing;
                }
            }
        }

        int index = constants.Count;
        constants.Add(k.ToArray());

        if(bucket is null)
        {
            bucket = [];
            constantTable.Add(hash, bucket);
        }

        bucket.Add(index);

        return index;
    }


    /// <summary>
    /// A deterministic 64-bit hash binning constant-table lookups; equality decides membership.
    /// </summary>
    /// <param name="element">The element bytes.</param>
    /// <returns>The hash.</returns>
    private static ulong HashElement(ReadOnlySpan<byte> element)
    {
        const ulong OffsetBasis = 0xCBF29CE484222325ul;
        const ulong Prime = 0x100000001B3ul;

        ulong hash = OffsetBasis;
        foreach(byte b in element)
        {
            hash = (hash ^ b) * Prime;
        }

        return hash;
    }


    /// <summary>
    /// Multiplies a coefficient in place by a constant.
    /// </summary>
    /// <param name="coefficient">The coefficient, canonical big-endian; receives the product.</param>
    /// <param name="k">The constant to fold in.</param>
    private void MultiplyInto(byte[] coefficient, byte[] k)
    {
        var product = new byte[Scalar.SizeBytes];
        field.Multiply(coefficient, k, product, field.Curve);
        product.CopyTo(coefficient, 0);
    }


    /// <summary>
    /// The circuit depth upper bound (<c>compute_depth_ub</c>): one past the deepest output, with
    /// linear last-layer assertions contributing their own depth because the fixup converts them
    /// into outputs of their operand.
    /// </summary>
    /// <returns>The depth upper bound.</returns>
    private int ComputeDepthUpperBound()
    {
        int bound = 0;
        foreach(LongfellowCircuitNode n in nodes)
        {
            if(n.IsOutput)
            {
                bound = Math.Max(bound, 1 + n.Depth);
            }
            else if(n.IsAssertZero)
            {
                bound = n.IsLinear
                    ? Math.Max(bound, n.Depth)
                    : Math.Max(bound, 1 + n.Depth);
            }
        }

        DepthUpperBound = bound;

        return bound;
    }


    /// <summary>
    /// Converts linear assertions sitting in the last layer into outputs of their asserted operand
    /// (<c>fixup_last_layer_assertions</c>); the outputs-are-zero convention then carries the
    /// assertion.
    /// </summary>
    /// <param name="depthUpperBound">The depth upper bound.</param>
    private void FixupLastLayerAssertions(int depthUpperBound)
    {
        int count = nodes.Count;
        for(int i = 0; i < count; i++)
        {
            LongfellowCircuitNode n = nodes[i];
            if(!n.IsOutput && n.IsAssertZero && n.Depth == depthUpperBound && n.IsLinear)
            {
                n.IsAssertZero = false;
                MarkOutput(n.Terms[0].Op1, LongfellowCircuitNode.WireIdUndefined);
            }
        }
    }


    /// <summary>
    /// Dead-code elimination (<c>compute_needed</c>): walks the DAG from the newest node down,
    /// marking inputs, outputs, assertions and every term operand of a needed node, and counts the
    /// discarded remainder.
    /// </summary>
    /// <param name="depthUpperBound">The depth upper bound.</param>
    private void ComputeNeeded(int depthUpperBound)
    {
        NotNeededCount = 0;
        for(int i = nodes.Count - 1; i >= 0; i--)
        {
            LongfellowCircuitNode n = nodes[i];

            //Inputs are always kept so the witness column layout stays unambiguous.
            if(n.IsInput)
            {
                MarkNeeded(i, 1);
            }

            if(n.IsOutput)
            {
                MarkNeeded(i, depthUpperBound);
            }

            if(n.IsAssertZero)
            {
                MarkNeeded(i, n.Depth + 1);
            }

            if(n.IsNeeded)
            {
                foreach(LongfellowCompilerTerm term in n.Terms)
                {
                    MarkNeeded(term.Op0, n.Depth);
                    MarkNeeded(term.Op1, n.Depth);
                }
            }
            else
            {
                NotNeededCount++;
            }
        }
    }


    /// <summary>
    /// Marks a node as needed at a layer (<c>mark_needed</c>). A node consumed more than one layer
    /// above its own depth is carried by copy wires, and every copy wire multiplies by the
    /// constant-one wire, so node 0 is then needed at the layer below the consumer.
    /// </summary>
    /// <param name="op">The node id.</param>
    /// <param name="depthAtWhichNeeded">The layer that consumes the node.</param>
    private void MarkNeeded(int op, int depthAtWhichNeeded)
    {
        LongfellowCircuitNode n = nodes[op];
        n.IsNeeded = true;
        n.MaxNeededDepth = Math.Max(depthAtWhichNeeded, n.MaxNeededDepth);

        if(depthAtWhichNeeded > n.Depth + 1)
        {
            LongfellowCircuitNode one = nodes[0];
            one.IsNeeded = true;
            one.MaxNeededDepth = Math.Max(depthAtWhichNeeded - 1, one.MaxNeededDepth);
        }
    }


    /// <summary>
    /// Rejects construction after <see cref="MakeCircuit"/> has consumed the DAG.
    /// </summary>
    /// <exception cref="InvalidOperationException">When the builder is already compiled.</exception>
    private void ThrowIfCompiled()
    {
        if(isCompiled)
        {
            throw new InvalidOperationException("The builder has already been compiled; construct a new one for another circuit.");
        }
    }
}

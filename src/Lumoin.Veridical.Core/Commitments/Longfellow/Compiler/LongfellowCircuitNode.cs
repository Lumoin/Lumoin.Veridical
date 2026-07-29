using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow.Compiler;

/// <summary>
/// One term of a compiler DAG node, a port of google/longfellow-zk's <c>term</c>
/// (<c>lib/circuits/compiler/node.h</c>): the product <c>constants[Ki] · w(Op0) · w(Op1)</c> over
/// two operand node ids, canonicalized so <see cref="Op0"/> ≤ <see cref="Op1"/>. A zero constant
/// index is reserved for the assert-zero form <c>0·(1·op)</c> built by
/// <see cref="CreateAssertZero"/>; ordinary terms never carry it because a zero node is an empty
/// term list instead.
/// </summary>
internal readonly struct LongfellowCompilerTerm : IEquatable<LongfellowCompilerTerm>
{
    /// <summary>The index of the coefficient in the compiler's constant table.</summary>
    public int Ki { get; }

    /// <summary>The smaller operand node id.</summary>
    public int Op0 { get; }

    /// <summary>The larger operand node id.</summary>
    public int Op1 { get; }


    /// <summary>
    /// Constructs an ordinary term, canonicalizing the operand order.
    /// </summary>
    /// <param name="ki">The coefficient's constant-table index; never zero for an ordinary term.</param>
    /// <param name="op0">One operand node id.</param>
    /// <param name="op1">The other operand node id.</param>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="ki"/> is zero or an id is negative.</exception>
    public LongfellowCompilerTerm(int ki, int op0, int op1)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(ki, 1);
        ArgumentOutOfRangeException.ThrowIfNegative(op0);
        ArgumentOutOfRangeException.ThrowIfNegative(op1);

        Ki = ki;
        Op0 = Math.Min(op0, op1);
        Op1 = Math.Max(op0, op1);
    }


    /// <summary>
    /// Constructs a raw term without operand canonicalization or the nonzero-coefficient guard; the
    /// assert-zero factory and the term-merge path use it for already-ordered content.
    /// </summary>
    /// <param name="ki">The coefficient's constant-table index.</param>
    /// <param name="op0">The smaller operand node id.</param>
    /// <param name="op1">The larger operand node id.</param>
    /// <param name="ordered">Disambiguates from the canonicalizing constructor; always <see langword="true"/>.</param>
    private LongfellowCompilerTerm(int ki, int op0, int op1, bool ordered)
    {
        Ki = ki;
        Op0 = op0;
        Op1 = op1;
        _ = ordered;
    }


    /// <summary>
    /// The assert-zero form <c>0·(1·op)</c>, the only term carrying constant index zero.
    /// </summary>
    /// <param name="op">The node whose value is asserted to be zero.</param>
    /// <returns>The assert-zero term.</returns>
    public static LongfellowCompilerTerm CreateAssertZero(int op)
    {
        return new LongfellowCompilerTerm(0, 0, op, ordered: true);
    }


    /// <summary>
    /// Rebuilds a term with a replaced coefficient index, preserving the operand order.
    /// </summary>
    /// <param name="ki">The new coefficient index.</param>
    /// <returns>The rebuilt term.</returns>
    public LongfellowCompilerTerm WithCoefficientIndex(int ki)
    {
        return new LongfellowCompilerTerm(ki, Op0, Op1, ordered: true);
    }


    /// <summary>The operand-index order the term merge walks (<c>ltndx</c>): <see cref="Op1"/> major, then <see cref="Op0"/>.</summary>
    /// <param name="other">The term to compare against.</param>
    /// <returns><see langword="true"/> when this term's operand pair precedes the other's.</returns>
    public bool PrecedesByIndex(in LongfellowCompilerTerm other)
    {
        if(Op1 != other.Op1)
        {
            return Op1 < other.Op1;
        }

        return Op0 < other.Op0;
    }


    /// <summary>Whether the operand pairs match (<c>eqndx</c>), regardless of coefficient.</summary>
    /// <param name="other">The term to compare against.</param>
    /// <returns><see langword="true"/> when the operand pairs match.</returns>
    public bool SameIndex(in LongfellowCompilerTerm other)
    {
        return Op0 == other.Op0 && Op1 == other.Op1;
    }


    /// <summary>Whether the term is a constant, both operands being the constant-one wire.</summary>
    public bool IsConstant => Op0 == 0 && Op1 == 0;

    /// <summary>Whether the term is linear, <c>k · (w0 · Op1)</c>.</summary>
    public bool IsLinear => Op0 == 0;


    /// <inheritdoc/>
    public bool Equals(LongfellowCompilerTerm other)
    {
        return Ki == other.Ki && Op0 == other.Op0 && Op1 == other.Op1;
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return obj is LongfellowCompilerTerm other && Equals(other);
    }


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return HashCode.Combine(Ki, Op0, Op1);
    }
}


/// <summary>
/// One compiler DAG node, a port of google/longfellow-zk's <c>NodeF</c> + <c>NodeInfoF</c>
/// (<c>lib/circuits/compiler/node.h</c>): a sum of <see cref="LongfellowCompilerTerm"/>s plus the
/// bookkeeping the depth computation, the needed-marking pass and the scheduler read. A node with no
/// terms and no input flag is the zero node.
/// </summary>
internal sealed class LongfellowCircuitNode
{
    /// <summary>The sentinel for an unassigned desired wire id (<c>kWireIdUndefined</c>).</summary>
    public const int WireIdUndefined = -1;

    /// <summary>The node's terms; empty for the zero node and for input wires.</summary>
    public LongfellowCompilerTerm[] Terms { get; }

    /// <summary>The node's depth in the DAG; inputs sit at zero, set once by the builder's push.</summary>
    public int Depth { get; set; }

    /// <summary>The input wire id claimed at depth zero, or <see cref="WireIdUndefined"/>.</summary>
    public int DesiredWireIdForInput { get; set; } = WireIdUndefined;

    /// <summary>The output wire id claimed at the last layer, or <see cref="WireIdUndefined"/>.</summary>
    public int DesiredWireIdForOutput { get; set; } = WireIdUndefined;

    /// <summary>The deepest layer at which some other node consumes this one.</summary>
    public int MaxNeededDepth { get; set; }

    /// <summary>Whether the node survives dead-code elimination.</summary>
    public bool IsNeeded { get; set; }

    /// <summary>Whether the node is a circuit output.</summary>
    public bool IsOutput { get; set; }

    /// <summary>Whether the node is an input wire.</summary>
    public bool IsInput { get; set; }

    /// <summary>Whether the node is an assert-zero node.</summary>
    public bool IsAssertZero { get; set; }


    /// <summary>
    /// Constructs an input-wire node claiming the given input position.
    /// </summary>
    /// <param name="desiredInputWireId">The input wire id, dense in declaration order.</param>
    /// <returns>The input node.</returns>
    public static LongfellowCircuitNode CreateInput(int desiredInputWireId)
    {
        return new LongfellowCircuitNode([])
        {
            IsInput = true,
            DesiredWireIdForInput = desiredInputWireId
        };
    }


    /// <summary>
    /// Constructs a single-term node <c>constants[ki] · w(op0) · w(op1)</c>; a zero coefficient
    /// index yields the zero node (an empty term list) instead.
    /// </summary>
    /// <param name="ki">The coefficient's constant-table index.</param>
    /// <param name="op0">One operand node id.</param>
    /// <param name="op1">The other operand node id.</param>
    /// <returns>The node.</returns>
    public static LongfellowCircuitNode CreateTerm(int ki, int op0, int op1)
    {
        return ki == 0
            ? new LongfellowCircuitNode([])
            : new LongfellowCircuitNode([new LongfellowCompilerTerm(ki, op0, op1)]);
    }


    /// <summary>
    /// Constructs a node over an already-ordered term list.
    /// </summary>
    /// <param name="terms">The terms, sorted by the merge order.</param>
    public LongfellowCircuitNode(LongfellowCompilerTerm[] terms)
    {
        ArgumentNullException.ThrowIfNull(terms);

        Terms = terms;
    }


    /// <summary>Whether the node is the zero node: no terms and not an input.</summary>
    public bool IsZero => !IsInput && Terms.Length == 0;

    /// <summary>Whether the node is a single constant term.</summary>
    public bool IsConstant => Terms.Length == 1 && Terms[0].IsConstant;

    /// <summary>Whether the node is a single linear term <c>k · (w0 · op)</c>.</summary>
    public bool IsLinear => Terms.Length == 1 && Terms[0].IsLinear;


    /// <summary>
    /// The content equality the common-subexpression table applies, the port of the reference
    /// node's <c>operator==</c>: the input and assertion flags, the desired input wire id and the
    /// full term list. Output-ness does not count towards wire equality — it is a compiler
    /// annotation like depth, so a recomputed expression unifies with a node already marked as an
    /// output.
    /// </summary>
    /// <param name="other">The node to compare against.</param>
    /// <returns><see langword="true"/> when the contents match.</returns>
    public bool ContentEquals(LongfellowCircuitNode other)
    {
        if(IsInput != other.IsInput
            || IsAssertZero != other.IsAssertZero
            || DesiredWireIdForInput != other.DesiredWireIdForInput
            || Terms.Length != other.Terms.Length)
        {
            return false;
        }

        for(int i = 0; i < Terms.Length; i++)
        {
            if(!Terms[i].Equals(other.Terms[i]))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// A deterministic 64-bit content hash binning the common-subexpression lookups; equality is
    /// decided by <see cref="ContentEquals"/>, so the hash function itself does not shape the
    /// emitted circuit.
    /// </summary>
    /// <returns>The content hash.</returns>
    public ulong ContentHash()
    {
        const ulong OffsetBasis = 0xCBF29CE484222325ul;
        const ulong Prime = 0x100000001B3ul;

        ulong hash = OffsetBasis;
        hash = (hash ^ (uint)DesiredWireIdForInput) * Prime;
        hash = (hash ^ (IsInput ? 1ul : 0ul)) * Prime;
        hash = (hash ^ (IsAssertZero ? 1ul : 0ul)) * Prime;
        hash = (hash ^ (ulong)Terms.Length) * Prime;
        foreach(LongfellowCompilerTerm term in Terms)
        {
            hash = (hash ^ (ulong)term.Ki) * Prime;
            hash = (hash ^ (ulong)term.Op0) * Prime;
            hash = (hash ^ (ulong)term.Op1) * Prime;
        }

        return hash;
    }


    /// <summary>
    /// The desired wire id at a given layer position (<c>NodeInfoF::desired_wire_id</c>): the input
    /// id at depth zero, the output id at the last layer, undefined elsewhere — copy wires never
    /// inherit a claim.
    /// </summary>
    /// <param name="depth">The layer depth being assigned.</param>
    /// <param name="depthUpperBound">The circuit's depth upper bound.</param>
    /// <returns>The claimed wire id or <see cref="WireIdUndefined"/>.</returns>
    public int DesiredWireIdAt(int depth, int depthUpperBound)
    {
        if(IsInput && depth == 0)
        {
            return DesiredWireIdForInput;
        }

        if(IsOutput && depth + 1 == depthUpperBound)
        {
            return DesiredWireIdForOutput;
        }

        return WireIdUndefined;
    }
}

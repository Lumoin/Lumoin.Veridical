using System;
using System.Collections.Immutable;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// The canonical form of a programmatically-constructed R1CS circuit: a
/// curve, an immutable ordered list of operations, and the variable
/// metadata describing each position. This is what
/// <see cref="R1csCircuitBuilder"/> produces and what
/// <c>Compile</c> consumes.
/// </summary>
/// <remarks>
/// <para>
/// A circuit is reusable: the same circuit compiles against many different
/// input bindings to produce many <see cref="RawR1csInstance"/> /
/// <see cref="RawR1csWitness"/> pairs (the same "x is in [a, b]" statement
/// for many different x). The operations list — not the compiled matrix
/// triples — is the canonical representation, so that a later optimisation
/// pass (out of scope here) would rewrite operations rather than matrices.
/// </para>
/// <para>
/// Equality is structural over the curve, the counts, and the element
/// sequences of <see cref="Operations"/> and <see cref="Variables"/>:
/// building the same circuit twice yields equal circuits. (The default
/// record equality cannot provide this, because an
/// <see cref="ImmutableArray{T}"/> field compares by underlying-array
/// reference, not element-wise.)
/// </para>
/// </remarks>
public sealed record R1csCircuit
{
    /// <summary>The curve whose scalar field the circuit compiles over.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The ordered operations: variable declarations and constraints, in construction order.</summary>
    public ImmutableArray<IR1csOp> Operations { get; }

    /// <summary>One entry per variable position, index 0 (the constant one) first.</summary>
    public ImmutableArray<R1csVariableMetadata> Variables { get; }

    /// <summary>The number of public inputs (variable positions <c>1..1+PublicInputCount</c>).</summary>
    public int PublicInputCount { get; }

    /// <summary>The number of witness and intermediate variables (positions after the public inputs).</summary>
    public int WitnessVariableCount { get; }

    /// <summary>The total number of variable positions, including the constant one. Equals <see cref="Variables"/> length.</summary>
    public int VariableCount => Variables.Length;


    /// <summary>Constructs a circuit from its parts. Normally produced by <see cref="R1csCircuitBuilder.Build"/> rather than directly.</summary>
    public R1csCircuit(
        CurveParameterSet curve,
        ImmutableArray<IR1csOp> operations,
        ImmutableArray<R1csVariableMetadata> variables,
        int publicInputCount,
        int witnessVariableCount)
    {
        Curve = curve;
        Operations = operations;
        Variables = variables;
        PublicInputCount = publicInputCount;
        WitnessVariableCount = witnessVariableCount;
    }


    /// <summary>Structural equality over curve, counts, and the operation and variable sequences.</summary>
    public bool Equals(R1csCircuit? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Curve.Code == other.Curve.Code
            && PublicInputCount == other.PublicInputCount
            && WitnessVariableCount == other.WitnessVariableCount
            && Operations.AsSpan().SequenceEqual(other.Operations.AsSpan())
            && Variables.AsSpan().SequenceEqual(other.Variables.AsSpan());
    }


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(Curve.Code);
        hash.Add(PublicInputCount);
        hash.Add(WitnessVariableCount);
        foreach(IR1csOp op in Operations)
        {
            hash.Add(op);
        }

        foreach(R1csVariableMetadata variable in Variables)
        {
            hash.Add(variable);
        }

        return hash.ToHashCode();
    }
}

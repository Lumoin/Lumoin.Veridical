using Lumoin.Veridical.Core.Common;
using System.Collections.Immutable;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Builds an <see cref="R1csCircuit"/> by folding transformations over a seed
/// circuit (the constant-one wire). The fluent surface — variable
/// declarations, constraints, and predicates — lives in extension blocks
/// (<see cref="R1csCircuitBuilderDeclarationExtensions"/>,
/// <see cref="R1csCircuitBuilderPredicates"/>); structural transformations
/// such as power-of-two padding compose through <see cref="R1csBuilder{TResult, TState, TBuilder}.With"/>
/// (<see cref="R1csCircuitTransformations"/>).
/// </summary>
/// <remarks>
/// <para>
/// This is the fold/aggregate <see cref="R1csBuilder{TResult, TState, TBuilder}"/>
/// pattern shared with the Verifiable library. Each declaration computes its
/// variable index <em>eagerly</em> — incrementing <see cref="NextVariableIndex"/>
/// during the fluent call so the caller can reference the returned index in
/// later constraint expressions — and appends a transformation (capturing that
/// index in its closure) that writes the declaration into the accumulating
/// circuit when <see cref="Build()"/> folds. The eager moving parts
/// (<see cref="NextVariableIndex"/>, <see cref="PublicInputsLocked"/>,
/// <see cref="State"/>) live on the builder; the deferred work lives in the
/// transformation list. <see cref="Build()"/> is idempotent.
/// </para>
/// </remarks>
public sealed class R1csCircuitBuilder: R1csBuilder<R1csCircuit, R1csBuildState, R1csCircuitBuilder>
{
    /// <summary>The next free variable index. Starts at 1; index 0 is the constant-one wire. Incremented eagerly as variables are declared.</summary>
    internal int NextVariableIndex = 1;

    /// <summary>True once the first witness/intermediate variable or constraint is added; further public inputs are then rejected (the contiguity rule).</summary>
    internal bool PublicInputsLocked;

    /// <summary>The build-state side-channel, updated as declarations add to the name map.</summary>
    internal R1csBuildState State;


    /// <summary>The curve this builder constructs over.</summary>
    public CurveParameterSet Curve { get; }


    /// <summary>Starts a builder for <paramref name="curve"/>. The constant-one wire occupies index 0 in the seed.</summary>
    /// <exception cref="System.ArgumentException">When <paramref name="curve"/> is not a wired curve.</exception>
    public R1csCircuitBuilder(CurveParameterSet curve)
    {
        WellKnownCurves.ThrowIfCurveNotWired(curve);

        Curve = curve;
        State = R1csBuildState.Initial(curve);
    }


    /// <summary>
    /// Folds the accumulated declaration and constraint transformations over a
    /// seed circuit consisting of just the constant-one wire. Idempotent —
    /// calling it twice yields equal circuits.
    /// </summary>
    public override R1csCircuit Build()
    {
        var seed = new R1csCircuit(
            Curve,
            ImmutableArray.Create<IR1csOp>(new DeclareConstantOneOp()),
            ImmutableArray.Create(new R1csVariableMetadata(new R1csVariableIndex(0), R1csBuildState.ConstantOneName, R1csVariableKind.ConstantOne)),
            publicInputCount: 0,
            witnessVariableCount: 0);

        return BuildWithState(seed, State);
    }
}

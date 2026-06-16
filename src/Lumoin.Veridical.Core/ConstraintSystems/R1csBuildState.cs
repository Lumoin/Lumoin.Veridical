using Lumoin.Veridical.Core.Common;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// The immutable build-state side-channel threaded through
/// <see cref="R1csCircuitBuilder"/>'s fold. It carries context a
/// transformation may consult — the curve and the name→index map of declared
/// variables — but not the accumulating result itself (that is the
/// <see cref="R1csCircuit"/>).
/// </summary>
/// <remarks>
/// <para>
/// The state is constructed once when the builder is created and replaced by a
/// new value (via <see cref="WithVariable"/>) as each declaration runs;
/// transformations read it but never write back. The moving parts of
/// construction that are <em>not</em> side-channel — the next free variable
/// index and the public-input lock — live on the builder as eager fields, not
/// here, because they are mutated during the fluent call (before the fold) so
/// a caller can reference a returned index immediately.
/// </para>
/// </remarks>
public readonly record struct R1csBuildState(
    CurveParameterSet Curve,
    IReadOnlyDictionary<string, R1csVariableIndex> NamedVariables): IBuilderState
{
    /// <summary>The reserved name of the constant-one wire at index 0; declarations cannot reuse it.</summary>
    public const string ConstantOneName = "one";


    /// <summary>The initial state for <paramref name="curve"/>: only the reserved constant-one name is mapped, to index 0.</summary>
    public static R1csBuildState Initial(CurveParameterSet curve)
    {
        IReadOnlyDictionary<string, R1csVariableIndex> named = ImmutableDictionary
            .Create<string, R1csVariableIndex>(StringComparer.Ordinal)
            .Add(ConstantOneName, new R1csVariableIndex(0));

        return new R1csBuildState(curve, named);
    }


    /// <summary>Returns a new state with <paramref name="name"/> mapped to <paramref name="index"/> added to the name map.</summary>
    public R1csBuildState WithVariable(string name, R1csVariableIndex index)
    {
        ImmutableDictionary<string, R1csVariableIndex> current =
            NamedVariables as ImmutableDictionary<string, R1csVariableIndex>
            ?? NamedVariables.ToImmutableDictionary(StringComparer.Ordinal);

        return this with { NamedVariables = current.Add(name, index) };
    }
}

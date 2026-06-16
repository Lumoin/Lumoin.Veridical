namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Describes one variable position in a built <see cref="R1csCircuit"/>:
/// its index (column in the compiled matrices), the author-supplied name
/// the compiler binds input values by, and what role it plays.
/// </summary>
/// <param name="Index">The variable's position. Equals its slot in the circuit's variable list.</param>
/// <param name="Name">The name the author gave the variable; the key used to bind a value at compile time. Names are unique within a circuit.</param>
/// <param name="Kind">What the variable represents (see <see cref="R1csVariableKind"/>).</param>
public sealed record R1csVariableMetadata(
    R1csVariableIndex Index,
    string Name,
    R1csVariableKind Kind);

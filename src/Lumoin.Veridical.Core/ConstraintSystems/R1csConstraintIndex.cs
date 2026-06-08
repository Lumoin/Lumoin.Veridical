using System.Globalization;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Identifies a constraint position in an R1CS instance. Values are
/// non-negative integers corresponding to rows of the constraint
/// matrices.
/// </summary>
/// <param name="Value">The constraint index.</param>
/// <remarks>
/// Wrapping an <see cref="int"/> in a semantic type prevents accidental
/// confusion with <see cref="R1csVariableIndex"/>.
/// </remarks>
public readonly record struct R1csConstraintIndex(int Value)
{
    /// <summary>Returns the standard human-readable form <c>c_&lt;value&gt;</c>.</summary>
    public override string ToString() => $"c_{Value.ToString(CultureInfo.InvariantCulture)}";
}
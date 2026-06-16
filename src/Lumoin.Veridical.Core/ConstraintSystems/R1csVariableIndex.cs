using System.Globalization;

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Identifies a variable position in an R1CS witness vector. Values are
/// non-negative integers corresponding to columns of the constraint
/// matrices.
/// </summary>
/// <param name="Value">The variable index. Convention: index 0 is the constant 1, indices 1..PublicInputCount are public inputs, the rest are witness variables.</param>
/// <remarks>
/// <para>
/// Wraps an <see cref="int"/> in a semantic type so the API surface
/// refuses to accept a constraint index where a variable index is
/// expected (or vice versa). Both values are integers in C# but the
/// types are not interchangeable.
/// </para>
/// </remarks>
public readonly record struct R1csVariableIndex(int Value)
{
    /// <summary>Returns the standard human-readable form <c>x_&lt;value&gt;</c> for use in inspector reports.</summary>
    public override string ToString() => $"x_{Value.ToString(CultureInfo.InvariantCulture)}";
}
namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Describes the shape of an R1CS instance: row count <c>m</c> (number
/// of constraints), column count <c>n</c> (length of the satisfying
/// vector <c>z</c>), and the number of public inputs.
/// </summary>
/// <param name="ConstraintCount">The number of constraints <c>m</c>.</param>
/// <param name="VariableCount">The total length of <c>z = (1, public_inputs, witness)</c>; equal to <c>n</c>.</param>
/// <param name="PublicInputCount">The number of public inputs; <c>z[1..PublicInputCount]</c> are public, <c>z[PublicInputCount + 1..]</c> are private witness variables.</param>
/// <remarks>
/// <para>
/// Carried in the instance's Tag so consumers can read the dimensions
/// without unwrapping the leaf type. The witness variable count is
/// <c>VariableCount - 1 - PublicInputCount</c>.
/// </para>
/// </remarks>
public readonly record struct R1csDimensions(
    int ConstraintCount,
    int VariableCount,
    int PublicInputCount)
{
    /// <summary>The number of strictly-private witness variables.</summary>
    public int WitnessVariableCount => VariableCount - 1 - PublicInputCount;
}
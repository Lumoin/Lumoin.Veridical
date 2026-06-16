namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Declares a public input at <paramref name="Index"/>. Public inputs are
/// laid out contiguously immediately after the constant wire; the builder
/// enforces that all public-input declarations precede the first witness
/// variable and the first constraint.
/// </summary>
/// <param name="Index">The variable position assigned to this public input.</param>
/// <param name="Name">The author-supplied name; the key its value is bound by at compile time.</param>
public sealed record DeclarePublicInputOp(
    R1csVariableIndex Index,
    string Name): IR1csOp;

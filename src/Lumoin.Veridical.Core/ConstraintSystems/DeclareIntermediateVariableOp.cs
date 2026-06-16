namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Declares an auxiliary witness variable introduced by a predicate
/// generator at <paramref name="Index"/> — a range-check bit, a partial
/// product, an indicator. Compiled identically to a
/// <see cref="DeclareWitnessVariableOp"/>; the distinct op records that
/// the variable was generator-introduced rather than author-declared.
/// </summary>
/// <param name="Index">The variable position assigned to this intermediate variable.</param>
/// <param name="Name">The generated name; the key its value is bound by at compile time, following the predicate's documented naming convention.</param>
public sealed record DeclareIntermediateVariableOp(
    R1csVariableIndex Index,
    string Name): IR1csOp;

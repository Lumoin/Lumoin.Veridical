namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Declares a private witness variable at <paramref name="Index"/>. The
/// prover supplies its value; the verifier never sees it.
/// </summary>
/// <param name="Index">The variable position assigned to this witness variable.</param>
/// <param name="Name">The author-supplied name; the key its value is bound by at compile time.</param>
public sealed record DeclareWitnessVariableOp(
    R1csVariableIndex Index,
    string Name): IR1csOp;

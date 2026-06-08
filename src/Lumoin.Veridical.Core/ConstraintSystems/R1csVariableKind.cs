namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Classifies what a variable position in a built circuit represents.
/// The kind is metadata: it drives nothing in the compiled matrices
/// (column position alone does that, per the
/// <see cref="R1csVariableIndex"/> convention), but it records the
/// author's intent and aids inspection and input validation.
/// </summary>
public enum R1csVariableKind
{
    /// <summary>The constant <c>1</c> wire at index 0. Every circuit has exactly one.</summary>
    ConstantOne,

    /// <summary>A public input: part of the verifier-visible statement, laid out contiguously after the constant.</summary>
    PublicInput,

    /// <summary>A private witness variable supplied by the prover.</summary>
    WitnessVariable,

    /// <summary>
    /// An auxiliary witness variable introduced by a predicate generator
    /// (for example a bit of a range-check decomposition or a partial
    /// product). Compiled identically to <see cref="WitnessVariable"/>;
    /// the distinct kind marks it as generator-introduced for inspection.
    /// </summary>
    Intermediate,
}

namespace Lumoin.Veridical.Core.ConstraintSystems;

/// <summary>
/// Stable Fiat-Shamir operation labels for the Nova-style relaxed-R1CS
/// fold step. Pinned strings so protocol implementers in different
/// runtimes can reproduce identical fold challenges from identical
/// inputs.
/// </summary>
/// <remarks>
/// <para>
/// The fold challenge <c>r</c> binds the two instances' varying
/// parameters (the relaxation scalar <c>u</c>, the public inputs, and
/// the error commitment) plus the prover-supplied cross-term
/// commitment. The shared coefficient matrices <c>A</c>, <c>B</c>,
/// <c>C</c> are constant across a fold chain and are bound once at
/// compression time (when the base Spartan prover absorbs the folded
/// instance), so the fold challenge does not re-absorb them.
/// </para>
/// </remarks>
public static class WellKnownFoldingTranscriptLabels
{
    /// <summary>Label for absorbing the left (accumulator) instance's fold parameters: <c>u</c>, public inputs, error commitment.</summary>
    public const string LeftParameters = "folding.left.parameters";

    /// <summary>Label for absorbing the right (incoming) instance's fold parameters: <c>u</c>, public inputs, error commitment.</summary>
    public const string RightParameters = "folding.right.parameters";

    /// <summary>Label for absorbing the prover-supplied cross-term Hyrax commitment.</summary>
    public const string CrossTermCommitment = "folding.cross-term.commitment";

    /// <summary>Label for squeezing the fold challenge scalar <c>r</c>.</summary>
    public const string Challenge = "folding.challenge";
}
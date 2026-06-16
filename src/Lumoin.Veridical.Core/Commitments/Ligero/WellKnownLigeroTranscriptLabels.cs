namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// Stable Fiat-Shamir operation labels for the Ligero argument. Pinned strings
/// so a prover and verifier in any runtime reproduce identical transcript
/// states — hence identical challenge scalars and opened-column indices — from
/// identical inputs.
/// </summary>
/// <remarks>
/// <para>
/// Labels follow the codebase's hierarchical scheme: the first segment names
/// the protocol (<c>ligero</c>), the rest the message kind. The label is the
/// second line of defence against transcript-confusion attacks; the first is
/// the <see cref="WellKnownLigeroDomainLabels.LigeroV1"/> domain separation.
/// No label is a prefix of another that can follow it with different data in
/// the same transcript.
/// </para>
/// <para>
/// The challenge schedule the prover and verifier replay in lockstep is:
/// absorb the tableau root, squeeze the low-degree challenges
/// <c>u_ldt</c>, then the dot-product test's linear (<c>αl</c>) and quadratic
/// (<c>αq</c>) constraint challenges, then the quadratic-row challenges
/// <c>u_quad</c>, then the opened-column indices — each prover response
/// absorbed before the challenge that depends on it.
/// </para>
/// </remarks>
public static class WellKnownLigeroTranscriptLabels
{
    /// <summary>Label for absorbing the tableau's column Merkle root (the commitment).</summary>
    public const string TableauRoot = "ligero.tableau.root";

    /// <summary>Label for squeezing the low-degree-test challenges <c>u_ldt</c> (one per witness-and-quadratic row).</summary>
    public const string LowDegreeChallenge = "ligero.lowdegree.challenge";

    /// <summary>Label for squeezing the dot-product test's linear-constraint challenges <c>αl</c>.</summary>
    public const string LinearChallenge = "ligero.dot.linear.challenge";

    /// <summary>Label for squeezing the dot-product test's quadratic-constraint challenges <c>αq</c> (three per quadratic constraint).</summary>
    public const string QuadraticConstraintChallenge = "ligero.dot.quadratic.challenge";

    /// <summary>Label for squeezing the quadratic-test row challenges <c>u_quad</c> (one per quadratic-row triple).</summary>
    public const string QuadraticRowChallenge = "ligero.quadratic.row.challenge";

    /// <summary>Label for squeezing an opened-column index in <c>[0, BlockExtension)</c>.</summary>
    public const string ColumnIndex = "ligero.column.index";

    /// <summary>Label for absorbing the low-degree-test response <c>y_ldt</c> before the opened-column indices are drawn.</summary>
    public const string LowDegreeResponse = "ligero.lowdegree.response";

    /// <summary>Label for absorbing the dot-product-test response <c>y_dot</c> before the opened-column indices are drawn.</summary>
    public const string DotResponse = "ligero.dot.response";

    /// <summary>Label for absorbing the quadratic-test response <c>y_quad</c> (its non-zero halves <c>y_quad_0 ‖ y_quad_2</c>) before the opened-column indices are drawn.</summary>
    public const string QuadraticResponse = "ligero.quadratic.response";
}

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// Stable Fiat-Shamir domain and operation labels for the Ligero
/// <em>polynomial-commitment</em> evaluation argument. These are deliberately
/// separate from <see cref="WellKnownLigeroDomainLabels"/> /
/// <see cref="WellKnownLigeroTranscriptLabels"/> (the constraint-satisfaction
/// argument): the distinct domain label puts the two protocols in disjoint
/// transcript worlds, so a challenge collision across them is impossible even
/// where their absorb sequences coincide.
/// </summary>
/// <remarks>
/// The schedule prover and verifier replay in lockstep: initialise under
/// <see cref="DomainV1"/>, absorb the column-commitment root
/// (<see cref="CommitmentRoot"/>), squeeze the proximity coefficients
/// (<see cref="ProximityChallenge"/>), absorb the proximity response
/// <c>u</c> (<see cref="ProximityResponse"/>) and the evaluation response
/// <c>v</c> (<see cref="EvaluationResponse"/>), then draw the opened-column
/// indices. The evaluation tensor is public (derived from the point), so it is
/// not squeezed.
/// </remarks>
public static class WellKnownLigeroEvaluationLabels
{
    /// <summary>The domain label for v1 of the Veridical Ligero polynomial-commitment argument.</summary>
    public const string DomainV1 = "veridical.ligero.pcs.v1";

    /// <summary>Label for absorbing the encoded-matrix column Merkle root (the commitment).</summary>
    public const string CommitmentRoot = "ligero.pcs.root";

    /// <summary>Label for squeezing the proximity-test row-combination coefficients (one per matrix row).</summary>
    public const string ProximityChallenge = "ligero.pcs.proximity.challenge";

    /// <summary>Label for absorbing the proximity-test response <c>u</c> before the opened-column indices are drawn.</summary>
    public const string ProximityResponse = "ligero.pcs.proximity.response";

    /// <summary>Label for absorbing the evaluation-test response <c>v</c> before the opened-column indices are drawn.</summary>
    public const string EvaluationResponse = "ligero.pcs.evaluation.response";
}

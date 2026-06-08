namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Stable Fiat-Shamir operation labels used when absorbing Spartan
/// messages into a transcript and when squeezing the corresponding
/// challenges. Pinned strings so protocol implementers in different
/// runtimes can reproduce identical transcript states from identical
/// inputs.
/// </summary>
/// <remarks>
/// <para>
/// Operation labels follow a hierarchical naming scheme — the first
/// segment is the sub-protocol (<c>sumcheck</c>, <c>spartan.outer</c>,
/// <c>spartan.inner</c>), the second is the message kind
/// (<c>round</c>, <c>claim</c>), and the third the role
/// (<c>polynomial</c>, <c>challenge</c>). The label is the second line
/// of defence against transcript-confusion attacks; the first is the
/// <see cref="WellKnownSpartanDomainLabels"/> separation.
/// </para>
/// </remarks>
public static class WellKnownSpartanTranscriptLabels
{
    /// <summary>Label for absorbing the prover's per-round compressed polynomial in a sumcheck.</summary>
    public const string SumcheckRoundPolynomial = "sumcheck.round.polynomial";

    /// <summary>Label for squeezing the verifier's per-round challenge.</summary>
    public const string SumcheckRoundChallenge = "sumcheck.round.challenge";

    /// <summary>Label for absorbing the initial claim of a sumcheck.</summary>
    public const string SumcheckInitialClaim = "sumcheck.initial.claim";

    /// <summary>Label for absorbing the witness commitment binding the prover's witness MLE.</summary>
    public const string WitnessCommitment = "spartan.witness.commitment";

    /// <summary>Label for squeezing each component of <c>τ</c>, the binding vector for the outer-sumcheck eq factor.</summary>
    public const string OuterTau = "spartan.outer.tau";

    /// <summary>Label for absorbing the three terminating evaluations <c>(claim_Az, claim_Bz, claim_Cz)</c> from the outer sumcheck.</summary>
    public const string OuterClaimedEvaluations = "spartan.outer.claimed_evaluations";

    /// <summary>Label for absorbing the relaxed outer-sumcheck error-MLE evaluation <c>E(r_x)</c>.</summary>
    public const string OuterErrorEvaluation = "spartan.outer.error_evaluation";

    /// <summary>Label for squeezing the linear-combination challenge that batches the three matrix MLEs into the inner sumcheck.</summary>
    public const string InnerCombinationChallenge = "spartan.inner.combination";

    /// <summary>Label for absorbing the final claimed witness MLE evaluation at <c>r_y</c>.</summary>
    public const string WitnessEvaluation = "spartan.witness.evaluation";
}
namespace Lumoin.Veridical.Core.Lookup;

/// <summary>
/// Stable Fiat-Shamir operation labels for the LogUp lookup argument's
/// transcript schedule. Pinned strings so protocol implementers in different
/// runtimes can reproduce identical transcript states from identical inputs.
/// </summary>
/// <remarks>
/// <para>
/// The schedule order is soundness-critical: the instance shape, the public
/// table, every witness-column commitment and the multiplicity commitment are
/// absorbed BEFORE the denominator challenge is squeezed, and the helper
/// commitment is absorbed before the kernel point and folding challenge. A
/// prover that could choose the multiplicity column after seeing the
/// denominator challenge would face one linear equation over the field and
/// could satisfy the log-derivative identity for arbitrary out-of-table
/// values — the Fiat-Shamir omission class Trail of Bits named Frozen Heart.
/// </para>
/// <para>
/// Labels follow the hierarchical <c>logup.&lt;message&gt;.&lt;role&gt;</c>
/// scheme of <see cref="Spartan.WellKnownSpartanTranscriptLabels"/>; the label
/// is the second line of defence against transcript confusion, the first being
/// the caller's transcript domain separation.
/// </para>
/// </remarks>
public static class WellKnownLogUpTranscriptLabels
{
    /// <summary>Label for absorbing the instance shape: variable count, witness-column count and curve code, each four big-endian bytes.</summary>
    public const string InstanceShape = "logup.instance.shape";

    /// <summary>Label for absorbing the public table's full evaluation bytes.</summary>
    public const string TableEvaluations = "logup.table.evaluations";

    /// <summary>Label for absorbing each witness-column commitment, in column order.</summary>
    public const string WitnessCommitment = "logup.witness.commitment";

    /// <summary>Label for absorbing the multiplicity-column commitment.</summary>
    public const string MultiplicityCommitment = "logup.multiplicity.commitment";

    /// <summary>Label for squeezing the denominator challenge the log-derivative identity is evaluated at.</summary>
    public const string DenominatorChallenge = "logup.denominator.challenge";

    /// <summary>Label for absorbing the helper-column commitment.</summary>
    public const string HelperCommitment = "logup.helper.commitment";

    /// <summary>Label for squeezing each component of the Lagrange-kernel point that reduces the well-formedness identity to a sumcheck.</summary>
    public const string KernelPoint = "logup.kernel.point";

    /// <summary>Label for squeezing the challenge that folds the well-formedness identity into the zero-sum claim.</summary>
    public const string FoldingChallenge = "logup.folding.challenge";

    /// <summary>Label for absorbing the prover's per-round evaluation message in the sumcheck.</summary>
    public const string SumcheckRoundPolynomial = "logup.sumcheck.round.polynomial";

    /// <summary>Label for squeezing the verifier's per-round sumcheck challenge.</summary>
    public const string SumcheckRoundChallenge = "logup.sumcheck.round.challenge";

    /// <summary>Label for absorbing each claimed witness-column evaluation at the sumcheck point, in column order.</summary>
    public const string WitnessEvaluation = "logup.witness.evaluation";

    /// <summary>Label for absorbing the claimed multiplicity-column evaluation at the sumcheck point.</summary>
    public const string MultiplicityEvaluation = "logup.multiplicity.evaluation";

    /// <summary>Label for absorbing the claimed helper-column evaluation at the sumcheck point.</summary>
    public const string HelperEvaluation = "logup.helper.evaluation";

    /// <summary>Label for absorbing the GKR variant's instance shape. Distinct from <see cref="InstanceShape"/> so the two protocols' transcripts diverge before any challenge is squeezed.</summary>
    public const string GkrInstanceShape = "logup.gkr.instance.shape";

    /// <summary>Label for squeezing the GKR variant's denominator challenge.</summary>
    public const string GkrDenominatorChallenge = "logup.gkr.denominator.challenge";

    /// <summary>Label for absorbing the four root values <c>p₁(0), p₁(1), q₁(0), q₁(1)</c>.</summary>
    public const string GkrRootValues = "logup.gkr.root.values";

    /// <summary>Label for squeezing each line-merge challenge that combines a layer's two-point claims into one.</summary>
    public const string GkrLineChallenge = "logup.gkr.line.challenge";

    /// <summary>Label for squeezing each layer's claim-batching challenge.</summary>
    public const string GkrLayerFoldingChallenge = "logup.gkr.layer.folding.challenge";

    /// <summary>Label for absorbing a layer sumcheck's per-round evaluation message.</summary>
    public const string GkrLayerRoundPolynomial = "logup.gkr.layer.round.polynomial";

    /// <summary>Label for squeezing a layer sumcheck's per-round challenge.</summary>
    public const string GkrLayerRoundChallenge = "logup.gkr.layer.round.challenge";

    /// <summary>Label for absorbing a layer sumcheck's four terminating half-table evaluations.</summary>
    public const string GkrLayerTerminatingValues = "logup.gkr.layer.terminating.values";

    /// <summary>Label for absorbing each claimed witness-column evaluation at the terminal row point, in column order.</summary>
    public const string GkrWitnessEvaluation = "logup.gkr.witness.evaluation";

    /// <summary>Label for absorbing the claimed multiplicity-column evaluation at the terminal row point.</summary>
    public const string GkrMultiplicityEvaluation = "logup.gkr.multiplicity.evaluation";
}

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// Stable Fiat-Shamir operation labels for the WHIR IOPP. Pinned strings so a
/// prover and verifier in any runtime reproduce identical transcript states —
/// hence identical challenges, out-of-domain points and query indices — from
/// identical inputs.
/// </summary>
/// <remarks>
/// Labels follow the codebase's hierarchical scheme: the first segment names
/// the protocol (<c>whir.iopp</c>), the rest the message kind. The label is
/// the second line of defence against transcript-confusion attacks; the first
/// is the <see cref="WellKnownWhirParameters.TranscriptDomainLabel"/>
/// separation. No label is a prefix of another that can follow it with
/// different data in the same transcript.
/// </remarks>
public static class WellKnownWhirTranscriptLabels
{
    /// <summary>Label for absorbing the public statement: the target <c>σ</c> and the equality-kernel constraint list.</summary>
    public const string Statement = "whir.iopp.statement";

    /// <summary>Label for absorbing an oracle's Merkle root — the input commitment and every folded oracle the main loop sends.</summary>
    public const string OracleRoot = "whir.iopp.oracle.root";

    /// <summary>Label for absorbing a compressed sumcheck round polynomial.</summary>
    public const string SumcheckPolynomial = "whir.iopp.sumcheck.polynomial";

    /// <summary>Label for squeezing a sumcheck folding challenge <c>α</c>.</summary>
    public const string FoldChallenge = "whir.iopp.fold.challenge";

    /// <summary>Label for squeezing an out-of-domain sample <c>z_(i,0)</c>.</summary>
    public const string OutOfDomainPoint = "whir.iopp.ood.point";

    /// <summary>Label for absorbing an out-of-domain reply <c>y_(i,0)</c>.</summary>
    public const string OutOfDomainReply = "whir.iopp.ood.reply";

    /// <summary>Label for squeezing a shift-query block index into the previous oracle's folded query domain.</summary>
    public const string ShiftQueryIndex = "whir.iopp.shift.query.index";

    /// <summary>Label for squeezing a combination challenge <c>γ</c>.</summary>
    public const string CombinationChallenge = "whir.iopp.combination.challenge";

    /// <summary>Label for absorbing the final polynomial's cleartext coefficients.</summary>
    public const string FinalPolynomial = "whir.iopp.final.polynomial";

    /// <summary>Label for squeezing a final-query block index into the last oracle's folded query domain.</summary>
    public const string FinalQueryIndex = "whir.iopp.final.query.index";

    /// <summary>Label for absorbing a batch of separate claims — the claim boundaries, targets and constraint lists — ahead of the batch combination challenge.</summary>
    public const string BatchStatement = "whir.iopp.batch.statement";

    /// <summary>Label for squeezing the batch combination challenge <c>γ</c> of WHIR Construction 5.5.</summary>
    public const string BatchCombinationChallenge = "whir.iopp.batch.combination.challenge";

    /// <summary>Label for absorbing a masked-sumcheck batch's interleaved mask oracle root (eprint 2026/391 Construction 6.3).</summary>
    public const string MaskOracleRoot = "whir.iopp.mask.oracle.root";

    /// <summary>Label for absorbing the mask total <c>μ̃</c> — the sum of every mask polynomial over the batch's Boolean cube, sent before any challenge.</summary>
    public const string MaskTotal = "whir.iopp.mask.total";

    /// <summary>Label for squeezing the mask combination challenge <c>ε</c> blending the plain sumcheck contribution into the masked rounds.</summary>
    public const string MaskCombinationChallenge = "whir.iopp.mask.combination.challenge";

    /// <summary>Label for absorbing the joint claim (source claim plus mask-claim total) bound at each masked-sumcheck batch entry, before the batch's mask oracle root (eprint 2026/391 Construction 6.3).</summary>
    public const string MaskBatchClaim = "whir.iopp.mask.batch.claim";

    /// <summary>Label for absorbing a code-switch round's fresh mask oracle root — folded randomness plus private out-of-domain pad (eprint 2026/391 Construction 9.7).</summary>
    public const string CodeSwitchMaskRoot = "whir.iopp.switch.mask.root";

    /// <summary>Label for squeezing a private out-of-domain sample of a code-switch round (eprint 2026/391 Construction 9.7).</summary>
    public const string PrivateOutOfDomainPoint = "whir.iopp.private.ood.point";

    /// <summary>Label for absorbing the zero-evader-padded reply to a private out-of-domain sample (eprint 2026/391 Construction 9.7).</summary>
    public const string PrivateOutOfDomainReply = "whir.iopp.private.ood.reply";

    /// <summary>Label for absorbing the masked base case's fresh main-oracle commitment (eprint 2026/391 Construction 7.2, move 1a).</summary>
    public const string BaseCaseFreshRoot = "whir.iopp.basecase.fresh.root";

    /// <summary>Label for absorbing one fresh blind commitment per carried mask group of the masked base case (eprint 2026/391 Construction 7.2, move 1b).</summary>
    public const string BaseCaseMaskRoot = "whir.iopp.basecase.mask.root";

    /// <summary>Label for absorbing the masked base-case claim μ_g, fixed before the blinding challenge (eprint 2026/391 Construction 7.2).</summary>
    public const string BaseCaseClaim = "whir.iopp.basecase.claim";

    /// <summary>Label for squeezing the base case's blinding challenge <c>γ</c> (eprint 2026/391 Construction 7.2).</summary>
    public const string BaseCaseCombinationChallenge = "whir.iopp.basecase.combination.challenge";

    /// <summary>Label for absorbing the blinded source reveals — message then encoding randomness — of the masked base case (eprint 2026/391 Construction 7.2).</summary>
    public const string BaseCaseReveal = "whir.iopp.basecase.reveal";

    /// <summary>Label for absorbing the blinded mask reveals — message then encoding randomness, per group member — of the masked base case (eprint 2026/391 Construction 7.2).</summary>
    public const string BaseCaseMaskReveal = "whir.iopp.basecase.mask.reveal";

    /// <summary>Label for squeezing a mask-oracle spot-check index of the masked base case (eprint 2026/391 Construction 7.2).</summary>
    public const string MaskQueryIndex = "whir.iopp.mask.query.index";
}

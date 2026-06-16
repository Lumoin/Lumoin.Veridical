namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// Stable Fiat-Shamir labels for the BaseFold evaluation protocol (the
/// multilinear PCS open/verify of Protocol 4 / Fig. 3 in Zeilberger, Chen,
/// Fisch, CRYPTO 2024, IACR ePrint 2023/1705). The evaluation protocol runs a
/// BaseFold IOPP interleaved with a sumcheck, so it reuses the IOPP's fold-root,
/// fold-challenge, final-oracle, and query-index labels
/// (<see cref="WellKnownBaseFoldTranscriptLabels"/>) and adds one label of its
/// own for the per-round sumcheck polynomial.
/// </summary>
/// <remarks>
/// The query repetition count is the same soundness property as the standalone
/// IOPP and is taken from
/// <see cref="WellKnownBaseFoldIoppParameters.ClassicalSecurityDefaultQueryCount"/>;
/// it is not re-derived here. The transcript domain label separates a
/// standalone-IOPP transcript from an evaluation-protocol transcript even when
/// the absorb sequence overlaps.
/// </remarks>
public static class WellKnownBaseFoldEvaluationParameters
{
    /// <summary>
    /// The domain-separation label every BaseFold evaluation-protocol
    /// Fiat-Shamir transcript carries when the protocol is run standalone (not
    /// embedded in a larger protocol's transcript).
    /// </summary>
    public const string TranscriptDomainLabel = "Lumoin.Veridical.BaseFold.Eval.v1";

    /// <summary>
    /// Label for absorbing a per-round compressed sumcheck polynomial
    /// <c>h_i</c> (the degree-2 round polynomial of <c>f · eq_z</c>).
    /// </summary>
    public const string RoundPolynomial = "basefold.eval.round.polynomial";

    /// <summary>
    /// Label for absorbing the statistical mask's coefficient-commitment Merkle
    /// root <c>com(C*)</c> — the salted, lifted commitment to (mask coefficients
    /// ‖ filler) — committed before the blend challenge is squeezed (design doc
    /// <c>ZK-STATMASK-DESIGN.md</c> §2 v3).
    /// </summary>
    public const string MaskCommitmentRoot = "basefold.eval.mask.commitment.root";

    /// <summary>
    /// Label for absorbing the mask sum <c>σ = Σ_b s(b)</c> over the hypercube,
    /// committed before the blend challenge is squeezed.
    /// </summary>
    public const string MaskSum = "basefold.eval.mask.sum";

    /// <summary>
    /// Label for absorbing the filler sum <c>σ_F</c> — the sum of the
    /// coefficient commitment's laundering filler block, precommitted alongside
    /// <c>σ</c> so the terminal weighted-opening claim <c>s(r) + σ_F</c> is
    /// fixed before the blend challenge.
    /// </summary>
    public const string MaskFillerSum = "basefold.eval.mask.filler.sum";

    /// <summary>
    /// Label for squeezing the mask-blend challenge <c>ρ</c> that blends the mask
    /// sumcheck into the witness sumcheck (round polynomials become
    /// <c>h_i + ρ·s_i</c>, the initial claim becomes <c>y + ρ·σ</c>).
    /// </summary>
    public const string MaskBlendChallenge = "basefold.eval.mask.blend.challenge";
}

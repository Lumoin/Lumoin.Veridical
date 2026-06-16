namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Stable Fiat-Shamir operation labels introduced by the
/// statistical-mask ZK construction implemented by
/// <c>MaskedSpartanProver</c> (the sum-of-univariates kernel masks with
/// the filler-laundered weighted-opening binding, design v3 of
/// <c>ZK-STATMASK-DESIGN.md</c>; SM.7b). Pinned strings so the
/// verifier replays the prover's transcript byte-for-byte.
/// </summary>
/// <remarks>
/// <para>
/// The base prover's transcript labels live in
/// <see cref="WellKnownSpartanTranscriptLabels"/>; the masked
/// variant extends them with the mask commit/blend/open steps
/// interleaved into the standard schedule. The labels here cover
/// those additional steps and nothing else — the per-round absorb
/// and squeeze labels (<c>SumcheckRoundPolynomial</c>,
/// <c>SumcheckRoundChallenge</c>) are reused from the base set
/// because the masked sumcheck rounds occupy the same per-round
/// slot, just with blended polynomial content.
/// </para>
/// </remarks>
public static class WellKnownMaskedSpartanTranscriptLabels
{
    /// <summary>Absorb label for the outer mask's coefficient-vector commitment <c>com(C*_outer)</c>.</summary>
    public const string OuterMaskCommitment = "veridical.spartan2.masking-polynomial.outer-commitment";

    /// <summary>Absorb label for the inner mask's coefficient-vector commitment <c>com(C*_inner)</c>.</summary>
    public const string InnerMaskCommitment = "veridical.spartan2.masking-polynomial.inner-commitment";

    /// <summary>Absorb label for the outer mask sum <c>σ_outer = Σ g_outer(x)</c>.</summary>
    public const string OuterMaskSum = "veridical.spartan2.masking-polynomial.outer-sum";

    /// <summary>Absorb label for the inner mask sum <c>σ_inner = Σ g_inner(y)</c>.</summary>
    public const string InnerMaskSum = "veridical.spartan2.masking-polynomial.inner-sum";

    /// <summary>Absorb label for the outer mask's filler sum <c>σ_F</c>; absorbed before <c>ρ_outer</c> so the weighted-opening claim is fixed by the commitment.</summary>
    public const string OuterMaskFillerSum = "veridical.spartan2.masking-polynomial.outer-filler-sum";

    /// <summary>Absorb label for the inner mask's filler sum <c>σ_F</c>; absorbed before <c>ρ_inner</c>.</summary>
    public const string InnerMaskFillerSum = "veridical.spartan2.masking-polynomial.inner-filler-sum";

    /// <summary>Squeeze label for the outer blending scalar <c>ρ_outer</c>.</summary>
    public const string OuterBlendingChallenge = "veridical.spartan2.masking-polynomial.outer-blending";

    /// <summary>Squeeze label for the inner blending scalar <c>ρ_inner</c>.</summary>
    public const string InnerBlendingChallenge = "veridical.spartan2.masking-polynomial.inner-blending";
}

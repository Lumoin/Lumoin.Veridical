namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Fixed protocol shape of the masked Spartan2 statistical masks (SM.7b,
/// design v3 of <c>ZK-STATMASK-DESIGN.md</c>): the per-variable
/// degree of each sumcheck's sum-of-univariates kernel mask, matching the
/// round format the mask must blanket. Pinned here so the prover, the
/// verifier, and the proof containers derive identical mask shapes.
/// </summary>
public static class WellKnownMaskedSpartanParameters
{
    /// <summary>The outer sumcheck's round format is cubic, so its mask carries degree-3 univariates (<c>3·d_x + 1</c> coefficients).</summary>
    public const int OuterMaskPerVariableDegree = 3;

    /// <summary>The inner sumcheck's round format is quadratic, so its mask carries degree-2 univariates (<c>2·d_y + 1</c> coefficients).</summary>
    public const int InnerMaskPerVariableDegree = 2;
}

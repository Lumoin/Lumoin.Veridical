using Lumoin.Veridical.Core.Algebraic;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// The Fiat-Shamir operation labels of the layered GKR protocol. Prover and verifier drive the
/// transcript with the identical label sequence, so the squeezed output point, per-round sumcheck
/// challenges and layer-combination coefficients agree.
/// </summary>
internal static class GkrTranscriptLabels
{
    public static FiatShamirOperationLabel Inputs { get; } = new("veridical.gkr.inputs");

    public static FiatShamirOperationLabel Outputs { get; } = new("veridical.gkr.outputs");

    public static FiatShamirOperationLabel OutputPoint { get; } = new("veridical.gkr.output-point");

    public static FiatShamirOperationLabel LayerClaims { get; } = new("veridical.gkr.layer-claims");

    public static FiatShamirOperationLabel LayerCombination { get; } = new("veridical.gkr.layer-combination");

    public static FiatShamirOperationLabel WitnessOpening { get; } = new("veridical.gkr.witness-opening");
}

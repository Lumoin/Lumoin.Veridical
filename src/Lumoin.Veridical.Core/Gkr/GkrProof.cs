using System;

namespace Lumoin.Veridical.Core.Gkr;

/// <summary>
/// A layered GKR proof: one product sumcheck proof per circuit layer, output layer first, each
/// backed by pooled storage this proof owns (dispose to return them). Each layer proof's
/// <c>FinalValues</c> carry the bound wiring value and the two wire claims <c>W(r_left)</c>,
/// <c>W(r_right)</c> the next layer (or the input check) consumes; the challenge points
/// themselves are re-derived from the transcript, so the proof is just the round polynomials and
/// final values.
/// </summary>
internal sealed class GkrProof: IDisposable
{
    public ProductSumcheckProof[] LayerProofs { get; }


    internal GkrProof(ProductSumcheckProof[] layerProofs)
    {
        LayerProofs = layerProofs;
    }


    public void Dispose()
    {
        foreach(ProductSumcheckProof layerProof in LayerProofs)
        {
            layerProof.Dispose();
        }
    }
}

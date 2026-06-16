using System;

namespace Lumoin.Veridical.Core.Commitments.Longfellow;

/// <summary>
/// The layout of one layer's pad inside the symbolic expression array, a faithful port of
/// google/longfellow-zk's <c>ZkCommon::PadLayout</c> (<c>lib/zk/zk_common.h</c>). A layer's pad holds a
/// claim pad triple <c>[dWC[0], dWC[1], dWC[0]·dWC[1]]</c> from the previous layer, then a poly pad pair
/// <c>[dP(0), dP(2)]</c> per binding round (the <c>p(1)</c> point is implied, not padded), then this
/// layer's claim pad triple. Adjacent layers' claim pads overlap, so two indexing schemes exist: one
/// "with overlap" whose first element is the previous claim pad, and one "without overlap" whose first
/// element is the first poly pad.
/// </summary>
/// <remarks>
/// The symbolic array layout is
/// <c>[CLAIM_PAD[layer−1], POLY_PAD[0], … POLY_PAD[LOGW−1], CLAIM_PAD[layer]]</c>. A claim pad is three
/// entries; a poly pad is two (points 0 and 2). The "with overlap" indices add 3 to skip the previous
/// claim pad. <see cref="LayerSize"/> is the without-overlap layer size used to advance the pad index
/// between layers.
/// </remarks>
internal readonly struct LongfellowZkPadLayout
{
    private readonly int handRounds;


    /// <summary>Constructs the layout for a layer with <paramref name="handRounds"/> binding rounds (<c>logw</c>).</summary>
    /// <param name="handRounds">The number of binding rounds per hand variable (<c>logw</c>); zero for the input fake layer.</param>
    public LongfellowZkPadLayout(int handRounds)
    {
        this.handRounds = handRounds;
    }


    //poly_pad(r, point): the without-overlap index of poly pad r's evaluation point (point in {0, 2}).
    private static int PolyPad(int round, int point) => point == 0 ? 2 * round : (2 * round) + 1;

    /// <summary>The without-overlap index of poly pad <paramref name="round"/>'s evaluation point <paramref name="point"/> (point in {0, 2}).</summary>
    public static int PolyPadWithoutOverlap(int round, int point) => PolyPad(round, point);

    /// <summary>The without-overlap index of this layer's claim pad entry <paramref name="n"/>.</summary>
    public int ClaimPad(int n) => PolyPad(2 * handRounds, 0) + n;

    /// <summary>The without-overlap size of the layer (<c>claim_pad(3)</c>).</summary>
    public int LayerSize => ClaimPad(3);

    /// <summary>The with-overlap index of the previous layer's claim pad entry <paramref name="n"/>.</summary>
    public static int OverlapPreviousClaimPad(int n) => n;

    /// <summary>The with-overlap index of poly pad <paramref name="round"/>'s evaluation point <paramref name="point"/>.</summary>
    public static int OverlapPolyPad(int round, int point) => 3 + PolyPad(round, point);

    /// <summary>The with-overlap index of this layer's claim pad entry <paramref name="n"/>.</summary>
    public int OverlapClaimPad(int n) => 3 + ClaimPad(n);

    /// <summary>The with-overlap size of the layer (<c>ovp_claim_pad(3)</c>); the symbolic expression length.</summary>
    public int OverlapLayerSize => OverlapClaimPad(3);
}

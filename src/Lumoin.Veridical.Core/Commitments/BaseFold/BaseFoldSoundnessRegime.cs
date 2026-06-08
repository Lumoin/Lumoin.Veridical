namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// The soundness regime that fixes the proximity parameter <c>δ</c> used to
/// derive the BaseFold IOPP query (repetition) count. The query count is
/// <c>ℓ = ⌈λ / -log2(1 - δ)⌉</c> for a target soundness of <c>2^-λ</c>; the
/// regime determines how <c>δ</c> is read off the code's relative minimum
/// distance <c>δ_min</c> and rate <c>ρ = 1/c</c>.
/// </summary>
/// <remarks>
/// <para>
/// The three regimes trade proof size against the strength of the assumption
/// the soundness claim rests on. They are listed from fewest queries (weakest
/// guarantee) to most queries (strongest, most conservative). The wired default
/// (<see cref="WellKnownBaseFoldIoppParameters.ClassicalSecurityRegime"/>) is
/// <see cref="ListDecodingJohnson"/>, the bound Theorem 3 of the BaseFold paper
/// literally proves for the IOPP.
/// </para>
/// <para>
/// References are to Zeilberger, Chen, Fisch, "BaseFold: Efficient
/// Field-Agnostic Polynomial Commitment Schemes from Foldable Codes" (CRYPTO
/// 2024, IACR ePrint 2023/1705).
/// </para>
/// </remarks>
public enum BaseFoldSoundnessRegime
{
    /// <summary>
    /// Decoding to capacity: <c>δ → 1 - ρ = 1 - 1/c</c>. The fewest queries
    /// (for <c>c = 8</c>, <c>ℓ ≈ λ / 3</c>), matching the reference
    /// implementation's small repetition counts. This regime is
    /// <b>conjecture-dependent</b>: the BaseFold paper does not prove IOPP
    /// soundness at the capacity radius, so a claim resting on this regime
    /// inherits the proximity-gap / list-decoding-to-capacity conjecture.
    /// </summary>
    ConjecturedCapacity = 0,

    /// <summary>
    /// Unique decoding: <c>δ = δ_min / 2</c>, half the code's relative minimum
    /// distance. The classical FRI-style proximity radius; provable without a
    /// list-decoding argument. Fewer queries than
    /// <see cref="ListDecodingJohnson"/> in the distance range of our wired
    /// code, because <c>δ_min/2 &gt; J(J(δ_min))</c> there.
    /// </summary>
    UniqueDecoding = 1,

    /// <summary>
    /// List decoding at the doubly-applied Johnson radius
    /// <c>δ = J(J(δ_min))</c> with <c>J(x) = 1 - √(1 - x)</c>. This is exactly
    /// the proximity parameter Theorem 3 (and Appendix B.3) of the BaseFold
    /// paper proves for the IOPP, so a soundness claim under this regime is
    /// fully supported by the paper. It demands the most queries of the three
    /// in our code's distance range and is the conservative default.
    /// </summary>
    ListDecodingJohnson = 2
}

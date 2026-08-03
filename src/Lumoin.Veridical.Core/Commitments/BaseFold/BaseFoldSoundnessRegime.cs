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
/// The four regimes trade proof size against the strength of the argument the
/// soundness claim rests on, and at the wired code's distance the two axes
/// move together — fewer queries means weaker support. (The alignment is a
/// property of the distance, not of the regimes: above the crossover noted on
/// <see cref="ListDecodingOneAndAHalfJohnson"/> that proven regime prices
/// fewer queries than the conjecture-dependent <see cref="UniqueDecoding"/>.)
/// In query order at the wired distance they are
/// <see cref="ConjecturedCapacity"/> (fewest; its underlying conjecture is
/// refuted), <see cref="UniqueDecoding"/> (rests on an open conjecture for
/// the wired code family), <see cref="ListDecodingOneAndAHalfJohnson"/>
/// (proven for every linear code in a CRYPTO 2026 result), and
/// <see cref="ListDecodingJohnson"/> (most queries; the peer-reviewed BaseFold
/// paper bound and the wired default,
/// <see cref="WellKnownBaseFoldIoppParameters.ClassicalSecurityRegime"/>).
/// </para>
/// <para>
/// References: Zeilberger, Chen, Fisch, "BaseFold: Efficient Field-Agnostic
/// Polynomial Commitment Schemes from Foldable Codes" (CRYPTO 2024, IACR
/// ePrint 2023/1705); Zeilberger, "Khatam: Proximity Gaps For Multilinear
/// Evaluation For All Linear Codes" (IACR ePrint 2024/1843, CRYPTO 2026);
/// Ben-Sasson, Kopparty, Saraf, "Worst-Case to Average Case Reductions for
/// the Distance to a Code" (CCC 2018); Arnon, Chiesa, Fenzi, Yogev, "WHIR"
/// (IACR ePrint 2024/1586, EUROCRYPT 2025); Diamond, Posen, "Proximity
/// Testing with Logarithmic Randomness" (IACR Communications in Cryptology
/// 1(1), 2024).
/// </para>
/// </remarks>
public enum BaseFoldSoundnessRegime
{
    /// <summary>
    /// Decoding to capacity, clamped to the code's distance:
    /// <c>δ = min(1 - ρ, δ_min)</c>. The fewest queries of the four regimes.
    /// For Reed-Solomon codes the capacity radius <c>1 - ρ</c> coincides with
    /// the code's relative minimum distance; for a code whose distance is
    /// smaller — the wired random foldable code has <c>δ_min = 0.728</c>
    /// against <c>1 - ρ = 0.875</c> — the code's own distance is the outer
    /// limit any proximity-gap statement reaches, so the clamp keeps the
    /// figure meaningful. This regime is <b>conjecture-dependent, and the
    /// conjecture is refuted as stated</b>: the proximity-gap-to-capacity
    /// conjectures are disproven in their plain form for Reed-Solomon codes
    /// (Crites, Stewart, IACR ePrint 2025/2046; Krachun, Kazanin, Haböck,
    /// IACR ePrint 2026/782), and no capacity-regime analysis exists for
    /// random foldable codes. The regime is retained for parameter
    /// comparison; a soundness claim must not rest on it.
    /// </summary>
    ConjecturedCapacity = 0,

    /// <summary>
    /// Unique decoding: <c>δ = δ_min / 2</c>, half the code's relative minimum
    /// distance. For general linear codes — including the wired random
    /// foldable code — correlated agreement at half the minimum distance is an
    /// <b>open conjecture</b> (Diamond, Posen, IACR Communications in
    /// Cryptology 1(1) 2024, Conjecture 1); it is proven only for
    /// Reed-Solomon codes (Ben-Sasson, Carmon, Ishai, Kopparty, Saraf,
    /// FOCS 2020 / J.ACM 2023), and the uncontested classical radius for
    /// general codes is <c>δ_min / 3</c> (Roth-Zémor; the Ligero lemma). The
    /// mutual-correlated-agreement upgrade the folding rounds need is
    /// loss-free for any linear code up to the radius cap
    /// <c>min(1 - δ_min/2, B)</c> of WHIR Lemma 4.10 — <c>B</c> the plain
    /// agreement's own bound, which this regime's radius sits inside — so the
    /// plain-agreement conjecture is the only gap. But it is a gap: query
    /// counts derived under this regime rest on it.
    /// </summary>
    UniqueDecoding = 1,

    /// <summary>
    /// List decoding at the doubly-applied Johnson radius
    /// <c>δ = J(J(δ_min))</c> with <c>J(x) = 1 - √(1 - x)</c>. This is the
    /// proximity parameter the BaseFold paper's Theorem 3 (and Appendix B.3)
    /// proves for the IOPP over its foldable codes, so a soundness claim under
    /// this regime is fully supported by peer-reviewed results: the
    /// correlated-agreement ingredient (Ben-Sasson, Kopparty, Saraf, CCC 2018,
    /// Theorem 4.4) holds for arbitrary linear codes, and the
    /// mutual-correlated-agreement form the folding argument uses follows
    /// loss-free within WHIR Lemma 4.10's radius cap
    /// <c>min(1 - δ_min/2, B)</c> — <c>B</c> the plain agreement's own bound,
    /// well clear of this regime's radius (the BaseFold paper's 2026-07-10
    /// revision bases its Theorem 3 proof on that upgrade, radius unchanged).
    /// It demands the most queries of the four regimes and is the
    /// conservative default.
    /// </summary>
    ListDecodingJohnson = 2,

    /// <summary>
    /// List decoding at the one-and-a-half-Johnson radius
    /// <c>δ = 1 - (1 - δ_min)^(1/3)</c>. This is the radius proven for every
    /// linear code — including the wired random foldable codes, whose shape
    /// the theorem addresses directly — by the BaseFold-IOP soundness theorem
    /// of Zeilberger, "Khatam: Proximity Gaps For Multilinear Evaluation For
    /// All Linear Codes" (IACR ePrint 2024/1843, CRYPTO 2026; Theorem 2 in
    /// the 2025-06-26 revision — the paper's numbering moved across
    /// revisions, so the statement, not a bare number, is the anchor), with
    /// the same radius reached independently for general codes by Gao, Kan,
    /// Li (IACR ePrint 2024/1810). The per-query bits price the <c>ε, η → 0</c>
    /// limit of the theorem's slack parameters, matching the Johnson-radius
    /// pricing convention documented in the security-bits design notes; the
    /// commit-phase failure the slacks control is a separate field-side term
    /// (<c>3d/(εη·|F|)</c>) accounted in
    /// <see cref="WellKnownSecurityLevels"/>. At the wired distance the
    /// guaranteed proximity lies inside the unique-decoding ball, so the
    /// commitment binds a unique multilinear polynomial and no cross-opening
    /// list ambiguity arises. Fewer queries than
    /// <see cref="ListDecodingJohnson"/> at every distance; fewer than
    /// <see cref="UniqueDecoding"/> only when <c>δ_min &gt; 0.7639</c>, but
    /// unlike that regime it carries a full proof for the wired code family.
    /// </summary>
    ListDecodingOneAndAHalfJohnson = 3
}

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The soundness regime that fixes the per-round proximity parameter
/// <c>δ_i</c> used to derive the WHIR query (repetition) schedule. Each
/// oracle round <c>i</c> pays <c>t_i = ⌈λ / -log2(1 - δ_i)⌉</c> queries for a
/// per-round soundness of <c>2^-λ</c>, with <c>δ_i</c> read off that round's
/// rate <c>ρ_i</c> — WHIR improves the rate every iteration, so later rounds
/// price markedly fewer queries than the first.
/// </summary>
/// <remarks>
/// <para>
/// WHIR works over smooth Reed-Solomon codes, and its folding argument rests
/// on <i>mutual</i> correlated agreement (WHIR Section 4.2). The regimes
/// differ in how far the claimed proximity radius reaches and in what the
/// mutual-agreement claim rests on at that radius: inside the unique-decoding
/// radius the mutual upgrade is loss-free for every linear code
/// (WHIR Lemma 4.10) on top of the proven Reed-Solomon correlated-agreement
/// theorem (Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, FOCS 2020 /
/// J.ACM 2023); at the Johnson radius correlated agreement is proven with
/// the improved <c>O(n/η^5)</c> error of BCHKS25 Theorem 1.5 and the mutual
/// form follows by the Guruswami-Sudan generalization of Haböck's note, so
/// both <see cref="UniqueDecoding"/> and <see cref="ListDecodingJohnson"/>
/// carry theorem-backed ledgers; only beyond the Johnson radius does the
/// mutual form remain conjectured (WHIR Conjecture 4.12 Item 2).
/// </para>
/// <para>
/// References: Arnon, Chiesa, Fenzi, Yogev, "WHIR: Reed-Solomon Proximity
/// Testing with Super-Fast Verification" (EUROCRYPT 2025, IACR ePrint
/// 2024/1586) — Construction 5.1, Theorem 5.2, Lemma 4.10, Conjecture 4.12,
/// Section 6.2; Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, "Proximity Gaps
/// for Reed-Solomon Codes" (FOCS 2020 / J.ACM 2023); Ben-Sasson, Carmon,
/// Haböck, Kopparty, Saraf, "On Proximity Gaps for Reed-Solomon Codes" (IACR
/// ePrint 2025/2055) — Theorem 1.5; Haböck, "A note on mutual correlated
/// agreement for Reed-Solomon codes" (IACR ePrint 2025/2110); Crites, Stewart
/// (IACR ePrint 2025/2046) and Krachun, Kazanin, Haböck (IACR ePrint
/// 2026/782) for the refutation of the plain-form capacity conjectures.
/// </para>
/// </remarks>
public enum WhirSoundnessRegime
{
    /// <summary>
    /// Unique decoding: <c>δ_i = (1 - ρ_i) / 2</c>, half the Reed-Solomon
    /// relative minimum distance. The most queries of the three regimes and
    /// the wired default, because its soundness chain rests on the least
    /// machinery: correlated agreement at this radius is the Reed-Solomon
    /// proximity-gap theorem (Ben-Sasson, Carmon, Ishai, Kopparty, Saraf,
    /// FOCS 2020), and the mutual-correlated-agreement form the folding
    /// rounds need follows loss-free from WHIR Lemma 4.10, whose radius cap
    /// <c>min(1 - δ_min/2, B)</c> this regime's radius sits inside
    /// (WHIR Corollary 4.11 gives <c>B* = (1 + ρ)/2</c> and error
    /// <c>(ℓ-1)·2^m / (ρ·|F|)</c>). List sizes are 1 inside this radius, so
    /// every union-bound ledger row is exact. One boundary note: the priced
    /// radius <c>δ = (1 - ρ)/2</c> equals <c>1 - B*</c>, the edge of the open
    /// interval the corollary states — this mirrors the paper's own WHIR-UD
    /// choice in Section 6.2 verbatim rather than introducing a deviation.
    /// </summary>
    UniqueDecoding = 0,

    /// <summary>
    /// List decoding at the Johnson radius:
    /// <c>δ_i = 1 - √ρ_i - η_i</c> for slack <c>η_i = √ρ_i / (2·m_J)</c> with
    /// Johnson proximity parameter <c>m_J</c>, whose default 10 gives the
    /// WHIR paper's <c>η = √ρ/20</c> (Section 6.2, the WHIR-JB
    /// configuration). Roughly a third fewer total queries than
    /// <see cref="UniqueDecoding"/> at the wired rates. <b>Theorem-backed</b>:
    /// correlated agreement to this radius carries the proven
    /// <c>O(n/η^5)</c> error of BCHKS25 Theorem 1.5 (IACR ePrint 2025/2055),
    /// and the <i>mutual</i> form the folding rounds need follows by the
    /// Guruswami-Sudan generalization of Haböck's note (IACR ePrint
    /// 2025/2110), superseding the WHIR paper's Conjecture 4.12 Item 1
    /// pricing at this radius. List sizes follow the Johnson bound
    /// <c>ℓ ≤ 1/(2η√ρ) = m_J/ρ</c> (WHIR Theorem 4.3).
    /// </summary>
    ListDecodingJohnson = 1,

    /// <summary>
    /// Decoding to capacity with the WHIR paper's slack:
    /// <c>δ_i = 1 - ρ_i - η_i</c> for <c>η_i = ρ_i / 2</c> (WHIR Section 6.2,
    /// the WHIR-CB configuration). The fewest queries, and <b>retained for
    /// parameter comparison only — a soundness claim must not rest on it</b>:
    /// the required mutual correlated agreement at capacity is WHIR
    /// Conjecture 4.12 Item 2, whose plain-form Reed-Solomon capacity
    /// analogues are disproven as stated (Crites, Stewart, IACR ePrint
    /// 2025/2046; Krachun, Kazanin, Haböck, IACR ePrint 2026/782), and the
    /// conjecture leaves the capacity-radius list-size bound unpinned, so the
    /// field-side union-bound ledger rows cannot be computed from a stated
    /// result. <see cref="WhirParameterSchedule.Create"/> therefore rejects
    /// this regime; the query-count and proximity-parameter derivations in
    /// <see cref="WellKnownWhirParameters"/> accept it so the comparison
    /// figures stay reproducible.
    /// </summary>
    ConjecturedCapacity = 2
}

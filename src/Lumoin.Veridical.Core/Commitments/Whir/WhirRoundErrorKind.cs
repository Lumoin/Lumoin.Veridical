namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The kind of verifier message a WHIR round-by-round soundness ledger row
/// prices: the five error families of WHIR Theorem 5.2, one per kind of
/// randomness the verifier sends, the batch combination randomness of
/// WHIR Theorem 5.6 that prefixes them when separate claims are batched, and
/// the mask spot checks the hiding extension of HVZK-WHIR Construction 9.7
/// appends.
/// </summary>
public enum WhirRoundErrorKind
{
    /// <summary>
    /// A folding challenge <c>α_{0,s}</c> of the initial sumcheck:
    /// <c>ε ≤ d*·ℓ_{0,s-1}/|F| + err*(C^{(0,s)}, 2, δ_0)</c>.
    /// </summary>
    InitialSumcheckFold = 0,

    /// <summary>
    /// An out-of-domain sample <c>z_{i,0}</c>:
    /// <c>ε ≤ 2^{m_i}·ℓ_{i,0}² / (2·|F|)</c> (WHIR Lemma 4.25).
    /// </summary>
    OutOfDomainSample = 1,

    /// <summary>
    /// The shift queries and combination randomness
    /// <c>(z_{i,1..t}, γ_i)</c>:
    /// <c>ε ≤ (1-δ_{i-1})^t + ℓ_{i,0}·(t+1)/|F|</c> for <c>t</c> the queries
    /// paid against oracle <c>i-1</c>.
    /// </summary>
    ShiftQueries = 2,

    /// <summary>
    /// A folding challenge <c>α_{i,s}</c> of a main-loop sumcheck:
    /// <c>ε ≤ d·ℓ_{i,s-1}/|F| + err*(C^{(i,s)}, 2, δ_i)</c>.
    /// </summary>
    MainSumcheckFold = 3,

    /// <summary>
    /// The final randomness <c>r^fin</c>:
    /// <c>ε ≤ (1-δ_{M-1})^t</c> for <c>t</c> the queries paid against the
    /// last oracle.
    /// </summary>
    FinalQueries = 4,

    /// <summary>
    /// The batch combination randomness <c>γ</c> of WHIR Construction 5.5,
    /// combining <c>t</c> separate claims into one:
    /// <c>ε ≤ (t-1)·ℓ/|F|</c> for <c>ℓ</c> the initial code's list-size
    /// bound (WHIR Theorem 5.6); the row prefixes the single-statement
    /// ledger.
    /// </summary>
    ConstraintBatching = 5,

    /// <summary>
    /// The base-case spot checks against one mask group of the hiding path:
    /// <c>ε ≤ (1-δ_zk)^t_zk</c> for <c>t_zk</c> positions at the mask code's
    /// rate, where the group's carried and fresh oracles are bound by one
    /// joint per-position identity (HVZK-WHIR Construction 9.7). One row per
    /// mask group in creation order; only zero-knowledge ledgers carry it.
    /// </summary>
    MaskOracleQueries = 6
}

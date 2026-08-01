namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The kind of verifier message a WHIR round-by-round soundness ledger row
/// prices: the five error families of WHIR Theorem 5.2, one per kind of
/// randomness the verifier sends.
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
    FinalQueries = 4
}

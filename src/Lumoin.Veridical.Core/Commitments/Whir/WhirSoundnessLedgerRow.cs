namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// One row of the WHIR round-by-round soundness ledger: the bits of one
/// verifier message's flip probability under WHIR Theorem 5.2. The
/// protocol's round-by-round soundness — the property the BCS transformation
/// compiles — is the worst row, not the sum, but the ledger also carries the
/// union-bound total for straight-line soundness accounting.
/// </summary>
/// <param name="Kind">The error family the row prices.</param>
/// <param name="Iteration">The iteration index <c>i</c> the message belongs to: 0 for the initial sumcheck, and <c>M</c> — one past the last oracle index — for the final-randomness row, which follows the main loop rather than belonging to any oracle round.</param>
/// <param name="SumcheckRound">The sumcheck round <c>s</c> in <c>1..k</c> for folding rows; 0 for the other kinds.</param>
/// <param name="ErrorBits">The row's soundness in bits, <c>-log2(ε)</c>.</param>
public readonly record struct WhirSoundnessLedgerRow(
    WhirRoundErrorKind Kind,
    int Iteration,
    int SumcheckRound,
    double ErrorBits);

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The derived parameters of one WHIR oracle round: the code the oracle
/// <c>f_i</c> claims membership of and the price the verifier pays to test
/// it. Row 0 describes the committed input oracle; rows <c>1..M-1</c>
/// describe the folded oracles the prover sends in the main loop
/// (WHIR Construction 5.1).
/// </summary>
/// <param name="OracleIndex">The oracle index <c>i</c> in <c>0..M-1</c>.</param>
/// <param name="VariableCount">The variable count <c>m_i = m - i·k</c> of the round's code.</param>
/// <param name="DomainSizeLog2">The evaluation-domain exponent: <c>|L_i| = 2^DomainSizeLog2</c>, halving every round.</param>
/// <param name="RateLog2">The inverse-rate exponent: <c>ρ_i = 2^-RateLog2</c>; grows by <c>k - 1</c> every round — the STIR-style rate improvement.</param>
/// <param name="ProximityParameter">The proximity parameter <c>δ_i</c> the regime prices at this round's rate.</param>
/// <param name="ListSizeBound">The list-size bound <c>ℓ_i</c> at radius <c>δ_i</c>; 1 under unique decoding.</param>
/// <param name="QueryCount">The queries <c>t_i</c> paid against this oracle — by the next iteration's shift phase, or by the final phase for the last oracle.</param>
public readonly record struct WhirRoundParameters(
    int OracleIndex,
    int VariableCount,
    int DomainSizeLog2,
    int RateLog2,
    double ProximityParameter,
    double ListSizeBound,
    int QueryCount);

using System;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// The deterministic parameter policy of the statistical sumcheck mask
/// (<c>ZK-STATMASK-DESIGN.md</c> §2 v3): from the masked sumcheck's
/// shape alone it derives where the mask's coefficient commitment lives, so the
/// prover and verifier agree on every size without wire data. The mask itself
/// is the Libra sum-of-univariates (<c>perVariableDegree·d + 1</c>
/// coefficients, degree matching the masked round format); the committed
/// vector <c>C*</c> appends random <em>filler</em> whose all-ones-weighted
/// coordinates launder the weighted opening's cleartext reveals (the §3
/// ledger). Over BaseFold the commitment is additionally dimension-lifted so
/// its IOPP query reveals are laundered by the lift block (the enforced
/// bounded-independence budget); over Pedersen/IPA there is no lift — the
/// commitment hides unconditionally and only the inner-product argument's
/// cleartext functionals spend filler.
/// </summary>
public static class WellKnownStatisticalMaskParameters
{
    //The rank-slack margin over the counted level-2 reveals: the §3 lemma's
    //generic-rank argument wants headroom beyond the exact reveal count so a
    //rank-deficient challenge draw stays a negligible-probability event. Firmed
    //by the SM.4 lemma; mirrors the hiding budget's additive margin in spirit.
    private const int RankSlackCoordinateCount = 8;

    //The ℓ₂ search ceiling: 2^31 coordinates is far beyond any realisable
    //commitment; reaching it indicates a logic error, not a configuration.
    private const int CoefficientVariableCountCeiling = 31;

    //The per-variable degree bounds of the mask's univariates, matching the
    //masked round formats the kernel supports: 2 for a quadratic sumcheck
    //(BaseFold's f·eq_z, the Spartan inner), 3 for the Spartan outer cubic.
    private const int QuadraticDegree = 2;
    private const int CubicDegree = 3;

    //The Pedersen/IPA weighted opening's cleartext functional reveals of the
    //committed vector: the precommitted filler sum σ_F and the IPA's final
    //folded scalar. The round L/R points and C_f are blinded or DLOG-hard
    //group elements — the Pedersen path's hiding is computational there, and
    //the filler only launders what is revealed in the clear.
    private const int PedersenIpaCleartextRevealCount = 2;


    /// <summary>
    /// Resolves the mask-commitment shape for a <paramref name="sumcheckVariableCount"/>-variable
    /// masked sumcheck under the wired classical-security code shape: the
    /// smallest coefficient variable count <c>ℓ₂</c> whose <c>2^ℓ₂</c>
    /// coordinates fit the <c>perVariableDegree·d + 1</c> mask coefficients
    /// plus the ledger-required filler <c>F ≥ 2·(ℓ₂ + t_C) + 2 + slack</c>,
    /// where <c>t_C</c> is the commitment's own minimum hiding lift at
    /// <paramref name="queryCount"/>. Every coordinate beyond the mask
    /// coefficients becomes filler — there are no zero-weight real coordinates.
    /// </summary>
    /// <param name="sumcheckVariableCount">The masked sumcheck's variable count <c>d</c>; must be positive.</param>
    /// <param name="curve">The curve the wired classical-security code shape is over.</param>
    /// <param name="queryCount">The IOPP query repetition count of the surrounding protocol.</param>
    /// <param name="perVariableDegree">The mask univariates' degree, matching the masked round format; in <c>[2, 3]</c>. Defaults to 2 (the BaseFold-internal quadratic sumcheck).</param>
    /// <returns>The resolved parameters.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    public static StatisticalMaskParameters CreateClassicalSecurity(int sumcheckVariableCount, CurveParameterSet curve, int queryCount, int perVariableDegree = QuadraticDegree)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sumcheckVariableCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);
        ArgumentOutOfRangeException.ThrowIfLessThan(perVariableDegree, QuadraticDegree);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(perVariableDegree, CubicDegree);

        //The sum-of-univariates mask: constant + one coefficient per variable
        //and degree.
        int maskCoefficientCount = (perVariableDegree * sumcheckVariableCount) + 1;

        for(int coefficientVariableCount = 1; coefficientVariableCount < CoefficientVariableCountCeiling; coefficientVariableCount++)
        {
            int extraVariableCount = ZkBaseFoldPolynomialCommitmentScheme.GetMinimumExtraVariableCount(coefficientVariableCount, curve, queryCount);
            int liftedVariableCount = coefficientVariableCount + extraVariableCount;

            //The weighted opening reveals ≈ 2·rounds + 2 functionals supported
            //on the nonzero-weight coordinates; the filler must rank-cover them
            //with slack (design doc §3 condition 2).
            int requiredFiller = (2 * liftedVariableCount) + 2 + RankSlackCoordinateCount;
            if(maskCoefficientCount + requiredFiller <= 1 << coefficientVariableCount)
            {
                return new StatisticalMaskParameters(sumcheckVariableCount, maskCoefficientCount, coefficientVariableCount, extraVariableCount);
            }
        }

        throw new ArgumentOutOfRangeException(
            nameof(sumcheckVariableCount),
            $"No coefficient variable count below {CoefficientVariableCountCeiling} satisfies the filler ledger for d = {sumcheckVariableCount}, queryCount = {queryCount} — this indicates a logic error.");
    }


    /// <summary>
    /// Resolves the mask-commitment shape for a Pedersen/IPA weighted opening
    /// (the Hyrax path's <c>CommitVector</c> + <c>OpenWeightedSum</c>): no
    /// dimension lift (<c>t_C = 0</c> — the Pedersen commitment hides without
    /// one), and the filler need only launder the inner-product argument's
    /// cleartext functional reveals (<c>σ_F</c> and the final folded scalar)
    /// with the rank slack. The smallest <c>ℓ₂</c> satisfying that ledger;
    /// every coordinate beyond the mask coefficients becomes filler.
    /// </summary>
    /// <param name="sumcheckVariableCount">The masked sumcheck's variable count <c>d</c>; must be positive.</param>
    /// <param name="perVariableDegree">The mask univariates' degree, matching the masked round format; in <c>[2, 3]</c>.</param>
    /// <returns>The resolved parameters, with <see cref="StatisticalMaskParameters.ExtraVariableCount"/> zero.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range.</exception>
    public static StatisticalMaskParameters CreatePedersenIpa(int sumcheckVariableCount, int perVariableDegree)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(sumcheckVariableCount);
        ArgumentOutOfRangeException.ThrowIfLessThan(perVariableDegree, QuadraticDegree);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(perVariableDegree, CubicDegree);

        int maskCoefficientCount = (perVariableDegree * sumcheckVariableCount) + 1;
        int requiredFiller = PedersenIpaCleartextRevealCount + RankSlackCoordinateCount;

        for(int coefficientVariableCount = 1; coefficientVariableCount < CoefficientVariableCountCeiling; coefficientVariableCount++)
        {
            if(maskCoefficientCount + requiredFiller <= 1 << coefficientVariableCount)
            {
                return new StatisticalMaskParameters(sumcheckVariableCount, maskCoefficientCount, coefficientVariableCount, extraVariableCount: 0);
            }
        }

        throw new ArgumentOutOfRangeException(
            nameof(sumcheckVariableCount),
            $"No coefficient variable count below {CoefficientVariableCountCeiling} fits the mask and filler for d = {sumcheckVariableCount} — this indicates a logic error.");
    }
}

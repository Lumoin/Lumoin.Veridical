using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Collections.Generic;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The derived parameter schedule of one WHIR IOPP instance: the per-round
/// codes, proximity parameters, list sizes and query counts of
/// WHIR Construction 5.1 for a constant folding parameter, together with the
/// full round-by-round soundness ledger of WHIR Theorem 5.2. The schedule is
/// the single authority the prover, the verifier and the wire codec size
/// their work from — the two endpoints derive it independently from the same
/// public figures, so no dimension travels in a proof.
/// </summary>
/// <remarks>
/// <para>
/// Shape: for message variable count <c>m</c>, initial inverse rate
/// <c>2^c</c> and folding parameter <c>k</c>, the protocol runs
/// <c>M = ⌊m/k⌋</c> iterations. Oracle <c>i</c> lives on a smooth domain of
/// size <c>2^(m + c - i)</c> — halving every iteration, the standard
/// instantiation of Construction 5.1's free choice <c>|L_i| ≥ 2^(m_i)</c> —
/// while its variable count drops by <c>k</c>, so the inverse-rate exponent
/// grows by <c>k - 1</c> per round and later rounds pay markedly fewer
/// queries: the STIR-style rate improvement that separates WHIR from
/// BaseFold. The final polynomial keeps <c>m - M·k</c> variables and is sent
/// in the clear.
/// </para>
/// <para>
/// The scalar field must carry a multiplicative subgroup of the initial
/// domain size, so <c>m + c</c> is capped by the field's two-adicity
/// (32 for the BLS12-381 scalar field, 28 for BN254).
/// </para>
/// </remarks>
public sealed class WhirParameterSchedule
{
    /// <summary>The curve whose scalar field the codes live in.</summary>
    public CurveParameterSet Curve { get; }

    /// <summary>The soundness regime the proximity parameters and list sizes are priced under.</summary>
    public WhirSoundnessRegime Regime { get; }

    /// <summary>The per-round soundness target <c>λ</c> in bits.</summary>
    public int SecurityLevelBits { get; }

    /// <summary>The committed message's variable count <c>m</c>.</summary>
    public int VariableCount { get; }

    /// <summary>The constant folding parameter <c>k</c>: variables folded per iteration.</summary>
    public int FoldingParameter { get; }

    /// <summary>The BCHKS25 Johnson proximity parameter <c>m_J</c> fixing the Johnson-regime slack <c>η = √ρ/(2m_J)</c>; carried for endpoint agreement even when the regime ignores it.</summary>
    public int JohnsonProximityParameter { get; }

    /// <summary>The initial inverse-rate exponent <c>c</c>: the input oracle's rate is <c>2^-c</c>.</summary>
    public int InitialRateLog2 { get; }

    /// <summary>The iteration count <c>M = ⌊m/k⌋</c>.</summary>
    public int IterationCount { get; }

    /// <summary>The final polynomial's variable count <c>m - M·k</c>, in <c>0..k-1</c>.</summary>
    public int FinalVariableCount { get; }

    /// <summary>The floor of the scalar field's size in bits, the denominator of every field-driven ledger row.</summary>
    public int FieldFloorBits { get; }

    /// <summary>The per-oracle round parameters, index <c>0..M-1</c>.</summary>
    public IReadOnlyList<WhirRoundParameters> Rounds { get; }

    /// <summary>The round-by-round soundness ledger: one row per verifier message family of WHIR Theorem 5.2.</summary>
    public IReadOnlyList<WhirSoundnessLedgerRow> LedgerRows { get; }

    /// <summary>
    /// The worst ledger row in bits — the protocol's round-by-round soundness,
    /// the figure the BCS transformation compiles. At least
    /// <see cref="SecurityLevelBits"/> by construction.
    /// </summary>
    public double MinimumRoundBits { get; }

    /// <summary>
    /// The union-bound total across all ledger rows in bits,
    /// <c>-log2(Σ ε_row)</c>: the straight-line soundness figure for
    /// accounting that sums rather than takes the worst round.
    /// </summary>
    public double UnionBoundBits { get; }


    private WhirParameterSchedule(
        CurveParameterSet curve,
        WhirSoundnessRegime regime,
        int securityLevelBits,
        int variableCount,
        int foldingParameter,
        int johnsonProximityParameter,
        int initialRateLog2,
        int fieldFloorBits,
        WhirRoundParameters[] rounds,
        WhirSoundnessLedgerRow[] ledgerRows,
        double minimumRoundBits,
        double unionBoundBits)
    {
        Curve = curve;
        Regime = regime;
        SecurityLevelBits = securityLevelBits;
        VariableCount = variableCount;
        FoldingParameter = foldingParameter;
        JohnsonProximityParameter = johnsonProximityParameter;
        InitialRateLog2 = initialRateLog2;
        IterationCount = rounds.Length;
        FinalVariableCount = variableCount - (rounds.Length * foldingParameter);
        FieldFloorBits = fieldFloorBits;
        Rounds = rounds;
        LedgerRows = ledgerRows;
        MinimumRoundBits = minimumRoundBits;
        UnionBoundBits = unionBoundBits;
    }


    /// <summary>
    /// Derives the schedule for the given shape, validating that the field
    /// carries the initial domain and that every round's query count fits its
    /// folded query domain, and computing the full round-by-round ledger. The
    /// derivation fails loudly rather than silently degrade: a shape whose
    /// worst ledger row lands under the target is rejected.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the codes live in.</param>
    /// <param name="variableCount">The committed message's variable count <c>m</c>, at least the folding parameter.</param>
    /// <param name="initialRateLog2">The initial inverse-rate exponent <c>c ≥ 1</c>.</param>
    /// <param name="foldingParameter">The folding parameter <c>k ≥ 1</c>; defaults to <see cref="WellKnownWhirParameters.DefaultFoldingParameter"/>.</param>
    /// <param name="securityLevelBits">The per-round soundness target <c>λ</c>; defaults to <see cref="WellKnownWhirParameters.ClassicalSecurityLevelBits"/>.</param>
    /// <param name="regime">The soundness regime; defaults to the fully-proven <see cref="WhirSoundnessRegime.UniqueDecoding"/>.</param>
    /// <param name="johnsonProximityParameter">The BCHKS25 Johnson proximity parameter <c>m_J ≥ 1</c> fixing the Johnson-regime slack <c>η = √ρ/(2m_J)</c>; defaults to <see cref="WellKnownWhirParameters.DefaultJohnsonProximityParameter"/> and is ignored outside the Johnson regime.</param>
    /// <returns>The validated schedule.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range or the regime cannot carry a soundness claim.</exception>
    /// <exception cref="ArgumentException">When the field's two-adicity cannot carry the initial domain, a query count exceeds its query domain, or the realised ledger misses the target.</exception>
    public static WhirParameterSchedule Create(
        CurveParameterSet curve,
        int variableCount,
        int initialRateLog2,
        int foldingParameter = WellKnownWhirParameters.DefaultFoldingParameter,
        int securityLevelBits = WellKnownWhirParameters.ClassicalSecurityLevelBits,
        WhirSoundnessRegime regime = WellKnownWhirParameters.ClassicalSecurityRegime,
        int johnsonProximityParameter = WellKnownWhirParameters.DefaultJohnsonProximityParameter)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(securityLevelBits);
        ArgumentOutOfRangeException.ThrowIfLessThan(foldingParameter, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(initialRateLog2, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(variableCount, foldingParameter);
        ArgumentOutOfRangeException.ThrowIfLessThan(johnsonProximityParameter, 1);

        if (regime == WhirSoundnessRegime.ConjecturedCapacity)
        {
            throw new ArgumentOutOfRangeException(
                nameof(regime),
                regime,
                "The capacity regime is retained for query-count comparison only; a schedule carrying a soundness claim must use a regime with a priced ledger.");
        }

        //A joint-shape failure of variableCount and initialRateLog2 together,
        //so an ArgumentException in the clamp-guard mold rather than the
        //single-argument range exception the raw NTT surface throws.
        int twoAdicity = ScalarNtt.TwoAdicity(curve);
        int initialDomainSizeLog2 = variableCount + initialRateLog2;
        if (initialDomainSizeLog2 > twoAdicity)
        {
            throw new ArgumentException(
                $"The initial evaluation domain needs 2^{initialDomainSizeLog2} elements but the scalar field's two-adicity is {twoAdicity}.",
                nameof(variableCount));
        }

        int iterationCount = variableCount / foldingParameter;
        var rounds = new WhirRoundParameters[iterationCount];
        for (int i = 0; i < iterationCount; i++)
        {
            int roundVariableCount = variableCount - (i * foldingParameter);
            int domainSizeLog2 = initialDomainSizeLog2 - i;
            int rateLog2 = domainSizeLog2 - roundVariableCount;
            double proximity = WellKnownWhirParameters.ProximityParameter(regime, rateLog2, johnsonProximityParameter);
            double listSize = WellKnownWhirParameters.ListSizeBound(regime, rateLog2, johnsonProximityParameter);
            int queryCount = WellKnownWhirParameters.ComputeQueryCount(securityLevelBits, rateLog2, regime, johnsonProximityParameter);

            //Shift and final queries land on the 2^k-coset-folded domain. The
            //paper's (1 - δ)^t bound tolerates repeated samples, so this is a
            //deliberate tightening: a shape that cannot even place its queries
            //on distinct cosets is refused rather than run with wasted budget.
            int queryDomainSizeLog2 = domainSizeLog2 - foldingParameter;
            if (queryCount > (1L << queryDomainSizeLog2))
            {
                throw new ArgumentException(
                    $"Oracle {i} needs {queryCount} queries but its folded query domain has only 2^{queryDomainSizeLog2} elements; the shape cannot reach {securityLevelBits} bits.",
                    nameof(variableCount));
            }

            rounds[i] = new WhirRoundParameters(i, roundVariableCount, domainSizeLog2, rateLog2, proximity, listSize, queryCount);
        }

        int fieldFloorBits = WellKnownSecurityLevels.ScalarFieldSoundnessFloorBits(curve);
        WhirSoundnessLedgerRow[] ledgerRows = ComputeLedger(regime, fieldFloorBits, foldingParameter, johnsonProximityParameter, rounds);

        double minimumRoundBits = double.PositiveInfinity;
        double totalError = 0.0;
        foreach (WhirSoundnessLedgerRow row in ledgerRows)
        {
            minimumRoundBits = Math.Min(minimumRoundBits, row.ErrorBits);
            totalError += Math.Pow(2.0, -row.ErrorBits);
        }

        if (minimumRoundBits < securityLevelBits)
        {
            throw new ArgumentException(
                $"The realised round-by-round soundness is {minimumRoundBits:F2} bits, under the {securityLevelBits}-bit target.",
                nameof(securityLevelBits));
        }

        return new WhirParameterSchedule(
            curve,
            regime,
            securityLevelBits,
            variableCount,
            foldingParameter,
            johnsonProximityParameter,
            initialRateLog2,
            fieldFloorBits,
            rounds,
            ledgerRows,
            minimumRoundBits,
            -Math.Log2(totalError));
    }


    /// <summary>
    /// Prices every verifier message of WHIR Theorem 5.2 for the derived
    /// rounds: the initial and main-loop folding challenges, the
    /// out-of-domain samples, the shift-query messages and the final
    /// randomness.
    /// </summary>
    /// <param name="regime">The soundness regime.</param>
    /// <param name="fieldFloorBits">The floor of the scalar field's size in bits.</param>
    /// <param name="foldingParameter">The folding parameter <c>k</c>.</param>
    /// <param name="johnsonProximityParameter">The BCHKS25 Johnson proximity parameter <c>m_J</c>.</param>
    /// <param name="rounds">The derived per-oracle rounds.</param>
    /// <returns>The ledger rows in protocol order.</returns>
    private static WhirSoundnessLedgerRow[] ComputeLedger(
        WhirSoundnessRegime regime,
        int fieldFloorBits,
        int foldingParameter,
        int johnsonProximityParameter,
        WhirRoundParameters[] rounds)
    {
        int iterationCount = rounds.Length;
        var ledger = new List<WhirSoundnessLedgerRow>((iterationCount * (foldingParameter + 2)) - 1);

        for (int i = 0; i < iterationCount; i++)
        {
            WhirRoundParameters round = rounds[i];

            if (i > 0)
            {
                WhirRoundParameters previous = rounds[i - 1];

                //Out-of-domain sample: ε ≤ 2^{m_i}·ℓ_i²/(2·|F|), WHIR Lemma 4.25.
                double outOfDomainBits = fieldFloorBits + 1.0 - round.VariableCount - (2.0 * Math.Log2(round.ListSizeBound));
                ledger.Add(new WhirSoundnessLedgerRow(WhirRoundErrorKind.OutOfDomainSample, i, 0, outOfDomainBits));

                //Shift queries: ε ≤ (1-δ_{i-1})^t + ℓ_i·(t+1)/|F| for t queries
                //against the previous oracle.
                double queryTermBits = previous.QueryCount * -Math.Log2(1.0 - previous.ProximityParameter);
                double shiftFieldBits = fieldFloorBits - Math.Log2(round.ListSizeBound * (previous.QueryCount + 1.0));
                ledger.Add(new WhirSoundnessLedgerRow(WhirRoundErrorKind.ShiftQueries, i, 0, CombineErrorBits(queryTermBits, shiftFieldBits)));
            }

            //Folding challenges: ε ≤ d·ℓ_i/|F| + err*(C^{(i,s)}, 2, δ_i) for the
            //sumcheck round landing in the code with m_i - s variables. The
            //initial and main-loop degrees coincide at the wired weight shape.
            WhirRoundErrorKind foldKind = i == 0 ? WhirRoundErrorKind.InitialSumcheckFold : WhirRoundErrorKind.MainSumcheckFold;
            for (int s = 1; s <= foldingParameter; s++)
            {
                double identityTermBits = fieldFloorBits - Math.Log2(WellKnownWhirParameters.SumcheckDegreeBound * round.ListSizeBound);
                double agreementBits = WellKnownWhirParameters.MutualCorrelatedAgreementErrorBits(
                    regime,
                    fieldFloorBits,
                    round.VariableCount - s,
                    round.RateLog2,
                    johnsonProximityParameter);
                ledger.Add(new WhirSoundnessLedgerRow(foldKind, i, s, CombineErrorBits(identityTermBits, agreementBits)));
            }
        }

        //Final randomness: ε ≤ (1-δ_{M-1})^t against the last oracle.
        WhirRoundParameters last = rounds[iterationCount - 1];
        double finalBits = last.QueryCount * -Math.Log2(1.0 - last.ProximityParameter);
        ledger.Add(new WhirSoundnessLedgerRow(WhirRoundErrorKind.FinalQueries, iterationCount, 0, finalBits));

        return [.. ledger];
    }


    /// <summary>
    /// Combines two error terms in bits: <c>-log2(2^-a + 2^-b)</c>. Shared
    /// with the zero-knowledge extension's ledger derivation.
    /// </summary>
    /// <param name="firstBits">The first term in bits.</param>
    /// <param name="secondBits">The second term in bits.</param>
    /// <returns>The combined error in bits, at most the smaller input.</returns>
    internal static double CombineErrorBits(double firstBits, double secondBits)
    {
        return -Math.Log2(Math.Pow(2.0, -firstBits) + Math.Pow(2.0, -secondBits));
    }
}

using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Collections.Generic;
using System.Numerics;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The derived zero-knowledge extension of a WHIR parameter schedule: the
/// per-oracle encoding-randomness budgets, the mask code shapes and the mask
/// spot-check count of the HVZK-WHIR pipeline (eprint 2026/391,
/// Constructions 6.3 and 9.7). The extension wraps the plain
/// <see cref="WhirParameterSchedule"/> by composition — the non-hiding round
/// structure, domains and query counts carry over unchanged, and both
/// endpoints derive this extension independently from the same public
/// figures, so no dimension travels in a proof.
/// </summary>
/// <remarks>
/// <para>
/// Budget rule: oracle <c>i</c> is opened exactly
/// <c>Rounds[i].QueryCount</c> times — by the next iteration's shift queries,
/// or by the final phase for the last oracle — so its per-limb randomness
/// budget <c>t_i</c> equals that count and every opening is simulatable. The
/// randomized limb occupies <c>2^(m_i - k) + t_i</c> coefficient slots inside
/// its <c>2^(n_i - k)</c>-row domain; the fit is enforced loudly because it is
/// load-bearing for hiding, not just a layout constraint — a saturated
/// opening set would reveal a limb polynomial outright.
/// </para>
/// <para>
/// The mask spot-check count <c>t_zk</c> is not a knob: it is derived from
/// the schedule's security target plus a union bound over all mask oracles,
/// with no proof-of-work discount — this library wires no proof-of-work at
/// all, and the field-driven rows of the wired ~2^254 scalar fields sit
/// hundreds of bits above every target. <c>t_zk</c> doubles as each mask
/// code's own randomness length, making the mask openings
/// <c>t_zk</c>-private.
/// </para>
/// <para>
/// The masked sumcheck of Construction 6.3 requires an odd field
/// characteristic and a mask covering the degree-2 plain round polynomial
/// (eprint 2026/391 Lemma 6.4). Every wired curve's scalar field is a large
/// odd prime field, and the <see cref="MinimumMaskMessageLength"/> floor is
/// checked loudly.
/// </para>
/// </remarks>
public sealed class WhirZkParameters
{
    /// <summary>
    /// The smallest admissible mask message length: a mask of degree
    /// <c>EllZk - 1 ≥ 2</c> covers the degree-2 plain sumcheck round
    /// polynomial (eprint 2026/391 Lemma 6.4).
    /// </summary>
    public const int MinimumMaskMessageLength = 3;

    /// <summary>
    /// The default mask message length <c>ℓ_zk = 4</c>: one above the floor,
    /// so the masked wire degree <c>max(ℓ_zk - 1, 2) = 3</c> coincides with
    /// the schedule's <see cref="WellKnownWhirParameters.SumcheckDegreeBound"/>.
    /// </summary>
    public const int DefaultMaskMessageLength = 4;

    /// <summary>
    /// The default mask-code inverse-rate exponent. A rate-one mask code has
    /// minimal distance and its spot checks barely bind, so the floor is 1 —
    /// at least a two-fold domain expansion.
    /// </summary>
    public const int DefaultMaskRateLog2 = 1;

    /// <summary>
    /// The out-of-domain samples each main-loop iteration draws — the wired
    /// prover and verifier exchange one point and reply per folded oracle.
    /// The code-switch masks of the hiding path answer these privately, so
    /// each carries one pad coordinate per sample.
    /// </summary>
    public const int OutOfDomainSamplesPerIteration = 1;


    /// <summary>The plain schedule this extension wraps.</summary>
    public WhirParameterSchedule Schedule { get; }

    /// <summary>The mask message length <c>ℓ_zk</c> of the masked sumcheck.</summary>
    public int MaskMessageLength { get; }

    /// <summary>The mask codes' inverse-rate exponent.</summary>
    public int MaskRateLog2 { get; }

    /// <summary>
    /// The mask spot-check count <c>t_zk</c>, derived from the schedule's
    /// security target plus the <see cref="MaskOracleUnionLog2"/> union bits;
    /// also every mask code's randomness length.
    /// </summary>
    public int MaskQueryCount { get; }

    /// <summary>
    /// The union-bound bits added to the mask spot-check target:
    /// <c>⌈log2(2M + 2)⌉</c> over the protocol's mask oracles — one sumcheck
    /// mask batch per iteration, one code-switch mask per folded oracle and
    /// the base case's fresh commitments.
    /// </summary>
    public int MaskOracleUnionLog2 { get; }

    /// <summary>
    /// The per-limb encoding-randomness budget <c>t_i</c> of every committed
    /// oracle, index <c>0..M-1</c>: the spot checks ever opened against that
    /// oracle, <c>Rounds[i].QueryCount</c>.
    /// </summary>
    public IReadOnlyList<int> OracleRandomnessCounts { get; }

    /// <summary>The mask code of the Construction 6.3 sumcheck masks: message length <c>ℓ_zk</c>.</summary>
    public WhirMaskCodeShape SumcheckMaskShape { get; }

    /// <summary>
    /// The code-switch mask codes, one per main-loop iteration
    /// <c>1..M-1</c>: entry <c>i - 1</c> commits the consumed oracle's folded
    /// randomness plus the iteration's private out-of-domain pad, message
    /// length <c>t_(i-1) + 1</c>.
    /// </summary>
    public IReadOnlyList<WhirMaskCodeShape> SwitchMaskShapes { get; }

    /// <summary>
    /// The zero-knowledge round-by-round soundness ledger: the plain
    /// schedule's rows with every folding row repriced for the masked
    /// sumcheck of Construction 6.3, followed by one
    /// <see cref="WhirRoundErrorKind.MaskOracleQueries"/> row per mask group
    /// in creation order. The non-fold rows carry over unchanged — the
    /// out-of-domain, shift-query and final-randomness bindings are the same
    /// error families in the hiding path.
    /// </summary>
    public IReadOnlyList<WhirSoundnessLedgerRow> LedgerRows { get; }

    /// <summary>
    /// The worst zero-knowledge ledger row in bits — at least the schedule's
    /// <see cref="WhirParameterSchedule.SecurityLevelBits"/> by construction;
    /// a shape whose masked rows land under the target is refused.
    /// </summary>
    public double MinimumRoundBits { get; }

    /// <summary>
    /// The union-bound total across all zero-knowledge ledger rows in bits,
    /// <c>-log2(Σ ε_row)</c>: the straight-line soundness figure for
    /// accounting that sums rather than takes the worst round.
    /// </summary>
    public double UnionBoundBits { get; }

    /// <summary>
    /// The honest-verifier zero-knowledge distance in bits:
    /// <c>-log2(Σ_rounds (t_ood² + t_ood)/(2·|F|))</c> — per code-switch
    /// round, the union of the pairwise-collision and zero-point events of
    /// the private out-of-domain draw, the hiding path's sole statistical
    /// distance (the mask codes' Reed-Solomon encodings simulate exactly).
    /// <see cref="double.PositiveInfinity"/> for a base-case-only shape,
    /// which draws no private points.
    /// </summary>
    /// <remarks>
    /// A privacy figure, not a soundness row: it bounds a different
    /// adversary, so it is deliberately kept out of <see cref="LedgerRows"/>
    /// and its minimum — mirroring how the cross-scheme ledger reports the
    /// hiding axis as a kind rather than folding it into the soundness bits.
    /// The wired endpoints enforce the inadmissible draw loudly instead of
    /// proceeding, so an honest transcript is within this distance of the
    /// simulation.
    /// </remarks>
    public double PrivacyErrorBits { get; }


    private WhirZkParameters(
        WhirParameterSchedule schedule,
        int maskMessageLength,
        int maskRateLog2,
        int maskQueryCount,
        int maskOracleUnionLog2,
        int[] oracleRandomnessCounts,
        WhirMaskCodeShape sumcheckMaskShape,
        WhirMaskCodeShape[] switchMaskShapes,
        WhirSoundnessLedgerRow[] ledgerRows,
        double minimumRoundBits,
        double unionBoundBits,
        double privacyErrorBits)
    {
        Schedule = schedule;
        MaskMessageLength = maskMessageLength;
        MaskRateLog2 = maskRateLog2;
        MaskQueryCount = maskQueryCount;
        MaskOracleUnionLog2 = maskOracleUnionLog2;
        OracleRandomnessCounts = oracleRandomnessCounts;
        SumcheckMaskShape = sumcheckMaskShape;
        SwitchMaskShapes = switchMaskShapes;
        LedgerRows = ledgerRows;
        MinimumRoundBits = minimumRoundBits;
        UnionBoundBits = unionBoundBits;
        PrivacyErrorBits = privacyErrorBits;
    }


    /// <summary>
    /// Derives the zero-knowledge extension for the given schedule,
    /// validating the mask floors, the per-oracle randomness fit and the mask
    /// domains' two-adicity, and pricing the zero-knowledge soundness ledger
    /// and the honest-verifier zero-knowledge distance. The derivation fails
    /// loudly rather than silently degrade hiding or soundness.
    /// </summary>
    /// <param name="schedule">The plain schedule to extend.</param>
    /// <param name="maskMessageLength">The mask message length <c>ℓ_zk</c>, at least <see cref="MinimumMaskMessageLength"/>; defaults to <see cref="DefaultMaskMessageLength"/>.</param>
    /// <param name="maskRateLog2">The mask codes' inverse-rate exponent, at least 1; defaults to <see cref="DefaultMaskRateLog2"/>.</param>
    /// <returns>The validated extension.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="schedule"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When a mask parameter is under its floor.</exception>
    /// <exception cref="ArgumentException">When an oracle's randomness budget does not fit its codeword slack, a mask domain exceeds the field's two-adicity, or the zero-knowledge ledger's worst row lands under the schedule's target.</exception>
    public static WhirZkParameters Create(
        WhirParameterSchedule schedule,
        int maskMessageLength = DefaultMaskMessageLength,
        int maskRateLog2 = DefaultMaskRateLog2)
    {
        ArgumentNullException.ThrowIfNull(schedule);
        ArgumentOutOfRangeException.ThrowIfLessThan(maskMessageLength, MinimumMaskMessageLength);
        ArgumentOutOfRangeException.ThrowIfLessThan(maskRateLog2, 1);

        int iterationCount = schedule.IterationCount;
        int foldingParameter = schedule.FoldingParameter;

        //Union over the mask oracles: M sumcheck batches, M - 1 code-switch
        //masks and the base case's fresh commitments, bounded by 2M + 2 as in
        //the reference derivation. Each mask spot-check branch is
        //(1 - δ_zk)^t_zk, so the union adds ⌈log2(2M + 2)⌉ bits to the target
        //and t_zk reaches the schedule's full security level across all masks.
        int maskOracleUnionLog2 = BitOperations.Log2(BitOperations.RoundUpToPowerOf2((uint)((2 * iterationCount) + 2)));
        int maskQueryCount = WellKnownWhirParameters.ComputeQueryCount(
            schedule.SecurityLevelBits + maskOracleUnionLog2,
            maskRateLog2,
            schedule.Regime,
            schedule.JohnsonProximityParameter);

        var oracleRandomnessCounts = new int[iterationCount];
        for(int i = 0; i < iterationCount; i++)
        {
            WhirRoundParameters round = schedule.Rounds[i];
            int budget = round.QueryCount;

            //Per-limb fit: the randomized limb occupies 2^(m_i - k) + t_i of
            //the 2^(n_i - k) coefficient rows its joint transform spans. The
            //bound keeps every opened set strictly inside the codeword — the
            //base of the t_i-query simulatability argument.
            long messageRows = 1L << (round.VariableCount - foldingParameter);
            long limbDomainRows = 1L << (round.DomainSizeLog2 - foldingParameter);
            long slack = limbDomainRows - messageRows;
            if(budget > slack)
            {
                throw new ArgumentException(
                    $"Oracle {i} needs {budget} randomness rows per limb but its codeword has only {slack} spare rows; the shape cannot hide its openings.",
                    nameof(schedule));
            }

            oracleRandomnessCounts[i] = budget;
        }

        WhirMaskCodeShape sumcheckMaskShape = WhirMaskCodeShape.Derive(maskMessageLength, maskQueryCount, maskRateLog2);
        var switchMaskShapes = new WhirMaskCodeShape[Math.Max(0, iterationCount - 1)];
        for(int i = 1; i < iterationCount; i++)
        {
            int switchMessageLength = oracleRandomnessCounts[i - 1] + OutOfDomainSamplesPerIteration;
            switchMaskShapes[i - 1] = WhirMaskCodeShape.Derive(switchMessageLength, maskQueryCount, maskRateLog2);
        }

        int twoAdicity = ScalarNtt.TwoAdicity(schedule.Curve);
        ThrowIfMaskDomainExceedsTwoAdicity(sumcheckMaskShape, twoAdicity);
        foreach(WhirMaskCodeShape shape in switchMaskShapes)
        {
            ThrowIfMaskDomainExceedsTwoAdicity(shape, twoAdicity);
        }

        WhirSoundnessLedgerRow[] ledgerRows = ComputeLedger(schedule, maskMessageLength, maskRateLog2, maskQueryCount);
        double minimumRoundBits = double.PositiveInfinity;
        double totalError = 0.0;
        foreach(WhirSoundnessLedgerRow row in ledgerRows)
        {
            minimumRoundBits = Math.Min(minimumRoundBits, row.ErrorBits);
            totalError += Math.Pow(2.0, -row.ErrorBits);
        }

        if(minimumRoundBits < schedule.SecurityLevelBits)
        {
            throw new ArgumentException(
                $"The realised zero-knowledge round-by-round soundness is {minimumRoundBits:F2} bits, under the schedule's {schedule.SecurityLevelBits}-bit target.",
                nameof(schedule));
        }

        //The private out-of-domain draw is the hiding path's sole statistical
        //distance: each round's t_ood points must be nonzero and pairwise
        //distinct, a (t_ood² + t_ood)/(2|F|) union per code-switch round. A
        //base-case-only shape draws none and simulates exactly.
        const int privateSampleCount = OutOfDomainSamplesPerIteration;
        const double perRoundEventCount = ((privateSampleCount * privateSampleCount) + privateSampleCount) / 2.0;
        double privacyErrorBits = iterationCount > 1
            ? schedule.FieldFloorBits - Math.Log2((iterationCount - 1) * perRoundEventCount)
            : double.PositiveInfinity;

        return new WhirZkParameters(
            schedule,
            maskMessageLength,
            maskRateLog2,
            maskQueryCount,
            maskOracleUnionLog2,
            oracleRandomnessCounts,
            sumcheckMaskShape,
            switchMaskShapes,
            ledgerRows,
            minimumRoundBits,
            -Math.Log2(totalError),
            privacyErrorBits);
    }


    /// <summary>
    /// The total randomness element count oracle
    /// <paramref name="oracleIndex"/>'s zero-knowledge encoding appends:
    /// <c>t_i · 2^k</c> — the per-limb budget across every limb, laid out as
    /// one contiguous coefficient block after the message.
    /// </summary>
    /// <param name="oracleIndex">The oracle index in <c>0..M-1</c>.</param>
    /// <returns>The randomness element count.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When the index is out of range.</exception>
    public int OracleRandomnessElementCount(int oracleIndex)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(oracleIndex);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(oracleIndex, OracleRandomnessCounts.Count);

        return OracleRandomnessCounts[oracleIndex] << Schedule.FoldingParameter;
    }


    /// <summary>
    /// Prices the zero-knowledge ledger. Every plain row carries over except
    /// the folding rows, whose identity term is repriced for the masked wire
    /// of Construction 6.3 — the plain degree bound becomes the mask message
    /// length <c>ℓ_zk</c> and the mask code's own decoding list joins the
    /// union: <c>ε ≤ ℓ_zk·ℓ_i·ℓ_Czk/|F| + err*(C^{(i,s)}, 2, δ_i)</c>. One
    /// <see cref="WhirRoundErrorKind.MaskOracleQueries"/> row is appended per
    /// mask group in creation order — the batch-0 sumcheck group, then per
    /// main-loop iteration its code-switch and sumcheck groups.
    /// </summary>
    /// <param name="schedule">The plain schedule.</param>
    /// <param name="maskMessageLength">The mask message length <c>ℓ_zk</c>.</param>
    /// <param name="maskRateLog2">The mask codes' inverse-rate exponent.</param>
    /// <param name="maskQueryCount">The mask spot-check count <c>t_zk</c>.</param>
    /// <returns>The zero-knowledge ledger rows in protocol order.</returns>
    private static WhirSoundnessLedgerRow[] ComputeLedger(
        WhirParameterSchedule schedule,
        int maskMessageLength,
        int maskRateLog2,
        int maskQueryCount)
    {
        int maskGroupCount = (2 * schedule.IterationCount) - 1;
        var ledger = new List<WhirSoundnessLedgerRow>(schedule.LedgerRows.Count + maskGroupCount);

        double maskListSizeBound = WellKnownWhirParameters.ListSizeBound(schedule.Regime, maskRateLog2, schedule.JohnsonProximityParameter);
        foreach(WhirSoundnessLedgerRow row in schedule.LedgerRows)
        {
            if(row.Kind is WhirRoundErrorKind.InitialSumcheckFold or WhirRoundErrorKind.MainSumcheckFold)
            {
                WhirRoundParameters round = schedule.Rounds[row.Iteration];
                double identityTermBits = schedule.FieldFloorBits
                    - Math.Log2(maskMessageLength * round.ListSizeBound * maskListSizeBound);
                double agreementBits = WellKnownWhirParameters.MutualCorrelatedAgreementErrorBits(
                    schedule.Regime,
                    schedule.FieldFloorBits,
                    round.VariableCount - row.SumcheckRound,
                    round.RateLog2,
                    schedule.JohnsonProximityParameter);
                ledger.Add(new WhirSoundnessLedgerRow(row.Kind, row.Iteration, row.SumcheckRound, WhirParameterSchedule.CombineErrorBits(identityTermBits, agreementBits)));
            }
            else
            {
                ledger.Add(row);
            }
        }

        //Each group's carried and fresh oracles are bound by one joint
        //identity per spot position, so a group is a single (1 - δ_zk)^t_zk
        //branch, priced at the mask codes' guaranteed rate floor.
        double maskProximity = WellKnownWhirParameters.ProximityParameter(schedule.Regime, maskRateLog2, schedule.JohnsonProximityParameter);
        double maskRowBits = maskQueryCount * -Math.Log2(1.0 - maskProximity);
        for(int group = 0; group < maskGroupCount; group++)
        {
            ledger.Add(new WhirSoundnessLedgerRow(WhirRoundErrorKind.MaskOracleQueries, group, 0, maskRowBits));
        }

        return [.. ledger];
    }


    /// <summary>
    /// Rejects a mask code domain the scalar field cannot host, before any
    /// encoding runs.
    /// </summary>
    private static void ThrowIfMaskDomainExceedsTwoAdicity(WhirMaskCodeShape shape, int twoAdicity)
    {
        if(shape.DomainSizeLog2 > twoAdicity)
        {
            throw new ArgumentException(
                $"A mask code domain of 2^{shape.DomainSizeLog2} elements exceeds the scalar field's two-adicity of {twoAdicity}.");
        }
    }
}

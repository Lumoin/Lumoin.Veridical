using Lumoin.Veridical.Core.Commitments.BaseFold;
using Lumoin.Veridical.Core.Commitments.Ligero;
using System;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// The per-proof-path security-level calculator: it unifies the scattered
/// documented boundaries — the Ligero opened-column soundness
/// (<see cref="WellKnownLigeroParameters"/>), the BaseFold IOPP query soundness
/// (<see cref="WellKnownBaseFoldIoppParameters"/>) and the field-size terms the
/// per-scheme docs previously carried only as prose — into one computed
/// <see cref="SecurityLevelLedger"/> per Spartan path, so a deployment can read
/// the bottleneck (effective) knowledge-soundness bits its parameters actually
/// realise instead of the target its query count nominally aims at.
/// </summary>
/// <remarks>
/// <para>
/// Every term is computed conservatively within the Johnson-radius pricing
/// convention documented in <c>SECURITY-BITS.md</c> (the per-column proximity
/// figure is the <c>η → 0</c> limit of the proximity-gap theorem's provable
/// range; any concrete <c>η</c> shaves a fraction of a bit and adds a
/// far-larger-exponent field-side error term). Field-size terms use the floor
/// <c>log2(r) ≥ BitLength(r) − 1</c> of the scalar-field order, and the
/// low-order field events are weighted deliberately loosely (see
/// <see cref="LigeroFieldTermBits"/>) — those terms exist to show they never
/// approach the query-term bottleneck for the shapes this library commits, not
/// to be tight. Design note: <c>SECURITY-BITS.md</c> next to this file.
/// </para>
/// <para>
/// The dominant practical hazard the ledger surfaces is the per-polynomial
/// clamp: a Ligero opening cannot reveal more columns than the code's extension
/// width, so a SMALL polynomial (a small circuit) silently realises fewer
/// opened columns — and fewer soundness bits — than the requested query count
/// suggests. <see cref="ThrowIfLigeroSoundnessClamped"/> turns that silent
/// downgrade into a loud failure; raising the inverse code rate (widening the
/// extension, which also raises the per-column bits) is the standard lever that
/// lets a small circuit reach a full target.
/// </para>
/// </remarks>
public static class WellKnownSecurityLevels
{
    /// <summary>The 128-bit-classical knowledge-soundness target the wired parameter sets aim at.</summary>
    public const int ClassicalSecurityLevelBits = 128;

    /// <summary>The Spartan outer sumcheck's per-round polynomial degree (the cubic <c>Az·Bz − u·Cz − E</c> combination).</summary>
    public const int SpartanOuterSumcheckDegree = 3;

    /// <summary>The Spartan inner sumcheck's per-round polynomial degree (the quadratic matrix-evaluation combination).</summary>
    public const int SpartanInnerSumcheckDegree = 2;

    /// <summary>
    /// The slack exponent for the one-and-a-half-Johnson regime's Khatam
    /// theorem parameters: <c>ε = η = 2^-55</c>. Chosen so the commit-phase
    /// failure bound <c>3d/(εη·|F|)</c> keeps roughly nine bits of margin
    /// under the 128-bit target for every opening shape this library commits
    /// (<c>d ≤ 28</c>; the margin moves under a bit even tens of variables
    /// past that, so a hiding lift stays covered) over the ~2^254 scalar
    /// fields, while the radius shift
    /// the slacks cause (about <c>2^-50</c>) is far below the pricing
    /// resolution — the derived query count is identical for any slack
    /// exponent between about 30 and the failure-bound ceiling near 59.
    /// </summary>
    public const int OneAndAHalfJohnsonSlackExponentBits = 55;

    /// <summary>
    /// The per-round weight multiplier of the one-and-a-half-Johnson regime's
    /// commit-phase failure bound <c>3d/(εη·|F|)</c>. Three is the bound the
    /// Khatam theorem's algebra supports (the constant published with the
    /// CRYPTO 2026 revision; the 2025-06-26 revision's smaller constant does
    /// not survive its own Lemma-3 expansion), and the ledger uses the larger,
    /// safe value.
    /// </summary>
    public const int OneAndAHalfJohnsonCommitFailureWeight = 3;

    //The deliberately loose exponent of the low-order field-event weight: the
    //bad-event weight is taken as codewordLength³, which dominates the
    //polynomial factors of the published proximity-gap error bounds (linear for
    //unique decoding, quadratic with small multipliers in the Johnson range)
    //for every code length this library commits, while still leaving the term
    //hundreds of bits above the query-term bottleneck.
    private const int FieldEventWeightExponent = 3;


    /// <summary>
    /// The conservative floor of the scalar field's size in bits:
    /// <c>log2(r) ≥ BitLength(r) − 1</c>. Every field-size soundness term uses
    /// this floor so a claimed level never rounds up past the true one.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the argument works in.</param>
    /// <returns>The floor of <c>log2(r)</c> in whole bits (254 for BLS12-381, 253 for BN254).</returns>
    public static int ScalarFieldSoundnessFloorBits(CurveParameterSet curve)
    {
        return (int)WellKnownCurves.GetScalarFieldOrder(curve).GetBitLength() - 1;
    }


    /// <summary>
    /// The Fiat-Shamir sumcheck soundness of the two Spartan phases: a cheating
    /// prover must land a forged round polynomial on the verifier's random
    /// evaluation point, an event of probability at most <c>degree/r</c> per
    /// round, summed over the cubic outer and quadratic inner rounds:
    /// <c>(3·outer + 2·inner)/r</c>.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the sumcheck runs in.</param>
    /// <param name="outerRoundCount">The outer (row) sumcheck round count; non-negative.</param>
    /// <param name="innerRoundCount">The inner (column) sumcheck round count; non-negative.</param>
    /// <returns>The soundness bits <c>log2(r) − log2(3·outer + 2·inner)</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a round count is negative or both are zero.</exception>
    public static double SpartanSumcheckSoundnessBits(CurveParameterSet curve, int outerRoundCount, int innerRoundCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(outerRoundCount);
        ArgumentOutOfRangeException.ThrowIfNegative(innerRoundCount);
        ArgumentOutOfRangeException.ThrowIfZero(outerRoundCount + innerRoundCount);

        double weight = (SpartanOuterSumcheckDegree * (double)outerRoundCount) + (SpartanInnerSumcheckDegree * (double)innerRoundCount);

        return ScalarFieldSoundnessFloorBits(curve) - Math.Log2(weight);
    }


    /// <summary>
    /// The proximity soundness one Ligero evaluation opening actually realises
    /// for a <paramref name="variableCount"/>-variable polynomial: the opened
    /// column count after the extension-width clamp, times the per-column bits
    /// of the regime at the rate. This is the term the query count nominally
    /// controls — and the one the clamp silently reduces for a small polynomial.
    /// </summary>
    /// <param name="variableCount">The opened polynomial's variable count.</param>
    /// <param name="inverseRate">The inverse code rate <c>c ≥ 2</c>.</param>
    /// <param name="queryCount">The requested opened-column count.</param>
    /// <param name="regime">The soundness regime; defaults to the conservative provable Johnson bound.</param>
    /// <returns>The realised proximity soundness in bits.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static double LigeroProximitySoundnessBits(
        int variableCount,
        int inverseRate,
        int queryCount,
        LigeroSoundnessRegime regime = WellKnownLigeroParameters.ClassicalSecurityRegime)
    {
        LigeroEvaluationDimensions dimensions = LigeroEvaluationDimensions.ForVariableCount(variableCount, inverseRate, queryCount);

        return WellKnownLigeroParameters.EffectiveSecurityBits(regime, inverseRate, dimensions.OpenedColumnCount);
    }


    /// <summary>
    /// The Ligero low-order field-side term: the random row-combination and
    /// decode-gap bad events, bounded by <c>codewordLength³/r</c>. The cubic
    /// weight is a deliberately loose engineering bound chosen to dominate the
    /// polynomial factors of the published proximity-gap error terms (linear
    /// for unique decoding, quadratic with small multipliers in the Johnson
    /// range; Ben-Sasson, Carmon, Ishai, Kopparty, Saraf, FOCS 2020, and the
    /// Ligero interleaved-testing lemmas) for every code length this library
    /// commits — the term shows those events never approach the query-term
    /// bottleneck; it is not tight.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the code lives in.</param>
    /// <param name="variableCount">The opened polynomial's variable count.</param>
    /// <param name="inverseRate">The inverse code rate <c>c ≥ 2</c>.</param>
    /// <param name="queryCount">The requested opened-column count (participates only through the shared dimension derivation).</param>
    /// <returns>The conservative field-side soundness in bits.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static double LigeroFieldTermBits(CurveParameterSet curve, int variableCount, int inverseRate, int queryCount)
    {
        LigeroEvaluationDimensions dimensions = LigeroEvaluationDimensions.ForVariableCount(variableCount, inverseRate, queryCount);
        double weight = Math.Pow(dimensions.CodewordLength, FieldEventWeightExponent);

        return ScalarFieldSoundnessFloorBits(curve) - Math.Log2(Math.Max(weight, 2.0));
    }


    /// <summary>
    /// The proximity soundness a BaseFold IOPP realises with
    /// <paramref name="queryCount"/> independent query repetitions:
    /// <c>queryCount · −log2(1 − δ)</c> for the regime's proximity parameter
    /// <c>δ</c>. Unlike Ligero's opened columns, IOPP repetitions are
    /// independent index draws with no width clamp.
    /// </summary>
    /// <param name="queryCount">The IOPP query repetition count; positive.</param>
    /// <param name="regime">The soundness regime; defaults to the paper-proven doubly-applied Johnson bound.</param>
    /// <param name="relativeMinimumDistance">The code's relative minimum distance; defaults to the wired conservative published value.</param>
    /// <param name="inverseRate">The code's inverse rate; defaults to the wired classical-security shape.</param>
    /// <returns>The realised proximity soundness in bits.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static double BaseFoldProximitySoundnessBits(
        int queryCount,
        BaseFoldSoundnessRegime regime = WellKnownBaseFoldIoppParameters.ClassicalSecurityRegime,
        double relativeMinimumDistance = WellKnownBaseFoldIoppParameters.ClassicalSecurityRelativeMinimumDistance,
        int inverseRate = WellKnownFoldableCodeParameters.ClassicalSecurityInverseRate)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(queryCount);

        double delta = WellKnownBaseFoldIoppParameters.ProximityParameter(regime, relativeMinimumDistance, inverseRate);

        return queryCount * -Math.Log2(1.0 - delta);
    }


    /// <summary>
    /// The commit-phase failure bound of the one-and-a-half-Johnson regime:
    /// the Khatam theorem admits the folding challenges a bad draw with
    /// probability at most <c>3d/(εη·|F|)</c> over the <c>d</c> folding
    /// rounds, at the wired slacks
    /// <c>ε = η = 2^-<see cref="OneAndAHalfJohnsonSlackExponentBits"/></c>.
    /// About 137 bits for a 28-variable opening on BN254 — roughly nine bits
    /// above the 128-bit query-term target, so the slack-controlled events
    /// never become the bottleneck for the shapes this library commits. A
    /// Spartan proof runs two independent openings (the error and witness
    /// polynomials), which costs at most one further bit against that margin.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the code lives in.</param>
    /// <param name="roundCount">The folding round count = the opened polynomial's (lifted) variable count; positive.</param>
    /// <returns>The commit-phase soundness in bits.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="roundCount"/> is non-positive.</exception>
    public static double BaseFoldOneAndAHalfJohnsonCommitTermBits(CurveParameterSet curve, int roundCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(roundCount);

        double weight = OneAndAHalfJohnsonCommitFailureWeight * (double)roundCount;

        return ScalarFieldSoundnessFloorBits(curve) - (2 * OneAndAHalfJohnsonSlackExponentBits) - Math.Log2(weight);
    }


    /// <summary>
    /// The complete ledger of the unmasked Spartan-over-Ligero path (the
    /// transparent, binding-not-hiding configuration the CLI's predicate proofs
    /// use). The proximity term is the WEAKER of the two embedded openings —
    /// the error opening over the row variables and the witness opening over
    /// the column variables — since a forger attacks the cheaper one.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the argument works in.</param>
    /// <param name="outerRoundCount">The outer sumcheck round count = the row variable count = the error opening's variable count.</param>
    /// <param name="innerRoundCount">The inner sumcheck round count = the column variable count = the witness opening's variable count.</param>
    /// <param name="inverseRate">The Ligero inverse code rate <c>c ≥ 2</c>.</param>
    /// <param name="queryCount">The requested opened-column count.</param>
    /// <param name="regime">The soundness regime; defaults to the conservative provable Johnson bound.</param>
    /// <returns>The path's ledger.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static SecurityLevelLedger ComputeSpartanOverLigero(
        CurveParameterSet curve,
        int outerRoundCount,
        int innerRoundCount,
        int inverseRate,
        int queryCount,
        LigeroSoundnessRegime regime = WellKnownLigeroParameters.ClassicalSecurityRegime)
    {
        double proximityBits = Math.Min(
            LigeroProximitySoundnessBits(outerRoundCount, inverseRate, queryCount, regime),
            LigeroProximitySoundnessBits(innerRoundCount, inverseRate, queryCount, regime));
        double sumcheckBits = SpartanSumcheckSoundnessBits(curve, outerRoundCount, innerRoundCount);
        double fieldTermBits = Math.Min(
            LigeroFieldTermBits(curve, outerRoundCount, inverseRate, queryCount),
            LigeroFieldTermBits(curve, innerRoundCount, inverseRate, queryCount));

        return new SecurityLevelLedger(CommitmentScheme.Ligero, curve, proximityBits, sumcheckBits, fieldTermBits, HidingKind.None);
    }


    /// <summary>
    /// The complete ledger of the Spartan-over-BaseFold path (plain, unmasked).
    /// The field term bundles the BaseFold evaluation argument's own internal
    /// quadratic sumcheck (<c>2d/r</c> over the larger opening's <c>d</c>
    /// variables) with the commit-phase bad event (<c>2d/(3r)</c>, BaseFold
    /// paper Theorem 3). Under
    /// <see cref="BaseFoldSoundnessRegime.ListDecodingOneAndAHalfJohnson"/>
    /// the commit-phase event is instead the Khatam slack bound
    /// (<see cref="BaseFoldOneAndAHalfJohnsonCommitTermBits"/>), and the field
    /// term takes the weaker of the two.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the argument works in.</param>
    /// <param name="outerRoundCount">The outer sumcheck round count = the error opening's variable count.</param>
    /// <param name="innerRoundCount">The inner sumcheck round count = the witness opening's variable count.</param>
    /// <param name="queryCount">The IOPP query repetition count.</param>
    /// <param name="regime">The soundness regime; defaults to the paper-proven doubly-applied Johnson bound.</param>
    /// <returns>The path's ledger.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static SecurityLevelLedger ComputeSpartanOverBaseFold(
        CurveParameterSet curve,
        int outerRoundCount,
        int innerRoundCount,
        int queryCount,
        BaseFoldSoundnessRegime regime = WellKnownBaseFoldIoppParameters.ClassicalSecurityRegime)
    {
        double proximityBits = BaseFoldProximitySoundnessBits(queryCount, regime);
        double sumcheckBits = SpartanSumcheckSoundnessBits(curve, outerRoundCount, innerRoundCount);
        double fieldTermBits = BaseFoldRegimeFieldTermBits(curve, Math.Max(outerRoundCount, innerRoundCount), regime);

        return new SecurityLevelLedger(CommitmentScheme.BaseFold, curve, proximityBits, sumcheckBits, fieldTermBits, HidingKind.None);
    }


    /// <summary>
    /// The complete ledger of the masked Spartan-over-ZK-BaseFold path: the
    /// soundness terms of the BaseFold argument at the LIFTED variable count
    /// (the hiding lift adds <paramref name="extraVariableCount"/> mask
    /// variables to every committed polynomial without weakening binding), and
    /// the statistical hiding the enforced budget grants.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the argument works in.</param>
    /// <param name="outerRoundCount">The outer sumcheck round count.</param>
    /// <param name="innerRoundCount">The inner sumcheck round count.</param>
    /// <param name="queryCount">The IOPP query repetition count.</param>
    /// <param name="extraVariableCount">The hiding lift <c>t</c> the provider commits each polynomial by; non-negative.</param>
    /// <param name="regime">The soundness regime; defaults to the paper-proven doubly-applied Johnson bound.</param>
    /// <returns>The path's ledger, with <see cref="HidingKind.Statistical"/>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static SecurityLevelLedger ComputeMaskedSpartanOverZkBaseFold(
        CurveParameterSet curve,
        int outerRoundCount,
        int innerRoundCount,
        int queryCount,
        int extraVariableCount,
        BaseFoldSoundnessRegime regime = WellKnownBaseFoldIoppParameters.ClassicalSecurityRegime)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(extraVariableCount);

        double proximityBits = BaseFoldProximitySoundnessBits(queryCount, regime);
        double sumcheckBits = SpartanSumcheckSoundnessBits(curve, outerRoundCount, innerRoundCount);
        int liftedVariableCount = Math.Max(outerRoundCount, innerRoundCount) + extraVariableCount;
        double fieldTermBits = BaseFoldRegimeFieldTermBits(curve, liftedVariableCount, regime);

        return new SecurityLevelLedger(CommitmentScheme.BaseFold, curve, proximityBits, sumcheckBits, fieldTermBits, HidingKind.Statistical);
    }


    /// <summary>
    /// The Fiat-Shamir soundness of the LogUp sumcheck (Haböck, ePrint
    /// 2022/1530, Protocol 2 at chunk size <c>ℓ = M + 1</c>): a cheating
    /// prover must land a forged degree-<c>(M + 3)</c> round polynomial on the
    /// verifier's random point in one of the <c>n</c> rounds —
    /// <c>n·(M + 3)/r</c>.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the sumcheck runs in.</param>
    /// <param name="variableCount">The hypercube variable count (the round count); positive.</param>
    /// <param name="witnessColumnCount">The witness-column count <c>M</c>; positive.</param>
    /// <returns>The soundness bits <c>log2(r) − log2(n·(M + 3))</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a count is non-positive.</exception>
    public static double LogUpSumcheckSoundnessBits(CurveParameterSet curve, int variableCount, int witnessColumnCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(variableCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(witnessColumnCount);

        double weight = (double)variableCount * (witnessColumnCount + 3);

        return ScalarFieldSoundnessFloorBits(curve) - Math.Log2(weight);
    }


    /// <summary>
    /// The LogUp field-side term: the Schwartz–Zippel loss of the
    /// log-derivative identity at the random denominator challenge —
    /// <c>((M + 1)·2^n − 1)/(r − 2^n)</c>, Haböck ePrint 2022/1530 eq. (22),
    /// the dominant term — plus the Lagrange-kernel and folding-challenge
    /// batching events, charged at the conservative <c>(n + 1)/r</c> (the
    /// paper prints <c>2/r</c> for the single-helper chunking; the standard
    /// multilinear Schwartz–Zippel argument supports <c>n/r</c> per identity
    /// and the ledger takes the larger).
    /// </summary>
    /// <param name="curve">The curve whose scalar field the argument works in.</param>
    /// <param name="variableCount">The hypercube variable count; positive.</param>
    /// <param name="witnessColumnCount">The witness-column count <c>M</c>; positive.</param>
    /// <returns>The field-side soundness in bits, about <c>log2(r) − n − log2(M + 1)</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a count is non-positive.</exception>
    public static double LogUpFieldTermBits(CurveParameterSet curve, int variableCount, int witnessColumnCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(variableCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(witnessColumnCount);

        double hypercubeSize = Math.Pow(2.0, variableCount);
        double weight = ((witnessColumnCount + 1) * hypercubeSize) + variableCount + 1;

        return ScalarFieldSoundnessFloorBits(curve) - Math.Log2(weight);
    }


    /// <summary>
    /// The complete ledger of the standalone LogUp-over-Ligero path. The
    /// argument runs <c>M + 2</c> openings (witness columns, multiplicity,
    /// helper), each drawing its own column queries from the evolving
    /// transcript, and forging any single one suffices — so the proximity
    /// term charges the union bound: one opening's realised soundness minus
    /// <c>log2(M + 2)</c> bits. Not hiding: openings disclose the opened
    /// values.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the argument works in.</param>
    /// <param name="variableCount">The hypercube variable count.</param>
    /// <param name="witnessColumnCount">The witness-column count <c>M</c>.</param>
    /// <param name="inverseRate">The Ligero inverse code rate <c>c ≥ 2</c>.</param>
    /// <param name="queryCount">The requested opened-column count.</param>
    /// <param name="regime">The soundness regime; defaults to the conservative provable Johnson bound.</param>
    /// <returns>The path's ledger.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static SecurityLevelLedger ComputeLogUpOverLigero(
        CurveParameterSet curve,
        int variableCount,
        int witnessColumnCount,
        int inverseRate,
        int queryCount,
        LigeroSoundnessRegime regime = WellKnownLigeroParameters.ClassicalSecurityRegime)
    {
        double proximityBits = LigeroProximitySoundnessBits(variableCount, inverseRate, queryCount, regime)
            - Math.Log2(witnessColumnCount + 2.0);
        double sumcheckBits = LogUpSumcheckSoundnessBits(curve, variableCount, witnessColumnCount);
        double fieldTermBits = Math.Min(
            LogUpFieldTermBits(curve, variableCount, witnessColumnCount),
            LigeroFieldTermBits(curve, variableCount, inverseRate, queryCount));

        return new SecurityLevelLedger(CommitmentScheme.Ligero, curve, proximityBits, sumcheckBits, fieldTermBits, HidingKind.None);
    }


    /// <summary>
    /// The complete ledger of the standalone LogUp-over-BaseFold path
    /// (plain, unmasked). The proximity term charges the union bound over the
    /// <c>M + 2</c> independent IOPP openings, as in
    /// <see cref="ComputeLogUpOverLigero"/>. Not hiding: openings disclose
    /// the opened values.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the argument works in.</param>
    /// <param name="variableCount">The hypercube variable count.</param>
    /// <param name="witnessColumnCount">The witness-column count <c>M</c>.</param>
    /// <param name="queryCount">The IOPP query repetition count.</param>
    /// <param name="regime">The soundness regime; defaults to the paper-proven doubly-applied Johnson bound.</param>
    /// <returns>The path's ledger.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static SecurityLevelLedger ComputeLogUpOverBaseFold(
        CurveParameterSet curve,
        int variableCount,
        int witnessColumnCount,
        int queryCount,
        BaseFoldSoundnessRegime regime = WellKnownBaseFoldIoppParameters.ClassicalSecurityRegime)
    {
        double proximityBits = BaseFoldProximitySoundnessBits(queryCount, regime)
            - Math.Log2(witnessColumnCount + 2.0);
        double sumcheckBits = LogUpSumcheckSoundnessBits(curve, variableCount, witnessColumnCount);
        double fieldTermBits = Math.Min(
            LogUpFieldTermBits(curve, variableCount, witnessColumnCount),
            BaseFoldRegimeFieldTermBits(curve, variableCount, regime));

        return new SecurityLevelLedger(CommitmentScheme.BaseFold, curve, proximityBits, sumcheckBits, fieldTermBits, HidingKind.None);
    }


    /// <summary>
    /// The Fiat-Shamir soundness of the LogUp-GKR layer cascade
    /// (Papini–Haböck, ePrint 2023/1284, Proposition 1): the line merges and
    /// the per-layer degree-3 sumchecks over the <c>ν = n + ⌈log2(M+1)⌉</c>
    /// tree variables compose to at most <c>ν·(3ν + 1)/(2·r)</c>.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the argument works in.</param>
    /// <param name="variableCount">The row hypercube variable count; positive.</param>
    /// <param name="witnessColumnCount">The witness-column count <c>M</c>; positive.</param>
    /// <returns>The soundness bits <c>log2(r) − log2(ν·(3ν+1)/2)</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a count is non-positive.</exception>
    public static double LogUpGkrSoundnessBits(CurveParameterSet curve, int variableCount, int witnessColumnCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(variableCount);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(witnessColumnCount);

        int totalVariableCount = variableCount + (int)Math.Ceiling(Math.Log2(witnessColumnCount + 1.0));
        double weight = totalVariableCount * ((3.0 * totalVariableCount) + 1.0) / 2.0;

        return ScalarFieldSoundnessFloorBits(curve) - Math.Log2(weight);
    }


    /// <summary>
    /// The complete ledger of the standalone LogUp-GKR-over-Ligero path: the
    /// multiplicity column is the only extra commitment, so the proximity
    /// union bound spans <c>M + 1</c> openings; the sumcheck term is the GKR
    /// cascade bound; the field term reuses the log-derivative identity
    /// charge (its small kernel/batching addend over-covers the GKR route's
    /// merge events, which Proposition 1 already prices — the double count is
    /// deliberate, conservative slack). Not hiding.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the argument works in.</param>
    /// <param name="variableCount">The row hypercube variable count.</param>
    /// <param name="witnessColumnCount">The witness-column count <c>M</c>.</param>
    /// <param name="inverseRate">The Ligero inverse code rate <c>c ≥ 2</c>.</param>
    /// <param name="queryCount">The requested opened-column count.</param>
    /// <param name="regime">The soundness regime; defaults to the conservative provable Johnson bound.</param>
    /// <returns>The path's ledger.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static SecurityLevelLedger ComputeLogUpGkrOverLigero(
        CurveParameterSet curve,
        int variableCount,
        int witnessColumnCount,
        int inverseRate,
        int queryCount,
        LigeroSoundnessRegime regime = WellKnownLigeroParameters.ClassicalSecurityRegime)
    {
        double proximityBits = LigeroProximitySoundnessBits(variableCount, inverseRate, queryCount, regime)
            - Math.Log2(witnessColumnCount + 1.0);
        double sumcheckBits = LogUpGkrSoundnessBits(curve, variableCount, witnessColumnCount);
        double fieldTermBits = Math.Min(
            LogUpFieldTermBits(curve, variableCount, witnessColumnCount),
            LigeroFieldTermBits(curve, variableCount, inverseRate, queryCount));

        return new SecurityLevelLedger(CommitmentScheme.Ligero, curve, proximityBits, sumcheckBits, fieldTermBits, HidingKind.None);
    }


    /// <summary>
    /// The complete ledger of the standalone LogUp-GKR-over-BaseFold path,
    /// with the same term composition as
    /// <see cref="ComputeLogUpGkrOverLigero"/>. Not hiding.
    /// </summary>
    /// <param name="curve">The curve whose scalar field the argument works in.</param>
    /// <param name="variableCount">The row hypercube variable count.</param>
    /// <param name="witnessColumnCount">The witness-column count <c>M</c>.</param>
    /// <param name="queryCount">The IOPP query repetition count.</param>
    /// <param name="regime">The soundness regime; defaults to the paper-proven doubly-applied Johnson bound.</param>
    /// <returns>The path's ledger.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static SecurityLevelLedger ComputeLogUpGkrOverBaseFold(
        CurveParameterSet curve,
        int variableCount,
        int witnessColumnCount,
        int queryCount,
        BaseFoldSoundnessRegime regime = WellKnownBaseFoldIoppParameters.ClassicalSecurityRegime)
    {
        double proximityBits = BaseFoldProximitySoundnessBits(queryCount, regime)
            - Math.Log2(witnessColumnCount + 1.0);
        double sumcheckBits = LogUpGkrSoundnessBits(curve, variableCount, witnessColumnCount);
        double fieldTermBits = Math.Min(
            LogUpFieldTermBits(curve, variableCount, witnessColumnCount),
            BaseFoldRegimeFieldTermBits(curve, variableCount, regime));

        return new SecurityLevelLedger(CommitmentScheme.BaseFold, curve, proximityBits, sumcheckBits, fieldTermBits, HidingKind.None);
    }


    /// <summary>
    /// Throws when a Ligero opening for a <paramref name="variableCount"/>-variable
    /// polynomial cannot open the full <paramref name="queryCount"/> columns —
    /// the extension-width clamp would silently realise fewer soundness bits
    /// than the query count targets. The Ligero soundness mirror of the ZK
    /// BaseFold hiding budget guard (see
    /// <see cref="ZkBaseFoldPolynomialCommitmentScheme.MeetsHidingBudget"/>):
    /// a tool that pins a security target calls this at prove and verify time so
    /// an under-target circuit/parameter combination fails loudly instead of
    /// shipping a grindable proof.
    /// </summary>
    /// <param name="variableCount">The opened polynomial's variable count.</param>
    /// <param name="inverseRate">The inverse code rate <c>c ≥ 2</c>.</param>
    /// <param name="queryCount">The requested opened-column count.</param>
    /// <param name="regime">The regime used to report the realised bits in the failure message.</param>
    /// <exception cref="ArgumentException">When the extension width clamps the opened-column count below <paramref name="queryCount"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static void ThrowIfLigeroSoundnessClamped(
        int variableCount,
        int inverseRate,
        int queryCount,
        LigeroSoundnessRegime regime = WellKnownLigeroParameters.ClassicalSecurityRegime)
    {
        LigeroEvaluationDimensions dimensions = LigeroEvaluationDimensions.ForVariableCount(variableCount, inverseRate, queryCount);
        if(dimensions.OpenedColumnCount < queryCount)
        {
            double realisedBits = WellKnownLigeroParameters.EffectiveSecurityBits(regime, inverseRate, dimensions.OpenedColumnCount);

            throw new ArgumentException(
                $"A {variableCount}-variable polynomial at inverse rate {inverseRate} has only {dimensions.ExtensionWidth} extension column(s), " +
                $"so a {queryCount}-column opening clamps to {dimensions.OpenedColumnCount} and realises about {realisedBits:0.#} soundness bit(s) " +
                $"under the {regime} regime instead of the targeted count. Raise the inverse rate (widen the code) or use a larger circuit.");
        }
    }


    //The BaseFold low-order field events over a d-variable opening: the
    //evaluation argument's internal quadratic sumcheck (at most 2d/r) plus the
    //commit-phase bad event (2d/(3r), BaseFold paper Theorem 3), summed as
    //(8/3)·d/r.
    private static double BaseFoldFieldTermBits(CurveParameterSet curve, int variableCount)
    {
        double weight = Math.Max(8.0 * variableCount / 3.0, 2.0);

        return ScalarFieldSoundnessFloorBits(curve) - Math.Log2(weight);
    }


    //The regime-aware field term: the one-and-a-half-Johnson regime replaces
    //the Theorem-3 commit-phase event with the Khatam slack bound 3d/(εη·|F|),
    //which is far larger than the (8/3)·d/r bundle, so the path's field term
    //is the weaker of the two; every other regime keeps the bundle alone.
    private static double BaseFoldRegimeFieldTermBits(CurveParameterSet curve, int variableCount, BaseFoldSoundnessRegime regime)
    {
        double bundleBits = BaseFoldFieldTermBits(curve, variableCount);

        return regime is BaseFoldSoundnessRegime.ListDecodingOneAndAHalfJohnson
            ? Math.Min(bundleBits, BaseFoldOneAndAHalfJohnsonCommitTermBits(curve, variableCount))
            : bundleBits;
    }
}

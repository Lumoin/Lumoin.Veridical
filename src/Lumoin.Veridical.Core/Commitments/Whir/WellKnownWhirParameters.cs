using System;

namespace Lumoin.Veridical.Core.Commitments.Whir;

/// <summary>
/// The WHIR IOPP soundness parameters: the per-regime proximity parameter and
/// list-size bound as functions of a round's rate, the per-round query-count
/// derivation, and the mutual-correlated-agreement error the folding rounds
/// charge. WHIR's rate improves every iteration
/// (<c>ρ_i = 2^(1-k) · ρ_(i-1)</c> for folding parameter <c>k</c>), so unlike
/// the single-rate BaseFold and Ligero derivations every figure here takes the
/// round's rate as an explicit argument.
/// </summary>
/// <remarks>
/// <para>
/// The soundness targets are round-by-round (WHIR Theorem 5.2): each verifier
/// message must flip a doomed transcript with probability at most
/// <c>2^-λ</c>, which is the property the BCS transformation compiles to a
/// non-interactive argument. Query-driven rounds reach the target through the
/// repetition count <c>t_i = ⌈λ / -log2(1 - δ_i)⌉</c>; field-driven terms are
/// fractions of the scalar-field size and sit hundreds of bits above the
/// target for the wired BLS12-381 and BN254 scalar fields, which is why —
/// unlike the paper's Goldilocks instantiation — no extension-field sampling
/// and no proof-of-work is wired.
/// </para>
/// <para>
/// Reference: Arnon, Chiesa, Fenzi, Yogev, "WHIR" (EUROCRYPT 2025, IACR
/// ePrint 2024/1586), Sections 5.1 and 6.2.
/// </para>
/// </remarks>
public static class WellKnownWhirParameters
{
    /// <summary>The 128-bit-classical soundness target: every round-by-round soundness error is at most <c>2^-128</c>.</summary>
    public const int ClassicalSecurityLevelBits = 128;

    /// <summary>
    /// The default soundness regime. Unique decoding rests on the least
    /// machinery — proximity gaps plus the loss-free mutual upgrade of
    /// WHIR Lemma 4.10, with every list size exactly 1 — and is therefore
    /// the conservative default even though it prices the most queries;
    /// <see cref="WhirSoundnessRegime.ListDecodingJohnson"/> is likewise
    /// theorem-backed and trades a longer proof chain for roughly a third
    /// fewer queries.
    /// </summary>
    public const WhirSoundnessRegime ClassicalSecurityRegime = WhirSoundnessRegime.UniqueDecoding;

    /// <summary>
    /// The domain-separation label every WHIR IOPP Fiat-Shamir transcript
    /// carries; binds challenges to this protocol so they cannot collide with
    /// another protocol's transcript even on a matching absorb sequence.
    /// </summary>
    public const string TranscriptDomainLabel = "Lumoin.Veridical.Whir.Iopp.v1";

    /// <summary>
    /// The default folding parameter <c>k</c>: every iteration folds
    /// <c>k</c> variables and halves the evaluation domain, improving the rate
    /// by <c>2^(k-1)</c>. The WHIR paper's experiments fix <c>k = 4</c>
    /// throughout (Section 6.2) and this library adopts that choice.
    /// </summary>
    public const int DefaultFoldingParameter = 4;

    /// <summary>
    /// The degree bound on the sumcheck round polynomials: with weight
    /// polynomials linear in <c>Z</c> and multilinear in the point variables —
    /// the shape every wired statement uses, evaluation claims
    /// <c>ŵ = Z·eq(z, ·)</c> and their random linear combinations included —
    /// Construction 5.1's <c>d* = 1 + deg_Z(ŵ) + max_i deg_Xi(ŵ) = 3</c> and
    /// <c>d = max{d*, 3} = 3</c> coincide, so a single bound serves the
    /// initial and the main-loop sumcheck rounds alike.
    /// </summary>
    public const int SumcheckDegreeBound = 3;

    /// <summary>
    /// The default Johnson proximity parameter <c>m</c> of BCHKS25
    /// Theorem 1.5 (Ben-Sasson, Carmon, Haböck, Kopparty, Saraf, "On
    /// Proximity Gaps for Reed-Solomon Codes", IACR ePrint 2025/2055): the
    /// Johnson-regime slack is <c>η = √ρ/(2m)</c> and the correlated-agreement
    /// error constant is <c>2·(m+0.5)^5/3</c>, so a larger <c>m</c> buys a
    /// larger proximity radius — fewer queries — priced by a larger error
    /// constant and list size. At the default <c>m = 10</c> the slack is the
    /// WHIR paper's canonical <c>η = √ρ/20</c> (WHIR Section 6.2, the WHIR-JB
    /// configuration).
    /// </summary>
    public const int DefaultJohnsonProximityParameter = 10;

    /// <summary>
    /// The divisor in the capacity-regime slack <c>η = ρ / 2</c>
    /// (WHIR Section 6.2, the WHIR-CB configuration). Comparison figures only;
    /// see <see cref="WhirSoundnessRegime.ConjecturedCapacity"/>.
    /// </summary>
    public const int CapacitySlackDivisor = 2;


    /// <summary>
    /// The proximity parameter <c>δ</c> for the given regime at rate
    /// <c>ρ = 2^-rateLog2</c>: the relative Hamming radius within which that
    /// round's queries guarantee rejection of non-close oracles. A larger
    /// <c>δ</c> means fewer queries.
    /// </summary>
    /// <param name="regime">The soundness regime.</param>
    /// <param name="rateLog2">The round's inverse-rate exponent: <c>ρ = 2^-rateLog2</c>, at least 1.</param>
    /// <param name="johnsonProximityParameter">The BCHKS25 Johnson proximity parameter <c>m ≥ 1</c> fixing the slack <c>η = √ρ/(2m)</c>; ignored outside the Johnson regime.</param>
    /// <returns>The proximity parameter <c>δ</c> in <c>(0, 1)</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When the rate exponent or Johnson parameter is out of range or the regime is unrecognised.</exception>
    public static double ProximityParameter(
        WhirSoundnessRegime regime,
        int rateLog2,
        int johnsonProximityParameter = DefaultJohnsonProximityParameter)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(rateLog2, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(johnsonProximityParameter, 1);

        double rate = Math.Pow(2.0, -rateLog2);

        return regime switch
        {
            //Unique decoding: half the Reed-Solomon relative minimum distance 1 - ρ.
            WhirSoundnessRegime.UniqueDecoding => (1.0 - rate) / 2.0,

            //Johnson: δ = 1 - √ρ - η with η = √ρ/(2m), i.e. 1 - (1 + 1/(2m))·√ρ.
            WhirSoundnessRegime.ListDecodingJohnson => 1.0 - ((1.0 + (0.5 / johnsonProximityParameter)) * Math.Sqrt(rate)),

            //Capacity: δ = 1 - ρ - η with η = ρ/2, i.e. 1 - (3/2)·ρ. Comparison only.
            WhirSoundnessRegime.ConjecturedCapacity => 1.0 - ((1.0 + (1.0 / CapacitySlackDivisor)) * rate),

            _ => throw new ArgumentOutOfRangeException(nameof(regime), regime, "Unrecognised WHIR soundness regime.")
        };
    }


    /// <summary>
    /// The number of query repetitions <c>t = ⌈λ / -log2(1 - δ)⌉</c> a round
    /// at rate <c>ρ = 2^-rateLog2</c> needs to drive its query-driven
    /// round-by-round error to at most <c>2^-securityLevelBits</c> under the
    /// given regime.
    /// </summary>
    /// <param name="securityLevelBits">The per-round soundness target <c>λ</c> in bits, positive.</param>
    /// <param name="rateLog2">The round's inverse-rate exponent.</param>
    /// <param name="regime">The soundness regime fixing <c>δ</c>.</param>
    /// <param name="johnsonProximityParameter">The BCHKS25 Johnson proximity parameter <c>m ≥ 1</c>; ignored outside the Johnson regime.</param>
    /// <returns>The query repetition count <c>t ≥ 1</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static int ComputeQueryCount(
        int securityLevelBits,
        int rateLog2,
        WhirSoundnessRegime regime,
        int johnsonProximityParameter = DefaultJohnsonProximityParameter)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(securityLevelBits);

        double delta = ProximityParameter(regime, rateLog2, johnsonProximityParameter);

        //Per-query accept probability is at most (1 - δ); t independent queries
        //give (1 - δ)^t ≤ 2^-λ ⟺ t ≥ λ / -log2(1 - δ).
        double bitsPerQuery = -Math.Log2(1.0 - delta);
        int queryCount = (int)Math.Ceiling(securityLevelBits / bitsPerQuery);

        return Math.Max(1, queryCount);
    }


    /// <summary>
    /// The list-size bound <c>ℓ</c> at the regime's proximity radius for a
    /// smooth Reed-Solomon code of rate <c>ρ = 2^-rateLog2</c>: the number of
    /// codewords the union-bound ledger rows multiply by. Inside the
    /// unique-decoding radius the list is a single codeword; at the Johnson
    /// radius with slack <c>η = √ρ/(2m)</c> the Johnson bound
    /// (WHIR Theorem 4.3) gives <c>ℓ ≤ 1/(2η√ρ) = m/ρ</c>.
    /// </summary>
    /// <param name="regime">The soundness regime.</param>
    /// <param name="rateLog2">The round's inverse-rate exponent.</param>
    /// <param name="johnsonProximityParameter">The BCHKS25 Johnson proximity parameter <c>m ≥ 1</c>; ignored outside the Johnson regime.</param>
    /// <returns>The list-size bound <c>ℓ ≥ 1</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When the rate exponent or Johnson parameter is out of range, the regime is unrecognised, or the regime pins no list-size bound.</exception>
    public static double ListSizeBound(
        WhirSoundnessRegime regime,
        int rateLog2,
        int johnsonProximityParameter = DefaultJohnsonProximityParameter)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(rateLog2, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(johnsonProximityParameter, 1);

        return regime switch
        {
            WhirSoundnessRegime.UniqueDecoding => 1.0,

            //Johnson bound at η = √ρ/(2m): 1/(2·(√ρ/(2m))·√ρ) = m/ρ = m·2^rateLog2.
            WhirSoundnessRegime.ListDecodingJohnson => johnsonProximityParameter * Math.Pow(2.0, rateLog2),

            //Conjecture 4.12 Item 2 leaves the capacity-radius list size unpinned.
            WhirSoundnessRegime.ConjecturedCapacity => throw new ArgumentOutOfRangeException(
                nameof(regime),
                regime,
                "The capacity regime pins no list-size bound; it is retained for query-count comparison only."),

            _ => throw new ArgumentOutOfRangeException(nameof(regime), regime, "Unrecognised WHIR soundness regime.")
        };
    }


    /// <summary>
    /// The mutual-correlated-agreement error <c>err*(C, 2, δ)</c> a folding
    /// round charges, in bits, for a smooth Reed-Solomon code with
    /// <paramref name="foldedVariableCount"/> variables and rate
    /// <c>ρ = 2^-rateLog2</c> over a scalar field of at least
    /// <c>2^fieldFloorBits</c> elements. Under unique decoding this is the
    /// proven bound of WHIR Corollary 4.11,
    /// <c>err* = 2^m / (ρ·|F|)</c> at generator length 2; under the Johnson
    /// regime it is the proven bound of BCHKS25 Theorem 1.5 at slack
    /// <c>η = √ρ/(2m_J)</c> for Johnson proximity parameter <c>m_J</c>,
    /// <c>err* = (2·(m_J + 1/2)^5/3) · 2^m · ρ^(-5/2) / |F|</c> — the message
    /// length <c>2^m</c> and <c>ρ^(-5/2)</c> form of the paper's
    /// codeword-length bound <c>O(n/η^5)</c> under <c>n = 2^m/ρ</c>. The
    /// mutual form the folding rounds need follows from the Guruswami-Sudan
    /// generalization of Haböck's note (IACR ePrint 2025/2110).
    /// </summary>
    /// <param name="regime">The soundness regime.</param>
    /// <param name="fieldFloorBits">The floor of <c>log2(|F|)</c> in whole bits.</param>
    /// <param name="foldedVariableCount">The variable count <c>m</c> of the folded code the round lands in.</param>
    /// <param name="rateLog2">The round's inverse-rate exponent.</param>
    /// <param name="johnsonProximityParameter">The BCHKS25 Johnson proximity parameter <c>m_J ≥ 1</c>; ignored outside the Johnson regime.</param>
    /// <returns>The error in bits, <c>-log2(err*)</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range or the regime prices no proven or conjectured error expression.</exception>
    public static double MutualCorrelatedAgreementErrorBits(
        WhirSoundnessRegime regime,
        int fieldFloorBits,
        int foldedVariableCount,
        int rateLog2,
        int johnsonProximityParameter = DefaultJohnsonProximityParameter)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(fieldFloorBits);
        ArgumentOutOfRangeException.ThrowIfNegative(foldedVariableCount);
        ArgumentOutOfRangeException.ThrowIfLessThan(rateLog2, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(johnsonProximityParameter, 1);

        return regime switch
        {
            //Corollary 4.11 at ℓ = 2: err* = 2^m/(ρ·|F|) = 2^(m + rateLog2 - fieldFloorBits).
            WhirSoundnessRegime.UniqueDecoding => fieldFloorBits - foldedVariableCount - rateLog2,

            //BCHKS25 Theorem 1.5 at η = √ρ/(2m_J): the error constant is
            //computed FROM the chosen m_J, so any m_J self-prices — no slack
            //floor needs asserting, unlike a fixed-constant wiring.
            WhirSoundnessRegime.ListDecodingJohnson =>
                fieldFloorBits
                    - Math.Log2(2.0 * Math.Pow(johnsonProximityParameter + 0.5, 5.0) / 3.0)
                    - foldedVariableCount
                    - (2.5 * rateLog2),

            WhirSoundnessRegime.ConjecturedCapacity => throw new ArgumentOutOfRangeException(
                nameof(regime),
                regime,
                "The capacity regime's mutual-correlated-agreement error rests on Conjecture 4.12 Item 2, which is not priced; it is retained for query-count comparison only."),

            _ => throw new ArgumentOutOfRangeException(nameof(regime), regime, "Unrecognised WHIR soundness regime.")
        };
    }
}

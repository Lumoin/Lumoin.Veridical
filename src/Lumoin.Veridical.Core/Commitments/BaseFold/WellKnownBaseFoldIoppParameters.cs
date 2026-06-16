using System;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// The BaseFold IOPP soundness parameters: the relative-minimum-distance
/// figure of the wired random foldable code, the query-count derivation, and
/// the recommended query counts for the 128-bit-classical target under each
/// <see cref="BaseFoldSoundnessRegime"/>.
/// </summary>
/// <remarks>
/// <para>
/// The BaseFold IOPP repeats its single-index query <c>ℓ</c> times. Each
/// independent query accepts a <c>δ</c>-far oracle with probability at most
/// <c>1 - δ</c>, and the commit-phase bad event contributes an additive
/// <c>2d / (3|F|)</c> term that is negligible for our roughly <c>2^254</c>
/// scalar field (about <c>2^-249</c> for the polynomial sizes Veridical
/// commits). So the soundness error is dominated by <c>(1 - δ)^ℓ</c>, and to
/// reach <c>2^-λ</c> the query count is
/// <c>ℓ = ⌈λ / -log2(1 - δ)⌉</c>. See Theorem 3 and Appendix B.3 of the
/// BaseFold paper (Zeilberger, Chen, Fisch, CRYPTO 2024, IACR ePrint
/// 2023/1705).
/// </para>
/// <para>
/// The proximity parameter <c>δ</c> depends on the chosen
/// <see cref="BaseFoldSoundnessRegime"/> and on the code's relative minimum
/// distance <c>δ_min</c>. The paper's Table 1 reports <c>δ_min ≈ 0.728</c> for
/// the wired shape (inverse rate <c>c = 8</c>, base dimension <c>k0 = 1</c>,
/// message length <c>2^25</c>) over a <c>2^256</c> field; our BN254 and
/// BLS12-381 scalar fields (<c>≈ 2^254</c>) match this row to within a
/// <c>1/|F|</c> correction, and the figure drifts only mildly with the
/// message length (the paper cites <c>0.76</c> at <c>2^256</c>, <c>d = 15</c>).
/// We pin the conservative published value as
/// <see cref="ClassicalSecurityRelativeMinimumDistance"/>; the derivation takes
/// <c>δ_min</c> as an explicit argument so a different code shape can be
/// re-derived from its own Table-1 / Appendix-C figure.
/// </para>
/// <para>
/// All three regimes are exposed so a deployment can pick its point on the
/// proof-size / assumption-strength curve. The wired default is
/// <see cref="BaseFoldSoundnessRegime.ListDecodingJohnson"/> — the bound the
/// paper literally proves and the most conservative of the two provable
/// options in our distance range.
/// </para>
/// </remarks>
public static class WellKnownBaseFoldIoppParameters
{
    /// <summary>The 128-bit-classical soundness target: the IOPP soundness error is at most <c>2^-128</c>.</summary>
    public const int ClassicalSecurityLevelBits = 128;

    /// <summary>
    /// The conservative relative minimum distance <c>δ_min</c> of the wired
    /// random foldable code, from the BaseFold paper's Table 1 (the
    /// <c>c = 8</c>, <c>k0 = 1</c>, <c>2^256</c>-field row). Used as the
    /// default basis for the unique-decoding and list-decoding query counts.
    /// </summary>
    public const double ClassicalSecurityRelativeMinimumDistance = 0.728;

    /// <summary>
    /// The default soundness regime for the 128-bit-classical target. The
    /// doubly-applied Johnson radius is the proximity parameter Theorem 3 of
    /// the BaseFold paper proves for the IOPP, and is the conservative choice.
    /// </summary>
    public const BaseFoldSoundnessRegime ClassicalSecurityRegime = BaseFoldSoundnessRegime.ListDecodingJohnson;

    /// <summary>
    /// The domain-separation label every BaseFold IOPP Fiat-Shamir transcript
    /// carries; binds challenges to this protocol so they cannot collide with
    /// another protocol's transcript even on a matching absorb sequence.
    /// </summary>
    public const string TranscriptDomainLabel = "Lumoin.Veridical.BaseFold.Iopp.v1";


    /// <summary>
    /// The Johnson list-decoding radius for a code of relative minimum distance
    /// <paramref name="relativeMinimumDistance"/>: <c>J(x) = 1 - √(1 - x)</c>
    /// (BaseFold paper, Definition 4).
    /// </summary>
    /// <param name="relativeMinimumDistance">The relative minimum distance in <c>[0, 1]</c>.</param>
    /// <returns>The Johnson radius <c>1 - √(1 - x)</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When the input is outside <c>[0, 1]</c>.</exception>
    public static double JohnsonRadius(double relativeMinimumDistance)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(relativeMinimumDistance, 0.0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(relativeMinimumDistance, 1.0);

        return 1.0 - Math.Sqrt(1.0 - relativeMinimumDistance);
    }


    /// <summary>
    /// The proximity parameter <c>δ</c> for the given regime: the relative
    /// Hamming radius within which the IOPP guarantees rejection of non-close
    /// oracles. A larger <c>δ</c> means fewer queries are needed.
    /// </summary>
    /// <param name="regime">The soundness regime.</param>
    /// <param name="relativeMinimumDistance">The code's relative minimum distance <c>δ_min</c>.</param>
    /// <param name="inverseRate">The code's inverse rate <c>c</c> (rate <c>ρ = 1/c</c>); used only by the capacity regime.</param>
    /// <returns>The proximity parameter <c>δ</c> in <c>(0, 1)</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When a numeric argument is out of range, or the regime is unrecognised.</exception>
    public static double ProximityParameter(BaseFoldSoundnessRegime regime, double relativeMinimumDistance, int inverseRate)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(relativeMinimumDistance, 0.0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(relativeMinimumDistance, 1.0);
        ArgumentOutOfRangeException.ThrowIfLessThan(inverseRate, 2);

        return regime switch
        {
            //Capacity: δ → 1 - ρ = 1 - 1/c.
            BaseFoldSoundnessRegime.ConjecturedCapacity => 1.0 - (1.0 / inverseRate),

            //Unique decoding: half the relative minimum distance.
            BaseFoldSoundnessRegime.UniqueDecoding => relativeMinimumDistance / 2.0,

            //List decoding at the doubly-applied Johnson radius (Theorem 3).
            BaseFoldSoundnessRegime.ListDecodingJohnson => JohnsonRadius(JohnsonRadius(relativeMinimumDistance)),

            _ => throw new ArgumentOutOfRangeException(nameof(regime), regime, "Unrecognised BaseFold soundness regime.")
        };
    }


    /// <summary>
    /// The number of IOPP query repetitions <c>ℓ = ⌈λ / -log2(1 - δ)⌉</c> needed
    /// to drive the soundness error to at most <c>2^-securityLevelBits</c> under
    /// the given regime.
    /// </summary>
    /// <param name="securityLevelBits">The target soundness level <c>λ</c> in bits (positive).</param>
    /// <param name="relativeMinimumDistance">The code's relative minimum distance <c>δ_min</c>.</param>
    /// <param name="inverseRate">The code's inverse rate <c>c</c>.</param>
    /// <param name="regime">The soundness regime fixing <c>δ</c>.</param>
    /// <returns>The query repetition count <c>ℓ ≥ 1</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static int ComputeQueryCount(
        int securityLevelBits,
        double relativeMinimumDistance,
        int inverseRate,
        BaseFoldSoundnessRegime regime)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(securityLevelBits);

        double delta = ProximityParameter(regime, relativeMinimumDistance, inverseRate);

        //Per-query accept probability is at most (1 - δ); ℓ independent queries
        //give (1 - δ)^ℓ ≤ 2^-λ ⟺ ℓ ≥ λ / -log2(1 - δ).
        double bitsPerQuery = -Math.Log2(1.0 - delta);
        int queryCount = (int)Math.Ceiling(securityLevelBits / bitsPerQuery);

        return Math.Max(1, queryCount);
    }


    /// <summary>
    /// The 128-bit-classical IOPP query count for <paramref name="regime"/>,
    /// using the wired code's relative minimum distance and inverse rate. For
    /// the default <see cref="BaseFoldSoundnessRegime.ListDecodingJohnson"/>
    /// this is the value the prover and verifier use unless told otherwise.
    /// </summary>
    /// <param name="regime">The soundness regime.</param>
    /// <returns>The query repetition count.</returns>
    public static int ClassicalSecurityQueryCount(BaseFoldSoundnessRegime regime)
    {
        return ComputeQueryCount(
            ClassicalSecurityLevelBits,
            ClassicalSecurityRelativeMinimumDistance,
            WellKnownFoldableCodeParameters.ClassicalSecurityInverseRate,
            regime);
    }


    /// <summary>
    /// The 128-bit-classical IOPP query count under the default regime
    /// (<see cref="ClassicalSecurityRegime"/>): the conservative, paper-proven
    /// list-decoding count. Roughly 273 for the wired parameters.
    /// </summary>
    public static int ClassicalSecurityDefaultQueryCount => ClassicalSecurityQueryCount(ClassicalSecurityRegime);
}

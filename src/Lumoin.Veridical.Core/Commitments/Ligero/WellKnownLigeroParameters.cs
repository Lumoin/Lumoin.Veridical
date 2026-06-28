using System;

namespace Lumoin.Veridical.Core.Commitments.Ligero;

/// <summary>
/// The soundness parameters of the interleaved-Reed-Solomon Ligero polynomial commitment: the inverse code
/// rate, the proximity parameter <c>δ</c> under each <see cref="LigeroSoundnessRegime"/>, and the opened-column
/// (query) count derivation for a target security level — the Ligero analogue of
/// <see cref="BaseFold.WellKnownBaseFoldIoppParameters"/>.
/// </summary>
/// <remarks>
/// <para>
/// Ligero commits a polynomial's evaluation matrix as interleaved RS codewords and opens <c>t</c> random
/// extension columns. A committed matrix that is <c>δ</c>-far from the interleaved code is caught by each
/// independent opened column with probability at least <c>δ</c>, so the proximity-test soundness error is
/// dominated by <c>(1 − δ)^t</c>, and to reach <c>2^−λ</c> the opened-column count is
/// <c>t = ⌈λ / −log2(1 − δ)⌉</c>. The lower-order terms — the random affine combination's <c>1/|F|</c>
/// soundness and the RS-decoding gap — are negligible for our roughly <c>2^254</c> scalar field (about
/// <c>2^-249</c> for the polynomial sizes Veridical commits). Reference: "Ligero" (Ames, Hazay, Ishai,
/// Venkitasubramaniam, IACR ePrint 2022/1608) and the Brakedown tensor-query evaluation argument.
/// </para>
/// <para>
/// The proximity parameter <c>δ</c> a <c>t</c>-column test can claim depends on the regime (rate
/// <c>ρ = 1/c</c>): the elementary unique-decoding radius <c>(1 − ρ)/2</c>, the Johnson list-decoding radius
/// <c>1 − √ρ</c> proven for RS codes by the proximity-gap theorem (Ben-Sasson, Carmon, Ishai, Kopparty, Saraf,
/// FOCS 2020), or the conjectured capacity radius <c>1 − ρ</c> (the code's full relative minimum distance).
/// Like <see cref="BaseFold.WellKnownBaseFoldIoppParameters"/>, the default
/// (<see cref="ClassicalSecurityRegime"/>) is the conservative provable bound
/// <see cref="LigeroSoundnessRegime.ListDecodingJohnson"/>: at rate 1/4 it gives <c>−log2(√ρ) = 1</c> bit per
/// opened column and 128 columns for the 128-bit-classical target. Conjectured capacity gives 2 bits/column
/// and 64 columns; a deployment that accepts the capacity conjecture can select it, and unique decoding (~189
/// columns at rate 1/4) is the most conservative.
/// </para>
/// <para>
/// The opened-column count is clamped per polynomial to the available extension width
/// (<c>min(t, ExtensionWidth)</c>); for a small polynomial whose extension width is below the target count the
/// realised soundness is below target. Check the clamped count against <see cref="EffectiveSecurityBits"/>.
/// </para>
/// </remarks>
public static class WellKnownLigeroParameters
{
    /// <summary>The 128-bit-classical soundness target: the proximity-test soundness error is at most <c>2^-128</c>.</summary>
    public const int ClassicalSecurityLevelBits = 128;

    /// <summary>
    /// The wired inverse code rate <c>c</c> (rate <c>ρ = 1/c</c>). Rate 1/4 fixes the opening size as a pure
    /// function of <c>(variableCount, queryCount, digest)</c>, letting the Spartan proof carrier size openings
    /// from provider metadata alone.
    /// </summary>
    public const int DefaultInverseRate = 4;

    /// <summary>
    /// The default soundness regime: the Johnson list-decoding radius — the conservative bound the RS
    /// proximity-gap theorem proves, the same conservative-provable choice
    /// <see cref="BaseFold.WellKnownBaseFoldIoppParameters"/> defaults to.
    /// </summary>
    public const LigeroSoundnessRegime ClassicalSecurityRegime = LigeroSoundnessRegime.ListDecodingJohnson;


    /// <summary>
    /// The relative minimum distance <c>δ = 1 − ρ = 1 − 1/c</c> of the systematic Reed-Solomon code at inverse
    /// rate <paramref name="inverseRate"/> (rate <c>ρ = 1/c</c>): the unique-decoding regime rejects within
    /// half of it, the capacity regime within all of it.
    /// </summary>
    /// <param name="inverseRate">The inverse code rate <c>c ≥ 2</c>.</param>
    /// <returns>The relative minimum distance in <c>(0, 1)</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When <paramref name="inverseRate"/> is below 2.</exception>
    public static double ReedSolomonRelativeDistance(int inverseRate)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(inverseRate, 2);

        return 1.0 - (1.0 / inverseRate);
    }


    /// <summary>
    /// The Johnson list-decoding radius <c>J(x) = 1 − √(1 − x)</c> of a code of relative minimum distance
    /// <paramref name="relativeMinimumDistance"/> — the proximity radius the Reed-Solomon proximity-gap theorem
    /// proves a random-column test rejects within (the same Johnson derivation the BaseFold IOPP parameters
    /// use). At <c>x = 1 − ρ</c> it equals <c>1 − √ρ</c>.
    /// </summary>
    /// <param name="relativeMinimumDistance">The code's relative minimum distance in <c>[0, 1]</c>.</param>
    /// <returns>The Johnson radius <c>1 − √(1 − x)</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When the input is outside <c>[0, 1]</c>.</exception>
    public static double JohnsonRadius(double relativeMinimumDistance)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(relativeMinimumDistance, 0.0);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(relativeMinimumDistance, 1.0);

        return 1.0 - Math.Sqrt(1.0 - relativeMinimumDistance);
    }


    /// <summary>
    /// The proximity parameter <c>δ</c> for <paramref name="regime"/> at inverse rate
    /// <paramref name="inverseRate"/> (rate <c>ρ = 1/c</c>): the relative Hamming radius the per-column
    /// proximity test rejects within.
    /// </summary>
    /// <param name="regime">The soundness regime.</param>
    /// <param name="inverseRate">The inverse code rate <c>c ≥ 2</c>.</param>
    /// <returns>The proximity parameter <c>δ</c> in <c>(0, 1)</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When the inverse rate is below 2, or the regime is unrecognised.</exception>
    public static double ProximityParameter(LigeroSoundnessRegime regime, int inverseRate)
    {
        double minimumDistance = ReedSolomonRelativeDistance(inverseRate);

        return regime switch
        {
            //Unique decoding: half the relative minimum distance, (1 - ρ)/2.
            LigeroSoundnessRegime.UniqueDecoding => minimumDistance / 2.0,

            //Johnson list-decoding radius, 1 - √ρ (proximity-gap provable).
            LigeroSoundnessRegime.ListDecodingJohnson => JohnsonRadius(minimumDistance),

            //Conjectured capacity: the full relative minimum distance, 1 - ρ.
            LigeroSoundnessRegime.ConjecturedCapacity => minimumDistance,

            _ => throw new ArgumentOutOfRangeException(nameof(regime), regime, "Unrecognised Ligero soundness regime.")
        };
    }


    /// <summary>
    /// The soundness contribution of one opened column, <c>−log2(1 − δ)</c> bits, under
    /// <paramref name="regime"/> at inverse rate <paramref name="inverseRate"/>.
    /// </summary>
    /// <param name="regime">The soundness regime.</param>
    /// <param name="inverseRate">The inverse code rate <c>c ≥ 2</c>.</param>
    /// <returns>The per-opened-column soundness in bits.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When the inverse rate is below 2, or the regime is unrecognised.</exception>
    public static double BitsPerOpenedColumn(LigeroSoundnessRegime regime, int inverseRate)
    {
        double delta = ProximityParameter(regime, inverseRate);

        return -Math.Log2(1.0 - delta);
    }


    /// <summary>
    /// The opened-column count <c>t = ⌈λ / −log2(1 − δ)⌉</c> needed to drive the proximity-test soundness error
    /// to at most <c>2^−securityLevelBits</c> under <paramref name="regime"/> at inverse rate
    /// <paramref name="inverseRate"/>.
    /// </summary>
    /// <param name="securityLevelBits">The target soundness level <c>λ</c> in bits (positive).</param>
    /// <param name="inverseRate">The inverse code rate <c>c ≥ 2</c>.</param>
    /// <param name="regime">The soundness regime fixing <c>δ</c>.</param>
    /// <returns>The opened-column count <c>t ≥ 1</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static int ComputeQueryCount(int securityLevelBits, int inverseRate, LigeroSoundnessRegime regime)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(securityLevelBits);

        double bitsPerColumn = BitsPerOpenedColumn(regime, inverseRate);
        int queryCount = (int)Math.Ceiling(securityLevelBits / bitsPerColumn);

        return Math.Max(1, queryCount);
    }


    /// <summary>
    /// The soundness in bits actually realised by opening <paramref name="openedColumnCount"/> columns under
    /// <paramref name="regime"/> at inverse rate <paramref name="inverseRate"/>:
    /// <c>openedColumnCount · −log2(1 − δ)</c>. Check the per-polynomial clamped count against this to confirm a
    /// small polynomial still meets the target.
    /// </summary>
    /// <param name="regime">The soundness regime.</param>
    /// <param name="inverseRate">The inverse code rate <c>c ≥ 2</c>.</param>
    /// <param name="openedColumnCount">The opened-column count actually used (after the per-polynomial clamp).</param>
    /// <returns>The realised soundness in bits.</returns>
    /// <exception cref="ArgumentOutOfRangeException">When an argument is out of range.</exception>
    public static double EffectiveSecurityBits(LigeroSoundnessRegime regime, int inverseRate, int openedColumnCount)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(openedColumnCount);

        return openedColumnCount * BitsPerOpenedColumn(regime, inverseRate);
    }


    /// <summary>
    /// The 128-bit-classical opened-column count under <paramref name="regime"/> at the wired
    /// <see cref="DefaultInverseRate"/>.
    /// </summary>
    /// <param name="regime">The soundness regime.</param>
    /// <returns>The opened-column count.</returns>
    public static int ClassicalSecurityQueryCount(LigeroSoundnessRegime regime)
    {
        return ComputeQueryCount(ClassicalSecurityLevelBits, DefaultInverseRate, regime);
    }


    /// <summary>
    /// The 128-bit-classical opened-column count under the default regime
    /// (<see cref="ClassicalSecurityRegime"/>, the conservative provable Johnson bound): the value a Ligero
    /// provider should use unless told otherwise. 128 for the wired rate 1/4.
    /// </summary>
    public static int ClassicalSecurityDefaultQueryCount => ClassicalSecurityQueryCount(ClassicalSecurityRegime);
}

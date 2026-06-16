namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// Recommended random-foldable-code parameter sets from the BaseFold paper
/// (Zeilberger, Chen, Fisch, CRYPTO 2024, IACR ePrint 2023/1705), for the
/// security levels Veridical targets.
/// </summary>
/// <remarks>
/// <para>
/// The paper's Table 1 reports the relative minimum distance of random
/// foldable codes for representative shapes. For cryptographically-sized
/// fields (around <c>2^128</c> to <c>2^256</c>) it uses inverse rate
/// <c>c = 8</c> and base dimension <c>k0 = 1</c>, giving relative minimum
/// distance roughly <c>0.55</c> to <c>0.73</c>. The BN254 and BLS12-381
/// scalar fields are both close to <c>2^254</c>, so this class fixes
/// <c>c = 8</c>, <c>k0 = 1</c> for the 128-bit-classical target.
/// </para>
/// <para>
/// The IOPP query count that turns this distance into a concrete soundness
/// error is a property of the BaseFold IOPP, not of the code, and is pinned
/// where the IOPP is implemented.
/// </para>
/// </remarks>
public static class WellKnownFoldableCodeParameters
{
    /// <summary>The inverse rate for the 128-bit-classical target: <c>c = 8</c> (rate <c>1/8</c>).</summary>
    public const int ClassicalSecurityInverseRate = 8;

    /// <summary>The base-code dimension for the 128-bit-classical target: <c>k0 = 1</c> (the <c>[8, 1, 8]</c> repetition MDS base code).</summary>
    public const int ClassicalSecurityBaseDimension = 1;

    /// <summary>
    /// The domain-separation tag binding the hash-to-scalar derivation of a
    /// foldable code's random diagonal entries, so the diagonals of a code
    /// derived for one purpose cannot collide with those of another.
    /// </summary>
    public const string DiagonalDerivationDomainSeparationTag = "Lumoin.Veridical.BaseFold.RandomFoldableCode.Diagonal.v1";


    /// <summary>
    /// Builds the 128-bit-classical foldable-code parameters for a multilinear
    /// polynomial in <paramref name="variableCount"/> variables over
    /// <paramref name="curve"/>: inverse rate 8, base dimension 1, and one
    /// foldable layer per variable (so the message is the polynomial's
    /// <c>2^variableCount</c> evaluations).
    /// </summary>
    /// <param name="variableCount">The multilinear polynomial's variable count; the number of foldable layers.</param>
    /// <param name="curve">The curve whose scalar field the code is over.</param>
    /// <returns>The validated parameter set.</returns>
    public static FoldableCodeParameters CreateClassicalSecurity(int variableCount, CurveParameterSet curve)
    {
        return FoldableCodeParameters.Create(
            ClassicalSecurityInverseRate,
            ClassicalSecurityBaseDimension,
            variableCount,
            curve);
    }
}

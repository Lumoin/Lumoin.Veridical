using Lumoin.Veridical.Core.Algebraic;
using System;

namespace Lumoin.Veridical.Core.Commitments;

/// <summary>
/// Prime-order-subgroup screening for prover-supplied G1 points on the
/// Pedersen-family verify paths (Bulletproofs, Hyrax). On a curve with a
/// non-trivial cofactor a length-valid compressed encoding can decode onto
/// the curve yet lie outside the prime-order subgroup, carrying a
/// small-order component the soundness argument never accounts for. The
/// verify funnels call these predicates on every untrusted point before any
/// multi-scalar multiplication runs and treat a failure as a rejection.
/// </summary>
internal static class ProverSuppliedPointValidation
{
    /// <summary>
    /// Decides whether every compressed G1 point in
    /// <paramref name="concatenatedPoints"/> decodes onto the curve and lies
    /// in the prime-order subgroup. The identity is a subgroup member and
    /// passes.
    /// </summary>
    /// <param name="concatenatedPoints">The candidate points, back to back in canonical compressed layout.</param>
    /// <param name="pointCount">The number of points in <paramref name="concatenatedPoints"/>.</param>
    /// <param name="g1IsOnCurve">Backend on-curve predicate; consulted first because the subgroup predicate's behaviour on off-curve input is backend-defined.</param>
    /// <param name="g1IsInPrimeOrderSubgroup">Backend prime-order-subgroup predicate.</param>
    /// <param name="curve">The curve the points are claimed on.</param>
    /// <returns><see langword="true"/> iff every point passes both predicates.</returns>
    public static bool AreAllInPrimeOrderSubgroup(
        ReadOnlySpan<byte> concatenatedPoints,
        int pointCount,
        G1IsOnCurveDelegate g1IsOnCurve,
        G1IsInPrimeOrderSubgroupDelegate g1IsInPrimeOrderSubgroup,
        CurveParameterSet curve)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        for(int i = 0; i < pointCount; i++)
        {
            ReadOnlySpan<byte> point = concatenatedPoints.Slice(i * g1Size, g1Size);
            if(!g1IsOnCurve(point, curve) || !g1IsInPrimeOrderSubgroup(point, curve))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Decides whether every prover-supplied point of one Bulletproofs range
    /// proof — the value commitments, the bit and blinding commitments
    /// <c>A</c> and <c>S</c>, the polynomial commitments <c>T₁</c> and
    /// <c>T₂</c>, and every inner-product-argument round point — passes
    /// <see cref="AreAllInPrimeOrderSubgroup"/>.
    /// </summary>
    /// <param name="proof">The range proof whose points are screened.</param>
    /// <param name="valueCommitmentsConcatenated">The proof's Pedersen value commitments, back to back.</param>
    /// <param name="valueCommitmentCount">The number of value commitments in <paramref name="valueCommitmentsConcatenated"/>.</param>
    /// <param name="g1IsOnCurve">Backend on-curve predicate.</param>
    /// <param name="g1IsInPrimeOrderSubgroup">Backend prime-order-subgroup predicate.</param>
    /// <param name="curve">The curve the proof is over.</param>
    /// <returns><see langword="true"/> iff every point passes both predicates.</returns>
    public static bool AreRangeProofPointsInPrimeOrderSubgroup(
        RangeProof proof,
        ReadOnlySpan<byte> valueCommitmentsConcatenated,
        int valueCommitmentCount,
        G1IsOnCurveDelegate g1IsOnCurve,
        G1IsInPrimeOrderSubgroupDelegate g1IsInPrimeOrderSubgroup,
        CurveParameterSet curve)
    {
        int g1Size = WellKnownCurves.GetG1CompressedSizeBytes(curve);
        int roundPointCount = proof.GetIpaRoundPairBytes().Length / g1Size;

        return AreAllInPrimeOrderSubgroup(valueCommitmentsConcatenated, valueCommitmentCount, g1IsOnCurve, g1IsInPrimeOrderSubgroup, curve)
            && AreAllInPrimeOrderSubgroup(proof.GetABytes(), 1, g1IsOnCurve, g1IsInPrimeOrderSubgroup, curve)
            && AreAllInPrimeOrderSubgroup(proof.GetSBytes(), 1, g1IsOnCurve, g1IsInPrimeOrderSubgroup, curve)
            && AreAllInPrimeOrderSubgroup(proof.GetT1Bytes(), 1, g1IsOnCurve, g1IsInPrimeOrderSubgroup, curve)
            && AreAllInPrimeOrderSubgroup(proof.GetT2Bytes(), 1, g1IsOnCurve, g1IsInPrimeOrderSubgroup, curve)
            && AreAllInPrimeOrderSubgroup(proof.GetIpaRoundPairBytes(), roundPointCount, g1IsOnCurve, g1IsInPrimeOrderSubgroup, curve);
    }
}

using Lumoin.Veridical.Core.Algebraic;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Commitments.BaseFold;

/// <summary>
/// Converts a multilinear extension's dense evaluations into the monomial
/// coefficient vector BaseFold's <see cref="FoldableCodeExtensions.Encode"/>
/// consumes. <see cref="MultilinearExtension"/> stores
/// <c>f(b)</c> for every <c>b ∈ {0,1}^n</c>; BaseFold commits to
/// <c>Enc_d(coeffs)</c>, so a commit (and every re-encode in the evaluation
/// protocol) first runs this evals→coeffs interpolation.
/// </summary>
/// <remarks>
/// <para>
/// The transform is the multilinear Möbius (zeta-inverse) over the subset
/// lattice: for a multilinear <c>f(X_1, …, X_n) = Σ_S coeff[S]·Π_{i∈S} X_i</c>,
/// the hypercube evaluations satisfy <c>f(b) = Σ_{S ⊆ supp(b)} coeff[S]</c>, so
/// <c>coeff[S] = Σ_{T ⊆ S} (−1)^{|S|−|T|} f(T)</c>. Computed in place by one
/// butterfly per variable bit: for each index whose bit <c>k</c> is set,
/// subtract the entry with bit <c>k</c> cleared. The butterflies for distinct
/// bits commute, so the bit order is immaterial to the result.
/// </para>
/// <para>
/// Index meaning is preserved end to end: evaluation index bit <c>k</c> is
/// variable <c>X_{k+1}</c> (the
/// <see cref="MultilinearExtension"/> storage convention, the first variable in
/// the low bit), so coefficient index bit <c>k</c> is the monomial in
/// <c>X_{k+1}</c>. <see cref="FoldableCodeExtensions.Encode"/> splits the
/// message <c>[m_l | m_r]</c> on the high index bit and recurses, so its top
/// layer collapses the highest-variable monomial — the same variable the
/// interleaved sumcheck binds first. This ordering match is what ties the
/// evaluation protocol's IOPP fold to its sumcheck; it is exercised by the
/// end-to-end commit→open→verify tie test rather than asserted here.
/// </para>
/// <para>
/// Mirrors <c>interpolate_over_boolean_hypercube</c> in the reference
/// plonkish_basefold implementation (structural inspiration only, no code
/// dependency); that implementation operates in a bit-reversed (Type-1) index
/// space, while this one stays in the paper's natural (Type-2) order to match
/// Veridical's <see cref="FoldableCodeExtensions.Fold"/>.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class BaseFoldInterpolation
{
    private const int ScalarSize = Scalar.SizeBytes;


    extension(MultilinearExtension mle)
    {
        /// <summary>
        /// Writes the monomial coefficient vector of this multilinear
        /// extension into <paramref name="coefficients"/>, in the index order
        /// <see cref="FoldableCodeExtensions.Encode"/> consumes (coefficient
        /// index bit <c>k</c> is the monomial in variable <c>X_{k+1}</c>).
        /// </summary>
        /// <param name="coefficients">The destination; exactly <c>2^VariableCount · 32</c> bytes. Receives the dense coefficient vector.</param>
        /// <param name="subtract">The scalar-subtract backend.</param>
        /// <exception cref="ArgumentNullException">When <paramref name="subtract"/> is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the MLE's curve is not wired or <paramref name="coefficients"/> has the wrong length.</exception>
        public void InterpolateToCoefficients(Span<byte> coefficients, ScalarSubtractDelegate subtract)
        {
            ArgumentNullException.ThrowIfNull(mle);
            ArgumentNullException.ThrowIfNull(subtract);

            WellKnownCurves.ThrowIfCurveNotWired(mle.Curve);

            int evaluationCount = mle.EvaluationCount;
            int expected = evaluationCount * ScalarSize;
            if(coefficients.Length != expected)
            {
                throw new ArgumentException(
                    $"Coefficient buffer must be {expected} bytes for a {mle.VariableCount}-variable MLE; received {coefficients.Length}.",
                    nameof(coefficients));
            }

            //Start from a copy of the dense evaluations, then transform in place.
            mle.AsReadOnlySpan().CopyTo(coefficients);

            CurveParameterSet curve = mle.Curve;

            //One butterfly per variable bit. For variable bit k (stride = 2^k),
            //walk every block of 2·stride entries; within a block the upper
            //half (bit k set) subtracts the matching lower-half entry (bit k
            //cleared). After all n bits this is the multilinear Möbius inverse.
            for(int bit = 0; bit < mle.VariableCount; bit++)
            {
                int stride = 1 << bit;
                int blockSpan = stride << 1;
                for(int blockStart = 0; blockStart < evaluationCount; blockStart += blockSpan)
                {
                    for(int offset = 0; offset < stride; offset++)
                    {
                        int lowIndex = blockStart + offset;
                        int highIndex = lowIndex + stride;

                        ReadOnlySpan<byte> low = coefficients.Slice(lowIndex * ScalarSize, ScalarSize);
                        Span<byte> high = coefficients.Slice(highIndex * ScalarSize, ScalarSize);
                        subtract(high, low, high, curve);
                    }
                }
            }
        }
    }
}

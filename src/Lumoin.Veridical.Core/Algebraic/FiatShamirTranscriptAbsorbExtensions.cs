using Lumoin.Veridical.Core;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Typed absorbs of algebraic values onto a
/// <see cref="FiatShamirTranscript"/>. Each absorb writes the operand's
/// canonical byte layout into the transcript via
/// <see cref="FiatShamirTranscriptByteAbsorbExtensions.AbsorbBytes"/>.
/// </summary>
/// <remarks>
/// <para>
/// The transcript itself is broad (the curve identity lives only in
/// what bytes it absorbs). The composite-operand absorbs
/// (<c>AbsorbMultilinearExtension</c>, <c>AbsorbPolynomial</c>) absorb
/// the operand's canonical bytes regardless of curve and guard only that
/// the operand's curve is wired (Bls12Curve381, Bn254). The block is
/// curve-broad: each additional curve extends the guard list, because
/// the curve identity travels with the operand rather than being fixed
/// by the block itself.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class FiatShamirTranscriptAbsorbExtensions
{
    /// <summary>Extension methods hung off <see cref="FiatShamirTranscript"/> for absorbing algebraic operands.</summary>
    extension(FiatShamirTranscript transcript)
    {
        /// <summary>
        /// Absorbs a BLS12-381 scalar by its canonical 32 big-endian bytes.
        /// </summary>
        public void AbsorbScalar(
            FiatShamirOperationLabel label,
            Scalar scalar,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(scalar);
            transcript.AbsorbBytes(label, scalar.AsReadOnlySpan(), hash);
        }


        /// <summary>
        /// Absorbs a BLS12-381 G1 point by its canonical 48-byte
        /// compressed encoding.
        /// </summary>
        public void AbsorbG1Point(
            FiatShamirOperationLabel label,
            G1Point point,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(point);
            transcript.AbsorbBytes(label, point.AsReadOnlySpan(), hash);
        }


        /// <summary>
        /// Absorbs a multilinear extension over BLS12-381 or BN254 by all
        /// of its canonical evaluations, in storage order.
        /// </summary>
        /// <exception cref="ArgumentException">When <paramref name="mle"/>'s curve is neither BLS12-381 nor BN254.</exception>
        public void AbsorbMultilinearExtension(
            FiatShamirOperationLabel label,
            MultilinearExtension mle,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(mle);
            WellKnownCurves.ThrowIfCurveNotWired(mle.Curve);

            transcript.AbsorbBytes(label, mle.AsReadOnlySpan(), hash);
        }


        /// <summary>
        /// Absorbs a univariate polynomial over BLS12-381 or BN254 by all
        /// of its canonical coefficients, low-degree first.
        /// </summary>
        /// <exception cref="ArgumentException">When <paramref name="polynomial"/>'s curve is neither BLS12-381 nor BN254.</exception>
        public void AbsorbPolynomial(
            FiatShamirOperationLabel label,
            Polynomial polynomial,
            FiatShamirHashDelegate hash)
        {
            ArgumentNullException.ThrowIfNull(transcript);
            ArgumentNullException.ThrowIfNull(polynomial);
            WellKnownCurves.ThrowIfCurveNotWired(polynomial.Curve);

            transcript.AbsorbBytes(label, polynomial.AsReadOnlySpan(), hash);
        }
    }
}
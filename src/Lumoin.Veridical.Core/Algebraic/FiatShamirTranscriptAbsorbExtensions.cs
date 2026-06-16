using Lumoin.Veridical.Core;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Algebraic;

/// <summary>
/// Typed absorbs of BLS12-381 algebraic values onto a
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
/// the operand's curve is wired (Bls12Curve381, Bn254); they were
/// curve-broadened in place when BN254 was wired (Batch U) rather than
/// duplicated into a parallel per-curve file.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class FiatShamirTranscriptAbsorbExtensions
{
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
        /// Absorbs a multilinear extension over BLS12-381 by all of its
        /// canonical evaluations, in storage order.
        /// </summary>
        /// <exception cref="ArgumentException">When <paramref name="mle"/> is not over BLS12-381.</exception>
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
        /// Absorbs a univariate polynomial over BLS12-381 by all of its
        /// canonical coefficients, low-degree first.
        /// </summary>
        /// <exception cref="ArgumentException">When <paramref name="polynomial"/> is not over BLS12-381.</exception>
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
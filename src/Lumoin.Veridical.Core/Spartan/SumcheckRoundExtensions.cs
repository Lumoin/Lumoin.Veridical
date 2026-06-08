using Lumoin.Veridical.Core.Algebraic;
using Lumoin.Veridical.Core.Memory;
using Lumoin.Veridical.Core.Sumcheck;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Lumoin.Veridical.Core.Spartan;

/// <summary>
/// Verbs on <see cref="SumcheckRound"/> that materialise the inner
/// algebraic values — the compressed round polynomial and the verifier
/// challenge — as proper leaf-typed instances. Each call rents a fresh
/// pool buffer and copies the relevant slice; the originating
/// <see cref="SumcheckRound"/> remains the canonical owner of the
/// combined bytes.
/// </summary>
/// <remarks>
/// <para>
/// The "compute" half of the round (running the round-polynomial
/// computation against the prover's MLE state and absorbing the result
/// into a transcript) lives with the prover driver in batch G.2. This
/// G.1-shaped extension class only surfaces the data-shape accessors
/// that callers of any role — prover, verifier, inspector — need to
/// pull a round's components into leaf-typed handles.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034", Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class SumcheckRoundExtensions
{
    extension(SumcheckRound round)
    {
        /// <summary>
        /// Materialises the round polynomial as a fresh
        /// <see cref="CompressedRoundPolynomial"/> wrapping a pool-rented
        /// copy of the relevant byte slice.
        /// </summary>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A fresh compressed round polynomial; the caller owns its lifetime.</returns>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        public CompressedRoundPolynomial GetCompressedRoundPolynomial(SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(round);
            ArgumentNullException.ThrowIfNull(pool);

            return CompressedRoundPolynomial.FromCompressedBytes(
                round.GetCompressedPolynomialBytes(),
                round.Degree,
                round.Curve,
                pool);
        }


        /// <summary>
        /// Materialises the verifier challenge as a fresh
        /// <see cref="Scalar"/> wrapping a pool-rented copy
        /// of the challenge byte slice.
        /// </summary>
        /// <param name="pool">The pool to rent the destination buffer from.</param>
        /// <returns>A fresh BLS12-381 scalar; the caller owns its lifetime.</returns>
        /// <exception cref="ArgumentNullException">When any reference argument is <see langword="null"/>.</exception>
        /// <exception cref="ArgumentException">When the round is not over BLS12-381.</exception>
        public Scalar GetChallenge(SensitiveMemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(round);
            ArgumentNullException.ThrowIfNull(pool);

            WellKnownCurves.ThrowIfCurveNotWired(round.Curve);


            return Scalar.FromCanonical(round.GetChallengeBytes(), round.Curve, pool);
        }
    }
}